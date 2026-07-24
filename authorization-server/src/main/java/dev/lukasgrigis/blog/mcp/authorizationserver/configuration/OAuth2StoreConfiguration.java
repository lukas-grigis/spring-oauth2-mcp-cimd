package dev.lukasgrigis.blog.mcp.authorizationserver.configuration;

import org.jspecify.annotations.NonNull;
import org.springaicommunity.mcp.security.common.url.DefaultUrlValidator;
import org.springframework.boot.http.client.ClientHttpRequestFactoryBuilder;
import org.springframework.boot.http.client.HttpClientSettings;
import org.springframework.boot.http.client.InetAddressFilter;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.jdbc.core.JdbcOperations;
import org.springframework.security.config.annotation.web.configurers.oauth2.server.authorization.DelegatingRegisteredClientRepository;
import org.springframework.security.config.annotation.web.configurers.oauth2.server.authorization.client.metadata.ClientIdMetadataDocumentRegisteredClientRepository;
import org.springframework.security.config.annotation.web.configurers.oauth2.server.authorization.client.metadata.ClientIdUrlValidator;
import org.springframework.security.config.annotation.web.configurers.oauth2.server.authorization.client.metadata.DefaultClientIdMetadataDocumentResolver;
import org.springframework.security.config.annotation.web.configurers.oauth2.server.authorization.client.metadata.DefaultClientMetadataValidator;
import org.springframework.security.oauth2.core.AuthorizationGrantType;
import org.springframework.security.oauth2.server.authorization.JdbcOAuth2AuthorizationConsentService;
import org.springframework.security.oauth2.server.authorization.JdbcOAuth2AuthorizationService;
import org.springframework.security.oauth2.server.authorization.OAuth2AuthorizationConsentService;
import org.springframework.security.oauth2.server.authorization.OAuth2AuthorizationService;
import org.springframework.security.oauth2.server.authorization.client.JdbcRegisteredClientRepository;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClient;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClientRepository;
import org.springframework.security.oauth2.server.authorization.http.converter.OAuth2ClientRegistrationHttpMessageConverter;
import org.springframework.security.oauth2.server.authorization.settings.TokenSettings;
import org.springframework.web.client.RestClient;

import java.time.Duration;
import java.util.List;
import java.util.Objects;

/**
 * The registered-client lookup path (CIMD + JDBC) and the JDBC-backed OAuth2 stores (Postgres).
 *
 * <p>Client lookup delegates in order:
 * <ol>
 *   <li><b>CIMD</b> — {@link ClientIdMetadataDocumentRegisteredClientRepository} (mcp-security)
 *       serves MCP clients whose {@code client_id} is a URL: it detects URL-formatted ids, fetches
 *       the Client ID Metadata Document from that URL, validates it (the document's
 *       {@code client_id} must equal the URL exactly; {@code redirect_uris} must be present and
 *       valid; no {@code client_secret} allowed), converts it into a public PKCE
 *       {@link RegisteredClient}, and caches the result with a short TTL taken from the response's
 *       {@code Cache-Control: max-age} (5 minutes when absent). The authorization request's
 *       {@code redirect_uri} is then matched exactly against the document's {@code redirect_uris}
 *       by Spring Authorization Server's authorization-code flow.
 *       The fetch itself runs through an SSRF-guarded HTTP client — the {@code client_id} URL is
 *       attacker-suppliable (see {@link SsrfGuardConfiguration}).</li>
 *   <li><b>JDBC</b> — pre-registered (non-CIMD) clients would live in
 *       {@code oauth2_registered_client}; the demo ships none. Under CIMD there is no registration
 *       step to persist: a client is resolved from the metadata document behind its URL
 *       {@code client_id} at request time, so MCP clients never write to that table.</li>
 * </ol>
 *
 * <p>Authorizations and consents stay JDBC-backed so they survive a restart. The repository bean
 * wraps the delegates to stamp policy onto every client it serves: a refresh token for the
 * auth-code grant and sane token lifetimes.
 *
 * <p>Note: MCP clients send <em>scopeless</em> authorization requests (the mcp-authorization-server
 * library skips the AS's own consent page for scopeless requests). The granted scopes come from the
 * upstream realm roles at mint time (see {@code ScopeMappingConfiguration}); the user-facing consent
 * is Keycloak's, shown when the {@code keycloak} client federates the login.
 */
@Configuration
class OAuth2StoreConfiguration {

    // Token lifetimes stamped onto every client this repository serves. DEMO ONLY — externalize these
    // (e.g. via @ConfigurationProperties bound to application.yml) to tune them per environment without a
    // rebuild.
    private static final Duration ACCESS_TOKEN_TTL = Duration.ofMinutes(30);
    private static final Duration REFRESH_TOKEN_TTL = Duration.ofDays(7);

    private RegisteredClient applyDefaults(RegisteredClient client) {
        if (Objects.isNull(client)) {
            return null;
        }

        final var tokenSettings = TokenSettings.builder()
            .accessTokenTimeToLive(ACCESS_TOKEN_TTL)
            .refreshTokenTimeToLive(REFRESH_TOKEN_TTL)
            .reuseRefreshTokens(false)
            .build();

        final var builder = RegisteredClient.from(client)
            .tokenSettings(tokenSettings);

        // REFRESH_TOKEN only for authorization_code — not for client_credentials (RFC 6749 §4.4).
        if (client.getAuthorizationGrantTypes().contains(AuthorizationGrantType.AUTHORIZATION_CODE)) {
            builder.authorizationGrantType(AuthorizationGrantType.REFRESH_TOKEN);
        }
        return builder.build();
    }

    @Bean
    RegisteredClientRepository registeredClientRepository(
        JdbcOperations jdbcOperations,
        InetAddressFilter cimdFetchAddressFilter
    ) {
        // CIMD path (mcp-security library types): URL client_id → fetch the metadata document →
        // validate → RegisteredClient, with a built-in short-TTL cache keyed on the URL. The fetch
        // dereferences an attacker-suppliable URL, so it goes through the SSRF-guarded HTTP client
        // below (the address filter and its demo-only relaxation live in SsrfGuardConfiguration).
        final var cimdRepository = new ClientIdMetadataDocumentRegisteredClientRepository();
        cimdRepository.setMetadataDocumentResolver(
            new DefaultClientIdMetadataDocumentResolver(cimdMetadataRestClient(cimdFetchAddressFilter)));
        // DEMO ONLY — the CIMD draft requires https client_ids and the library enforces that by
        // default. The local stack serves the demo metadata document over plain HTTP, so loopback
        // hosts (localhost / 127.0.0.1 / [::1]) are allowed here, both for the client_id URL and for
        // the document's redirect_uris (the e2e callback listens on a loopback port). Any
        // non-loopback URL still requires HTTPS.
        cimdRepository.setClientIdUrlValidator(new ClientIdUrlValidator(true));
        cimdRepository.setMetadataValidator(new DefaultClientMetadataValidator(new DefaultUrlValidator(true)));

        // Pre-registered clients (none in the demo); also the save target, so a programmatic save
        // still persists. CIMD clients never hit this path: they are resolved, not registered.
        final var jdbcRepository = new JdbcRegisteredClientRepository(jdbcOperations);

        final var delegating = new DelegatingRegisteredClientRepository(
            List.of(cimdRepository, jdbcRepository), jdbcRepository);

        return new RegisteredClientRepository() {
            @Override
            public void save(@NonNull RegisteredClient registeredClient) {
                delegating.save(applyDefaults(registeredClient));
            }

            @Override
            public RegisteredClient findById(String id) {
                var client = delegating.findById(id);
                // For CIMD clients the library sets id == client_id == the metadata URL, but its
                // findById only consults the short-TTL cache. A miss on a URL-shaped id (TTL
                // elapsed, or a restart while a JDBC-persisted authorization is replayed, e.g. a
                // refresh-token grant) is re-resolved through the full fetch-and-validate path.
                if (client == null && (id.startsWith("http://") || id.startsWith("https://"))) {
                    client = delegating.findByClientId(id);
                }
                return applyDefaults(client);
            }

            @Override
            public RegisteredClient findByClientId(String clientId) {
                return applyDefaults(delegating.findByClientId(clientId));
            }
        };
    }

    /**
     * The HTTP client behind the CIMD metadata fetch. Two deliberate choices:
     * <ul>
     *   <li><b>SSRF guard</b> — the {@link InetAddressFilter} is enforced inside the connection
     *       manager's DNS resolver, so it vets the resolved addresses actually connected to,
     *       redirect hops included. A refused host fails with
     *       {@code org.springframework.boot.http.client.FilteredHostException} before any
     *       connection is attempted.</li>
     *   <li><b>Apache HttpComponents</b> — the same reason it is on the classpath at all (see
     *       pom.xml): the JDK client's h2c upgrade hangs against plain-HTTP endpoints like the
     *       demo's Traefik-fronted hosts.</li>
     * </ul>
     * Mirrors {@link DefaultClientIdMetadataDocumentResolver}'s default RestClient (same message
     * converter for the metadata document) — only the request factory is swapped. Package-private
     * and static so the unit test exercises the exact production construction.
     */
    static RestClient cimdMetadataRestClient(InetAddressFilter addressFilter) {
        final var requestFactory = ClientHttpRequestFactoryBuilder.httpComponents()
            .build(HttpClientSettings.defaults().withInetAddressFilter(addressFilter));
        return RestClient.builder()
            .requestFactory(requestFactory)
            .configureMessageConverters(converters ->
                converters.addCustomConverter(new OAuth2ClientRegistrationHttpMessageConverter()))
            .build();
    }

    @Bean
    OAuth2AuthorizationService authorizationService(
        JdbcOperations jdbcOperations,
        RegisteredClientRepository registeredClientRepository
    ) {
        return new JdbcOAuth2AuthorizationService(jdbcOperations, registeredClientRepository);
    }

    @Bean
    OAuth2AuthorizationConsentService authorizationConsentService(
        JdbcOperations jdbcOperations,
        RegisteredClientRepository registeredClientRepository
    ) {
        return new JdbcOAuth2AuthorizationConsentService(jdbcOperations, registeredClientRepository);
    }

}
