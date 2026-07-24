package dev.lukasgrigis.blog.mcp.authorizationserver.configuration;

import jakarta.validation.constraints.NotEmpty;
import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.boot.context.properties.bind.DefaultValue;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.Ordered;
import org.springframework.core.annotation.Order;
import org.springframework.http.MediaType;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configurers.AbstractHttpConfigurer;
import org.springframework.security.config.annotation.web.configurers.HeadersConfigurer;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.oauth2.jose.jws.SignatureAlgorithm;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.LoginUrlAuthenticationEntryPoint;
import org.springframework.security.web.header.writers.ReferrerPolicyHeaderWriter.ReferrerPolicy;
import org.springframework.security.web.util.matcher.MediaTypeRequestMatcher;
import org.springframework.validation.annotation.Validated;
import org.springframework.web.cors.CorsConfigurationSource;

import static org.springaicommunity.mcp.security.authorizationserver.config.McpAuthorizationServerConfigurer.mcpAuthorizationServer;

/**
 * The upstream IdP's OAuth2 client registration id. It must match the key under
 * {@code spring.security.oauth2.client.registration.<id>} and is the only Java touch-point for the
 * federation: the login is triggered at {@code /oauth2/authorization/<id>}. Keeping it a property (rather
 * than hardcoding "keycloak") means the upstream IdP is a configuration choice, not a code change.
 */
@Validated
@ConfigurationProperties("app.upstream")
record UpstreamProperties(@DefaultValue("keycloak") @NotEmpty String registrationId) {

    String authorizationRequestUri() {
        return "/oauth2/authorization/" + registrationId;
    }

}

/**
 * The three security chains of the authorization server.
 *
 * <ol>
 *   <li><b>actuator</b> — public health/info probes (used by the demo startup wait-loop).</li>
 *   <li><b>authorization server</b> — the OAuth2/OIDC + MCP endpoints: discovery, authorize, token,
 *       JWKS. Client identity is CIMD (Client ID Metadata Documents): a client's {@code client_id}
 *       is a URL, and the server resolves the client's metadata from that URL — there is no
 *       registration endpoint. ES256 is advertised in the provider metadata here (Spring defaults
 *       to RS256). A browser hitting a protected endpoint with no session is sent to the upstream
 *       login. Note the MCP clients send <em>scopeless</em> authorization requests, so Spring
 *       Authorization Server's own consent page is never shown — the only consent the user sees is
 *       Keycloak's (see {@code OAuth2StoreConfiguration}).</li>
 *   <li><b>login</b> — federates the human login to the upstream IdP via {@code oauth2Login}.</li>
 * </ol>
 *
 * <p>CORS is wired onto the two browser-facing chains for the MCP Inspector (see {@link CorsConfig}).
 * The endpoints serve JSON / redirects rather than HTML, so the CSP is a tight {@code default-src 'self'}
 * with no inline allowance; enabling the AS consent page is the one thing that would need it relaxed.
 */
@Configuration
@EnableWebSecurity
@EnableConfigurationProperties(UpstreamProperties.class)
class WebSecurityConfiguration {

    @Bean
    @Order(Ordered.HIGHEST_PRECEDENCE)
    SecurityFilterChain actuatorChain(HttpSecurity http) {
        return http.securityMatcher("/actuator/**")
            .authorizeHttpRequests(auth -> auth.anyRequest().permitAll())
            .csrf(AbstractHttpConfigurer::disable)
            .requestCache(AbstractHttpConfigurer::disable)
            .securityContext(AbstractHttpConfigurer::disable)
            .sessionManagement(sm -> sm.sessionCreationPolicy(SessionCreationPolicy.STATELESS))
            .build();
    }

    @Bean
    @Order(Ordered.HIGHEST_PRECEDENCE + 1)
    SecurityFilterChain authorizationServerChain(
        HttpSecurity http,
        CorsConfigurationSource corsConfigurationSource,
        UpstreamProperties upstream
    ) throws
        Exception {
        return http.csrf(AbstractHttpConfigurer::disable)
            .cors(cors -> cors.configurationSource(corsConfigurationSource))
            // These endpoints return JSON (RFC 6749 error responses) or redirects, not HTML, so this CSP
            // is just defence-in-depth. The only HTML this chain could serve is Spring Authorization
            // Server's built-in consent page, which the demo never shows (MCP clients send scopeless
            // authorization requests, and those skip consent — see OAuth2StoreConfiguration). Enabling
            // AS-side consent would need inline script/style allowed back, or a custom consent page.
            .headers(h -> h.contentSecurityPolicy(csp -> csp.policyDirectives(
                    "default-src 'self'; form-action 'self'; frame-ancestors 'none'"))
                .frameOptions(HeadersConfigurer.FrameOptionsConfig::deny)
                .referrerPolicy(rp -> rp.policy(ReferrerPolicy.NO_REFERRER)))
            .authorizeHttpRequests(auth -> auth.anyRequest().authenticated())
            .with(
                mcpAuthorizationServer(),
                // Client identity via CIMD: the client_id is a URL, resolved to a metadata document at
                // request time (see OAuth2StoreConfiguration for what is — and is not — persisted).
                // RFC 7591 registration is switched OFF explicitly: the library enables its registration
                // endpoint by default, and this server must expose none.
                mcp -> mcp.cimd(true).dynamicClientRegistration(false).authorizationServer(authzServer -> {
                    // Advertise ES256 in the provider metadata — Spring defaults to RS256.
                    authzServer.oidc(oidc -> oidc.providerConfigurationEndpoint(endpoint -> endpoint.providerConfigurationCustomizer(
                        cfg -> cfg.idTokenSigningAlgorithms(algs -> {
                            algs.clear();
                            algs.add(SignatureAlgorithm.ES256.getName());
                        }))));
                    http.securityMatcher(authzServer.getEndpointsMatcher());
                })
            )
            .exceptionHandling(ex -> ex.defaultAuthenticationEntryPointFor(
                new LoginUrlAuthenticationEntryPoint(upstream.authorizationRequestUri()),
                new MediaTypeRequestMatcher(MediaType.TEXT_HTML)
            ))
            .build();
    }

    @Bean
    @Order(2)
    SecurityFilterChain loginChain(
        HttpSecurity http,
        CorsConfigurationSource corsConfigurationSource,
        UpstreamProperties upstream
    ) {
        return http.cors(cors -> cors.configurationSource(corsConfigurationSource))
            .headers(
                h -> h.contentSecurityPolicy(csp -> csp.policyDirectives(
                        "default-src 'self'; form-action 'self'; frame-ancestors 'none'"))
                    .frameOptions(HeadersConfigurer.FrameOptionsConfig::deny)
                    .referrerPolicy(rp -> rp.policy(ReferrerPolicy.NO_REFERRER)))
            .authorizeHttpRequests(auth -> auth.requestMatchers("/.well-known/**", "/error")
                .permitAll()
                .anyRequest()
                .authenticated())
            .oauth2Login(login -> login.loginPage(upstream.authorizationRequestUri()))
            .build();
    }

}
