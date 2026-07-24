package dev.lukasgrigis.blog.mcp.authorizationserver.configuration;

import org.springframework.boot.http.client.InetAddressFilter;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.env.Environment;

/**
 * The SSRF guard for the CIMD metadata fetch — one bean.
 *
 * <p>Under CIMD the authorization server dereferences a client-supplied URL (the {@code client_id})
 * at authorization time. That is a textbook Server-Side Request Forgery vector: without a guard,
 * anyone could steer this server at internal-only addresses (cloud metadata endpoints, sidecars,
 * the database host). The CIMD draft and the MCP 2025-11-25 authorization spec both call this out.
 *
 * <p>The guard is this single {@link InetAddressFilter} bean. The metadata-fetch HTTP client
 * enforces it at DNS-resolution time inside the Apache HttpComponents connection manager (see
 * {@code OAuth2StoreConfiguration#cimdMetadataRestClient}), so the filter vets the exact addresses
 * being connected to — redirect hops included:
 * <ul>
 *   <li><b>Always:</b> only externally-routable addresses pass. Private ranges (10/8, 172.16/12,
 *       192.168/16, fc00::/7), link-local (169.254/16, fe80::/10), loopback (127/8, ::1) and the
 *       remaining RFC 6890 special-purpose blocks are refused.</li>
 *   <li><b>demo profile only</b> (this repo's default profile — see application.yml): loopback is
 *       allowed back in, because the demo serves its client metadata document from localhost.
 *       DEMO ONLY — never relax loopback where real clients connect, or every service listening on
 *       the server's own loopback interface becomes reachable through the fetcher. Private and
 *       link-local ranges stay blocked even in demo.</li>
 * </ul>
 *
 * <p>Side benefit: Boot's {@code HttpClientAutoConfiguration} folds any {@link InetAddressFilter}
 * bean into its default {@code HttpClientSettings}, so auto-configured HTTP clients in this app get
 * the same address filtering.
 */
@Configuration
class SsrfGuardConfiguration {

    @Bean
    InetAddressFilter cimdFetchAddressFilter(Environment environment) {
        // Filter semantics: matches == allowed. externalAddresses() = routable minus multicast,
        // RFC 6890 special-purpose, and the private/link-local/loopback ranges listed above.
        final var externalOnly = InetAddressFilter.externalAddresses();
        if (environment.matchesProfiles("demo")) {
            // DEMO ONLY — allow loopback so the locally-served metadata document is fetchable.
            return externalOnly.or("127.0.0.0/8", "::1/128");
        }
        return externalOnly;
    }

}
