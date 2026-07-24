package dev.lukasgrigis.blog.mcp.authorizationserver.configuration;

import org.assertj.core.api.ThrowableAssert.ThrowingCallable;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.boot.http.client.FilteredHostException;
import org.springframework.boot.http.client.InetAddressFilter;
import org.springframework.mock.env.MockEnvironment;

import java.net.InetAddress;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.catchThrowable;

/**
 * The CIMD SSRF guard. Offline; no Spring context. Every probed URL uses a literal IP address (or
 * localhost, which resolves from the hosts file), and the guard refuses filtered hosts before any
 * connection is attempted — so nothing here touches the network.
 */
class SsrfGuardConfigurationTest {

    private final SsrfGuardConfiguration configuration = new SsrfGuardConfiguration();

    /** No active profile — MockEnvironment's default profile is "default", not "demo" → strict. */
    private InetAddressFilter strictFilter() {
        return configuration.cimdFetchAddressFilter(new MockEnvironment());
    }

    private InetAddressFilter demoFilter() {
        final var environment = new MockEnvironment();
        environment.setActiveProfiles("demo");
        return configuration.cimdFetchAddressFilter(environment);
    }

    @Test
    @DisplayName("the strict guard refuses private, link-local and loopback addresses")
    void strictGuardRefusesInternalRanges() throws Exception {
        final var filter = strictFilter();
        for (final var ip : new String[] {
            "10.0.0.7", "172.16.0.1", "192.168.1.1", // private (RFC 1918)
            "169.254.169.254",                       // link-local (the cloud metadata endpoint)
            "127.0.0.1",                             // loopback
            "::1", "fe80::1", "fd00::1"              // IPv6 loopback / link-local / unique-local
        }) {
            assertThat(filter.matches(InetAddress.getByName(ip))).as("must refuse %s", ip).isFalse();
        }
        assertThat(filter.matches(InetAddress.getByName("93.184.216.34")))
            .as("must allow an externally-routable address").isTrue();
    }

    @Test
    @DisplayName("the demo profile relaxes loopback only — private ranges stay refused")
    void demoGuardRelaxesLoopbackOnly() throws Exception {
        final var filter = demoFilter();
        assertThat(filter.matches(InetAddress.getByName("127.0.0.1"))).isTrue();
        assertThat(filter.matches(InetAddress.getByName("::1"))).isTrue();
        assertThat(filter.matches(InetAddress.getByName("10.0.0.7"))).isFalse();
        assertThat(filter.matches(InetAddress.getByName("169.254.169.254"))).isFalse();
    }

    @Test
    @DisplayName("a private-range client_id URL is refused by the guarded metadata-fetch client")
    void privateRangeUrlIsRefused() {
        final var restClient = OAuth2StoreConfiguration.cimdMetadataRestClient(strictFilter());
        assertRefused(() -> restClient.get().uri("http://10.255.255.1/client.json").retrieve().toEntity(String.class));
        assertRefused(() -> restClient.get().uri("http://localhost:1/client.json").retrieve().toEntity(String.class));
    }

    @Test
    @DisplayName("the demo relaxation does not open private ranges through the guarded client")
    void demoGuardStillRefusesPrivateRangeUrl() {
        final var restClient = OAuth2StoreConfiguration.cimdMetadataRestClient(demoFilter());
        assertRefused(() -> restClient.get().uri("http://192.168.0.10/client.json").retrieve().toEntity(String.class));
    }

    private static void assertRefused(ThrowingCallable fetch) {
        final var thrown = catchThrowable(fetch);
        assertThat(thrown).as("the guarded client must throw").isNotNull();
        var cursor = thrown;
        while (cursor != null && !(cursor instanceof FilteredHostException)) {
            cursor = cursor.getCause();
        }
        assertThat(cursor)
            .as("FilteredHostException must be in the cause chain of: " + thrown)
            .isInstanceOf(FilteredHostException.class);
    }

}
