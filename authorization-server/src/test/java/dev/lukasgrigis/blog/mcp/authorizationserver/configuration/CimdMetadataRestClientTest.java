package dev.lukasgrigis.blog.mcp.authorizationserver.configuration;

import com.sun.net.httpserver.HttpServer;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.boot.http.client.InetAddressFilter;
import org.springframework.web.client.RestClientException;

import java.io.IOException;
import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.nio.charset.StandardCharsets;
import java.util.concurrent.atomic.AtomicInteger;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

/**
 * The CIMD metadata fetch accepts a 200 and nothing else. Runs against a loopback HTTP server, so
 * the filter here admits loopback; the address rules themselves are {@link SsrfGuardConfigurationTest}'s.
 */
class CimdMetadataRestClientTest {

    private static final byte[] DOCUMENT = "{\"client_name\":\"x\"}".getBytes(StandardCharsets.UTF_8);

    private final AtomicInteger redirectTargetHits = new AtomicInteger();
    private HttpServer server;
    private String baseUrl;

    @BeforeEach
    void startServer() throws IOException {
        server = HttpServer.create(new InetSocketAddress(InetAddress.getLoopbackAddress(), 0), 0);
        server.createContext("/ok.json", exchange -> {
            exchange.getResponseHeaders().add("Content-Type", "application/json");
            exchange.sendResponseHeaders(200, DOCUMENT.length);
            exchange.getResponseBody().write(DOCUMENT);
            exchange.close();
        });
        // A redirect that also carries a parseable document: neither the hop nor the body may count.
        server.createContext("/moved.json", exchange -> {
            exchange.getResponseHeaders().add("Location", "/target.json");
            exchange.getResponseHeaders().add("Content-Type", "application/json");
            exchange.sendResponseHeaders(302, DOCUMENT.length);
            exchange.getResponseBody().write(DOCUMENT);
            exchange.close();
        });
        server.createContext("/target.json", exchange -> {
            redirectTargetHits.incrementAndGet();
            exchange.getResponseHeaders().add("Content-Type", "application/json");
            exchange.sendResponseHeaders(200, DOCUMENT.length);
            exchange.getResponseBody().write(DOCUMENT);
            exchange.close();
        });
        server.start();
        baseUrl = "http://127.0.0.1:" + server.getAddress().getPort();
    }

    @AfterEach
    void stopServer() {
        server.stop(0);
    }

    /** Status only: the client carries just the metadata-document converter, by design. */
    private int fetch(String path) {
        final var filter = InetAddressFilter.externalAddresses().or("127.0.0.0/8");
        return OAuth2StoreConfiguration.cimdMetadataRestClient(filter)
            .get().uri(baseUrl + path).retrieve().toBodilessEntity().getStatusCode().value();
    }

    @Test
    @DisplayName("a 200 response is accepted")
    void okIsAccepted() {
        assertThat(fetch("/ok.json")).isEqualTo(200);
    }

    @Test
    @DisplayName("a redirect is neither followed nor parsed, even with a document in its body")
    void redirectIsRejected() {
        assertThatThrownBy(() -> fetch("/moved.json"))
            .isInstanceOf(RestClientException.class)
            .hasMessageContaining("302");
        assertThat(redirectTargetHits).hasValue(0);
    }

}
