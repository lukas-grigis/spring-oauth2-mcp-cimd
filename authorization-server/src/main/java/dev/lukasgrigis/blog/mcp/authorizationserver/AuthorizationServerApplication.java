package dev.lukasgrigis.blog.mcp.authorizationserver;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;

/**
 * The OAuth2 Authorization Server (:9000).
 *
 * <p>It is the piece the article is about: it accepts <strong>Client ID Metadata Documents</strong>
 * (CIMD, MCP authorization spec 2025-11-25) in front of an upstream identity provider. An MCP
 * client identifies itself with a URL {@code client_id}; this server resolves the metadata document
 * behind that URL instead of offering a registration endpoint. The human login is federated to
 * Keycloak (an OAuth2 client), the upstream realm roles are mapped to fine-grained scopes, and this
 * server mints its own ES256 access tokens that the MCP server validates.
 */
@SpringBootApplication
public class AuthorizationServerApplication {

    static void main(String[] args) {
        SpringApplication.run(AuthorizationServerApplication.class, args);
    }

}
