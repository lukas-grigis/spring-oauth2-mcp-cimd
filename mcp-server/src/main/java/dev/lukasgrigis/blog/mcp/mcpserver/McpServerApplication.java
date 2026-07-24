package dev.lukasgrigis.blog.mcp.mcpserver;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;

/**
 * The Spring AI MCP server (:9200, Streamable HTTP).
 *
 * <p>A thin Boot main: the {@code configuration} package contributes the OAuth2 resource-server
 * security ({@code mcp-server-security}) and the scope-gated {@code @McpTool} beans. Tokens are
 * minted by the authorization server (:9000) and validated here against its JWKS.
 */
@SpringBootApplication
public class McpServerApplication {

    public static void main(String[] args) {
        SpringApplication.run(McpServerApplication.class, args);
    }

}
