package dev.lukasgrigis.blog.mcp.mcpserver.configuration;

import dev.lukasgrigis.blog.mcp.mcpserver.security.McpCurrentUserResolver;
import dev.lukasgrigis.blog.mcp.mcpserver.tool.DebugTool;
import dev.lukasgrigis.blog.mcp.mcpserver.tool.NoteTool;
import org.springframework.ai.mcp.server.common.autoconfigure.properties.McpServerProperties;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

/**
 * Registers the MCP tools as Spring beans. Spring AI's MCP server discovers the {@code @McpTool}
 * methods on these beans at startup; the {@code @PreAuthorize} scope gates fire because the beans are
 * Spring-proxied and {@code @EnableMethodSecurity} is on (see {@code McpServerSecurityConfiguration}).
 */
@Configuration(proxyBeanMethods = false)
public class ToolConfiguration {

    @Bean
    McpCurrentUserResolver mcpCurrentUserResolver() {
        return new McpCurrentUserResolver();
    }

    @Bean
    DebugTool debugTool(McpCurrentUserResolver currentUser, McpServerProperties properties) {
        return new DebugTool(currentUser, properties.getVersion());
    }

    @Bean
    NoteTool noteTool(McpCurrentUserResolver currentUser) {
        return new NoteTool(currentUser);
    }

}
