package dev.lukasgrigis.blog.mcp.mcpserver.tool;

import dev.lukasgrigis.blog.mcp.mcpserver.security.McpCurrentUserResolver;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.authentication.AuthenticationCredentialsNotFoundException;
import org.springframework.security.config.annotation.method.configuration.EnableMethodSecurity;
import org.springframework.security.test.context.support.WithMockUser;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

/**
 * Offline method-security slice for {@code whoami}: only {@code @EnableMethodSecurity} + the tool, so the
 * {@code @PreAuthorize} gate runs with no resource-server chain and no authorization server. Proves the
 * gate is effective (the silent {@code @EnableMethodSecurity} bypass would fail this).
 */
@SpringBootTest(classes = DebugToolSecurityTest.Config.class, webEnvironment = SpringBootTest.WebEnvironment.NONE)
class DebugToolSecurityTest {

    @Autowired
    DebugTool tool;

    @Test
    @WithMockUser(authorities = "SCOPE_note:read")
    void whoamiAllowsAnyAuthenticatedUser() {
        DebugTool.WhoAmI who = tool.whoami();
        assertThat(who.server()).startsWith("mcp-server");
        assertThat(who.scopes()).contains("note:read");
    }

    @Test
    void whoamiDeniesAnonymous() {
        assertThatThrownBy(tool::whoami).isInstanceOf(AuthenticationCredentialsNotFoundException.class);
    }

    @Configuration
    @EnableMethodSecurity
    static class Config {

        @Bean
        McpCurrentUserResolver mcpCurrentUserResolver() {
            return new McpCurrentUserResolver();
        }

        @Bean
        DebugTool debugTool(McpCurrentUserResolver currentUser) {
            return new DebugTool(currentUser, "test");
        }

    }

}
