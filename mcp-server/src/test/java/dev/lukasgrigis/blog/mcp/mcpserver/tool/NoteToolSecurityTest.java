package dev.lukasgrigis.blog.mcp.mcpserver.tool;

import dev.lukasgrigis.blog.mcp.mcpserver.security.McpCurrentUserResolver;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.access.AccessDeniedException;
import org.springframework.security.authentication.AuthenticationCredentialsNotFoundException;
import org.springframework.security.config.annotation.method.configuration.EnableMethodSecurity;
import org.springframework.security.test.context.support.WithMockUser;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

/**
 * Offline method-security slice proving the scope-gate matrix on the note tools — the build-time twin of
 * the live e2e allow/deny check. {@code list_notes} needs note:read, {@code create_note} note:write,
 * {@code purge_notes} note:admin; a missing scope is an {@code AccessDeniedException}, anonymous is an
 * {@code AuthenticationCredentialsNotFoundException}.
 */
@SpringBootTest(classes = NoteToolSecurityTest.Config.class, webEnvironment = SpringBootTest.WebEnvironment.NONE)
class NoteToolSecurityTest {

    @Autowired
    NoteTool tool;

    @Test
    @WithMockUser(authorities = "SCOPE_note:read")
    void listAllowedWithReadScope() {
        assertThat(tool.listNotes()).isNotNull();
    }

    @Test
    @WithMockUser(authorities = "SCOPE_note:read")
    void createDeniedWithoutWriteScope() {
        assertThatThrownBy(() -> tool.createNote("x")).isInstanceOf(AccessDeniedException.class);
    }

    @Test
    @WithMockUser(authorities = {"SCOPE_note:read", "SCOPE_note:write"})
    void createAllowedWithWriteScope() {
        assertThat(tool.createNote("hello").text()).isEqualTo("hello");
    }

    @Test
    @WithMockUser(authorities = {"SCOPE_note:read", "SCOPE_note:write"})
    void purgeDeniedWithoutAdminScope() {
        assertThatThrownBy(tool::purgeNotes).isInstanceOf(AccessDeniedException.class);
    }

    @Test
    @WithMockUser(authorities = "SCOPE_note:admin")
    void purgeAllowedWithAdminScope() {
        assertThat(tool.purgeNotes()).contains("purged");
    }

    @Test
    void listDeniedAnonymous() {
        assertThatThrownBy(tool::listNotes).isInstanceOf(AuthenticationCredentialsNotFoundException.class);
    }

    @Configuration
    @EnableMethodSecurity
    static class Config {

        @Bean
        McpCurrentUserResolver mcpCurrentUserResolver() {
            return new McpCurrentUserResolver();
        }

        @Bean
        NoteTool noteTool(McpCurrentUserResolver currentUser) {
            return new NoteTool(currentUser);
        }

    }

}
