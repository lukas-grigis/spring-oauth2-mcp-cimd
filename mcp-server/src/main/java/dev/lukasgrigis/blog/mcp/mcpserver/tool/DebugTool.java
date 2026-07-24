package dev.lukasgrigis.blog.mcp.mcpserver.tool;

import dev.lukasgrigis.blog.mcp.mcpserver.security.McpCurrentUserResolver;
import dev.lukasgrigis.blog.mcp.mcpserver.security.McpCurrentUserResolver.CurrentUser;
import org.springframework.ai.mcp.annotation.McpTool;
import org.springframework.security.access.prepost.PreAuthorize;

import java.util.List;

/**
 * A tiny "who am I" probe — the simplest possible window onto the two-plane auth.
 *
 * <p>{@code whoami} echoes the caller's identity (carried from Keycloak through the authorization
 * server's token) and the scopes the token holds. It is gated only by {@code isAuthenticated()}, so any
 * valid token can call it; the scope-gated behaviour is demonstrated by {@link NoteTool}. Method
 * security must be enabled ({@code @EnableMethodSecurity}) or these {@code @PreAuthorize} gates are
 * silently ignored.
 */
public class DebugTool {

    private final McpCurrentUserResolver currentUser;
    private final String serverVersion;

    public DebugTool(McpCurrentUserResolver currentUser, String serverVersion) {
        this.currentUser = currentUser;
        this.serverVersion = serverVersion;
    }

    @McpTool(
        name = "whoami",
        description = "Returns your authenticated identity (subject, username, email) and the scopes your "
            + "token carries. Any authenticated caller — use it to see what the note tools "
            + "(list_notes / create_note / purge_notes) will allow.",
        annotations = @McpTool.McpAnnotations(
            readOnlyHint = true, destructiveHint = false, idempotentHint = true, openWorldHint = false))
    @PreAuthorize("isAuthenticated()")
    public WhoAmI whoami() {
        CurrentUser user = currentUser.currentUser();
        return new WhoAmI(user.subject(), user.username(), user.email(), user.scopes(), "mcp-server " + serverVersion);
    }

    /**
     * What {@code whoami} returns; the MCP framework serializes it to JSON.
     */
    public record WhoAmI(
        String subject,
        String username,
        String email,
        List<String> scopes,
        String server
    ) {

    }

}
