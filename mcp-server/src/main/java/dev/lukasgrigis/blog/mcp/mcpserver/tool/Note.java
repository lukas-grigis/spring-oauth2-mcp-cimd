package dev.lukasgrigis.blog.mcp.mcpserver.tool;

/**
 * A note in the demo's in-memory store. {@code author} is the caller's username, carried from the
 * {@code preferred_username} claim the authorization server propagates onto the token — so the federated
 * Keycloak identity is visible in the tool output, not just an opaque subject id.
 */
public record Note(
    String id,
    String text,
    String author,
    String createdAt
) {

}
