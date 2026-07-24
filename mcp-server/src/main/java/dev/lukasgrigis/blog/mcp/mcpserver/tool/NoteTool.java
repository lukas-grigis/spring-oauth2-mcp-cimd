package dev.lukasgrigis.blog.mcp.mcpserver.tool;

import dev.lukasgrigis.blog.mcp.mcpserver.security.McpCurrentUserResolver;
import org.springframework.ai.mcp.annotation.McpTool;
import org.springframework.ai.mcp.annotation.McpToolParam;
import org.springframework.security.access.prepost.PreAuthorize;

import java.time.Instant;
import java.util.List;
import java.util.UUID;
import java.util.concurrent.CopyOnWriteArrayList;

/**
 * The scope-gated demo surface: a trivial notes store whose three operations map one-to-one to the
 * three scopes the authorization server can mint. The allow/deny matrix across the test users is the
 * whole point — it is the live proof that the federated realm roles became enforced scopes:
 *
 * <pre>
 *   alice (realm role: user ) → note:read, note:write          → list + create, purge DENIED
 *   bob   (realm role: admin) → note:read, note:write, note:admin → list + create + purge
 * </pre>
 *
 * <p>Each {@code @PreAuthorize} runs in method security before the body. A token missing the scope
 * yields an {@code AccessDeniedException} that the MCP framework returns as a tool error (isError=true,
 * HTTP 200); a missing/invalid token is rejected earlier with a 401. The store is in-memory on purpose
 * — keep tool bodies synchronous (no {@code @Async}/executor/streaming) or the SecurityContext is lost.
 */
public class NoteTool {

    private final McpCurrentUserResolver currentUser;
    private final List<Note> notes = new CopyOnWriteArrayList<>();

    public NoteTool(McpCurrentUserResolver currentUser) {
        this.currentUser = currentUser;
    }

    @McpTool(name = "list_notes", description = "List all notes. Requires the note:read scope.",
        annotations = @McpTool.McpAnnotations(
            readOnlyHint = true, destructiveHint = false, idempotentHint = true, openWorldHint = false))
    @PreAuthorize("hasAuthority('SCOPE_note:read')")
    public List<Note> listNotes() {
        return List.copyOf(notes);
    }

    @McpTool(name = "create_note", description = "Create a note (recorded under your identity). Requires the note:write scope.",
        annotations = @McpTool.McpAnnotations(
            readOnlyHint = false, destructiveHint = false, idempotentHint = false, openWorldHint = false))
    @PreAuthorize("hasAuthority('SCOPE_note:write')")
    public Note createNote(
        @McpToolParam(description = "the note text") String text
    ) {
        Note note = new Note(
            UUID.randomUUID().toString(),
            text,
            currentUser.currentUser().displayName(),
            Instant.now().toString()
        );
        notes.add(note);
        return note;
    }

    @McpTool(name = "purge_notes", description = "Delete ALL notes. Admin-only — requires the note:admin scope.",
        annotations = @McpTool.McpAnnotations(
            readOnlyHint = false, destructiveHint = true, idempotentHint = false, openWorldHint = false))
    @PreAuthorize("hasAuthority('SCOPE_note:admin')")
    public String purgeNotes() {
        int removed = notes.size();
        notes.clear();
        return "purged " + removed + " note(s)";
    }

}
