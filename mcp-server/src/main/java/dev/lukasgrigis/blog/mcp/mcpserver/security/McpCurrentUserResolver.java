package dev.lukasgrigis.blog.mcp.mcpserver.security;

import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.oauth2.jwt.Jwt;

import java.util.List;
import java.util.Objects;

/**
 * Reads the authenticated caller off the security context.
 *
 * <p>MCP tool methods are not controllers, so there is no {@code @AuthenticationPrincipal} injection
 * point — the validated {@link Jwt} (placed there by the {@code mcp-server-security} resource-server
 * filter before the tool runs) is read from the {@link SecurityContextHolder} instead. The token was
 * minted by the authorization server (:9000): {@code sub} is the upstream Keycloak subject, and the
 * {@code SCOPE_*} authorities are the scopes mapped from the upstream realm roles.
 */
public class McpCurrentUserResolver {

    public CurrentUser currentUser() {
        Authentication auth = SecurityContextHolder.getContext().getAuthentication();
        if (auth == null || !auth.isAuthenticated()) {
            throw new IllegalStateException("No authenticated MCP principal in the security context");
        }
        String subject = auth.getName();
        String username = null;
        String email = null;
        if (auth.getPrincipal() instanceof Jwt jwt) {
            subject = jwt.getSubject();
            username = jwt.getClaimAsString("preferred_username");
            email = jwt.getClaimAsString("email");
        }
        List<String> scopes = auth.getAuthorities().stream()
            .map(GrantedAuthority::getAuthority)
            .filter(Objects::nonNull)
            .filter(a -> a.startsWith("SCOPE_"))
            .map(a -> a.substring("SCOPE_".length()))
            .sorted()
            .toList();
        return new CurrentUser(subject, username, email, scopes);
    }

    /**
     * The authenticated caller, distilled to what the demo tools need.
     */
    public record CurrentUser(String subject, String username, String email, List<String> scopes) {

        /**
         * A human-friendly name for the note author: the username, falling back to the subject.
         */
        public String displayName() {
            return (username != null && !username.isBlank()) ? username : subject;
        }

    }

}
