package dev.lukasgrigis.blog.mcp.authorizationserver.configuration;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.core.Authentication;
import org.springframework.security.oauth2.core.endpoint.OAuth2AuthorizationRequest;
import org.springframework.security.oauth2.core.oidc.user.OidcUser;
import org.springframework.security.oauth2.server.authorization.OAuth2Authorization;
import org.springframework.security.oauth2.server.authorization.OAuth2TokenType;
import org.springframework.security.oauth2.server.authorization.token.JwtEncodingContext;
import org.springframework.security.oauth2.server.authorization.token.OAuth2TokenCustomizer;

import java.util.List;
import java.util.Optional;

/**
 * Shapes every access token with the two things the MCP resource server needs beyond the scopes
 * ({@link ScopeMappingConfiguration} handles those):
 *
 * <ul>
 *   <li><b>Identity</b> — copies {@code preferred_username} / {@code email} / {@code name} off the upstream
 *       {@link OidcUser}, so {@code whoami} and note authorship show the human, not the bare subject id.</li>
 *   <li><b>Audience (RFC 8707)</b> — stamps {@code aud} with the {@code resource} the client requested
 *       (instead of Spring's default {@code aud = client_id}), so the resource server rejects a token minted
 *       for a different resource.</li>
 * </ul>
 *
 * <p>Runs as a second access-token customizer alongside the scope and ES256-header customizers; the
 * {@code mcp-authorization-server} library applies all of them.
 */
@Configuration
class AccessTokenClaimsConfiguration {

    private static void copyIdentity(JwtEncodingContext context) {
        Authentication principal = context.getPrincipal();
        if (principal != null && principal.getPrincipal() instanceof OidcUser user) {
            claim(context, "preferred_username", user.getPreferredUsername());
            claim(context, "email", user.getEmail());
            claim(context, "name", user.getFullName());
        }
    }

    private static void bindAudience(JwtEncodingContext context) {
        OAuth2Authorization authorization = context.getAuthorization();
        OAuth2AuthorizationRequest request = (OAuth2AuthorizationRequest) Optional.ofNullable(authorization)
            .map(auth -> auth.getAttribute(OAuth2AuthorizationRequest.class.getName()))
            .orElse(null);
        if (request != null
            && request.getAdditionalParameters().get("resource") instanceof String resource
            && !resource.isBlank()) {
            context.getClaims().audience(List.of(resource));
        }
    }

    private static void claim(JwtEncodingContext context, String name, String value) {
        if (value != null && !value.isBlank()) {
            context.getClaims().claim(name, value);
        }
    }

    @Bean
    OAuth2TokenCustomizer<JwtEncodingContext> accessTokenClaimsCustomizer() {
        return context -> {
            if (!OAuth2TokenType.ACCESS_TOKEN.equals(context.getTokenType())) {
                return;
            }
            copyIdentity(context);
            bindAudience(context);
        };
    }

}
