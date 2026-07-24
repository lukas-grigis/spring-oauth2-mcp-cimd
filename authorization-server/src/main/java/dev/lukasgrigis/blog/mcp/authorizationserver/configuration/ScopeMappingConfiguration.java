package dev.lukasgrigis.blog.mcp.authorizationserver.configuration;

import dev.lukasgrigis.blog.mcp.authorizationserver.security.RoleScopeMapper;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.core.Authentication;
import org.springframework.security.oauth2.core.endpoint.OAuth2ParameterNames;
import org.springframework.security.oauth2.core.oidc.user.OidcUser;
import org.springframework.security.oauth2.server.authorization.OAuth2TokenType;
import org.springframework.security.oauth2.server.authorization.token.JwtEncodingContext;
import org.springframework.security.oauth2.server.authorization.token.OAuth2TokenCustomizer;

import java.util.HashSet;
import java.util.List;
import java.util.Set;

/**
 * Stamps the {@code scope} claim on every access token from the caller's <em>upstream realm roles</em>,
 * not from what the client asked for. This is where federation becomes authorization: Keycloak says
 * "this human is a {@code user}", and {@link RoleScopeMapper} turns that into {@code note:read} /
 * {@code note:write}; the MCP server then reads those scopes as {@code SCOPE_*} authorities.
 */
@Configuration
class ScopeMappingConfiguration {

    private static final Logger log = LoggerFactory.getLogger(ScopeMappingConfiguration.class);

    private static Set<String> realmRoles(Authentication principal) {
        if (principal != null && principal.getPrincipal() instanceof OidcUser oidc) {
            List<String> roles = oidc.getClaimAsStringList("roles");
            if (roles != null) {
                return new HashSet<>(roles);
            }
        }
        return Set.of();
    }

    private static String principalName(Authentication principal) {
        return principal != null ? principal.getName() : "<none>";
    }

    @Bean
    OAuth2TokenCustomizer<JwtEncodingContext> mcpScopeTokenCustomizer(RoleScopeMapper roleScopeMapper) {
        return context -> {
            if (!OAuth2TokenType.ACCESS_TOKEN.equals(context.getTokenType())) {
                return;
            }
            final Set<String> roles = realmRoles(context.getPrincipal());
            final Set<String> granted = roleScopeMapper.scopesFor(roles);
            if (granted.isEmpty()) {
                // FAIL CLOSED: if we left the claim alone, Spring Authorization Server would stamp the
                // client's REQUESTED scopes — and under CIMD the client authors its own metadata document,
                // so requested scopes are attacker-suppliable. No mappable roles ⇒ no scopes.
                context.getClaims().claim(OAuth2ParameterNames.SCOPE, Set.of());
                log.warn(
                    "No mappable realm roles on principal '{}'; stamping an EMPTY scope claim (fail closed)",
                    principalName(context.getPrincipal())
                );
                return;
            }
            // Scope derives from the upstream roles, never from the client request, so the role set is
            // always the hard ceiling — stamp it directly.
            context.getClaims().claim(OAuth2ParameterNames.SCOPE, granted);
            log.debug(
                "MCP token for '{}': roles={} -> scopes={}",
                principalName(context.getPrincipal()), roles, granted
            );
        };
    }

}
