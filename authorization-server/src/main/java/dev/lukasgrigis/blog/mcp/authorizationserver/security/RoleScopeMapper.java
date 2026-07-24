package dev.lukasgrigis.blog.mcp.authorizationserver.security;

import jakarta.validation.constraints.NotEmpty;
import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.boot.context.properties.bind.DefaultValue;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.validation.annotation.Validated;

import java.util.Set;
import java.util.TreeSet;

/**
 * The role&rarr;scope contract: the single place that turns the coarse realm roles the upstream IdP
 * assigns into the fine-grained {@code resource:action} scopes the MCP tools are gated on.
 *
 * <p>The upstream IdP (Keycloak here) only authenticates the human and hands out a couple of broad realm
 * roles; it does not know about {@code note:read} / {@code note:write} / {@code note:admin}. This
 * authorization server mints those scopes, expanding the roles below at token time (see
 * {@code ScopeMappingConfiguration}).
 *
 * <p><strong>The scopes are a fixed API contract</strong> ({@code static final}); only the <em>role
 * names</em> are configurable (constructor args, bound from {@code app.security.roles.*} via
 * {@link SecurityRolesProperties}). Pointing those names at whatever roles a new IdP assigns is the first
 * swap seam. A second IdP that delivers its roles under a different claim than the flat {@code roles} claim
 * this demo reads (e.g. Entra ID's {@code roles}/{@code groups} with its own shape) also needs the claim
 * reader in {@code ScopeMappingConfiguration} adjusted — config for the role <em>names</em>, a small code
 * change for the claim <em>shape</em>.
 */
public final class RoleScopeMapper {

    /**
     * Scopes granted to any authenticated user.
     */
    public static final Set<String> USER_SCOPES = Set.of(
        "note:read",
        "note:write"
    );

    /**
     * Additional scopes granted only to admins.
     */
    public static final Set<String> ADMIN_SCOPES = Set.of(
        "note:admin"
    );

    private final String userRole;
    private final String adminRole;

    public RoleScopeMapper(String userRole, String adminRole) {
        this.userRole = userRole;
        this.adminRole = adminRole;
    }

    /**
     * Expand upstream realm roles into the scopes they grant. The admin role inherits the user scopes.
     * Returns a sorted (deterministic) set so minted claims don't reorder between requests.
     */
    public Set<String> scopesFor(Set<String> roles) {
        Set<String> scopes = new TreeSet<>();
        if (roles.contains(userRole) || roles.contains(adminRole)) {
            scopes.addAll(USER_SCOPES);
        }
        if (roles.contains(adminRole)) {
            scopes.addAll(ADMIN_SCOPES);
        }
        return scopes;
    }

}

/**
 * Binds the configurable upstream realm-role names. Only the role <em>names</em> are configurable — the
 * scopes are a fixed contract (see {@link RoleScopeMapper}). Match these names to whatever roles the
 * deployed IdP assigns; if that IdP delivers roles under a different claim than the flat {@code roles}
 * claim, also adjust the reader in {@code ScopeMappingConfiguration} (see {@link RoleScopeMapper} for the
 * two swap seams). Defaults match the Keycloak realm roles provisioned in {@code support/keycloak}.
 */
@Validated
@ConfigurationProperties("app.security.roles")
record SecurityRolesProperties(
    @DefaultValue("user") @NotEmpty String userRole,
    @DefaultValue("admin") @NotEmpty String adminRole
) {

}

/**
 * Exposes the {@link RoleScopeMapper} as a bean, built from the configured role names. Component-scanned
 * (this package sits under the {@code @SpringBootApplication} base package), so it needs no explicit import.
 */
@Configuration(proxyBeanMethods = false)
@EnableConfigurationProperties(SecurityRolesProperties.class)
class RoleScopeMapperConfiguration {

    @Bean
    RoleScopeMapper roleScopeMapper(SecurityRolesProperties properties) {
        return new RoleScopeMapper(properties.userRole(), properties.adminRole());
    }

}
