package dev.lukasgrigis.blog.mcp.authorizationserver.security;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import java.util.Set;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * The role→scope contract — the heart of the federation's authorization. Offline; no Spring context.
 */
class RoleScopeMapperTest {

    private final RoleScopeMapper mapper = new RoleScopeMapper("user", "admin");

    @Test
    @DisplayName("the user role grants read + write only")
    void userRoleGrantsReadWrite() {
        assertThat(mapper.scopesFor(Set.of("user")))
            .containsExactlyInAnyOrder("note:read", "note:write");
    }

    @Test
    @DisplayName("the admin role inherits the user scopes and adds note:admin")
    void adminRoleGrantsEverything() {
        assertThat(mapper.scopesFor(Set.of("admin")))
            .containsExactlyInAnyOrder("note:read", "note:write", "note:admin");
    }

    @Test
    @DisplayName("an unknown role (or no role) grants nothing — the fail-closed input")
    void unknownRoleGrantsNothing() {
        assertThat(mapper.scopesFor(Set.of("guest"))).isEmpty();
        assertThat(mapper.scopesFor(Set.of())).isEmpty();
    }

}
