package dev.lukasgrigis.blog.mcp.mcpserver.configuration;

import jakarta.validation.constraints.NotEmpty;
import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.boot.context.properties.bind.DefaultValue;
import org.springframework.context.annotation.Bean;
import org.springframework.core.Ordered;
import org.springframework.core.annotation.Order;
import org.springframework.security.config.annotation.method.configuration.EnableMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configurers.AbstractHttpConfigurer;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.validation.annotation.Validated;
import org.springframework.web.cors.CorsConfigurationSource;

import static org.springaicommunity.mcp.security.server.config.McpServerOAuth2Configurer.mcpServerOAuth2;

@Validated
@ConfigurationProperties(prefix = "app.mcp.security")
record McpServerSecurityProperties(
    @NotEmpty String issuerUri,
    // RFC 8707 audience validation. ON by default: the authorization server stamps `aud` with the
    // `resource` indicator the client requested (AccessTokenClaimsConfiguration), and this checks that
    // `aud` contains this resource server — so a token minted for a different resource is rejected.
    // Set false only if you must accept clients that don't send a `resource` indicator.
    @DefaultValue("true") boolean validateAudience
) {

}

/**
 * The MCP server's resource-server security.
 *
 * <ul>
 *   <li><b>actuator</b> — public probes (used by the demo startup wait-loop).</li>
 *   <li><b>resource server</b> — every other request needs a valid bearer token. {@code mcpServerOAuth2()}
 *       wires JWKS-backed ES256 validation against the authorization server's issuer plus RFC 9728
 *       Protected Resource Metadata discovery (so a 401 carries the {@code WWW-Authenticate} pointer the
 *       MCP Inspector follows).</li>
 * </ul>
 *
 * <p><b>{@code @EnableMethodSecurity} is load-bearing:</b> without it the {@code @PreAuthorize} scope
 * gates on the tools are silently ignored and every authenticated caller can call every tool. CORS is
 * wired for the browser-based Inspector (see {@link CorsConfig}). The issuer's JWKS is resolved eagerly
 * at boot, so the authorization server must be running before this one starts.
 */
@org.springframework.context.annotation.Configuration
@EnableWebSecurity
@EnableMethodSecurity
@EnableConfigurationProperties(McpServerSecurityProperties.class)
class McpServerSecurityConfiguration {

    @Bean
    @Order(Ordered.HIGHEST_PRECEDENCE)
    SecurityFilterChain actuatorChain(HttpSecurity http) {
        return http
            .securityMatcher("/actuator/**")
            .authorizeHttpRequests(auth -> auth.anyRequest().permitAll())
            .csrf(AbstractHttpConfigurer::disable)
            .requestCache(AbstractHttpConfigurer::disable)
            .securityContext(AbstractHttpConfigurer::disable)
            .sessionManagement(sm -> sm.sessionCreationPolicy(SessionCreationPolicy.STATELESS))
            .build();
    }

    @Bean
    SecurityFilterChain mcpResourceServerChain(
        HttpSecurity http,
        McpServerSecurityProperties properties,
        CorsConfigurationSource corsConfigurationSource
    ) {
        return http
            .csrf(AbstractHttpConfigurer::disable)
            .cors(cors -> cors.configurationSource(corsConfigurationSource))
            .sessionManagement(sm -> sm.sessionCreationPolicy(SessionCreationPolicy.STATELESS))
            .authorizeHttpRequests(auth -> auth.anyRequest().authenticated())
            .with(
                mcpServerOAuth2(),
                mcp -> mcp.authorizationServer(properties.issuerUri())
                    .validateAudienceClaim(properties.validateAudience())
            )
            .build();
    }

}
