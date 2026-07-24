package dev.lukasgrigis.blog.mcp.authorizationserver.configuration;

import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.boot.context.properties.bind.DefaultValue;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.web.cors.CorsConfiguration;
import org.springframework.web.cors.CorsConfigurationSource;
import org.springframework.web.cors.UrlBasedCorsConfigurationSource;

import java.util.List;

@ConfigurationProperties("app.cors")
record CorsProperties(
    @DefaultValue("http://localhost:6274") List<String> allowedOrigins
) {

}

/**
 * CORS for the browser-based MCP Inspector.
 *
 * <p>The Inspector is a web app (origin {@code http://localhost:6274}) that makes <em>direct</em>
 * browser fetches to this server's discovery and token endpoints during the OAuth flow. Without
 * these headers the browser blocks them and the authorization-code + PKCE dance never completes.
 * Demo-only — a same-origin or non-browser client would not need this; do not ship a wide-open CORS
 * policy to production.
 */
@Configuration
@EnableConfigurationProperties(CorsProperties.class)
class CorsConfig {

    // Bean name matches the chain methods' parameter name so it resolves past Spring MVC's own
    // CorsConfigurationSource (mvcHandlerMappingIntrospector) without an explicit @Qualifier.
    @Bean
    CorsConfigurationSource corsConfigurationSource(CorsProperties properties) {
        final var cors = new CorsConfiguration();
        cors.setAllowedOrigins(properties.allowedOrigins());
        cors.setAllowedMethods(List.of("GET", "POST", "OPTIONS", "HEAD"));
        cors.setAllowedHeaders(List.of("*"));
        cors.setExposedHeaders(List.of("WWW-Authenticate"));
        cors.setAllowCredentials(false);
        cors.setMaxAge(3600L);

        final var source = new UrlBasedCorsConfigurationSource();
        source.registerCorsConfiguration("/**", cors);
        return source;
    }

}
