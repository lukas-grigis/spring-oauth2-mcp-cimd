package dev.lukasgrigis.blog.mcp.mcpserver.configuration;

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
 * CORS for the browser-based MCP Inspector (origin {@code http://localhost:6274}). The Inspector fetches
 * Protected Resource Metadata and posts to {@code /mcp} directly from the browser, and reads the streaming
 * session header back — so {@code Mcp-Session-Id} / {@code Last-Event-ID} are allowed and
 * {@code WWW-Authenticate} / {@code Mcp-Session-Id} are exposed. Demo-only; a non-browser client (Claude
 * Code, etc.) would not need this.
 */
@Configuration
@EnableConfigurationProperties(CorsProperties.class)
class CorsConfig {

    @Bean
    CorsConfigurationSource corsConfigurationSource(CorsProperties properties) {
        final var cors = new CorsConfiguration();
        cors.setAllowedOrigins(properties.allowedOrigins());
        cors.setAllowedMethods(List.of("GET", "POST", "OPTIONS", "HEAD"));
        cors.setAllowedHeaders(List.of("Authorization", "Content-Type", "Mcp-Session-Id", "Last-Event-ID", "Accept"));
        cors.setExposedHeaders(List.of("WWW-Authenticate", "Mcp-Session-Id"));
        cors.setAllowCredentials(false);
        cors.setMaxAge(3600L);

        final var source = new UrlBasedCorsConfigurationSource();
        source.registerCorsConfiguration("/**", cors);
        return source;
    }

}
