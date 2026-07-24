package dev.lukasgrigis.blog.mcp.mcpserver.configuration;

import com.fasterxml.jackson.annotation.JsonIgnoreProperties;
import org.springframework.boot.jackson.autoconfigure.JsonMapperBuilderCustomizer;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

/**
 * Stops transport-layer errors from leaking the server's internals.
 *
 * <p>When a request fails inside Spring AI's {@code WebMvcStreamableServerTransportProvider} (e.g. a
 * {@code tools/call} with no {@code Mcp-Session-Id}), the transport serializes the
 * {@link io.modelcontextprotocol.spec.McpError} straight to the response with the application's Jackson&nbsp;3
 * {@code JsonMapper}. Because {@code McpError} is a {@link Throwable}, Jackson otherwise writes its
 * {@code stackTrace} / {@code cause} / {@code suppressed} — leaking the full server-side stack (class names,
 * line numbers, even the JDK version) to any caller.
 *
 * <p>This customizer adds a {@link Throwable} mix-in to the Boot-managed {@code JsonMapper} (the one the
 * transport is injected with), so a transport error returns just {@code {"jsonRpcError":{...},"message":"…"}}.
 * It hardens every JSON response, not only the MCP transport — you never want a stack trace on the wire.
 * Spring Boot&nbsp;4 uses Jackson&nbsp;3 ({@code tools.jackson}); there is no legacy {@code ObjectMapper} here.
 */
@Configuration(proxyBeanMethods = false)
class McpJsonMapperConfiguration {

    @Bean
    JsonMapperBuilderCustomizer noStackTraceJsonMapperCustomizer() {
        return builder -> builder.addMixIn(Throwable.class, NoStackTraceMixin.class);
    }

    @JsonIgnoreProperties({"stackTrace", "cause", "suppressed", "localizedMessage"})
    private abstract static class NoStackTraceMixin {

    }

}
