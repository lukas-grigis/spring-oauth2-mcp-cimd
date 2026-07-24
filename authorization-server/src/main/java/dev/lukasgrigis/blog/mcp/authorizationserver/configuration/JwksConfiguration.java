package dev.lukasgrigis.blog.mcp.authorizationserver.configuration;

import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.jwk.Curve;
import com.nimbusds.jose.jwk.ECKey;
import com.nimbusds.jose.jwk.JWK;
import com.nimbusds.jose.jwk.JWKSet;
import com.nimbusds.jose.jwk.KeyUse;
import com.nimbusds.jose.jwk.gen.ECKeyGenerator;
import com.nimbusds.jose.jwk.source.ImmutableJWKSet;
import com.nimbusds.jose.jwk.source.JWKSource;
import com.nimbusds.jose.proc.SecurityContext;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.boot.context.properties.bind.DefaultValue;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.oauth2.jose.jws.SignatureAlgorithm;
import org.springframework.security.oauth2.server.authorization.token.JwtEncodingContext;
import org.springframework.security.oauth2.server.authorization.token.OAuth2TokenCustomizer;

@ConfigurationProperties(prefix = "app.security.jwt")
record JwksProperties(
    @DefaultValue("") String signingKeyPem
) {

}

/**
 * ES256 signing for the access tokens this server mints. Spring Authorization Server defaults to RS256,
 * so getting ES256 working takes <strong>three</strong> coordinated pieces; this class owns two of them
 * (the EC key and the per-token JWS header), the third — advertising ES256 in the OIDC metadata — lives
 * in {@code WebSecurityConfiguration}. Drop any one and the server silently mints RS256 with no matching
 * key, and every token is rejected by the MCP resource server.
 */
@Configuration
@EnableConfigurationProperties(JwksProperties.class)
class JwksConfiguration {

    private static final Logger log = LoggerFactory.getLogger(JwksConfiguration.class);

    private static ECKey generateEphemeralKey() throws Exception {
        log.warn("app.security.jwt.signing-key-pem is not set — generating an ephemeral ES256 key. " +
            "Tokens (and the resource server's cached JWKS) will not survive a restart.");
        return new ECKeyGenerator(Curve.P_256)
            .keyUse(KeyUse.SIGNATURE)
            .algorithm(JWSAlgorithm.ES256)
            .keyIDFromThumbprint(true)
            .generate();
    }

    private static ECKey loadFromPem(String pem) throws Exception {
        // Needs BouncyCastle (bcpkix) to parse the SEC1 "EC PRIVATE KEY" PEM.
        final var parsed = JWK.parseFromPEMEncodedObjects(pem).toECKey();
        return new ECKey.Builder(parsed)
            .keyID(parsed.computeThumbprint().toString())
            .keyUse(KeyUse.SIGNATURE)
            .algorithm(JWSAlgorithm.ES256)
            .build();
    }

    /**
     * Piece 1: a single EC P-256 key in the JWKS (served at /oauth2/jwks for the resource server).
     */
    @Bean
    JWKSource<SecurityContext> jwkSource(JwksProperties properties) throws Exception {
        final var pem = properties.signingKeyPem();
        final var ecKey = pem.isBlank() ? generateEphemeralKey() : loadFromPem(pem);
        return new ImmutableJWKSet<>(new JWKSet(ecKey));
    }

    /**
     * Piece 2: force the JWS header to ES256 — without it JwtGenerator defaults to RS256 (no key).
     */
    @Bean
    OAuth2TokenCustomizer<JwtEncodingContext> es256JwsHeaderCustomizer() {
        return context -> context.getJwsHeader().algorithm(SignatureAlgorithm.ES256);
    }

}
