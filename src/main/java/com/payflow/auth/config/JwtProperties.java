package com.payflow.auth.config;

import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.NotNull;
import java.time.Duration;
import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.validation.annotation.Validated;

/**
 * Externalised JWT settings, bound from the {@code payflow.jwt.*} configuration prefix.
 *
 * <p>Nothing here has a compiled-in default. The dev fallbacks live in
 * {@code application.yml} as {@code ${JWT_SECRET:...}} placeholders; {@code
 * application-prod.yml} removes them, so a production start-up without a real secret
 * fails fast rather than signing tokens with a value from source control.
 *
 * @param secret                 HMAC-SHA signing key, at least 32 bytes for HS256
 * @param issuer                 value placed in the {@code iss} claim
 * @param accessTokenExpiration  lifetime of an access token
 * @param refreshTokenExpiration lifetime of a refresh token
 */
@Validated
@ConfigurationProperties(prefix = "payflow.jwt")
public record JwtProperties(

        @NotBlank(message = "payflow.jwt.secret must be set") String secret,

        @NotBlank(message = "payflow.jwt.issuer must be set") String issuer,

        @NotNull(message = "payflow.jwt.access-token-expiration must be set")
        Duration accessTokenExpiration,

        @NotNull(message = "payflow.jwt.refresh-token-expiration must be set")
        Duration refreshTokenExpiration) {

    /** HS256 requires a key of at least 256 bits; anything shorter is rejected by JJWT. */
    private static final int MINIMUM_SECRET_BYTES = 32;

    public JwtProperties {
        if (secret != null && secret.getBytes(java.nio.charset.StandardCharsets.UTF_8).length
                < MINIMUM_SECRET_BYTES) {
            throw new IllegalArgumentException(
                    "payflow.jwt.secret must be at least " + MINIMUM_SECRET_BYTES
                            + " bytes for HS256 signing");
        }
    }

    /**
     * @return access token lifetime in seconds, for the {@code expiresIn} field clients
     *         use to refresh ahead of expiry
     */
    public long accessTokenExpirationSeconds() {
        return accessTokenExpiration.toSeconds();
    }
}
