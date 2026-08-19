package com.splitexpense.auth.security;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import com.splitexpense.auth.config.JwtProperties;
import com.splitexpense.auth.entity.Role;
import com.splitexpense.auth.entity.User;
import io.jsonwebtoken.Claims;
import io.jsonwebtoken.JwtException;
import java.time.Duration;
import java.util.UUID;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

/**
 * Unit tests for token minting and verification. No Spring context: the service takes
 * only its properties, so it can be built directly.
 */
class JwtServiceTest {

    private static final String SECRET = "test-secret-that-is-definitely-long-enough-for-hs256";
    private static final String ISSUER = "splitexpense-auth-test";

    private JwtService jwtService;
    private User user;

    @BeforeEach
    void setUp() {
        jwtService = new JwtService(properties(Duration.ofMinutes(15), Duration.ofDays(7)));
        user = User.builder()
                .id(UUID.randomUUID())
                .email("ada@splitexpense.io")
                .passwordHash("irrelevant")
                .fullName("Ada Lovelace")
                .role(Role.USER)
                .enabled(true)
                .build();
    }

    private JwtProperties properties(Duration accessTtl, Duration refreshTtl) {
        return new JwtProperties(SECRET, ISSUER, accessTtl, refreshTtl);
    }

    @Test
    @DisplayName("access token carries the email as subject")
    void accessTokenSubjectIsEmail() {
        String token = jwtService.generateAccessToken(user);

        assertThat(jwtService.extractUsername(token)).isEqualTo("ada@splitexpense.io");
    }

    @Test
    @DisplayName("access token carries the user id and role for downstream services")
    void accessTokenCarriesIdAndRole() {
        String token = jwtService.generateAccessToken(user);

        String uid = jwtService.extractClaim(token, c -> c.get(JwtService.CLAIM_USER_ID, String.class));
        String role = jwtService.extractClaim(token, c -> c.get(JwtService.CLAIM_ROLE, String.class));
        String issuer = jwtService.extractClaim(token, Claims::getIssuer);

        assertThat(uid).isEqualTo(user.getId().toString());
        assertThat(role).isEqualTo("USER");
        assertThat(issuer).isEqualTo(ISSUER);
    }

    @Test
    @DisplayName("refresh token is marked as such and carries no role")
    void refreshTokenHasNoRole() {
        String token = jwtService.generateRefreshToken(user);

        String role = jwtService.extractClaim(token, c -> c.get(JwtService.CLAIM_ROLE, String.class));

        assertThat(jwtService.isRefreshToken(token)).isTrue();
        assertThat(jwtService.isAccessToken(token)).isFalse();
        assertThat(role).isNull();
    }

    @Test
    @DisplayName("a valid access token authenticates its own subject")
    void validAccessTokenIsAccepted() {
        String token = jwtService.generateAccessToken(user);

        assertThat(jwtService.isTokenValid(token, new UserPrincipal(user))).isTrue();
    }

    @Test
    @DisplayName("a refresh token is rejected as a bearer credential")
    void refreshTokenIsNotAValidAccessToken() {
        String refreshToken = jwtService.generateRefreshToken(user);

        // The whole point of the type claim: a stolen 7-day refresh token must not work
        // as an access token against the rest of the platform.
        assertThat(jwtService.isTokenValid(refreshToken, new UserPrincipal(user))).isFalse();
    }

    @Test
    @DisplayName("a token belonging to another account is rejected")
    void tokenForDifferentSubjectIsRejected() {
        String token = jwtService.generateAccessToken(user);

        User other = User.builder()
                .id(UUID.randomUUID())
                .email("grace@splitexpense.io")
                .passwordHash("irrelevant")
                .fullName("Grace Hopper")
                .role(Role.USER)
                .enabled(true)
                .build();

        assertThat(jwtService.isTokenValid(token, new UserPrincipal(other))).isFalse();
    }

    @Test
    @DisplayName("a token for a disabled account is rejected")
    void tokenForDisabledAccountIsRejected() {
        String token = jwtService.generateAccessToken(user);
        user.setEnabled(false);

        assertThat(jwtService.isTokenValid(token, new UserPrincipal(user))).isFalse();
    }

    @Test
    @DisplayName("an expired token is rejected rather than throwing")
    void expiredTokenIsRejected() {
        JwtService shortLived =
                new JwtService(properties(Duration.ofSeconds(-1), Duration.ofDays(7)));
        String token = shortLived.generateAccessToken(user);

        assertThat(shortLived.isTokenValid(token, new UserPrincipal(user))).isFalse();
        assertThat(shortLived.isAccessToken(token)).isFalse();
    }

    @Test
    @DisplayName("a token signed with a different key is rejected")
    void tokenSignedWithAnotherKeyIsRejected() {
        String foreignToken = new JwtService(new JwtProperties(
                        "a-completely-different-secret-key-of-sufficient-length",
                        ISSUER,
                        Duration.ofMinutes(15),
                        Duration.ofDays(7)))
                .generateAccessToken(user);

        assertThat(jwtService.isTokenValid(foreignToken, new UserPrincipal(user))).isFalse();
        assertThatThrownBy(() -> jwtService.extractUsername(foreignToken))
                .isInstanceOf(JwtException.class);
    }

    @Test
    @DisplayName("a token from another issuer is rejected even with the same key")
    void tokenFromAnotherIssuerIsRejected() {
        String foreignToken = new JwtService(
                        new JwtProperties(SECRET, "some-other-service",
                                Duration.ofMinutes(15), Duration.ofDays(7)))
                .generateAccessToken(user);

        assertThat(jwtService.isTokenValid(foreignToken, new UserPrincipal(user))).isFalse();
    }

    @Test
    @DisplayName("garbage input is rejected without leaking an exception")
    void malformedTokenIsRejected() {
        assertThat(jwtService.isTokenValid("not-a-jwt", new UserPrincipal(user))).isFalse();
        assertThat(jwtService.isAccessToken("")).isFalse();
    }

    @Test
    @DisplayName("two tokens minted in the same second are still distinct")
    void tokensAreUniquePerIssue() {
        // Every other claim is identical within a second, so only the jti separates them.
        // Refresh rotation stores the token value under a unique constraint and would
        // fail on a collision.
        assertThat(jwtService.generateRefreshToken(user))
                .isNotEqualTo(jwtService.generateRefreshToken(user));
        assertThat(jwtService.generateAccessToken(user))
                .isNotEqualTo(jwtService.generateAccessToken(user));
    }

    @Test
    @DisplayName("expiry helpers reflect the configured lifetimes")
    void expiryHelpers() {
        assertThat(jwtService.accessTokenExpirationSeconds()).isEqualTo(900);
        assertThat(jwtService.refreshTokenExpiryFromNow()).isAfter(java.time.Instant.now());
    }

    @Test
    @DisplayName("a secret shorter than 32 bytes is refused at construction")
    void shortSecretIsRefused() {
        assertThatThrownBy(() -> new JwtProperties(
                        "too-short", ISSUER, Duration.ofMinutes(15), Duration.ofDays(7)))
                .isInstanceOf(IllegalArgumentException.class)
                .hasMessageContaining("at least 32 bytes");
    }
}
