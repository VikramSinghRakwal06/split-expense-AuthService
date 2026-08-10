package com.payflow.auth.security;

import com.payflow.auth.config.JwtProperties;
import com.payflow.auth.entity.User;
import io.jsonwebtoken.Claims;
import io.jsonwebtoken.JwtException;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.security.Keys;
import java.nio.charset.StandardCharsets;
import java.time.Instant;
import java.util.Date;
import java.util.Map;
import java.util.UUID;
import java.util.function.Function;
import javax.crypto.SecretKey;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.stereotype.Service;

/**
 * Mints and verifies the JSON Web Tokens that carry a PayFlow session.
 *
 * <h2>Why there are two kinds of token</h2>
 *
 * <p>An <strong>access token</strong> is a self-contained, signed statement of who the
 * caller is. Every other PayFlow service (wallet, payments, ledger, notifications) can
 * verify one using the shared signing key alone — no network call back to auth-service,
 * which is exactly what makes the platform horizontally scalable. The cost of that
 * independence is that an access token cannot be withdrawn: nobody asks us whether it is
 * still valid, so it stays good until its {@code exp} passes. Its lifetime is therefore
 * kept deliberately short (15 minutes by default) to bound the damage from a leaked one.
 *
 * <p>A <strong>refresh token</strong> solves the opposite problem. Logging out, changing
 * a password or losing a device must end a session <em>now</em>, which requires state
 * that a stateless token cannot provide. Refresh tokens are consequently written to the
 * {@code refresh_tokens} table and checked against it on every use, so revocation is
 * real. They live for 7 days but are only ever presented to this one service, on one
 * endpoint.
 *
 * <p>The two are distinguished by a {@code type} claim and are <em>not</em>
 * interchangeable: {@link #isAccessToken(String)} is what stops a stolen 7-day refresh
 * token from being replayed as a bearer credential against the rest of the platform.
 *
 * <h2>Request flow</h2>
 *
 * <ol>
 *   <li>{@code /login} verifies the password, then calls
 *       {@link #generateAccessToken(User)} and {@link #generateRefreshToken(User)}.</li>
 *   <li>The client sends the access token as {@code Authorization: Bearer <token>};
 *       {@link JwtAuthenticationFilter} validates it on every request.</li>
 *   <li>When it expires, {@code /refresh} exchanges the persisted refresh token for a
 *       fresh access token, provided the stored row is neither expired nor revoked.</li>
 *   <li>{@code /logout} sets {@code revoked} on that row, ending the ability to
 *       refresh.</li>
 * </ol>
 */
@Service
public class JwtService {

    /** Claim naming the token's purpose, so the two kinds cannot be swapped. */
    static final String CLAIM_TYPE = "type";

    /** Claim carrying the user's surrogate id, so downstream services need no lookup. */
    static final String CLAIM_USER_ID = "uid";

    /** Claim carrying the authorisation role. */
    static final String CLAIM_ROLE = "role";

    static final String TYPE_ACCESS = "access";
    static final String TYPE_REFRESH = "refresh";

    private final JwtProperties properties;
    private final SecretKey signingKey;

    public JwtService(JwtProperties properties) {
        this.properties = properties;
        this.signingKey = Keys.hmacShaKeyFor(
                properties.secret().getBytes(StandardCharsets.UTF_8));
    }

    /**
     * Mints a short-lived credential for calling PayFlow APIs.
     *
     * <p>The subject is the user's email (the login identifier), with id and role carried
     * as extra claims so a resource service can authorise a request without querying
     * auth-service.
     *
     * @param user authenticated account
     * @return a signed, compact JWT
     */
    public String generateAccessToken(User user) {
        return buildToken(
                user,
                TYPE_ACCESS,
                properties.accessTokenExpiration().toMillis(),
                Map.of(
                        CLAIM_USER_ID, user.getId().toString(),
                        CLAIM_ROLE, user.getRole().name()));
    }

    /**
     * Mints the long-lived token used only to obtain new access tokens.
     *
     * <p>Carries no role claim: it confers no authority by itself, and is worthless
     * unless the matching row in {@code refresh_tokens} is still active.
     *
     * @param user authenticated account
     * @return a signed, compact JWT
     */
    public String generateRefreshToken(User user) {
        return buildToken(
                user,
                TYPE_REFRESH,
                properties.refreshTokenExpiration().toMillis(),
                Map.of(CLAIM_USER_ID, user.getId().toString()));
    }

    /**
     * @param token signed JWT
     * @return the {@code sub} claim, which for PayFlow is the user's email
     * @throws JwtException if the token is malformed, expired or incorrectly signed
     */
    public String extractUsername(String token) {
        return extractClaim(token, Claims::getSubject);
    }

    /**
     * Reads one claim from a token, verifying the signature first.
     *
     * @param token    signed JWT
     * @param resolver picks the wanted value out of the verified claim set
     * @param <T>      claim type
     * @return the resolved claim value
     * @throws JwtException if the token is malformed, expired or incorrectly signed
     */
    public <T> T extractClaim(String token, Function<Claims, T> resolver) {
        return resolver.apply(parseClaims(token));
    }

    /**
     * Full check applied to every authenticated request: the signature and expiry must
     * hold, the token must be an access token rather than a refresh token, and the
     * subject must match the account the filter resolved.
     *
     * @param token       bearer token from the request
     * @param userDetails account loaded for the token's subject
     * @return {@code true} if the token may authenticate this user right now
     */
    public boolean isTokenValid(String token, UserDetails userDetails) {
        try {
            Claims claims = parseClaims(token);
            return TYPE_ACCESS.equals(claims.get(CLAIM_TYPE, String.class))
                    && userDetails.getUsername().equals(claims.getSubject())
                    && userDetails.isEnabled();
        } catch (JwtException | IllegalArgumentException ex) {
            // Parsing already rejects bad signatures and expired tokens; treat any
            // failure as "not valid" rather than letting it escape as a 500.
            return false;
        }
    }

    /**
     * @param token signed JWT
     * @return {@code true} if the token is a well-formed, unexpired access token
     */
    public boolean isAccessToken(String token) {
        try {
            return TYPE_ACCESS.equals(parseClaims(token).get(CLAIM_TYPE, String.class));
        } catch (JwtException | IllegalArgumentException ex) {
            return false;
        }
    }

    /**
     * @param token signed JWT
     * @return {@code true} if the token is a well-formed, unexpired refresh token
     */
    public boolean isRefreshToken(String token) {
        try {
            return TYPE_REFRESH.equals(parseClaims(token).get(CLAIM_TYPE, String.class));
        } catch (JwtException | IllegalArgumentException ex) {
            return false;
        }
    }

    /**
     * @return when the refresh token issued now will expire, for the persisted row
     */
    public Instant refreshTokenExpiryFromNow() {
        return Instant.now().plus(properties.refreshTokenExpiration());
    }

    /**
     * @return access token lifetime in seconds, for the {@code expiresIn} response field
     */
    public long accessTokenExpirationSeconds() {
        return properties.accessTokenExpirationSeconds();
    }

    private String buildToken(User user, String type, long ttlMillis, Map<String, String> claims) {
        Date issuedAt = new Date();
        Date expiration = new Date(issuedAt.getTime() + ttlMillis);
        return Jwts.builder()
                // Without a unique jti, two tokens minted for the same user inside the
                // same second are byte-identical, because every other claim matches.
                // Refresh rotation would then try to store a duplicate token value.
                .id(UUID.randomUUID().toString())
                .subject(user.getEmail())
                .issuer(properties.issuer())
                .issuedAt(issuedAt)
                .expiration(expiration)
                .claims(claims)
                .claim(CLAIM_TYPE, type)
                .signWith(signingKey)
                .compact();
    }

    /**
     * Verifies signature, expiry and issuer in one step. Requiring the issuer means a
     * correctly signed token minted by a different PayFlow environment sharing a key is
     * still rejected here.
     */
    private Claims parseClaims(String token) {
        return Jwts.parser()
                .verifyWith(signingKey)
                .requireIssuer(properties.issuer())
                .build()
                .parseSignedClaims(token)
                .getPayload();
    }
}
