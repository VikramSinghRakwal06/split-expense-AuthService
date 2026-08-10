package com.payflow.auth.repository;

import com.payflow.auth.entity.RefreshToken;
import com.payflow.auth.entity.User;
import java.time.Instant;
import java.util.Optional;
import java.util.UUID;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Modifying;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;
import org.springframework.stereotype.Repository;

/**
 * Persistence access for {@link RefreshToken}, the revocation state behind otherwise
 * stateless JWT authentication.
 */
@Repository
public interface RefreshTokenRepository extends JpaRepository<RefreshToken, UUID> {

    /**
     * Loads a token together with its owner, so validating a refresh and minting the
     * next access token costs one query rather than two.
     *
     * @param token opaque refresh token value presented by the client
     * @return the stored token, if it was ever issued
     */
    @Query("SELECT rt FROM RefreshToken rt JOIN FETCH rt.user WHERE rt.token = :token")
    Optional<RefreshToken> findByTokenWithUser(@Param("token") String token);

    /**
     * @param token opaque refresh token value
     * @return the stored token, without eagerly loading the owner
     */
    Optional<RefreshToken> findByToken(String token);

    /**
     * Revokes every live token belonging to a user — the "sign out everywhere" action,
     * and the correct response to a password change or a suspected compromise.
     *
     * @param user owner whose sessions should end
     * @return number of tokens revoked
     */
    @Modifying(clearAutomatically = true, flushAutomatically = true)
    @Query("UPDATE RefreshToken rt SET rt.revoked = true WHERE rt.user = :user AND rt.revoked = false")
    int revokeAllForUser(@Param("user") User user);

    /**
     * Housekeeping for tokens that are past their expiry and can no longer be used,
     * so the table does not grow without bound.
     *
     * @param cutoff delete tokens that expired before this instant
     * @return number of rows removed
     */
    @Modifying
    @Query("DELETE FROM RefreshToken rt WHERE rt.expiryDate < :cutoff")
    int deleteExpiredBefore(@Param("cutoff") Instant cutoff);
}
