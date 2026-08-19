package com.splitexpense.auth.entity;

import jakarta.persistence.Column;
import jakarta.persistence.Entity;
import jakarta.persistence.FetchType;
import jakarta.persistence.GeneratedValue;
import jakarta.persistence.GenerationType;
import jakarta.persistence.Id;
import jakarta.persistence.JoinColumn;
import jakarta.persistence.ManyToOne;
import jakarta.persistence.Table;
import java.time.Instant;
import java.util.UUID;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.Setter;
import org.hibernate.annotations.CreationTimestamp;

/**
 * A server-side record of one issued refresh token.
 *
 * <p>Access tokens are deliberately stateless — any SplitExpense service can verify one with
 * the signing key alone — which also means they cannot be withdrawn before they expire.
 * Refresh tokens carry the opposite requirement: logout, a password change or a stolen
 * device must invalidate them immediately. That needs state, which is this table. The
 * {@code revoked} flag is the authoritative answer to "may this session continue?".
 */
@Entity
@Table(name = "refresh_tokens")
@Getter
@Setter
@Builder
@NoArgsConstructor
@AllArgsConstructor
public class RefreshToken {

    @Id
    @GeneratedValue(strategy = GenerationType.UUID)
    @Column(name = "id", nullable = false, updatable = false)
    private UUID id;

    @Column(name = "token", nullable = false, unique = true, length = 512)
    private String token;

    /**
     * Lazy: refreshing a token only needs the owner's id in the common path, and the
     * association is navigated explicitly when the new access token is minted.
     */
    @ManyToOne(fetch = FetchType.LAZY, optional = false)
    @JoinColumn(name = "user_id", nullable = false)
    private User user;

    @Column(name = "expiry_date", nullable = false)
    private Instant expiryDate;

    @Builder.Default
    @Column(name = "revoked", nullable = false)
    private boolean revoked = false;

    @CreationTimestamp
    @Column(name = "created_at", nullable = false, updatable = false)
    private Instant createdAt;

    /**
     * @return {@code true} once {@link #expiryDate} has passed
     */
    public boolean isExpired() {
        return Instant.now().isAfter(expiryDate);
    }

    /**
     * @return {@code true} when this token may still be exchanged for a new access token
     */
    public boolean isUsable() {
        return !revoked && !isExpired();
    }

    @Override
    public boolean equals(Object other) {
        if (this == other) {
            return true;
        }
        if (!(other instanceof RefreshToken refreshToken)) {
            return false;
        }
        return id != null && id.equals(refreshToken.id);
    }

    @Override
    public int hashCode() {
        return RefreshToken.class.hashCode();
    }
}
