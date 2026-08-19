package com.splitexpense.auth.security;

import com.splitexpense.auth.entity.User;
import java.util.Collection;
import java.util.List;
import java.util.UUID;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;

/**
 * Adapts a {@link User} entity to Spring Security's {@link UserDetails} contract.
 *
 * <p>Exists so the entity itself stays a plain JPA type with no framework interface
 * bolted on, and so controllers can reach the authenticated user's id without a second
 * database round trip.
 *
 * @param user the account this principal represents
 */
public record UserPrincipal(User user) implements UserDetails {

    /**
     * @return the account's surrogate id
     */
    public UUID getId() {
        return user.getId();
    }

    @Override
    public Collection<? extends GrantedAuthority> getAuthorities() {
        return List.of(new SimpleGrantedAuthority(user.getRole().authority()));
    }

    @Override
    public String getPassword() {
        return user.getPasswordHash();
    }

    /** SplitExpense logs users in by email, so email is the Spring Security username. */
    @Override
    public String getUsername() {
        return user.getEmail();
    }

    /** SplitExpense models only one disabled state; expiry and lockout are not tracked. */
    @Override
    public boolean isAccountNonExpired() {
        return true;
    }

    @Override
    public boolean isAccountNonLocked() {
        return true;
    }

    @Override
    public boolean isCredentialsNonExpired() {
        return true;
    }

    @Override
    public boolean isEnabled() {
        return user.isEnabled();
    }
}
