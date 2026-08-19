package com.splitexpense.auth.entity;

/**
 * Authorisation role granted to a {@link User}.
 *
 * <p>Persisted as its {@code name()} string, and mirrored by the
 * {@code ck_users_role} check constraint in {@code V1__create_users_and_refresh_tokens.sql}.
 * Adding a constant here therefore requires a migration that widens that constraint.
 */
public enum Role {

    /** Standard wallet holder. */
    USER,

    /** SplitExpense operator with elevated privileges. */
    ADMIN;

    /**
     * @return the Spring Security authority name for this role, e.g. {@code ROLE_ADMIN}
     */
    public String authority() {
        return "ROLE_" + name();
    }
}
