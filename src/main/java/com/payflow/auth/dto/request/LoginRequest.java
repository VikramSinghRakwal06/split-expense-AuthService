package com.payflow.auth.dto.request;

import io.swagger.v3.oas.annotations.media.Schema;
import jakarta.validation.constraints.Email;
import jakarta.validation.constraints.NotBlank;

/**
 * Payload for {@code POST /api/v1/auth/login}.
 *
 * <p>Deliberately weaker validation than {@code RegisterRequest}: the credential rules
 * that applied at sign-up may have changed since, and rejecting a login on format would
 * leak which passwords could possibly exist. Correctness is decided by the authentication
 * manager, not by the validator.
 *
 * @param email    login identifier
 * @param password plaintext password to verify against the stored BCrypt hash
 */
@Schema(description = "Credentials for an existing account")
public record LoginRequest(

        @Schema(example = "ada@payflow.io")
        @NotBlank(message = "Email is required")
        @Email(message = "Email must be a well-formed address")
        String email,

        @Schema(example = "correct-horse-9")
        @NotBlank(message = "Password is required")
        String password) {
}
