package com.payflow.auth.dto.request;

import io.swagger.v3.oas.annotations.media.Schema;
import jakarta.validation.constraints.Email;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.Pattern;
import jakarta.validation.constraints.Size;

/**
 * Payload for {@code POST /api/v1/auth/register}.
 *
 * @param email       login identifier, must be unique across PayFlow
 * @param password    plaintext password; hashed with BCrypt before it is stored
 * @param fullName    account holder's display name
 * @param phoneNumber optional contact number in E.164 form
 */
@Schema(description = "New account registration details")
public record RegisterRequest(

        @Schema(example = "ada@payflow.io")
        @NotBlank(message = "Email is required")
        @Email(message = "Email must be a well-formed address")
        @Size(max = 255, message = "Email must not exceed 255 characters")
        String email,

        @Schema(example = "correct-horse-9", minLength = 8)
        @NotBlank(message = "Password is required")
        // Upper bound is BCrypt's: it silently ignores anything past 72 bytes, so a
        // longer password would give a false sense of added strength.
        @Size(min = 8, max = 72, message = "Password must be between 8 and 72 characters")
        @Pattern(
                regexp = "^(?=.*[A-Za-z])(?=.*\\d).+$",
                message = "Password must contain at least one letter and one digit")
        String password,

        @Schema(example = "Ada Lovelace")
        @NotBlank(message = "Full name is required")
        @Size(max = 150, message = "Full name must not exceed 150 characters")
        String fullName,

        @Schema(example = "+441632960961", description = "Optional, E.164 format")
        @Pattern(
                regexp = "^\\+?[1-9]\\d{7,14}$",
                message = "Phone number must be 8 to 15 digits, optionally prefixed with +")
        String phoneNumber) {
}
