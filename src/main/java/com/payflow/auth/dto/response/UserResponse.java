package com.payflow.auth.dto.response;

import com.payflow.auth.entity.Role;
import io.swagger.v3.oas.annotations.media.Schema;
import java.time.Instant;
import java.util.UUID;

/**
 * Client-facing view of an account. This is the only shape a {@code User} is ever
 * exposed in; notably it has no {@code passwordHash} field to accidentally populate.
 *
 * @param id          account identifier, stable and safe to share with other services
 * @param email       login identifier
 * @param fullName    account holder's display name
 * @param phoneNumber contact number, may be null
 * @param role        authorisation role
 * @param enabled     whether the account may authenticate
 * @param createdAt   when the account was registered
 */
@Schema(description = "Public profile of a PayFlow account")
public record UserResponse(
        UUID id,
        String email,
        String fullName,
        String phoneNumber,
        Role role,
        boolean enabled,
        Instant createdAt) {
}
