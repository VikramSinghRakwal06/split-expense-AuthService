package com.splitexpense.auth.dto.response;

import io.swagger.v3.oas.annotations.media.Schema;
import java.util.UUID;

/**
 * The identity another SplitExpense user is allowed to see: an id and a display name,
 * nothing else.
 *
 * <p>Deliberately narrower than {@link UserResponse}. That type is "your own profile,
 * read back to you" and includes email, phone, role and account status — none of which a
 * group-mate has any business seeing just because they share a group. This type exists so
 * group-service's and expense-service's callers can turn a bare account UUID into "Priya"
 * instead of the id itself, and nothing more.
 *
 * @param id       account identifier, as it appears in a group's member list
 * @param fullName the name to display for this account
 */
@Schema(description = "The public-facing identity of a SplitExpense account")
public record PublicProfileResponse(UUID id, String fullName) {
}
