package com.splitexpense.auth.mapper;

import com.splitexpense.auth.dto.response.PublicProfileResponse;
import com.splitexpense.auth.dto.response.UserResponse;
import com.splitexpense.auth.entity.User;
import org.springframework.stereotype.Component;

/**
 * Converts {@link User} entities into their client-facing representation.
 *
 * <p>Kept as an explicit component rather than a mapping framework: there is one
 * translation, and writing it by hand makes it obvious that {@code passwordHash} is
 * excluded rather than relying on a generator to leave it out.
 */
@Component
public class UserMapper {

    /**
     * @param user entity to convert, never null
     * @return the safe-to-serialise view of that user
     */
    public UserResponse toResponse(User user) {
        return new UserResponse(
                user.getId(),
                user.getEmail(),
                user.getFullName(),
                user.getPhoneNumber(),
                user.getRole(),
                user.isEnabled(),
                user.getCreatedAt());
    }

    /**
     * @param user entity to convert, never null
     * @return the narrow, other-people-can-see-this view of that user
     */
    public PublicProfileResponse toPublicProfile(User user) {
        return new PublicProfileResponse(user.getId(), user.getFullName());
    }
}
