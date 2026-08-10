package com.payflow.auth.repository;

import com.payflow.auth.entity.User;
import java.util.Optional;
import java.util.UUID;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

/**
 * Persistence access for {@link User}. Email is the login identifier, so it is the
 * lookup key here rather than the surrogate id.
 */
@Repository
public interface UserRepository extends JpaRepository<User, UUID> {

    /**
     * @param email address to look up, matched exactly
     * @return the user, if one exists with that email
     */
    Optional<User> findByEmail(String email);

    /**
     * Pre-flight check for registration. Cheaper than loading the row, but note it is
     * advisory only: the {@code uq_users_email} constraint is what actually guarantees
     * uniqueness under concurrent registrations.
     *
     * @param email address to test
     * @return {@code true} if the email is already taken
     */
    boolean existsByEmail(String email);
}
