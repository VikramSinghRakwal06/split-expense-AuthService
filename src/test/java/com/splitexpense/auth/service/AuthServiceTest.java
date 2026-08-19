package com.splitexpense.auth.service;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

import com.splitexpense.auth.dto.request.LoginRequest;
import com.splitexpense.auth.dto.request.RefreshTokenRequest;
import com.splitexpense.auth.dto.request.RegisterRequest;
import com.splitexpense.auth.dto.response.AuthResponse;
import com.splitexpense.auth.dto.response.PublicProfileResponse;
import com.splitexpense.auth.dto.response.UserResponse;
import com.splitexpense.auth.entity.RefreshToken;
import com.splitexpense.auth.entity.Role;
import com.splitexpense.auth.entity.User;
import com.splitexpense.auth.exception.DuplicateResourceException;
import com.splitexpense.auth.exception.InvalidTokenException;
import com.splitexpense.auth.exception.ResourceNotFoundException;
import com.splitexpense.auth.mapper.UserMapper;
import com.splitexpense.auth.repository.RefreshTokenRepository;
import com.splitexpense.auth.repository.UserRepository;
import com.splitexpense.auth.security.JwtService;
import java.time.Instant;
import java.util.List;
import java.util.Optional;
import java.util.UUID;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.ArgumentCaptor;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.dao.DataIntegrityViolationException;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.core.Authentication;
import org.springframework.security.crypto.password.PasswordEncoder;

/**
 * Unit tests for the authentication business rules, with all collaborators mocked.
 */
@ExtendWith(MockitoExtension.class)
class AuthServiceTest {

    private static final String EMAIL = "ada@splitexpense.io";
    private static final String PASSWORD = "correct-horse-9";

    @Mock private UserRepository userRepository;
    @Mock private RefreshTokenRepository refreshTokenRepository;
    @Mock private PasswordEncoder passwordEncoder;
    @Mock private AuthenticationManager authenticationManager;
    @Mock private JwtService jwtService;
    @Mock private UserMapper userMapper;

    @InjectMocks private AuthService authService;

    private User user;

    @BeforeEach
    void setUp() {
        user = User.builder()
                .id(UUID.randomUUID())
                .email(EMAIL)
                .passwordHash("$2a$10$hashed")
                .fullName("Ada Lovelace")
                .phoneNumber("+441632960961")
                .role(Role.USER)
                .enabled(true)
                .createdAt(Instant.now())
                .build();
    }

    private UserResponse responseFor(User u) {
        return new UserResponse(
                u.getId(), u.getEmail(), u.getFullName(), u.getPhoneNumber(),
                u.getRole(), u.isEnabled(), u.getCreatedAt());
    }

    private void stubTokenIssuance() {
        when(jwtService.generateAccessToken(any())).thenReturn("access-token");
        when(jwtService.generateRefreshToken(any())).thenReturn("refresh-token");
        when(jwtService.refreshTokenExpiryFromNow())
                .thenReturn(Instant.now().plusSeconds(604800));
        when(jwtService.accessTokenExpirationSeconds()).thenReturn(900L);
        when(userMapper.toResponse(any())).thenAnswer(inv -> responseFor(inv.getArgument(0)));
    }

    @Nested
    @DisplayName("register")
    class Register {

        private final RegisterRequest request =
                new RegisterRequest(EMAIL, PASSWORD, "Ada Lovelace", "+441632960961");

        @Test
        @DisplayName("hashes the password and never stores the plaintext")
        void hashesPassword() {
            when(userRepository.existsByEmail(EMAIL)).thenReturn(false);
            when(passwordEncoder.encode(PASSWORD)).thenReturn("$2a$10$hashed");
            when(userRepository.saveAndFlush(any(User.class))).thenAnswer(inv -> inv.getArgument(0));
            when(userMapper.toResponse(any())).thenAnswer(inv -> responseFor(inv.getArgument(0)));

            authService.register(request);

            ArgumentCaptor<User> saved = ArgumentCaptor.forClass(User.class);
            verify(userRepository).saveAndFlush(saved.capture());
            assertThat(saved.getValue().getPasswordHash()).isEqualTo("$2a$10$hashed");
            assertThat(saved.getValue().getPasswordHash()).isNotEqualTo(PASSWORD);
        }

        @Test
        @DisplayName("stores the email lower-cased so casing cannot create a second account")
        void normalisesEmail() {
            when(userRepository.existsByEmail(EMAIL)).thenReturn(false);
            when(passwordEncoder.encode(anyString())).thenReturn("$2a$10$hashed");
            when(userRepository.saveAndFlush(any(User.class))).thenAnswer(inv -> inv.getArgument(0));
            when(userMapper.toResponse(any())).thenAnswer(inv -> responseFor(inv.getArgument(0)));

            authService.register(new RegisterRequest(
                    "  Ada@SplitExpense.IO ", PASSWORD, "Ada Lovelace", null));

            ArgumentCaptor<User> saved = ArgumentCaptor.forClass(User.class);
            verify(userRepository).saveAndFlush(saved.capture());
            assertThat(saved.getValue().getEmail()).isEqualTo(EMAIL);
        }

        @Test
        @DisplayName("defaults a new account to the USER role and enabled")
        void defaultsRoleAndEnabled() {
            when(userRepository.existsByEmail(EMAIL)).thenReturn(false);
            when(passwordEncoder.encode(anyString())).thenReturn("$2a$10$hashed");
            when(userRepository.saveAndFlush(any(User.class))).thenAnswer(inv -> inv.getArgument(0));
            when(userMapper.toResponse(any())).thenAnswer(inv -> responseFor(inv.getArgument(0)));

            authService.register(request);

            ArgumentCaptor<User> saved = ArgumentCaptor.forClass(User.class);
            verify(userRepository).saveAndFlush(saved.capture());
            assertThat(saved.getValue().getRole()).isEqualTo(Role.USER);
            assertThat(saved.getValue().isEnabled()).isTrue();
        }

        @Test
        @DisplayName("rejects an email that is already registered")
        void rejectsDuplicate() {
            when(userRepository.existsByEmail(EMAIL)).thenReturn(true);

            assertThatThrownBy(() -> authService.register(request))
                    .isInstanceOf(DuplicateResourceException.class)
                    .hasMessageContaining(EMAIL);

            verify(userRepository, never()).saveAndFlush(any());
        }

        @Test
        @DisplayName("translates the unique-constraint race into a 409, not a 500")
        void translatesConstraintViolation() {
            // Two concurrent registrations both pass existsByEmail; the loser hits the
            // uq_users_email constraint at insert time.
            when(userRepository.existsByEmail(EMAIL)).thenReturn(false);
            when(passwordEncoder.encode(anyString())).thenReturn("$2a$10$hashed");
            when(userRepository.saveAndFlush(any(User.class)))
                    .thenThrow(new DataIntegrityViolationException("uq_users_email"));

            assertThatThrownBy(() -> authService.register(request))
                    .isInstanceOf(DuplicateResourceException.class);
        }
    }

    @Nested
    @DisplayName("login")
    class Login {

        private final LoginRequest request = new LoginRequest(EMAIL, PASSWORD);

        @Test
        @DisplayName("issues a token pair and persists the refresh token")
        void issuesTokens() {
            when(authenticationManager.authenticate(any())).thenReturn(mock(Authentication.class));
            when(userRepository.findByEmail(EMAIL)).thenReturn(Optional.of(user));
            stubTokenIssuance();

            AuthResponse response = authService.login(request);

            assertThat(response.accessToken()).isEqualTo("access-token");
            assertThat(response.refreshToken()).isEqualTo("refresh-token");
            assertThat(response.tokenType()).isEqualTo("Bearer");
            assertThat(response.expiresIn()).isEqualTo(900L);
            assertThat(response.user().email()).isEqualTo(EMAIL);

            // Persisted so that logout can later revoke it.
            verify(refreshTokenRepository).save(any(RefreshToken.class));
        }

        @Test
        @DisplayName("propagates a bad-credentials failure and issues nothing")
        void badCredentials() {
            when(authenticationManager.authenticate(any()))
                    .thenThrow(new BadCredentialsException("Bad credentials"));

            assertThatThrownBy(() -> authService.login(request))
                    .isInstanceOf(BadCredentialsException.class);

            verify(refreshTokenRepository, never()).save(any());
        }

        @Test
        @DisplayName("fails if the account vanished between authentication and lookup")
        void missingUserAfterAuthentication() {
            when(authenticationManager.authenticate(any())).thenReturn(mock(Authentication.class));
            when(userRepository.findByEmail(EMAIL)).thenReturn(Optional.empty());

            assertThatThrownBy(() -> authService.login(request))
                    .isInstanceOf(ResourceNotFoundException.class);
        }
    }

    @Nested
    @DisplayName("refresh")
    class Refresh {

        private final RefreshTokenRequest request = new RefreshTokenRequest("stored-token");

        private RefreshToken storedToken(boolean revoked, Instant expiry) {
            return RefreshToken.builder()
                    .id(UUID.randomUUID())
                    .token("stored-token")
                    .user(user)
                    .expiryDate(expiry)
                    .revoked(revoked)
                    .build();
        }

        @Test
        @DisplayName("issues a new pair and rotates the presented token")
        void rotatesToken() {
            RefreshToken stored = storedToken(false, Instant.now().plusSeconds(3600));
            when(jwtService.isRefreshToken("stored-token")).thenReturn(true);
            when(refreshTokenRepository.findByTokenWithUser("stored-token"))
                    .thenReturn(Optional.of(stored));
            stubTokenIssuance();

            AuthResponse response = authService.refresh(request);

            assertThat(response.accessToken()).isEqualTo("access-token");
            // The presented token is spent: a replay must not work.
            assertThat(stored.isRevoked()).isTrue();
            verify(refreshTokenRepository).save(any(RefreshToken.class));
        }

        @Test
        @DisplayName("rejects a token that was revoked at logout")
        void rejectsRevoked() {
            when(jwtService.isRefreshToken("stored-token")).thenReturn(true);
            when(refreshTokenRepository.findByTokenWithUser("stored-token"))
                    .thenReturn(Optional.of(storedToken(true, Instant.now().plusSeconds(3600))));

            assertThatThrownBy(() -> authService.refresh(request))
                    .isInstanceOf(InvalidTokenException.class);
        }

        @Test
        @DisplayName("rejects a token whose row has expired")
        void rejectsExpired() {
            when(jwtService.isRefreshToken("stored-token")).thenReturn(true);
            when(refreshTokenRepository.findByTokenWithUser("stored-token"))
                    .thenReturn(Optional.of(storedToken(false, Instant.now().minusSeconds(1))));

            assertThatThrownBy(() -> authService.refresh(request))
                    .isInstanceOf(InvalidTokenException.class);
        }

        @Test
        @DisplayName("rejects an access token presented in place of a refresh token")
        void rejectsAccessToken() {
            when(jwtService.isRefreshToken("stored-token")).thenReturn(false);

            assertThatThrownBy(() -> authService.refresh(request))
                    .isInstanceOf(InvalidTokenException.class);

            verify(refreshTokenRepository, never()).findByTokenWithUser(anyString());
        }

        @Test
        @DisplayName("rejects a token whose account has since been disabled")
        void rejectsDisabledAccount() {
            user.setEnabled(false);
            when(jwtService.isRefreshToken("stored-token")).thenReturn(true);
            when(refreshTokenRepository.findByTokenWithUser("stored-token"))
                    .thenReturn(Optional.of(storedToken(false, Instant.now().plusSeconds(3600))));

            assertThatThrownBy(() -> authService.refresh(request))
                    .isInstanceOf(InvalidTokenException.class);
        }

        @Test
        @DisplayName("rejects a token that was never issued")
        void rejectsUnknown() {
            when(jwtService.isRefreshToken("stored-token")).thenReturn(true);
            when(refreshTokenRepository.findByTokenWithUser("stored-token"))
                    .thenReturn(Optional.empty());

            assertThatThrownBy(() -> authService.refresh(request))
                    .isInstanceOf(InvalidTokenException.class);
        }
    }

    @Nested
    @DisplayName("logout")
    class Logout {

        private final RefreshTokenRequest request = new RefreshTokenRequest("stored-token");

        @Test
        @DisplayName("revokes the caller's own token")
        void revokesOwnToken() {
            RefreshToken stored = RefreshToken.builder()
                    .id(UUID.randomUUID())
                    .token("stored-token")
                    .user(user)
                    .expiryDate(Instant.now().plusSeconds(3600))
                    .revoked(false)
                    .build();
            when(refreshTokenRepository.findByTokenWithUser("stored-token"))
                    .thenReturn(Optional.of(stored));

            authService.logout(request, EMAIL);

            assertThat(stored.isRevoked()).isTrue();
        }

        @Test
        @DisplayName("will not revoke a token belonging to someone else")
        void refusesForeignToken() {
            User other = User.builder()
                    .id(UUID.randomUUID())
                    .email("grace@splitexpense.io")
                    .passwordHash("x")
                    .fullName("Grace Hopper")
                    .role(Role.USER)
                    .enabled(true)
                    .build();
            RefreshToken foreign = RefreshToken.builder()
                    .id(UUID.randomUUID())
                    .token("stored-token")
                    .user(other)
                    .expiryDate(Instant.now().plusSeconds(3600))
                    .revoked(false)
                    .build();
            when(refreshTokenRepository.findByTokenWithUser("stored-token"))
                    .thenReturn(Optional.of(foreign));

            authService.logout(request, EMAIL);

            // Silently ignored rather than 403: revealing that the token exists would
            // itself be a leak, and logout must stay idempotent.
            assertThat(foreign.isRevoked()).isFalse();
        }

        @Test
        @DisplayName("is a no-op for an unknown token")
        void unknownTokenIsNoOp() {
            when(refreshTokenRepository.findByTokenWithUser("stored-token"))
                    .thenReturn(Optional.empty());

            authService.logout(request, EMAIL);
        }
    }

    @Nested
    @DisplayName("getCurrentUser")
    class GetCurrentUser {

        @Test
        @DisplayName("reads the profile fresh from the database")
        void returnsProfile() {
            when(userRepository.findByEmail(EMAIL)).thenReturn(Optional.of(user));
            when(userMapper.toResponse(user)).thenReturn(responseFor(user));

            UserResponse response = authService.getCurrentUser(EMAIL);

            assertThat(response.email()).isEqualTo(EMAIL);
            assertThat(response.id()).isEqualTo(user.getId());
        }

        @Test
        @DisplayName("fails when the account has been deleted since the token was issued")
        void missingAccount() {
            when(userRepository.findByEmail(EMAIL)).thenReturn(Optional.empty());

            assertThatThrownBy(() -> authService.getCurrentUser(EMAIL))
                    .isInstanceOf(ResourceNotFoundException.class);
        }
    }

    @Nested
    @DisplayName("getPublicProfiles")
    class GetPublicProfiles {

        @Test
        @DisplayName("resolves every id that exists, in the narrow public shape")
        void resolvesExistingIds() {
            User bob = User.builder()
                    .id(UUID.randomUUID())
                    .email("bob@splitexpense.io")
                    .fullName("Bob B")
                    .role(Role.USER)
                    .enabled(true)
                    .build();
            when(userRepository.findByIdIn(List.of(user.getId(), bob.getId())))
                    .thenReturn(List.of(user, bob));
            when(userMapper.toPublicProfile(user))
                    .thenReturn(new PublicProfileResponse(user.getId(), user.getFullName()));
            when(userMapper.toPublicProfile(bob))
                    .thenReturn(new PublicProfileResponse(bob.getId(), bob.getFullName()));

            List<PublicProfileResponse> profiles =
                    authService.getPublicProfiles(List.of(user.getId(), bob.getId()));

            assertThat(profiles)
                    .extracting(PublicProfileResponse::fullName)
                    .containsExactlyInAnyOrder(user.getFullName(), "Bob B");
        }

        /**
         * The narrow shape is the entire reason this endpoint exists rather than reusing
         * {@code UserResponse}: an id resolved through it must never carry email, phone,
         * role or account status back to a caller who is not that account's own owner.
         */
        @Test
        @DisplayName("never resolves through the wide UserResponse mapping")
        void doesNotUseTheWideMapper() {
            when(userRepository.findByIdIn(any())).thenReturn(List.of(user));
            when(userMapper.toPublicProfile(user))
                    .thenReturn(new PublicProfileResponse(user.getId(), user.getFullName()));

            authService.getPublicProfiles(List.of(user.getId()));

            verify(userMapper, never()).toResponse(any());
        }

        @Test
        @DisplayName("silently omits ids that don't resolve to any account")
        void omitsUnknownIds() {
            UUID deleted = UUID.randomUUID();
            when(userRepository.findByIdIn(List.of(deleted))).thenReturn(List.of());

            List<PublicProfileResponse> profiles = authService.getPublicProfiles(List.of(deleted));

            assertThat(profiles).isEmpty();
        }

        @Test
        @DisplayName("returns empty for a null or empty id list without querying the database")
        void emptyInputSkipsTheQuery() {
            assertThat(authService.getPublicProfiles(null)).isEmpty();
            assertThat(authService.getPublicProfiles(List.of())).isEmpty();

            verify(userRepository, never()).findByIdIn(any());
        }
    }
}
