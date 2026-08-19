package com.splitexpense.auth.service;

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
import java.util.List;
import java.util.UUID;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.dao.DataIntegrityViolationException;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

/**
 * Registration, authentication and session lifecycle. All business rules for the
 * {@code /api/v1/auth} endpoints live here; the controller only adapts HTTP to these
 * calls.
 */
@Service
public class AuthService {

    private static final Logger log = LoggerFactory.getLogger(AuthService.class);

    private final UserRepository userRepository;
    private final RefreshTokenRepository refreshTokenRepository;
    private final PasswordEncoder passwordEncoder;
    private final AuthenticationManager authenticationManager;
    private final JwtService jwtService;
    private final UserMapper userMapper;

    public AuthService(
            UserRepository userRepository,
            RefreshTokenRepository refreshTokenRepository,
            PasswordEncoder passwordEncoder,
            AuthenticationManager authenticationManager,
            JwtService jwtService,
            UserMapper userMapper) {
        this.userRepository = userRepository;
        this.refreshTokenRepository = refreshTokenRepository;
        this.passwordEncoder = passwordEncoder;
        this.authenticationManager = authenticationManager;
        this.jwtService = jwtService;
        this.userMapper = userMapper;
    }

    /**
     * Creates an account with a BCrypt-hashed password.
     *
     * @param request validated registration details
     * @return the new account's public profile
     * @throws DuplicateResourceException if the email is already registered
     */
    @Transactional
    public UserResponse register(RegisterRequest request) {
        String email = normaliseEmail(request.email());

        if (userRepository.existsByEmail(email)) {
            throw new DuplicateResourceException("An account already exists for " + email);
        }

        User user = User.builder()
                .email(email)
                .passwordHash(passwordEncoder.encode(request.password()))
                .fullName(request.fullName().trim())
                .phoneNumber(request.phoneNumber())
                .role(Role.USER)
                .enabled(true)
                .build();

        try {
            User saved = userRepository.saveAndFlush(user);
            log.info("Registered account {}", saved.getId());
            return userMapper.toResponse(saved);
        } catch (DataIntegrityViolationException ex) {
            // The existsByEmail check above is advisory: two concurrent registrations can
            // both pass it and race to the insert. uq_users_email is what actually
            // guarantees uniqueness, so the loser of that race is translated here rather
            // than surfacing as a 500. saveAndFlush forces the constraint to fire inside
            // this try block instead of at transaction commit.
            throw new DuplicateResourceException("An account already exists for " + email);
        }
    }

    /**
     * Verifies credentials and starts a session.
     *
     * @param request email and password
     * @return access token, refresh token and the caller's profile
     * @throws org.springframework.security.core.AuthenticationException if the
     *         credentials are not valid
     */
    @Transactional
    public AuthResponse login(LoginRequest request) {
        String email = normaliseEmail(request.email());

        // Delegating to the AuthenticationManager rather than comparing hashes here keeps
        // the account checks (enabled, locked) and the password verification in one place.
        // A failure throws, and is translated to a 401 by GlobalExceptionHandler.
        authenticationManager.authenticate(
                new UsernamePasswordAuthenticationToken(email, request.password()));

        User user = userRepository
                .findByEmail(email)
                .orElseThrow(() -> ResourceNotFoundException.of("User", "email", email));

        log.info("Login succeeded for account {}", user.getId());
        return issueTokens(user);
    }

    /**
     * Exchanges a refresh token for a new access token.
     *
     * <p>The presented token must parse as a refresh token <em>and</em> its row must still
     * be active. The stateless signature check alone is not enough: it would happily
     * accept a token that was revoked at logout an hour ago.
     *
     * <p>The refresh token is rotated — the presented one is revoked and a new one issued.
     * That bounds the value of a stolen refresh token to a single use, and means a replay
     * of the old value arrives at an already-revoked row where it can be detected.
     *
     * @param request the refresh token to exchange
     * @return a new access token, a new refresh token, and the caller's profile
     * @throws InvalidTokenException if the token is unknown, expired, revoked or not a
     *         refresh token
     */
    @Transactional
    public AuthResponse refresh(RefreshTokenRequest request) {
        String presented = request.refreshToken();

        if (!jwtService.isRefreshToken(presented)) {
            throw new InvalidTokenException("Refresh token is invalid or expired");
        }

        RefreshToken stored = refreshTokenRepository
                .findByTokenWithUser(presented)
                .orElseThrow(() -> new InvalidTokenException("Refresh token is invalid or expired"));

        if (!stored.isUsable()) {
            log.warn("Rejected unusable refresh token for account {}", stored.getUser().getId());
            throw new InvalidTokenException("Refresh token is invalid or expired");
        }

        User user = stored.getUser();
        if (!user.isEnabled()) {
            throw new InvalidTokenException("Refresh token is invalid or expired");
        }

        stored.setRevoked(true);
        return issueTokens(user);
    }

    /**
     * Ends a session by revoking its refresh token.
     *
     * <p>The token must belong to the caller. Without that check the endpoint would let
     * any authenticated account revoke any session whose token value it could obtain or
     * guess, which is a denial-of-service against other users rather than a logout.
     *
     * <p>Deliberately idempotent: an unknown, already-revoked or foreign token is a no-op
     * rather than an error, so logout cannot be used to probe which token values are
     * real, and a client retrying after a dropped response still succeeds.
     *
     * <p>Note that any access token already issued stays valid until it expires — that is
     * the accepted cost of stateless verification, and the reason the access token
     * lifetime is 15 minutes.
     *
     * @param request     the refresh token to revoke
     * @param callerEmail the authenticated caller, who must own the token
     */
    @Transactional
    public void logout(RefreshTokenRequest request, String callerEmail) {
        refreshTokenRepository
                .findByTokenWithUser(request.refreshToken())
                .filter(token -> token.getUser().getEmail().equals(callerEmail))
                .ifPresent(token -> {
                    token.setRevoked(true);
                    log.info("Logout revoked a refresh token for account {}",
                            token.getUser().getId());
                });
    }

    /**
     * Loads the authenticated caller's profile.
     *
     * <p>Read fresh from the database rather than reconstructed from the token's claims,
     * so a role or profile change made after the token was issued is reflected here.
     *
     * @param email the authenticated principal's login identifier
     * @return the caller's public profile
     * @throws ResourceNotFoundException if the account has been deleted since the token
     *         was issued
     */
    @Transactional(readOnly = true)
    public UserResponse getCurrentUser(String email) {
        return userRepository
                .findByEmail(email)
                .map(userMapper::toResponse)
                .orElseThrow(() -> ResourceNotFoundException.of("User", "email", email));
    }

    /**
     * Resolves a batch of account ids to their public-facing identity.
     *
     * <p>This is the endpoint that lets group-service's and expense-service's callers show
     * "Priya" instead of a UUID for anyone but the caller themselves — the frontend already
     * knows its own name from {@link #getCurrentUser}, but has no other way to learn a
     * group-mate's, since auth-service owns the only table that has it.
     *
     * <p>{@link com.splitexpense.auth.dto.response.PublicProfileResponse} is deliberately
     * narrow: any authenticated account may resolve any other id through this method — that
     * is the whole point, and is no wider than what group-service already reveals by listing
     * raw member ids to every member. What it must never reveal is email, phone, role or
     * account status, none of which this endpoint's callers have a claim to.
     *
     * @param ids account identifiers to resolve; a null caller list yields an empty result
     *            rather than every account in the platform
     * @return one profile per id that actually exists, in no guaranteed order — ids naming
     *         a deleted or never-existent account are simply absent, not an error
     */
    @Transactional(readOnly = true)
    public List<PublicProfileResponse> getPublicProfiles(List<UUID> ids) {
        if (ids == null || ids.isEmpty()) {
            return List.of();
        }
        return userRepository.findByIdIn(ids).stream()
                .map(userMapper::toPublicProfile)
                .toList();
    }

    /**
     * Resolves one account's public-facing identity by email — how a group owner turns
     * "priya@example.com" into an account id they can pass to group-service's add-member
     * endpoint, without ever seeing anything about that account beyond its name and id.
     *
     * <p>Same narrowness argument as {@link #getPublicProfiles}: this reveals no more than
     * an account's existence and display name to another authenticated caller.
     *
     * @param email the email address to resolve; matched case-insensitively, same as login
     * @return the matching account's public profile
     * @throws ResourceNotFoundException if no account is registered under that email
     */
    @Transactional(readOnly = true)
    public PublicProfileResponse getPublicProfileByEmail(String email) {
        return userRepository
                .findByEmail(normaliseEmail(email))
                .map(userMapper::toPublicProfile)
                .orElseThrow(() -> ResourceNotFoundException.of("User", "email", email));
    }

    /** Mints a token pair and persists the refresh half so it can later be revoked. */
    private AuthResponse issueTokens(User user) {
        String accessToken = jwtService.generateAccessToken(user);
        String refreshTokenValue = jwtService.generateRefreshToken(user);

        RefreshToken refreshToken = RefreshToken.builder()
                .token(refreshTokenValue)
                .user(user)
                .expiryDate(jwtService.refreshTokenExpiryFromNow())
                .revoked(false)
                .build();
        refreshTokenRepository.save(refreshToken);

        return AuthResponse.bearer(
                accessToken,
                refreshTokenValue,
                jwtService.accessTokenExpirationSeconds(),
                userMapper.toResponse(user));
    }

    /**
     * Emails are case-insensitive in practice; storing them lower-cased keeps
     * {@code uq_users_email} from treating Ada@ and ada@ as two accounts.
     */
    private String normaliseEmail(String email) {
        return email.trim().toLowerCase(java.util.Locale.ROOT);
    }
}
