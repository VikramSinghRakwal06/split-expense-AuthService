package com.splitexpense.auth.controller;

import com.splitexpense.auth.dto.request.LoginRequest;
import com.splitexpense.auth.dto.request.RefreshTokenRequest;
import com.splitexpense.auth.dto.request.RegisterRequest;
import com.splitexpense.auth.dto.response.AuthResponse;
import com.splitexpense.auth.dto.response.ErrorResponse;
import com.splitexpense.auth.dto.response.PublicProfileResponse;
import com.splitexpense.auth.dto.response.UserResponse;
import com.splitexpense.auth.security.UserPrincipal;
import com.splitexpense.auth.service.AuthService;
import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.media.Content;
import io.swagger.v3.oas.annotations.media.Schema;
import io.swagger.v3.oas.annotations.responses.ApiResponse;
import io.swagger.v3.oas.annotations.security.SecurityRequirement;
import io.swagger.v3.oas.annotations.tags.Tag;
import jakarta.validation.Valid;
import java.util.List;
import java.util.UUID;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

/**
 * HTTP surface for accounts and sessions.
 *
 * <p>Holds no business rules: each method validates its payload, calls {@link AuthService}
 * and chooses a status code.
 */
@RestController
@RequestMapping("/api/v1/auth")
@Tag(name = "Authentication", description = "Registration, login and session management")
public class AuthController {

    /** Upper bound on one {@code GET /users} call; see that method for why this caps
     *  rather than rejects. */
    private static final int MAX_IDS_PER_REQUEST = 200;

    private final AuthService authService;

    public AuthController(AuthService authService) {
        this.authService = authService;
    }

    /**
     * @param request validated registration details
     * @return 201 with the new account's profile
     */
    @PostMapping("/register")
    @Operation(
            summary = "Register a new account",
            description = "Creates an account and returns its profile. Does not log the user in.",
            security = {})
    @ApiResponse(responseCode = "201", description = "Account created")
    @ApiResponse(responseCode = "400", description = "Validation failed",
            content = @Content(schema = @Schema(implementation = ErrorResponse.class)))
    @ApiResponse(responseCode = "409", description = "Email already registered",
            content = @Content(schema = @Schema(implementation = ErrorResponse.class)))
    public ResponseEntity<UserResponse> register(@Valid @RequestBody RegisterRequest request) {
        return ResponseEntity.status(HttpStatus.CREATED).body(authService.register(request));
    }

    /**
     * @param request email and password
     * @return 200 with a token pair and the caller's profile
     */
    @PostMapping("/login")
    @Operation(
            summary = "Authenticate and obtain tokens",
            description = "Verifies credentials and issues an access token and a refresh token.",
            security = {})
    @ApiResponse(responseCode = "200", description = "Authenticated")
    @ApiResponse(responseCode = "401", description = "Invalid credentials",
            content = @Content(schema = @Schema(implementation = ErrorResponse.class)))
    public ResponseEntity<AuthResponse> login(@Valid @RequestBody LoginRequest request) {
        return ResponseEntity.ok(authService.login(request));
    }

    /**
     * @param request the refresh token to exchange
     * @return 200 with a new access token and a rotated refresh token
     */
    @PostMapping("/refresh")
    @Operation(
            summary = "Exchange a refresh token for a new access token",
            description = "The presented refresh token is revoked and replaced as part of "
                    + "the exchange, so each refresh token is usable exactly once.",
            security = {})
    @ApiResponse(responseCode = "200", description = "New tokens issued")
    @ApiResponse(responseCode = "401", description = "Refresh token invalid, expired or revoked",
            content = @Content(schema = @Schema(implementation = ErrorResponse.class)))
    public ResponseEntity<AuthResponse> refresh(@Valid @RequestBody RefreshTokenRequest request) {
        return ResponseEntity.ok(authService.refresh(request));
    }

    /**
     * @param request   the refresh token to revoke
     * @param principal the authenticated caller, who must own the token
     * @return 204, whether or not the token was still active
     */
    @PostMapping("/logout")
    @Operation(
            summary = "End a session",
            description = "Revokes the refresh token, which must belong to the "
                    + "authenticated caller. Idempotent: an unknown, already-revoked or "
                    + "foreign token also returns 204. Any access token already issued "
                    + "remains valid until it expires.",
            security = @SecurityRequirement(name = "bearerAuth"))
    @ApiResponse(responseCode = "204", description = "Session ended")
    @ApiResponse(responseCode = "401", description = "Missing or invalid access token",
            content = @Content(schema = @Schema(implementation = ErrorResponse.class)))
    public ResponseEntity<Void> logout(
            @Valid @RequestBody RefreshTokenRequest request,
            @AuthenticationPrincipal UserPrincipal principal) {
        authService.logout(request, principal.getUsername());
        return ResponseEntity.noContent().build();
    }

    /**
     * @param principal the authenticated caller, injected from the security context
     * @return 200 with the caller's profile
     */
    @GetMapping("/me")
    @Operation(
            summary = "Get the authenticated account's profile",
            security = @SecurityRequirement(name = "bearerAuth"))
    @ApiResponse(responseCode = "200", description = "Profile returned")
    @ApiResponse(responseCode = "401", description = "Missing or invalid access token",
            content = @Content(schema = @Schema(implementation = ErrorResponse.class)))
    public ResponseEntity<UserResponse> me(@AuthenticationPrincipal UserPrincipal principal) {
        return ResponseEntity.ok(authService.getCurrentUser(principal.getUsername()));
    }

    /**
     * Resolves a batch of account ids to display names — how a caller who only has a group's
     * member ids (from group-service) turns them into something a person can read.
     *
     * @param ids the account ids to resolve, as a comma-separated query parameter
     * @return 200 with one profile per id that exists; unmatched ids are simply absent
     */
    @GetMapping("/users")
    @Operation(
            summary = "Resolve account ids to display names",
            description = "Any authenticated caller may resolve any ids — the response "
                    + "carries a name only, nothing an id's owner would consider private.",
            security = @SecurityRequirement(name = "bearerAuth"))
    @ApiResponse(responseCode = "200", description = "Profiles returned")
    @ApiResponse(responseCode = "401", description = "Missing or invalid access token",
            content = @Content(schema = @Schema(implementation = ErrorResponse.class)))
    public ResponseEntity<List<PublicProfileResponse>> getPublicProfiles(
            @RequestParam List<UUID> ids) {
        // Capped rather than rejected: every real caller is asking about one group's
        // membership, which is never remotely this large, so a longer list is a client bug
        // worth tolerating rather than a 400 worth defining new validation machinery for.
        List<UUID> capped = ids.size() > MAX_IDS_PER_REQUEST ? ids.subList(0, MAX_IDS_PER_REQUEST) : ids;
        return ResponseEntity.ok(authService.getPublicProfiles(capped));
    }

    /**
     * Resolves one account's id and display name by email — lets a group owner invite
     * someone by the email address they know them by, rather than needing that person's
     * raw account id in hand before the invite can happen.
     *
     * @param email the email address to resolve
     * @return 200 with the matching account's public profile
     */
    @GetMapping("/users/lookup")
    @Operation(
            summary = "Resolve an email address to an account id and display name",
            description = "Any authenticated caller may resolve any email — the response "
                    + "carries an id and a name only, the same narrow shape as GET /users.",
            security = @SecurityRequirement(name = "bearerAuth"))
    @ApiResponse(responseCode = "200", description = "Profile returned")
    @ApiResponse(responseCode = "401", description = "Missing or invalid access token",
            content = @Content(schema = @Schema(implementation = ErrorResponse.class)))
    @ApiResponse(responseCode = "404", description = "No account registered under that email",
            content = @Content(schema = @Schema(implementation = ErrorResponse.class)))
    public ResponseEntity<PublicProfileResponse> getPublicProfileByEmail(
            @RequestParam String email) {
        return ResponseEntity.ok(authService.getPublicProfileByEmail(email));
    }
}
