package com.payflow.auth.controller;

import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.doThrow;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

import com.payflow.auth.dto.request.LoginRequest;
import com.payflow.auth.dto.request.RefreshTokenRequest;
import com.payflow.auth.dto.request.RegisterRequest;
import com.payflow.auth.dto.response.AuthResponse;
import com.payflow.auth.dto.response.UserResponse;
import com.payflow.auth.entity.Role;
import com.payflow.auth.entity.User;
import com.payflow.auth.exception.DuplicateResourceException;
import com.payflow.auth.exception.InvalidTokenException;
import com.payflow.auth.security.JwtService;
import com.payflow.auth.security.UserPrincipal;
import com.payflow.auth.service.AuthService;
import java.time.Instant;
import java.util.UUID;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.webmvc.test.autoconfigure.AutoConfigureMockMvc;
import org.springframework.boot.webmvc.test.autoconfigure.WebMvcTest;
import org.springframework.http.MediaType;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.test.context.bean.override.mockito.MockitoBean;
import org.springframework.test.web.servlet.MockMvc;
import tools.jackson.databind.ObjectMapper;

/**
 * Web-layer slice test: request mapping, payload validation, status codes and the error
 * contract. The service is mocked, and the security filters are switched off so this test
 * fails for controller reasons only — the real filter chain is exercised by
 * {@code AuthFlowIntegrationTest}.
 */
@WebMvcTest(AuthController.class)
@AutoConfigureMockMvc(addFilters = false)
class AuthControllerTest {

    private static final String BASE = "/api/v1/auth";

    @Autowired private MockMvc mockMvc;
    @Autowired private ObjectMapper objectMapper;

    @MockitoBean private AuthService authService;

    // The slice includes Filter beans, so JwtAuthenticationFilter is instantiated even
    // with the chain disabled — its @Service collaborators are not in the slice and must
    // be supplied here.
    @MockitoBean private JwtService jwtService;
    @MockitoBean private UserDetailsService userDetailsService;

    private final UUID userId = UUID.randomUUID();

    @AfterEach
    void clearContext() {
        SecurityContextHolder.clearContext();
    }

    private UserResponse userResponse() {
        return new UserResponse(
                userId, "ada@payflow.io", "Ada Lovelace", "+441632960961",
                Role.USER, true, Instant.parse("2026-01-01T00:00:00Z"));
    }

    private String json(Object value) {
        return objectMapper.writeValueAsString(value);
    }

    @Test
    @DisplayName("POST /register returns 201 with the created profile")
    void registerReturnsCreated() throws Exception {
        when(authService.register(any(RegisterRequest.class))).thenReturn(userResponse());

        mockMvc.perform(post(BASE + "/register")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(json(new RegisterRequest(
                                "ada@payflow.io", "correct-horse-9",
                                "Ada Lovelace", "+441632960961"))))
                .andExpect(status().isCreated())
                .andExpect(jsonPath("$.id").value(userId.toString()))
                .andExpect(jsonPath("$.email").value("ada@payflow.io"))
                .andExpect(jsonPath("$.role").value("USER"))
                // The hash must never appear in a response body.
                .andExpect(jsonPath("$.passwordHash").doesNotExist());
    }

    @Test
    @DisplayName("POST /register returns 409 for a duplicate email")
    void registerDuplicateReturnsConflict() throws Exception {
        when(authService.register(any(RegisterRequest.class)))
                .thenThrow(new DuplicateResourceException("An account already exists for ada@payflow.io"));

        mockMvc.perform(post(BASE + "/register")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(json(new RegisterRequest(
                                "ada@payflow.io", "correct-horse-9", "Ada Lovelace", null))))
                .andExpect(status().isConflict())
                .andExpect(jsonPath("$.status").value(409))
                .andExpect(jsonPath("$.error").value("Conflict"))
                .andExpect(jsonPath("$.path").value(BASE + "/register"));
    }

    @Test
    @DisplayName("POST /register returns 400 listing every rejected field")
    void registerValidationFailure() throws Exception {
        mockMvc.perform(post(BASE + "/register")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(json(new RegisterRequest(
                                "not-an-email", "short", "", "not-a-phone"))))
                .andExpect(status().isBadRequest())
                .andExpect(jsonPath("$.status").value(400))
                .andExpect(jsonPath("$.validationErrors.email").exists())
                .andExpect(jsonPath("$.validationErrors.password").exists())
                .andExpect(jsonPath("$.validationErrors.fullName").exists())
                .andExpect(jsonPath("$.validationErrors.phoneNumber").exists());
    }

    @Test
    @DisplayName("POST /register rejects a password with no digit")
    void registerRejectsPasswordWithoutDigit() throws Exception {
        mockMvc.perform(post(BASE + "/register")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(json(new RegisterRequest(
                                "ada@payflow.io", "onlyletters", "Ada Lovelace", null))))
                .andExpect(status().isBadRequest())
                .andExpect(jsonPath("$.validationErrors.password").exists());
    }

    @Test
    @DisplayName("POST /login returns 200 with a token pair")
    void loginReturnsTokens() throws Exception {
        when(authService.login(any(LoginRequest.class)))
                .thenReturn(AuthResponse.bearer("access", "refresh", 900L, userResponse()));

        mockMvc.perform(post(BASE + "/login")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(json(new LoginRequest("ada@payflow.io", "correct-horse-9"))))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.accessToken").value("access"))
                .andExpect(jsonPath("$.refreshToken").value("refresh"))
                .andExpect(jsonPath("$.tokenType").value("Bearer"))
                .andExpect(jsonPath("$.expiresIn").value(900))
                .andExpect(jsonPath("$.user.email").value("ada@payflow.io"));
    }

    @Test
    @DisplayName("POST /login returns 400 when the body is missing a field")
    void loginValidationFailure() throws Exception {
        mockMvc.perform(post(BASE + "/login")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content("{\"email\":\"ada@payflow.io\"}"))
                .andExpect(status().isBadRequest())
                .andExpect(jsonPath("$.validationErrors.password").exists());
    }

    @Test
    @DisplayName("POST /login returns 400 for a malformed body without leaking the parser error")
    void loginMalformedBody() throws Exception {
        mockMvc.perform(post(BASE + "/login")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content("{\"email\":"))
                .andExpect(status().isBadRequest())
                .andExpect(jsonPath("$.message").value("Malformed request body"));
    }

    @Test
    @DisplayName("POST /refresh returns 401 for a revoked token")
    void refreshRejectsRevokedToken() throws Exception {
        when(authService.refresh(any(RefreshTokenRequest.class)))
                .thenThrow(new InvalidTokenException("Refresh token is invalid or expired"));

        mockMvc.perform(post(BASE + "/refresh")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(json(new RefreshTokenRequest("revoked-token"))))
                .andExpect(status().isUnauthorized())
                .andExpect(jsonPath("$.status").value(401))
                .andExpect(jsonPath("$.message").value("Refresh token is invalid or expired"));
    }

    @Test
    @DisplayName("POST /logout returns 204 and passes the caller's identity to the service")
    void logoutReturnsNoContent() throws Exception {
        authenticateAs("ada@payflow.io");

        mockMvc.perform(post(BASE + "/logout")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(json(new RefreshTokenRequest("refresh-token"))))
                .andExpect(status().isNoContent());

        verify(authService).logout(any(RefreshTokenRequest.class), anyString());
    }

    @Test
    @DisplayName("GET /me returns the authenticated caller's profile")
    void meReturnsProfile() throws Exception {
        authenticateAs("ada@payflow.io");
        when(authService.getCurrentUser("ada@payflow.io")).thenReturn(userResponse());

        mockMvc.perform(get(BASE + "/me"))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.email").value("ada@payflow.io"))
                .andExpect(jsonPath("$.passwordHash").doesNotExist());
    }

    @Test
    @DisplayName("an unexpected failure returns a 500 that reveals nothing")
    void unexpectedFailureIsOpaque() throws Exception {
        doThrow(new IllegalStateException("connection pool exhausted at jdbc:postgresql://db:5432"))
                .when(authService).login(any(LoginRequest.class));

        mockMvc.perform(post(BASE + "/login")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(json(new LoginRequest("ada@payflow.io", "correct-horse-9"))))
                .andExpect(status().isInternalServerError())
                .andExpect(jsonPath("$.message")
                        .value("An unexpected error occurred. Please try again later."));
    }

    /**
     * Populates the security context directly. With the filter chain disabled there is
     * nothing to establish an authentication, but {@code @AuthenticationPrincipal} still
     * resolves from {@link SecurityContextHolder}.
     */
    private void authenticateAs(String email) {
        User user = User.builder()
                .id(userId)
                .email(email)
                .passwordHash("$2a$10$hashed")
                .fullName("Ada Lovelace")
                .role(Role.USER)
                .enabled(true)
                .build();
        UserPrincipal principal = new UserPrincipal(user);
        SecurityContextHolder.getContext().setAuthentication(
                new UsernamePasswordAuthenticationToken(
                        principal, null, principal.getAuthorities()));
    }
}
