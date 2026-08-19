package com.splitexpense.auth;

import static org.assertj.core.api.Assertions.assertThat;

import com.splitexpense.auth.dto.request.LoginRequest;
import com.splitexpense.auth.dto.request.RefreshTokenRequest;
import com.splitexpense.auth.dto.request.RegisterRequest;
import com.splitexpense.auth.dto.response.AuthResponse;
import com.splitexpense.auth.dto.response.UserResponse;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.resttestclient.TestRestTemplate;
import org.springframework.boot.resttestclient.autoconfigure.AutoConfigureTestRestTemplate;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.http.HttpEntity;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpMethod;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.test.context.DynamicPropertyRegistry;
import org.springframework.test.context.DynamicPropertySource;
import org.testcontainers.junit.jupiter.Container;
import org.testcontainers.junit.jupiter.Testcontainers;
import org.testcontainers.postgresql.PostgreSQLContainer;

/**
 * End-to-end test over the real stack: a genuine PostgreSQL instance, the Flyway
 * migration, the full security filter chain and HTTP.
 *
 * <p>Also serves as the context-loads check — if the entity mappings and the migrated
 * schema ever disagree, Hibernate's {@code validate} fails here at start-up.
 */
@Testcontainers
@SpringBootTest(webEnvironment = SpringBootTest.WebEnvironment.RANDOM_PORT)
// Spring Boot 4 no longer contributes TestRestTemplate implicitly; it must be requested.
@AutoConfigureTestRestTemplate
class AuthFlowIntegrationTest {

    private static final String BASE = "/api/v1/auth";

    @Container
    @SuppressWarnings("resource") // Lifecycle is managed by the Testcontainers extension.
    static PostgreSQLContainer postgres = new PostgreSQLContainer("postgres:16-alpine")
            .withDatabaseName("splitexpense_auth")
            .withUsername("splitexpense")
            .withPassword("splitexpense");

    @DynamicPropertySource
    static void datasourceProperties(DynamicPropertyRegistry registry) {
        registry.add("spring.datasource.url", postgres::getJdbcUrl);
        registry.add("spring.datasource.username", postgres::getUsername);
        registry.add("spring.datasource.password", postgres::getPassword);
        // Pinned so the test does not depend on whichever profile a developer has active.
        registry.add("splitexpense.jwt.secret",
                () -> "integration-test-secret-key-of-more-than-32-bytes");
        registry.add("splitexpense.jwt.issuer", () -> "splitexpense-auth-service");
    }

    @Autowired private TestRestTemplate restTemplate;

    @Test
    @DisplayName("register, then log in, then call /me with the issued token")
    void registerLoginAndFetchProfile() {
        String email = "ada@splitexpense.io";
        String password = "correct-horse-9";

        // 1. Register.
        ResponseEntity<UserResponse> registered = restTemplate.postForEntity(
                BASE + "/register",
                new RegisterRequest(email, password, "Ada Lovelace", "+441632960961"),
                UserResponse.class);

        assertThat(registered.getStatusCode()).isEqualTo(HttpStatus.CREATED);
        assertThat(registered.getBody()).isNotNull();
        assertThat(registered.getBody().email()).isEqualTo(email);
        assertThat(registered.getBody().id()).isNotNull();

        // 2. Log in.
        ResponseEntity<AuthResponse> loggedIn = restTemplate.postForEntity(
                BASE + "/login", new LoginRequest(email, password), AuthResponse.class);

        assertThat(loggedIn.getStatusCode()).isEqualTo(HttpStatus.OK);
        assertThat(loggedIn.getBody()).isNotNull();
        AuthResponse tokens = loggedIn.getBody();
        assertThat(tokens.accessToken()).isNotBlank();
        assertThat(tokens.refreshToken()).isNotBlank();
        assertThat(tokens.tokenType()).isEqualTo("Bearer");
        assertThat(tokens.expiresIn()).isEqualTo(900L);

        // 3. Call /me with the returned access token.
        ResponseEntity<UserResponse> profile = restTemplate.exchange(
                BASE + "/me", HttpMethod.GET,
                new HttpEntity<>(bearer(tokens.accessToken())), UserResponse.class);

        assertThat(profile.getStatusCode()).isEqualTo(HttpStatus.OK);
        assertThat(profile.getBody()).isNotNull();
        assertThat(profile.getBody().email()).isEqualTo(email);
        assertThat(profile.getBody().id()).isEqualTo(registered.getBody().id());
    }

    @Test
    @DisplayName("/me is unauthorised without a token")
    void meRequiresAuthentication() {
        ResponseEntity<String> response =
                restTemplate.getForEntity(BASE + "/me", String.class);

        assertThat(response.getStatusCode()).isEqualTo(HttpStatus.UNAUTHORIZED);
        assertThat(response.getBody()).contains("\"status\":401");
    }

    @Test
    @DisplayName("a refresh token cannot be used as a bearer credential")
    void refreshTokenIsNotABearerCredential() {
        AuthResponse tokens = registerAndLogin("grace@splitexpense.io");

        ResponseEntity<String> response = restTemplate.exchange(
                BASE + "/me", HttpMethod.GET,
                new HttpEntity<>(bearer(tokens.refreshToken())), String.class);

        assertThat(response.getStatusCode()).isEqualTo(HttpStatus.UNAUTHORIZED);
    }

    @Test
    @DisplayName("refresh rotates the token, and the spent one stops working")
    void refreshRotatesToken() {
        AuthResponse tokens = registerAndLogin("katherine@splitexpense.io");

        ResponseEntity<AuthResponse> refreshed = restTemplate.postForEntity(
                BASE + "/refresh",
                new RefreshTokenRequest(tokens.refreshToken()),
                AuthResponse.class);

        assertThat(refreshed.getStatusCode()).isEqualTo(HttpStatus.OK);
        assertThat(refreshed.getBody()).isNotNull();
        assertThat(refreshed.getBody().refreshToken()).isNotEqualTo(tokens.refreshToken());

        // Replaying the spent token must fail.
        ResponseEntity<String> replay = restTemplate.postForEntity(
                BASE + "/refresh",
                new RefreshTokenRequest(tokens.refreshToken()),
                String.class);

        assertThat(replay.getStatusCode()).isEqualTo(HttpStatus.UNAUTHORIZED);
    }

    @Test
    @DisplayName("logout revokes the refresh token so it can no longer be exchanged")
    void logoutRevokesRefreshToken() {
        AuthResponse tokens = registerAndLogin("margaret@splitexpense.io");

        ResponseEntity<Void> loggedOut = restTemplate.exchange(
                BASE + "/logout", HttpMethod.POST,
                new HttpEntity<>(new RefreshTokenRequest(tokens.refreshToken()),
                        bearerJson(tokens.accessToken())),
                Void.class);

        assertThat(loggedOut.getStatusCode()).isEqualTo(HttpStatus.NO_CONTENT);

        ResponseEntity<String> afterLogout = restTemplate.postForEntity(
                BASE + "/refresh",
                new RefreshTokenRequest(tokens.refreshToken()),
                String.class);

        assertThat(afterLogout.getStatusCode()).isEqualTo(HttpStatus.UNAUTHORIZED);
    }

    @Test
    @DisplayName("a duplicate registration is rejected with 409")
    void duplicateRegistrationIsRejected() {
        RegisterRequest request = new RegisterRequest(
                "dorothy@splitexpense.io", "correct-horse-9", "Dorothy Vaughan", null);

        assertThat(restTemplate.postForEntity(BASE + "/register", request, UserResponse.class)
                        .getStatusCode())
                .isEqualTo(HttpStatus.CREATED);

        ResponseEntity<String> duplicate =
                restTemplate.postForEntity(BASE + "/register", request, String.class);

        assertThat(duplicate.getStatusCode()).isEqualTo(HttpStatus.CONFLICT);
        assertThat(duplicate.getBody()).contains("\"status\":409");
    }

    @Test
    @DisplayName("wrong credentials and an unknown account are indistinguishable")
    void loginFailuresAreIndistinguishable() {
        registerAndLogin("mary@splitexpense.io");

        ResponseEntity<String> wrongPassword = restTemplate.postForEntity(
                BASE + "/login",
                new LoginRequest("mary@splitexpense.io", "wrong-password-1"),
                String.class);

        ResponseEntity<String> unknownAccount = restTemplate.postForEntity(
                BASE + "/login",
                new LoginRequest("nobody@splitexpense.io", "correct-horse-9"),
                String.class);

        assertThat(wrongPassword.getStatusCode()).isEqualTo(HttpStatus.UNAUTHORIZED);
        assertThat(unknownAccount.getStatusCode()).isEqualTo(wrongPassword.getStatusCode());
        assertThat(unknownAccount.getBody()).contains("Invalid email or password");
        assertThat(wrongPassword.getBody()).contains("Invalid email or password");
    }

    @Test
    @DisplayName("an unknown path returns 404, not a 500 from the catch-all handler")
    void unknownPathReturnsNotFound() {
        AuthResponse tokens = registerAndLogin("annie@splitexpense.io");

        ResponseEntity<String> response = restTemplate.exchange(
                BASE + "/does-not-exist", HttpMethod.GET,
                new HttpEntity<>(bearer(tokens.accessToken())), String.class);

        assertThat(response.getStatusCode()).isEqualTo(HttpStatus.NOT_FOUND);
        assertThat(response.getBody()).contains("\"status\":404");
    }

    @Test
    @DisplayName("the health probe is public")
    void healthIsPublic() {
        assertThat(restTemplate.getForEntity("/actuator/health", String.class).getStatusCode())
                .isEqualTo(HttpStatus.OK);
    }

    @Test
    @DisplayName("metrics stay behind authentication")
    void metricsAreProtected() {
        assertThat(restTemplate.getForEntity("/actuator/metrics", String.class).getStatusCode())
                .isEqualTo(HttpStatus.UNAUTHORIZED);
    }

    private AuthResponse registerAndLogin(String email) {
        restTemplate.postForEntity(
                BASE + "/register",
                new RegisterRequest(email, "correct-horse-9", "Test Account", null),
                UserResponse.class);

        return restTemplate.postForEntity(
                        BASE + "/login",
                        new LoginRequest(email, "correct-horse-9"),
                        AuthResponse.class)
                .getBody();
    }

    private HttpHeaders bearer(String token) {
        HttpHeaders headers = new HttpHeaders();
        headers.setBearerAuth(token);
        return headers;
    }

    private HttpHeaders bearerJson(String token) {
        HttpHeaders headers = bearer(token);
        headers.setContentType(MediaType.APPLICATION_JSON);
        return headers;
    }
}
