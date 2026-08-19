package com.splitexpense.auth.dto.request;

import io.swagger.v3.oas.annotations.media.Schema;
import jakarta.validation.constraints.NotBlank;

/**
 * Payload for {@code POST /api/v1/auth/refresh} and {@code POST /api/v1/auth/logout}.
 *
 * @param refreshToken the refresh token previously issued by {@code /login} or {@code /refresh}
 */
@Schema(description = "A previously issued refresh token")
public record RefreshTokenRequest(

        @Schema(description = "Opaque refresh token value")
        @NotBlank(message = "Refresh token is required")
        String refreshToken) {
}
