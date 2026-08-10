package com.payflow.auth.dto.response;

import io.swagger.v3.oas.annotations.media.Schema;

/**
 * Result of a successful {@code /login} or {@code /refresh}.
 *
 * @param accessToken  short-lived JWT; send as {@code Authorization: Bearer <token>}
 * @param refreshToken long-lived token used to obtain the next access token
 * @param tokenType    always {@code Bearer}, per RFC 6750
 * @param expiresIn    lifetime of {@code accessToken} in seconds, so clients can refresh
 *                     ahead of expiry instead of waiting for a 401
 * @param user         profile of the authenticated account, saving the client a call to /me
 */
@Schema(description = "Issued tokens and the account they belong to")
public record AuthResponse(
        String accessToken,
        String refreshToken,
        String tokenType,
        long expiresIn,
        UserResponse user) {

    private static final String BEARER = "Bearer";

    /**
     * @param accessToken  freshly minted access JWT
     * @param refreshToken refresh token backing the session
     * @param expiresIn    access token lifetime in seconds
     * @param user         authenticated account
     * @return a response with {@code tokenType} set to {@code Bearer}
     */
    public static AuthResponse bearer(
            String accessToken, String refreshToken, long expiresIn, UserResponse user) {
        return new AuthResponse(accessToken, refreshToken, BEARER, expiresIn, user);
    }
}
