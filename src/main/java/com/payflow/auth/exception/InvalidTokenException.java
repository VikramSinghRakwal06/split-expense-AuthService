package com.payflow.auth.exception;

/**
 * Raised when a refresh token is unusable — unknown, malformed, expired, already revoked,
 * or an access token presented where a refresh token was required. Mapped to HTTP 401.
 *
 * <p>Every one of those conditions produces the same message on the wire. Distinguishing
 * "this token never existed" from "this token was revoked" would tell a caller holding a
 * stolen token which of their guesses were once real.
 */
public class InvalidTokenException extends RuntimeException {

    public InvalidTokenException(String message) {
        super(message);
    }
}
