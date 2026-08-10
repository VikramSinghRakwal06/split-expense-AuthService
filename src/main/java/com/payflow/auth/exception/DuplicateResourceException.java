package com.payflow.auth.exception;

/**
 * Raised when a write would violate a uniqueness rule, such as registering an email that
 * already has an account. Mapped to HTTP 409.
 */
public class DuplicateResourceException extends RuntimeException {

    public DuplicateResourceException(String message) {
        super(message);
    }
}
