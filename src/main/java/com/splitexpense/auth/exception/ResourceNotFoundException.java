package com.splitexpense.auth.exception;

/**
 * Raised when a requested record does not exist. Mapped to HTTP 404.
 */
public class ResourceNotFoundException extends RuntimeException {

    public ResourceNotFoundException(String message) {
        super(message);
    }

    /**
     * @param resource human-readable type name, e.g. {@code User}
     * @param field    the attribute searched on
     * @param value    the value searched for
     * @return an exception with a uniform "User not found with email: ada@splitexpense.io" message
     */
    public static ResourceNotFoundException of(String resource, String field, Object value) {
        return new ResourceNotFoundException(
                "%s not found with %s: %s".formatted(resource, field, value));
    }
}
