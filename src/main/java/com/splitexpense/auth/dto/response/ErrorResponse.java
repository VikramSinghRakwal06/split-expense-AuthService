package com.splitexpense.auth.dto.response;

import io.swagger.v3.oas.annotations.media.Schema;
import java.time.Instant;
import java.util.Map;
import lombok.Builder;

/**
 * The single error shape returned by every failing endpoint, produced by
 * {@code GlobalExceptionHandler}.
 *
 * <p>{@code validationErrors} is null, and so omitted from the JSON, for everything
 * except a request body that failed bean validation.
 *
 * @param timestamp        when the failure was handled
 * @param status           HTTP status code
 * @param error            HTTP reason phrase, e.g. {@code Conflict}
 * @param message          human-readable summary, safe to show a caller
 * @param path             request URI that failed
 * @param validationErrors field name to rejection reason, only for 400s
 */
@Builder
@Schema(description = "Standard error payload")
public record ErrorResponse(
        Instant timestamp,
        int status,
        String error,
        String message,
        String path,
        Map<String, String> validationErrors) {
}
