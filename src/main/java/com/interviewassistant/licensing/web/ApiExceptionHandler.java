package com.interviewassistant.licensing.web;

import com.interviewassistant.licensing.service.ErrorCode;
import com.interviewassistant.licensing.service.LicensingException;
import com.interviewassistant.licensing.store.StoreExceptions;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatusCode;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.MethodArgumentNotValidException;
import org.springframework.web.bind.annotation.ExceptionHandler;
import org.springframework.web.bind.annotation.RestControllerAdvice;
import org.springframework.web.context.request.WebRequest;
import org.springframework.web.servlet.mvc.method.annotation.ResponseEntityExceptionHandler;

/**
 * One consistent, safe error shape for every failure. Nothing from the request (field values, activation codes, SQL, stack
 * traces, exception messages of unexpected errors) is ever echoed to the caller.
 */
@RestControllerAdvice
class ApiExceptionHandler extends ResponseEntityExceptionHandler {

    private static final System.Logger LOG = System.getLogger(ApiExceptionHandler.class.getName());

    @ExceptionHandler(LicensingException.class)
    ResponseEntity<ApiError> handleLicensing(LicensingException e) {
        ResponseEntity.BodyBuilder b = ResponseEntity.status(e.code().httpStatus());
        if (e.retryAfterSeconds() > 0) {
            b.header(HttpHeaders.RETRY_AFTER, Long.toString(e.retryAfterSeconds()));
        }
        return b.body(new ApiError(e.code().name(), e.getMessage()));
    }

    @ExceptionHandler(SecurityFilter.BodyTooLargeException.class)
    ResponseEntity<ApiError> handleTooLarge(SecurityFilter.BodyTooLargeException e) {
        return body(ErrorCode.PAYLOAD_TOO_LARGE);
    }

    @ExceptionHandler(StoreExceptions.StoreFailureException.class)
    ResponseEntity<ApiError> handleStore(StoreExceptions.StoreFailureException e) {
        // Deliberately WITHOUT the cause: the database driver's message can carry the failing row (customer e-mail included).
        // The exception's own message already holds the SQLState, which is what diagnosis needs.
        LOG.log(System.Logger.Level.ERROR, "storage failure: " + e.getMessage());
        return body(ErrorCode.INTERNAL_ERROR);
    }

    @ExceptionHandler(Exception.class)
    ResponseEntity<ApiError> handleUnexpected(Exception e) {
        LOG.log(System.Logger.Level.ERROR, "unexpected " + e.getClass().getName(), e);
        return body(ErrorCode.INTERNAL_ERROR);
    }

    /** Spring's own failures (bad JSON, wrong method/media type, validation) get the same body shape and no detail. */
    @Override
    protected ResponseEntity<Object> handleExceptionInternal(Exception ex, Object ignoredBody, HttpHeaders headers,
                                                             HttpStatusCode status, WebRequest request) {
        Throwable cause = ex;
        while (cause != null) {
            if (cause instanceof SecurityFilter.BodyTooLargeException) {
                return ResponseEntity.status(ErrorCode.PAYLOAD_TOO_LARGE.httpStatus()).body(
                        new ApiError(ErrorCode.PAYLOAD_TOO_LARGE.name(), ErrorCode.PAYLOAD_TOO_LARGE.defaultMessage()));
            }
            cause = cause.getCause();
        }
        ErrorCode code = status.value() == 400 || ex instanceof MethodArgumentNotValidException ? ErrorCode.VALIDATION_FAILED
                : status.is5xxServerError() ? ErrorCode.INTERNAL_ERROR : ErrorCode.VALIDATION_FAILED;
        String message = status.value() == 404 ? "No such endpoint."
                : status.value() == 405 ? "Method not allowed."
                : status.value() == 415 ? "Unsupported media type; send application/json."
                : code.defaultMessage();
        if (status.is5xxServerError()) {
            LOG.log(System.Logger.Level.ERROR, "framework failure " + ex.getClass().getName(), ex);
        }
        return ResponseEntity.status(status).body(new ApiError(code.name(), message));
    }

    private static ResponseEntity<ApiError> body(ErrorCode code) {
        return ResponseEntity.status(code.httpStatus()).body(new ApiError(code.name(), code.defaultMessage()));
    }
}
