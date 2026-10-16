package dev.passkeyforge;

import org.springframework.http.*;
import org.springframework.web.bind.annotation.*;

public class ApiError extends RuntimeException {
  final int status;

  public ApiError(int status, String message) {
    super(message);
    this.status = status;
  }

  public static ApiError denied() {
    return new ApiError(401, "Authentication failed or expired");
  }

  @RestControllerAdvice
  static class Handler {
    @ExceptionHandler(ApiError.class)
    ResponseEntity<?> known(ApiError e) {
      return ResponseEntity.status(e.status).body(java.util.Map.of("error", e.getMessage()));
    }

    @ExceptionHandler({
      org.springframework.web.bind.MethodArgumentNotValidException.class,
      org.springframework.http.converter.HttpMessageNotReadableException.class,
      IllegalArgumentException.class
    })
    ResponseEntity<?> invalid(Exception e) {
      return ResponseEntity.badRequest().body(java.util.Map.of("error", "Invalid request"));
    }

    @ExceptionHandler(org.springframework.dao.DataIntegrityViolationException.class)
    ResponseEntity<?> conflict(Exception e) {
      return ResponseEntity.status(409)
          .body(java.util.Map.of("error", "Operation conflicts with current account state"));
    }
  }
}
