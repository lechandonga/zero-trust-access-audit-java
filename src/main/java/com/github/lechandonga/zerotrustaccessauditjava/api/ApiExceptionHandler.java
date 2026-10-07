package com.github.lechandonga.zerotrustaccessauditjava.api;

import com.github.lechandonga.zerotrustaccessauditjava.authz.AuthorizationService;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.ExceptionHandler;
import org.springframework.web.bind.annotation.RestControllerAdvice;

import java.util.Map;

@RestControllerAdvice
public class ApiExceptionHandler {

    @ExceptionHandler(AuthorizationService.AuditAccessDeniedException.class)
    public ResponseEntity<Map<String, Object>> auditDenied(AuthorizationService.AuditAccessDeniedException e) {
        return ResponseEntity.status(HttpStatus.FORBIDDEN)
                .body(Map.of("error", "audit access denied", "detail", e.getMessage()));
    }

    @ExceptionHandler(UnauthenticatedException.class)
    public ResponseEntity<Map<String, Object>> unauthenticated(UnauthenticatedException e) {
        return ResponseEntity.status(HttpStatus.UNAUTHORIZED)
                .body(Map.of("error", "unauthenticated", "reason", e.reason, "detail", e.getMessage()));
    }

    /** 凭证校验未通过时抛出，reason 为可区分的拒绝原因名。 */
    public static class UnauthenticatedException extends RuntimeException {
        final String reason;

        public UnauthenticatedException(String reason, String detail) {
            super(detail);
            this.reason = reason;
        }
    }
}
