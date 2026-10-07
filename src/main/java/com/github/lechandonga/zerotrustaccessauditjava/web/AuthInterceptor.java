package com.github.lechandonga.zerotrustaccessauditjava.web;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.github.lechandonga.zerotrustaccessauditjava.config.AppConfig;
import com.github.lechandonga.zerotrustaccessauditjava.credential.CredentialException;
import com.github.lechandonga.zerotrustaccessauditjava.credential.CredentialService;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.stereotype.Component;
import org.springframework.web.servlet.HandlerInterceptor;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.util.List;
import java.util.Map;

/**
 * Authenticates every request to protected paths.
 *
 * <p>Two schemes are accepted in the {@code Authorization} header:
 * <ul>
 *   <li>{@code Bearer <credential>} — HMAC credential, role comes from it;</li>
 *   <li>{@code AdminToken <token>} — local bootstrap management token,
 *       which carries the built-in {@code admin} role.</li>
 * </ul>
 *
 * Rejection responses carry the stable reason code but never the token,
 * signature or any key material. The token itself is never logged.
 */
@Component
public class AuthInterceptor implements HandlerInterceptor {

    public static final String PRINCIPAL_ATTRIBUTE = "ztaa.principal";

    private final CredentialService credentialService;
    private final AppConfig.BootstrapAdminToken adminToken;
    private final ObjectMapper mapper;

    public AuthInterceptor(CredentialService credentialService,
                           AppConfig.BootstrapAdminToken adminToken,
                           ObjectMapper mapper) {
        this.credentialService = credentialService;
        this.adminToken = adminToken;
        this.mapper = mapper;
    }

    @Override
    public boolean preHandle(HttpServletRequest request, HttpServletResponse response,
                             Object handler) throws Exception {
        String header = request.getHeader("Authorization");
        if (header == null || header.isBlank()) {
            return reject(response, HttpStatus.UNAUTHORIZED, "missing_authorization",
                    "Authorization header is required");
        }
        String[] parts = header.split(" ", 2);
        if (parts.length != 2) {
            return reject(response, HttpStatus.UNAUTHORIZED, "malformed_authorization",
                    "Authorization header must be '<scheme> <token>'");
        }
        String scheme = parts[0];
        String token = parts[1];
        try {
            Principal principal;
            if ("Bearer".equalsIgnoreCase(scheme)) {
                CredentialService.VerifiedCredential verified = credentialService.verify(token);
                principal = new Principal(verified.subject(), verified.roles(),
                        verified.jti(), verified.keyId());
            } else if ("AdminToken".equalsIgnoreCase(scheme)) {
                if (!constantTimeEquals(adminToken.value(), token)) {
                    return reject(response, HttpStatus.UNAUTHORIZED, "invalid_admin_token",
                            "bootstrap admin token is invalid");
                }
                principal = new Principal("bootstrap-admin", List.of("admin"), null, null);
            } else {
                return reject(response, HttpStatus.UNAUTHORIZED, "unsupported_scheme",
                        "use Bearer or AdminToken");
            }
            request.setAttribute(PRINCIPAL_ATTRIBUTE, principal);
            return true;
        } catch (CredentialException e) {
            return reject(response, HttpStatus.UNAUTHORIZED, e.rejection().code(), e.getMessage());
        }
    }

    static boolean constantTimeEquals(String expected, String actual) {
        return MessageDigest.isEqual(
                expected.getBytes(StandardCharsets.UTF_8),
                actual.getBytes(StandardCharsets.UTF_8));
    }

    private boolean reject(HttpServletResponse response, HttpStatus status,
                           String code, String message) throws Exception {
        response.setStatus(status.value());
        response.setContentType(MediaType.APPLICATION_JSON_VALUE);
        response.setCharacterEncoding(StandardCharsets.UTF_8.name());
        mapper.writeValue(response.getWriter(), Map.of("error", code, "message", message));
        return false;
    }
}
