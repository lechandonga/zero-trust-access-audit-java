package com.github.lechandonga.zerotrustaccessauditjava.web;

import com.github.lechandonga.zerotrustaccessauditjava.audit.AuditRecord;
import com.github.lechandonga.zerotrustaccessauditjava.audit.AuditService;
import com.github.lechandonga.zerotrustaccessauditjava.authz.AuthorizationService;
import com.github.lechandonga.zerotrustaccessauditjava.authz.Policy;
import com.github.lechandonga.zerotrustaccessauditjava.authz.PolicyStore;
import com.github.lechandonga.zerotrustaccessauditjava.authz.ResourceRequest;
import com.github.lechandonga.zerotrustaccessauditjava.credential.CredentialService;
import com.github.lechandonga.zerotrustaccessauditjava.crypto.KeyManager;
import jakarta.servlet.http.HttpServletRequest;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.PutMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

import java.util.List;
import java.util.Map;

/**
 * Management and decision endpoints. Responses expose only ids, roles,
 * decisions and metadata — never signing keys. The credential token is
 * returned exactly once, in the issuance response.
 */
@RestController
public class ZtaaController {

    private final CredentialService credentialService;
    private final KeyManager keyManager;
    private final PolicyStore policyStore;
    private final AuthorizationService authorizationService;
    private final AuditService auditService;

    public ZtaaController(CredentialService credentialService,
                          KeyManager keyManager,
                          PolicyStore policyStore,
                          AuthorizationService authorizationService,
                          AuditService auditService) {
        this.credentialService = credentialService;
        this.keyManager = keyManager;
        this.policyStore = policyStore;
        this.authorizationService = authorizationService;
        this.auditService = auditService;
    }

    @PostMapping("/ztaa/credentials")
    public Map<String, Object> issue(HttpServletRequest request,
                                     @RequestBody Map<String, Object> body) {
        requireAdmin(principal(request));
        String subject = String.valueOf(body.getOrDefault("subject", ""));
        @SuppressWarnings("unchecked")
        List<String> roles = (List<String>) body.getOrDefault("roles", List.of());
        CredentialService.Credential credential = credentialService.issue(subject, roles);
        return Map.of(
                "token", credential.token(),
                "jti", credential.jti(),
                "subject", credential.subject(),
                "roles", credential.roles(),
                "keyId", credential.keyId(),
                "issuedAt", credential.issuedAt(),
                "expiresAt", credential.expiresAt());
    }

    @PostMapping("/ztaa/credentials/revoke")
    public Map<String, Object> revoke(HttpServletRequest request,
                                      @RequestBody Map<String, String> body) {
        requireAdmin(principal(request));
        boolean newlyRevoked = credentialService.revoke(body.get("jti"));
        return Map.of("jti", body.get("jti"), "revoked", newlyRevoked);
    }

    @GetMapping("/ztaa/keys")
    public Map<String, Object> keys(HttpServletRequest request) {
        requireAdmin(principal(request));
        return Map.of("activeKeyId", keyManager.activeKeyId(), "keys", keyManager.listKeys());
    }

    @PostMapping("/ztaa/keys/rotate")
    public Map<String, Object> rotate(HttpServletRequest request) {
        requireAdmin(principal(request));
        String keyId = keyManager.rotate();
        return Map.of("activeKeyId", keyId, "keys", keyManager.listKeys());
    }

    @GetMapping("/ztaa/policy")
    public Map<String, Object> getPolicy(HttpServletRequest request) {
        requireAdmin(principal(request));
        Policy policy = policyStore.current();
        return Map.of("version", policy.version(), "rules", policy.rules());
    }

    @PutMapping("/ztaa/policy")
    public Map<String, Object> putPolicy(HttpServletRequest request,
                                         @RequestBody PolicyUpdate update) {
        requireAdmin(principal(request));
        List<Policy.Rule> rules = update.rules() == null
                ? List.of()
                : update.rules().stream().map(PolicyUpdate.RuleDto::toRule).toList();
        long version = policyStore.publish(rules);
        return Map.of("version", version, "rules", rules);
    }

    @PostMapping("/api/access/evaluate")
    public AuditRecord evaluate(HttpServletRequest request,
                                @RequestBody ResourceRequest resourceRequest) {
        Principal principal = principal(request);
        CredentialService.VerifiedCredential credential = new CredentialService.VerifiedCredential(
                principal.jti() == null ? "admin-token" : principal.jti(),
                principal.subject(), principal.roles(),
                principal.keyId(), Long.MAX_VALUE);
        return authorizationService.authorize(credential, resourceRequest);
    }

    @GetMapping("/ztaa/audit")
    public Map<String, Object> audit(HttpServletRequest request,
                                     @RequestParam(required = false) String subject,
                                     @RequestParam(defaultValue = "50") int limit) {
        Principal principal = principal(request);
        if (!principal.isAdmin() && !principal.hasRole("audit-reader")) {
            throw new ForbiddenException("audit query requires permission audit:read");
        }
        List<AuditRecord> records = auditService.query(subject, limit);
        return Map.of("count", records.size(), "records", records);
    }

    private static Principal principal(HttpServletRequest request) {
        return (Principal) request.getAttribute(AuthInterceptor.PRINCIPAL_ATTRIBUTE);
    }

    private static void requireAdmin(Principal principal) {
        if (!principal.isAdmin()) {
            throw new ForbiddenException("management endpoint requires role admin");
        }
    }

 public record PolicyUpdate(List<RuleDto> rules) {
        public record RuleDto(String name, String effect,
                              List<String> roles,
                              List<String> actions,
                              List<String> resourceTypes,
                              List<String> environments,
                              List<String> tags) {
            Policy.Rule toRule() {
                return new Policy.Rule(name, Policy.Effect.valueOf(effect),
                        roles, actions, resourceTypes, environments, tags);
            }
        }
    }

    static class ForbiddenException extends RuntimeException {
        ForbiddenException(String message) {
            super(message);
        }
    }

    @org.springframework.web.bind.annotation.ExceptionHandler(ForbiddenException.class)
    public ResponseEntity<Map<String, String>> forbidden(ForbiddenException e) {
        return ResponseEntity.status(HttpStatus.FORBIDDEN)
                .body(Map.of("error", "forbidden", "message", e.getMessage()));
    }

    @org.springframework.web.bind.annotation.ExceptionHandler(IllegalArgumentException.class)
    public ResponseEntity<Map<String, String>> badRequest(IllegalArgumentException e) {
        return ResponseEntity.badRequest()
                .body(Map.of("error", "bad_request", "message", e.getMessage()));
    }
}

