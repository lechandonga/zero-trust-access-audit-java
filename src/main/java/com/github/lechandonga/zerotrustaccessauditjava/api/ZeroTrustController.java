package com.github.lechandonga.zerotrustaccessauditjava.api;

import com.github.lechandonga.zerotrustaccessauditjava.audit.AuditRecord;
import com.github.lechandonga.zerotrustaccessauditjava.authz.AuthorizationService;
import com.github.lechandonga.zerotrustaccessauditjava.authz.Policy;
import com.github.lechandonga.zerotrustaccessauditjava.credential.CredentialClaims;
import com.github.lechandonga.zerotrustaccessauditjava.credential.CredentialService;
import com.github.lechandonga.zerotrustaccessauditjava.credential.VerificationResult;
import com.github.lechandonga.zerotrustaccessauditjava.keys.KeyManager;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestHeader;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import java.time.Duration;
import java.util.List;
import java.util.Map;
import java.util.Set;

/**
 * 零信任访问控制 REST 接口。
 * 响应与日志中绝不包含凭证原文或密钥内容。
 */
@RestController
@RequestMapping("/api/zt")
public class ZeroTrustController {

    private final CredentialService credentialService;
    private final KeyManager keyManager;
    private final AuthorizationService authorizationService;

    public ZeroTrustController(CredentialService credentialService, KeyManager keyManager,
                               AuthorizationService authorizationService) {
        this.credentialService = credentialService;
        this.keyManager = keyManager;
        this.authorizationService = authorizationService;
    }

    public record IssueRequest(String subject, Set<String> roles,
                               Map<String, String> attributes, long ttlSeconds) {
    }

    @PostMapping("/credentials")
    public Map<String, Object> issue(@RequestBody IssueRequest req) {
        String token = credentialService.issue(req.subject(), req.roles(), req.attributes(),
                Duration.ofSeconds(req.ttlSeconds()));
        return Map.of("credential", token, "keyId", keyManager.currentKeyId());
    }

    @PostMapping("/credentials/verify")
    public Map<String, Object> verify(@RequestBody Map<String, String> body) {
        VerificationResult result = credentialService.verify(body.get("credential"));
        if (result instanceof VerificationResult.Valid valid) {
            CredentialClaims c = valid.claims();
            return Map.of("valid", true, "subject", c.subject(), "roles", c.roles(),
                    "attributes", c.attributes(), "expiresAt", c.expiresAt().toString());
        }
        VerificationResult.Invalid invalid = (VerificationResult.Invalid) result;
        return Map.of("valid", false, "reason", invalid.reason().name(), "detail", invalid.detail());
    }

    @PostMapping("/credentials/revoke")
    public Map<String, Object> revoke(@RequestBody Map<String, String> body) {
        boolean revoked = credentialService.revoke(body.get("credential"));
        return Map.of("revoked", revoked);
    }

    @PostMapping("/keys/rotate")
    public Map<String, Object> rotateKey() {
        return Map.of("activeKeyId", keyManager.rotate());
    }

    @GetMapping("/keys/current")
    public Map<String, Object> currentKey() {
        return Map.of("activeKeyId", keyManager.currentKeyId());
    }

    public record AuthorizeRequest(String action, String resourceType, Map<String, String> resourceAttrs) {
    }

    @PostMapping("/authorize")
    public Map<String, Object> authorize(@RequestHeader("Authorization") String authHeader,
                                         @RequestBody AuthorizeRequest req) {
        CredentialClaims claims = authenticate(authHeader);
        AuthorizationService.Decision decision = authorizationService.authorize(
                claims, req.action(), req.resourceType(), req.resourceAttrs());
        return Map.of("allowed", decision.allowed(), "reason", decision.reason(),
                "auditId", decision.auditId());
    }

    @PostMapping("/policy")
    public Map<String, Object> updatePolicy(@RequestBody Policy policy) {
        authorizationService.updatePolicy(policy);
        return Map.of("rules", authorizationService.currentPolicy().rules().size());
    }

    @GetMapping("/audit")
    public List<AuditRecord> audit(@RequestHeader("Authorization") String authHeader) {
        CredentialClaims claims = authenticate(authHeader);
        return authorizationService.queryAudit(claims);
    }

    private CredentialClaims authenticate(String authHeader) {
        String token = authHeader != null && authHeader.startsWith("Bearer ")
                ? authHeader.substring(7) : null;
        VerificationResult result = credentialService.verify(token);
        if (result instanceof VerificationResult.Valid valid) {
            return valid.claims();
        }
        VerificationResult.Invalid invalid = (VerificationResult.Invalid) result;
        throw new ApiExceptionHandler.UnauthenticatedException(invalid.reason().name(), invalid.detail());
    }
}
