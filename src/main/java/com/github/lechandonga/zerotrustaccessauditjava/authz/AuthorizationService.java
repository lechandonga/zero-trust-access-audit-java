package com.github.lechandonga.zerotrustaccessauditjava.authz;

import com.github.lechandonga.zerotrustaccessauditjava.audit.AuditRecord;
import com.github.lechandonga.zerotrustaccessauditjava.audit.AuditService;
import com.github.lechandonga.zerotrustaccessauditjava.credential.CredentialService;
import org.springframework.stereotype.Service;

import java.util.List;

/**
 * Evaluates resource requests against the current policy snapshot.
 *
 * <p>Every decision — allowed or denied — is captured as an audit record.
 * The policy is read once per evaluation, so a concurrent policy update can
 * never produce a decision mixing rules from two policy versions. Default
 * outcome with no matching rule is DENY.
 */
@Service
public class AuthorizationService {

    private final PolicyStore policyStore;
    private final AuditService auditService;

    public AuthorizationService(PolicyStore policyStore, AuditService auditService) {
        this.policyStore = policyStore;
        this.auditService = auditService;
    }

    public AuditRecord authorize(CredentialService.VerifiedCredential credential,
                                 ResourceRequest request) {
        Policy snapshot = policyStore.current();
        AuthorizationResult result = evaluate(snapshot, credential, request);
        return auditService.append(credential, result);
    }

    AuthorizationResult evaluate(Policy policy, CredentialService.VerifiedCredential credential,
                                 ResourceRequest request) {
        List<String> roles = credential.roles();
        for (Policy.Rule rule : policy.rules()) {
            if (matches(rule, roles, request)) {
                return AuthorizationResult.of(rule, policy, credential.subject(), roles, request);
            }
        }
        return AuthorizationResult.deny("default-deny", policy,
                credential.subject(), roles, request);
    }

    private boolean matches(Policy.Rule rule, List<String> roles, ResourceRequest request) {
        return containsAnyOrWildcard(rule.roles(), roles)
                && scalarMatches(rule.actions(), request.action())
                && scalarMatches(rule.resourceTypes(), request.resourceType())
                && scalarMatches(rule.environments(), request.environment())
                && containsAnyOrWildcard(rule.tags(), request.tags());
    }

    private boolean scalarMatches(List<String> allowed, String actual) {
        return allowed.isEmpty() || actual != null && allowed.contains(actual);
    }

    private boolean containsAnyOrWildcard(List<String> required, List<String> actual) {
        if (required.isEmpty()) {
            return true;
        }
        for (String value : actual) {
            if (required.contains(value)) {
                return true;
            }
        }
        return false;
    }
}

