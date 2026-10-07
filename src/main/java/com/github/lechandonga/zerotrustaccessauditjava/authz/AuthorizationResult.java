package com.github.lechandonga.zerotrustaccessauditjava.authz;

import java.util.List;

/**
 * Outcome of an authorization decision. {@code denied} is the default;
 * the matched rule name is null for default denies.
 */
public record AuthorizationResult(boolean allowed,
                                  String reason,
                                  String matchedRule,
                                  long policyVersion,
                                  String subject,
                                  List<String> roles,
                                  String action,
                                  String resourceType,
                                  String resourceId) {

    static AuthorizationResult deny(String reason, Policy policy, String subject,
                                    List<String> roles, ResourceRequest request) {
        return new AuthorizationResult(false, reason, null, policy.version(), subject,
                List.copyOf(roles), request.action(), request.resourceType(), request.resourceId());
    }

    static AuthorizationResult of(Policy.Rule rule, Policy policy, String subject,
                                  List<String> roles, ResourceRequest request) {
        return new AuthorizationResult(rule.effect() == Policy.Effect.ALLOW,
                rule.effect() == Policy.Effect.ALLOW ? "rule:" + rule.name() : "deny-rule:" + rule.name(),
                rule.name(), policy.version(), subject, List.copyOf(roles),
                request.action(), request.resourceType(), request.resourceId());
    }
}

