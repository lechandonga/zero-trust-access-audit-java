package com.github.lechandonga.zerotrustaccessauditjava.audit;

import java.util.List;

/**
 * One traceable access decision. Deliberately contains no credential tokens,
 * signatures or key material — only identifiers (jti, keyId) and attributes.
 */
public record AuditRecord(long sequence,
                          long timestamp,
                          String subject,
                          String credentialId,
                          String keyId,
                          List<String> roles,
                          String action,
                          String resourceType,
                          String resourceId,
                          boolean allowed,
                          String reason,
                          String matchedRule,
                          long policyVersion) {
}

