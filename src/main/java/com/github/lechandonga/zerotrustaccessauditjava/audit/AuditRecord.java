package com.github.lechandonga.zerotrustaccessauditjava.audit;

import java.time.Instant;
import java.util.Map;
import java.util.UUID;

/**
 * 一次授权判定的审计记录。不包含凭证或密钥内容。
 */
public record AuditRecord(
        String auditId,
        Instant timestamp,
        String subject,
        String action,
        String resourceType,
        Map<String, String> resourceAttrs,
        boolean allowed,
        String reason) {

    public static AuditRecord of(String subject, String action, String resourceType,
                                 Map<String, String> resourceAttrs, boolean allowed, String reason) {
        return new AuditRecord(UUID.randomUUID().toString(), Instant.now(),
                subject, action, resourceType,
                resourceAttrs == null ? Map.of() : Map.copyOf(resourceAttrs),
                allowed, reason);
    }
}
