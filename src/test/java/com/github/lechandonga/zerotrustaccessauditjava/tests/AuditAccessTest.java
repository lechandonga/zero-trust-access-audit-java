package com.github.lechandonga.zerotrustaccessauditjava.tests;

import com.github.lechandonga.zerotrustaccessauditjava.audit.AuditLog;
import com.github.lechandonga.zerotrustaccessauditjava.audit.AuditRecord;
import com.github.lechandonga.zerotrustaccessauditjava.authz.AuthorizationService;
import com.github.lechandonga.zerotrustaccessauditjava.authz.Policy;
import com.github.lechandonga.zerotrustaccessauditjava.credential.CredentialClaims;
import org.junit.jupiter.api.Test;
import org.slf4j.Logger;

import java.time.Instant;
import java.util.List;
import java.util.Map;
import java.util.Set;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * 业务：审计记录与受权限保护的审计查询。
 */
class AuditAccessTest {

    private static final Logger log = TestCoverageLog.cover(AuditAccessTest.class,
            "审计：每次判定可追溯 / 审计查询权限保护 / 不泄露凭证与密钥",
            "每次授权判定都产生审计记录",
            "无 audit:read 权限的查询被拒绝并留痕",
            "具备权限的角色可查询审计",
            "审计记录不含凭证与密钥内容");

    private final AuditLog auditLog = new AuditLog();
    private final AuthorizationService service = new AuthorizationService(auditLog);

    @Test
    void everyDecisionProducesAuditRecord() {
        CredentialClaims claims = claims("alice", Set.of("reader"));
        AuthorizationService.Decision d1 = service.authorize(claims, "read", "document", Map.of());
        AuthorizationService.Decision d2 = service.authorize(claims, "write", "document", Map.of());
        List<AuditRecord> records = auditLog.query();
        assertEquals(2, records.size());
        assertTrue(records.stream().anyMatch(r -> r.auditId().equals(d1.auditId())));
        assertTrue(records.stream().anyMatch(r -> r.auditId().equals(d2.auditId())));
        TestCoverageLog.pass(log, "每次授权判定都产生审计记录");
    }

    @Test
    void unauthorizedAuditQueryDeniedAndTraced() {
        service.updatePolicy(new Policy(List.of(
                new Policy.Rule("auditor", "audit:read", "audit", Map.of()))));
        CredentialClaims intruder = claims("mallory", Set.of("reader"));
        assertThrows(AuthorizationService.AuditAccessDeniedException.class,
                () -> service.queryAudit(intruder));
        // 越权查询本身也被审计
        assertTrue(auditLog.query().stream().anyMatch(
                r -> r.subject().equals("mallory") && r.action().equals("audit:read") && !r.allowed()));
        TestCoverageLog.pass(log, "无 audit:read 权限的查询被拒绝并留痕");
    }

    @Test
    void authorizedAuditorCanQuery() {
        service.updatePolicy(new Policy(List.of(
                new Policy.Rule("auditor", "audit:read", "audit", Map.of()))));
        CredentialClaims auditor = claims("auditor-1", Set.of("auditor"));
        List<AuditRecord> records = service.queryAudit(auditor);
        assertTrue(records.stream().anyMatch(
                r -> r.subject().equals("auditor-1") && r.action().equals("audit:read") && r.allowed()));
        TestCoverageLog.pass(log, "具备权限的角色可查询审计");
    }

    @Test
    void auditRecordsContainNoSecrets() {
        CredentialClaims claims = claims("alice", Set.of("reader"));
        service.authorize(claims, "read", "document", Map.of("tenant", "t1"));
        for (AuditRecord record : auditLog.query()) {
            String serialized = record.toString();
            assertTrue(!serialized.contains("k-test"), "审计记录不得包含密钥标识以外的密钥信息");
            assertTrue(!serialized.contains("Bearer"), "审计记录不得包含凭证内容");
        }
        TestCoverageLog.pass(log, "审计记录不含凭证与密钥内容");
    }

    private static CredentialClaims claims(String subject, Set<String> roles) {
        return new CredentialClaims("jti-" + subject, subject, roles, Map.of(),
                Instant.now(), Instant.now().plusSeconds(60), "k-test");
    }
}
