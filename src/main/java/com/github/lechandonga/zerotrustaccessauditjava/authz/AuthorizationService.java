package com.github.lechandonga.zerotrustaccessauditjava.authz;

import com.github.lechandonga.zerotrustaccessauditjava.audit.AuditLog;
import com.github.lechandonga.zerotrustaccessauditjava.audit.AuditRecord;
import com.github.lechandonga.zerotrustaccessauditjava.credential.CredentialClaims;
import org.springframework.stereotype.Service;

import java.util.List;
import java.util.Map;
import java.util.concurrent.atomic.AtomicReference;

/**
 * 授权判定服务：基于角色与资源属性，默认拒绝。
 *
 * 策略保存在 AtomicReference 中，更新时先构造完整的新 Policy 再一次性替换，
 * 因此策略更新要么整体生效要么完全不生效，并发读不会看到半更新状态。
 * 每次判定都会写入一条可追溯的审计记录。
 */
@Service
public class AuthorizationService {

    private final AtomicReference<Policy> policyRef;
    private final AuditLog auditLog;

    public AuthorizationService(AuditLog auditLog) {
        this.auditLog = auditLog;
        // 默认策略：空规则集 -> 全部拒绝
        this.policyRef = new AtomicReference<>(new Policy(List.of()));
    }

    /** 原子地整体替换策略。 */
    public void updatePolicy(Policy newPolicy) {
        policyRef.set(newPolicy);
    }

    /** 当前策略快照（只读）。 */
    public Policy currentPolicy() {
        return policyRef.get();
    }

    /**
     * 对一次访问请求进行授权判定，并写入审计记录。
     *
     * @return 判定结果；审计记录可通过返回值或审计查询获取
     */
    public Decision authorize(CredentialClaims claims, String action, String resourceType,
                              Map<String, String> resourceAttrs) {
        Policy snapshot = policyRef.get();
        boolean allowed = snapshot.isAllowed(claims.roles(), action, resourceType, resourceAttrs);
        String reason = allowed ? "matched allow rule" : "default deny: no matching rule";
        AuditRecord record = AuditRecord.of(claims.subject(), action, resourceType,
                resourceAttrs, allowed, reason);
        auditLog.append(record);
        return new Decision(allowed, reason, record.auditId());
    }

    /**
     * 查询审计日志，受权限保护：调用方必须具备 audit:read 权限。
     * 越权查询同样会被审计。
     */
    public List<AuditRecord> queryAudit(CredentialClaims claims) {
        Decision decision = authorize(claims, "audit:read", "audit", Map.of());
        if (!decision.allowed()) {
            throw new AuditAccessDeniedException(
                    "subject lacks audit:read permission, auditId=" + decision.auditId());
        }
        return auditLog.query();
    }

    public record Decision(boolean allowed, String reason, String auditId) {
    }

    public static class AuditAccessDeniedException extends RuntimeException {
        public AuditAccessDeniedException(String message) {
            super(message);
        }
    }
}
