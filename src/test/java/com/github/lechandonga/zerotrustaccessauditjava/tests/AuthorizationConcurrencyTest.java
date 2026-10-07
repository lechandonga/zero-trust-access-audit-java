package com.github.lechandonga.zerotrustaccessauditjava.tests;

import com.github.lechandonga.zerotrustaccessauditjava.audit.AuditLog;
import com.github.lechandonga.zerotrustaccessauditjava.authz.AuthorizationService;
import com.github.lechandonga.zerotrustaccessauditjava.authz.Policy;
import com.github.lechandonga.zerotrustaccessauditjava.credential.CredentialClaims;
import org.junit.jupiter.api.Test;
import org.slf4j.Logger;

import java.time.Instant;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicInteger;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * 业务：授权判定（默认拒绝）与策略原子更新。
 */
class AuthorizationConcurrencyTest {

    private static final Logger log = TestCoverageLog.cover(AuthorizationConcurrencyTest.class,
            "授权策略：默认拒绝 / 原子更新 / 并发读一致性",
            "无匹配规则时默认拒绝",
            "角色 + 资源属性匹配时允许",
            "策略并发更新时读不到半更新状态");

    private final AuditLog auditLog = new AuditLog();
    private final AuthorizationService service = new AuthorizationService(auditLog);

    @Test
    void defaultDenyWhenNoRuleMatches() {
        CredentialClaims claims = claims("alice", Set.of("reader"));
        AuthorizationService.Decision decision = service.authorize(claims, "read", "document", Map.of());
        assertFalse(decision.allowed());
        assertEquals("default deny: no matching rule", decision.reason());
        TestCoverageLog.pass(log, "无匹配规则时默认拒绝");
    }

    @Test
    void allowWhenRoleAndResourceAttrsMatch() {
        service.updatePolicy(new Policy(List.of(
                new Policy.Rule("reader", "read", "document", Map.of("tenant", "t1")))));
        CredentialClaims claims = claims("alice", Set.of("reader"));
        assertTrue(service.authorize(claims, "read", "document", Map.of("tenant", "t1")).allowed());
        assertFalse(service.authorize(claims, "read", "document", Map.of("tenant", "t2")).allowed(),
                "资源属性不匹配应拒绝");
        assertFalse(service.authorize(claims, "write", "document", Map.of("tenant", "t1")).allowed(),
                "动作不匹配应拒绝");
        TestCoverageLog.pass(log, "角色 + 资源属性匹配时允许");
    }

    @Test
    void concurrentPolicyUpdateNeverShowsPartialState() throws InterruptedException {
        // 策略 A 含 2 条规则，策略 B 含 0 条；半更新状态会表现为 1 条规则
        Policy policyA = new Policy(List.of(
                new Policy.Rule("reader", "read", "document", Map.of("tenant", "t1")),
                new Policy.Rule("reader", "read", "document", Map.of("tenant", "t2"))));
        Policy policyB = new Policy(List.of());
        service.updatePolicy(policyA);

        int threads = 8;
        ExecutorService pool = Executors.newFixedThreadPool(threads);
        CountDownLatch start = new CountDownLatch(1);
        AtomicInteger partialReads = new AtomicInteger();
        AtomicInteger reads = new AtomicInteger();
        for (int i = 0; i < threads; i++) {
            boolean writer = i % 2 == 1;
            pool.submit(() -> {
                try {
                    start.await();
                    for (int j = 0; j < 500; j++) {
                        if (writer) {
                            service.updatePolicy(j % 2 == 0 ? policyA : policyB);
                        } else {
                            int size = service.currentPolicy().rules().size();
                            reads.incrementAndGet();
                            if (size != 0 && size != 2) {
                                partialReads.incrementAndGet();
                            }
                        }
                    }
                } catch (InterruptedException e) {
                    Thread.currentThread().interrupt();
                }
            });
        }
        start.countDown();
        pool.shutdown();
        assertTrue(pool.awaitTermination(30, TimeUnit.SECONDS));
        log.info("  并发读取策略 {} 次，观察到半更新 {} 次", reads.get(), partialReads.get());
        assertEquals(0, partialReads.get(), "并发读不得看到半更新的策略");
        TestCoverageLog.pass(log, "策略并发更新时读不到半更新状态");
    }

    private static CredentialClaims claims(String subject, Set<String> roles) {
        return new CredentialClaims("jti-" + subject, subject, roles, Map.of(),
                Instant.now(), Instant.now().plusSeconds(60), "k-test");
    }
}
