package com.github.lechandonga.zerotrustaccessauditjava.tests;

import com.github.lechandonga.zerotrustaccessauditjava.audit.AuditRecord;
import com.github.lechandonga.zerotrustaccessauditjava.audit.AuditService;
import com.github.lechandonga.zerotrustaccessauditjava.authz.AuthorizationService;
import com.github.lechandonga.zerotrustaccessauditjava.authz.Policy;
import com.github.lechandonga.zerotrustaccessauditjava.authz.PolicyStore;
import com.github.lechandonga.zerotrustaccessauditjava.authz.ResourceRequest;
import com.github.lechandonga.zerotrustaccessauditjava.credential.CredentialService;
import com.github.lechandonga.zerotrustaccessauditjava.crypto.SystemClock;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.RegisterExtension;

import java.util.List;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicInteger;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

@Business("基于角色与资源属性的授权及审计")
class AuthorizationPolicyTest {

    @RegisterExtension
    static final BusinessTestLogger LOGGER = new BusinessTestLogger();

    private PolicyStore store;
    private AuthorizationService authz;
    private AuditService audit;
    private CredentialService.VerifiedCredential alice;
    private CredentialService.VerifiedCredential bob;

    @BeforeEach
    void setUp() {
        store = new PolicyStore();
        audit = new AuditService(new SystemClock());
        authz = new AuthorizationService(store, audit);
        alice = new CredentialService.VerifiedCredential("jti-alice", "alice",
                List.of("reader"), "k1", Long.MAX_VALUE);
        bob = new CredentialService.VerifiedCredential("jti-bob", "bob",
                List.of("guest"), "k1", Long.MAX_VALUE);
    }

    private ResourceRequest docRead() {
        return new ResourceRequest("read", "document", "doc-1", "prod",
                List.of("public"), Map.of());
    }

    @Test
    @DisplayName("空策略默认拒绝，且任何决策都写审计")
    void defaultDenyAndAudit() {
        AuditRecord record = authz.authorize(alice, docRead());
        assertFalse(record.allowed());
        assertEquals("default-deny", record.reason());
        assertEquals(1, audit.size());
    }

    @Test
    @DisplayName("角色+动作+资源类型+环境+标签全部匹配才允许，否则拒绝")
    void ruleMatchingOnRolesAndResourceAttributes() {
        store.publish(List.of(new Policy.Rule("readers-read-public-docs", Policy.Effect.ALLOW,
                List.of("reader"), List.of("read"), List.of("document"),
                List.of("prod"), List.of("public"))));

        assertTrue(authz.authorize(alice, docRead()).allowed());
        assertFalse(authz.authorize(bob, docRead()).allowed());

        ResourceRequest staging = new ResourceRequest("read", "document", "doc-1", "staging",
                List.of("public"), Map.of());
        assertFalse(authz.authorize(alice, staging).allowed());

        ResourceRequest write = new ResourceRequest("write", "document", "doc-1", "prod",
                List.of("public"), Map.of());
        assertFalse(authz.authorize(alice, write).allowed());
    }

    @Test
    @DisplayName("策略更新整体生效：并发读者看到的版本号在单次判定内始终一致")
    void concurrentPolicyUpdateIsAtomic() throws Exception {
        List<Policy.Rule> v1 = List.of(new Policy.Rule("allow-all-read",
                Policy.Effect.ALLOW, List.of(), List.of("read"), List.of(), List.of(), List.of()));
        store.publish(v1);

        int readerCount = 6;
        ExecutorService pool = Executors.newFixedThreadPool(readerCount + 1);
        CountDownLatch start = new CountDownLatch(1);
        AtomicInteger mismatches = new AtomicInteger();
        Map<Long, String> observedVersions = new ConcurrentHashMap<>();

        for (int i = 0; i < readerCount; i++) {
            pool.submit(() -> {
                try {
                    start.await();
                    for (int n = 0; n < 2_000; n++) {
                        AuditRecord record = authz.authorize(alice, docRead());
                        long storeVersion = store.current().version();
                        observedVersions.put(record.policyVersion(),
                                record.allowed() + "|" + record.reason());
                        if (record.policyVersion() > storeVersion) {
                            mismatches.incrementAndGet();
                        }
                    }
                } catch (Exception e) {
                    mismatches.incrementAndGet();
                }
            });
        }

        pool.submit(() -> {
            try {
                start.await();
                for (int n = 0; n < 50; n++) {
                    List<Policy.Rule> next = List.of(
                            new Policy.Rule("allow-all-read-" + n, Policy.Effect.ALLOW,
                                    List.of(), List.of("read"), List.of(), List.of(), List.of()),
                            new Policy.Rule("deny-write-" + n, Policy.Effect.DENY,
                                    List.of(), List.of("write"), List.of(), List.of(), List.of()));
                    long version = store.publish(next);
                    if (store.current().rules().size() != 2) {
                        mismatches.incrementAndGet();
                    }
                    assertEquals(2, store.current().rules().size());
                    assertEquals(version, store.current().version());
                }
            } catch (Exception e) {
                mismatches.incrementAndGet();
            }
        });

        start.countDown();
        pool.shutdown();
        assertTrue(pool.awaitTermination(30, TimeUnit.SECONDS));
        assertEquals(0, mismatches.get(), "出现半更新读取或版本错乱");
        assertTrue(observedVersions.size() > 1, "读者应观察到多个策略版本: " + observedVersions);
        observedVersions.forEach((version, outcome) ->
                assertTrue(outcome.startsWith("true|rule:"), "版本 " + version + " 出现混合判定"));
    }

    @Test
    @DisplayName("审计记录只包含身份标识与判定，不包含凭证或密钥内容")
    void auditRecordsContainNoSecrets() {
        authz.authorize(alice, docRead());
        AuditRecord record = audit.query(null, 1).get(0);
        assertEquals("alice", record.subject());
        assertEquals("jti-alice", record.credentialId());
        assertEquals("k1", record.keyId());
        assertFalse(record.toString().contains("Bearer"));
    }
}
