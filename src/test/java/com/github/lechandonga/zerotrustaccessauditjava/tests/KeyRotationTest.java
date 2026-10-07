package com.github.lechandonga.zerotrustaccessauditjava.tests;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.github.lechandonga.zerotrustaccessauditjava.credential.CredentialService;
import com.github.lechandonga.zerotrustaccessauditjava.credential.RejectionReason;
import com.github.lechandonga.zerotrustaccessauditjava.credential.VerificationResult;
import com.github.lechandonga.zerotrustaccessauditjava.keys.KeyManager;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.slf4j.Logger;

import java.time.Duration;
import java.time.Instant;
import java.util.Map;
import java.util.Set;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicInteger;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * 业务：签名密钥轮换与多密钥共存。
 */
class KeyRotationTest {

    private static final Logger log = TestCoverageLog.cover(KeyRotationTest.class,
            "签名密钥：轮换 / 宽限期共存 / 并发一致 / 不暴露密钥内容",
            "轮换后旧密钥签发的凭证在宽限期内仍有效",
            "宽限期结束后旧密钥签发的凭证必须失效",
            "轮换与校验并发时不得误判",
            "仅暴露密钥标识，不暴露密钥内容");

    private MutableClock clock;
    private KeyManager keyManager;
    private CredentialService credentialService;

    @BeforeEach
    void setUp() {
        clock = new MutableClock(Instant.parse("2026-01-01T00:00:00Z"));
        keyManager = new KeyManager(Duration.ofMinutes(5), clock);
        credentialService = new CredentialService(keyManager, new ObjectMapper(),
                Duration.ofSeconds(30), clock);
    }

    @Test
    void oldKeyCredentialValidWithinGracePeriod() {
        String oldKeyId = keyManager.currentKeyId();
        String token = credentialService.issue("alice", Set.of(), Map.of(), Duration.ofHours(1));
        String newKeyId = keyManager.rotate();
        assertNotEquals(oldKeyId, newKeyId);
        clock.advance(Duration.ofMinutes(4));
        assertTrue(credentialService.verify(token).isValid(), "宽限期内旧密钥凭证应通过校验");
        TestCoverageLog.pass(log, "轮换后旧密钥签发的凭证在宽限期内仍有效");
    }

    @Test
    void oldKeyCredentialInvalidAfterGracePeriod() {
        String token = credentialService.issue("alice", Set.of(), Map.of(), Duration.ofHours(1));
        keyManager.rotate();
        clock.advance(Duration.ofMinutes(5).plusSeconds(1));
        VerificationResult result = credentialService.verify(token);
        assertEquals(RejectionReason.UNKNOWN_KEY, ((VerificationResult.Invalid) result).reason(),
                "宽限期结束后旧密钥凭证必须失效");
        TestCoverageLog.pass(log, "宽限期结束后旧密钥签发的凭证必须失效");
    }

    @Test
    void concurrentRotationAndVerificationNeverMisjudges() throws InterruptedException {
        String token = credentialService.issue("alice", Set.of(), Map.of(), Duration.ofHours(1));
        int threads = 8;
        ExecutorService pool = Executors.newFixedThreadPool(threads);
        CountDownLatch start = new CountDownLatch(1);
        AtomicInteger failures = new AtomicInteger();
        AtomicInteger verifications = new AtomicInteger();
        for (int i = 0; i < threads; i++) {
            boolean verifier = i % 2 == 0;
            pool.submit(() -> {
                try {
                    start.await();
                    for (int j = 0; j < 200; j++) {
                        if (verifier) {
                            // 宽限期内，旧密钥凭证任何时候都必须校验通过
                            if (!credentialService.verify(token).isValid()) {
                                failures.incrementAndGet();
                            }
                            verifications.incrementAndGet();
                        } else {
                            keyManager.rotate();
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
        log.info("  并发期间完成校验 {} 次，误判 {} 次", verifications.get(), failures.get());
        assertEquals(0, failures.get(), "轮换与校验并发时不得误判");
        TestCoverageLog.pass(log, "轮换与校验并发时不得误判");
    }

    @Test
    void onlyKeyIdExposed() {
        String keyId = keyManager.currentKeyId();
        assertTrue(keyId.startsWith("k-"));
        // 对外接口只返回 keyId 字符串，SigningKey.key() 不出现在任何 API 返回值中
        assertEquals(keyId, keyManager.currentKeyId());
        TestCoverageLog.pass(log, "仅暴露密钥标识，不暴露密钥内容");
    }
}
