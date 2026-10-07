package com.github.lechandonga.zerotrustaccessauditjava.tests;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.github.lechandonga.zerotrustaccessauditjava.credential.CredentialException;
import com.github.lechandonga.zerotrustaccessauditjava.credential.CredentialRejection;
import com.github.lechandonga.zerotrustaccessauditjava.credential.CredentialService;
import com.github.lechandonga.zerotrustaccessauditjava.crypto.KeyManager;
import com.github.lechandonga.zerotrustaccessauditjava.crypto.SystemClock;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.RegisterExtension;

import java.time.Clock;
import java.time.Instant;
import java.time.ZoneOffset;
import java.util.List;
import java.util.Set;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.TimeUnit;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

@Business("签名密钥轮换与宽限期")
class KeyRotationTest {

    @RegisterExtension
    static final BusinessTestLogger LOGGER = new BusinessTestLogger();

    private static final Instant T0 = Instant.parse("2026-10-07T10:00:00Z");

    private SystemClock clock;
    private KeyManager keys;
    private CredentialService credentials;

    @BeforeEach
    void setUp() {
        clock = new SystemClock();
        clock.setClock(Clock.fixed(T0, ZoneOffset.UTC));
        keys = new KeyManager(clock, 10_000);
        credentials = new CredentialService(keys, clock, new ObjectMapper(),
                1_000_000, 1_000);
    }

    @AfterEach
    void tearDown() {
        clock.reset();
    }

    @Test
    @DisplayName("轮换后新凭证用新密钥，旧凭证宽限期内仍可用，到期失效")
    void gracePeriodBoundary() {
        CredentialService.Credential oldToken = credentials.issue("alice", List.of("reader"));
        String oldKeyId = keys.activeKeyId();

        clock.setClock(Clock.fixed(T0.plusSeconds(30), ZoneOffset.UTC));
        String newKeyId = keys.rotate();
        assertNotEquals(oldKeyId, newKeyId);
        assertEquals(newKeyId, keys.activeKeyId());

        CredentialService.Credential newToken = credentials.issue("alice", List.of("reader"));
        assertEquals(newKeyId, newToken.keyId());

        clock.setClock(Clock.fixed(T0.plusSeconds(39), ZoneOffset.UTC));
        credentials.verify(oldToken.token());
        credentials.verify(newToken.token());

        clock.setClock(Clock.fixed(T0.plusSeconds(40), ZoneOffset.UTC));
        CredentialException ex = assertThrows(CredentialException.class,
                () -> credentials.verify(oldToken.token()));
        assertEquals(CredentialRejection.UNKNOWN_KEY, ex.rejection());
        credentials.verify(newToken.token());

        assertFalse(keys.listKeys().stream().anyMatch(k -> k.keyId().equals(oldKeyId)));
    }

    @Test
    @DisplayName("轮换与校验并发执行，任何时刻都能得到确定、非异常的判定")
    void concurrentRotationAndVerification() throws Exception {
        CredentialService.Credential token = credentials.issue("alice", List.of("reader"));
        int threads = 8;
        ExecutorService pool = Executors.newFixedThreadPool(threads);
        CountDownLatch start = new CountDownLatch(1);
        Set<Throwable> errors = ConcurrentHashMap.newKeySet();
        Set<String> observedKeyIds = ConcurrentHashMap.newKeySet();

        for (int i = 0; i < threads; i++) {
            final int idx = i;
            pool.submit(() -> {
                try {
                    start.await();
                    for (int attempt = 0; attempt < 200; attempt++) {
                        observedKeyIds.add(keys.activeKeyId());
                        try {
                            credentials.verify(token.token());
                        } catch (CredentialException e) {
                            if (e.rejection() != CredentialRejection.UNKNOWN_KEY
                                    && e.rejection() != CredentialRejection.EXPIRED) {
                                errors.add(e);
                            }
                        }
                        if (idx == 0 && attempt % 25 == 0) {
                            keys.rotate();
                        }
                    }
                } catch (Throwable t) {
                    errors.add(t);
                }
            });
        }
        start.countDown();
        pool.shutdown();
        assertTrue(pool.awaitTermination(30, TimeUnit.SECONDS));
        assertTrue(errors.isEmpty(), "并发轮换期间出现非预期错误: " + errors);
        assertTrue(observedKeyIds.size() >= 2, "校验过程应观察到至少一次密钥切换");
    }

    @Test
    @DisplayName("密钥查询仅暴露标识与指纹，密钥元数据不含任何密钥字节")
    void keyListingNeverExposesSecrets() {
        keys.rotate();
        List<KeyManager.KeyInfo> infos = keys.listKeys();
        assertEquals(2, infos.size());
        for (KeyManager.KeyInfo info : infos) {
            assertFalse(info.fingerprint().isBlank());
            assertEquals(16, info.fingerprint().length());
            assertThrows(NoSuchFieldException.class,
                    () -> KeyManager.KeyInfo.class.getDeclaredField("key"));
        }
        KeyManager.KeyInfo active = infos.stream()
                .filter(k -> k.keyId().equals(keys.activeKeyId())).findFirst().orElseThrow();
        assertTrue(active.retiredAt() == null);
    }

}
