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

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertInstanceOf;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * 业务：访问凭证的签发、校验与吊销。
 */
class CredentialServiceTest {

    private static final Logger log = TestCoverageLog.cover(CredentialServiceTest.class,
            "访问凭证：签发 / 校验 / 吊销，拒绝原因可区分，时钟偏差容忍",
            "合法凭证校验通过",
            "过期凭证被拒绝（超出时钟偏差）",
            "时钟偏差内的过期凭证仍被接受",
            "篡改负载的凭证因签名不匹配被拒绝",
            "结构损坏的凭证被拒绝",
            "吊销立即生效且不影响其他凭证");

    private MutableClock clock;
    private CredentialService service;

    @BeforeEach
    void setUp() {
        clock = new MutableClock(Instant.parse("2026-01-01T00:00:00Z"));
        KeyManager keyManager = new KeyManager(Duration.ofMinutes(5), clock);
        service = new CredentialService(keyManager, new ObjectMapper(),
                Duration.ofSeconds(30), clock);
    }

    @Test
    void validCredentialPasses() {
        String token = service.issue("alice", Set.of("reader"), Map.of("dept", "rd"),
                Duration.ofMinutes(10));
        VerificationResult result = service.verify(token);
        assertInstanceOf(VerificationResult.Valid.class, result);
        assertEquals("alice", ((VerificationResult.Valid) result).claims().subject());
        TestCoverageLog.pass(log, "合法凭证校验通过");
    }

    @Test
    void expiredCredentialRejectedBeyondSkew() {
        String token = service.issue("alice", Set.of(), Map.of(), Duration.ofMinutes(1));
        // 过期 1 分钟 + 31 秒，超出 30 秒时钟偏差
        clock.advance(Duration.ofSeconds(91));
        VerificationResult result = service.verify(token);
        assertInvalid(result, RejectionReason.EXPIRED);
        TestCoverageLog.pass(log, "过期凭证被拒绝（超出时钟偏差）");
    }

    @Test
    void expiredWithinClockSkewStillAccepted() {
        String token = service.issue("alice", Set.of(), Map.of(), Duration.ofMinutes(1));
        // 过期 20 秒，在 30 秒时钟偏差内
        clock.advance(Duration.ofSeconds(80));
        assertTrue(service.verify(token).isValid());
        TestCoverageLog.pass(log, "时钟偏差内的过期凭证仍被接受");
    }

    @Test
    void tamperedCredentialRejectedAsSignatureMismatch() {
        String token = service.issue("alice", Set.of("reader"), Map.of(), Duration.ofMinutes(10));
        int dot = token.indexOf('.');
        // 篡改负载：把 subject 从 alice 改为 admin（重新编码但不重新签名）
        String payload = new String(java.util.Base64.getUrlDecoder().decode(token.substring(0, dot)));
        String tamperedPayload = java.util.Base64.getUrlEncoder().withoutPadding()
                .encodeToString(payload.replace("alice", "admin").getBytes());
        String tampered = tamperedPayload + token.substring(dot);
        VerificationResult result = service.verify(tampered);
        assertInvalid(result, RejectionReason.SIGNATURE_MISMATCH);
        TestCoverageLog.pass(log, "篡改负载的凭证因签名不匹配被拒绝");
    }

    @Test
    void malformedCredentialRejected() {
        assertInvalid(service.verify("not-a-credential"), RejectionReason.MALFORMED);
        assertInvalid(service.verify(""), RejectionReason.MALFORMED);
        assertInvalid(service.verify("@@@" + ".abc"), RejectionReason.MALFORMED);
        TestCoverageLog.pass(log, "结构损坏的凭证被拒绝");
    }

    @Test
    void revocationIsImmediateAndDoesNotAffectOthers() {
        String tokenA = service.issue("alice", Set.of(), Map.of(), Duration.ofMinutes(10));
        String tokenB = service.issue("bob", Set.of(), Map.of(), Duration.ofMinutes(10));
        assertTrue(service.revoke(tokenA));
        assertInvalid(service.verify(tokenA), RejectionReason.REVOKED);
        assertTrue(service.verify(tokenB).isValid(), "吊销 tokenA 不应影响 tokenB");
        TestCoverageLog.pass(log, "吊销立即生效且不影响其他凭证");
    }

    private static void assertInvalid(VerificationResult result, RejectionReason reason) {
        assertFalse(result.isValid());
        assertEquals(reason, ((VerificationResult.Invalid) result).reason());
    }
}
