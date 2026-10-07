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
import java.util.Base64;
import java.util.List;

import static org.junit.jupiter.api.Assertions.assertDoesNotThrow;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;

@Business("凭证签发/校验/吊销")
class CredentialServiceTest {

    @RegisterExtension
    static final BusinessTestLogger LOGGER = new BusinessTestLogger();

    private static final Instant T0 = Instant.parse("2026-10-07T10:00:00Z");

    private SystemClock clock;
    private CredentialService credentials;

    @BeforeEach
    void setUp() {
        clock = new SystemClock();
        clock.setClock(Clock.fixed(T0, ZoneOffset.UTC));
        KeyManager keys = new KeyManager(clock, 10_000);
        credentials = new CredentialService(keys, clock, new ObjectMapper(), 60_000, 5_000);
    }

    @AfterEach
    void tearDown() {
        clock.reset();
    }

    @Test
    @DisplayName("有效凭证校验通过并返回主体与角色")
    void validCredentialVerifies() {
        CredentialService.Credential token = credentials.issue("alice", List.of("reader"));
        CredentialService.VerifiedCredential verified = credentials.verify(token.token());
        assertEquals("alice", verified.subject());
        assertEquals(List.of("reader"), verified.roles());
        assertEquals(token.jti(), verified.jti());
    }

    @Test
    @DisplayName("超过容忍时钟偏差的过期凭证被拒绝，偏差内仍可通过")
    void expiredCredentialRejectedWithSkew() {
        CredentialService.Credential token = credentials.issue("alice", List.of());

        clock.setClock(Clock.fixed(T0.plusMillis(65_001), ZoneOffset.UTC));
        CredentialException rejected = assertThrows(CredentialException.class,
                () -> credentials.verify(token.token()));
        assertEquals(CredentialRejection.EXPIRED, rejected.rejection());

        clock.setClock(Clock.fixed(T0.plusMillis(65_000), ZoneOffset.UTC));
        assertDoesNotThrow(() -> credentials.verify(token.token()));
    }

    @Test
    @DisplayName("签名段被篡改时给出 signature_mismatch")
    void tamperedSignatureRejected() {
        CredentialService.Credential token = credentials.issue("alice", List.of());
        String[] parts = token.token().split("\\.");
        byte[] sig = Base64.getUrlDecoder().decode(parts[2]);
        sig[0] ^= 0x01;
        String tampered = parts[0] + "." + parts[1] + "."
                + Base64.getUrlEncoder().withoutPadding().encodeToString(sig);

        CredentialException rejected = assertThrows(CredentialException.class,
                () -> credentials.verify(tampered));
        assertEquals(CredentialRejection.SIGNATURE_MISMATCH, rejected.rejection());
    }

    @Test
    @DisplayName("载荷被篡改同样签名不匹配，而非结构错误")
    void tamperedPayloadRejectedAsSignatureMismatch() {
        CredentialService.Credential token = credentials.issue("alice", List.of());
        String[] parts = token.token().split("\\.");
        String payload = new String(Base64.getUrlDecoder().decode(parts[1]));
        String tamperedPayload = payload.replace("alice", "mallory");
        String encoded = Base64.getUrlEncoder().withoutPadding()
                .encodeToString(tamperedPayload.getBytes());

        CredentialException rejected = assertThrows(CredentialException.class,
                () -> credentials.verify(parts[0] + "." + encoded + "." + parts[2]));
        assertEquals(CredentialRejection.SIGNATURE_MISMATCH, rejected.rejection());
    }

    @Test
    @DisplayName("结构损坏（段数错误/非法Base64/缺字段）统一给出 malformed")
    void malformedCredentialsRejected() {
        CredentialService.Credential token = credentials.issue("alice", List.of());

        assertRejection(CredentialRejection.MALFORMED, "not-a-token");
        assertRejection(CredentialRejection.MALFORMED, token.token() + ".extra");
        assertRejection(CredentialRejection.MALFORMED, null);

        String[] parts = token.token().split("\\.");
        assertRejection(CredentialRejection.MALFORMED, "%%%.%%%." + parts[2]);

        String header = "{\"alg\":\"none\",\"kid\":\"x\"}";
        String badHeader = Base64.getUrlEncoder().withoutPadding().encodeToString(header.getBytes());
        assertRejection(CredentialRejection.MALFORMED, badHeader + "." + parts[1] + "." + parts[2]);
    }

    @Test
    @DisplayName("吊销立即生效，且不影响同一主体的其他凭证")
    void revocationIsImmediateAndScoped() {
        CredentialService.Credential first = credentials.issue("bob", List.of("reader"));
        CredentialService.Credential second = credentials.issue("bob", List.of("reader"));

        credentials.revoke(first.jti());

        CredentialException rejected = assertThrows(CredentialException.class,
                () -> credentials.verify(first.token()));
        assertEquals(CredentialRejection.REVOKED, rejected.rejection());
        assertDoesNotThrow(() -> credentials.verify(second.token()));
    }

    private void assertRejection(CredentialRejection expected, String token) {
        CredentialException ex = assertThrows(CredentialException.class,
                () -> credentials.verify(token));
        assertEquals(expected, ex.rejection());
    }
}
