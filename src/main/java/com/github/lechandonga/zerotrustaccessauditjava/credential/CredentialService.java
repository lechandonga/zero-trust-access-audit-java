package com.github.lechandonga.zerotrustaccessauditjava.credential;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.node.ObjectNode;
import com.github.lechandonga.zerotrustaccessauditjava.keys.KeyManager;
import com.github.lechandonga.zerotrustaccessauditjava.keys.SigningKey;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;

import javax.crypto.Mac;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.util.Base64;
import java.util.LinkedHashMap;
import java.util.LinkedHashSet;
import java.util.Map;
import java.util.Optional;
import java.util.Set;
import java.util.UUID;
import java.util.concurrent.ConcurrentHashMap;

/**
 * 访问凭证服务：签发、校验与吊销。
 *
 * 凭证格式：base64url(payloadJson) + "." + base64url(hmacSha256)。
 * 校验失败时返回可区分的拒绝原因；过期判定容忍少量时钟偏差；
 * 吊销立即生效且只影响被吊销的单个凭证。
 *
 * 注意：凭证内容与密钥内容永不写入日志。
 */
@Service
public class CredentialService {

    private static final Logger log = LoggerFactory.getLogger(CredentialService.class);
    private static final Base64.Encoder B64_ENC = Base64.getUrlEncoder().withoutPadding();
    private static final Base64.Decoder B64_DEC = Base64.getUrlDecoder();

    private final KeyManager keyManager;
    private final ObjectMapper objectMapper;
    private final Duration clockSkew;
    private final Clock clock;

    /** 已吊销凭证的 jti 集合（本地内存实现，吊销立即生效）。 */
    private final Set<String> revokedJti = ConcurrentHashMap.newKeySet();

    @Autowired
    public CredentialService(KeyManager keyManager,
                             ObjectMapper objectMapper,
                             @Value("${zerotrust.credential.clock-skew:PT30S}") Duration clockSkew) {
        this(keyManager, objectMapper, clockSkew, Clock.systemUTC());
    }

    public CredentialService(KeyManager keyManager, ObjectMapper objectMapper,
                             Duration clockSkew, Clock clock) {
        this.keyManager = keyManager;
        this.objectMapper = objectMapper;
        this.clockSkew = clockSkew;
        this.clock = clock;
    }

    /** 签发凭证，返回凭证字符串。 */
    public String issue(String subject, Set<String> roles, Map<String, String> attributes, Duration ttl) {
        SigningKey key = keyManager.activeKey();
        Instant now = clock.instant();
        ObjectNode payload = objectMapper.createObjectNode();
        payload.put("jti", UUID.randomUUID().toString());
        payload.put("sub", subject);
        payload.putPOJO("roles", roles == null ? Set.of() : roles);
        payload.putPOJO("attrs", attributes == null ? Map.of() : attributes);
        payload.put("iat", now.getEpochSecond());
        payload.put("exp", now.plus(ttl).getEpochSecond());
        payload.put("kid", key.keyId());
        String payloadB64 = B64_ENC.encodeToString(toBytes(payload));
        String signature = sign(payloadB64, key);
        log.info("Issued credential: jti={}, subject={}, roles={}, keyId={}",
                payload.get("jti").asText(), subject, roles, key.keyId());
        return payloadB64 + "." + signature;
    }

    /** 校验凭证，返回有效负载或可区分的拒绝原因。 */
    public VerificationResult verify(String token) {
        if (token == null || token.isBlank()) {
            return new VerificationResult.Invalid(RejectionReason.MALFORMED, "empty credential");
        }
        int dot = token.indexOf('.');
        if (dot <= 0 || dot == token.length() - 1 || token.indexOf('.', dot + 1) >= 0) {
            return new VerificationResult.Invalid(RejectionReason.MALFORMED, "bad credential structure");
        }
        String payloadB64 = token.substring(0, dot);
        String signatureB64 = token.substring(dot + 1);

        final JsonNode payload;
        try {
            payload = objectMapper.readTree(B64_DEC.decode(payloadB64));
        } catch (Exception e) {
            return new VerificationResult.Invalid(RejectionReason.MALFORMED, "payload is not valid base64/json");
        }
        if (!payload.isObject() || payload.get("jti") == null || payload.get("sub") == null
                || payload.get("exp") == null || payload.get("kid") == null) {
            return new VerificationResult.Invalid(RejectionReason.MALFORMED, "payload missing required fields");
        }
        String jti = payload.get("jti").asText();
        String keyId = payload.get("kid").asText();

        Instant now = clock.instant();
        Optional<SigningKey> keyOpt = keyManager.findVerificationKey(keyId, now);
        if (keyOpt.isEmpty()) {
            return new VerificationResult.Invalid(RejectionReason.UNKNOWN_KEY,
                    "unknown or expired key: " + keyId);
        }
        String expected = sign(payloadB64, keyOpt.get());
        if (!MessageDigest.isEqual(expected.getBytes(StandardCharsets.UTF_8),
                signatureB64.getBytes(StandardCharsets.UTF_8))) {
            log.info("Credential rejected: jti={}, reason={}", jti, RejectionReason.SIGNATURE_MISMATCH);
            return new VerificationResult.Invalid(RejectionReason.SIGNATURE_MISMATCH, "signature mismatch");
        }
        Instant expiresAt = Instant.ofEpochSecond(payload.get("exp").asLong());
        if (now.isAfter(expiresAt.plus(clockSkew))) {
            log.info("Credential rejected: jti={}, reason={}", jti, RejectionReason.EXPIRED);
            return new VerificationResult.Invalid(RejectionReason.EXPIRED, "credential expired at " + expiresAt);
        }
        if (revokedJti.contains(jti)) {
            log.info("Credential rejected: jti={}, reason={}", jti, RejectionReason.REVOKED);
            return new VerificationResult.Invalid(RejectionReason.REVOKED, "credential revoked");
        }
        return new VerificationResult.Valid(toClaims(payload, jti, keyId, expiresAt));
    }

    /**
     * 吊销指定凭证（按 jti），立即生效，不影响其他有效凭证。
     *
     * @return true 表示吊销成功；false 表示凭证本身无效，拒绝吊销
     */
    public boolean revoke(String token) {
        VerificationResult result = verify(token);
        if (result instanceof VerificationResult.Valid valid) {
            revokedJti.add(valid.claims().jti());
            log.info("Credential revoked: jti={}", valid.claims().jti());
            return true;
        }
        return false;
    }

    private CredentialClaims toClaims(JsonNode payload, String jti, String keyId, Instant expiresAt) {
        Set<String> roles = new LinkedHashSet<>();
        if (payload.get("roles") != null && payload.get("roles").isArray()) {
            payload.get("roles").forEach(r -> roles.add(r.asText()));
        }
        Map<String, String> attrs = new LinkedHashMap<>();
        if (payload.get("attrs") != null && payload.get("attrs").isObject()) {
            payload.get("attrs").fields().forEachRemaining(e -> attrs.put(e.getKey(), e.getValue().asText()));
        }
        Instant issuedAt = payload.get("iat") != null
                ? Instant.ofEpochSecond(payload.get("iat").asLong()) : Instant.EPOCH;
        return new CredentialClaims(jti, payload.get("sub").asText(), roles, attrs, issuedAt, expiresAt, keyId);
    }

    private String sign(String payloadB64, SigningKey key) {
        try {
            Mac mac = Mac.getInstance("HmacSHA256");
            mac.init(key.key());
            return B64_ENC.encodeToString(mac.doFinal(payloadB64.getBytes(StandardCharsets.UTF_8)));
        } catch (Exception e) {
            throw new IllegalStateException("failed to sign credential", e);
        }
    }

    private byte[] toBytes(ObjectNode node) {
        try {
            return objectMapper.writeValueAsBytes(node);
        } catch (Exception e) {
            throw new IllegalStateException("failed to serialize payload", e);
        }
    }
}
