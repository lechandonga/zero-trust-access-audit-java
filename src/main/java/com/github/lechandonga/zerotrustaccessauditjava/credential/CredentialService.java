package com.github.lechandonga.zerotrustaccessauditjava.credential;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.github.lechandonga.zerotrustaccessauditjava.crypto.KeyManager;
import com.github.lechandonga.zerotrustaccessauditjava.crypto.SystemClock;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;

import javax.crypto.SecretKey;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.util.Base64;
import java.util.HexFormat;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.concurrent.ConcurrentHashMap;

/**
 * Issues, verifies and revokes compact bearer credentials.
 *
 * <p>Wire format (ASCII, three dot-separated base64url segments, no padding):
 * <pre>
 * base64url(header) . base64url(payload) . base64url(HMAC_SHA256(header.payload))
 * header  = {"alg":"HS256","kid":"&lt;key id&gt;"}
 * payload = {"jti":"...","sub":"...","roles":[...],"iat":epochMillis,"exp":epochMillis}
 * </pre>
 *
 * <p>Verification fails with one distinct {@link CredentialRejection}:
 * malformed structure, unknown signing key, signature mismatch, expiry
 * (with clock-skew tolerance), or revocation. Revocation is an immediate,
 * per-credential effect keyed by {@code jti}; other credentials, including
 * other credentials of the same subject, keep verifying.
 *
 * <p>No method logs or returns tokens, signatures or key material.
 */
@Service
public class CredentialService {

    public record Credential(String token, String jti, String keyId,
                             long issuedAt, long expiresAt, String subject, List<String> roles) {
    }

    public record VerifiedCredential(String jti, String subject, List<String> roles,
                                    String keyId, long expiresAt) {
        public boolean hasRole(String role) {
            return roles.contains(role);
        }
    }

    private final KeyManager keyManager;
    private final SystemClock clock;
    private final ObjectMapper mapper;
    private final long ttlMillis;
    private final long skewMillis;

    /** Revoked jti set. ConcurrentHashMap gives O(1) atomic visibility. */
    private final Set<String> revokedJtis = ConcurrentHashMap.newKeySet();

    public CredentialService(KeyManager keyManager,
                             SystemClock clock,
                             ObjectMapper mapper,
                             @Value("${ztaa.credential.ttl-millis:3600000}") long ttlMillis,
                             @Value("${ztaa.credential.clock-skew-millis:60000}") long skewMillis) {
        this.keyManager = keyManager;
        this.clock = clock;
        this.mapper = mapper;
        this.ttlMillis = ttlMillis;
        this.skewMillis = skewMillis;
    }

    public Credential issue(String subject, List<String> roles) {
        if (subject == null || subject.isBlank()) {
            throw new IllegalArgumentException("subject is required");
        }
        long now = clock.epochMilli();
        String keyId = keyManager.activeKeyId();
        String jti = newJti(subject, now);
        Map<String, Object> header = Map.of("alg", "HS256", "kid", keyId);
        Map<String, Object> payload = Map.of(
                "jti", jti,
                "sub", subject,
                "roles", List.copyOf(roles == null ? List.of() : roles),
                "iat", now,
                "exp", now + ttlMillis);

        String headerPart = encode(toJson(header));
        String payloadPart = encode(toJson(payload));
        String signingInput = headerPart + "." + payloadPart;
        String signaturePart = encode(hmac(signingInput, keyManager.activeKey()));

        return new Credential(signingInput + "." + signaturePart, jti, keyId,
                now, now + ttlMillis, subject,
                List.copyOf(roles == null ? List.of() : roles));
    }

    /**
     * Verifies a token. Failure ordering: malformed → unknown key →
     * signature mismatch → expired (skew-tolerant) → revoked.
     */
    public VerifiedCredential verify(String token) {
        if (token == null) {
            throw new CredentialException(CredentialRejection.MALFORMED, "missing credential");
        }
        String[] parts = token.split("\\.", -1);
        if (parts.length != 3) {
            throw new CredentialException(CredentialRejection.MALFORMED,
                    "credential must have three segments");
        }

        JsonNode header;
        JsonNode payload;
        byte[] signatureBytes;
        byte[] expectedSignature;
        try {
            header = mapper.readTree(decode(parts[0]));
            payload = mapper.readTree(decode(parts[1]));
            signatureBytes = Base64.getUrlDecoder().decode(parts[2]);
            if (!header.path("alg").asText("").equals("HS256")) {
                throw new CredentialException(CredentialRejection.MALFORMED, "unsupported alg");
            }
            String keyId = header.path("kid").asText(null);
            if (keyId == null || keyId.isBlank()) {
                throw new CredentialException(CredentialRejection.MALFORMED, "missing kid");
            }
            SecretKey key = keyManager.verificationKey(keyId);
            if (key == null) {
                throw new CredentialException(CredentialRejection.UNKNOWN_KEY,
                        "signing key unknown or past grace period");
            }
            expectedSignature = hmac(parts[0] + "." + parts[1], key);

            requireText(payload, "jti");
            requireText(payload, "sub");
            if (!payload.path("roles").isArray() || !payload.has("iat") || !payload.has("exp")) {
                throw new CredentialException(CredentialRejection.MALFORMED, "incomplete payload");
            }
        } catch (CredentialException e) {
            throw e;
        } catch (Exception e) {
            throw new CredentialException(CredentialRejection.MALFORMED,
                    "credential structure is corrupted");
        }

        if (!MessageDigest.isEqual(expectedSignature, signatureBytes)) {
            throw new CredentialException(CredentialRejection.SIGNATURE_MISMATCH,
                    "credential signature does not match");
        }

        long now = clock.epochMilli();
        long exp = payload.get("exp").asLong();
        if (now - skewMillis > exp) {
            throw new CredentialException(CredentialRejection.EXPIRED,
                    "credential expired beyond tolerated clock skew");
        }

        String jti = payload.get("jti").asText();
        if (revokedJtis.contains(jti)) {
            throw new CredentialException(CredentialRejection.REVOKED,
                    "credential has been revoked");
        }

        List<String> roles = mapper.convertValue(payload.get("roles"),
                mapper.getTypeFactory().constructCollectionType(List.class, String.class));
        return new VerifiedCredential(jti, payload.get("sub").asText(), List.copyOf(roles),
                header.get("kid").asText(), exp);
    }

    /** Revokes a single credential id. Revocation is immediate and independent per credential. */
    public boolean revoke(String jti) {
        if (jti == null || jti.isBlank()) {
            throw new IllegalArgumentException("jti is required");
        }
        return revokedJtis.add(jti);
    }

    public boolean isRevoked(String jti) {
        return revokedJtis.contains(jti);
    }

    long skewMillis() {
        return skewMillis;
    }

    private static void requireText(JsonNode node, String field) {
        if (!node.path(field).isTextual() || node.get(field).asText().isBlank()) {
            throw new CredentialException(CredentialRejection.MALFORMED,
                    "missing field " + field);
        }
    }

    private byte[] toJson(Object value) {
        try {
            return mapper.writeValueAsBytes(value);
        } catch (JsonProcessingException e) {
            throw new IllegalStateException("JSON encoding failed", e);
        }
    }

    private static String encode(byte[] bytes) {
        return Base64.getUrlEncoder().withoutPadding().encodeToString(bytes);
    }

    private static byte[] decode(String part) {
        return Base64.getUrlDecoder().decode(part);
    }

    private static byte[] hmac(String signingInput, SecretKey key) {
        return KeyManager.hmacSha256(key).doFinal(
                signingInput.getBytes(StandardCharsets.UTF_8));
    }

    private String newJti(String subject, long now) {
        String raw = subject + ":" + now + ":" + java.util.UUID.randomUUID();
        return HexFormat.of().formatHex(digest(raw));
    }

    private static byte[] digest(String raw) {
        try {
            return MessageDigest.getInstance("SHA-256")
                    .digest(raw.getBytes(StandardCharsets.UTF_8));
        } catch (Exception e) {
            throw new IllegalStateException("SHA-256 unavailable", e);
        }
    }
}
