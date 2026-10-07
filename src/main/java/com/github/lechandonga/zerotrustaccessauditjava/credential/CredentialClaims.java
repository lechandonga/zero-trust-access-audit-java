package com.github.lechandonga.zerotrustaccessauditjava.credential;

import java.time.Instant;
import java.util.Map;
import java.util.Set;

/**
 * 凭证负载。注意：不包含任何密钥或签名材料。
 */
public record CredentialClaims(
        String jti,
        String subject,
        Set<String> roles,
        Map<String, String> attributes,
        Instant issuedAt,
        Instant expiresAt,
        String keyId) {
}
