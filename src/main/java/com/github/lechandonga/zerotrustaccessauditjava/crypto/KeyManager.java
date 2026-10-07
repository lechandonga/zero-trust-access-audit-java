package com.github.lechandonga.zerotrustaccessauditjava.crypto;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Component;

import javax.crypto.KeyGenerator;
import javax.crypto.Mac;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.HexFormat;
import java.util.List;
import java.util.NavigableMap;
import java.util.TreeMap;

/**
 * Stores HMAC-SHA256 signing keys with rotation support.
 *
 * <p>At any moment there is exactly one <em>active</em> key used for signing.
 * When a new key is activated the previously active key becomes a
 * <em>retired</em> key. Retired keys remain usable for verification until the
 * configured grace period elapses (measured from their retirement instant,
 * not from each credential's issuance instant), after which they are removed
 * and tokens signed by them fail with {@code unknown_key}.
 *
 * <p>All state transitions publish an immutable snapshot, so concurrent
 * verification threads either observe the pre-rotation or the post-rotation
 * state completely — never a half-updated one. Secret key bytes are never
 * exposed; only opaque key ids and key fingerprints leave this component.
 */
@Component
public class KeyManager {

    public record KeyInfo(String keyId, String fingerprint, long activatedAt, Long retiredAt) {
    }

    private record StoredKey(SecretKey key, String keyId, String fingerprint,
                             long activatedAt, long retiredAt) {
        boolean isActive(long now) {
            return retiredAt == Long.MAX_VALUE;
        }

        boolean withinGrace(long now, long graceMillis) {
            return retiredAt != Long.MAX_VALUE && now < retiredAt + graceMillis;
        }

        KeyInfo toInfo() {
            return new KeyInfo(keyId, fingerprint, activatedAt,
                    retiredAt == Long.MAX_VALUE ? null : retiredAt);
        }
    }

    private record Snapshot(String activeKeyId, NavigableMap<String, StoredKey> keys) {
    }

    private final SystemClock clock;
    private final long graceMillis;
    private volatile Snapshot snapshot;

    public KeyManager(SystemClock clock,
                      @Value("${ztaa.key.grace-millis:600000}") long graceMillis) {
        this.clock = clock;
        this.graceMillis = graceMillis;
        StoredKey initial = generateKey(clock.epochMilli());
        this.snapshot = new Snapshot(initial.keyId(),
                new TreeMap<>(java.util.Map.of(initial.keyId(), initial)));
    }

    private static StoredKey generateKey(long now) {
        try {
            KeyGenerator generator = KeyGenerator.getInstance("HmacSHA256");
            generator.init(256);
            SecretKey secret = generator.generateKey();
            String fingerprint = HexFormat.of().formatHex(
                    MessageDigest.getInstance("SHA-256").digest(secret.getEncoded()))
                    .substring(0, 16);
            return new StoredKey(secret, "k" + Long.toHexString(now) + "-" + fingerprint.substring(0, 8),
                    fingerprint, now, Long.MAX_VALUE);
        } catch (NoSuchAlgorithmException e) {
            throw new IllegalStateException("HMAC-SHA256 unavailable", e);
        }
    }

    /** Activates a fresh key and retires the previously active one. Returns the new key id. */
    public synchronized String rotate() {
        long now = clock.epochMilli();
        Snapshot current = prune(this.snapshot, now);
        StoredKey fresh = generateKey(now);
        NavigableMap<String, StoredKey> next = new TreeMap<>(current.keys());
        StoredKey previous = next.get(current.activeKeyId());
        if (previous != null) {
            next.put(previous.keyId(), new StoredKey(previous.key(), previous.keyId(),
                    previous.fingerprint(), previous.activatedAt(), now));
        }
        next.put(fresh.keyId(), fresh);
        this.snapshot = new Snapshot(fresh.keyId(), next);
        return fresh.keyId();
    }

    /** Key id used for signing new credentials. */
    public String activeKeyId() {
        return prune(snapshot, clock.epochMilli()).activeKeyId();
    }

    public SecretKey activeKey() {
        Snapshot current = prune(snapshot, clock.epochMilli());
        return current.keys().get(current.activeKeyId()).key();
    }

    /**
     * Resolves a key for verification. Retired keys resolve while inside their
     * grace window. Returns {@code null} when the id is unknown or expired.
     */
    public SecretKey verificationKey(String keyId) {
        Snapshot current = prune(snapshot, clock.epochMilli());
        StoredKey stored = current.keys().get(keyId);
        if (stored == null) {
            return null;
        }
        long now = clock.epochMilli();
        if (stored.isActive(now) || stored.withinGrace(now, graceMillis)) {
            return stored.key();
        }
        return null;
    }

    /** Metadata only — never the secret bytes. */
    public List<KeyInfo> listKeys() {
        Snapshot current = prune(snapshot, clock.epochMilli());
        return current.keys().values().stream().map(StoredKey::toInfo).toList();
    }

    long graceMillis() {
        return graceMillis;
    }

    private Snapshot prune(Snapshot source, long now) {
        boolean changed = false;
        NavigableMap<String, StoredKey> kept = new TreeMap<>();
        for (StoredKey key : source.keys().values()) {
            if (key.isActive(now) || key.withinGrace(now, graceMillis)) {
                kept.put(key.keyId(), key);
            } else {
                changed = true;
            }
        }
        if (!changed) {
            return source;
        }
        Snapshot pruned = new Snapshot(source.activeKeyId(), kept);
        if (source == this.snapshot) {
            this.snapshot = pruned;
        }
        return pruned;
    }

    /** Reconstructs a key from raw bytes; used only by tests for controlled scenarios. */
    static SecretKey hmacKeyFromBytes(byte[] bytes) {
        return new SecretKeySpec(bytes, "HmacSHA256");
    }

    public static Mac hmacSha256(SecretKey key) {
        try {
            Mac mac = Mac.getInstance("HmacSHA256");
            mac.init(key);
            return mac;
        } catch (Exception e) {
            throw new IllegalStateException("HMAC init failed", e);
        }
    }
}

