package com.github.lechandonga.zerotrustaccessauditjava.keys;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Component;

import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.util.ArrayList;
import java.util.List;
import java.util.Optional;
import java.util.UUID;
import java.util.concurrent.locks.ReentrantLock;

/**
 * 签名密钥管理器：负责密钥生成、轮换与多密钥共存。
 *
 * 并发模型：当前密钥环保存在 volatile 引用中，读取无锁；
 * 轮换在锁内构造全新的不可变 KeyRing 后一次性替换引用，
 * 因此轮换与校验并发时不会出现误判或半更新状态。
 */
@Component
public class KeyManager {

    private static final Logger log = LoggerFactory.getLogger(KeyManager.class);

    private final Duration gracePeriod;
    private final Clock clock;
    private final ReentrantLock rotateLock = new ReentrantLock();

    private volatile KeyRing keyRing;

    @Autowired
    public KeyManager(@Value("${zerotrust.key.grace-period:PT5M}") Duration gracePeriod) {
        this(gracePeriod, Clock.systemUTC());
    }

    public KeyManager(Duration gracePeriod, Clock clock) {
        this.gracePeriod = gracePeriod;
        this.clock = clock;
        this.keyRing = new KeyRing(generateKey(), List.of());
        log.info("Signing key initialized, keyId={}", keyRing.active().keyId());
    }

    /** 当前生效密钥的标识（不暴露密钥内容）。 */
    public String currentKeyId() {
        return keyRing.active().keyId();
    }

    /** 当前生效密钥（仅供内部签名使用）。 */
    public SigningKey activeKey() {
        return keyRing.active();
    }

    /**
     * 按 keyId 查找在给定时间点可用于校验的密钥。
     * 宽限期已过的旧密钥不会被返回，对应凭证校验失败。
     */
    public Optional<SigningKey> findVerificationKey(String keyId, Instant now) {
        return keyRing.findUsable(keyId, now);
    }

    /**
     * 轮换密钥：生成新密钥作为生效密钥，旧密钥进入宽限期。
     * 返回新密钥的标识。
     */
    public String rotate() {
        rotateLock.lock();
        try {
            KeyRing current = keyRing;
            Instant now = clock.instant();
            SigningKey oldActive = new SigningKey(
                    current.active().keyId(), current.active().key(),
                    current.active().createdAt(), now.plus(gracePeriod));
            List<SigningKey> retired = new ArrayList<>();
            retired.add(oldActive);
            // 清理已过宽限期的旧密钥，避免无限增长
            for (SigningKey k : current.retired()) {
                if (k.usableAt(now)) {
                    retired.add(k);
                }
            }
            SigningKey fresh = generateKey();
            keyRing = new KeyRing(fresh, List.copyOf(retired));
            log.info("Signing key rotated: newKeyId={}, retiredKeyId={}, graceUntil={}",
                    fresh.keyId(), oldActive.keyId(), oldActive.graceUntil());
            return fresh.keyId();
        } finally {
            rotateLock.unlock();
        }
    }

    private SigningKey generateKey() {
        try {
            KeyGenerator generator = KeyGenerator.getInstance("HmacSHA256");
            generator.init(256, new SecureRandom());
            SecretKey key = generator.generateKey();
            String keyId = "k-" + UUID.randomUUID().toString().substring(0, 8);
            return new SigningKey(keyId, key, clock.instant(), null);
        } catch (NoSuchAlgorithmException e) {
            throw new IllegalStateException("HmacSHA256 not available", e);
        }
    }
}
