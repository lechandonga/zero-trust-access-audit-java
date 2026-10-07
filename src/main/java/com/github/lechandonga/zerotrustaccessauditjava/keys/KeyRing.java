package com.github.lechandonga.zerotrustaccessauditjava.keys;

import java.time.Instant;
import java.util.List;
import java.util.Optional;

/**
 * 密钥环的不可变快照。轮换时整体替换引用，
 * 保证并发校验要么看到旧快照、要么看到新快照，绝不出现半更新状态。
 */
public record KeyRing(SigningKey active, List<SigningKey> retired) {

    public Optional<SigningKey> findUsable(String keyId, Instant now) {
        if (active.keyId().equals(keyId) && active.usableAt(now)) {
            return Optional.of(active);
        }
        return retired.stream()
                .filter(k -> k.keyId().equals(keyId) && k.usableAt(now))
                .findFirst();
    }
}
