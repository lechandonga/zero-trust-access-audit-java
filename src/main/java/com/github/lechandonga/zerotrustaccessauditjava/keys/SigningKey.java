package com.github.lechandonga.zerotrustaccessauditjava.keys;

import javax.crypto.SecretKey;
import java.time.Instant;

/**
 * 一把签名密钥。密钥内容（SecretKey）永不对外暴露，
 * 仅在本模块内部用于签名与校验。
 *
 * @param keyId      密钥标识，可安全对外返回
 * @param key        密钥内容，禁止序列化/日志输出
 * @param createdAt  创建时间
 * @param graceUntil 宽限期截止时间；null 表示当前生效密钥（无宽限限制）
 */
public record SigningKey(String keyId, SecretKey key, Instant createdAt, Instant graceUntil) {

    /** 判断在给定时间点该密钥是否仍可用于校验。 */
    public boolean usableAt(Instant instant) {
        return graceUntil == null || !instant.isAfter(graceUntil);
    }
}
