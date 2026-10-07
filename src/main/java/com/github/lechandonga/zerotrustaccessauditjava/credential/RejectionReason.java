package com.github.lechandonga.zerotrustaccessauditjava.credential;

/** 凭证被拒绝的原因，彼此可区分。 */
public enum RejectionReason {
    /** 结构损坏：无法解析为合法的凭证格式 */
    MALFORMED,
    /** 签名不匹配：内容被篡改或签名密钥不符 */
    SIGNATURE_MISMATCH,
    /** 凭证已过期（已容忍少量时钟偏差） */
    EXPIRED,
    /** 凭证已被吊销 */
    REVOKED,
    /** 签名密钥未知或已过轮换宽限期 */
    UNKNOWN_KEY
}
