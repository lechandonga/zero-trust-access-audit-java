package com.github.lechandonga.zerotrustaccessauditjava.tests;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/** 在测试日志中明确标注业务覆盖范围与用例执行情况。 */
public final class TestCoverageLog {

    private TestCoverageLog() {
    }

    public static Logger cover(Class<?> testClass, String business, String... cases) {
        Logger log = LoggerFactory.getLogger(testClass);
        log.info("==================== 业务覆盖: {} ====================", business);
        for (String c : cases) {
            log.info("  用例: {}", c);
        }
        return log;
    }

    public static void pass(Logger log, String caseName) {
        log.info("  [通过] {}", caseName);
    }
}
