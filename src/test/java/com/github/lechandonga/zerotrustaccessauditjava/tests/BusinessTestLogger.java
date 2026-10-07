package com.github.lechandonga.zerotrustaccessauditjava.tests;

import org.junit.jupiter.api.extension.AfterEachCallback;
import org.junit.jupiter.api.extension.BeforeEachCallback;
import org.junit.jupiter.api.extension.ExtensionContext;
import org.slf4j.LoggerFactory;

import java.lang.reflect.Method;

/**
 * Prints a clear business/case banner around every unit test so the test
 * log shows which business capability is covered and whether each case
 * passed or failed.
 */
public class BusinessTestLogger implements BeforeEachCallback, AfterEachCallback {

    @Override
    public void beforeEach(ExtensionContext context) {
        Method method = context.getRequiredTestMethod();
        String business = business(context);
        LoggerFactory.getLogger("ztaa.tests").info(
                "========== [业务:{}] 用例开始: {} ==========", business, method.getName());
    }

    @Override
    public void afterEach(ExtensionContext context) {
        String business = business(context);
        String method = context.getRequiredTestMethod().getName();
        boolean failed = context.getExecutionException().isPresent();
        LoggerFactory.getLogger("ztaa.tests").info(
                "========== [业务:{}] 用例{}: {} ==========",
                business, failed ? "失败" : "通过", method);
    }

    private String business(ExtensionContext context) {
        Class<?> type = context.getRequiredTestClass();
        if (type.isAnnotationPresent(Business.class)) {
            return type.getAnnotation(Business.class).value();
        }
        Method method = context.getRequiredTestMethod();
        if (method.isAnnotationPresent(Business.class)) {
            return method.getAnnotation(Business.class).value();
        }
        return type.getSimpleName();
    }
}

