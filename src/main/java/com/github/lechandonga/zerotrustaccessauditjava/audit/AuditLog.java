package com.github.lechandonga.zerotrustaccessauditjava.audit;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Component;

import java.util.List;
import java.util.concurrent.CopyOnWriteArrayList;

/**
 * 本地审计日志：线程安全的追加与查询。
 * 审计记录不含凭证与密钥内容，日志输出亦然。
 */
@Component
public class AuditLog {

    private static final Logger log = LoggerFactory.getLogger(AuditLog.class);

    private final CopyOnWriteArrayList<AuditRecord> records = new CopyOnWriteArrayList<>();

    public void append(AuditRecord record) {
        records.add(record);
        log.info("Audit: id={}, subject={}, action={}, resourceType={}, allowed={}, reason={}",
                record.auditId(), record.subject(), record.action(),
                record.resourceType(), record.allowed(), record.reason());
    }

    /** 返回当前审计记录的不可变快照。 */
    public List<AuditRecord> query() {
        return List.copyOf(records);
    }
}
