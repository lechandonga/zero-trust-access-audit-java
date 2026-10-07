package com.github.lechandonga.zerotrustaccessauditjava.audit;

import com.github.lechandonga.zerotrustaccessauditjava.authz.AuthorizationResult;
import com.github.lechandonga.zerotrustaccessauditjava.credential.CredentialService;
import com.github.lechandonga.zerotrustaccessauditjava.crypto.SystemClock;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Service;

import java.util.List;
import java.util.concurrent.atomic.AtomicLong;

/**
 * Stores every authorization decision in an append-only in-memory log and
 * mirrors a sanitized line to the application logger.
 *
 * <p>Only non-secret attributes are recorded: never the credential token,
 * signature or any key bytes. The in-memory ring is bounded so a long
 * running process cannot grow it without limit.
 */
@Service
public class AuditService {

    private static final Logger log = LoggerFactory.getLogger("ztaa.audit");
    private static final int MAX_RECORDS = 10_000;

    private final SystemClock clock;
    private final AtomicLong sequence = new AtomicLong();

    /** Visible for tests; production code interacts via append/query. */
    final java.util.concurrent.ConcurrentLinkedDeque<AuditRecord> records =
            new java.util.concurrent.ConcurrentLinkedDeque<>();

    public AuditService(SystemClock clock) {
        this.clock = clock;
    }

    public AuditRecord append(CredentialService.VerifiedCredential credential,
                              AuthorizationResult result) {
        AuditRecord record = new AuditRecord(
                sequence.incrementAndGet(),
                clock.epochMilli(),
                result.subject(),
                credential.jti(),
                credential.keyId(),
                result.roles(),
                result.action(),
                result.resourceType(),
                result.resourceId(),
                result.allowed(),
                result.reason(),
                result.matchedRule(),
                result.policyVersion());
        records.addLast(record);
        while (records.size() > MAX_RECORDS) {
            records.pollFirst();
        }
        log.info("audit subject={} jti={} keyId={} action={} resource={}/{} allowed={} reason={} policyVersion={}",
                record.subject(), record.credentialId(), record.keyId(),
                record.action(), record.resourceType(), record.resourceId(),
                record.allowed(), record.reason(), record.policyVersion());
        return record;
    }

    /** Returns newest-first; optional subject filter. No credential material is included. */
    public List<AuditRecord> query(String subject, int limit) {
        int bounded = Math.min(Math.max(limit, 1), MAX_RECORDS);
        java.util.List<AuditRecord> snapshot = new java.util.ArrayList<>(records);
        java.util.Collections.reverse(snapshot);
        return snapshot.stream()
                .filter(r -> subject == null || subject.isBlank() || subject.equals(r.subject()))
                .limit(bounded)
                .toList();
    }

    public int size() {
        return records.size();
    }
}
