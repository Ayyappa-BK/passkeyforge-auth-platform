package dev.passkeyforge;

import io.micrometer.core.instrument.MeterRegistry;
import io.micrometer.tracing.Tracer;
import java.util.*;
import org.slf4j.*;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.*;

@Service
public class Audit {
  final JdbcTemplate db;
  final MeterRegistry metrics;
  final Tracer tracer;
  final Logger log = LoggerFactory.getLogger(Audit.class);

  public Audit(JdbcTemplate db, MeterRegistry metrics, Tracer tracer) {
    this.db = db;
    this.metrics = metrics;
    this.tracer = tracer;
  }

  @Transactional(propagation = Propagation.REQUIRES_NEW)
  public void event(UUID account, String event, String outcome) {
    String trace = tracer.currentSpan() == null ? null : tracer.currentSpan().context().traceId();
    db.update(
        "insert into audit_events(id,account_id,event,outcome,trace_id) values(?,?,?,?,?)",
        UUID.randomUUID(),
        account,
        event,
        outcome,
        trace);
    metrics.counter("forge.auth.events", "event", event, "outcome", outcome).increment();
    log.atInfo()
        .addKeyValue("account_id", account)
        .addKeyValue("event", event)
        .addKeyValue("outcome", outcome)
        .log("Authentication audit");
  }
}
