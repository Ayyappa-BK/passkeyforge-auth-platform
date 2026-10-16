package dev.passkeyforge;

import java.time.*;
import java.util.*;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.scheduling.annotation.Scheduled;
import org.springframework.stereotype.Service;
import org.springframework.transaction.*;
import org.springframework.transaction.support.TransactionTemplate;

@Service
public class Challenges {
  final JdbcTemplate db;
  final TransactionTemplate fresh;
  final Audit audit;

  public Challenges(JdbcTemplate db, PlatformTransactionManager tm, Audit audit) {
    this.db = db;
    this.audit = audit;
    fresh = new TransactionTemplate(tm);
    fresh.setPropagationBehavior(TransactionDefinition.PROPAGATION_REQUIRES_NEW);
  }

  record Challenge(UUID id, String kind, UUID account, String payload) {}

  UUID issue(String binding, String kind, UUID account, String payload) {
    UUID id = UUID.randomUUID();
    db.update(
        "insert into challenges values (?,?,?,?,?,now()+interval '120 seconds')",
        id,
        Crypto.digest(binding),
        kind,
        account,
        payload);
    return id;
  }

  Challenge consume(UUID id, String binding, String kind) {
    // Commit the burn even if protocol validation or the outer transaction fails.
    try {
      return fresh.execute(
          tx ->
              db
                  .query(
                      "delete from challenges where id=? and binding=? and kind=? and"
                          + " expires_at>now() returning *",
                      (r, n) ->
                          new Challenge(
                              r.getObject("id", UUID.class),
                              r.getString("kind"),
                              r.getObject("account_id", UUID.class),
                              r.getString("payload")),
                      id,
                      Crypto.digest(binding),
                      kind)
                  .stream()
                  .findFirst()
                  .orElseThrow(ApiError::denied));
    } catch (ApiError e) {
      audit.event(null, "challenge_rejected", "failure");
      throw e;
    }
  }

  @Scheduled(fixedDelay = 60000)
  void cleanup() {
    db.update("delete from challenges where expires_at<now()");
    db.update("delete from rate_buckets where expires_at<now()");
    db.update("update accounts set pending_totp=null,pending_until=null where pending_until<now()");
  }
}
