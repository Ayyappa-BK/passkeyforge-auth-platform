package dev.passkeyforge;

import com.fasterxml.jackson.databind.JsonNode;
import jakarta.servlet.http.*;
import jakarta.validation.Valid;
import jakarta.validation.constraints.*;
import java.util.*;
import org.springframework.security.web.csrf.CsrfToken;
import org.springframework.transaction.PlatformTransactionManager;
import org.springframework.transaction.support.TransactionTemplate;
import org.springframework.web.bind.annotation.*;

@RestController
@RequestMapping("/api")
public class Api {
  final WebAuthnService webauthn;
  final MfaService mfa;
  final Sessions sessions;
  final Store store;
  final RateLimits limits;
  final Audit audit;
  final TransactionTemplate tx;

  public Api(
      WebAuthnService webauthn,
      MfaService mfa,
      Sessions sessions,
      Store store,
      RateLimits limits,
      Audit audit,
      PlatformTransactionManager tm) {
    this.webauthn = webauthn;
    this.mfa = mfa;
    this.sessions = sessions;
    this.store = store;
    this.limits = limits;
    this.audit = audit;
    tx = new TransactionTemplate(tm);
  }

  record Name(String username) {}

  record Finish(
      @NotNull UUID ceremonyId,
      @NotNull JsonNode credential,
      @Size(min = 1, max = 80) String label) {}

  record Code(@NotBlank @Size(max = 128) String code) {}

  record Recovery(
      @NotBlank @Size(max = 64) String username, @NotBlank @Size(max = 128) String code) {}

  @GetMapping("/csrf")
  Map<String, String> csrf(CsrfToken token) {
    return Map.of("token", token.getToken(), "headerName", token.getHeaderName());
  }

  void attempt(HttpServletRequest req, String action, UUID user) {
    limits.check(action + ":" + req.getRemoteAddr(), 20, 60);
    if (user != null) limits.check(action + ":" + user, 8, 300);
  }

  @PostMapping("/registration/options")
  Object registration(HttpServletRequest req, @RequestBody Name name) throws Exception {
    attempt(req, "registration", null);
    return webauthn.registration(req, name.username());
  }

  @PostMapping("/registration/finish")
  Object register(HttpServletRequest req, @Valid @RequestBody Finish f) throws Exception {
    attempt(req, "registration", null);
    var result =
        webauthn.register(
            req, f.ceremonyId(), f.credential(), f.label() == null ? "My passkey" : f.label());
    sessions.establish(req, result.id(), result.mfa() ? "PENDING" : "FULL");
    return Map.of("mfaRequired", result.mfa());
  }

  @PostMapping("/authentication/options")
  Object authentication(HttpServletRequest req) throws Exception {
    attempt(req, "authentication", null);
    return webauthn.authentication(req);
  }

  @PostMapping("/authentication/finish")
  Object authenticate(HttpServletRequest req, @Valid @RequestBody Finish f) throws Exception {
    attempt(req, "authentication", null);
    var result = webauthn.authenticate(req, f.ceremonyId(), f.credential());
    sessions.establish(req, result.id(), result.mfa() ? "PENDING" : "FULL");
    return Map.of("mfaRequired", result.mfa());
  }

  @PostMapping("/mfa/totp")
  Object verify(HttpServletRequest req, @Valid @RequestBody Code code) {
    UUID id = sessions.require(req, "PENDING");
    attempt(req, "mfa", id);
    mfa.verify(id, code.code());
    sessions.establish(req, id, "FULL");
    return Map.of("authenticated", true);
  }

  @PostMapping("/mfa/recovery")
  Object recoveryMfa(HttpServletRequest req, @Valid @RequestBody Code code) {
    UUID id = sessions.require(req, "PENDING");
    attempt(req, "recovery", id);
    mfa.redeem(id, code.code());
    sessions.revoke(id);
    sessions.establish(req, id, "FULL");
    return Map.of("authenticated", true);
  }

  @PostMapping("/recovery")
  Object recover(HttpServletRequest req, @Valid @RequestBody Recovery r) {
    attempt(req, "recovery", null);
    var a = store.named(WebAuthnService.normalize(r.username())).orElseThrow(ApiError::denied);
    limits.check("recovery:" + a.id(), 8, 300);
    mfa.redeem(a.id(), r.code());
    sessions.revoke(a.id());
    sessions.establish(req, a.id(), "RECOVERY");
    return Map.of("enrollPasskeyRequired", true);
  }

  @GetMapping("/me")
  Object me(HttpServletRequest req) {
    var a = store.account(sessions.require(req, "FULL"), false);
    return Map.of(
        "id",
        a.id(),
        "username",
        a.username(),
        "totpEnabled",
        a.secret() != null,
        "recoveryCodesRemaining",
        store
            .jdbc()
            .queryForObject(
                "select count(*) from recovery_codes where account_id=?", Integer.class, a.id()));
  }

  @GetMapping("/credentials")
  Object credentials(HttpServletRequest req) {
    return store
        .jdbc()
        .queryForList(
            "select id,label,backup_eligible,backed_up,created_at,last_used_at from credentials"
                + " where account_id=? order by created_at",
            sessions.require(req, "FULL"));
  }

  @DeleteMapping("/credentials/{id}")
  void delete(HttpServletRequest req, @PathVariable String id) {
    UUID user = sessions.recent(req);
    tx.executeWithoutResult(
        t -> {
          store.account(user, true);
          if (store
                  .jdbc()
                  .queryForObject(
                      "select count(*) from credentials where account_id=?", Integer.class, user)
              <= 1) throw new ApiError(409, "Enroll another passkey before removing the last one");
          if (store.jdbc().update("delete from credentials where id=? and account_id=?", id, user)
              != 1) throw new ApiError(404, "Credential not found");
        });
    sessions.revoke(user);
    sessions.refresh(req, user);
    audit.event(user, "credential_deleted", "success");
  }

  @PostMapping("/totp/enrollment")
  Object enroll(HttpServletRequest req) throws Exception {
    UUID id = sessions.recent(req);
    attempt(req, "enrollment", id);
    return mfa.enroll(id);
  }

  @PostMapping("/totp/confirmation")
  Object confirm(HttpServletRequest req, @Valid @RequestBody Code c) {
    UUID id = sessions.recent(req);
    attempt(req, "enrollment", id);
    var codes = mfa.confirm(id, c.code());
    sessions.revoke(id);
    sessions.refresh(req, id);
    return Map.of("recoveryCodes", codes);
  }

  @PostMapping("/totp/disable")
  void disable(HttpServletRequest req, @Valid @RequestBody Code c) {
    UUID id = sessions.recent(req);
    attempt(req, "mfa", id);
    mfa.disable(id, c.code());
    sessions.revoke(id);
    sessions.refresh(req, id);
  }

  @PostMapping("/recovery-codes")
  Object rotate(HttpServletRequest req) {
    UUID id = sessions.recent(req);
    attempt(req, "recovery_rotation", id);
    return Map.of("recoveryCodes", mfa.rotate(id));
  }

  @GetMapping("/audit")
  Object events(HttpServletRequest req) {
    return store
        .jdbc()
        .queryForList(
            "select event,outcome,occurred_at from audit_events where account_id=? order by"
                + " occurred_at desc limit 50",
            sessions.require(req, "FULL"));
  }

  @PostMapping("/sessions/revoke")
  void revoke(HttpServletRequest req) {
    UUID id = sessions.recent(req);
    sessions.revoke(id);
    sessions.refresh(req, id);
    audit.event(id, "sessions_revoked", "success");
  }

  @PostMapping("/logout")
  void logout(HttpServletRequest req) {
    var s = req.getSession(false);
    if (s != null) s.invalidate();
  }
}
