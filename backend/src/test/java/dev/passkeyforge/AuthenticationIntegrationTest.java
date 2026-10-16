package dev.passkeyforge;

import static org.junit.jupiter.api.Assertions.*;
import static org.springframework.security.test.web.servlet.request.SecurityMockMvcRequestPostProcessors.csrf;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.*;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.*;

import com.fasterxml.jackson.databind.*;
import dev.samstevens.totp.code.DefaultCodeGenerator;
import java.util.*;
import java.util.concurrent.*;
import org.junit.jupiter.api.*;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.mock.web.MockHttpSession;
import org.springframework.test.web.servlet.*;

@SpringBootTest(
    properties = {
      "spring.autoconfigure.exclude=org.springframework.boot.autoconfigure.session.SessionAutoConfiguration",
      "logging.level.dev.passkeyforge.WebAuthnService=DEBUG",
      "management.otlp.tracing.export.enabled=false",
      "forge.encryption-key=AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA="
    })
@AutoConfigureMockMvc
class AuthenticationIntegrationTest {
  @Autowired MockMvc mvc;
  @Autowired ObjectMapper json;
  @Autowired JdbcTemplate db;
  @Autowired Crypto crypto;
  @Autowired MfaService mfa;
  @Autowired Challenges challenges;
  MockHttpSession session;

  @BeforeEach
  void reset() {
    db.execute(
        "truncate"
            + " accounts,credentials,challenges,recovery_codes,rate_buckets,audit_events,spring_session"
            + " cascade");
    session = new MockHttpSession();
  }

  JsonNode body(MvcResult r) throws Exception {
    return json.readTree(r.getResponse().getContentAsString());
  }

  MvcResult postJson(String path, Object data, int status) throws Exception {
    var result =
        mvc.perform(
                post("/api" + path)
                    .session(session)
                    .with(csrf())
                    .contentType("application/json")
                    .content(json.writeValueAsBytes(data)))
            .andExpect(status().is(status))
            .andReturn();
    var updated = result.getRequest().getSession(false);
    if (updated != null) session = (MockHttpSession) updated;
    return result;
  }

  JsonNode options(String path) throws Exception {
    return body(postJson(path, Map.of("username", "alice"), 200));
  }

  Map<String, Object> finish(JsonNode options, JsonNode response) {
    return Map.of(
        "ceremonyId",
        options.get("ceremonyId").asText(),
        "credential",
        response,
        "label",
        "Test passkey");
  }

  VirtualAuthenticator signup() throws Exception {
    var a = new VirtualAuthenticator();
    var opts = options("/registration/options");
    postJson("/registration/finish", finish(opts, a.registration(opts)), 200);
    return a;
  }

  JsonNode login(VirtualAuthenticator a) throws Exception {
    session = new MockHttpSession();
    var opts = options("/authentication/options");
    return body(postJson("/authentication/finish", finish(opts, a.assertion(opts)), 200));
  }

  UUID user() {
    return db.queryForObject("select id from accounts where username='alice'", UUID.class);
  }

  String enroll() throws Exception {
    var result = body(postJson("/totp/enrollment", Map.of(), 200));
    assertTrue(result.get("qrDataUrl").asText().startsWith("data:image/png;base64,"));
    String stored =
        db.queryForObject("select pending_totp from accounts where id=?", String.class, user());
    assertFalse(stored.contains("otpauth"));
    return crypto.decrypt(user(), stored);
  }

  String otp(String secret, long offset) throws Exception {
    return new DefaultCodeGenerator().generate(secret, System.currentTimeMillis() / 30000 + offset);
  }

  @Test
  void completeRegistrationAuthenticationEnrollmentAndMfa() throws Exception {
    var auth = signup();
    mvc.perform(get("/api/me").session(session)).andExpect(status().isOk());
    String secret = enroll();
    String enrollmentCode = otp(secret, 0);
    var codes =
        body(postJson("/totp/confirmation", Map.of("code", enrollmentCode), 200))
            .get("recoveryCodes");
    assertEquals(10, codes.size());
    assertEquals(10, db.queryForObject("select count(*) from recovery_codes", Integer.class));
    assertTrue(login(auth).get("mfaRequired").asBoolean());
    mvc.perform(get("/api/me").session(session)).andExpect(status().isUnauthorized());
    postJson("/mfa/totp", Map.of("code", "nototp"), 401);
    postJson(
        "/mfa/totp",
        Map.of("code", enrollmentCode),
        401); // enrollment already burned this timestep
    postJson("/mfa/totp", Map.of("code", otp(secret, 1)), 200);
    mvc.perform(get("/api/me").session(session)).andExpect(status().isOk());
  }

  @Test
  void challengeCannotBeReusedIncludingAfterFailedSignature() throws Exception {
    var auth = signup();
    var opts = options("/authentication/options");
    var response = auth.assertion(opts);
    postJson("/authentication/finish", finish(opts, response), 200);
    postJson("/authentication/finish", finish(opts, response), 401);
    opts = options("/authentication/options");
    response = auth.assertion(opts, "http://localhost:8080", "localhost", 5, null, true);
    postJson("/authentication/finish", finish(opts, response), 401);
    postJson("/authentication/finish", finish(opts, auth.assertion(opts)), 401);
  }

  @Test
  void registrationReplayAndExpiredChallengesFail() throws Exception {
    var auth = new VirtualAuthenticator();
    var opts = options("/registration/options");
    var response = auth.registration(opts);
    db.update("update challenges set expires_at=now()-interval '1 second'");
    postJson("/registration/finish", finish(opts, response), 401);
    opts = options("/registration/options");
    response = auth.registration(opts);
    postJson("/registration/finish", finish(opts, response), 200);
    postJson("/registration/finish", finish(opts, response), 401);
  }

  @Test
  void rejectsWrongOriginRpChallengeMissingUvAndBadSignature() throws Exception {
    var auth = signup();
    for (int i = 0; i < 5; i++) {
      var opts = options("/authentication/options");
      var response =
          auth.assertion(
              opts,
              i == 0 ? "https://evil.example" : "http://localhost:8080",
              i == 1 ? "evil.example" : "localhost",
              i == 2 ? 1 : 5,
              i == 3 ? Crypto.token() : null,
              i == 4);
      postJson("/authentication/finish", finish(opts, response), 401);
    }
  }

  @Test
  void registrationValidatesOriginRpChallengeAndUv() throws Exception {
    for (int i = 0; i < 4; i++) {
      var auth = new VirtualAuthenticator();
      var opts = options("/registration/options");
      var response =
          auth.registration(
              opts,
              i == 0 ? "https://evil.example" : "http://localhost:8080",
              i == 1 ? "evil.example" : "localhost",
              i == 2 ? 0x41 : 0x45,
              i == 3 ? Crypto.token() : null);
      postJson("/registration/finish", finish(opts, response), 401);
    }
    assertEquals(0, db.queryForObject("select count(*) from accounts", Integer.class));
  }

  @Test
  void crossSessionCeremoniesAndCsrfAreRejected() throws Exception {
    var auth = new VirtualAuthenticator();
    var opts = options("/registration/options");
    var response = auth.registration(opts);
    var original = session;
    session = new MockHttpSession();
    postJson("/registration/finish", finish(opts, response), 401);
    session = original;
    postJson("/registration/finish", finish(opts, response), 200);
    mvc.perform(post("/api/recovery-codes").session(session)).andExpect(status().isForbidden());
  }

  @Test
  void recoveryIsSingleUseAndRestrictsAccountManagement() throws Exception {
    signup();
    var codes = body(postJson("/recovery-codes", Map.of(), 200)).get("recoveryCodes");
    String code = codes.get(0).asText();
    session = new MockHttpSession();
    postJson("/recovery", Map.of("username", "alice", "code", code), 200);
    mvc.perform(get("/api/me").session(session)).andExpect(status().isUnauthorized());
    postJson("/recovery", Map.of("username", "alice", "code", code), 401);
    var replacement = new VirtualAuthenticator();
    var opts = options("/registration/options");
    postJson("/registration/finish", finish(opts, replacement.registration(opts)), 200);
    assertEquals(2, db.queryForObject("select count(*) from credentials", Integer.class));
    assertFalse(login(replacement).get("mfaRequired").asBoolean());
  }

  @Test
  void recoveryMfaWorksOnceAndCanDisableTotpWithFreshOtp() throws Exception {
    var auth = signup();
    String secret = enroll();
    var codes =
        body(postJson("/totp/confirmation", Map.of("code", otp(secret, 0)), 200))
            .get("recoveryCodes");
    login(auth);
    postJson("/mfa/recovery", Map.of("code", codes.get(0).asText()), 200);
    login(auth);
    postJson("/mfa/recovery", Map.of("code", codes.get(0).asText()), 401);
    postJson("/mfa/recovery", Map.of("code", codes.get(1).asText()), 200);
    postJson("/totp/disable", Map.of("code", otp(secret, 1)), 200);
    assertNull(
        db.queryForObject("select totp_secret from accounts where id=?", String.class, user()));
  }

  @Test
  void unauthorizedCredentialOperationsAndLastPasskeyFail() throws Exception {
    signup();
    String id = db.queryForObject("select id from credentials", String.class);
    mvc.perform(delete("/api/credentials/" + id).session(session).with(csrf()))
        .andExpect(status().isConflict());
    var opts = options("/registration/options");
    var second = new VirtualAuthenticator();
    postJson("/registration/finish", finish(opts, second.registration(opts)), 200);
    UUID other = UUID.randomUUID();
    db.update(
        "insert into accounts(id,username,handle) values(?,?,?)", other, "bob", Crypto.random(32));
    db.update(
        "insert into"
            + " credentials(id,account_id,public_key,signature_count,label,backup_eligible,backed_up)"
            + " values('foreign',?, ?,0,'Other',false,false)",
        other,
        new byte[] {1});
    mvc.perform(delete("/api/credentials/foreign").session(session).with(csrf()))
        .andExpect(status().isNotFound());
    mvc.perform(delete("/api/credentials/" + id).session(session).with(csrf()))
        .andExpect(status().isOk());
    session = new MockHttpSession();
    mvc.perform(delete("/api/credentials/foreign").session(session).with(csrf()))
        .andExpect(status().isUnauthorized());
  }

  @Test
  void rateLimitIsEnforcedAndAudited() throws Exception {
    for (int i = 0; i < 20; i++) options("/authentication/options");
    postJson("/authentication/options", Map.of(), 429);
  }

  @Test
  void concurrentRecoveryRedemptionHasExactlyOneWinner() throws Exception {
    signup();
    String code = body(postJson("/recovery-codes", Map.of(), 200)).at("/recoveryCodes/0").asText();
    UUID id = user();
    try (var pool = Executors.newFixedThreadPool(2)) {
      Callable<Boolean> call =
          () -> {
            try {
              mfa.redeem(id, code);
              return true;
            } catch (ApiError e) {
              return false;
            }
          };
      var futures = pool.invokeAll(List.of(call, call));
      assertEquals(
          1,
          futures.stream()
              .filter(
                  f -> {
                    try {
                      return f.get();
                    } catch (Exception e) {
                      throw new RuntimeException(e);
                    }
                  })
              .count());
    }
  }

  @Test
  void expiredPendingMfaAndEnrollmentAreRejected() throws Exception {
    var auth = signup();
    String secret = enroll();
    db.update("update accounts set pending_until=now()-interval '1 second'");
    postJson("/totp/confirmation", Map.of("code", otp(secret, 0)), 401);
    secret = enroll();
    postJson("/totp/confirmation", Map.of("code", otp(secret, 0)), 200);
    login(auth);
    session.setAttribute("issued", System.currentTimeMillis() / 1000 - 301);
    postJson("/mfa/recovery", Map.of("code", "anything"), 401);
  }

  @Test
  void recentAuthenticationIsRequiredForSecurityChanges() throws Exception {
    signup();
    session.setAttribute("verified", System.currentTimeMillis() / 1000 - 301);
    postJson("/recovery-codes", Map.of(), 403);
    postJson("/totp/enrollment", Map.of(), 403);
  }

  @Test
  void expiredAssertionAndWrongUserHandleAreRejected() throws Exception {
    var auth = signup();
    var opts = options("/authentication/options");
    db.update("update challenges set expires_at=now()-interval '1 second'");
    postJson("/authentication/finish", finish(opts, auth.assertion(opts)), 401);
    opts = options("/authentication/options");
    auth.handle = Crypto.random(32);
    postJson("/authentication/finish", finish(opts, auth.assertion(opts)), 401);
  }

  @Test
  void signatureCounterRollbackIsRejected() throws Exception {
    var auth = signup();
    login(auth);
    auth.counter = 0;
    var opts = options("/authentication/options");
    postJson("/authentication/finish", finish(opts, auth.assertion(opts)), 401);
  }

  @Test
  void concurrentChallengeConsumeHasExactlyOneWinner() throws Exception {
    UUID ceremony = challenges.issue("binding", "AUTHENTICATE", UUID.randomUUID(), "{}");
    try (var pool = Executors.newFixedThreadPool(2)) {
      Callable<Boolean> call =
          () -> {
            try {
              challenges.consume(ceremony, "binding", "AUTHENTICATE");
              return true;
            } catch (ApiError e) {
              return false;
            }
          };
      var futures = pool.invokeAll(List.of(call, call));
      assertEquals(
          1,
          futures.stream()
              .filter(
                  f -> {
                    try {
                      return f.get();
                    } catch (Exception e) {
                      throw new RuntimeException(e);
                    }
                  })
              .count());
    }
  }
}
