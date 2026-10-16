package dev.passkeyforge;
import com.yubico.webauthn.*;
import com.yubico.webauthn.data.*;
import com.fasterxml.jackson.databind.*;
import jakarta.servlet.http.HttpServletRequest;
import java.util.*;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;
@Service
public class WebAuthnService {
 final Store store; final Challenges challenges; final Sessions sessions; final Audit audit;
 final ObjectMapper json; final RelyingParty rp;
 public WebAuthnService(Store store,Challenges challenges,Sessions sessions,Audit audit,ObjectMapper json,
  @Value("${forge.rp-id}") String rpId,@Value("${forge.origin}") String origin) {
  this.store=store; this.challenges=challenges; this.sessions=sessions; this.audit=audit; this.json=json;
  var uri=java.net.URI.create(origin);
  if(!"https".equals(uri.getScheme()) && !("http".equals(uri.getScheme()) && "localhost".equals(uri.getHost())))
   throw new IllegalArgumentException("Production WebAuthn requires HTTPS");
  rp=RelyingParty.builder().identity(RelyingPartyIdentity.builder().id(rpId).name("PasskeyForge").build())
   .credentialRepository(store).origins(Set.of(origin)).allowOriginPort(false).allowOriginSubdomain(false)
   .preferredPubkeyParams(java.util.List.of(PublicKeyCredentialParameters.ES256,PublicKeyCredentialParameters.EdDSA,PublicKeyCredentialParameters.RS256)).attestationConveyancePreference(AttestationConveyancePreference.NONE).validateSignatureCounter(true).build();
 }
 record Options(UUID ceremonyId,JsonNode options) {}
 record Identity(UUID id,boolean mfa) {}
 @Transactional
 public Options registration(HttpServletRequest req,String username) throws Exception {
  UUID id; UserIdentity user;
  var s=req.getSession(false);
  if(s!=null && s.getAttribute("uid")!=null) {
   id="RECOVERY".equals(s.getAttribute("level"))?sessions.require(req,"RECOVERY"):sessions.recent(req);
   var a=store.account(id,true);
   if(store.db.queryForObject("select count(*) from credentials where account_id=?",Integer.class,id)>=10)
    throw new ApiError(409,"Credential limit reached");
   user=UserIdentity.builder().name(a.username()).displayName(a.username()).id(new ByteArray(a.handle())).build();
  } else {
   String name=normalize(username);
   if(store.named(name).isPresent()) throw new ApiError(409,"Choose a different account name");
   id=UUID.randomUUID(); user=UserIdentity.builder().name(name).displayName(name).id(new ByteArray(Crypto.random(32))).build();
  }
  var options=rp.startRegistration(StartRegistrationOptions.builder().user(user)
   .authenticatorSelection(AuthenticatorSelectionCriteria.builder().residentKey(ResidentKeyRequirement.REQUIRED)
    .userVerification(UserVerificationRequirement.REQUIRED).build()).timeout(120000).build());
  UUID ceremony=challenges.issue(sessions.binding(req),"REGISTER",id,options.toJson());
  audit.event(id,"registration_start","success");
  return new Options(ceremony,json.readTree(options.toCredentialsCreateJson()));
 }
 @Transactional
 public Identity register(HttpServletRequest req,UUID ceremony,JsonNode credential,String label) throws Exception {
  var c=challenges.consume(ceremony,sessions.binding(req),"REGISTER");
  try {
   var options=PublicKeyCredentialCreationOptions.fromJson(c.payload());
   boolean exists=store.db.queryForObject("select count(*) from accounts where id=?",Integer.class,c.account())>0;
   if(exists) {
    UUID caller="RECOVERY".equals(req.getSession().getAttribute("level"))?sessions.require(req,"RECOVERY"):sessions.recent(req);
    if(!caller.equals(c.account())) throw ApiError.denied();
    store.account(c.account(),true);
   }
   var response=PublicKeyCredential.parseRegistrationResponseJson(credential.toString());
   var result=rp.finishRegistration(FinishRegistrationOptions.builder().request(options).response(response).build());
   if(!exists) store.db.update("insert into accounts(id,username,handle) values(?,?,?)",c.account(),options.getUser().getName(),options.getUser().getId().getBytes());
   if(store.db.queryForObject("select count(*) from credentials where account_id=?",Integer.class,c.account())>=10)
    throw new ApiError(409,"Credential limit reached");
   store.db.update("insert into credentials(id,account_id,public_key,signature_count,label,backup_eligible,backed_up) values(?,?,?,?,?,?,?)",
    result.getKeyId().getId().getBase64Url(),c.account(),result.getPublicKeyCose().getBytes(),result.getSignatureCount(),label,result.isBackupEligible(),result.isBackedUp());
   audit.event(c.account(),"registration_finish","success");
   return new Identity(c.account(),store.account(c.account(),false).secret()!=null);
  } catch(Exception e) { rejection(e); audit.event(c.account(),"registration_finish","failure"); throw ApiError.denied(); }
 }
 public Options authentication(HttpServletRequest req) throws Exception {
  var options=rp.startAssertion(StartAssertionOptions.builder().userVerification(UserVerificationRequirement.REQUIRED).timeout(120000).build());
  UUID id=challenges.issue(sessions.binding(req),"AUTHENTICATE",new UUID(0,0),options.toJson());
  return new Options(id,json.readTree(options.toCredentialsGetJson()));
 }
 @Transactional
 public Identity authenticate(HttpServletRequest req,UUID ceremony,JsonNode credential) throws Exception {
  var c=challenges.consume(ceremony,sessions.binding(req),"AUTHENTICATE");
  UUID owner=null;
  try {
   var response=PublicKeyCredential.parseAssertionResponseJson(credential.toString());
   owner=store.db.query("select account_id from credentials where id=?",(r,n)->r.getObject(1,UUID.class),response.getId().getBase64Url())
    .stream().findFirst().orElseThrow(ApiError::denied);
   var a=store.account(owner,true);
   store.db.queryForList("select id from credentials where id=? for update",response.getId().getBase64Url());
   var result=rp.finishAssertion(FinishAssertionOptions.builder().request(AssertionRequest.fromJson(c.payload())).response(response).build());
   if(!result.isSuccess() || !result.getUsername().equals(a.username())) throw ApiError.denied();
   store.db.update("update credentials set signature_count=?,backed_up=?,last_used_at=now() where id=? and account_id=?",
    result.getSignatureCount(),result.isBackedUp(),result.getCredentialId().getBase64Url(),owner);
   audit.event(owner,"passkey_authentication","success");
   return new Identity(owner,a.secret()!=null);
  } catch(Exception e) { rejection(e); audit.event(owner,"passkey_authentication","failure"); throw ApiError.denied(); }
 }
 static void rejection(Exception e) {
  // Deliberately exclude exception messages and response objects from logs.
  org.slf4j.LoggerFactory.getLogger(WebAuthnService.class).atDebug()
   .addKeyValue("exception_type",e.getClass().getName())
   .addKeyValue("location",e.getStackTrace().length==0?"unknown":e.getStackTrace()[0].toString())
   .log("WebAuthn operation rejected");
 }
 static String normalize(String input) {
  if(input==null || !input.matches("[A-Za-z0-9_]{3,64}")) throw new ApiError(400,"Use 3–64 letters, numbers or underscores");
  return input.toLowerCase(Locale.ROOT);
 }
}
