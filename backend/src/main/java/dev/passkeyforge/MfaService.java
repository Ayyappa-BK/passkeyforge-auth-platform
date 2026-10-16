package dev.passkeyforge;
import java.util.*;
import java.time.*;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import dev.samstevens.totp.code.*;
import dev.samstevens.totp.secret.DefaultSecretGenerator;
import com.google.zxing.*;
import com.google.zxing.qrcode.QRCodeWriter;
import com.google.zxing.client.j2se.MatrixToImageWriter;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;
@Service
public class MfaService {
 final Store store; final Crypto crypto; final Audit audit;
 public MfaService(Store store,Crypto crypto,Audit audit) { this.store=store; this.crypto=crypto; this.audit=audit; }
 record Enrollment(String uri,String qrDataUrl) {}
 @Transactional
 public Enrollment enroll(UUID id) throws Exception {
  var a=store.account(id,true);
  if(a.secret()!=null) throw new ApiError(409,"TOTP is already enrolled");
  String secret=new DefaultSecretGenerator(32).generate();
  store.jdbc().update("update accounts set pending_totp=?,pending_until=now()+interval '5 minutes' where id=?",crypto.encrypt(id,secret),id);
  String uri="otpauth://totp/PasskeyForge:"+a.username()+"?secret="+secret+"&issuer=PasskeyForge&algorithm=SHA1&digits=6&period=30";
  var matrix=new QRCodeWriter().encode(uri,BarcodeFormat.QR_CODE,320,320);
  var bytes=new java.io.ByteArrayOutputStream(); MatrixToImageWriter.writeToStream(matrix,"PNG",bytes);
  audit.event(id,"totp_enrollment_start","success");
  return new Enrollment(uri,"data:image/png;base64,"+Base64.getEncoder().encodeToString(bytes.toByteArray()));
 }
 @Transactional
 public List<String> confirm(UUID id,String code) {
  var a=store.account(id,true);
  if(a.pending()==null || a.pendingUntil()==null || !a.pendingUntil().isAfter(Instant.now()) || a.secret()!=null) throw ApiError.denied();
  long step=match(crypto.decrypt(id,a.pending()),code,-1,Instant.now());
  if(step<0) { audit.event(id,"totp_enrollment_finish","failure"); throw ApiError.denied(); }
  store.jdbc().update("update accounts set totp_secret=pending_totp,pending_totp=null,pending_until=null,totp_step=? where id=?",step,id);
  List<String> codes=rotateInternal(id);
  audit.event(id,"totp_enrollment_finish","success"); return codes;
 }
 @Transactional
 public void verify(UUID id,String code) {
  var a=store.account(id,true);
  long step=a.secret()==null?-1:match(crypto.decrypt(id,a.secret()),code,a.step(),Instant.now());
  if(step<0) { audit.event(id,"totp_verification","failure"); throw ApiError.denied(); }
  store.jdbc().update("update accounts set totp_step=? where id=?",step,id);
  audit.event(id,"totp_verification","success");
 }
 // Protocol calculation comes from java-totp; account lock + persisted timestep enforces one-time use.
 static long match(String secret,String code,long last,Instant now) {
  if(code==null || !code.matches("[0-9]{6}")) return -1;
  long current=now.getEpochSecond()/30,matched=-1;
  for(long step=current-1;step<=current+1;step++) {
   try {
    String actual=new DefaultCodeGenerator(HashingAlgorithm.SHA1,6).generate(secret,step);
    boolean equal=MessageDigest.isEqual(actual.getBytes(StandardCharsets.US_ASCII),code.getBytes(StandardCharsets.US_ASCII));
    if(equal && step>last) matched=step;
   } catch(Exception e) { throw new IllegalStateException(e); }
  }
  return matched;
 }
 @Transactional
 public List<String> rotate(UUID id) { store.account(id,true); var result=rotateInternal(id); audit.event(id,"recovery_rotation","success"); return result; }
 private List<String> rotateInternal(UUID id) {
  store.jdbc().update("delete from recovery_codes where account_id=?",id);
  var codes=new ArrayList<String>();
  for(int i=0;i<10;i++) {
   String code=Base64.getUrlEncoder().withoutPadding().encodeToString(Crypto.random(20)); codes.add(code);
   store.jdbc().update("insert into recovery_codes values(?,?)",id,Crypto.digest(id+":"+code));
  } return codes;
 }
 @Transactional
 public void redeem(UUID id,String code) {
  store.account(id,true);
  int deleted=store.jdbc().update("delete from recovery_codes where account_id=? and digest=?",id,Crypto.digest(id+":"+code));
  audit.event(id,"recovery_redemption",deleted==1?"success":"failure");
  if(deleted!=1) throw ApiError.denied();
 }
 @Transactional
 public void disable(UUID id,String code) {
  // Invokes verification in this same transaction; locked row prevents concurrent OTP reuse.
  verify(id,code);
  store.jdbc().update("update accounts set totp_secret=null,totp_step=-1,pending_totp=null,pending_until=null where id=?",id);
  audit.event(id,"totp_disabled","success");
 }
}
