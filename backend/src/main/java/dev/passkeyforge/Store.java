package dev.passkeyforge;
import com.yubico.webauthn.*;
import com.yubico.webauthn.data.*;
import java.util.*;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.stereotype.Repository;
@Repository
public class Store implements CredentialRepository {
 final JdbcTemplate db;
 public Store(JdbcTemplate db) { this.db=db; }
 public JdbcTemplate jdbc() { return db; }
 record Account(UUID id,String username,byte[] handle,String secret,String pending,java.time.Instant pendingUntil,long step) {}
 Account account(UUID id,boolean lock) {
  return db.query("select * from accounts where id=?"+(lock?" for update":""),(r,n)->new Account(
   r.getObject("id",UUID.class),r.getString("username"),r.getBytes("handle"),r.getString("totp_secret"),
   r.getString("pending_totp"),r.getTimestamp("pending_until")==null?null:r.getTimestamp("pending_until").toInstant(),r.getLong("totp_step")),id)
   .stream().findFirst().orElseThrow(ApiError::denied);
 }
 Optional<Account> named(String username) {
  return db.query("select id from accounts where username=?",(r,n)->r.getObject(1,UUID.class),username).stream().findFirst().map(id->account(id,false));
 }
 @Override public Set<PublicKeyCredentialDescriptor> getCredentialIdsForUsername(String username) {
  return new HashSet<>(db.query("select c.id from credentials c join accounts a on a.id=c.account_id where a.username=?",
   (r,n)->PublicKeyCredentialDescriptor.builder().id(new ByteArray(Base64.getUrlDecoder().decode(r.getString(1)))).build(),username));
 }
 @Override public Optional<ByteArray> getUserHandleForUsername(String username) { return named(username).map(a->new ByteArray(a.handle)); }
 @Override public Optional<String> getUsernameForUserHandle(ByteArray handle) {
  return db.query("select username from accounts where handle=?",(r,n)->r.getString(1),handle.getBytes()).stream().findFirst();
 }
 @Override public Optional<RegisteredCredential> lookup(ByteArray credentialId,ByteArray userHandle) {
  return lookupAll(credentialId).stream().filter(c->c.getUserHandle().equals(userHandle)).findFirst();
 }
 @Override public Set<RegisteredCredential> lookupAll(ByteArray credentialId) {
  return new HashSet<>(db.query("select c.*,a.handle from credentials c join accounts a on a.id=c.account_id where c.id=?",
   (r,n)->RegisteredCredential.builder().credentialId(credentialId).userHandle(new ByteArray(r.getBytes("handle")))
    .publicKeyCose(new ByteArray(r.getBytes("public_key"))).signatureCount(r.getLong("signature_count"))
    .backupEligible(r.getBoolean("backup_eligible")).backupState(r.getBoolean("backed_up")).build(),credentialId.getBase64Url()));
 }
}
