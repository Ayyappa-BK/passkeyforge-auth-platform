package dev.passkeyforge;
import java.nio.charset.StandardCharsets;
import java.security.*;
import java.util.*;
import javax.crypto.*;
import javax.crypto.spec.*;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Component;
@Component
public class Crypto {
 private static final SecureRandom RNG=new SecureRandom();
 private final SecretKeySpec key;
 public Crypto(@Value("${forge.encryption-key}") String encoded) {
  byte[] bytes=Base64.getDecoder().decode(encoded);
  if(bytes.length!=32) throw new IllegalArgumentException("TOTP_ENCRYPTION_KEY must be a base64 256-bit key");
  key=new SecretKeySpec(bytes,"AES");
 }
 public static byte[] random(int n) { byte[] b=new byte[n]; RNG.nextBytes(b); return b; }
 public static String token() { return Base64.getUrlEncoder().withoutPadding().encodeToString(random(32)); }
 public static String digest(String s) {
  try { return HexFormat.of().formatHex(MessageDigest.getInstance("SHA-256").digest(s.getBytes(StandardCharsets.UTF_8))); }
  catch(GeneralSecurityException e) { throw new IllegalStateException(e); }
 }
 public String encrypt(UUID owner,String secret) {
  try {
   byte[] nonce=random(12); Cipher c=Cipher.getInstance("AES/GCM/NoPadding");
   c.init(Cipher.ENCRYPT_MODE,key,new GCMParameterSpec(128,nonce)); c.updateAAD(owner.toString().getBytes(StandardCharsets.UTF_8));
   return "v1."+Base64.getEncoder().encodeToString(nonce)+"."+Base64.getEncoder().encodeToString(c.doFinal(secret.getBytes(StandardCharsets.UTF_8)));
  } catch(GeneralSecurityException e) { throw new IllegalStateException(e); }
 }
 public String decrypt(UUID owner,String envelope) {
  try {
   String[] p=envelope.split("\\.");
   if(p.length!=3 || !p[0].equals("v1")) throw new IllegalArgumentException("Invalid ciphertext version");
   Cipher c=Cipher.getInstance("AES/GCM/NoPadding");
   c.init(Cipher.DECRYPT_MODE,key,new GCMParameterSpec(128,Base64.getDecoder().decode(p[1])));
   c.updateAAD(owner.toString().getBytes(StandardCharsets.UTF_8));
   return new String(c.doFinal(Base64.getDecoder().decode(p[2])),StandardCharsets.UTF_8);
  } catch(GeneralSecurityException e) { throw new IllegalStateException("Unable to decrypt credential",e); }
 }
}
