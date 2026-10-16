package dev.passkeyforge;
import java.util.*;
import java.security.*;
import java.security.interfaces.ECPublicKey;
import java.nio.*;
import java.nio.charset.StandardCharsets;
import com.fasterxml.jackson.databind.*;
import com.fasterxml.jackson.dataformat.cbor.CBORFactory;
// Test-only authenticator: real P-256 COSE public key, CBOR attestation and ES256 signatures.
final class VirtualAuthenticator {
 final KeyPair key; final byte[] id=Crypto.random(32); byte[] handle; int counter=0;
 final ObjectMapper json=new ObjectMapper();
 VirtualAuthenticator() throws Exception {
  var gen=KeyPairGenerator.getInstance("EC"); gen.initialize(new java.security.spec.ECGenParameterSpec("secp256r1")); key=gen.generateKeyPair();
 }
 static String b64(byte[] b) { return Base64.getUrlEncoder().withoutPadding().encodeToString(b); }
 static byte[] sha(byte[] b) throws Exception { return MessageDigest.getInstance("SHA-256").digest(b); }
 byte[] client(JsonNode options,String type,String origin,String challenge) throws Exception {
  return json.writeValueAsBytes(Map.of("type",type,"challenge",challenge==null?options.at("/options/publicKey/challenge").asText():challenge,"origin",origin,"crossOrigin",false));
 }
 byte[] authData(String rp,int flags,int count) throws Exception {
  return ByteBuffer.allocate(37).put(sha(rp.getBytes(StandardCharsets.UTF_8))).put((byte)flags).putInt(count).array();
 }
 JsonNode registration(JsonNode options) throws Exception { return registration(options,"http://localhost:8080","localhost",0x45,null); }
 JsonNode registration(JsonNode options,String origin,String rp,int flags,String challenge) throws Exception {
  handle=Base64.getUrlDecoder().decode(options.at("/options/publicKey/user/id").asText());
  ECPublicKey pub=(ECPublicKey)key.getPublic();
  Map<Integer,Object> cose=new LinkedHashMap<>(); cose.put(1,2); cose.put(3,-7); cose.put(-1,1);
  cose.put(-2,unsigned(pub.getW().getAffineX())); cose.put(-3,unsigned(pub.getW().getAffineY()));
  byte[] encoded=new ObjectMapper(new CBORFactory()).writeValueAsBytes(cose);
  byte[] data=ByteBuffer.allocate(37+16+2+id.length+encoded.length).put(authData(rp,flags,0)).put(new byte[16]).putShort((short)id.length).put(id).put(encoded).array();
  byte[] attestation=new ObjectMapper(new CBORFactory()).writeValueAsBytes(Map.of("fmt","none","authData",data,"attStmt",Map.of()));
  return json.valueToTree(Map.of("id",b64(id),"rawId",b64(id),"type","public-key","response",Map.of(
   "clientDataJSON",b64(client(options,"webauthn.create",origin,challenge)),"attestationObject",b64(attestation),"transports",List.of("internal")),"clientExtensionResults",Map.of("credProps",Map.of("rk",true))));
 }
 JsonNode assertion(JsonNode options) throws Exception { return assertion(options,"http://localhost:8080","localhost",5,null,false); }
 JsonNode assertion(JsonNode options,String origin,String rp,int flags,String challenge,boolean badSignature) throws Exception {
  byte[] client=client(options,"webauthn.get",origin,challenge), data=authData(rp,flags,++counter);
  Signature signature=Signature.getInstance("SHA256withECDSA"); signature.initSign(key.getPrivate()); signature.update(data); signature.update(sha(client));
  byte[] signed=signature.sign(); if(badSignature) signed[signed.length-1]^=1;
  return json.valueToTree(Map.of("id",b64(id),"rawId",b64(id),"type","public-key","response",Map.of(
   "clientDataJSON",b64(client),"authenticatorData",b64(data),"signature",b64(signed),"userHandle",b64(handle)),"clientExtensionResults",Map.of()));
 }
 static byte[] unsigned(java.math.BigInteger n) { byte[] b=n.toByteArray(),out=new byte[32]; System.arraycopy(b,Math.max(0,b.length-32),out,Math.max(0,32-b.length),Math.min(32,b.length)); return out; }
}
