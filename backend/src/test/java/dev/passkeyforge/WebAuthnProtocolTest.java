package dev.passkeyforge;
import com.yubico.webauthn.*;
import com.yubico.webauthn.data.*;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.junit.jupiter.api.Test;
import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.Mockito.*;
import java.util.*;
class WebAuthnProtocolTest {
 @Test void validatesRealCborRegistrationAndSignature() throws Exception {
  var repo=mock(CredentialRepository.class);
  var rp=RelyingParty.builder().identity(RelyingPartyIdentity.builder().id("localhost").name("Test").build()).credentialRepository(repo).origins(Set.of("http://localhost:8080")).build();
  var handle=new ByteArray(Crypto.random(32));
  var options=rp.startRegistration(StartRegistrationOptions.builder().user(UserIdentity.builder().name("alice").displayName("alice").id(handle).build())
   .authenticatorSelection(AuthenticatorSelectionCriteria.builder().residentKey(ResidentKeyRequirement.REQUIRED).userVerification(UserVerificationRequirement.REQUIRED).build()).build());
  var json=new ObjectMapper();var envelope=json.createObjectNode();envelope.set("options",json.readTree(options.toCredentialsCreateJson()));
  var auth=new VirtualAuthenticator();
  var result=rp.finishRegistration(FinishRegistrationOptions.builder().request(PublicKeyCredentialCreationOptions.fromJson(options.toJson())).response(PublicKeyCredential.parseRegistrationResponseJson(auth.registration(envelope).toString())).build());
  assertTrue(result.isUserVerified());
  var stored=RegisteredCredential.builder().credentialId(result.getKeyId().getId()).userHandle(handle).publicKeyCose(result.getPublicKeyCose()).signatureCount(0).backupEligible(false).backupState(false).build();
  when(repo.lookupAll(result.getKeyId().getId())).thenReturn(Set.of(stored));
  when(repo.lookup(result.getKeyId().getId(),handle)).thenReturn(Optional.of(stored));
  when(repo.getUsernameForUserHandle(handle)).thenReturn(Optional.of("alice"));
  when(repo.getUserHandleForUsername("alice")).thenReturn(Optional.of(handle));
  var request=rp.startAssertion(StartAssertionOptions.builder().userVerification(UserVerificationRequirement.REQUIRED).build());
  envelope.set("options",json.readTree(request.toCredentialsGetJson()));
  var assertion=rp.finishAssertion(FinishAssertionOptions.builder().request(request).response(PublicKeyCredential.parseAssertionResponseJson(auth.assertion(envelope).toString())).build());
  assertTrue(assertion.isSuccess());
 }
}
