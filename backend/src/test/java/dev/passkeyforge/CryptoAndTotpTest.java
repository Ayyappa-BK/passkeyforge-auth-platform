package dev.passkeyforge;

import static org.junit.jupiter.api.Assertions.*;

import dev.samstevens.totp.code.*;
import java.time.Instant;
import java.util.*;
import org.junit.jupiter.api.Test;

class CryptoAndTotpTest {
  @Test
  void encryptedEnvelopesHaveUniqueNoncesAndBindOwner() {
    Crypto crypto = new Crypto(Base64.getEncoder().encodeToString(Crypto.random(32)));
    UUID owner = UUID.randomUUID();
    String encrypted = crypto.encrypt(owner, "secret");
    assertEquals("secret", crypto.decrypt(owner, encrypted));
    assertFalse(encrypted.contains("secret"));
    assertNotEquals(encrypted, crypto.encrypt(owner, "secret"));
    assertThrows(IllegalStateException.class, () -> crypto.decrypt(UUID.randomUUID(), encrypted));
    assertThrows(
        IllegalStateException.class,
        () ->
            new Crypto(Base64.getEncoder().encodeToString(Crypto.random(32)))
                .decrypt(owner, encrypted));
  }

  @Test
  void rfc6238Sha1EightDigitVectors() throws Exception {
    var generator = new DefaultCodeGenerator(HashingAlgorithm.SHA1, 8);
    String secret = "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ";
    long[] times = {59, 1111111109, 1111111111, 1234567890, 2000000000, 20000000000L};
    String[] expected = {"94287082", "07081804", "14050471", "89005924", "69279037", "65353130"};
    for (int i = 0; i < times.length; i++)
      assertEquals(expected[i], generator.generate(secret, times[i] / 30));
  }

  @Test
  void acceptsWindowAndRejectsReuseMalformedAndOldOtp() throws Exception {
    String secret = "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ";
    Instant now = Instant.ofEpochSecond(1234567890);
    long current = now.getEpochSecond() / 30;
    String code = new DefaultCodeGenerator().generate(secret, current);
    assertEquals(current, MfaService.match(secret, code, -1, now));
    assertEquals(-1, MfaService.match(secret, code, current, now));
    assertEquals(-1, MfaService.match(secret, "abc123", -1, now));
    assertEquals(-1, MfaService.match(secret, code, -1, now.plusSeconds(90)));
  }
}
