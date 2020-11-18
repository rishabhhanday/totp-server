package com.practice.totp.totp;

import com.eatthepath.otp.TimeBasedOneTimePasswordGenerator;
import java.security.InvalidKeyException;
import java.security.Key;
import java.security.NoSuchAlgorithmException;
import java.time.Duration;
import java.time.Instant;
import javax.crypto.KeyGenerator;
import javax.crypto.spec.SecretKeySpec;
import org.apache.tomcat.util.buf.HexUtils;
import org.junit.jupiter.api.Test;

class TotpTest {

  @Test
  void testTotp() throws NoSuchAlgorithmException, InvalidKeyException {
    final TimeBasedOneTimePasswordGenerator totp = new TimeBasedOneTimePasswordGenerator(
        Duration.ofSeconds(10));

    final KeyGenerator keyGenerator = KeyGenerator.getInstance(totp.getAlgorithm());

    keyGenerator.init(160);

    Key key = keyGenerator.generateKey();
    Instant startTime = Instant.ofEpochMilli(0);
    long initialTime = Instant.now().toEpochMilli();
    int current = totp.generateOneTimePassword(new SecretKeySpec(HexUtils.fromHexString(""),"HmacSHA512"), startTime);

    System.out.println("current time --- " + Instant.now() + " , otp is ---" + current);
    while (true) {
      int next = totp.generateOneTimePassword(key,
          startTime.plusMillis(Instant.now().toEpochMilli() - initialTime));

      if (current != next) {
        current = next;
        System.out.println("totp changed at --- " + Instant.now());
      }
    }
  }

  @Test
  void testCustomTOTP() throws NoSuchAlgorithmException, InvalidKeyException {
    final TimeBasedOneTimePasswordGenerator totp = new TimeBasedOneTimePasswordGenerator(Duration.ofSeconds(10));

    final KeyGenerator keyGenerator = KeyGenerator.getInstance(totp.getAlgorithm());

    keyGenerator.init(160);

    Key key = keyGenerator.generateKey();
    Instant currentTime = Instant.now();

    int current = totp.generateOneTimePassword(key, currentTime);
    System.out.println("current time --- " + currentTime + " , otp is ---" + current);

    long expiry = ((currentTime.toEpochMilli() / Duration.ofSeconds(10).toMillis()) + 1) * Duration
        .ofSeconds(10).toMillis();

    System.out.println("next time will be " + Instant.ofEpochMilli(expiry));
    while (true) {
      int next = totp.generateOneTimePassword(key, Instant.now());
      if (current != next) {
        current = next;
        System.out.println("totp changed at --- " + Instant.now());
      }
    }
  }

  @Test
  void testTimeStep() {
    long timeStep = Duration.ofSeconds(30).toMillis();
    long currentTime = Instant.now().toEpochMilli();
    System.out.println("current time --- "+Instant.ofEpochMilli(currentTime));

    long counter = currentTime / timeStep;
    System.out.println("counter --- " + counter);

    Instant expiryAt = Instant.ofEpochMilli(currentTime + timeStep);
    System.out.println(expiryAt + "should be equals to " + Instant.ofEpochMilli((counter + 1) * timeStep));
  }
}

// things are converted to seconds for more precision .
