package com.practice.totp.totp.controller;

import com.eatthepath.otp.TimeBasedOneTimePasswordGenerator;
import java.security.InvalidKeyException;
import java.security.Key;
import java.security.NoSuchAlgorithmException;
import java.time.Duration;
import java.time.Instant;
import java.util.HashMap;
import java.util.Map;
import javax.crypto.KeyGenerator;
import org.springframework.web.bind.annotation.CrossOrigin;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
public class OTPControllerRef {

  final TimeBasedOneTimePasswordGenerator totp;
  Key key;

  public OTPControllerRef() throws NoSuchAlgorithmException {
    this.totp = new TimeBasedOneTimePasswordGenerator(
        Duration.ofSeconds(30));
    final KeyGenerator keyGenerator = KeyGenerator.getInstance("HmacSHA1");

    keyGenerator.init(160);
    this.key = keyGenerator.generateKey();
  }


  @GetMapping("/totp")
  @CrossOrigin("*")
  public Map<String, String> getTOTP() throws InvalidKeyException {
    Instant currentTime = Instant.now();

    int otp = totp.generateOneTimePassword(key, currentTime);
    long expiry = ((currentTime.toEpochMilli() / Duration.ofSeconds(30).toMillis()) + 1) * Duration
        .ofSeconds(30).toMillis();

    System.out.println("token will expirt in " + (expiry - Instant.now().toEpochMilli()) / 1000);

    Map<String, String> response = new HashMap<>();
    response.put("otp", otp + "");
    response.put("exp", expiry + "");

    return response;
  }
}
