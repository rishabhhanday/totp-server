package com.practice.totp.totp.service;

import com.eatthepath.otp.TimeBasedOneTimePasswordGenerator;
import com.practice.totp.totp.model.OTPResponse;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.time.Duration;
import javax.crypto.spec.SecretKeySpec;
import org.apache.tomcat.util.buf.HexUtils;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;

@Service
public class TOTPService {

  private final String hexKey;

  public TOTPService(@Value("${otp.key}") String hexKey) {
    this.hexKey = hexKey;
  }

  public OTPResponse generateTOTP(
      String algorithm,
      Integer passwordLength,
      Long startTime,
      Integer timeStep,
      Long currentTime) throws NoSuchAlgorithmException, InvalidKeyException {
    final SecretKeySpec key = new SecretKeySpec(HexUtils.fromHexString(hexKey), algorithm);

    long counter = (currentTime / 1000 - startTime / 1000) / timeStep;

    return OTPResponse.builder()
        .exp(((counter + 1) * timeStep * 1000) + startTime)
        .otp(genrateOTP(algorithm, passwordLength, timeStep, counter, key))
        .build();
  }

  private Long genrateOTP(String algorithm, Integer passwordLength, Integer timeStep, long counter,
      SecretKeySpec key) throws NoSuchAlgorithmException, InvalidKeyException {
    TimeBasedOneTimePasswordGenerator totp = new TimeBasedOneTimePasswordGenerator(
        Duration.ofSeconds(timeStep),
        passwordLength,
        algorithm
    );

    return (long) totp.generateOneTimePassword(key, counter);
  }
}
