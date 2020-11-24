package com.practice.totp.service;

import com.practice.totp.model.OTPResponse;
import com.practice.totp.otp.HmacOneTimePassword;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
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
        .otp(genrateHOTP(algorithm, passwordLength, counter, key))
        .build();
  }

  private Long genrateHOTP(
      String algorithm,
      Integer passwordLength,
      long counter,
      SecretKeySpec key) throws NoSuchAlgorithmException, InvalidKeyException {
    HmacOneTimePassword hotp = new HmacOneTimePassword(passwordLength, algorithm);

    return (long) hotp.generateOneTimePassword(key, counter);
  }
}
