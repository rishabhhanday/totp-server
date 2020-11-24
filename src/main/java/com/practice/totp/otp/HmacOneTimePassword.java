package com.practice.totp.otp;

import com.eatthepath.otp.HmacOneTimePasswordGenerator;
import java.security.NoSuchAlgorithmException;

public class HmacOneTimePassword extends HmacOneTimePasswordGenerator {

  public HmacOneTimePassword(int passwordLength, String algorithm) throws NoSuchAlgorithmException {
    super(passwordLength, algorithm);
  }
}
