package com.practice.totp.totp.controller;

import com.practice.totp.totp.model.OTPResponse;
import com.practice.totp.totp.service.TOTPService;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.time.Instant;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.CrossOrigin;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping("/otp")
public class OTPController {

  @Autowired
  TOTPService totpService;

  @GetMapping("/totp")
  @CrossOrigin("*")
  ResponseEntity<OTPResponse> generateTOTP(
      @RequestParam(required = false, defaultValue = "HmacSHA512") String algorithm,
      @RequestParam(required = false, defaultValue = "6") Integer passwordLength,
      @RequestParam(required = false, defaultValue = "0") Long startTime,
      @RequestParam(required = false, defaultValue = "30") Integer timeStep)
      throws InvalidKeyException, NoSuchAlgorithmException {

    final OTPResponse otpResponse = totpService.generateTOTP(
        algorithm,
        passwordLength,
        startTime,
        timeStep,
        Instant.now().toEpochMilli()
    );

    return ResponseEntity.ok(otpResponse);
  }
}
