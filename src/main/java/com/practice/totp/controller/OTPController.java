package com.practice.totp.controller;

import com.practice.totp.model.OTPResponse;
import com.practice.totp.service.TOTPService;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.time.Instant;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.ResponseEntity;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;

@Controller
@RequestMapping(value = "/otp")
@Slf4j
public class OTPController {

  @Autowired
  TOTPService totpService;

  @GetMapping("/totp")
  ResponseEntity<OTPResponse> generateTOTP(
      @RequestParam(required = false, defaultValue = "HmacSHA512", name = "algorithm") String algorithm,
      @RequestParam(required = false, defaultValue = "6", name = "passwordLength") Integer passwordLength,
      @RequestParam(required = false, defaultValue = "0", name = "startTime") Long startTime,
      @RequestParam(required = false, defaultValue = "30", name = "timeStep") Integer timeStep)
      throws InvalidKeyException, NoSuchAlgorithmException {

    log.info("algo={} , passwordLength={}, startTime={}, timeStep={}", algorithm, passwordLength,
        startTime, timeStep);

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
