/*
 * SPDX-FileCopyrightText: Copyright © 2018 WebGoat authors
 * SPDX-License-Identifier: GPL-2.0-or-later
 */
package org.owasp.webgoat.lessons.passwordreset;

import static org.owasp.webgoat.container.assignments.AttackResultBuilder.failed;
import static org.owasp.webgoat.container.assignments.AttackResultBuilder.informationMessage;
import static org.owasp.webgoat.container.assignments.AttackResultBuilder.success;

import java.security.SecureRandom;
import java.time.Duration;
import java.time.Instant;
import java.time.LocalDateTime;
import java.util.Base64;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;
import org.owasp.webgoat.container.CurrentUsername;
import org.owasp.webgoat.container.assignments.AssignmentEndpoint;
import org.owasp.webgoat.container.assignments.AttackResult;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.util.StringUtils;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.ResponseBody;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.client.RestClientException;
import org.springframework.web.client.RestTemplate;

@RestController
public class SimpleMailAssignment implements AssignmentEndpoint {

  private static final String EMAIL_DOMAIN = "@webgoat.org";
  private static final String GENERIC_RESPONSE =
      "If the address matches your account, a password reset link will be sent.";
  private static final Duration TOKEN_LIFETIME = Duration.ofMinutes(15);
  private static final SecureRandom SECURE_RANDOM = new SecureRandom();
  private static final Map<String, ResetToken> RESET_TOKENS = new ConcurrentHashMap<>();
  private static final Map<String, String> PASSWORD_HASHES = new ConcurrentHashMap<>();
  private static final PasswordEncoder PASSWORD_ENCODER = new BCryptPasswordEncoder();

  private final String webWolfURL;
  private final String webGoatURL;
  private final RestTemplate restTemplate;

  public SimpleMailAssignment(
      RestTemplate restTemplate,
      @Value("${webwolf.mail.url}") String webWolfURL,
      @Value("${webgoat.url}") String webGoatURL) {
    this.restTemplate = restTemplate;
    this.webWolfURL = webWolfURL;
    this.webGoatURL = webGoatURL;
  }

  @PostMapping(
      path = "/PasswordReset/simple-mail",
      consumes = MediaType.APPLICATION_FORM_URLENCODED_VALUE)
  @ResponseBody
  public AttackResult login(
      @RequestParam String email,
      @RequestParam String password,
      @CurrentUsername String webGoatUsername) {
    String passwordHash =
        StringUtils.hasText(webGoatUsername) ? PASSWORD_HASHES.get(webGoatUsername) : null;
    if (isOwnEmail(email, webGoatUsername)
        && passwordHash != null
        && password != null
        && PASSWORD_ENCODER.matches(password, passwordHash)) {
      return success(this).build();
    }
    return failed(this).feedback("password-reset-simple.password_incorrect").build();
  }

  @PostMapping(
      consumes = MediaType.APPLICATION_FORM_URLENCODED_VALUE,
      value = "/PasswordReset/simple-mail/reset")
  @ResponseBody
  public AttackResult resetPassword(
      @RequestParam(required = false) String emailReset,
      @CurrentUsername String username) {
    if (isOwnEmail(emailReset, username)) {
      String tokenValue = newResetToken();
      ResetToken token = new ResetToken(username, Instant.now().plus(TOKEN_LIFETIME));
      RESET_TOKENS.put(tokenValue, token);
      try {
        sendResetEmail(username, tokenValue);
      } catch (RestClientException e) {
        RESET_TOKENS.remove(tokenValue, token);
      }
    }
    return informationMessage(this).output(GENERIC_RESPONSE).build();
  }

  @GetMapping("/PasswordReset/simple-mail/reset/complete")
  public ResponseEntity<String> showResetForm(
      @RequestParam String token, @CurrentUsername String username) {
    if (validTokenFor(token, username) == null) {
      return ResponseEntity.status(HttpStatus.BAD_REQUEST).body("Invalid or expired reset link.");
    }
    String form =
        "<!doctype html><html><body><form method='post' action='"
            + webGoatURL
            + "/PasswordReset/simple-mail/reset/complete?token="
            + token
            + "'><label>New password <input type='password' name='password' minlength='12'"
            + " maxlength='128' required autocomplete='new-password'></label>"
            + "<button type='submit'>Reset password</button></form></body></html>";
    return ResponseEntity.ok()
        .contentType(MediaType.TEXT_HTML)
        .body(form);
  }

  @PostMapping(
      path = "/PasswordReset/simple-mail/reset/complete",
      consumes = MediaType.APPLICATION_FORM_URLENCODED_VALUE)
  @ResponseBody
  public AttackResult completeReset(
      @RequestParam String token,
      @RequestParam(required = false) String password,
      @CurrentUsername String username) {
    ResetToken resetToken = validTokenFor(token, username);
    if (resetToken == null
        || !StringUtils.hasText(password)
        || password.length() < 12
        || password.length() > 128
        || !RESET_TOKENS.remove(token, resetToken)) {
      return failed(this).output("Invalid or expired reset link.").build();
    }
    PASSWORD_HASHES.put(username, PASSWORD_ENCODER.encode(password));
    return success(this).build();
  }

  private boolean isOwnEmail(String email, String username) {
    return email != null
        && StringUtils.hasText(username)
        && email.trim().equalsIgnoreCase(username + EMAIL_DOMAIN);
  }

  private String newResetToken() {
    byte[] token = new byte[32];
    SECURE_RANDOM.nextBytes(token);
    return Base64.getUrlEncoder().withoutPadding().encodeToString(token);
  }

  private ResetToken validTokenFor(String token, String username) {
    if (token == null || !StringUtils.hasText(username) || !token.matches("[A-Za-z0-9_-]{43}")) {
      return null;
    }
    ResetToken resetToken = RESET_TOKENS.get(token);
    if (resetToken == null
        || !resetToken.expiresAt().isAfter(Instant.now())
        || !resetToken.username().equals(username)) {
      if (resetToken != null && !resetToken.expiresAt().isAfter(Instant.now())) {
        RESET_TOKENS.remove(token, resetToken);
      }
      return null;
    }
    return resetToken;
  }

  private void sendResetEmail(String username, String token) {
    PasswordResetEmail email =
        PasswordResetEmail.builder()
            .recipient(username)
            .title("Password reset instructions")
            .time(LocalDateTime.now())
            .contents(
                "Use this one-time link to choose a new password: <a href=\""
                    + webGoatURL
                    + "/PasswordReset/simple-mail/reset/complete?token="
                    + token
                    + "\">Reset password</a>")
            .sender("webgoat@owasp.org")
            .build();
    restTemplate.postForEntity(webWolfURL, email, Object.class);
  }

  private record ResetToken(String username, Instant expiresAt) {}
}
