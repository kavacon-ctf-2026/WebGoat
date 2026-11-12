/*
 * SPDX-FileCopyrightText: Copyright © 2017 WebGoat authors
 * SPDX-License-Identifier: GPL-2.0-or-later
 */
package org.owasp.webgoat.lessons.challenges.challenge7;

import static org.owasp.webgoat.container.assignments.AttackResultBuilder.informationMessage;
import static org.owasp.webgoat.container.assignments.AttackResultBuilder.success;

import java.time.Duration;
import java.time.Instant;
import java.time.LocalDateTime;
import java.util.Locale;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;
import lombok.extern.slf4j.Slf4j;
import org.owasp.webgoat.container.CurrentUsername;
import org.owasp.webgoat.container.assignments.AssignmentEndpoint;
import org.owasp.webgoat.container.assignments.AttackResult;
import org.owasp.webgoat.lessons.challenges.Email;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.util.StringUtils;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.ResponseBody;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.client.RestTemplate;

@RestController
@Slf4j
public class Assignment7 implements AssignmentEndpoint {

  private static final String RESET_EMAIL_DOMAIN = "@webgoat.org";
  private static final Duration RESET_TOKEN_LIFETIME = Duration.ofMinutes(15);
  private static final String RESET_LINK_TEMPLATE =
      "Hi, use this link to reset your password: %s/challenge/7/reset-password/%s\n\n"
          + "If you did not request this password change you can ignore this message.\n"
          + "Kind regards, Team WebGoat";
  private static final String GENERIC_RESPONSE =
      "If the address matches your account, a password reset link will be sent.";
  private static final Map<String, ResetToken> RESET_TOKENS = new ConcurrentHashMap<>();
  private static final Map<String, String> PASSWORD_HASHES = new ConcurrentHashMap<>();
  private static final PasswordEncoder PASSWORD_ENCODER = new BCryptPasswordEncoder();

  private final RestTemplate restTemplate;
  private final String webWolfMailURL;
  private final String webGoatURL;

  public Assignment7(
      RestTemplate restTemplate,
      @Value("${webwolf.mail.url}") String webWolfMailURL,
      @Value("${webgoat.url}") String webGoatURL) {
    this.restTemplate = restTemplate;
    this.webWolfMailURL = webWolfMailURL;
    this.webGoatURL = webGoatURL;
  }

  @GetMapping("/challenge/7/reset-password/{link}")
  public ResponseEntity<String> resetPassword(
      @PathVariable("link") String link, @CurrentUsername String username) {
    ResetToken token = validTokenFor(link, username);
    if (token == null) {
      return ResponseEntity.status(HttpStatus.BAD_REQUEST).body("Invalid or expired reset link.");
    }
    String form =
        "<!doctype html><html><body><p>Choose a new password for your account.</p>"
            + "<form method='post' action='"
            + webGoatURL
            + "/challenge/7/reset-password/"
            + link
            + "'><label>New password <input type='password' name='password' minlength='12'"
            + " maxlength='128' required autocomplete='new-password'></label>"
            + "<button type='submit'>Reset password</button></form></body></html>";
    return ResponseEntity.ok()
        .header("Content-Type", "text/html; charset=UTF-8")
        .body(form);
  }

  @PostMapping("/challenge/7/reset-password/{link}")
  public ResponseEntity<AttackResult> completeReset(
      @PathVariable("link") String link,
      @RequestParam(required = false) String password,
      @CurrentUsername String username) {
    ResetToken token = validTokenFor(link, username);
    if (token == null
        || !StringUtils.hasText(password)
        || password.length() < 12
        || password.length() > 128) {
      return ResponseEntity.status(HttpStatus.BAD_REQUEST).build();
    }
    if (!RESET_TOKENS.remove(link, token)) {
      return ResponseEntity.status(HttpStatus.BAD_REQUEST).build();
    }
    PASSWORD_HASHES.put(username, PASSWORD_ENCODER.encode(password));
    return ResponseEntity.ok(success(this).build());
  }

  @PostMapping("/challenge/7")
  @ResponseBody
  public AttackResult sendPasswordResetLink(
      @RequestParam(required = false) String email, @CurrentUsername String username) {
    if (username != null
        && !username.isBlank()
        && email != null
        && email.trim().equalsIgnoreCase(username + RESET_EMAIL_DOMAIN)) {
      RESET_TOKENS.entrySet().removeIf(entry -> !entry.getValue().expiresAt().isAfter(Instant.now()));
      String tokenValue = new PasswordResetLink().createPasswordReset(username, null);
      ResetToken resetToken =
          new ResetToken(username, Instant.now().plus(RESET_TOKEN_LIFETIME));
      RESET_TOKENS.put(tokenValue, resetToken);
      try {
        Email mail =
            Email.builder()
                .title("Your password reset link")
                .contents(String.format(RESET_LINK_TEMPLATE, webGoatURL, tokenValue))
                .sender("password-reset@webgoat-cloud.net")
                .recipient(username)
                .time(LocalDateTime.now())
                .build();
        restTemplate.postForEntity(webWolfMailURL, mail, Object.class);
      } catch (Exception e) {
        RESET_TOKENS.remove(tokenValue, resetToken);
        log.warn("Password reset email could not be delivered");
      }
    }
    return informationMessage(this).output(GENERIC_RESPONSE).build();
  }

  private ResetToken validTokenFor(String link, String username) {
    if (!StringUtils.hasText(username) || !StringUtils.hasText(link)) {
      return null;
    }
    if (!link.matches("[A-Za-z0-9_-]{43}")) {
      return null;
    }
    ResetToken token = RESET_TOKENS.get(link);
    if (token == null
        || !token.expiresAt().isAfter(Instant.now())
        || !token.username().equals(username)) {
      if (token != null && !token.expiresAt().isAfter(Instant.now())) {
        RESET_TOKENS.remove(link, token);
      }
      return null;
    }
    return token;
  }

  private record ResetToken(String username, Instant expiresAt) {}
}
