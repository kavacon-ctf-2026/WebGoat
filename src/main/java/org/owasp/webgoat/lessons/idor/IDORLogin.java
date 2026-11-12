/*
 * SPDX-FileCopyrightText: Copyright © 2014 WebGoat authors
 * SPDX-License-Identifier: GPL-2.0-or-later
 */
package org.owasp.webgoat.lessons.idor;

import static org.owasp.webgoat.container.assignments.AttackResultBuilder.failed;
import static org.owasp.webgoat.container.assignments.AttackResultBuilder.success;

import java.security.SecureRandom;
import java.util.Base64;
import java.util.Map;
import org.owasp.webgoat.container.assignments.AssignmentEndpoint;
import org.owasp.webgoat.container.assignments.AssignmentHints;
import org.owasp.webgoat.container.assignments.AttackResult;
import org.owasp.webgoat.container.session.LessonSession;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.ResponseBody;
import org.springframework.web.bind.annotation.RestController;

@RestController
@AssignmentHints({"idor.hints.idor_login"})
public class IDORLogin implements AssignmentEndpoint {
  private static final PasswordEncoder PASSWORD_ENCODER = new BCryptPasswordEncoder();

  // The demo account used to ship with a hard-coded, publicly known password. The password hash
  // now comes from deployment configuration; when none is configured, a random secret that nobody
  // knows is generated, so the account can no longer be logged into with a guessable default.
  private static final Map<String, DemoAccount> DEMO_ACCOUNTS =
      Map.of("tom", new DemoAccount(resolvePasswordHash(), "2342384"));

  private static String resolvePasswordHash() {
    String configured = System.getenv("WEBGOAT_IDOR_TOM_PASSWORD_HASH");
    if (configured != null && configured.startsWith("$2")) {
      return configured;
    }
    byte[] secret = new byte[32];
    new SecureRandom().nextBytes(secret);
    return PASSWORD_ENCODER.encode(Base64.getEncoder().encodeToString(secret));
  }

  private final LessonSession lessonSession;

  public IDORLogin(LessonSession lessonSession) {
    this.lessonSession = lessonSession;
  }

  @PostMapping("/IDOR/login")
  @ResponseBody
  public AttackResult completed(@RequestParam String username, @RequestParam String password) {
    // A failed re-authentication must not leave a previous lesson identity active.
    lessonSession.setValue("idor-authenticated-as", null);
    lessonSession.setValue("idor-authenticated-user-id", null);

    DemoAccount account = DEMO_ACCOUNTS.get(username);
    if (account != null
        && password != null
        && PASSWORD_ENCODER.matches(password, account.passwordHash())) {
      lessonSession.setValue("idor-authenticated-as", username);
      lessonSession.setValue("idor-authenticated-user-id", account.id());
      return success(this).feedback("idor.login.success").feedbackArgs(username).build();
    }
    return failed(this).feedback("idor.login.failure").build();
  }

  private record DemoAccount(String passwordHash, String id) {}
}
