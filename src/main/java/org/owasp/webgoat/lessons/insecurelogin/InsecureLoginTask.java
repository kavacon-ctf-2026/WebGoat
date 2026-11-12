/*
 * SPDX-FileCopyrightText: Copyright © 2014 WebGoat authors
 * SPDX-License-Identifier: GPL-2.0-or-later
 */
package org.owasp.webgoat.lessons.insecurelogin;

import static org.owasp.webgoat.container.assignments.AttackResultBuilder.failed;
import static org.owasp.webgoat.container.assignments.AttackResultBuilder.informationMessage;
import static org.owasp.webgoat.container.assignments.AttackResultBuilder.success;

import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;
import org.owasp.webgoat.container.CurrentUsername;
import org.owasp.webgoat.container.assignments.AssignmentEndpoint;
import org.owasp.webgoat.container.assignments.AttackResult;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.ResponseBody;
import org.springframework.web.bind.annotation.RestController;

@RestController
public class InsecureLoginTask implements AssignmentEndpoint {

  private static final int MAX_PASSWORD_LENGTH = 128;
  private final PasswordEncoder passwordEncoder = new BCryptPasswordEncoder();
  private final Map<String, String> passwordHashes = new ConcurrentHashMap<>();

  @PostMapping("/InsecureLogin/register")
  @ResponseBody
  public AttackResult registerPassword(
      @RequestParam String password,
      @RequestParam String confirmation,
      @CurrentUsername String username) {
    if (username == null
        || username.isBlank()
        || password == null
        || password.length() < 12
        || password.length() > MAX_PASSWORD_LENGTH
        || !password.equals(confirmation)) {
      return failed(this).build();
    }

    passwordHashes.put(username, passwordEncoder.encode(password));
    return informationMessage(this)
        .output("Password stored. Submit it below to verify your own account.")
        .build();
  }

  @PostMapping("/InsecureLogin/task")
  @ResponseBody
  public AttackResult completed(@RequestParam String password, @CurrentUsername String username) {
    if (username == null || username.isBlank() || password == null) {
      return failed(this).build();
    }
    String passwordHash = passwordHashes.get(username);
    if (passwordHash != null && passwordEncoder.matches(password, passwordHash)) {
      return success(this).build();
    }
    return failed(this).build();
  }
}
