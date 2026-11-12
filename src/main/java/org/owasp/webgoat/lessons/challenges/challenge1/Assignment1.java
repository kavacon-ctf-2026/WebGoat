/*
 * SPDX-FileCopyrightText: Copyright © 2014 WebGoat authors
 * SPDX-License-Identifier: GPL-2.0-or-later
 */
package org.owasp.webgoat.lessons.challenges.challenge1;

import static org.owasp.webgoat.container.assignments.AttackResultBuilder.failed;
import static org.owasp.webgoat.container.assignments.AttackResultBuilder.success;

import org.owasp.webgoat.container.assignments.AssignmentEndpoint;
import org.owasp.webgoat.container.assignments.AttackResult;
import org.owasp.webgoat.lessons.challenges.Flags;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.util.StringUtils;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.ResponseBody;
import org.springframework.web.bind.annotation.RestController;

@RestController
public class Assignment1 implements AssignmentEndpoint {

  private final Flags flags;
  private final String adminPasswordHash;
  private final PasswordEncoder passwordEncoder = new BCryptPasswordEncoder();

  public Assignment1(
      Flags flags,
      @Value("${webgoat.challenge.admin.password-hash:}") String adminPasswordHash) {
    this.flags = flags;
    this.adminPasswordHash = adminPasswordHash;
  }

  @PostMapping("/challenge/1")
  @ResponseBody
  public AttackResult completed(@RequestParam String username, @RequestParam String password) {
    if ("admin".equals(username)
        && StringUtils.hasText(adminPasswordHash)
        && password != null
        && passwordEncoder.matches(password, adminPasswordHash)) {
      return success(this).feedback("challenge.solved").feedbackArgs(flags.getFlag(1)).build();
    }
    return failed(this).build();
  }
}
