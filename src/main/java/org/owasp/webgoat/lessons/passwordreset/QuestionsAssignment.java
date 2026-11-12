/*
 * SPDX-FileCopyrightText: Copyright © 2017 WebGoat authors
 * SPDX-License-Identifier: GPL-2.0-or-later
 */
package org.owasp.webgoat.lessons.passwordreset;

import static org.owasp.webgoat.container.assignments.AttackResultBuilder.failed;
import static org.owasp.webgoat.container.assignments.AttackResultBuilder.informationMessage;
import static org.owasp.webgoat.container.assignments.AttackResultBuilder.success;

import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;
import org.owasp.webgoat.container.CurrentUsername;
import org.owasp.webgoat.container.assignments.AssignmentEndpoint;
import org.owasp.webgoat.container.assignments.AttackResult;
import org.springframework.http.MediaType;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.util.StringUtils;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.ResponseBody;
import org.springframework.web.bind.annotation.RestController;

@RestController
public class QuestionsAssignment implements AssignmentEndpoint {

  private static final int MIN_ANSWER_LENGTH = 12;
  private static final int MAX_ANSWER_LENGTH = 128;
  private static final Map<String, String> ANSWER_HASHES = new ConcurrentHashMap<>();
  private static final PasswordEncoder PASSWORD_ENCODER = new BCryptPasswordEncoder();

  @PostMapping(
      path = "/PasswordReset/questions/enroll",
      consumes = MediaType.APPLICATION_FORM_URLENCODED_VALUE)
  @ResponseBody
  public AttackResult enroll(
      @RequestParam String answer,
      @RequestParam String confirmation,
      @CurrentUsername String username) {
    if (!hasValidAnswer(answer) || !answer.equals(confirmation) || !StringUtils.hasText(username)) {
      return failed(this).output("Unable to save the recovery answer.").build();
    }
    String hash = PASSWORD_ENCODER.encode(answer);
    if (ANSWER_HASHES.putIfAbsent(username, hash) != null) {
      return failed(this).output("Unable to save the recovery answer.").build();
    }
    return informationMessage(this)
        .output("Recovery answer saved. It is stored as a password hash.")
        .build();
  }

  @PostMapping(
      path = "/PasswordReset/questions",
      consumes = MediaType.APPLICATION_FORM_URLENCODED_VALUE)
  @ResponseBody
  public AttackResult passwordReset(
      @RequestParam String securityQuestion, @CurrentUsername String username) {
    String answerHash = StringUtils.hasText(username) ? ANSWER_HASHES.get(username) : null;
    if (!StringUtils.hasText(username)
        || !StringUtils.hasText(securityQuestion)
        || answerHash == null
        || !PASSWORD_ENCODER.matches(securityQuestion, answerHash)) {
      return failed(this).output("Unable to verify the recovery answer.").build();
    }
    return success(this).build();
  }

  private boolean hasValidAnswer(String answer) {
    return StringUtils.hasText(answer)
        && answer.length() >= MIN_ANSWER_LENGTH
        && answer.length() <= MAX_ANSWER_LENGTH;
  }
}
