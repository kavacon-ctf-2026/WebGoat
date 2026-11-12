/*
 * SPDX-FileCopyrightText: Copyright © 2014 WebGoat authors
 * SPDX-License-Identifier: GPL-2.0-or-later
 */
package org.owasp.webgoat.lessons.logging;

import static org.owasp.webgoat.container.assignments.AttackResultBuilder.failed;
import static org.owasp.webgoat.container.assignments.AttackResultBuilder.success;

import org.apache.logging.log4j.util.Strings;
import org.owasp.webgoat.container.assignments.AssignmentEndpoint;
import org.owasp.webgoat.container.assignments.AttackResult;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.ResponseBody;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.util.HtmlUtils;

@RestController
public class LogSpoofingTask implements AssignmentEndpoint {

  @PostMapping("/LogSpoofing/log-spoofing")
  @ResponseBody
  public AttackResult completed(@RequestParam String username, @RequestParam String password) {
    if (Strings.isEmpty(username)) {
      return failed(this).output("A username is required.").build();
    }
    if (username.contains("\r") || username.contains("\n")) {
      return failed(this)
          .feedback("logging.line-break-blocked")
          .output("Line breaks are not allowed.")
          .build();
    }
    // This lesson renders the simulated log through an HTML sink; show input
    // as text and do not treat a forged line as a successful authentication.
    return success(this)
        .feedback("logging.safe-line-accepted")
        .output(HtmlUtils.htmlEscape(username))
        .build();
  }
}
