/*
 * SPDX-FileCopyrightText: Copyright © 2014 WebGoat authors
 * SPDX-License-Identifier: GPL-2.0-or-later
 */
package org.owasp.webgoat.lessons.sqlinjection.introduction;

import static org.owasp.webgoat.container.assignments.AttackResultBuilder.failed;

import org.owasp.webgoat.container.assignments.AssignmentEndpoint;
import org.owasp.webgoat.container.assignments.AssignmentHints;
import org.owasp.webgoat.container.assignments.AttackResult;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.ResponseBody;
import org.springframework.web.bind.annotation.RestController;

@RestController
@AssignmentHints(
    value = {
      "SqlStringInjectionHint5-1",
      "SqlStringInjectionHint5-2",
      "SqlStringInjectionHint5-3",
      "SqlStringInjectionHint5-4"
    })
public class SqlInjectionLesson5 implements AssignmentEndpoint {

  /**
   * The endpoint used to run a DCL statement (GRANT) written by the client. Privileges must never
   * be changed from request data, so the server no longer executes client-supplied SQL.
   */
  @PostMapping("/SqlInjection/attack5")
  @ResponseBody
  public AttackResult completed(String query) {
    return injectableQuery(query);
  }

  protected AttackResult injectableQuery(String query) {
    return failed(this)
        .output("Client-supplied SQL statements are not executed by the server.")
        .build();
  }
}
