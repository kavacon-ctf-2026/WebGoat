/*
 * SPDX-FileCopyrightText: Copyright © 2016 WebGoat authors
 * SPDX-License-Identifier: GPL-2.0-or-later
 */
package org.owasp.webgoat.lessons.sqlinjection.introduction;

import static org.owasp.webgoat.container.assignments.AttackResultBuilder.failed;
import static org.owasp.webgoat.container.assignments.AttackResultBuilder.success;

import java.sql.Connection;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.util.Set;
import org.owasp.webgoat.container.LessonDataSource;
import org.owasp.webgoat.container.assignments.AssignmentEndpoint;
import org.owasp.webgoat.container.assignments.AssignmentHints;
import org.owasp.webgoat.container.assignments.AttackResult;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.ResponseBody;
import org.springframework.web.bind.annotation.RestController;

@RestController
@AssignmentHints(
    value = {
      "SqlStringInjectionHint5b1",
      "SqlStringInjectionHint5b2",
      "SqlStringInjectionHint5b3",
      "SqlStringInjectionHint5b4"
    })
public class SqlInjectionLesson5b implements AssignmentEndpoint {

  private static final Set<Integer> ALLOWED_USER_IDS =
      Set.of(101, 102, 103, 10312, 10323, 15603, 15613, 15837, 19204);
  private static final Set<Integer> ALLOWED_LOGIN_COUNTS = Set.of(0);

  private final LessonDataSource dataSource;

  public SqlInjectionLesson5b(LessonDataSource dataSource) {
    this.dataSource = dataSource;
  }

  @PostMapping("/SqlInjection/assignment5b")
  @ResponseBody
  public AttackResult completed(@RequestParam String userid, @RequestParam String login_count) {
    return lookupAccountSummary(login_count, userid);
  }

  protected AttackResult lookupAccountSummary(String loginCountValue, String userIdValue) {
    int loginCount;
    int userId;
    try {
      loginCount = Integer.parseInt(loginCountValue);
      userId = Integer.parseInt(userIdValue);
    } catch (NumberFormatException e) {
      return failed(this).feedback("sql-injection.5b.no.results").build();
    }

    if (!ALLOWED_LOGIN_COUNTS.contains(loginCount) || !ALLOWED_USER_IDS.contains(userId)) {
      return failed(this).feedback("sql-injection.5b.no.results").build();
    }

    String query = "SELECT COUNT(*) FROM user_data WHERE login_count = ? AND userid = ?";
    try (Connection connection = dataSource.getConnection()) {
      try (PreparedStatement statement = connection.prepareStatement(query)) {
        statement.setInt(1, loginCount);
        statement.setInt(2, userId);
        try (ResultSet results = statement.executeQuery()) {
          if (results.next()) {
            int matchingRecords = results.getInt(1);
            if (matchingRecords > 0) {
              return success(this)
                  .feedback("sql-injection.5b.success")
                  .feedbackArgs(matchingRecords)
                  .output(
                      "Matching non-sensitive records: "
                          + matchingRecords
                          + "<br>Prepared query: "
                          + query)
                  .build();
            }
          }
        }
      } catch (SQLException e) {
        return failed(this).feedback("sql-injection.5b.no.results").build();
      }
    } catch (SQLException e) {
      return failed(this).feedback("sql-injection.5b.no.results").build();
    }
    return failed(this).feedback("sql-injection.5b.no.results").build();
  }
}
