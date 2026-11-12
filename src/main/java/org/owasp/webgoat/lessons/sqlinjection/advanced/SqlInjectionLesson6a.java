/*
 * SPDX-FileCopyrightText: Copyright © 2016 WebGoat authors
 * SPDX-License-Identifier: GPL-2.0-or-later
 */
package org.owasp.webgoat.lessons.sqlinjection.advanced;

import static org.owasp.webgoat.container.assignments.AttackResultBuilder.failed;
import static org.owasp.webgoat.container.assignments.AttackResultBuilder.success;

import java.sql.Connection;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.util.Locale;
import java.util.Map;
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
      "SqlStringInjectionHint-advanced-6a-1",
      "SqlStringInjectionHint-advanced-6a-2",
      "SqlStringInjectionHint-advanced-6a-3",
      "SqlStringInjectionHint-advanced-6a-4",
      "SqlStringInjectionHint-advanced-6a-5"
    })
public class SqlInjectionLesson6a implements AssignmentEndpoint {

  private static final Map<String, String> ALLOWED_LAST_NAMES =
      Map.of("smith", "Smith", "snow", "Snow", "plane", "Plane");

  private final LessonDataSource dataSource;

  public SqlInjectionLesson6a(LessonDataSource dataSource) {
    this.dataSource = dataSource;
  }

  @PostMapping("/SqlInjectionAdvanced/attack6a")
  @ResponseBody
  public AttackResult completed(@RequestParam(value = "userid_6a") String userId) {
    return lookupApprovedAccountSummary(userId);
  }

  public AttackResult lookupApprovedAccountSummary(String lastName) {
    String normalizedLastName =
        lastName == null ? null : ALLOWED_LAST_NAMES.get(lastName.trim().toLowerCase(Locale.ROOT));
    if (normalizedLastName == null) {
      return failed(this).feedback("sql-injection.advanced.6a.no.results").build();
    }

    String query = "SELECT COUNT(*) FROM user_data WHERE last_name = ?";
    try (Connection connection = dataSource.getConnection();
        PreparedStatement statement = connection.prepareStatement(query)) {
      statement.setString(1, normalizedLastName);
      try (ResultSet results = statement.executeQuery()) {
        if (results.next()) {
          int matchingRecords = results.getInt(1);
          if (matchingRecords > 0) {
            return success(this)
                .feedback("sql-injection.advanced.6a.success")
                .feedbackArgs(matchingRecords)
                .output("Matching non-sensitive records: " + matchingRecords)
                .build();
          }
        }
      }
    } catch (SQLException e) {
      return failed(this).feedback("sql-injection.advanced.6a.no.results").build();
    }
    return failed(this).feedback("sql-injection.advanced.6a.no.results").build();
  }
}
