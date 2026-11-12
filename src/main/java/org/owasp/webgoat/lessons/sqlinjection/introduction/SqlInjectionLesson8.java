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
import java.sql.ResultSetMetaData;
import java.sql.SQLException;
import java.text.SimpleDateFormat;
import java.util.Calendar;
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
      "SqlStringInjectionHint.8.1",
      "SqlStringInjectionHint.8.2",
      "SqlStringInjectionHint.8.3",
      "SqlStringInjectionHint.8.4",
      "SqlStringInjectionHint.8.5"
    })
public class SqlInjectionLesson8 implements AssignmentEndpoint {

  private static final Set<String> ALLOWED_LAST_NAMES = Set.of("Smith");

  private final LessonDataSource dataSource;

  public SqlInjectionLesson8(LessonDataSource dataSource) {
    this.dataSource = dataSource;
  }

  @PostMapping("/SqlInjection/attack8")
  @ResponseBody
  public AttackResult completed(@RequestParam String name, @RequestParam String auth_tan) {
    return injectableQueryConfidentiality(name, auth_tan);
  }

  protected AttackResult injectableQueryConfidentiality(String name, String auth_tan) {
    if (name == null
        || !ALLOWED_LAST_NAMES.contains(name)
        || auth_tan == null
        || auth_tan.length() != 6) {
      return failed(this).feedback("sql-injection.8.no.results").build();
    }

    try (Connection connection = dataSource.getConnection()) {
      log(connection, "Employee lookup");
      try (PreparedStatement statement =
          connection.prepareStatement(
              "SELECT department FROM employees WHERE first_name = 'John'"
                  + " AND last_name = ? AND auth_tan = ?")) {
        statement.setString(1, name);
        statement.setString(2, auth_tan);
        try (ResultSet results = statement.executeQuery()) {
          if (results.next()) {
            return success(this)
                .feedback("sql-injection.8.success")
                .output("Your department: " + results.getString("department"))
                .build();
          }
          return failed(this).feedback("sql-injection.8.no.results").build();
        }
      }
    } catch (SQLException e) {
      return failed(this).feedback("sql-injection.8.no.results").build();
    }
  }

  public static String generateTable(ResultSet results) throws SQLException {
    ResultSetMetaData resultsMetaData = results.getMetaData();
    int numColumns = resultsMetaData.getColumnCount();
    results.beforeFirst();
    StringBuilder table = new StringBuilder();
    table.append("<table>");

    if (results.next()) {
      table.append("<tr>");
      for (int i = 1; i < (numColumns + 1); i++) {
        table.append("<th>" + resultsMetaData.getColumnName(i) + "</th>");
      }
      table.append("</tr>");

      results.beforeFirst();
      while (results.next()) {
        table.append("<tr>");
        for (int i = 1; i < (numColumns + 1); i++) {
          table.append("<td>" + results.getString(i) + "</td>");
        }
        table.append("</tr>");
      }

    } else {
      table.append("Query Successful; however no data was returned from this query.");
    }

    table.append("</table>");
    return (table.toString());
  }

  public static void log(Connection connection, String action) {
    Calendar cal = Calendar.getInstance();
    SimpleDateFormat sdf = new SimpleDateFormat("yyyy-MM-dd HH:mm:ss");
    String time = sdf.format(cal.getTime());

    try (PreparedStatement statement =
        connection.prepareStatement("INSERT INTO access_log (time, action) VALUES (?, ?)")) {
      statement.setString(1, time);
      statement.setString(2, action);
      statement.executeUpdate();
    } catch (SQLException e) {
      System.err.println(e.getMessage());
    }
  }
}
