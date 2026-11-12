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
import org.owasp.webgoat.container.LessonDataSource;
import org.owasp.webgoat.container.assignments.AssignmentEndpoint;
import org.owasp.webgoat.container.assignments.AssignmentHints;
import org.owasp.webgoat.container.assignments.AttackResult;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.ResponseBody;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.util.HtmlUtils;

@RestController
@AssignmentHints(value = {"SqlStringInjectionHint5a1"})
public class SqlInjectionLesson5a implements AssignmentEndpoint {

  private final LessonDataSource dataSource;

  public SqlInjectionLesson5a(LessonDataSource dataSource) {
    this.dataSource = dataSource;
  }

  @PostMapping("/SqlInjection/assignment5a")
  @ResponseBody
  public AttackResult completed(
      @RequestParam String account, @RequestParam String operator, @RequestParam String injection) {
    // operator and injection used to be concatenated into the SQL text. They are never part of the
    // statement now; the account is bound as a plain value.
    return injectableQuery(account);
  }

  protected AttackResult injectableQuery(String accountName) {
    String query = "SELECT * FROM user_data WHERE first_name = 'John' and last_name = ?";
    try (Connection connection = dataSource.getConnection();
        PreparedStatement statement =
            connection.prepareStatement(
                query, ResultSet.TYPE_SCROLL_INSENSITIVE, ResultSet.CONCUR_READ_ONLY)) {
      statement.setString(1, accountName);
      try (ResultSet results = statement.executeQuery()) {
        if (results != null && results.first()) {
          results.last();
          // Returning more than one user used to prove that the injection worked.
          if (results.getRow() >= 6) {
            return success(this).feedback("sql-injection.5a.success").build();
          }
        }
      }
      return failed(this).feedback("sql-injection.5a.no.results").build();
    } catch (SQLException e) {
      return failed(this).feedback("sql-injection.5a.no.results").build();
    }
  }

  public static String writeTable(ResultSet results, ResultSetMetaData resultsMetaData)
      throws SQLException {
    int numColumns = resultsMetaData.getColumnCount();
    results.beforeFirst();
    StringBuilder t = new StringBuilder();
    t.append("<p>");

    if (results.next()) {
      for (int i = 1; i < (numColumns + 1); i++) {
        t.append(HtmlUtils.htmlEscape(resultsMetaData.getColumnName(i)));
        t.append(", ");
      }
      t.append("<br />");
      results.beforeFirst();
      while (results.next()) {
        for (int i = 1; i < (numColumns + 1); i++) {
          t.append(HtmlUtils.htmlEscape(String.valueOf(results.getString(i))));
          t.append(", ");
        }
        t.append("<br />");
      }
    } else {
      t.append("Query Successful; however no data was returned from this query.");
    }
    t.append("</p>");
    return (t.toString());
  }
}
