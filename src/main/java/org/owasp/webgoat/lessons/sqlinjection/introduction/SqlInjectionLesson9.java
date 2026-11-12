/*
 * SPDX-FileCopyrightText: Copyright © 2018 WebGoat authors
 * SPDX-License-Identifier: GPL-2.0-or-later
 */
package org.owasp.webgoat.lessons.sqlinjection.introduction;

import static java.sql.ResultSet.CONCUR_UPDATABLE;
import static java.sql.ResultSet.TYPE_SCROLL_SENSITIVE;
import static org.owasp.webgoat.container.assignments.AttackResultBuilder.failed;
import static org.owasp.webgoat.container.assignments.AttackResultBuilder.success;

import java.sql.Connection;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Statement;
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
      "SqlStringInjectionHint.9.1",
      "SqlStringInjectionHint.9.2",
      "SqlStringInjectionHint.9.3",
      "SqlStringInjectionHint.9.4",
      "SqlStringInjectionHint.9.5"
    })
public class SqlInjectionLesson9 implements AssignmentEndpoint {

  private final LessonDataSource dataSource;

  public SqlInjectionLesson9(LessonDataSource dataSource) {
    this.dataSource = dataSource;
  }

  @PostMapping("/SqlInjection/attack9")
  @ResponseBody
  public AttackResult completed(@RequestParam String name, @RequestParam String auth_tan) {
    return injectableQueryIntegrity(name, auth_tan);
  }

  protected AttackResult injectableQueryIntegrity(String name, String auth_tan) {
    // Root cause: name and auth_tan used to be concatenated into the statement, which allowed
    // stacked statements (UPDATE employees SET salary ...). Both values are bound parameters now.
    String query = "SELECT * FROM employees WHERE last_name = ? AND auth_tan = ?";
    try (Connection connection = dataSource.getConnection()) {
      int oldMaxSalary = this.getMaxSalary(connection);
      int oldSumSalariesOfOtherEmployees = this.getSumSalariesOfOtherEmployees(connection);
      // begin transaction
      connection.setAutoCommit(false);
      try (PreparedStatement statement =
          connection.prepareStatement(query, TYPE_SCROLL_SENSITIVE, CONCUR_UPDATABLE)) {
        statement.setString(1, name);
        statement.setString(2, auth_tan);
        SqlInjectionLesson8.log(connection, "Salary lookup");
        statement.execute();
      }
      // check new sum of salaries other employees and new salaries of John
      int newJohnSalary = this.getJohnSalary(connection);
      int newSumSalariesOfOtherEmployees = this.getSumSalariesOfOtherEmployees(connection);
      if (newJohnSalary > oldMaxSalary
          && newSumSalariesOfOtherEmployees == oldSumSalariesOfOtherEmployees) {
        connection.commit();
        connection.setAutoCommit(true);
        return success(this).feedback("sql-injection.9.success").build();
      }
      connection.rollback();
      return failed(this).feedback("sql-injection.9.one").build();
    } catch (SQLException e) {
      return failed(this).feedback("sql-injection.9.one").build();
    }
  }

  private int getSqlInt(Connection connection, String query) throws SQLException {
    try (Statement statement =
            connection.createStatement(TYPE_SCROLL_SENSITIVE, CONCUR_UPDATABLE);
        ResultSet results = statement.executeQuery(query)) {
      results.first();
      return results.getInt(1);
    }
  }

  private int getMaxSalary(Connection connection) throws SQLException {
    return this.getSqlInt(connection, "SELECT max(salary) FROM employees");
  }

  private int getSumSalariesOfOtherEmployees(Connection connection) throws SQLException {
    return this.getSqlInt(
        connection, "SELECT sum(salary) FROM employees WHERE auth_tan != '3SL99A'");
  }

  private int getJohnSalary(Connection connection) throws SQLException {
    return this.getSqlInt(connection, "SELECT salary FROM employees WHERE auth_tan = '3SL99A'");
  }
}
