/*
 * SPDX-FileCopyrightText: Copyright © 2014 WebGoat authors
 * SPDX-License-Identifier: GPL-2.0-or-later
 */
package org.owasp.webgoat.lessons.htmltampering;

import java.math.BigDecimal;

import static org.owasp.webgoat.container.assignments.AttackResultBuilder.failed;
import static org.owasp.webgoat.container.assignments.AttackResultBuilder.success;

import org.owasp.webgoat.container.assignments.AssignmentEndpoint;
import org.owasp.webgoat.container.assignments.AssignmentHints;
import org.owasp.webgoat.container.assignments.AttackResult;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.ResponseBody;
import org.springframework.web.bind.annotation.RestController;

@RestController
@AssignmentHints({"hint1", "hint2", "hint3"})
public class HtmlTamperingTask implements AssignmentEndpoint {

  private static final BigDecimal UNIT_PRICE = new BigDecimal("2999.99");
  private static final int MAX_QUANTITY = 1000;

  @PostMapping("/HtmlTampering/task")
  @ResponseBody
  public AttackResult completed(@RequestParam String QTY, @RequestParam String Total) {
    try {
      int quantity = Integer.parseInt(QTY);
      BigDecimal submittedTotal = new BigDecimal(Total);
      if (quantity > 0
          && quantity <= MAX_QUANTITY
          && UNIT_PRICE.multiply(BigDecimal.valueOf(quantity)).compareTo(submittedTotal) == 0) {
        return success(this).feedback("html-tampering.tamper.success").build();
      }
    } catch (NumberFormatException ignored) {
      // Malformed client values do not represent a valid order.
    }
    return failed(this).feedback("html-tampering.tamper.failure").build();
  }
}
