/*
 * SPDX-FileCopyrightText: Copyright © 2016 WebGoat authors
 * SPDX-License-Identifier: GPL-2.0-or-later
 */
package org.owasp.webgoat.lessons.xss;

import static org.owasp.webgoat.container.assignments.AttackResultBuilder.failed;

import java.util.function.Predicate;
import java.util.regex.Pattern;
import org.owasp.webgoat.container.assignments.AssignmentEndpoint;
import org.owasp.webgoat.container.assignments.AssignmentHints;
import org.owasp.webgoat.container.assignments.AttackResult;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.ResponseBody;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.util.HtmlUtils;

@RestController
@AssignmentHints(
    value = {
      "xss-reflected-5a-hint-1",
      "xss-reflected-5a-hint-2",
      "xss-reflected-5a-hint-3",
      "xss-reflected-5a-hint-4"
    })
public class CrossSiteScriptingLesson5a implements AssignmentEndpoint {

  public static final Predicate<String> XSS_PATTERN =
      Pattern.compile(
              ".*<script>(console\\.log|alert)\\(.*\\);?</script>.*", Pattern.CASE_INSENSITIVE)
          .asMatchPredicate();

  @GetMapping("/CrossSiteScripting/attack5a")
  @ResponseBody
  public AttackResult completed(
      @RequestParam Integer QTY1,
      @RequestParam Integer QTY2,
      @RequestParam Integer QTY3,
      @RequestParam Integer QTY4,
      @RequestParam String field1,
      @RequestParam String field2) {

    if (XSS_PATTERN.test(field2)) {
      return failed(this).feedback("xss-reflected-5a-failed-wrong-field").build();
    }

    double totalSale =
        QTY1.intValue() * 69.99
            + QTY2.intValue() * 27.99
            + QTY3.intValue() * 1599.99
            + QTY4.intValue() * 299.99;

    StringBuilder cart = new StringBuilder();
    cart.append("Thank you for shopping at WebGoat. <br />Your support is appreciated<hr />");
    cart.append("<p>We have charged credit card:" + HtmlUtils.htmlEscape(field1) + "<br />");
    cart.append("                             ------------------- <br />");
    cart.append("                               $" + totalSale);

    if (XSS_PATTERN.test(field1)) {
      return failed(this)
          .feedback("xss-reflected-5a-safe")
          .output(cart.toString())
          .build();
    }

    return failed(this).feedback("xss-reflected-5a-failure").output(cart.toString()).build();
  }
}
