/*
 * SPDX-FileCopyrightText: Copyright © 2014 WebGoat authors
 * SPDX-License-Identifier: GPL-2.0-or-later
 */
package org.owasp.webgoat.lessons.bypassrestrictions;

import static org.owasp.webgoat.container.assignments.AttackResultBuilder.failed;
import static org.owasp.webgoat.container.assignments.AttackResultBuilder.success;

import org.owasp.webgoat.container.assignments.AssignmentEndpoint;
import org.owasp.webgoat.container.assignments.AttackResult;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.ResponseBody;
import org.springframework.web.bind.annotation.RestController;

@RestController
public class BypassRestrictionsFieldRestrictions implements AssignmentEndpoint {

  @PostMapping("/BypassRestrictions/FieldRestrictions")
  @ResponseBody
  public AttackResult completed(
      @RequestParam String select,
      @RequestParam String radio,
      @RequestParam String checkbox,
      @RequestParam String shortInput,
      @RequestParam String readOnlyInput) {
    boolean selectValid = "option1".equals(select) || "option2".equals(select);
    boolean radioValid = "option1".equals(radio) || "option2".equals(radio);
    boolean checkboxValid = "on".equals(checkbox) || "off".equals(checkbox);
    boolean shortInputValid = shortInput != null && shortInput.length() <= 5;
    boolean readOnlyInputValid = "change".equals(readOnlyInput);

    if (selectValid && radioValid && checkboxValid && shortInputValid && readOnlyInputValid) {
      return success(this).build();
    }
    return failed(this).build();
  }
}
