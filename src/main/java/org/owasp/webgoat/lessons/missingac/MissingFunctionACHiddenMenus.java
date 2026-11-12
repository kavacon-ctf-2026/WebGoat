/*
 * SPDX-FileCopyrightText: Copyright © 2017 WebGoat authors
 * SPDX-License-Identifier: GPL-2.0-or-later
 */
package org.owasp.webgoat.lessons.missingac;

import static org.owasp.webgoat.container.assignments.AttackResultBuilder.failed;
import static org.owasp.webgoat.container.assignments.AttackResultBuilder.success;

import org.owasp.webgoat.container.assignments.AssignmentEndpoint;
import org.owasp.webgoat.container.assignments.AssignmentHints;
import org.owasp.webgoat.container.assignments.AttackResult;
import org.owasp.webgoat.container.users.WebGoatUser;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.ResponseBody;
import org.springframework.web.bind.annotation.RestController;

/** Created by jason on 1/5/17. */
@RestController
@AssignmentHints({
  "access-control.hidden-menus.hint1",
  "access-control.hidden-menus.hint2",
  "access-control.hidden-menus.hint3"
})
public class MissingFunctionACHiddenMenus implements AssignmentEndpoint {

  @PostMapping(
      path = "/access-control/hidden-menu",
      produces = {"application/json"})
  @ResponseBody
  public AttackResult completed(String hiddenMenu1, String hiddenMenu2) {
    // Missing function-level access control: the privileged menu entries were disclosed to, and
    // accepted from, any authenticated user. The server now authorizes the function itself.
    Authentication authentication = SecurityContextHolder.getContext().getAuthentication();
    boolean admin =
        authentication != null
            && authentication.isAuthenticated()
            && authentication.getAuthorities().stream()
                .anyMatch(authority -> WebGoatUser.ROLE_ADMIN.equals(authority.getAuthority()));
    if (!admin) {
      return failed(this).feedback("access-control.hidden-menus.failure").output("").build();
    }

    if ("Users".equals(hiddenMenu1) && "Config".equals(hiddenMenu2)) {
      return success(this).output("").feedback("access-control.hidden-menus.success").build();
    }

    if ("Config".equals(hiddenMenu1) && "Users".equals(hiddenMenu2)) {
      return failed(this).output("").feedback("access-control.hidden-menus.close").build();
    }

    return failed(this).feedback("access-control.hidden-menus.failure").output("").build();
  }
}
