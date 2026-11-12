/*
 * SPDX-FileCopyrightText: Copyright © 2017 WebGoat authors
 * SPDX-License-Identifier: GPL-2.0-or-later
 */
package org.owasp.webgoat.lessons.idor;

import static org.owasp.webgoat.container.assignments.AttackResultBuilder.failed;
import static org.owasp.webgoat.container.assignments.AttackResultBuilder.success;

import java.net.URI;
import java.net.URISyntaxException;
import org.owasp.webgoat.container.assignments.AssignmentEndpoint;
import org.owasp.webgoat.container.assignments.AssignmentHints;
import org.owasp.webgoat.container.assignments.AttackResult;
import org.owasp.webgoat.container.session.LessonSession;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.ResponseBody;
import org.springframework.web.bind.annotation.RestController;

@RestController
@AssignmentHints({
  "idor.hints.ownProfileAltUrl1",
  "idor.hints.ownProfileAltUrl2",
  "idor.hints.ownProfileAltUrl3"
})
public class IDORViewOwnProfileAltUrl implements AssignmentEndpoint {
  private final LessonSession userSessionData;

  public IDORViewOwnProfileAltUrl(LessonSession userSessionData) {
    this.userSessionData = userSessionData;
  }

  @PostMapping("/IDOR/profile/alt-path")
  @ResponseBody
  public AttackResult completed(@RequestParam String url) {
    if (!"tom".equals(userSessionData.getValue("idor-authenticated-as"))) {
      return failed(this).feedback("idor.view.own.profile.failure2").build();
    }

    String authUserId = (String) userSessionData.getValue("idor-authenticated-user-id");
    if (authUserId == null || !isOwnProfilePath(url, authUserId)) {
      return failed(this).feedback("idor.view.own.profile.failure1").build();
    }

    UserProfile userProfile = new UserProfile(authUserId);
    return success(this)
        .feedback("idor.view.own.profile.success")
        .output(userProfile.profileToMap().toString())
        .build();
  }

  private boolean isOwnProfilePath(String input, String authenticatedUserId) {
    if (input == null || input.isBlank()) {
      return false;
    }

    try {
      URI uri = new URI(input.trim());
      String rawPath = uri.getRawPath();
      if (rawPath == null
          || uri.getRawQuery() != null
          || uri.getRawFragment() != null
          || uri.getRawUserInfo() != null
          || rawPath.indexOf('%') >= 0
          || rawPath.indexOf('\\') >= 0
          || !rawPath.equals(uri.normalize().getRawPath())) {
        return false;
      }

      // The lesson accepts either a relative application path or an absolute URL, but the
      // resource path itself must be exactly the authenticated user's profile path.
      String normalizedPath = rawPath.startsWith("/") ? rawPath.substring(1) : rawPath;
      return normalizedPath.equals("WebGoat/IDOR/profile/" + authenticatedUserId);
    } catch (URISyntaxException ex) {
      return false;
    }
  }
}
