/*
 * SPDX-FileCopyrightText: Copyright © 2014 WebGoat authors
 * SPDX-License-Identifier: GPL-2.0-or-later
 */
package org.owasp.webgoat.lessons.ssrf;

import static org.owasp.webgoat.container.assignments.AttackResultBuilder.failed;

import java.util.Set;
import org.owasp.webgoat.container.assignments.AssignmentEndpoint;
import org.owasp.webgoat.container.assignments.AssignmentHints;
import org.owasp.webgoat.container.assignments.AttackResult;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.ResponseBody;
import org.springframework.web.bind.annotation.RestController;

@RestController
@AssignmentHints({"ssrf.hint1", "ssrf.hint2"})
public class SSRFTask1 implements AssignmentEndpoint {

  // The resource to render used to be chosen freely by the client, which exposed the image that
  // is not meant to be served here. Only resources the server explicitly publishes are allowed.
  private static final Set<String> PUBLIC_IMAGES = Set.of("images/tom.png", "images/cat.jpg");

  @PostMapping("/SSRF/task1")
  @ResponseBody
  public AttackResult completed(@RequestParam String url) {
    return stealTheCheese(url);
  }

  protected AttackResult stealTheCheese(String url) {
    if (url != null && PUBLIC_IMAGES.contains(url)) {
      String alt = url.contains("tom") ? "Tom" : "Silly Cat";
      String html =
          "<img class=\"image\" alt=\""
              + alt
              + "\" src=\""
              + url
              + "\" width=\"25%\" height=\"25%\">";
      return failed(this).feedback("ssrf.tom").output(html).build();
    }
    return failed(this)
        .feedback("ssrf.failure")
        .output("<img class=\"image\" alt=\"Silly Cat\" src=\"images/cat.jpg\">")
        .build();
  }
}
