/*
 * SPDX-FileCopyrightText: Copyright © 2017 WebGoat authors
 * SPDX-License-Identifier: GPL-2.0-or-later
 */
package org.owasp.webgoat.lessons.webwolfintroduction;

import static org.owasp.webgoat.container.assignments.AttackResultBuilder.failed;
import static org.owasp.webgoat.container.assignments.AttackResultBuilder.informationMessage;
import static org.owasp.webgoat.container.assignments.AttackResultBuilder.success;

import java.util.regex.Pattern;
import org.owasp.webgoat.container.CurrentUsername;
import org.owasp.webgoat.container.assignments.AssignmentEndpoint;
import org.owasp.webgoat.container.assignments.AttackResult;
import org.owasp.webgoat.container.session.LessonSession;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.ResponseBody;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.client.RestClientException;
import org.springframework.web.client.RestTemplate;

/**
 * @author nbaars
 * @since 8/20/17.
 */
@RestController
public class MailAssignment implements AssignmentEndpoint {

  private static final Pattern EMAIL_ADDRESS =
      Pattern.compile(
          "[A-Za-z0-9.!#$%&'*+/=?^_`{|}~-]{1,64}@[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?(?:\\.[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?)*");

  private final String webWolfURL;
  private final LessonSession lessonSession;
  private RestTemplate restTemplate;

  public MailAssignment(
      RestTemplate restTemplate,
      @Value("${webwolf.mail.url}") String webWolfURL,
      LessonSession lessonSession) {
    this.restTemplate = restTemplate;
    this.webWolfURL = webWolfURL;
    this.lessonSession = lessonSession;
  }

  @PostMapping("/WebWolf/mail/send")
  @ResponseBody
  public AttackResult sendEmail(
      @RequestParam(required = false) String email, @CurrentUsername String webGoatUsername) {
    if (!isValidEmail(email)) {
      return informationMessage(this).feedback("webwolf.email_invalid").build();
    }
    String username = email.substring(0, email.indexOf('@'));
    if (username.equalsIgnoreCase(webGoatUsername)) {
      String resetCode = WebWolfCode.getOrCreate(lessonSession);
      Email mailEvent =
          Email.builder()
              .recipient(webGoatUsername)
              .title("Test messages from WebWolf")
              .contents(
                  "This is a test message from WebWolf, your unique code is: "
                      + resetCode)
              .sender("webgoat@owasp.org")
              .build();
      try {
        restTemplate.postForEntity(webWolfURL, mailEvent, Object.class);
      } catch (RestClientException e) {
        return informationMessage(this).feedback("webwolf.email_failed").build();
      }
      return informationMessage(this).feedback("webwolf.email_send").build();
    } else {
      return informationMessage(this).feedback("webwolf.email_mismatch").build();
    }
  }

  @PostMapping("/WebWolf/mail")
  @ResponseBody
  public AttackResult completed(@RequestParam String uniqueCode, @CurrentUsername String username) {
    if (WebWolfCode.matches(lessonSession, uniqueCode)) {
      WebWolfCode.consume(lessonSession);
      return success(this).build();
    } else {
      return failed(this).feedback("webwolf.code_incorrect").build();
    }
  }

  private boolean isValidEmail(String email) {
    return email != null && email.length() <= 254 && EMAIL_ADDRESS.matcher(email).matches();
  }
}
