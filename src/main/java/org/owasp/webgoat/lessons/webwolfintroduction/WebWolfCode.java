/*
 * SPDX-FileCopyrightText: Copyright © 2026 WebGoat authors
 * SPDX-License-Identifier: GPL-2.0-or-later
 */
package org.owasp.webgoat.lessons.webwolfintroduction;

import java.security.MessageDigest;
import java.util.UUID;
import org.owasp.webgoat.container.session.LessonSession;

final class WebWolfCode {

  private static final String SESSION_KEY = "webwolf-reset-code";

  private WebWolfCode() {}

  static String getOrCreate(LessonSession session) {
    Object existing = session.getValue(SESSION_KEY);
    if (existing instanceof String code && !code.isBlank()) {
      return code;
    }
    String code = UUID.randomUUID().toString();
    session.setValue(SESSION_KEY, code);
    return code;
  }

  static boolean matches(LessonSession session, String suppliedCode) {
    Object expected = session.getValue(SESSION_KEY);
    if (!(expected instanceof String code) || suppliedCode == null) {
      return false;
    }
    return MessageDigest.isEqual(code.getBytes(java.nio.charset.StandardCharsets.UTF_8),
        suppliedCode.getBytes(java.nio.charset.StandardCharsets.UTF_8));
  }

  static void consume(LessonSession session) {
    session.setValue(SESSION_KEY, null);
  }
}
