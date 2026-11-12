/*
 * SPDX-FileCopyrightText: Copyright © 2017 WebGoat authors
 * SPDX-License-Identifier: GPL-2.0-or-later
 */
package org.owasp.webgoat.lessons.challenges.challenge7;

import java.security.SecureRandom;
import java.util.Base64;

/** Generates opaque reset tokens without deriving them from user-controlled data. */
public class PasswordResetLink {

  private static final SecureRandom SECURE_RANDOM = new SecureRandom();

  public String createPasswordReset(String username, String key) {
    byte[] token = new byte[32];
    SECURE_RANDOM.nextBytes(token);
    return Base64.getUrlEncoder().withoutPadding().encodeToString(token);
  }
}
