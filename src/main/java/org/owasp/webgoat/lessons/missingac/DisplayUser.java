/*
 * SPDX-FileCopyrightText: Copyright © 2014 WebGoat authors
 * SPDX-License-Identifier: GPL-2.0-or-later
 */
package org.owasp.webgoat.lessons.missingac;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.SecureRandom;
import java.util.Base64;
import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;
import lombok.Getter;

@Getter
public class DisplayUser {
  // intended to provide a display version of WebGoatUser for admins to view user attributes
  private static final byte[] HASH_KEY = createHashKey();

  private final String username;
  private final boolean admin;
  private final String userHash;

  public DisplayUser(User user, String passwordSalt) {
    this.username = user.getUsername();
    this.admin = user.isAdmin();

    String generatedHash;
    try {
      generatedHash = genUserHash(user.getUsername(), user.getPassword(), passwordSalt);
    } catch (Exception ex) {
      generatedHash = "";
    }
    this.userHash = generatedHash;
  }

  protected String genUserHash(String username, String password, String passwordSalt)
      throws Exception {
    Mac mac = Mac.getInstance("HmacSHA256");
    mac.init(new SecretKeySpec(HASH_KEY, "HmacSHA256"));
    updateField(mac, passwordSalt);
    updateField(mac, username);
    updateField(mac, password);
    return Base64.getEncoder().encodeToString(mac.doFinal());
  }

  static boolean matchesHash(String suppliedHash, String expectedHash) {
    if (suppliedHash == null || expectedHash == null) {
      return false;
    }
    try {
      return MessageDigest.isEqual(
          Base64.getDecoder().decode(suppliedHash), Base64.getDecoder().decode(expectedHash));
    } catch (IllegalArgumentException ex) {
      return false;
    }
  }

  private static byte[] createHashKey() {
    byte[] key = new byte[32];
    new SecureRandom().nextBytes(key);
    return key;
  }

  private static void updateField(Mac mac, String field) {
    byte[] value = field == null ? new byte[0] : field.getBytes(StandardCharsets.UTF_8);
    mac.update((byte) (value.length >>> 24));
    mac.update((byte) (value.length >>> 16));
    mac.update((byte) (value.length >>> 8));
    mac.update((byte) value.length);
    mac.update(value);
  }
}
