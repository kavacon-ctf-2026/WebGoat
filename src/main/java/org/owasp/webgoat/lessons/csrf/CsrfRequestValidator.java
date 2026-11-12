/*
 * SPDX-FileCopyrightText: Copyright © 2026 WebGoat authors
 * SPDX-License-Identifier: GPL-2.0-or-later
 */
package org.owasp.webgoat.lessons.csrf;

import jakarta.servlet.http.HttpServletRequest;
import java.net.URI;

/** Validates browser supplied origin metadata for state-changing lesson requests. */
final class CsrfRequestValidator {

  private CsrfRequestValidator() {}

  static boolean isSameOrigin(HttpServletRequest request) {
    String fetchSite = request.getHeader("Sec-Fetch-Site");
    if ("cross-site".equalsIgnoreCase(fetchSite) || "none".equalsIgnoreCase(fetchSite)) {
      return false;
    }

    String source = request.getHeader("Origin");
    if (source == null || source.isBlank()) {
      source = request.getHeader("Referer");
    }
    if (source == null || source.isBlank() || "null".equalsIgnoreCase(source)) {
      return false;
    }

    try {
      URI sourceUri = URI.create(source);
      String targetScheme = request.getHeader("X-Forwarded-Proto");
      if (targetScheme == null || targetScheme.isBlank()) {
        targetScheme = request.getScheme();
      } else if (targetScheme.contains(",")) {
        targetScheme = targetScheme.substring(0, targetScheme.indexOf(',')).trim();
      }

      String authority = request.getHeader("Host");
      if (authority == null || authority.isBlank()) {
        authority = request.getServerName();
        int port = request.getServerPort();
        if (port > 0 && port != defaultPort(targetScheme)) {
          authority += ":" + port;
        }
      }
      URI targetUri = URI.create(targetScheme + "://" + authority);
      return sourceUri.getScheme() != null
          && sourceUri.getHost() != null
          && sourceUri.getScheme().equalsIgnoreCase(targetUri.getScheme())
          && sourceUri.getHost().equalsIgnoreCase(targetUri.getHost())
          && effectivePort(sourceUri) == effectivePort(targetUri);
    } catch (IllegalArgumentException e) {
      return false;
    }
  }

  private static int effectivePort(URI uri) {
    return uri.getPort() >= 0 ? uri.getPort() : defaultPort(uri.getScheme());
  }

  private static int defaultPort(String scheme) {
    return "https".equalsIgnoreCase(scheme) ? 443 : 80;
  }
}
