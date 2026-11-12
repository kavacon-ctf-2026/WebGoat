/*
 * SPDX-FileCopyrightText: Copyright © 2018 WebGoat authors
 * SPDX-License-Identifier: GPL-2.0-or-later
 */
package org.owasp.webgoat.lessons.jwt;

import static org.owasp.webgoat.container.assignments.AttackResultBuilder.failed;
import static org.owasp.webgoat.container.assignments.AttackResultBuilder.success;
import static org.springframework.http.ResponseEntity.ok;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.ExpiredJwtException;
import io.jsonwebtoken.JwtException;
import io.jsonwebtoken.Jwts;
import java.security.SecureRandom;
import java.time.Instant;
import java.util.Base64;
import java.util.Date;
import java.util.HashMap;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;
import org.owasp.webgoat.container.assignments.AssignmentEndpoint;
import org.owasp.webgoat.container.assignments.AssignmentHints;
import org.owasp.webgoat.container.assignments.AttackResult;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.security.authentication.AnonymousAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestHeader;
import org.springframework.web.bind.annotation.ResponseBody;
import org.springframework.web.bind.annotation.RestController;

@RestController
@AssignmentHints({
  "jwt-refresh-hint1",
  "jwt-refresh-hint2",
  "jwt-refresh-hint3",
  "jwt-refresh-hint4"
})
public class JWTRefreshEndpoint implements AssignmentEndpoint {

  private static final byte[] JWT_PASSWORD = newSecret();
  private static final Map<String, RefreshToken> validRefreshTokens = new ConcurrentHashMap<>();

  private static byte[] newSecret() {
    byte[] secret = new byte[64];
    new SecureRandom().nextBytes(secret);
    return secret;
  }

  private static String newRefreshToken() {
    byte[] token = new byte[32];
    new SecureRandom().nextBytes(token);
    return Base64.getUrlEncoder().withoutPadding().encodeToString(token);
  }

  @PostMapping(
      value = "/JWT/refresh/login",
      produces = MediaType.APPLICATION_JSON_VALUE)
  @ResponseBody
  public ResponseEntity follow(Authentication authentication) {
    if (authentication == null
        || !authentication.isAuthenticated()
        || authentication instanceof AnonymousAuthenticationToken
        || authentication.getName() == null
        || authentication.getName().isBlank()) {
      return ResponseEntity.status(HttpStatus.UNAUTHORIZED).build();
    }
    return ok(createNewTokens(authentication.getName()));
  }

  private Map<String, Object> createNewTokens(String user) {
    Instant issuedAt = Instant.now();
    Map<String, Object> claims = Map.of("admin", false, "user", user);
    String token =
        Jwts.builder()
            .setClaims(claims)
            .setIssuedAt(Date.from(issuedAt))
            .setExpiration(Date.from(issuedAt.plusSeconds(15 * 60)))
            .signWith(io.jsonwebtoken.SignatureAlgorithm.HS512, JWT_PASSWORD)
            .compact();
    Map<String, Object> tokenJson = new HashMap<>();
    String refreshToken = newRefreshToken();
    validRefreshTokens.put(refreshToken, new RefreshToken(user, issuedAt.plusSeconds(15 * 60)));
    tokenJson.put("access_token", token);
    tokenJson.put("refresh_token", refreshToken);
    return tokenJson;
  }

  @PostMapping("/JWT/refresh/checkout")
  @ResponseBody
  public ResponseEntity<AttackResult> checkout(
      @RequestHeader(value = "Authorization", required = false) String token) {
    if (token == null) {
      return ResponseEntity.status(HttpStatus.UNAUTHORIZED).build();
    }
    try {
      Claims claims =
          Jwts.parser().setSigningKey(JWT_PASSWORD).parseClaimsJws(stripBearer(token)).getBody();
      String user = (String) claims.get("user");
      if ("Tom".equals(user)) {
        return ok(success(this).build());
      }
      return ok(failed(this).feedback("jwt-refresh-not-tom").feedbackArgs(user).build());
    } catch (ExpiredJwtException e) {
      return ok(failed(this).feedback("jwt-invalid-token").build());
    } catch (JwtException e) {
      return ok(failed(this).feedback("jwt-invalid-token").build());
    }
  }

  @PostMapping("/JWT/refresh/newToken")
  @ResponseBody
  public ResponseEntity newToken(
      @RequestHeader(value = "Authorization", required = false) String token,
      @RequestBody(required = false) Map<String, Object> json) {
    if (token == null || json == null) {
      return ResponseEntity.status(HttpStatus.UNAUTHORIZED).build();
    }

    String user;
    String refreshToken;
    try {
      Claims claims =
          Jwts.parser().setSigningKey(JWT_PASSWORD).parseClaimsJws(stripBearer(token)).getBody();
      user = (String) claims.get("user");
      refreshToken = (String) json.get("refresh_token");
    } catch (ExpiredJwtException e) {
      user = (String) e.getClaims().get("user");
      refreshToken = (String) json.get("refresh_token");
    }

    if (user == null || refreshToken == null) {
      return ResponseEntity.status(HttpStatus.UNAUTHORIZED).build();
    } else {
      RefreshToken issuedTo = validRefreshTokens.get(refreshToken);
      if (issuedTo != null
          && issuedTo.expiresAt().isAfter(Instant.now())
          && user.equals(issuedTo.username())
          && validRefreshTokens.remove(refreshToken, issuedTo)) {
        return ok(createNewTokens(user));
      }
      if (issuedTo != null && !issuedTo.expiresAt().isAfter(Instant.now())) {
        validRefreshTokens.remove(refreshToken, issuedTo);
      }
      return ResponseEntity.status(HttpStatus.UNAUTHORIZED).build();
    }
  }

  private String stripBearer(String token) {
    return token.startsWith("Bearer ") ? token.substring("Bearer ".length()) : token;
  }

  private record RefreshToken(String username, Instant expiresAt) {}
}
