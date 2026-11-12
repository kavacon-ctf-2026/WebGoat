/*
 * SPDX-FileCopyrightText: Copyright © 2018 WebGoat authors
 * SPDX-License-Identifier: GPL-2.0-or-later
 */
package org.owasp.webgoat.lessons.jwt.claimmisuse;

import static org.owasp.webgoat.container.assignments.AttackResultBuilder.failed;
import static org.owasp.webgoat.container.assignments.AttackResultBuilder.success;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.JwsHeader;
import io.jsonwebtoken.Jwt;
import io.jsonwebtoken.JwtException;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.SigningKeyResolverAdapter;
import java.security.SecureRandom;
import org.apache.commons.lang3.StringUtils;
import org.owasp.webgoat.container.LessonDataSource;
import org.owasp.webgoat.container.assignments.AssignmentEndpoint;
import org.owasp.webgoat.container.assignments.AssignmentHints;
import org.owasp.webgoat.container.assignments.AttackResult;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.ResponseBody;
import org.springframework.web.bind.annotation.RestController;

@RestController
@AssignmentHints({
  "jwt-kid-hint1",
  "jwt-kid-hint2",
  "jwt-kid-hint3",
  "jwt-kid-hint4",
  "jwt-kid-hint5",
  "jwt-kid-hint6"
})
@RequestMapping("/JWT/")
public class JWTHeaderKIDEndpoint implements AssignmentEndpoint {
  private static final String TRUSTED_KEY_ID = "webgoat_key";
  private static final byte[] TRUSTED_SIGNING_KEY = createTrustedSigningKey();

  private JWTHeaderKIDEndpoint(LessonDataSource ignoredDataSource) {
    // Keep constructor injection compatible with the lesson's existing configuration. The
    // untrusted kid is no longer used to select a database row or construct a SQL query.
  }

  private static byte[] createTrustedSigningKey() {
    byte[] key = new byte[32];
    new SecureRandom().nextBytes(key);
    return key;
  }

  @PostMapping("kid/follow/{user}")
  public @ResponseBody String follow(@PathVariable("user") String user) {
    if ("Jerry".equals(user)) {
      return "Following yourself seems redundant";
    } else {
      return "You are now following Tom";
    }
  }

  @PostMapping("kid/delete")
  public @ResponseBody AttackResult resetVotes(@RequestParam("token") String token) {
    if (StringUtils.isEmpty(token)) {
      return failed(this).feedback("jwt-invalid-token").build();
    } else {
      try {
        Jwt jwt =
            Jwts.parser()
                .setSigningKeyResolver(
                    new SigningKeyResolverAdapter() {
                      @Override
                      public byte[] resolveSigningKeyBytes(JwsHeader header, Claims claims) {
                        final String kid = header.getKeyId();
                        if (!TRUSTED_KEY_ID.equals(kid)
                            || !"HS256".equals(header.getAlgorithm())) {
                          throw new JwtException("Untrusted JWT key identifier or algorithm");
                        }
                        return TRUSTED_SIGNING_KEY.clone();
                      }
                    })
                .parseClaimsJws(token);
        Claims claims = (Claims) jwt.getBody();
        if (!"WebGoat Token Builder".equals(claims.getIssuer())
            || !"webgoat.org".equals(claims.getAudience())
            || claims.getIssuedAt() == null) {
          return failed(this).feedback("jwt-invalid-token").build();
        }
        String username = claims.get("username", String.class);
        if ("Jerry".equals(username)) {
          return failed(this).feedback("jwt-final-jerry-account").build();
        }
        if ("Tom".equals(username)) {
          return success(this).build();
        } else {
          return failed(this).feedback("jwt-final-not-tom").build();
        }
      } catch (RuntimeException e) {
        return failed(this).feedback("jwt-invalid-token").build();
      }
    }
  }
}
