/*
 * SPDX-FileCopyrightText: Copyright © 2023 WebGoat authors
 * SPDX-License-Identifier: GPL-2.0-or-later
 */
package org.owasp.webgoat.lessons.jwt.claimmisuse;

import static org.owasp.webgoat.container.assignments.AttackResultBuilder.failed;
import static org.owasp.webgoat.container.assignments.AttackResultBuilder.success;

import com.auth0.jwk.JwkException;
import com.auth0.jwk.JwkProviderBuilder;
import com.auth0.jwt.JWT;
import com.auth0.jwt.algorithms.Algorithm;
import com.auth0.jwt.exceptions.JWTVerificationException;
import java.net.MalformedURLException;
import java.net.URI;
import java.net.URL;
import java.security.interfaces.RSAPublicKey;
import java.util.concurrent.TimeUnit;
import org.apache.commons.lang3.StringUtils;
import org.owasp.webgoat.container.assignments.AssignmentEndpoint;
import org.owasp.webgoat.container.assignments.AssignmentHints;
import org.owasp.webgoat.container.assignments.AttackResult;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.ResponseBody;
import org.springframework.web.bind.annotation.RestController;

@RequestMapping("/JWT/")
@RestController
@AssignmentHints({
  "jwt-jku-hint1",
  "jwt-jku-hint2",
  "jwt-jku-hint3",
  "jwt-jku-hint4",
  "jwt-jku-hint5"
})
public class JWTHeaderJKUEndpoint implements AssignmentEndpoint {
  private final String trustedJwksUrl;

  public JWTHeaderJKUEndpoint(
      @Value("${jwt.jku.trusted-jwks-url:}") String trustedJwksUrl) {
    this.trustedJwksUrl = trustedJwksUrl;
  }

  @PostMapping("jku/follow/{user}")
  public @ResponseBody String follow(@PathVariable("user") String user) {
    if ("Jerry".equals(user)) {
      return "Following yourself seems redundant";
    } else {
      return "You are now following Tom";
    }
  }

  @PostMapping("jku/delete")
  public @ResponseBody AttackResult resetVotes(@RequestParam("token") String token) {
    if (StringUtils.isEmpty(token)) {
      return failed(this).feedback("jwt-invalid-token").build();
    } else {
      try {
        var decodedJWT = JWT.decode(token);
        URL trustedUrl = trustedJwksUrl();
        var jwkProvider =
            new JwkProviderBuilder(trustedUrl).cached(10, 10, TimeUnit.MINUTES).build();
        var jwk = jwkProvider.get(decodedJWT.getKeyId());
        var algorithm = Algorithm.RSA256((RSAPublicKey) jwk.getPublicKey());
        JWT.require(algorithm)
            .withIssuer("WebGoat Token Builder")
            .withAudience("webgoat.org")
            .build()
            .verify(decodedJWT);

        var username = decodedJWT.getClaims().get("username").asString();
        if ("Jerry".equals(username)) {
          return failed(this).feedback("jwt-final-jerry-account").build();
        }
        if ("Tom".equals(username)) {
          return success(this).build();
        } else {
          return failed(this).feedback("jwt-final-not-tom").build();
        }
      } catch (MalformedURLException
          | IllegalArgumentException
          | JWTVerificationException
          | JwkException e) {
        return failed(this).feedback("jwt-invalid-token").build();
      }
    }
  }

  private URL trustedJwksUrl() throws MalformedURLException {
    if (StringUtils.isBlank(trustedJwksUrl)) {
      throw new MalformedURLException("Trusted JWKS URL is not configured");
    }
    try {
      URI uri = URI.create(trustedJwksUrl);
      if (!"https".equalsIgnoreCase(uri.getScheme())
          || uri.getHost() == null
          || uri.getUserInfo() != null) {
        throw new MalformedURLException("Trusted JWKS URL is invalid");
      }
      return uri.toURL();
    } catch (IllegalArgumentException e) {
      throw new MalformedURLException("Trusted JWKS URL is invalid");
    }
  }
}
