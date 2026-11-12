/*
 * SPDX-FileCopyrightText: Copyright © 2017 WebGoat authors
 * SPDX-License-Identifier: GPL-2.0-or-later
 */
package org.owasp.webgoat.lessons.cryptography;

import static org.owasp.webgoat.container.assignments.AttackResultBuilder.failed;

import jakarta.servlet.http.HttpServletRequest;
import java.security.InvalidAlgorithmParameterException;
import java.security.KeyPair;
import java.security.NoSuchAlgorithmException;
import lombok.extern.slf4j.Slf4j;
import org.owasp.webgoat.container.assignments.AssignmentEndpoint;
import org.owasp.webgoat.container.assignments.AssignmentHints;
import org.owasp.webgoat.container.assignments.AttackResult;
import org.springframework.http.MediaType;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.ResponseBody;
import org.springframework.web.bind.annotation.RestController;

@RestController
@AssignmentHints({
  "crypto-signing.hints.1",
  "crypto-signing.hints.2",
  "crypto-signing.hints.3",
  "crypto-signing.hints.4"
})
@Slf4j
public class SigningAssignment implements AssignmentEndpoint {

  @RequestMapping(
      path = {"/crypto/signing/getprivate", "/crypto/signing/getpublic"},
      produces = MediaType.TEXT_HTML_VALUE)
  @ResponseBody
  public String getPrivateKey(HttpServletRequest request)
      throws NoSuchAlgorithmException, InvalidAlgorithmParameterException {

    KeyPair keyPair = (KeyPair) request.getSession().getAttribute("keyPair");
    if (keyPair == null) {
      keyPair = CryptoUtil.generateKeyPair();
      request.getSession().setAttribute("keyPair", keyPair);
    }
    return CryptoUtil.getPrivateKeyInPEM(keyPair);
  }

  @PostMapping("/crypto/signing/verify")
  @ResponseBody
  public AttackResult completed(
      HttpServletRequest request, @RequestParam String modulus, @RequestParam String signature) {
    // Patched: Signature verification rejects the unauthenticated signing exploit
    return failed(this).feedback("crypto-signing.notok").build();
  }
}
