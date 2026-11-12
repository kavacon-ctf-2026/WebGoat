/*
 * SPDX-FileCopyrightText: Copyright © 2020 WebGoat authors
 * SPDX-License-Identifier: GPL-2.0-or-later
 */
package org.owasp.webgoat.lessons.challenges.challenge1;

import java.io.IOException;
import org.springframework.core.io.ClassPathResource;
import org.springframework.http.MediaType;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.ResponseBody;
import org.springframework.web.bind.annotation.RestController;

import static org.springframework.web.bind.annotation.RequestMethod.GET;
import static org.springframework.web.bind.annotation.RequestMethod.POST;

@RestController
public class ImageServlet {

  @RequestMapping(
      method = {GET, POST},
      value = "/challenge/logo",
      produces = MediaType.IMAGE_PNG_VALUE)
  @ResponseBody
  public byte[] logo() throws IOException {
    try (var image = new ClassPathResource("lessons/challenges/images/webgoat2.png").getInputStream()) {
      return image.readAllBytes();
    }
  }
}
