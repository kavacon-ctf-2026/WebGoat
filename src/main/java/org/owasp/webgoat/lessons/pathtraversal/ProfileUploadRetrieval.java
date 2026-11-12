/*
 * SPDX-FileCopyrightText: Copyright © 2020 WebGoat authors
 * SPDX-License-Identifier: GPL-2.0-or-later
 */
package org.owasp.webgoat.lessons.pathtraversal;

import static org.owasp.webgoat.container.assignments.AttackResultBuilder.failed;
import static org.owasp.webgoat.container.assignments.AttackResultBuilder.success;

import jakarta.annotation.PostConstruct;
import jakarta.servlet.http.HttpServletRequest;
import java.io.File;
import java.io.IOException;
import java.io.InputStream;
import java.net.URI;
import java.net.URISyntaxException;
import java.nio.file.Files;
import java.nio.file.LinkOption;
import java.nio.file.Path;
import java.util.Base64;
import lombok.extern.slf4j.Slf4j;
import org.apache.commons.lang3.RandomUtils;
import org.owasp.webgoat.container.assignments.AssignmentEndpoint;
import org.owasp.webgoat.container.assignments.AssignmentHints;
import org.owasp.webgoat.container.assignments.AttackResult;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.core.io.ClassPathResource;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.ResponseBody;
import org.springframework.web.bind.annotation.RestController;

@RestController
@AssignmentHints({
  "path-traversal-profile-retrieve.hint1",
  "path-traversal-profile-retrieve.hint2",
  "path-traversal-profile-retrieve.hint3",
  "path-traversal-profile-retrieve.hint4",
  "path-traversal-profile-retrieve.hint5",
  "path-traversal-profile-retrieve.hint6"
})
@Slf4j
public class ProfileUploadRetrieval implements AssignmentEndpoint {
  private final File catPicturesDirectory;

  public ProfileUploadRetrieval(@Value("${webgoat.server.directory}") String webGoatHomeDirectory) {
    this.catPicturesDirectory =
        Path.of(webGoatHomeDirectory)
            .toAbsolutePath()
            .normalize()
            .resolve("PathTraversal")
            .resolve("cats")
            .toFile();
  }

  @PostConstruct
  public void initAssignment() {
    Path imageDirectory = catPicturesDirectory.toPath().toAbsolutePath().normalize();
    if (hasSymbolicLinkComponent(imageDirectory)) {
      log.error("Refusing to initialize the picture gallery through a symbolic link");
      return;
    }
    try {
      Files.createDirectories(imageDirectory);
    } catch (IOException e) {
      log.error("Unable to create the picture gallery", e);
      return;
    }
    if (hasSymbolicLinkComponent(imageDirectory)) {
      log.error("Refusing to initialize the picture gallery through a symbolic link");
      return;
    }

    for (int i = 1; i <= 10; i++) {
      try (InputStream is =
          new ClassPathResource("lessons/pathtraversal/images/cats/" + i + ".jpg")
              .getInputStream()) {
        Files.copy(
            is,
            catPicturesDirectory.toPath().resolve(i + ".jpg"),
            java.nio.file.StandardCopyOption.REPLACE_EXISTING);
      } catch (Exception e) {
        log.error("Unable to copy pictures" + e.getMessage());
      }
    }
  }

  @PostMapping("/PathTraversal/random")
  @ResponseBody
  public AttackResult execute(
      @RequestParam(value = "id", required = false) String idParameter) {
    if (validPictureId(idParameter) != null) {
      return success(this).feedback("path-traversal-retrieval-success").build();
    }
    return failed(this).feedback("path-traversal-retrieval-invalid").build();
  }

  @GetMapping("/PathTraversal/random-picture")
  @ResponseBody
  public ResponseEntity<?> getProfilePicture(HttpServletRequest request) {
    try {
      String idParameter = request.getParameter("id");
      Integer selectedId;
      if (idParameter == null) {
        selectedId = RandomUtils.nextInt(1, 11);
      } else {
        selectedId = validPictureId(idParameter);
      }
      if (selectedId == null) {
        return ResponseEntity.badRequest().build();
      }
      int id = selectedId;

      Path configuredImageDirectory = catPicturesDirectory.toPath().toAbsolutePath().normalize();
      if (hasSymbolicLinkComponent(configuredImageDirectory)) {
        return ResponseEntity.notFound().build();
      }

      Path imageRoot = configuredImageDirectory.toRealPath();
      Path catPicture = imageRoot.resolve(id + ".jpg").normalize();
      if (!catPicture.startsWith(imageRoot)
          || Files.isSymbolicLink(catPicture)
          || !Files.isRegularFile(catPicture, LinkOption.NOFOLLOW_LINKS)) {
        return ResponseEntity.notFound().build();
      }

      if (Files.exists(catPicture, LinkOption.NOFOLLOW_LINKS)) {
        return ResponseEntity.ok()
            .contentType(MediaType.parseMediaType(MediaType.IMAGE_JPEG_VALUE))
            .location(new URI("/PathTraversal/random-picture?id=" + id))
            .body(Base64.getEncoder().encode(Files.readAllBytes(catPicture)));
      }
      return ResponseEntity.notFound().build();
    } catch (IOException | URISyntaxException e) {
      log.error("Image not found", e);
    }

    return ResponseEntity.badRequest().build();
  }

  private Integer validPictureId(String idParameter) {
    if (idParameter == null) {
      return null;
    }
    try {
      int id = Integer.parseInt(idParameter);
      return id >= 1 && id <= 10 && Integer.toString(id).equals(idParameter) ? id : null;
    } catch (NumberFormatException e) {
      return null;
    }
  }

  private boolean hasSymbolicLinkComponent(Path path) {
    Path normalized = path.toAbsolutePath().normalize();
    Path parent = normalized.getParent();
    // The configured WebGoat data directory is trusted. Reject links in the
    // gallery directory and its lesson-owned parent, where uploads may exist.
    return Files.isSymbolicLink(normalized) || (parent != null && Files.isSymbolicLink(parent));
  }
}
