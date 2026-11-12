/*
 * SPDX-FileCopyrightText: Copyright © 2020 WebGoat authors
 * SPDX-License-Identifier: GPL-2.0-or-later
 */
package org.owasp.webgoat.lessons.pathtraversal;

import static org.owasp.webgoat.container.assignments.AttackResultBuilder.failed;
import static org.owasp.webgoat.container.assignments.AttackResultBuilder.informationMessage;

import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.InvalidPathException;
import java.nio.file.LinkOption;
import java.nio.file.Path;
import java.nio.file.StandardCopyOption;
import java.nio.file.StandardOpenOption;
import java.util.Arrays;
import java.util.Base64;
import java.util.Comparator;
import java.util.Locale;
import lombok.Getter;
import lombok.SneakyThrows;
import org.owasp.webgoat.container.CurrentUsername;
import org.owasp.webgoat.container.assignments.AssignmentEndpoint;
import org.owasp.webgoat.container.assignments.AttackResult;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.util.FileCopyUtils;
import org.springframework.util.StringUtils;
import org.springframework.web.multipart.MultipartFile;

@Getter
public class ProfileUploadBase implements AssignmentEndpoint {

  private final String webGoatHomeDirectory;

  public ProfileUploadBase(String webGoatHomeDirectory) {
    this.webGoatHomeDirectory = webGoatHomeDirectory;
  }

  protected AttackResult execute(MultipartFile file, String fullName, String username) {
    if (file.isEmpty()) {
      return failed(this).feedback("path-traversal-profile-empty-file").build();
    }
    String safeFileName = safeFileName(fullName);
    if (safeFileName == null) {
      return failed(this).feedback("path-traversal-profile-empty-name").build();
    }

    try {
      Path uploadDirectory = uploadDirectoryForUser(username);
      Path uploadedFile = uploadDirectory.resolve(safeFileName).normalize();
      if (!uploadedFile.startsWith(uploadDirectory)) {
        return failed(this).feedback("path-traversal-profile-empty-name").build();
      }

      // Replace a prior upload atomically. Moving over a symlink replaces the
      // link itself rather than writing through it.
      Path stagedFile = Files.createTempFile(uploadDirectory, ".profile-", ".tmp");
      try {
        Files.write(
            stagedFile,
            file.getBytes(),
            StandardOpenOption.WRITE,
            StandardOpenOption.TRUNCATE_EXISTING);
        Files.move(
            stagedFile,
            uploadedFile,
            StandardCopyOption.REPLACE_EXISTING);
      } finally {
        Files.deleteIfExists(stagedFile);
      }

      if (isProfileImage(uploadedFile)) {
        deleteOtherProfileImages(uploadDirectory, uploadedFile);
      }

      return informationMessage(this)
          .feedback("path-traversal-profile-updated")
          .build();

    } catch (IOException e) {
      return failed(this).feedback("path-traversal-profile-upload-failed").build();
    }
  }

  @SneakyThrows
  protected File cleanupAndCreateDirectoryForUser(String username) {
    // Keep existing user uploads. The old implementation recursively deleted
    // this directory on every request, which was unnecessary and made path
    // handling harder to reason about.
    return uploadDirectoryForUser(username).toFile();
  }

  protected Path uploadDirectoryForUser(String username) throws IOException {
    if (username == null || username.isBlank()) {
      throw new IOException("Invalid user directory");
    }

    Path root = Path.of(webGoatHomeDirectory).toAbsolutePath().normalize();
    Path uploadRoot = root.resolve("PathTraversal").normalize();
    Files.createDirectories(uploadRoot);
    Path realUploadRoot = uploadRoot.toRealPath();

    Path userDirectory = uploadRoot.resolve(username).normalize();
    if (!userDirectory.startsWith(uploadRoot) || userDirectory.equals(uploadRoot)) {
      throw new IOException("Invalid user directory");
    }
    Files.createDirectories(userDirectory);
    Path realUserDirectory = userDirectory.toRealPath();
    if (!realUserDirectory.startsWith(realUploadRoot)) {
      throw new IOException("Invalid user directory");
    }
    return realUserDirectory;
  }

  private String safeFileName(String fileName) {
    if (StringUtils.isEmpty(fileName)) {
      return null;
    }

    try {
      Path parsed = Path.of(fileName);
      if (parsed.isAbsolute()
          || parsed.getNameCount() != 1
          || fileName.matches("^[A-Za-z]:.*")
          || fileName.contains("/")
          || fileName.contains("\\")
          || fileName.equals(".")
          || fileName.equals("..")) {
        return null;
      }
      return parsed.toString();
    } catch (InvalidPathException e) {
      return null;
    }
  }

  public ResponseEntity<?> getProfilePicture(@CurrentUsername String username) {
    return ResponseEntity.ok()
        .contentType(MediaType.parseMediaType(MediaType.IMAGE_JPEG_VALUE))
        .body(getProfilePictureAsBase64(username));
  }

  protected byte[] getProfilePictureAsBase64(String username) {
    File profilePictureDirectory;
    try {
      profilePictureDirectory = uploadDirectoryForUser(username).toFile();
    } catch (IOException e) {
      return defaultImage();
    }
    var profileDirectoryFiles = profilePictureDirectory.listFiles();

    if (profileDirectoryFiles != null && profileDirectoryFiles.length > 0) {
      return Arrays.stream(profileDirectoryFiles)
          .filter(file -> isProfileImage(file.toPath()))
          .filter(file -> Files.isRegularFile(file.toPath(), LinkOption.NOFOLLOW_LINKS))
          .sorted(Comparator.comparing(File::getName))
          .findFirst()
          .map(
              file -> {
                try (var inputStream = new FileInputStream(file)) {
                  return Base64.getEncoder().encode(FileCopyUtils.copyToByteArray(inputStream));
                } catch (IOException e) {
                  return defaultImage();
                }
              })
          .orElse(defaultImage());
    } else {
      return defaultImage();
    }
  }

  protected boolean isProfileImage(Path path) {
    String name = path.getFileName().toString().toLowerCase(Locale.ROOT);
    return name.endsWith(".jpg") || name.endsWith(".png");
  }

  protected void deleteOtherProfileImages(Path directory, Path imageToKeep) throws IOException {
    Path normalizedImageToKeep = imageToKeep.toAbsolutePath().normalize();
    try (var entries = Files.newDirectoryStream(directory)) {
      for (Path entry : entries) {
        if (entry.toAbsolutePath().normalize().equals(normalizedImageToKeep)
            || !isProfileImage(entry)) {
          continue;
        }
        if (Files.isSymbolicLink(entry)
            || Files.isRegularFile(entry, LinkOption.NOFOLLOW_LINKS)) {
          Files.deleteIfExists(entry);
        }
      }
    }
  }

  protected boolean hasSymbolicLinkComponent(Path root, Path target) {
    Path normalizedRoot = root.toAbsolutePath().normalize();
    Path normalizedTarget = target.toAbsolutePath().normalize();
    if (!normalizedTarget.startsWith(normalizedRoot)) {
      return true;
    }

    Path current = normalizedRoot;
    for (Path component : normalizedRoot.relativize(normalizedTarget)) {
      current = current.resolve(component);
      if (Files.isSymbolicLink(current)) {
        return true;
      }
    }
    return false;
  }

  @SneakyThrows
  protected byte[] defaultImage() {
    var inputStream = getClass().getResourceAsStream("/images/account.png");
    return Base64.getEncoder().encode(FileCopyUtils.copyToByteArray(inputStream));
  }
}
