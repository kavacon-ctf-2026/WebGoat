/*
 * SPDX-FileCopyrightText: Copyright © 2021 WebGoat authors
 * SPDX-License-Identifier: GPL-2.0-or-later
 */
package org.owasp.webgoat.lessons.pathtraversal;

import static org.owasp.webgoat.container.assignments.AttackResultBuilder.failed;
import static org.owasp.webgoat.container.assignments.AttackResultBuilder.success;
import static org.springframework.http.MediaType.ALL_VALUE;
import static org.springframework.http.MediaType.APPLICATION_JSON_VALUE;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.StandardCopyOption;
import java.nio.file.StandardOpenOption;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.Locale;
import java.util.zip.ZipEntry;
import java.util.zip.ZipInputStream;
import lombok.SneakyThrows;
import lombok.extern.slf4j.Slf4j;
import org.owasp.webgoat.container.CurrentUsername;
import org.owasp.webgoat.container.assignments.AssignmentHints;
import org.owasp.webgoat.container.assignments.AttackResult;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.ResponseBody;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.multipart.MultipartFile;

@RestController
@AssignmentHints({
  "path-traversal-zip-slip.hint1",
  "path-traversal-zip-slip.hint2",
  "path-traversal-zip-slip.hint3",
  "path-traversal-zip-slip.hint4"
})
@Slf4j
public class ProfileZipSlip extends ProfileUploadBase {

  private static final int MAX_ARCHIVE_ENTRIES = 256;
  private static final long MAX_COMPRESSED_SIZE = 2 * 1024 * 1024;
  private static final long MAX_EXPANDED_SIZE = 8 * 1024 * 1024;

  public ProfileZipSlip(@Value("${webgoat.server.directory}") String webGoatHomeDirectory) {
    super(webGoatHomeDirectory);
  }

  @PostMapping(
      value = "/PathTraversal/zip-slip",
      consumes = ALL_VALUE,
      produces = APPLICATION_JSON_VALUE)
  @ResponseBody
  public AttackResult uploadFileHandler(
      @RequestParam("uploadedFileZipSlip") MultipartFile file, @CurrentUsername String username) {
    String originalFilename = file.getOriginalFilename();
    if (originalFilename == null
        || !originalFilename.toLowerCase(Locale.ROOT).endsWith(".zip")
        || file.getSize() > MAX_COMPRESSED_SIZE) {
      return failed(this).feedback("path-traversal-zip-slip.no-zip").build();
    } else {
      return processZipUpload(file, username);
    }
  }

  @SneakyThrows
  private AttackResult processZipUpload(MultipartFile file, String username) {
    Path uploadDirectory = uploadDirectoryForUser(username);
    var currentImage = getProfilePictureAsBase64(username);

    try (ZipInputStream zip = new ZipInputStream(new ByteArrayInputStream(file.getBytes()))) {
      List<ArchiveEntry> entries = new ArrayList<>();
      long totalExpandedSize = 0;
      ZipEntry entry;
      while ((entry = zip.getNextEntry()) != null) {
        if (entries.size() >= MAX_ARCHIVE_ENTRIES
            || entry.getName() == null
            || entry.getName().isBlank()
            || entry.getName().contains("\\")
            || entry.getName().matches("^[A-Za-z]:.*")) {
          return failed(this).feedback("path-traversal-zip-slip.no-zip").build();
        }

        Path relativePath = Path.of(entry.getName());
        boolean hasParentSegment = false;
        for (Path component : relativePath) {
          if ("..".equals(component.toString())) {
            hasParentSegment = true;
            break;
          }
        }
        Path destination = uploadDirectory.resolve(relativePath).normalize();
        if (relativePath.isAbsolute()
            || hasParentSegment
            || destination.equals(uploadDirectory)
            || !destination.startsWith(uploadDirectory)
            || hasSymbolicLinkComponent(uploadDirectory, destination)) {
          return failed(this).feedback("path-traversal-zip-slip.no-zip").build();
        }

        if (entry.isDirectory()) {
          entries.add(new ArchiveEntry(destination, new byte[0], true));
          continue;
        }

        ByteArrayOutputStream contents = new ByteArrayOutputStream();
        byte[] buffer = new byte[8192];
        int read;
        while ((read = zip.read(buffer)) != -1) {
          totalExpandedSize += read;
          if (totalExpandedSize > MAX_EXPANDED_SIZE) {
            return failed(this).feedback("path-traversal-zip-slip.no-zip").build();
          }
          contents.write(buffer, 0, read);
        }
        entries.add(new ArchiveEntry(destination, contents.toByteArray(), false));
      }

      // Validate the complete archive before writing any entry, then stage each
      // file inside the user's directory and replace the target in place.
      for (ArchiveEntry archiveEntry : entries) {
        if (hasSymbolicLinkComponent(uploadDirectory, archiveEntry.path())) {
          return failed(this).feedback("path-traversal-zip-slip.no-zip").build();
        }
        if (archiveEntry.directory()) {
          Files.createDirectories(archiveEntry.path());
        } else {
          Files.createDirectories(archiveEntry.path().getParent());
          if (hasSymbolicLinkComponent(uploadDirectory, archiveEntry.path())) {
            return failed(this).feedback("path-traversal-zip-slip.no-zip").build();
          }
          Path stagedFile = Files.createTempFile(uploadDirectory, ".zip-slip-", ".tmp");
          try {
            Files.write(
                stagedFile,
                archiveEntry.contents(),
                StandardOpenOption.WRITE,
                StandardOpenOption.TRUNCATE_EXISTING);
            Files.move(stagedFile, archiveEntry.path(), StandardCopyOption.REPLACE_EXISTING);
          } finally {
            Files.deleteIfExists(stagedFile);
          }
        }
      }

      Path activeImage =
          entries.stream()
              .filter(archiveEntry -> !archiveEntry.directory())
              .map(ArchiveEntry::path)
              .filter(path -> uploadDirectory.equals(path.getParent()))
              .filter(this::isProfileImage)
              .filter(path -> Files.isRegularFile(path, java.nio.file.LinkOption.NOFOLLOW_LINKS))
              .sorted()
              .findFirst()
              .orElse(null);
      if (activeImage != null) {
        deleteOtherProfileImages(uploadDirectory, activeImage);
      }

      return isSolved(currentImage, getProfilePictureAsBase64(username));
    } catch (IOException | RuntimeException e) {
      log.warn("Rejected invalid profile archive");
      return failed(this).feedback("path-traversal-zip-slip.no-zip").build();
    }
  }

  private record ArchiveEntry(Path path, byte[] contents, boolean directory) {}

  private AttackResult isSolved(byte[] currentImage, byte[] newImage) {
    if (Arrays.equals(currentImage, newImage)) {
      return failed(this).output("path-traversal-zip-slip.extracted").build();
    }
    return success(this).output("path-traversal-zip-slip.extracted").build();
  }

  @GetMapping("/PathTraversal/zip-slip/")
  @ResponseBody
  public ResponseEntity<?> getProfilePicture(@CurrentUsername String username) {
    return super.getProfilePicture(username);
  }

  @GetMapping("/PathTraversal/zip-slip/profile-image/{username}")
  @ResponseBody
  public ResponseEntity<?> getProfileImage(@PathVariable String username) {
    return ResponseEntity.notFound().build();
  }
}
