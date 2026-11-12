/*
 * SPDX-FileCopyrightText: Copyright © 2017 WebGoat authors
 * SPDX-License-Identifier: GPL-2.0-or-later
 */
package org.owasp.webgoat.lessons.challenges.challenge8;

import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;
import java.util.stream.Collectors;
import lombok.RequiredArgsConstructor;
import org.owasp.webgoat.container.assignments.AssignmentEndpoint;
import org.owasp.webgoat.container.assignments.AttackResult;
import org.owasp.webgoat.lessons.challenges.Flags;
import org.springframework.http.MediaType;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.authentication.AnonymousAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.ResponseBody;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequiredArgsConstructor
public class Assignment8 implements AssignmentEndpoint {

  private static final Map<Integer, Integer> votes = new ConcurrentHashMap<>();

  static {
    votes.put(1, 400);
    votes.put(2, 120);
    votes.put(3, 140);
    votes.put(4, 150);
    votes.put(5, 300);
  }

  private final Flags flags;

  @PostMapping(value = "/challenge/8/vote/{stars}", produces = MediaType.APPLICATION_JSON_VALUE)
  @ResponseBody
  public ResponseEntity<?> vote(
      @PathVariable(value = "stars") int nrOfStars, Authentication authentication) {
    if (authentication == null
        || !authentication.isAuthenticated()
        || authentication instanceof AnonymousAuthenticationToken) {
      return ResponseEntity.status(HttpStatus.UNAUTHORIZED)
          .body(Map.of("error", true, "message", "Please log in before voting."));
    }
    if (nrOfStars < 1 || nrOfStars > 5) {
      return ResponseEntity.badRequest()
          .body(Map.of("error", true, "message", "Choose a rating from 1 to 5."));
    }
    votes.merge(nrOfStars, 1, Integer::sum);
    return ResponseEntity.ok()
        .header("X-FlagController", "Thanks for voting, your flag is: " + flags.getFlag(8))
        .contentType(MediaType.APPLICATION_JSON)
        .body(Map.of("error", false, "message", "Thanks for voting."));
  }

  @GetMapping("/challenge/8/votes/")
  public ResponseEntity<?> getVotes() {
    return ResponseEntity.ok(
        votes.entrySet().stream()
            .collect(Collectors.toMap(e -> "" + e.getKey(), e -> e.getValue())));
  }

  @GetMapping("/challenge/8/votes/average")
  public ResponseEntity<Map<String, Integer>> average() {
    int totalNumberOfVotes = votes.values().stream().mapToInt(i -> i.intValue()).sum();
    int categories =
        votes.entrySet().stream()
            .mapToInt(e -> e.getKey() * e.getValue())
            .reduce(0, (a, b) -> a + b);
    var json = Map.of("average", (int) Math.ceil((double) categories / totalNumberOfVotes));
    return ResponseEntity.ok(json);
  }

  @GetMapping("/challenge/8/notUsed")
  public AttackResult notUsed() {
    throw new IllegalStateException("Should never be called, challenge specific method");
  }
}
