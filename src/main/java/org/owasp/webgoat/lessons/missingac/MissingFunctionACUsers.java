/*
 * SPDX-FileCopyrightText: Copyright © 2017 WebGoat authors
 * SPDX-License-Identifier: GPL-2.0-or-later
 */
package org.owasp.webgoat.lessons.missingac;

import static org.owasp.webgoat.lessons.missingac.MissingFunctionAC.PASSWORD_SALT_ADMIN;
import static org.owasp.webgoat.lessons.missingac.MissingFunctionAC.PASSWORD_SALT_SIMPLE;

import java.util.ArrayList;
import java.util.List;
import java.util.stream.Collectors;
import lombok.AllArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.owasp.webgoat.container.users.WebGoatUser;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.Authentication;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.ResponseBody;
import org.springframework.web.servlet.ModelAndView;

/** Created by jason on 1/5/17. */
@Controller
@AllArgsConstructor
@Slf4j
public class MissingFunctionACUsers {
  private static final PasswordEncoder PASSWORD_ENCODER = new BCryptPasswordEncoder();

  private final MissingAccessControlUserRepository userRepository;

  @GetMapping(path = {"access-control/users"})
  public ModelAndView listUsers(
      Authentication authentication, jakarta.servlet.http.HttpServletResponse response) {

    ModelAndView model = new ModelAndView();
    model.setViewName("list_users");
    if (!isAuthenticatedAdmin(authentication)) {
      response.setStatus(HttpStatus.FORBIDDEN.value());
      model.addObject("numUsers", 0);
      model.addObject("allUsers", List.of());
      return model;
    }
    List<User> allUsers = userRepository.findAllUsers();
    model.addObject("numUsers", allUsers.size());
    // add display user objects in place of direct users
    List<DisplayUser> displayUsers = new ArrayList<>();
    for (User user : allUsers) {
      displayUsers.add(new DisplayUser(user, PASSWORD_SALT_SIMPLE));
    }
    model.addObject("allUsers", displayUsers);

    return model;
  }

  @GetMapping(
      path = {"access-control/users"},
      produces = "application/json")
  @ResponseBody
  public ResponseEntity<List<DisplayUser>> usersService(Authentication authentication) {
    if (!isAuthenticatedAdmin(authentication)) {
      return ResponseEntity.status(HttpStatus.FORBIDDEN).build();
    }
    return ResponseEntity.ok(
        userRepository.findAllUsers().stream()
            .map(user -> new DisplayUser(user, PASSWORD_SALT_SIMPLE))
            .collect(Collectors.toList()));
  }

  @GetMapping(
      path = {"access-control/users-admin-fix"},
      produces = "application/json")
  @ResponseBody
  public ResponseEntity<List<DisplayUser>> usersFixed(Authentication authentication) {
    if (isAuthenticatedAdmin(authentication)) {
      return ResponseEntity.ok(
          userRepository.findAllUsers().stream()
              .map(user -> new DisplayUser(user, PASSWORD_SALT_ADMIN))
              .collect(Collectors.toList()));
    }
    return ResponseEntity.status(HttpStatus.FORBIDDEN).build();
  }

  @PostMapping(
      path = {"access-control/users", "access-control/users-admin-fix"},
      consumes = "application/json",
      produces = "application/json")
  @ResponseBody
  public ResponseEntity<Void> addUser(
      @RequestBody User newUser, Authentication authentication) {
    try {
      if (!isAuthenticatedAdmin(authentication)) {
        return ResponseEntity.status(HttpStatus.FORBIDDEN).build();
      }
      if (newUser == null || newUser.getUsername() == null || newUser.getPassword() == null) {
        return ResponseEntity.badRequest().build();
      }
      if (newUser.getUsername().isBlank()
          || newUser.getPassword().length() < 12
          || newUser.getPassword().length() > 128) {
        return ResponseEntity.badRequest().build();
      }
      newUser.setAdmin(false);
      newUser.setPassword(PASSWORD_ENCODER.encode(newUser.getPassword()));
      userRepository.save(newUser);
      return ResponseEntity.status(HttpStatus.CREATED).build();
    } catch (Exception ex) {
      log.error("Error creating new User", ex);
      return ResponseEntity.internalServerError().build();
    }

    // @RequestMapping(path = {"user/{username}","/"}, method = RequestMethod.DELETE, consumes =
    // "application/json", produces = "application/json")
    // TODO implement delete method with id param and authorization

  }

  private boolean isAuthenticatedAdmin(Authentication authentication) {
    return authentication != null
        && authentication.isAuthenticated()
        && authentication.getAuthorities().stream()
            .anyMatch(
                authority -> WebGoatUser.ROLE_ADMIN.equals(authority.getAuthority()));
  }
}
