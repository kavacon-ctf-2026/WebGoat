/*
 * SPDX-FileCopyrightText: Copyright © 2014 WebGoat authors
 * SPDX-License-Identifier: GPL-2.0-or-later
 */
package org.owasp.webgoat.lessons.vulnerablecomponents;

import static org.owasp.webgoat.container.assignments.AttackResultBuilder.failed;
import static org.owasp.webgoat.container.assignments.AttackResultBuilder.success;

import java.io.StringReader;
import java.util.HashSet;
import java.util.Set;
import javax.xml.XMLConstants;
import javax.xml.parsers.DocumentBuilderFactory;
import org.apache.commons.lang3.StringUtils;
import org.owasp.webgoat.container.assignments.AssignmentEndpoint;
import org.owasp.webgoat.container.assignments.AssignmentHints;
import org.owasp.webgoat.container.assignments.AttackResult;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.ResponseBody;
import org.springframework.web.bind.annotation.RestController;
import org.w3c.dom.Element;
import org.w3c.dom.Node;
import org.xml.sax.InputSource;

@RestController
@AssignmentHints({"vulnerable.hint"})
public class VulnerableComponentsLesson implements AssignmentEndpoint {

  @PostMapping("/VulnerableComponents/attack1")
  public @ResponseBody AttackResult completed(@RequestParam String payload) {
    try {
      if (StringUtils.isEmpty(payload) || payload.length() > 8192) {
        return failed(this).feedback("vulnerable-components.close").build();
      }
      parseContact(payload);
    } catch (Exception ex) {
      return failed(this).feedback("vulnerable-components.close").build();
    }
    return success(this).feedback("vulnerable-components.success").build();
  }

  private Contact parseContact(String payload) throws Exception {
    DocumentBuilderFactory factory = DocumentBuilderFactory.newInstance();
    factory.setFeature(XMLConstants.FEATURE_SECURE_PROCESSING, true);
    factory.setFeature("http://apache.org/xml/features/disallow-doctype-decl", true);
    factory.setFeature("http://xml.org/sax/features/external-general-entities", false);
    factory.setFeature("http://xml.org/sax/features/external-parameter-entities", false);
    factory.setXIncludeAware(false);
    factory.setExpandEntityReferences(false);
    factory.setAttribute(XMLConstants.ACCESS_EXTERNAL_DTD, "");
    factory.setAttribute(XMLConstants.ACCESS_EXTERNAL_SCHEMA, "");

    var builder = factory.newDocumentBuilder();
    builder.setEntityResolver((publicId, systemId) -> new InputSource(new StringReader("")));
    Element root = builder.parse(new InputSource(new StringReader(payload))).getDocumentElement();
    if (root == null || !"contact".equals(root.getTagName()) || root.hasAttributes()) {
      throw new IllegalArgumentException("Invalid contact document");
    }

    ContactImpl contact = new ContactImpl();
    var fields = new HashSet<String>();
    for (Node node = root.getFirstChild(); node != null; node = node.getNextSibling()) {
      if (node.getNodeType() == Node.TEXT_NODE && node.getTextContent().isBlank()) {
        continue;
      }
      if (node.getNodeType() != Node.ELEMENT_NODE) {
        throw new IllegalArgumentException("Unexpected contact content");
      }
      Element field = (Element) node;
      if (field.hasAttributes() || !fields.add(field.getTagName())) {
        throw new IllegalArgumentException("Unexpected contact field metadata");
      }

      StringBuilder text = new StringBuilder();
      for (Node child = field.getFirstChild(); child != null; child = child.getNextSibling()) {
        if (child.getNodeType() == Node.TEXT_NODE || child.getNodeType() == Node.CDATA_SECTION_NODE) {
          text.append(child.getNodeValue());
        } else {
          throw new IllegalArgumentException("Contact fields must contain scalar text");
        }
      }
      String value = text.toString();
      switch (field.getTagName()) {
        case "id" -> contact.setId(Integer.valueOf(value.trim()));
        case "firstName" -> contact.setFirstName(value);
        case "lastName" -> contact.setLastName(value);
        case "email" -> contact.setEmail(value);
        default -> throw new IllegalArgumentException("Unexpected contact field");
      }
    }
    if (!fields.equals(Set.of("id", "firstName", "lastName", "email"))) {
      throw new IllegalArgumentException("A complete contact is required");
    }
    return contact;
  }
}
