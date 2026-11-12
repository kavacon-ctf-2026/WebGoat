/*
 * SPDX-FileCopyrightText: Copyright © 2019 WebGoat authors
 * SPDX-License-Identifier: GPL-2.0-or-later
 */
package org.dummy.insecure.framework;

import java.io.ObjectInputStream;
import java.io.Serializable;
import java.time.LocalDateTime;

public class VulnerableTaskHolder implements Serializable {

  private static final long serialVersionUID = 2;

  private String taskName;
  private String taskAction;
  private LocalDateTime requestedExecutionTime;

  public VulnerableTaskHolder(String taskName, String taskAction) {
    super();
    this.taskName = taskName;
    this.taskAction = taskAction;
    this.requestedExecutionTime = LocalDateTime.now();
  }

  /** Identifies the lesson's inert demo action; this value is never executed. */
  public boolean isExpectedSafeDemo() {
    return "sleep 5".equals(taskAction);
  }

  @Override
  public String toString() {
    return "VulnerableTaskHolder [taskName="
        + taskName
        + ", taskAction="
        + taskAction
        + ", requestedExecutionTime="
        + requestedExecutionTime
        + "]";
  }

  /** Restore data only; deserialization must never perform the requested action. */
  private void readObject(ObjectInputStream stream) throws Exception {
    stream.defaultReadObject();
    if (taskName == null
        || taskName.length() > 128
        || taskAction == null
        || taskAction.length() > 256
        || requestedExecutionTime == null) {
      throw new IllegalArgumentException("invalid task data");
    }
  }
}
