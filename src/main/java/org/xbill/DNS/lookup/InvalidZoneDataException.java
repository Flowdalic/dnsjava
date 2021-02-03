// SPDX-License-Identifier: BSD-2-Clause
package org.xbill.DNS.lookup;

public class InvalidZoneDataException extends LookupFailedException {
  public InvalidZoneDataException(String message) {
    super(message);
  }
}
