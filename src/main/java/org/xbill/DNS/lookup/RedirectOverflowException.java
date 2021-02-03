// SPDX-License-Identifier: BSD-2-Clause
package org.xbill.DNS.lookup;

public class RedirectOverflowException extends LookupFailedException {
  public RedirectOverflowException(String message) {
    super(message);
  }
}
