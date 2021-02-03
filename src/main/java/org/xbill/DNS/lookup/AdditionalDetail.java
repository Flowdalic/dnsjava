// SPDX-License-Identifier: BSD-2-Clause
package org.xbill.DNS.lookup;

public enum AdditionalDetail {
  /**
   * An empty response was returned because the resolver returned the NXDOMAIN status code, meaning
   * that there was no dns data associated with the provided name.
   */
  NXDOMAIN,
  /**
   * An empty response was returned because although there was a response for the specified name it
   * was not of the Type requested.
   */
  NXRRSET,
}
