// SPDX-License-Identifier: BSD-2-Clause
package org.xbill.DNS.lookup;

import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import lombok.EqualsAndHashCode;
import lombok.ToString;
import org.xbill.DNS.Record;

/** LookupResult instances holds the result of a successful lookup operation. */
@ToString
@EqualsAndHashCode
public final class LookupResult {
  private final List<Record> records;
  private final AdditionalDetail additionalDetail;

  /**
   * Construct an instance with the provided records.
   *
   * @param records a list of records to return, or null if there was no response
   * @param additionalDetail additional detail on this response, such as the reason for records
   *     being null.
   */
  public LookupResult(List<Record> records, AdditionalDetail additionalDetail) {
    this.records = Collections.unmodifiableList(new ArrayList<>(records));
    if (records.isEmpty() && additionalDetail == null) {
      throw new IllegalArgumentException(
          "Empty records can not be combined with null additionalDetail");
    }
    this.additionalDetail = additionalDetail;
  }

  /**
   * An unmodifiable list of records that this instance wraps
   *
   * @return an unmodifiable List of Record instances.
   */
  public List<Record> get() {
    return records;
  }

  public AdditionalDetail getAdditionalDetail() {
    return additionalDetail;
  }
}
