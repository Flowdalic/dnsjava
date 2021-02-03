// SPDX-License-Identifier: BSD-2-Clause
package org.xbill.DNS.lookup;

import static java.util.Collections.emptyList;
import static java.util.Collections.singletonList;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.xbill.DNS.lookup.AdditionalDetail.NXDOMAIN;

import java.net.InetAddress;
import org.junit.jupiter.api.Test;
import org.xbill.DNS.ARecord;
import org.xbill.DNS.DClass;
import org.xbill.DNS.Name;
import org.xbill.DNS.Record;

class LookupResultTest {
  @Test
  public void ctor_nullRecords() {
    assertThrows(NullPointerException.class, () -> new LookupResult(null, null));
  }

  @Test
  public void ctor_emptyListNoAdditionalDetail() {
    assertThrows(IllegalArgumentException.class, () -> new LookupResult(emptyList(), null));
  }

  @Test
  public void getResult() {
    Record record =
        new ARecord(Name.fromConstantString("a."), DClass.IN, 0, InetAddress.getLoopbackAddress());
    LookupResult lookupResult = new LookupResult(singletonList(record), null);
    assertEquals(singletonList(record), lookupResult.get());
  }

  @Test
  public void getAdditionalDetail() {
    LookupResult lookupResult = new LookupResult(emptyList(), NXDOMAIN);
    assertTrue(lookupResult.get().isEmpty());
    assertEquals(NXDOMAIN, lookupResult.getAdditionalDetail());
  }
}
