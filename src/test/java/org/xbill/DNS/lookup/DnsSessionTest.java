package org.xbill.DNS.lookup;

import static java.lang.String.format;
import static java.util.Arrays.asList;
import static java.util.Collections.emptyList;
import static java.util.Collections.singletonList;
import static java.util.stream.Collectors.toList;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.verifyNoMoreInteractions;
import static org.mockito.Mockito.when;
import static org.xbill.DNS.DClass.IN;
import static org.xbill.DNS.LookupTest.DUMMY_NAME;
import static org.xbill.DNS.LookupTest.LONG_LABEL;
import static org.xbill.DNS.LookupTest.answer;
import static org.xbill.DNS.LookupTest.fail;
import static org.xbill.DNS.Type.A;
import static org.xbill.DNS.Type.CNAME;
import static org.xbill.DNS.lookup.AdditionalDetail.NXDOMAIN;
import static org.xbill.DNS.lookup.AdditionalDetail.NXRRSET;

import java.net.InetAddress;
import java.util.List;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.CompletionStage;
import java.util.concurrent.ExecutionException;
import java.util.function.Function;
import java.util.stream.Collectors;
import java.util.stream.IntStream;
import java.util.stream.Stream;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.junit.jupiter.api.function.Executable;
import org.mockito.ArgumentCaptor;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.xbill.DNS.*;

@ExtendWith(MockitoExtension.class)
class DnsSessionTest {

  @Mock Resolver mockResolver;

  @AfterEach
  public void after() {
    verifyNoMoreInteractions(mockResolver);
  }

  @Test
  public void lookupAsync_absoluteQuery() throws InterruptedException, ExecutionException {
    wireUpMockResolver(mockResolver, query -> answer(query, name -> LOOPBACK_A));

    DnsSession dnsSession = new DnsSession(mockResolver);
    CompletionStage<LookupResult> resultFuture =
        dnsSession.lookupAsync(Name.fromConstantString("a.b."), A, IN);

    LookupResult result = resultFuture.toCompletableFuture().get();
    assertEquals(singletonList(LOOPBACK_A.withName(name("a.b."))), result.get());

    verify(mockResolver).sendAsync(any());
  }

  @Test
  public void lookupAsync_simpleCnameRedirect() throws Exception {
    Function<Name, Record> nameToRecord =
        name -> name("cname.r.").equals(name) ? cname("cname.r.", "a.b.") : LOOPBACK_A;
    wireUpMockResolver(mockResolver, q -> answer(q, nameToRecord));

    DnsSession dnsSession = new DnsSession(mockResolver);

    CompletionStage<LookupResult> resultFuture = dnsSession.lookupAsync(name("cname.r."), A, IN);

    LookupResult result = resultFuture.toCompletableFuture().get();
    assertEquals(singletonList(LOOPBACK_A.withName(name("a.b."))), result.get());
    verify(mockResolver, times(2)).sendAsync(any());
  }

  @Test
  public void lookupAsync_simpleDnameRedirect() throws Exception {
    Function<Name, Record> nameToRecord =
        n -> name("x.y.to.dname.").equals(n) ? dname("to.dname.", "to.a.") : LOOPBACK_A;
    wireUpMockResolver(mockResolver, q -> answer(q, nameToRecord));

    DnsSession dnsSession = new DnsSession(mockResolver);

    CompletionStage<LookupResult> resultFuture =
        dnsSession.lookupAsync(name("x.y.to.dname."), A, IN);

    LookupResult result = resultFuture.toCompletableFuture().get();
    assertEquals(singletonList(LOOPBACK_A.withName(name("x.y.to.a."))), result.get());
    verify(mockResolver, times(2)).sendAsync(any());
  }

  @Test
  public void lookupAsync_redirectLoop() {
    Function<Name, Record> nameToRecord =
        name -> name("a.b.").equals(name) ? cname("a.", "b.") : cname("b.", "a.");
    wireUpMockResolver(mockResolver, q -> answer(q, nameToRecord));

    DnsSession dnsSession = new DnsSession(mockResolver);
    dnsSession.setMaxRedirects(2);

    CompletionStage<LookupResult> resultFuture =
        dnsSession.lookupAsync(name("first.example.com."), A, IN);

    assertThrowsCause(
        RedirectOverflowException.class, () -> resultFuture.toCompletableFuture().get());
    verify(mockResolver, times(3)).sendAsync(any());
  }

  @Test
  public void lookupAsync_NXDOMAIN() throws Exception {
    wireUpMockResolver(mockResolver, q -> fail(q, Rcode.NXDOMAIN));

    DnsSession dnsSession = new DnsSession(mockResolver);
    CompletionStage<LookupResult> resultFuture = dnsSession.lookupAsync(name("a.b."), A, IN);

    assertEquals(new LookupResult(emptyList(), NXDOMAIN), resultFuture.toCompletableFuture().get());
    verify(mockResolver).sendAsync(any());
  }

  @Test
  public void lookupAsync_SERVFAIL() {
    wireUpMockResolver(mockResolver, q -> fail(q, Rcode.SERVFAIL));

    DnsSession dnsSession = new DnsSession(mockResolver);
    CompletionStage<LookupResult> resultFuture = dnsSession.lookupAsync(name("a.b."), A, IN);

    assertThrowsCause(ServerFailedException.class, () -> resultFuture.toCompletableFuture().get());
    verify(mockResolver).sendAsync(any());
  }

  @Test
  public void lookupAsync_unknownFailure() {
    wireUpMockResolver(mockResolver, q -> fail(q, Rcode.NOTIMP));

    DnsSession dnsSession = new DnsSession(mockResolver);
    CompletionStage<LookupResult> resultFuture = dnsSession.lookupAsync(name("a.b."), A, IN);

    assertThrowsCause(LookupFailedException.class, () -> resultFuture.toCompletableFuture().get());
    verify(mockResolver).sendAsync(any());
  }

  @Test
  public void lookupAsync_NXRRSET() throws Exception {
    wireUpMockResolver(mockResolver, q -> fail(q, Rcode.NXRRSET));

    DnsSession dnsSession = new DnsSession(mockResolver);
    CompletionStage<LookupResult> resultFuture = dnsSession.lookupAsync(name("a.b."), A, IN);

    assertEquals(new LookupResult(emptyList(), NXRRSET), resultFuture.toCompletableFuture().get());
    verify(mockResolver).sendAsync(any());
  }

  @Test
  public void lookupAsync_TooLongNameDNAME() {
    wireUpMockResolver(
        mockResolver, q -> answer(q, n -> dname("to.dname.", format("%s.to.a.", LONG_LABEL))));

    DnsSession dnsSession = new DnsSession(mockResolver);
    Name toLookup = name(format("%s.%s.%s.to.dname.", LONG_LABEL, LONG_LABEL, LONG_LABEL));
    CompletionStage<LookupResult> resultFuture = dnsSession.lookupAsync(toLookup, A, IN);

    assertThrowsCause(
        InvalidZoneDataException.class, () -> resultFuture.toCompletableFuture().get());
    verify(mockResolver).sendAsync(any());
  }

  @Test
  public void lookupAsync_MultipleCNAMEs() {
    // According to https://docstore.mik.ua/orelly/networking_2ndEd/dns/ch10_07.htm this is
    // apparently something
    // that BIND 4 did.
    wireUpMockResolver(mockResolver, DnsSessionTest::multipleCNAMEs);

    DnsSession dnsSession = new DnsSession(mockResolver);
    CompletionStage<LookupResult> resultFuture = dnsSession.lookupAsync(name("a.b."), A, IN);

    assertThrowsCause(
        InvalidZoneDataException.class, () -> resultFuture.toCompletableFuture().get());
    verify(mockResolver).sendAsync(any());
  }

  private static Message multipleCNAMEs(Message query) {
    Message answer = new Message(query.getHeader().getID());
    Record question = query.getQuestion();
    answer.addRecord(question, Section.QUESTION);
    answer.addRecord(
        new CNAMERecord(question.getName(), CNAME, IN, name("target1.")), Section.ANSWER);
    answer.addRecord(
        new CNAMERecord(question.getName(), CNAME, IN, name("target2.")), Section.ANSWER);
    return answer;
  }

  @Test
  void lookupAsync_searchAppended() throws Exception {
    wireUpMockResolver(mockResolver, query -> answer(query, name -> LOOPBACK_A));

    DnsSession dnsSession = new DnsSession(mockResolver);

    dnsSession.setSearchPath(singletonList(name("example.com")));
    CompletionStage<LookupResult> resultFuture = dnsSession.lookupAsync(name("host"), A, IN);
    LookupResult lookupResult = resultFuture.toCompletableFuture().get();

    ArgumentCaptor<Message> messageCaptor = ArgumentCaptor.forClass(Message.class);
    verify(mockResolver).sendAsync(messageCaptor.capture());

    assertEquals(
        Record.newRecord(Name.fromConstantString("host.example.com."), Type.A, DClass.IN, 0L),
        messageCaptor.getValue().getSection(Section.QUESTION).get(0));

    assertEquals(singletonList(LOOPBACK_A.withName(name("host.example.com."))), lookupResult.get());
  }

  @Test
  void lookupAsync_searchAppendTooLongName() throws Exception {
    wireUpMockResolver(mockResolver, query -> answer(query, name -> LOOPBACK_A));

    DnsSession dnsSession = new DnsSession(mockResolver);

    dnsSession.setSearchPath(
        singletonList(name(format("%s.%s.%s", LONG_LABEL, LONG_LABEL, LONG_LABEL))));
    CompletionStage<LookupResult> resultFuture = dnsSession.lookupAsync(name(LONG_LABEL), A, IN);
    LookupResult lookupResult = resultFuture.toCompletableFuture().get();

    ArgumentCaptor<Message> messageCaptor = ArgumentCaptor.forClass(Message.class);
    verify(mockResolver).sendAsync(messageCaptor.capture());

    assertEquals(
        Record.newRecord(name(LONG_LABEL + "."), A, IN, 0L),
        messageCaptor.getValue().getSection(Section.QUESTION).get(0));

    assertEquals(singletonList(LOOPBACK_A.withName(name(LONG_LABEL + "."))), lookupResult.get());
  }

  @Test
  void lookupAsync_twoItemSearchPath() throws Exception {
    wireUpMockResolver(
        mockResolver,
        query -> answer(query, name -> name.equals(name("host.a.")) ? null : LOOPBACK_A));

    DnsSession dnsSession = new DnsSession(mockResolver);

    dnsSession.setSearchPath(asList(name("a"), name("b")));
    CompletionStage<LookupResult> resultFuture = dnsSession.lookupAsync(name("host"), A, IN);
    LookupResult lookupResult = resultFuture.toCompletableFuture().get();

    ArgumentCaptor<Message> messageCaptor = ArgumentCaptor.forClass(Message.class);
    verify(mockResolver, times(2)).sendAsync(messageCaptor.capture());

    List<Message> allValues = messageCaptor.getAllValues();
    assertEquals(
        Record.newRecord(Name.fromConstantString("host.a."), Type.A, DClass.IN, 0L),
        allValues.get(0).getSection(Section.QUESTION).get(0));
    assertEquals(
        Record.newRecord(Name.fromConstantString("host.b."), Type.A, DClass.IN, 0L),
        allValues.get(1).getSection(Section.QUESTION).get(0));

    assertEquals(singletonList(LOOPBACK_A.withName(name("host.b."))), lookupResult.get());
  }

  @Test
  public void setSearchPath_tooLongRelativeName() {
    DnsSession session = new DnsSession(mockResolver);
    String label = IntStream.range(0, 62).mapToObj(i -> "a").collect(Collectors.joining());
    Name longRelativeLabel = name(format("%s.%s.%s.%s", LONG_LABEL, LONG_LABEL, LONG_LABEL, label));
    assertThrows(
        RuntimeException.class, () -> session.setSearchPath(singletonList(longRelativeLabel)));
  }

  @Test
  public void expandName_absolute() {
    DnsSession session = new DnsSession(mockResolver);
    Stream<Name> nameStream = session.expandName(name("a."));
    assertEquals(singletonList(name("a.")), nameStream.collect(toList()));
  }

  @Test
  public void expandName_singleSearchPath() {
    DnsSession session = new DnsSession(mockResolver);
    session.setSearchPath(singletonList(name("example.com.")));
    Stream<Name> nameStream = session.expandName(name("host"));
    assertEquals(asList(name("host.example.com."), name("host.")), nameStream.collect(toList()));
  }

  @Test
  public void expandName_searchPathIsMadeAbsolute() {
    DnsSession session = new DnsSession(mockResolver);
    session.setSearchPath(singletonList(name("example.com")));
    Stream<Name> nameStream = session.expandName(name("host"));
    assertEquals(asList(name("host.example.com."), name("host.")), nameStream.collect(toList()));
  }

  private static final ARecord LOOPBACK_A =
      new ARecord(DUMMY_NAME, IN, 0, InetAddress.getLoopbackAddress());

  private static CNAMERecord cname(String name, String target) {
    return new CNAMERecord(name(name), IN, 0, name(target));
  }

  @SuppressWarnings("SameParameterValue")
  private static DNAMERecord dname(String name, String target) {
    return new DNAMERecord(name(name), IN, 0, name(target));
  }

  private static Name name(String name) {
    return Name.fromConstantString(name);
  }

  @SuppressWarnings("SameParameterValue")
  private <T extends Throwable> void assertThrowsCause(Class<T> ex, Executable executable) {
    Throwable outerException = assertThrows(Throwable.class, executable);
    assertEquals(ex, outerException.getCause().getClass());
  }

  private void wireUpMockResolver(Resolver mockResolver, Function<Message, Message> handler) {
    when(mockResolver.sendAsync(any(Message.class)))
        .thenAnswer(
            invocation -> {
              Message query = invocation.getArgument(0);
              return CompletableFuture.completedFuture(handler.apply(query));
            });
  }
}
