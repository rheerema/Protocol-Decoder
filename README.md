# Protocol-Decoder
Portfolio Code for Wireline Protocol Decoder

## Product Description
The code in this repository was written for a data security appliance
designed to detect data theft and audit access to databases and CIFS file
shares in order to provide regulatory compliance and information governance
for standards such as SOX, PCI DSS, and  GLBA.  The product hardware
platform was a commercial 1U server populated with standard network
interface cards and which ran CentOS Linux.

As a security appliance it provided a means to monitor employee access to
databases and file shares that was independent of server logs which could
potentially be manipulated by bad actors to hide their tracks.  The
monitoring capability was through direct analysis of the content of network
traffic on a customer's internal network.  Internal network traffic was
port mirrored into the interfaces of the data appliance which ran in
promiscuous mode utilizing the PCAP API.

All TCP sessions (source IP, source port, destination IP, destination port)
were tracked and fed to protocol specific decoders.  Each specialized
decoder could decipher (based on TCP port)  the transactions being
conducted on that session.  Protocols such as Oracle, SQL Server, CIFS
SMB, DB2, Informix were decoded and protocol transactions extracted as
events.

When an employee mounted a database or file share their identity was
obtained and associated with all subsequent transactions on that TCP
session.  Each transaction was also time stamped and the amount of data
requested was captured.  Each transaction was fully decoded with all
parameters and then injected into an internal database managed by the
appliance.

The product provided a policy language to evaluate the protocol transaction
events entered into the internal database.  The policy language could
detect and instigate an alarm on conditions which might have represented
data theft.  Examples are data accesses in the early hours of the day,
failed logins, and data accesses whose size was inordinate relative to what
an employee should normally request.  Initially the appliance would be
placed in the network and audit all transactions.  This provided insight
into ordinary usage of servers which was then used as a baseline to
program policy entries which would then audit and detect future anomalous
events for compliance and data theft.

## Dispatch to a Decoder
Digging deeper into software internals, the appliance had a single event
stack which channeled protocol events into a database.  There were three
Worker threads which each contained a copy of a decoder for each of the
supported protocols.  For that particular server hardware three Workers
produced the best performance on the hardware platform chosen.

Raw TCP traffic segments entered into the device through PCAP on the
network interface.  The Worker code was designed to accept raw network
traffic which could consist of unordered or lost TCP segments.  It had the
capability to re-order segments where it was possible and would indicate
the presence of a lost segment (a "hole") to the decoder handling the
session.

Once the TCP-like layer completed whatever re-ordering it could then the
session was dispatched to the appropriate decoder (e.g. SQL Server, SMB,
Oracle, DB2, Informix) based on the destination port number for segments
coming from the client side.  The Worker threads utilized semaphores to
access traffic from the NIC below it  and to inject a protocol event into
the event stack above it.  Installation of the appliance required placement
within the network where both sides of client and server traffic could be
seen and where network congestion was kept to a minimum.

## Decoder Internals
Sample code is provided for two protocols developed from scratch by the
author.  The primary mission of the decoder was to evaluate each
transaction and inject an event upward into the database that contained
all relevant information about that transaction.  This includes user identity,
time of access, the specific protocol action and all of the relevant
parameters associated with the transaction.  The data contained in the
parameters was the primary target of the security policy language.

The perspective these decoders are written around was "man in the middle."
The decoder was a passive observer of interactions between the client and
the server.  These protocols are based on request-response.  The client
host connects to the server side service through a well known port, makes
a request and awaits the server's response before another transaction can
take place.

One advantage of a request-response protocol is that it gives the decoder
the opportunity to re-synchronize quickly if a TCP segment is lost.  If the
decoder sees a response without a matching request it will toss it and
start looking for the next request.  If the decoder sees a request without
a matching response it will ignore it and start looking for the next request.

Almost all transaction codepoints were self-contained in the sense that the
request was completed by the response versus spanning several transactions
to accomplish completion.  One of the earliest transactions on a session is
typically client authentication and it is of primary interest to decoders.
Once the client's identity is established it is tagged to every subsequent
transaction on that session.  Sessions for which the client could not be
determined were still tracked and generated events since it was possible
to later infer client identity through the source IP.

All potential transactions between the client and server were handled.
This includes protocol variations for each transaction which arise due to
different manufacturer implementations of the protocol.  For example a
Solaris CIFS client may have slightly different transaction formats versus,
say, a MacOS client despite both being "CIFS compliant."  The decoder
handled all of these cases.  Regardless of what a specification may say
"the truth is on the wire."

In the development of these decoders many combinations of client versus
server network traffic were captured between actual equipment running
different versions of OS using WireShark.  These capture files were used
for development, test, and validation of the decoder's integrity.

The SMB code supported SMB1 which was the primary CIFS protocol at the
time of deployment.  Client authentication at the time was based on
NTLM v1 and v2 or Kerberos.  The Postgres code was a second generation
design of the decoder.  It incorporated a "Session Buffer" subsystem
which provided local temporary caching of protocol data as the decoder
worked its way through each request and response.  This helped clean
up coding in cases where a length field was not provided and the decoder
had to empirically determine length by way of data context.

The code provided represents two examples of protocol decoders written
by the author.  Similar decoders were written by the author for DB2 and
INFORMIX.
