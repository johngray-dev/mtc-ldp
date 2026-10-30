---
title: "Landmark Distribution Point Fetching for Merkle Tree Certificates"
abbrev: "MTC Landmark Distribution"
category: info

docname: draft-gray-plants-mtc-ldp-latest
submissiontype: IETF  
number:
date:
consensus: true
v: 3
area: Security
workgroup: "PKI, Logs, And Tree Signatures"
keyword:
 - Merkle Tree Certificate
 - Landmark Distribution Point
 - PKI
venue:
  group: "PKI, Logs, And Tree Signatures"
  type: "Working Group"
  mail: "plants@ietf.org"
  arch: "https://mailarchive.ietf.org/arch/browse/plants"
  github: "johngray-dev/mtc-ldp"
  latest: "https://johngray-dev.github.io/mtc-ldp/draft-gray-plants-mtc-ldp.html"

author:
 -
    ins: J. Gray
    name: John Gray
    org: Entrust Limited
    abbrev: Entrust
    street: 2500 Solandt Road – Suite 100
    city: Ottawa, Ontario
    country: Canada
    code: K2K 3G5
    email: john.gray@entrust.com
 -
    ins: J. Klaussner
    name: Jan Klaussner
    org: Bundesdruckerei GmbH
    email: jan.klaussner@bdr.de
    street: Kommandantenstr. 18
    code: 10969
    city: Berlin
    country: Germany
 -
    ins: L. Tindell
    name: Luke Tindell
    org: UK National Cyber Security Centre
    email: luke.t2@ncsc.gov.uk
    country: United Kingdom
-
    ins: T. Reddy Konda
    name: Tirumaleswar Reddy Konda
    org: Nokia
    email: kondtir@gmail.com

normative:
  RFC2119:
  RFC3986:
  RFC5280:
  RFC8174:
  RFC8446:
  RFC9110:
  I-D.draft-ietf-plants-merkle-tree-certs-03:

informative:

...

--- abstract

This document specifies a mechanism for a relying party to retrieve Merkle-tree
subtree consistency proofs needed to validate a landmark-relative Merkle Tree
Certificate (MTC). An X.509 certificate extension identifies one or more
Landmark Distribution Points (LDPs). A relying party requests a proof set from
an LDP and validates the proof chain against a trusted, signed target checkpoint.


--- middle

# Introduction {#intro}

A landmark-relative Merkle Tree Certificate (MTC) carries an inclusion proof but
omits signatures. It can be verified when the relying party has trusted the
corresponding landmark subtree. A relying party that does not have the required
subtree locally can obtain consistency proofs that connect it to a newer,
trusted checkpoint. The MTC format and the subtree consistency proof algorithm
are defined in {{I-D.ietf-plants-merkle-tree-certs-03}}.

This document defines an X.509 extension for discovering LDP servers, a request
format, a response format, and the validation procedure for proof sets returned
by those servers. LDP responses are untrusted input: acceptance depends on
successful proof verification and on the relying party's existing MTC trust
policy, not on trusting the server.


# Conventions and Definitions

{::boilerplate bcp14-tagged}

This document uses the TLS presentation language defined in {{RFC8446}}. The
structures in this document use the `HashValue` type and the hash function of
the MTC issuance log, as defined in {{I-D.ietf-plants-merkle-tree-certs-03}}.

The terms *landmark*, *landmark subtree*, *relying party*, *checkpoint*, and
*subtree consistency proof* have the meanings given in
{{I-D.ietf-plants-merkle-tree-certs-03}}.

# Overview

An MTC certificate's `MTCProof` contains `start`, `end`, and an inclusion proof.
Those values identify a source subtree and allow the relying party to compute
its hash. The relying party can then request a proof set from an LDP. The proof
set connects that source subtree through zero or more intermediate tree states
to a target checkpoint already trusted by the relying party.

The relying party MUST authenticate the target checkpoint using its normal MTC
policy. Proofs and intermediate roots returned by the LDP do not establish
trust by themselves. Each proof establishes subtree consistency with its stated
target root; the final target root MUST match the authenticated checkpoint.

# Landmark Distribution Point Extension

The `ldpBaseURIs` extension is included in an MTC certificate by its issuer. It
contains one or more base URIs at which the issuer makes LDP resources
available. The relying party MUST process the extension as an X.509 certificate
extension in accordance with {{RFC5280}}. The extension MUST be non-critical.

The extension is defined as follows:

~~~asn1
id-pe-ldpBaseURIs OBJECT IDENTIFIER ::= { id-pe TBD }

LandmarkDistributionPoints ::= SEQUENCE SIZE (1..MAX) OF
    LandmarkDistributionPoint

LandmarkDistributionPoint ::= IA5String
~~~

Each `LandmarkDistributionPoint` MUST be an absolute HTTPS URI, as defined by
{{RFC3986}}. A base URI MUST NOT contain a query component or fragment. Its path
identifies the LDP resource to which the request parameters in {{request}} are
appended. A client MAY try the listed URIs in order until it obtains a valid
response. A client MUST NOT accept a proof solely because it came from a URI in
this extension.

# LDP Request and Response

## Request

The relying party constructs an HTTP GET request to a `LandmarkDistributionPoint`
URI. It appends the following query parameters, encoded using the URI query
syntax in {{RFC3986}}:

* `st`: the `start` value from the certificate's `MTCProof`.
* `ed`: the `end` value from the certificate's `MTCProof`.
* `target`: the tree size of the trusted target checkpoint selected by the
  relying party.

Each value MUST be encoded as an unsigned decimal integer in its shortest form
(no leading zeroes, except for the value zero). Each parameter MUST appear
exactly once. The endpoint MUST reject a request with a missing, duplicated, or
malformed parameter. An example request URI is:

~~~
https://ldp.example/mtc?st=4096&ed=4352&target=8192
~~~

The target checkpoint MUST be authenticated by the relying party and MUST
belong to the same MTC log as the certificate. The relying party selects the
target; the server cannot cause the relying party to accept a different target
by changing the request or response.

## Proof Structures

A `LandmarkSubtreeProof` carries a subtree consistency proof and the source and
target roots needed to verify it:

~~~
struct {
    uint64 source_start;
    uint64 source_end;
    HashValue source_root;
    uint64 target_tree_size;
    HashValue target_root;
    HashValue consistency_proof<0..2^16-1>;
} LandmarkSubtreeProof;

struct {
    LandmarkSubtreeProof proofs<1..2^16-1>;
} LandmarkSubtreeProofSet;
~~~

The first proof in the set MUST identify the certificate subtree: its
`source_start` and `source_end` MUST equal the MTCProof's `start` and `end`, and
its `source_root` MUST equal the root reconstructed from the MTCProof inclusion
proof.

Each subsequent proof MUST use the preceding proof's target as its source. Its
`source_start` MUST be zero, its `source_end` MUST equal the preceding
`target_tree_size`, and its `source_root` MUST equal the preceding `target_root`.
The target tree size of each proof after the first MUST be greater than the
preceding proof's target tree size.

For every proof, `source_start` MUST be less than `source_end`, and
`source_end` MUST be less than or equal to `target_tree_size`. The proof's
`consistency_proof` MUST be a subtree consistency proof as defined in
{{I-D.ietf-plants-merkle-tree-certs-03}}. `target_root` is the root reconstructed
for the target tree by verifying that proof; it is not trusted until it is
connected to the relying party's authenticated target checkpoint.

## Response

A successful response has an HTTP 200 status code and a body containing exactly
one `LandmarkSubtreeProofSet`, encoded using the TLS presentation language in
{{RFC8446}}. The response Content-Type is `application/octet-stream`. The body
MUST NOT contain trailing data. The proof set's final `target_tree_size` and
`target_root` MUST equal the tree size and root of the target checkpoint named
in the request.

An LDP server MUST NOT return a proof set that fails these requirements. An
endpoint SHOULD return an appropriate 4xx status code for a malformed request
and MAY return a 5xx status code when it cannot currently fulfill a valid
request. A client MUST treat any non-200 response as a failed retrieval and
MUST NOT accept the certificate on the basis of an incomplete proof set.

# Verifier Procedure

A relying party validating an MTC certificate with no locally trusted subtree
for its `MTCProof` MUST perform the following steps:

1. Validate the certificate and construct the MTC log entry as specified in
   {{I-D.ietf-plants-merkle-tree-certs-03}}.
2. Reconstruct the source subtree root by evaluating the certificate's inclusion
   proof using its `start` and `end` values. If proof evaluation fails, reject
   the certificate.
3. Select a trusted target checkpoint for the same log and verify its
   signature or signatures using the relying party's configured MTC policy. If
   no suitable trusted target is available, validation fails.
4. Construct the request in {{request}} using the MTCProof's `start` and `end`
   values and the selected target checkpoint's tree size. Retrieve the response
   from one of the certificate's LDP URIs.
5. Parse exactly one `LandmarkSubtreeProofSet`. Reject the response if it is
   malformed, contains trailing data, or exceeds the protocol's vector bounds.
6. For each proof, verify that its source range and source root satisfy the
   chaining requirements in {{proof-structures}}. Verify its subtree
   consistency proof using the algorithm in
   {{I-D.ietf-plants-merkle-tree-certs-03}}. Reject the set if any verification
   fails.
7. Verify that the last proof's target tree size and root equal those of the
   authenticated target checkpoint. Reject the certificate if they differ.
8. Accept the certificate only if all other certificate path validation and
   MTC checks also succeed.

A relying party that already has the source subtree in its trusted-subtree
store uses the normal MTC verification procedure and does not need to contact an
LDP server. Retrieval failure does not weaken certificate validation and MUST
NOT cause the relying party to accept an otherwise unverifiable certificate.

# Efficiency Considerations

A proof set can avoid fetching and verifying every intermediate signed
landmark. Only the final checkpoint needs to be authenticated by the relying
party's MTC trust policy; intermediate steps are connected by subtree
consistency proofs. LDP servers MAY choose intermediate targets to make proof
sets smaller or easier to produce. They SHOULD avoid returning unnecessarily
long proof chains, subject to the response size limits imposed by the TLS
presentation vectors.

An LDP server can precompute or cache consistency proofs when checkpoints or
landmarks are published. The choice of caching strategy and intermediate
checkpoints is an implementation matter and does not affect the verifier
procedure.

# Security Considerations {#security}

The LDP server is not a trust anchor. A malicious or compromised server can
withhold, corrupt, or replay proof data, causing validation to fail or consume
resources, but it cannot make a relying party accept a false subtree without
breaking the MTC hash function or the authenticated target checkpoint. A relying
party MUST verify every proof and MUST compare the final root and tree size with
the target checkpoint it authenticated independently.

The extension is covered by the certificate issuer's signature. Relying parties
MUST apply their ordinary certificate path validation and issuer-trust rules
before using its URIs. Implementations SHOULD impose limits on URI length,
response size, proof count, and retrieval time to limit resource exhaustion.

Although the proof data is integrity-checked cryptographically, HTTPS is
required for LDP URIs to protect request metadata and response availability in
transit. The query parameters reveal the requested subtree and target tree size;
implementations should account for this disclosure in their privacy policies.


# IANA Considerations {#iana}

IANA is requested to allocate an object identifier for `id-pe-ldpBaseURIs` under
the PKIX `id-pe` arc, as defined in {{RFC5280}}. The assigned value will replace
`TBD` in this document.


--- back

# Acknowledgments
{:numbered="false"}

TODO acknowledge.
