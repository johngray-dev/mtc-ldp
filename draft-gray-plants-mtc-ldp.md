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
   RFC5280:
   RFC3986:
   RFC8446:
   I-D.ietf-plants-merkle-tree-certs:

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
are defined in {{I-D.ietf-plants-merkle-tree-certs}}.

This document defines an X.509 extension for discovering Landmark Distribution
Point (LDP) servers, a request format, a response format, and the validation
procedure for proof sets returned by those servers. LDP responses are untrusted
input: acceptance depends on successful proof verification and on the relying
party's existing trust policy.

## LDP mechanism use cases

### Private PKI Deployment without Transparency Logs
In large enterprise/private PKI settings, certificate transparency may not be
a requirement.  In these environments, the transparency logs will not be able
to distribute the require checkpoints.  The LDP mechanism described in this
document can be used as a replacement for transparency logs.

### Distribution of landmarks
If a relying party is not part of the browser-based web PKI ecosystem, and it is
presented with a landmark certificate, it will need a way to obtain the appropriate
landmarks so it can verify the consistency proof in the certificate.  The LDP
mechanism defined in this document gives a certificate issuer a way to indicate
where those landmarks can be obtained.

### Long-lived or intermittently connected devices
The validity period of certificates may last for a long time. An LDP makes a way
for the verifier to discover the landmark material it needs when performing
validation, without requiring the verifier to have received that material through
the same channel as the certificate.

### Cached Landmark distribution at scale
Landmarks are reusable across verifications for many certificates, and the
infrastructure that serves them may cache the landmarks. This makes distribution
much more efficient.

### Constrained certificate environments
The LDP allow information to be stored separation from the certificate, with a
simply mechanism to look up the required information at validation time.  This is
useful when certificate size, handshake size, bandwidth or storage is constrained.

### Operational resilience
The LDP mechanism allows more than one LDP to be specified, this then allows more
resilience in the event of service disruptions.

In summary, the Landmark Distribution Point (LDP) provides a mechanism for
separating the distribution of landmarks from the certificates and proofs that
depend upon them. This separation is particularly useful for large-scale PKI
deployments, constrained environments, and long-lived devices that do not
use certificate transparency.   For example, a device may receive a certificate
through one protocol while obtaining the corresponding landmark through a
separately operated distribution service.  Landmark Distribution Points therefore
provide a common discovery and distribution mechanism without requiring the
mechanism used to deliver certificates to also distribute the landmarks
required to validate them.

# Conventions and Definitions

{::boilerplate bcp14-tagged}

This document uses the TLS presentation language defined in {{RFC8446}}. The
structures in this document use the `HashValue` type and the hash function of
the MTC issuance log, as defined in {{I-D.ietf-plants-merkle-tree-certs}}.

The terms *landmark*, *landmark subtree*, *relying party*, *checkpoint*, and
*subtree consistency proof* have the meanings given in
{{I-D.ietf-plants-merkle-tree-certs}}.

# Overview

An MTC certificate's `MTCProof` contains `start`, `end`, and an inclusion proof.
The pair `[start, end)` identifies the certificate's source subtree. If the relying
party does not have this subtree in its trusted-subtree store, it obtains the
LDP URI from the certificate's `ldpBaseURIs` extension and sends a request
containing only `st` and `ed`, corresponding to `start` and `end`.

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

ext-ldpBaseURIs EXTENSION ::= {
	 SYNTAX LandmarkDistributionPoints
	 IDENTIFIED BY id-pe-ldpBaseURIs
	 CRITICALITY FALSE
}
~~~

Each `LandmarkDistributionPoint` MUST be an absolute HTTPS URI, as defined by
{{RFC3986}}. A base URI MUST NOT contain a query component or fragment. Its path
identifies the LDP resource to which the request parameters in {{request}} are
appended. A client MAY try the listed URIs in order until it obtains a valid
response. A client MUST NOT accept a proof solely because it came from a URI in
this extension.

# LDP Request and Response {#ldp-request-response}

## Request {#request}

The relying party constructs an HTTP GET request to a `LandmarkDistributionPoint`
URI. The request identifies the subtree represented by the certificate's
`MTCProof`.  It appends the following query parameters, encoded using the URI query
syntax in {{RFC3986}}:

* `st`: the `start` value from the certificate's `MTCProof`.
* `ed`: the `end` value from the certificate's `MTCProof`.

Each value MUST be encoded as an unsigned decimal integer in its shortest form
(no leading zeroes, except for the value zero). Each parameter MUST appear
exactly once. The endpoint MUST reject a request with a missing, duplicated, or
malformed parameter. An example request URI is:

For an `MTCProof` having `start` equal to 4096 and `end` equal to 4352, an
example request URI is:

~~~
https://ldp.example/mtc?st=4096&ed=4352
~~~

The `st` and `ed` values MUST be copied from the MTCProof. The relying party
MUST reject a request it constructs if the range is not a valid subtree as
defined by {{I-D.ietf-plants-merkle-tree-certs}}.

The relying party MUST NOT consider the returned checkpoint or requested
subtree authenticated until all verification requirements in
{{verification}} have succeeded.

## Landmark Subtree Proof

A `LandmarkSubtreeProof` proves that a source subtree is consistent with a
larger target tree. It is defined using the TLS presentation language as
follows:

~~~
struct {
	 uint48 source_start;
	 uint48 source_end;
	 HashValue source_root;
	 uint48 target_tree_size;
	 HashValue target_root;
	 HashValue consistency_proof<0..2^16-1>;
} LandmarkSubtreeProof;

struct {
	 LandmarkSubtreeProof proofs<1..2^16-1>;
} LandmarkSubtreeProofSet;
~~~

`source_start` and `source_end` identify the source subtree. `source_root` is
its Merkle Tree hash. `target_tree_size` and `target_root` identify the target
tree. `consistency_proof` is a subtree consistency proof as defined in
Section 4.4 of {{I-D.ietf-plants-merkle-tree-certs}}.

The first proof in a `LandmarkSubtreeProofSet` MUST identify the certificate
subtree: its `source_start` and `source_end` MUST equal the MTCProof's `start`
and `end`, and its `source_root` MUST equal the root reconstructed by
evaluating the MTCProof inclusion proof.

Each subsequent proof MUST use the preceding proof's target tree as its
source. Its `source_start` MUST be zero, `source_end` MUST equal the preceding
`target_tree_size`, and `source_root` MUST equal the preceding `target_root`.
Each subsequent `target_tree_size` MUST be greater than the preceding target
tree size. For every proof, `source_start` MUST be less than `source_end`, and
`source_end` MUST be less than or equal to `target_tree_size`.

Successful verification of each proof MUST demonstrate that all entries in
the source subtree are included in the target tree with their original order
and contents. The final proof's target tree size and root MUST match the
checkpoint carried in the response.

## Response Format

A successful response MUST have HTTP status 200 and Content-Type
`application/octet-stream`. The body contains exactly one
`LandmarkDistributionResponse`, encoded using the TLS presentation language:

~~~
struct {
	 opaque landmarks<1..2^24-1>;
	 opaque checkpoint<1..2^24-1>;
	 LandmarkSubtreeProofSet proof_set;
} LandmarkDistributionResponse;
~~~

`landmarks` contains the UTF-8 active-landmark list defined in Section 6.4.3
of {{I-D.ietf-plants-merkle-tree-certs}}, including its required newline
terminators. `checkpoint` contains an MTC checkpoint, including the
cosignatures needed to authenticate its tree root under the relying party's
MTC policy. It is encoded as specified below. The proof set MUST terminate at
the tree size and root in that checkpoint. The response MUST NOT contain
trailing data.

The LDP server MUST return a proof set whose first proof matches the requested
`st` and `ed` values. It MUST NOT return a set that does not verify. A server
SHOULD return a 4xx status for a malformed request and MAY return a 5xx status
if it cannot fulfill a valid request. A relying party MUST treat any
non-success response as a failed retrieval and MUST NOT accept the certificate
on the basis of an incomplete response.

## Checkpoint Format

The checkpoint carries a complete-tree hash and cosignatures over that tree.
It is defined using the TLS presentation language:

~~~
struct {
	 uint48 tree_size;
	 HashValue root_hash;
	 uint64 timestamp;
	 Cosignature signatures<1..2^24-1>;
} LandmarkCheckpoint;
~~~

`Cosignature` is defined in Section 6.2 of
{{I-D.ietf-plants-merkle-tree-certs}}. Each signature is computed over the
MTC `CosignedSubtree` structure defined in Section 5.3.1 of that document,
with `start` set to zero, `end` set to `tree_size`, `subtree_hash` set to
`root_hash`, and `timestamp` set to the value in `LandmarkCheckpoint`.
`log_origin` MUST identify the MTC issuance tree containing the certificate.
The checkpoint `timestamp` MUST be nonzero, and all signatures in this
structure MUST use that timestamp. The relying party MUST verify the checkpoint
signatures against its configured MTC cosigner policy. The checkpoint
timestamp MUST be acceptable under local freshness policy.

# Verifier Procedure {#verification}

A relying party validating an MTC certificate with no locally trusted subtree
for its `MTCProof` MUST perform the following steps:

1. Validate the certificate path from the MTC issuer’s CA certificate to a
   configured trust anchor according to {{RFC5280}}. Validate the MTC-specific
   certificate fields and proof according to {{I-D.ietf-plants-merkle-tree-certs}}
2. Extract `start` and `end` from the certificate's MTCProof. Validate that
 	 `[start, end)` is a valid subtree and evaluate the MTCProof inclusion proof
 	 to produce its subtree root. If either check fails, reject the certificate.
3. Retrieve the LDP URI list from `ldpBaseURIs` and send a request containing
	  only `st` and `ed` as specified in {{request}}.
4. Parse exactly one `LandmarkDistributionResponse`. Reject malformed
	  encodings, trailing data, oversized vectors, or a proof source range that
	  differs from the requested range.
5. Parse the active-landmark list according to Section 6.4.3 of
	  {{I-D.ietf-plants-merkle-tree-certs}}. Confirm that `[start, end)` is an
	  active landmark subtree for the certificate's MTC issuance tree. Reject the
	  certificate otherwise.
6. Verify `LandmarkCheckpoint` signatures using the relying party's configured
  	MTC cosigner policy. Verify that `log_origin` identifies the same MTC
  	issuance tree as the certificate, and that the checkpoint timestamp is
	  sufficiently recent under local policy. Reject the response if these
  	checks fail.
7. Verify every subtree consistency proof in `proof_set` in order, using the
	  procedure in Section 4.4.3 of
  	{{I-D.ietf-plants-merkle-tree-certs}}. The first proof MUST be verified
  	against the subtree root from the MTCProof. Each later proof MUST be
	  verified against the root reconstructed by the preceding proof.
8. Confirm that the final proof's `target_tree_size` and `target_root` equal
	  the authenticated checkpoint's tree size and root. Reject the certificate
  	if they differ.
9. Accept the certificate only if all MTC, certificate path, and application
  	validation checks succeed.

A relying party that already has the source subtree in its trusted-subtree
store uses the normal MTC verification procedure and does not need to contact an
LDP server. Retrieval failure does not weaken certificate validation and MUST
NOT cause the relying party to accept an otherwise unverifiable certificate.

# Cached Landmarks and Incremental Updates

A relying party MAY cache a successfully authenticated landmark.

If a cached authenticated landmark is sufficient to validate a subsequent MTC
certificate according to the normal verification procedure in
{{I-D.ietf-plants-merkle-tree-certs}}, the relying party does not need to contact
an LDP server.

An implementation MAY also periodically obtain more recent signed landmarks and
consistency proofs from the LDP server. Such retrieval allows a relying party to
advance its cached authenticated landmark state without requiring certificate
validation to begin with knowledge of a particular target tree size.

Landmark consistency proofs MAY be generated and cached by the LDP server when new
landmarks are published. An LDP server MAY additionally maintain skip-link proofs
between landmarks to reduce the number of consistency proofs required to connect
an older subtree or landmark to a more recent signed landmark.

Retrieval failure MUST NOT weaken MTC certificate validation. A relying party MUST
NOT accept a certificate for which the required cryptographic relationship to an
authenticated landmark cannot be established.


# Proof Generation and Efficiency

Without consistency proofs, a relying party catching up from an old landmark
might need to retrieve and authenticate every intermediate landmark. A
`LandmarkSubtreeProofSet` permits the LDP to connect the requested source
subtree to one currently trusted checkpoint, reducing repeated
checkpoint-signature verification. The final checkpoint remains independently
authenticated by the relying party.

An LDP MAY generate a direct consistency proof from the source subtree to the
selected checkpoint. When it retains proofs between landmarks, the LDP SHOULD
use `skip links` to bound the number of proofs required to connect older and
newer landmarks.  A `skip link` only generates O(Log(num_landmarks)) for each
landmark.  For example, a system that issued a landmark every hour for 10 years
would have 87,600 landmarks.  When landmark 87,601 is created, only 17 landmark
proofs will need to be created.  It would also reduce the LandmarkSubtreeProofSet
from O(num_landmarks) to O(Log(num_landmarks), greatly reducing bandwidth
requirements!  The precise skip-link layout is an implementation choice; all
returned proofs MUST satisfy the chaining and verification rules in this document.

# Security Considerations

The LDP server is not a trust anchor. A malicious or compromised server can
withhold, corrupt, or replay data, causing validation to fail or consume
resources. It cannot cause acceptance of an invalid certificate without
breaking the MTC hash function, the authenticated checkpoint, or the subtree
consistency proof algorithm. A relying party MUST authenticate the checkpoint
and verify every proof locally; it MUST NOT trust the LDP's assertions about
proof validity.

The `ldpBaseURIs` extension is included in the MTC TBSCertificate contents and
is covered by the MTC inclusion proof. Relying parties MUST validate the
certificate issuer and MTC proof before using the extension. Implementations
SHOULD impose limits on URI length, response size, proof count, and retrieval
time to limit resource-exhaustion attacks.

The `st` and `ed` query values reveal which subtree a relying party is
verifying. Deployments should consider this disclosure in their privacy
policies. HTTPS protects these values and the response against observation or
modification in transit, but does not replace cryptographic proof validation.

Although the proof data is integrity-checked cryptographically, HTTPS is
required for LDP URIs to protect request metadata and response availability in
transit. The query parameters reveal the requested subtree and target tree size;
implementations should account for this disclosure in their privacy policies.

# IANA Considerations

IANA is requested to allocate an object identifier for `id-pe-ldpBaseURIs`
under the PKIX `id-pe` arc. The assigned value will replace `TBD` in this
document.

--- back

# Acknowledgments
{:numbered="false"}

Thanks to David Benjamin, Bas Westerbaan, Mike Ounsworth, Rich Salz and
Kris Kwiatkowski for their feedback during the design of this draft.
