# Bouncy Castle Crypto Package For Java LTS - Release Notes

## 1.0 Introduction

The Bouncy Castle Crypto package for Java LTS is a long term support distribution of the Bouncy
Castle Crypto APIs. It offers the same lightweight API, JCA/JCE provider, JSSE provider, CMS/PKIX
and OpenPGP APIs as the regular Java distribution, with the addition of optional native (JNI)
acceleration for AES modes, SHA-2/SHA-3, GCM-SIV and DRBG on x86_64 (AVX, VAES, VAESF) and ARM64
(NEON-LE). The jars are named `bc{module}-lts8on-<version>.jar` and target Java 8 and later.

This is not the FIPS distribution; release notes for that are carried with the BC-FJA
distributions.

## 2.0 Release History

<a id="r2rv73dot14"></a>

### 2.1.1 Version

Release: 2.73.14\
Date: 2026, TBD.

### 2.1.2 Defects Fixed

**Lightweight API - conformance.**

- ML-KEM matrix generation (FIPS 203 Algorithm 7, SampleNTT) squeezed two SHAKE128 blocks for each
  additional block it needed after the first three, but sampled from only the first of them, so a
  matrix entry needing more than one additional block was sampled from the wrong part of the XOF
  stream and differed from the one FIPS 203 specifies. The chance of an entry needing that is about
  10^-32, so no key, ciphertext or test vector is known to be affected; each additional block is
  now squeezed singly, as the standard and the reference implementation do.

**Lightweight API - malformed input, bounds and state.**

- Grain-128AEAD returned corrupted plaintext from a decryption driven in chunks. The AEAD stream
  cipher data operator splits a `processBytes()` call that spans the buffered authentication tag
  into two output segments, and wrote the second at the caller's output offset instead of after the
  first, so it overwrote the head of the first and the tail of the reported output was never
  written. The call still returned the full byte count and the tag still verified. The second
  segment is now written after the first.
- The same operator wrote its output without first checking that the caller's buffer was long
  enough, so a short output buffer surfaced as an `ArrayIndexOutOfBoundsException` from inside the
  engine rather than the `OutputLengthException` every other AEAD engine reports. Both directions
  of `processBytes()`, and `processByte()`, now check before anything is written or buffered.
- The key factories cast fields of a PrivateKeyInfo or SubjectPublicKeyInfo to the ASN.1 type they
  expected, or used algorithm parameters without checking they were present, so a malformed DH,
  ElGamal, DSA, EC or GOST R 34.10 key gave a `ClassCastException` or `NullPointerException`, and
  `ECNamedDomainParameters.lookup()` built parameters from no curve for an OID it did not know.
  They now go through `getInstance` and refuse absent parameters, and an unknown curve, with an
  `IllegalArgumentException`; an EC private key whose algorithm carries no parameters takes its
  curve from the ECPrivateKey, as RFC 5915 allows.
- PrivateKeyInfo and the CMS SignerInfo, the CMP PKIMessage and PKIHeader refused a sequence
  shorter than their required fields only by failing with a `NoSuchElementException`,
  PrivateKeyInfo a version too large for an int with an `ArithmeticException`, and an OCSP response
  with a status too large for an int was accepted and then failed in `getStatus()`; each is now
  refused when parsed with an `IllegalArgumentException`, which OCSPResp and GeneralPKIMessage
  report as the `IOException` they declare. `RSAKeyParameters` refuses a negative modulus, which
  passed the parity check and failed in the small factor search, and the lightweight `DSASigner`
  refuses a key without domain parameters with an `IllegalArgumentException` rather than a
  `NullPointerException`.
- A GeneralizedTime read without its minutes or seconds and with a fraction of the hour or minute,
  as X.680 allows - `9050010112.100Z`, say - was written as DER with the missing digits appended
  after the fraction, which is not DER and grew each time the value was re-encoded. The fraction is
  now carried down into minutes and seconds (`90500101120600Z` here), and a ',' decimal separator
  becomes the '.' DER requires.
- Both ML-DSA and ML-KEM private key factories decided between the raw and the DER-wrapped pre-RFC
  forms by whether the content parsed, and a raw expanded key is random bytes, so about one in 2^31
  begins with bytes that read as a DER header covering the rest. Such a key was refused, or -
  through the `org.bouncycastle.pqc.crypto.mldsa` key class, which sliced and padded an encoding of
  any length - loaded as a different key. The raw forms are now recognised by their length before
  anything is parsed, and that key class refuses an encoding that is neither a seed nor an expanded
  key.

- Ported from the BC 1.87 development line: the Base64, Base32 and Hex decoders no longer read
  past the range they are given, fail a truncated final Base64 block and refuse non-ASCII input;
  `ISO9796d2PSSSigner` compares the message passed in with the one recovered from the signature,
  and the X9.31 and ISO 9796-2 signers reset on every failed verification; `HMacDSAKCalculator`
  clears its copies of the private scalar and candidate nonce; `CipherInputStream.mark()` and
  `reset()` keep all of the read-ahead state and `CipherOutputStream.close()` is idempotent; the
  `AEADBaseEngine` in-place overlap check counts buffered bytes; DSTU 7624 KGCM, KGMac, KCCM and
  `DSTU7624Mac` refuse the inputs DSTU 7624:2014 excludes and KGCM re-initialises from a clean
  state; the GOST wrap engines take `ParametersWithUKM` outside `ParametersWithRandom` and
  `CryptoProWrapEngine` diversifies a copy of the KEK; the TupleHash length prefix is computed in
  long arithmetic; `Blake2bDigest` and `Blake2sDigest` read their parameter block correctly and keep
  the tree parameters across copies and `reset()`; `KMAC.reset(Memoable)` copies the key; Argon2
  returns every block to its pool zeroised; `DESedeParameters.isWeakKey` checks every part of a key
  at a non-zero offset; `ECPoint.hashCode()` hashes coordinate values, so equal points hash
  equally; `CryptoServicesRegistrar` no longer copies a global property onto the calling thread.
- CCM decryption, in the java and native CCM and in both packet ciphers, applied the payload
  length limit to the input including the tag, so the largest payloads that encrypt were refused on
  decryption; the limit now applies to the payload, and the B0 length field is exactly q bytes.
- The ML-DSA public key (rho, t1) constructor and the ML-DSA and SLH-DSA private key component
  constructors reject components of the wrong length; an ML-DSA private key given a public key
  compares rho as well as t1 with it; and an expanded ML-DSA private key is rejected when its tr
  does not match the hash of its public key.
- The LMS private key reader bounded the master secret by `InputStream.available()`, which refused
  keys read from streams reporting nothing available; it is now bounded by
  `org.bouncycastle.lms.max_seed_length` (default 1024).
- `ASN1Enumerated` now accepts negative values, an ENUMERATED being an integer (X.680 sec. 20).

- ASN.1, from the BC 1.87 development line: the SEQUENCE parsers of the X.509, PKCS, CMS, CRMF,
  CMP, ESF, TSP, OCSP, EAC, DVCS, CMC, ESS, X9, GOST and qualified-certificate types take each
  optional field at most once, in definition order and with its tag checked, and refuse elements
  after the last field; `ASN1InputStream`, the streaming ASN.1 parsers and the streaming CMS and
  time-stamped data parsers report malformed content as the exception they declare; a UTCTime or
  GeneralizedTime day is checked against the length of its month; and a definite-length read no
  longer allocates the full length from the length field before any content arrives.
- The first DER encoding of an `ASN1Set` not built in DER order cached its copy of the elements
  before sorting it, so another thread encoding the same SET, or comparing it with `equals()`, at
  the same time could see the copy unsorted or part way through the sort and produce a wrong DER
  encoding - for example of a CMS SignerInfo's signed attributes when two threads verified the same
  `SignerInformation` at once. The copy is now cached only once it is sorted, and the `ASN1Set` array
  constructor keeps its own copy of the elements it is given.
- `JceKEKAuthEnvelopedRecipient`, `JceKeyAgreeAuthEnvelopedRecipient` and
  `JcePasswordAuthEnvelopedRecipient` have been added: AuthEnvelopedData with authenticated
  attributes could not be read through the KEK, key agreement or password recipients, the
  enveloped-data recipients failing with a `NullPointerException` on the missing AAD stream.
- `ECPoint.multiply` threw a `NullPointerException` from the WNAF precomputation for an unvalidated
  point of small odd order on an Fp curve in Jacobian coordinates, such as (0, 2) on BLS12-381 G1,
  whose table of odd multiples reaches the point at infinity: `ECCurve.normalizeAll` now skips it, and
  `WNafUtil` rebuilds such a table on the curve itself rather than on the isomorphic curve, where a
  doubling would also have used the wrong curve coefficient. Validated points are unaffected.
- DH and ElGamal key pair generation: a private value length equal to the bit length of p is
  accepted again and gives an l-bit private value, as PKCS#3 sec. 7.1 specifies; a private value
  whose public value would fall outside [2, p - 2] is redrawn; and the private value length must be
  at least twice the security strength of p (SP 800-56A Appendix D: at least 304, 352 and 400 bits
  for 4096, 6144 and 8192-bit p), including for the DHIES ephemeral key. A shorter length is now
  refused; set `org.bouncycastle.dh.allow_short_private_value` to `true` to allow it.

**Provider (prov).**

- The raw JCA provider bounded the PBKDF2 iteration count taken from an encoding
  (`org.bouncycastle.pbe.max_iteration_count`, default 10,000,000) but not the counts of the legacy
  PBES1 (PKCS#5 scheme 1) and PKCS#12 PBE families beside it. Their `AlgorithmParameters`
  (`PKCS12PBE` and its OID aliases, `PBKDF1`) accepted any count, narrowing one beyond the `int`
  range with `intValue()` so that 2^32 arrived as 0, and every `Cipher`, `Mac` and
  `SecretKeyFactory` derivation ran with whatever count it was given - including a count decoded by
  another provider's `AlgorithmParameters`, as when `javax.crypto.EncryptedPrivateKeyInfo.getKeySpec()`
  decrypts a PKCS#12 PBE-protected key with BC. As these schemes carry the count in unauthenticated
  parameters and derive before anything can be checked, a supplied blob could hold a derivation for
  tens of minutes. The parameter parse now rejects a negative, beyond-int or over-limit count, and
  the derivations reject a negative or over-limit count, under the same property as PBKDF2. The
  PKCS#12 key store derives through the same code, so an `org.bouncycastle.pkcs12.max_it_count`
  raised above 10,000,000 now needs `org.bouncycastle.pbe.max_iteration_count` raised with it.
- The PKCS#12 key stores wrote the MAC key-derivation parameters of a file they had loaded into
  every file they wrote afterwards, under whatever password the caller stored with. For
  PKCS12-PBMAC1 that carried the loaded file's PBKDF2 salt, iteration count, key length and PRF, and
  one store reused a single PBKDF2 salt across every write, including writes under different
  passwords, with no file loaded at all; the classic store inherited the MAC salt length and digest
  algorithm the same way. The values were also latched before the MAC was verified. The PBKDF2 salt
  and the MAC salt are now generated for every write, the MAC salt at no fewer than 8 octets, and
  nothing is latched until the file has verified. A loaded file's PBKDF2 count is kept only where
  it is at least the count being written with, and raised to it otherwise; that count is the new
  `org.bouncycastle.pkcs12.pbkdf2_it_count`, default 65,536. Reading is unaffected.
- A DSA public key without domain parameters, as a certificate may carry when it inherits them from
  its issuer (RFC 3279 sec. 2.3.2), made `BCDSAPublicKey.toString()`, and so
  `X509Certificate.toString()`, throw a `NullPointerException`, and the DSA Signature classes threw
  one when initialised with such a key or with a null key. The key now prints by its y value alone,
  and initialisation refuses either with an `InvalidKeyException`.

- Ported from the BC 1.87 development line: the KeyAgreement services report the
  `IllegalStateException` `javax.crypto.KeyAgreement` specifies when a secret is asked for before
  `doPhase`, report an initialisation they cannot carry out as a parameter error, refuse a
  `UserKeyingMaterialSpec` salt unless the KDF is HKDF, and the X25519/X448 agreements take the
  unified flag and curve from their own name rather than the `EMULATE_ORACLE` name;
  `ConcatenationKDFGenerator` treats a missing OtherInfo as empty; the KTS Ciphers check a
  `KTSParameterSpec`'s KDF at init.
- The key stores: JKS refuses a store shorter than its checksum with an `IOException`, BCFKS
  `isKeyEntry()` reports PBE key entries, the BC stores empty themselves on a load with a null
  stream, and PKCS#12 generates the MAC salt only when a MAC is written, counts a SunJCE secret key
  bag as protected content, resets the MAC defaults when a file without a MAC is loaded, gives secret
  keys read from JDK-written files their JCA names, and writes 300,000 PBE iterations by default
  (600,000 for the MAC).
- The GOST R 34.10 Signatures verify only a signature of exactly the encoded length; the EC services
  report a key whose domain parameters are not a valid curve with `InvalidKeyException`; the EC IES
  ciphers give `getKeySize` for any EC key `init` accepts; the stream and wrap ciphers refuse an
  `AEADParameterSpec`; ML-KEM, ML-DSA and SLH-DSA keys from other providers are converted via their
  encodings, including through `javax.crypto.KEM`; the composite ML-DSA Signatures discard the
  buffered message on every `initSign` and `initVerify`; certificate signature algorithm names no
  longer come from a non-BouncyCastle provider registered as "BC".
- `CRL.isRevoked()` no longer throws `ClassCastException` for an "X.509" certificate that is not an
  `X509Certificate`.

**CMS, PKIX and EST (pkix).**

- The RFC 9709 content-encryption `AlgorithmIdentifier`, which carries the real algorithm inside
  the parameters of an outer id-alg-cek-hkdf-sha256, was unwrapped at only some of the points where
  a CMS recipient makes a decision about it. Key-size validation in the KEK, RSA-KTS and KEM
  recipients, and in the key-transport recipient's ORI-KEM branch, compared the recovered key
  against the outer identifier, which registers no key size, so `setKeySizeValidation(true)`
  silently checked nothing there; the `setAllowedContentAlgorithms` allow-list and the
  `setMinimumTagSize` floor were applied to the outer identifier on every recipient. The inner
  algorithm is now resolved first at each of these points.
- A CMS message naming the RFC 9709 key derivation but carrying no readable inner
  content-encryption `AlgorithmIdentifier` was reported as a `NullPointerException`, or as an
  `IllegalArgumentException` from the ASN.1 decoder, out of methods declared to throw
  `CMSException`. The places that resolve the wrapper now share one resolver, which reports an
  absent or unreadable inner algorithm as a `CMSException`.
- The CMS RFC 8418 key agreement schemes (dhSinglePass-stdDH-hkdf-sha256/384/512, used with X25519
  and X448) put the user keying material in the entityUInfo of the ECC-CMS-SharedInfo but never used
  it as the HKDF salt, which RFC 8418 sec. 2.2 also requires, so a message carrying a ukm did not
  interoperate with a conforming implementation in either direction. The ukm is now passed as the
  salt as well, on both the generating and the receiving side. A message with a ukm written by
  2.73.11 to 2.73.13 is not readable by this release and vice versa; messages without a ukm, and the
  X9.63-KDF key agreement schemes, are unaffected.
- Building an evidence record was cubic in the number of data objects: `SortedHashList` and
  `SortedIndexedHashList` found each insertion point by walking a `LinkedList`. Each now sorts its
  hashes once, stably, so the order of the leaves and every root hash are unchanged; generating a
  time-stamp request over 8,000 data objects goes from about 210 seconds to under a tenth of a
  second. An `ERSDataGroup` now takes its hash from the `ERSCachingData` cache rather than
  recomputing it on every request, and `ERSArchiveTimeStampGenerator` builds its reduced hash tree
  once rather than on every call.

- The DANE SMIMEA support in `org.bouncycastle.cert.dane` had three defects. `JndiDANEFetcherFactory`,
  when asked for every entry under a bare domain name, removed the first and last characters of the
  owner name the JNDI DNS provider reports for each listed record, assuming a quoted name; the
  provider returns the name unquoted with a trailing root dot, so the first hex digit of the hash
  label was lost and the lookup that followed could never find the record. It now removes only the
  root dot. `DANEEntryStore` kept one entry per owner name, so an address with more than one SMIMEA
  record (a signing and an encryption certificate, say) only ever showed its last; every entry is
  now kept. `DANEEntrySelectorFactory` split an address at its first '@', mis-handling a quoted
  local-part containing one, and threw `StringIndexOutOfBoundsException` rather than `DANEException`
  for an address with none; it now splits at the last '@', removes enclosing quotes and backslash
  quoting from the local-part before hashing as RFC 8162 sec. 3 describes, and rejects an address
  with no '@'. The `DANEEntry(String, byte[])` constructor also now rejects, with an `IOException`,
  a record whose flags do not describe a full certificate entry rather than parsing whatever follows
  the flags as a certificate.
- `SignerInformation.verify()`, and the `isSignatureValid()` methods of X509CertificateHolder
  (including the alternative signature), X509CRLHolder, X509AttributeCertificateHolder and
  PKCS10CertificationRequest and the signature checks of CertificateRequestMessage,
  ProtectedPKIMessage and SignedPublicKeyAndChallenge, let an unchecked `RuntimeOperatorException`
  escape when a DSA or ECDSA signature did not decode; each now reports it as the checked exception
  it declares, with the operator exception as the cause. `JcaContentVerifierProviderBuilder`, given
  a certificate whose key algorithm the provider does not recognise, handed a null key to the
  Signature; it now refuses with an `OperatorCreationException`.
- A CMS AuthenticatedData message using the des-ede3-cbc or rc2-cbc CBC-MAC without authenticated
  attributes started the MAC from the IV in the macAlgorithm parameters, which the MAC does not
  cover when its input is the content alone (RFC 5652 sec. 9.2), so a change to the first eight
  content bytes could be offset by one to the IV. `JceCMSMacCalculatorBuilder` now writes these
  MACs with a zero IV, which earlier releases also verify, and the generators,
  `CMSAuthenticatedData`, `CMSAuthenticatedDataParser` and `RecipientInformation.getMac()` refuse a
  non-zero IV for a message without authenticated attributes. Messages in that form written by
  earlier releases carry a random IV and can be read by setting
  `org.bouncycastle.cms.allow_unauthenticated_cbc_mac_iv` to true; messages with authenticated
  attributes are unaffected. The javadoc examples now use HMAC-SHA256.
- `RecipientInformation.getMac()` did not check the content-type authenticated attribute of a CMS
  AuthenticatedData message, so a message whose authenticated attributes had no content-type
  attribute, or one not matching the eContentType, was accepted. RFC 5652 sec. 9.2 and 9.3 require
  the attribute whenever authenticated attributes are present, with a value matching the
  eContentType; `getMac()` now enforces both, as `SignerInformation` already does for SignedData.
- `PKIXCertPathReviewer` let a delta CRL decide the status of a certificate. A delta CRL lists only
  the changes since its base CRL, so a certificate revoked on the base was reported as not revoked
  when the CRLs the reviewer was given held a current delta and only an expired base, or earlier
  deltas and no base at all. `SignedMailValidator` gives the reviewer the CRLs carried in the signed
  message. As in `CertPathValidator`, only a complete CRL now decides the status of a certificate,
  whether found in the CertStores or fetched from a CRL distribution point; where no current
  complete CRL is available the reviewer reports that rather than a status.
- `PKIXCertPathReviewer` did not refuse a CRL carrying a critical extension other than the issuing
  distribution point and the delta CRL indicator, as RFC 5280 sec. 5.2 requires and
  `CertPathValidator` does, and looked up a certificate on an indirect CRL by serial number alone.
  Such a CRL is now refused, and the entry is matched on the certificate issuer as well.
- The certificate path validators looked a certificate up in an indirect CRL by serial number alone
  and then compared the issuer of whichever entry came first, so where two issuers had each revoked
  the same serial number a certificate whose own entry followed the other issuer's was reported as
  not revoked. The provider's PKIX validator and the pkix `X509RevocationChecker` now check every
  entry carrying the serial number against the issuer it applies to (RFC 5280 sec. 5.3.3), and the
  provider's `X509CRL` implements `getRevokedCertificate(X509Certificate)` the same way.
  `CRL.isRevoked()` on the provider's CRLs stopped at the first entry carrying the serial number and
  now does the same. The validators also look beyond the JDK provider's
  `getRevokedCertificate(BigInteger)`, which sees only the CRL issuer's entries, whenever that lookup
  cannot be conclusive (github #2464).
- `JcaContentVerifierProviderBuilder` and the BC provider's `X509Certificate` and `X509CRL`
  `verify()` no longer verify legacy generic composite signatures (`id_alg_composite`), whose
  creation was removed earlier; such a signature is now refused with "legacy composite signature
  algorithm not supported". The standardised composite ML-DSA signatures are unaffected.

- Ported from the BC 1.87 development line, certification path processing: an empty DNS, rfc822
  host or URI host label is refused under a name constraint of that type; the validators apply the
  RFC 5280 sec. 6.3.3 distribution point name match and reasons intersection, count only
  non-self-issued intermediates against the maximum path length, apply a TrustAnchor's name
  constraints, keep a CRL entry's reasonCode apart from the revocation status and report
  `BasicReason.REVOKED`; `PKIXCertPathReviewer` applies the CRL scope rules, rfc822Name constraints
  to subject DN e-mail addresses and TrustAnchor name constraints, and fetches from CRL distribution
  points only when `org.bouncycastle.x509.enableCRLDP` is set and no error is recorded above the
  certificate; `BasicConstraintsValidation`, `CertificatePoliciesValidation` and `CRLValidation` in
  `cert.path` check pathLenConstraint, policy extensions and CRL currency correctly;
  `LDAPUtils.parseDN` matches the attribute only as an RDN type and decodes DN escapes before
  filter encoding.
- OCSP: `OCSPResp` and `OCSPReq` report a malformed encoding as `CertIOException`, the OCSP ASN.1
  types refuse a short SEQUENCE, and `org.bouncycastle.ocsp.max_response_age` bounds a response
  with no nextUpdate (default one hour).
- CMS and TSP: the RSA-KTS key is derived to the length the wrapping algorithm fixes; 1-pass ECMQV
  uses a fresh ephemeral key pair per recipient and feeds the KDF the DER-encoded
  ECC-CMS-SharedInfo (RFC 5753), keeping the raw-ukm form for earlier messages; the CMS decoders
  and streaming parsers reject short or malformed content with their declared exceptions; the
  algorithm protection attribute is generated from the algorithms actually used;
  `CMSAuthenticatedDataParser` returns its unauthenticated attributes; `TimeStampToken` rejects a
  token whose signing-time attribute disagrees with its genTime, unless
  `org.bouncycastle.tsp.allow_inconsistent_signing_time` is set.
- CRMF, EST and MIME: `PKIPublicationInfo` rejects the combinations RFC 4211 sec. 6.3 forbids,
  `CertificateRequestMessageBuilder.build()` reports bad configurations rather than throwing
  `NullPointerException`, and `ESTResponse` and `mime.Headers` parse repeated and folded headers in
  linear time.

**OpenPGP (pg).**

- Decrypting an OpenPGP message in two steps - recovering the session key from a SKESK packet and
  then decrypting the SEIPD v1 body through `PGPEncryptedDataList.extractSessionKeyEncryptedData()` -
  stopped detecting a wrong passphrase once 2.73.12 suppressed the legacy CFB quick check for every
  session-key decryption. For a password-derived session key the check is what identifies a wrong
  passphrase, and a SKESK v4 packet deriving the session key from the S2K output directly yields a
  well-formed session key for any passphrase, so a wrong one surfaced as a parse or integrity
  failure further down the stream. The new `extractSessionKeyEncryptedData(boolean)` states whether
  the session key came from a password: true restores the check and the
  `PGPDataValidationException` on a wrong passphrase, while the no-argument method goes on
  suppressing it, so a session key recovered from a public key operation is still never quick
  checked.
- `PGPObjectFactory.nextObject()` let an `IllegalArgumentException`, `IllegalStateException` or
  `UnsupportedPacketVersionException` from the object built from a packet escape, although it
  declares only `IOException` - for example for a version 4 SKESK followed by a version 2 SEIPD, an
  order RFC 9580 forbids. Each is now reported as an `IOException` with the original exception as
  its cause.

**Native code.**

- `DumpInfo` no longer prints the native random source information when native support is not
  available.

### 2.1.3 Additional Features and Functionality

- `PGPEncryptedDataList.extractSessionKeyEncryptedData(boolean)` has been added; see above.
- The `org.bouncycastle.pkcs12.pbkdf2_it_count` property (`Properties.PKCS12_PBKDF2_IT_COUNT`)
  sets the PBKDF2 iteration count for a PBMAC1-protected PKCS#12 file's MAC, default 65,536.
- `org.bouncycastle.util.Pack.longToBigEndian()` now writes the eight bytes of the long directly
  rather than through two `intToBigEndian()` calls, which the JIT of JDK 25 compiles to a single
  byte-swapped store. On JDK 23 and later `longToLittleEndian()` does the same, from a copy of
  `Pack` the bcprov and bccore multi-release jars carry under `META-INF/versions/23`, since JDK 23
  is the first whose JIT merges those stores and the form is slower than the existing one on
  earlier JDKs. Packing longs big-endian measured about 5 times as fast on JDK 25 and about 10%
  faster on JDK 8 to 23, and little-endian about 2.2 to 2.7 times as fast on JDK 23 and 25, with
  SHAKE squeezing about 6% and SHA-512 about 4% faster on JDK 25 (github #2474).
- `ChaCha20Poly1305` - and with it the provider's ChaCha20-Poly1305 cipher - now hands runs of
  whole 64-byte blocks to ChaCha and to Poly1305 in one call each, where it used to alternate
  between them one block at a time and, when decrypting, copied every byte through its buffer
  individually. The output is unchanged (github #2481).
- Ported from the BC 1.87 development line: the CRMF `ProtocolEncrKeyControl`,
  `PKIPublicationInfoControl` and `OldCertIDControl` (with JCA forms) and
  `CertificateRequestMessage.getControlValue()`; `Argon2BytesGenerator.getBlockCount()` and a
  public `Argon2BytesGenerator.Block.clear()`; `ASN1Enumerated.isNegative()` and
  `longValueExact()`; and the properties `org.bouncycastle.lms.max_seed_length`,
  `org.bouncycastle.ocsp.max_response_age` and `org.bouncycastle.tsp.allow_inconsistent_signing_time`.
- The property `org.bouncycastle.dh.allow_short_private_value`, which lets DH and ElGamal key pair
  generation use a private value length below twice the security strength of p.

<a id="r2rv73dot13"></a>

### 2.2.1 Version

Release: 2.73.13\
Date: 2026, 22nd September.

### 2.2.2 Defects Fixed

**Lightweight API - secret-dependent operations.**

- The lightweight API had no constant-time modular arithmetic or EC scalar multiplication
  primitives for secret-key operations. `BigIntegers.modAdd`, `modSubtract`, `modMult` and
  `createBlindedExponent`, and `ECAlgorithms.multiplySecret` / `sumOfTwoMultipliesSecret` with the
  supporting `ECConstantTimeMultiplier`, have been ported, and the DSA, ECDSA, ECGOST3410, ECNR,
  DSTU4145 and SM2 signers now use them, with exponent blinding for their secret-key operations.
  GOST3410Signer additionally gained the DSA/ECDSA-style nonce blinding it had been missing.
- DH, ECDH, ECDHC, ECVKO, MQV, ECMQV, SM2, SRP and J-PAKE key agreement now use constant-time EC
  scalar multiplication, exponent blinding and constant-time evidence/MAC-tag comparison.
- The EC ElGamal transform classes and the ElGamal, SM2, Naccache-Stern and Cramer-Shoup engines,
  and the ECIES and RSA KEMs, have been hardened against timing side channels. RSA-KEM
  decapsulation is now blinded, Cramer-Shoup performs a ciphertext range check, and the
  invalid-point-encoding exception message is zero-padded.
- The Zuc MAC comparison is now constant-time, and `DSTU7624WrapEngine` uses a constant-time
  checksum comparison.
- `IESEngine` computed its MAC over the padding buffer rather than the actual cipher-mode output
  length.

**Lightweight API - malformed input, bounds and state.**

- `SICBlockCipher` (CTR) propagated its borrow incorrectly for counter increments carrying across
  0xFF IV bytes, and `skip()` moved to the wrong position for backward moves smaller than the
  current intra-block offset. The full-block-IV counter advance is bounded at 2^64 blocks, the
  short-IV range check now covers the `processBlock` path, and the skip/seekTo cascades are a
  constant-time counter addition. The 2^64-block bound is also enforced on the skip path for
  8-byte block ciphers, and the native CTR range bound and `getPosition()` were aligned with the
  Java path.
- `Salsa20Engine.skip(Long.MIN_VALUE)` silently moved nothing while reporting that it had, because
  negating the argument overflowed back to itself; the ChaCha family sharing the engine had the
  same defect, and ChaCha/ChaCha7539 skip carry now uses the unsigned comparison.
- A dropped squeezing flag in Kangaroo broke repeated Xof `output()` calls; the `GOST28147`, `RC2`,
  `DESede` and `DSTU7624` wrap engines gained unwrap-length guards; and `ISO9796d2Signer` rejects a
  too-short recovered block instead of raising an uncaught `ArrayIndexOutOfBoundsException`.
- `TupleHash` and `ParallelHash` bind the requested output length as the NIST SP 800-185 L
  parameter rather than the configured digest size.
- Blake2b's counter overflow handling was corrected, `OldHMac`'s broken constructor restored, and
  the digest-state-restore `CryptoServicePurpose` decoupled from the enum ordinal.
- LMS/HSS now reject malformed and trailing-data signatures and reused-mode signers, raise a clear
  error rather than a `NullPointerException` for an unknown LM-OTS type code, and the HSS
  key-exhaustion off-by-comparison is fixed (github #2414). `ExhaustedPrivateKeyException` was
  given a common superclass so catching the new one also catches the legacy `pqc.crypto` one, and
  the LMS/HSS tree cache adopted upstream's versioning (github #2365/#2414).
- `HashSLHDSASigner` and `SLHDSASigner` gained uninitialised-use guards, and SLH-DSA's double
  hypertree-root computation was removed.
- The HPKE context advances its sequence number only after Seal and Open succeed, per RFC 9180
  sec. 5.2, and HPKE DHKEM uses `ECDHCRawAgreement` directly rather than wrapping a basic
  agreement.
- DSA and GOST3410 private keys validate that x lies in [1, q-1] at construction, ML-DSA and ML-KEM
  private keys validate their encoding length, and `PublicKeyFactory` rejects an out-of-range DH
  `pgenCounter` rather than silently truncating it.
- Zeroization on `destroy()` was added to the RSA, EC, DSA, GOST3410, ElGamal and DH private key
  parameter classes, and to the LMS and HSS private key parameters.

**ASN.1 and encoding.**

- `BMPString` content was read by sizing a `char[]` from the declared length before any content had
  arrived, so a short crafted header could drive a 1GB allocation and an `OutOfMemoryError` out of
  a parse API declaring `IOException`. It is now read through `DefiniteLengthInputStream`.
- Sorting the elements of a DER SET re-derived an element's encoding every time the insertion sort
  shifted it, costing O(N^2) encodings; each element is now encoded once and the ordering uses a
  stable O(N log N) sort.
- The BER/DER generators encoded context tag numbers of 31 and above incorrectly.
- Too-short-SEQUENCE and mandatory-field-consistency guards were added to `RevAnnContent`,
  `CertRequest`, `EvidenceRecord`, `TSTInfo`, `PasswordRecipientInfo`, `KEKRecipientInfo`,
  `AuthenticatedData` and `KEMRecipientInfo`, so a malformed encoding raises
  `IllegalArgumentException` rather than an `ArrayIndexOutOfBoundsException`; `EvidenceRecord`'s
  always-false length check was corrected.
- A copy-paste `instanceof` bug in three OER `getInstance()` methods (`UINT32`, `Version`,
  `EtsiTs103097DataEncryptedUnicast`) and an inverted `isInstance` check in `OEROptional` were
  fixed; malformed OER structures are reported as `IOException`, and an unknown OER extension is
  consumed in bounded chunks.
- `X500Name.hashCode()` guards the RDN first-element lookup, and RFC 4514 unescaping was hardened.
- A wire-declared length is read through `Streams.readLenBytesFully`.

**Provider (prov).**

- The AES, ARIA, SM4 and PBKDF2 GCM/CCM parameter handling was hardened and the raw JCA PBKDF2
  iteration count capped; the PKCS#12 and BCFKS write-side iteration counts are configurable; BCFKS
  scrypt keys derive with p rather than the block size; and the PBKDF2 keyLength taken from a BCFKS
  keystore or a PBMAC1 PKCS#12 file is bounded before deriving.
- The OCSP response read is bounded, and future-dated and unbounded responses are rejected. An
  unreachable or failing OCSP responder is reported as a recoverable failure naming the responder
  rather than a definite "configuration error", so path validation can fall back to CRL checking.
- A reused `CertPathBuilder` reported the previous build's failure; the builder was hardened
  against large self-issued candidate sets, the X.509 valid-policy-tree size is bounded, and
  `PKIXPolicyNode.copy` re-parents its children.
- `ReasonsMask.hasNewReasons` was written as `(_reasons | mask ^ _reasons) != 0`, where `^` binds
  tighter than `|`, so it reported new reasons for almost any pair of masks. The RFC 5280 sec.
  6.3.3 CRL scope rules are now single-sourced in the pure-ASN.1
  `org.bouncycastle.asn1.x509.PKIXCRLValidator`, with `RFC3280CertPathUtilities` delegating to it.
- The X509CRL implementation actually used had an indirect-CRL issuer defect; the BKS keystore
  exception type, the PKCS12 alias and public-key checks and the CRL `dateOfCertGen` handling were
  corrected, and `KeyStore.getCertificateAlias` on a PKCS12 keystore could return the alias of an
  unrelated certificate.
- Composite ML-DSA registration, key derivation and the `SignatureSpi` (empty-message signing,
  `SecureRandom` threading, context bound) were fixed, as was the composite ML-KEM OID map; EC
  components are normalised and the composite key attributes published.
- SLH-DSA `Signature` instances are bound to their named parameter set; the ML-DSA key-confusion
  defect was fixed (github #2396/#2397); PQC SPI `NullPointerException`s were removed; and ML-KEM
  encapsulation through `javax.crypto.KEM` was fixed - the JDK 17 source set carrying those SPIs
  was not being compiled at all, so the shipped encapsulator threw `ClassCastException` on every
  call.
- `LMSSignatureSpi` resets its digest on every exit and narrows its verify catch, and an LMS key
  that has been destroyed is refused at `initSign`.
- RIPEMD-with-RSA-PSS is supported end to end, and a PSS `trailerField` state-corruption defect was
  fixed.
- EC key agreement and ETSI KEM secrets are derived into a `byte[]` rather than a `BigInteger`, so
  leading zero bytes are not lost; `KdfUtil` guards a short secret; `BouncyCastleProvider`
  construction is thread-safe and no longer materialises every named curve; and the DH
  `KeyAgreementSpi` blinds the exponent of its raw `modPow` finish-agreement step.
- The multi-release EdEC overlays had drifted from the base implementations: the jdk1.11
  `KeyAgreementSpi` dropped the HKDF salt and the jdk1.15 `SignatureSpi` lost the encoding
  fallback.
- KMAC `AlgorithmParameters` and the RFC 8702 OIDs are registered, the LMS OTS name table is
  complete, and `BaseAgreementSpi` validates the requested key size.
- The `org.bouncycastle.jce.exception` package is deprecated in favour of the
  `java.security.cert` exceptions.

**CMS, PKIX and EST (pkix).**

- Both copies of `PKIXCertPathReviewer` drove `checkNameConstraints` from a loop bound of
  `index > 0`, so name constraints were never applied to the target certificate (CVE-2026-71889).
- A PBMAC1 MAC-key-length floor is enforced and PBMAC1's KDF algorithm OID corrected; scrypt
  parameters are bounded and empty or absent ASN.1 content rejected.
- CMS malformed-content handling no longer lets undeclared unchecked exceptions escape;
  `EnvelopedDataHelper` honours a caller-supplied `SecureRandom` and gained the GCM, SM4 and KMAC
  content-cipher names; the RFC 9629 KEM recipient family was added for the JCE, with a KEK-length
  check; and `CMSInputAEADDecryptor` is shared between the AuthEnveloped recipients.
- Definite-length CMS streaming was added and wired through the generators.
- TSP/ERS malformed-content handling was hardened and the digest-algorithm equivalence checks
  corrected.
- The composite ML-DSA name mappings were migrated to the IANA arc, fixing a live mismatch, and the
  Composite ML-KEM names added to the name finder.
- The CRL distribution point protocol allow-list is opt-in, `CrlCache` handles non-HTTP schemes, and
  a DANE null-guard was added.
- The policy tree is null-checked before dereferencing the node to remove, a composite-key
  verification guard and an EST digest-lookup fix were added, and dead legacy composite-signature
  creation was dropped.
- RFC 7894 `tls-unique` attribute support was added to EST, and a `close()` failure is no longer
  reported in place of an EST 204/404 status.

**TLS and JSSE (tls).**

- DTLS gained RFC 9147 invalid-record resilience; the reassembly gap list is bounded and its scan
  starts from a binary search.
- The TLS 1.3 signature-scheme and named-group coupling was corrected, along with the JSSE
  early-key-share handling, the ML-KEM FIPS-group classification and the curveSM2 filter.
- SRP-6a gained exponent blinding and constant-time M1/M2 comparison, and the SRP verifier
  generator's random wiring was fixed.
- JSSE cipher-suite-order defaults were brought to parity with the reference implementation,
  `org.bouncycastle.jsse.useNamedGroupsOrder` is wired as a context default, and privileged file
  I/O gaps were closed.
- `tls/src/main/jdk25` is now compiled and shipped as `META-INF/versions/25`; it carries the
  RFC 5705 `exportKeyingMaterial*` overrides and previously belonged to no source set at all, so
  the jar shipped without it.

**OpenPGP (pg).**

- The AEAD decryption streams in `BcAEADUtil` and `JceAEADUtil` re-throw an `EOFException` from the
  underlying packet stream as a plain `IOException` ("truncated AEAD data"), which
  `nextPacketTag()` does not launder, so a truncated message is reported rather than read back as a
  shorter well-formed one (CVE-2026-85515).
- ASCII armor gained DoS caps and now rejects a second checksum line; signature subpacket bodies
  are validated; a pad count past the end of the buffer is folded into the `PGPPad` reject; the
  `PGPSecretKeyParser` extended-header loop terminates on end of input; `KeyBoxByteBuffer.rangeOf`
  checks its end on its own; the encrypted session key length is checked before the index; and the
  SEIPDv2 AEAD chunk size is capped.
- `PGPPublicKey.hasRevocation` raised a `NullPointerException` on an encryption-algorithm primary
  key.
- The bcrypt round count for an encrypted OpenSSH v1 private key is capped, configurably, through
  `org.bouncycastle.openssh.max_rounds`, and malformed OpenSSH public keys surface as
  `InvalidKeySpecException`.

**S/MIME (mail, jmail).**

- The depth of nested multipart content is bounded in both S/MIME canonicalisers.
- The journaling encryptor is rebuilt from its OID.

**Native code.**

- Every CPUID leaf read is bounded by the range the CPU reports, so a leaf the CPU lacks reads as
  feature-absent rather than as another leaf's bits, and RDRAND/RDSEED are gated behind CPUID.
- The ARM SHA block loads were corrected, the key-derived S-box lookup was removed from the ARM AES
  key schedule, and the ARM SHAKE mixed `doOutput`/`doFinal` continuation was fixed.
- The native packet ciphers wrote the expanded key over the caller's output buffer when the input
  and output arrays aliased, so an in-place packet encryption returned the raw AES key in place of
  the ciphertext it was asked for (CVE-2026-71883).
- A native packet CTR request past the counter's capacity reported a full success length while
  producing keystream that had wrapped; such a request is now rejected (CVE-2026-71884).
- `memzero` was ported to hand-written assembly; SHA-224/256 no longer export processed block state;
  the AVX SHA-224 path mitigates a potential unaligned output store; and CTR skip is failure-atomic
  on a rejected move.
- The native CTR counter carries into the high lane when a 16-byte IV's low lane wraps, and
  `getPosition` reports the offset rather than the counter.
- The native entropy source retried `RDSEED` and `RDRAND` without any bound, spinning for as long
  as the carry flag stayed clear, so a persistent failure of the instruction left the calling thread
  looping inside the JNI call where it could be neither interrupted nor timed out. The retry loops
  are now bounded - 200 attempts for `RDSEED` and 20 for `RDRAND`, twice Intel's baselines - and on
  exhaustion the routine clears any partially written buffer with an un-elidable `memzero` and
  throws (CVE-2026-8798).
- RDRAND/RDSEED retries are adjustable; the one-shot hybrid no longer casts its base entropy source
  to `IncrementalEntropySource`; and `DumpInfo` reports the RNG source selection without seeding a
  DRBG to do it.

### 2.2.3 Additional Features and Functionality

- CBOM and SBOM generation has been added to the build.
- The JCE KEM recipient family for CMS (RFC 9629) has been added, together with definite-length CMS
  streaming.
- BCJSSE now implements server-side OCSP stapling (`status_request` / `status_request_v2`) and
  socket-level handshake timeouts.
- RFC 7250 raw public key certificates are supported (`JcaTlsRawKeyCertificate`).
- The JSSE provider ships an RFC 5705 `exportKeyingMaterial*` implementation for Java 25 and later
  as `META-INF/versions/25`.
- EST supports the RFC 7894 `tls-unique` attribute.
- New DoS-hardening `Properties` constants were added, together with opt-ins for zoneless UTCTime
  and empty-issuer certificates.
- The native RNG settings moved onto the native services, with a new `native.rand` selector.
- The build now requires `LTS_JDK25`; see README.md for why this is not optional.

### 2.2.4 Additional Notes

- The following CVEs addressed in the regular Java release 1.86 do not apply to this distribution,
  as the affected components are not shipped in the LTS edition: CVE-2026-17507, CVE-2026-71885 and
  CVE-2026-71890 (MLS, `org.bouncycastle.mls`), CVE-2026-18036 (NTRU), CVE-2026-18040 (HQC),
  CVE-2026-71891 (BLS12-381), and CVE-2026-71886 and CVE-2026-71887 (the high-level OpenPGP API
  introduced in 1.81, `org.bouncycastle.openpgp.api`). For the same reason only the AEAD route of
  CVE-2026-85515 was reachable here; the SEIPDv1 route runs through the high-level OpenPGP API.
- As in earlier LTS releases, the native paths may buffer input differently from the pure-Java
  implementations, so `CipherInputStream.read(byte[])` and lightweight `processBytes` calls can
  return short reads. Always check returned lengths, and use `Streams.readFully(...)` or
  `DataInputStream.readFully(...)` where a full read is required. See README.md.

### 2.2.5 Security Advisories.

Release 2.73.13 deals with the following CVEs:

- CVE-2026-8798 - Native entropy source retries the CPU entropy instructions without limit.
- CVE-2026-17508 - Password-based KDF cost parameters honoured unbounded from untrusted input across the remaining PBE entry points.
- CVE-2026-71883 - Native AES packet cipher returns the raw AES key on an alias.
- CVE-2026-71884 - Packet CTR reports a full success length after the counter is exhausted.
- CVE-2026-71888 - CMS AuthenticatedData exposes attacker-inserted authAttrs when digestAlgorithm is absent.
- CVE-2026-71889 - PKIXCertPathReviewer does not apply X.509 name constraints to the target certificate.
- CVE-2026-85515 - OpenPGP message truncation not reported, bypassing the SEIPDv1 integrity check.

<a id="r2rv73dot12"></a>

### 2.3.1 Version

Release: 2.73.12, 2.73.12.1\
Date: 2026, 16th July.

### 2.3.2 Defects Fixed

**Lightweight API and ASN.1.**

- Upstream's hardened AEAD modes were merged while preserving the LTS native paths: `GCMBlockCipher`,
  `CCMBlockCipher` (MAC verify before write, nonce-reuse guard), `EAXBlockCipher` (nonce-reuse
  guard, MAC-size validation), the OCB nonce-reuse guard, `KGCMBlockCipher` and `KCCMBlockCipher`
  (partial-block handling, tag verify before decrypt, nonce guard, parameter validation). The CCM
  nonce-reuse guard is enforced on the native path as well.
- `IESEngine` stream mode derived its MAC key from a length-dependent KDF split, which allowed a MAC
  forgery; the static-key path was corrected with it.
- The `KCCMBlockCipher` MAC did not bind the nonce when no AAD was present, permitting a cross-nonce
  AEAD forgery.
- RSA PKCS#1 verification skipped the last two hash bytes on the NULL-omitted path, and strict
  DigestInfo checking was adopted.
- DH/DSA modulus sizes and Argon2 cost parameters are bounded; the MTI/A0 DH agreement no longer
  exponentiates an unvalidated peer value; X25519 and X448 gained null and bounds validation; and
  ECIES-KEM and LMS/HSS reject malformed input.
- The HSS public-key level count was unbounded, allowing a large allocation on verify, and LMS/HSS
  public-key parsing now rejects malformed keys.
- Lazy ASN.1 sequence forcing reset the nesting-depth guard; the depth limit is now enforced on the
  lazy parse path, thirteen core ASN.1 factories reject malformed and empty SEQUENCEs, explicit-tag
  validation was adopted, and a definite-length read no longer allocates up-front from an unbounded
  declared length.
- Stringifying an X.500 distinguished name escaped in quadratic time; X.500 name validation,
  `hashCode` hardening and the `PrivateKeyHashUtil` private-key `hashCode` hardening were adopted.
- The OER parser recursed without a depth limit on the self-referential IEEE 1609.2 schema.
- Non-DER time enforcement was completed on both the parse and DER-write sides.
- Upstream's ARIA, GOST3412-2015, Salsa20, Camellia and ML-DSA `PolyVec` refactors were merged,
  along with the `SkeinEngine` overflow fix, `BigIntegers` additions (`areSecretValuesEqual`,
  `hasAnySmallFactors`) and the ECDH-C constant-time agreement refactor.
- SHA-3 and SHAKE state persistence was hardened further in 2.73.12.1.

**Provider, keystores and cert paths.**

- BKS and UBER keystores allocated from untrusted lengths before the integrity check, BKS accepted a
  legacy version with a 16-bit integrity MAC key, and the BKS/PKCS12 keystore KDF iteration counts
  are now bounded.
- The BCFKS keystore load honoured unbounded KDF cost from the file; those parameters are now
  bounded before verification.
- PKCS#12 MAC and bag-decryption KDF iteration counts, and attacker-supplied PKCS12/CRMF PBE
  iteration counts, are bounded.
- PKCS#8 and PBES2 decryptors honoured unbounded KDF cost from their input.
- Name constraints could be bypassed with a trailing dot in an `rfc822Name` or URI; a
  name-constraint bypass test and a reviewer diagnostic flagging a name-constraints extension on a
  non-CA certificate were added.
- The X.509 valid-policy-tree size is bounded (CVE-2023-0464 class DoS), and CRL revocation checking
  fails closed.
- A stapled OCSP response was accepted without being bound to the certificate being checked, and an
  exceptional-signature-rejection test was added (github #2254).
- The CRL cache gained a TTL, ML-KEM key material is zeroized in a binary-compatible way, ARIA CCM
  was fixed, and composite malformed-input guards were added.
- `id-RSASSA-PSS` is routed through PSS in the Bc operator builders (github #721), the dead generic
  composite verify branch in `JcaContentVerifierProviderBuilder` was removed, and BSI ECKA-EG
  algorithms are routed as EC key agreement (#790).
- The prov jdk17 ML-KEM JCE SPIs compile against the backported `javax.crypto.KEM`.

**CMS, PKIX, TLS, OpenPGP and S/MIME.**

- CMS `AuthEnvelopedData` did not enforce the tag length on decryption; a CMS recipient
  content-algorithm allow-list and an AEAD tag-size floor were added and extended to KTS recipients,
  and the GCM ICV length is enforced with CCM AEAD parameters routed correctly.
- CMS `verifySignatures` returned true for a `SignedData` carrying no signers, and
  `AuthenticatedData` content was not bound to the MAC when `authAttrs` were present.
- `KEMRecipientId` was ported and `KEMRecipientInformation` wired to the correct recipient id; the
  CMS ML-DSA digest defaults to SHA-512.
- CRMF/CMP password-MAC honoured an unbounded iteration count.
- The DTLS handshake reassembler allocated its buffer from an unchecked 24-bit length.
- The JSSE hostname verifier's CN fallback was enabled by default despite being documented as
  opt-in; it is now gated per RFC 9525. The server handshake timeout is honoured in
  `ProvTlsServer`.
- OpenPGP AEAD decryption skipped the final tag on chunk-aligned data, the CFB quick-check oracle
  was active on the symmetric and session-key paths, Argon2 S2K honoured attacker-chosen memory and
  pass counts, and a user-attribute subpacket length was bounded only by the JVM's maximum memory.
  OpenPGP AEAD encryption on the native GCM path failed with an output buffer too small.
- The S/MIME validator trusted the signer-asserted `signingTime` for path validation; a writer
  header-injection test was added and wired.
- PEM header checking was added, and encrypted OpenSSH private-key support was ported.

**Native code.**

- A missing CCM decrypt MAC-size check caused a heap overflow on the ARM path.
- Three low-severity Intel JNI defects were fixed, and ARM variant selection was improved.

### 2.3.3 Additional Features and Functionality

- The index reconciliation workflow against the upstream bc-java tree, and the hidden stale-source
  residual scan, are documented in CLAUDE.md, with a `reconcile-residuals` skill to drive them.
- `module-info` exports dropped from bcutil and bcprov were restored for JPMS and OSGi consistency.
- SM2 PKCS#7 content-type OIDs were added to `GMObjectIdentifiers`, and ML-KEM private-key parsing
  was enabled in the PQC `PrivateKeyFactory`.

### 2.3.4 Security Advisories.

Release 2.73.12 deals with the following CVEs:

- CVE-2026-8763 - Name Constraints bypass via trailing dot in rfc822Name and URI.
- CVE-2026-12185 - BKS/UBER keystore allocates from untrusted lengths before integrity check.
- CVE-2026-12802 - CMS AuthEnvelopedData fails to enforce tag-length on decryption.
- CVE-2026-12803 - KCCMBlockCipher MAC does not bind nonce when AAD is absent (cross-nonce AEAD forgery).
- CVE-2026-12816 - IESEngine stream-mode MAC forgery via length-dependent KDF split.
- CVE-2026-12817 - OpenPGP AEAD decryption skips final tag on chunk-aligned data.
- CVE-2026-12860 - RSA PKCS#1 verification skips last two hash bytes in NULL-omitted path.
- CVE-2026-13506 - Lazy ASN.1 sequence forcing resets nesting-depth guard.
- CVE-2026-13586 - PKCS#12 MAC and bag-decryption KDF iteration-count bound (DoS).
- CVE-2026-14682 - Possible OOM from unbounded up-front allocation on a definite-length read.
- CVE-2026-15055 - PKCS#8 / PBES2 decryptors honour unbounded KDF cost from input.
- CVE-2026-58059 - Quadratic-time escaping when stringifying X.500 distinguished names.
- CVE-2026-58060 - HSS public-key level count unbounded, enabling huge allocation on verify.
- CVE-2026-58061 - CCM-family modes write plaintext to caller buffer before tag check.
- CVE-2026-58062 - Stapled OCSP response accepted without binding to the checked certificate.
- CVE-2026-58063 - BCFKS keystore load honours unbounded KDF cost from untrusted file.
- CVE-2026-59638 - JSSE hostname verifier CN-fallback enabled by default despite documented opt-in.
- CVE-2026-59639 - CMS verifySignatures returns true for SignedData with zero signers.
- CVE-2026-59640 - OpenPGP CFB quick-check oracle active on symmetric/session-key paths.
- CVE-2026-59641 - S/MIME validator trusts signer-asserted signingTime for path validation.
- CVE-2026-59642 - CMS AuthenticatedData content not bound to MAC when authAttrs present.
- CVE-2026-59645 - OER parser recurses without depth limit on self-referential IEEE 1609.2 schema.
- CVE-2026-59646 - DTLS handshake reassembler allocates buffer from unchecked 24-bit length.
- CVE-2026-59647 - CRMF/CMP password-MAC honours unbounded iteration count.
- CVE-2026-59648 - OpenPGP Argon2 S2K honours attacker-chosen memory and passes.
- CVE-2026-59649 - OpenPGP user-attribute subpacket length bounded only by JVM max memory.
- CVE-2026-59650 - MTI/A0 DH agreement exponentiates unvalidated peer value.
- CVE-2026-59651 - BKS keystore accepts legacy version with 16-bit integrity MAC key.
