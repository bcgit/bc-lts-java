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

<a id="r2rv73dot13"></a>

### 2.1.1 Version

Release: 2.73.13\
Date: 2026, 22nd September.

### 2.1.2 Defects Fixed

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

### 2.1.3 Additional Features and Functionality

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

### 2.1.4 Additional Notes

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

### 2.1.5 Security Advisories.

Release 2.73.13 deals with the following CVEs:

- CVE-2026-8798 - Native entropy source retries the CPU entropy instructions without limit.
- CVE-2026-17508 - Password-based KDF cost parameters honoured unbounded from untrusted input across the remaining PBE entry points.
- CVE-2026-71883 - Native AES packet cipher returns the raw AES key on an alias.
- CVE-2026-71884 - Packet CTR reports a full success length after the counter is exhausted.
- CVE-2026-71888 - CMS AuthenticatedData exposes attacker-inserted authAttrs when digestAlgorithm is absent.
- CVE-2026-71889 - PKIXCertPathReviewer does not apply X.509 name constraints to the target certificate.
- CVE-2026-85515 - OpenPGP message truncation not reported, bypassing the SEIPDv1 integrity check.

<a id="r2rv73dot12"></a>

### 2.2.1 Version

Release: 2.73.12, 2.73.12.1\
Date: 2026, 16th July.

### 2.2.2 Defects Fixed

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

### 2.2.3 Additional Features and Functionality

- The index reconciliation workflow against the upstream bc-java tree, and the hidden stale-source
  residual scan, are documented in CLAUDE.md, with a `reconcile-residuals` skill to drive them.
- `module-info` exports dropped from bcutil and bcprov were restored for JPMS and OSGi consistency.
- SM2 PKCS#7 content-type OIDs were added to `GMObjectIdentifiers`, and ML-KEM private-key parsing
  was enabled in the PQC `PrivateKeyFactory`.

### 2.2.4 Security Advisories.

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
