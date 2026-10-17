# Core compatibility vectors

`core-vectors.json` contains only public synthetic test keys, never wallet keys.
The 48-byte SLH generation seed is the sequence `00 01 ... 2f`; the BLS private
scalar is the integer one.

The accompanying C++ generator was compiled against:

* Syscoin legacy BasicSchemeMPL library from current Core
  `dd1457d89a5906288d0c0813a157413e79f75f6d`;
* Core PR #609 source `fa24600369c7afbe338afc09d07c840d21c2e205`, including
  `pq_global_auth.cpp`, `pq_chainlock_types.cpp`, `slhdsa.cpp`, and Core's
  bundled SLH-DSA-SHAKE-128s implementation.

It uses Core `CDataStream`, `CHash256`, `GetProviderServiceAuthorizationHash`,
`GetGlobalAuthContext`, and `slhdsa::SignDeterministic`, not the TypeScript SDK.
The legacy service preimage omits the signature as `SER_GETHASH` requires.
Provider payload signatures are domain-specific and these vectors use fabricated
proTx/prevout hashes, not spendable transactions or on-chain registrations.

The SDK tests compare exact byte preimages, registered-record serialization,
input hashes, authorization digests, public keys and deterministic signatures in
both implementations. Separate integration tests use correctly hashed synthetic
funding transactions for the complete wallet review/sign/verify flow.

`generate-management-vectors.cpp` and `management-core-vectors.json` extend this
coverage to registration, registrar updates, revocation, owner proofs and global
operator enrollment/rotation. The generator uses Core CDataStream field layouts,
Core Bech32 address encoding, the same libsecp256k1 recoverable RFC6979 signing
routine as CKey::SignCompact, BasicSchemeMPL, and the actual Core global/PQ
authorization functions. Registration/registrar owner domains are serialized
explicitly as specified in Core's providertx.cpp. Long secondary SLH signatures
are represented by SHA256d hashes in this fixture to limit checked-in size; the
SDK tests recompute the full signature and compare its hash.

The management funding transaction is a synthetic coinbase with a correctly
computed transaction ID, enabling full SDK fee review in those vector tests.
Its external registration collateral hash is intentionally fictitious: that
part of the vector tests the protocol encoding/message only, never an on-chain
registration claim. Complete collateral validation is covered separately by the
management integration tests.
