// Public synthetic key only. Cross-checked with Syscoin Core 9bdd0a0dd9.
// To reproduce, temporarily include this file from src/test/fs_tests.cpp in a
// configured Core checkout, build test/test_syscoin, and run:
// test/test_syscoin --run_test=governance_vector_probe --log_level=message
// The committed JSON contains the six GOVERNANCE_VECTOR output objects.
#include <test/util/setup_common.h>
#include <governance/governancevote.h>
#include <key.h>
#include <pubkey.h>
#include <protocol.h>
#include <univalue.h>
#include <util/strencodings.h>
#include <boost/test/unit_test.hpp>
#include <iostream>

BOOST_FIXTURE_TEST_SUITE(governance_vector_probe, BasicTestingSetup)
BOOST_AUTO_TEST_CASE(known_key_votes)
{
    const auto secret = ParseHex("0000000000000000000000000000000000000000000000000000000000000001");
    for (const bool compressed : {true, false}) {
        CKey key;
        key.Set(secret.begin(), secret.end(), compressed);
        for (int outcome = 1; outcome <= 3; ++outcome) {
            const auto collateral = uint256S("00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff");
            const auto parent = uint256S("ffeeddccbbaa99887766554433221100ffeeddccbbaa99887766554433221100");
            const uint32_t index = outcome == 3 ? 2147483647 : outcome - 1;
            const int64_t timestamp = outcome == 1 ? 1700000000 : outcome == 2 ? 4294967297LL : 9007199254740991LL;
            CGovernanceVote vote(COutPoint(collateral, index), parent, VOTE_SIGNAL_FUNDING, static_cast<vote_outcome_enum_t>(outcome));
            vote.SetTime(timestamp);
            BOOST_REQUIRE(vote.Sign(key, key.GetPubKey().GetID()));
            BOOST_REQUIRE(vote.CheckSignature(key.GetPubKey().GetID()));
            CDataStream serialized(SER_NETWORK, PROTOCOL_VERSION);
            serialized << vote;
            std::vector<unsigned char> signature;
            for (auto it = serialized.end() - 65; it != serialized.end(); ++it) signature.push_back(std::to_integer<unsigned char>(*it));
            UniValue obj(UniValue::VOBJ);
            obj.pushKV("collateralHash", collateral.GetHex());
            obj.pushKV("collateralIndex", index);
            obj.pushKV("proposalHash", parent.GetHex());
            obj.pushKV("outcome", outcome);
            obj.pushKV("timestamp", timestamp);
            obj.pushKV("digest", HexStr(vote.GetSignatureHash()));
            obj.pushKV("signatureHash", vote.GetSignatureHash().GetHex());
            obj.pushKV("voteHash", vote.GetHash().GetHex());
            obj.pushKV("voteSig", EncodeBase64(signature));
            obj.pushKV("publicKey", HexStr(key.GetPubKey()));
            obj.pushKV("compressed", compressed);
            std::cout << "GOVERNANCE_VECTOR " << obj.write() << std::endl;
        }
    }
}
BOOST_AUTO_TEST_SUITE_END()
