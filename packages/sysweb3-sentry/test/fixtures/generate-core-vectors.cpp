#include <crypto/slhdsa/slhdsa.h>
#include <crypto/sha256.h>
#include <hash.h>
#include <streams.h>
#include <llmq/pq_global_auth.h>
#include <dashbls/bls.hpp>
#include <array>
#include <cstdio>
#include <vector>
#include <string>

template<class R> std::string hex(const R& r) { static const char* h="0123456789abcdef"; std::string s; for(auto c:r){s+=h[(uint8_t)c>>4];s+=h[(uint8_t)c&15];}return s; }
template<class R> uint256 hash256(const R& r) { uint256 out; CHash256().Write(Span<const unsigned char>{reinterpret_cast<const unsigned char*>(r.data()),r.size()}).Finalize(out); return out; }
int main() {
    const auto uniform=[](unsigned char c){uint256 h;std::fill(h.begin(),h.end(),c);return h;};
    const auto genesis=uniform(0x44), protx=uniform(0x11), prevtx=uniform(0x22);
    CDataStream prevouts(SER_NETWORK,0); prevouts << prevtx << uint32_t{1};
    const auto inputs_hash=hash256(prevouts);
    std::vector<unsigned char> payout{0,20}; payout.insert(payout.end(),20,0x33);
    std::vector<unsigned char> nevm(20,0x55);
    std::array<unsigned char,16> addr{};addr[10]=0xff;addr[11]=0xff;addr[12]=127;addr[15]=1;
    CDataStream payload(SER_NETWORK,0);payload << uint16_t{3} << protx;
    payload.write(AsBytes(Span{addr})); const std::array<unsigned char,2> port{0x47,0xbf};payload.write(AsBytes(Span{port}));
    payload << payout << inputs_hash << nevm;
    const auto legacy_hash=hash256(payload);
    std::vector<uint8_t> secret(32);secret.back()=1;
    const auto sk=bls::PrivateKey::FromByteVector(secret);
    const std::vector<uint8_t> legacy_digest(legacy_hash.begin(),legacy_hash.end());
    const auto sig=bls::BasicSchemeMPL().Sign(sk,legacy_digest).Serialize(false);
    const auto pub=sk.GetG1Element().Serialize(false);
    std::printf("{\"legacy\":{\"payloadPreimageHex\":\"%s\",\"inputsHash\":\"%s\",\"authorizationHash\":\"%s\",\"publicKey\":\"%s\",\"signature\":\"%s\"},",hex(payload).c_str(),hex(inputs_hash).c_str(),hex(legacy_hash).c_str(),hex(pub).c_str(),hex(sig).c_str());
    slhdsa::KeyGenerationSeed seed{}; for(size_t i=0;i<seed.size();++i)seed[i]=i;
    auto pqkey=slhdsa::GenerateSecretKey(seed);if(!pqkey)return 2;
    llmq::pq::GlobalKeyRecord record;record.key_version=1;record.activated_height=1440;record.child_key_commitment.generation=1;record.child_key_commitment.first_epoch=7;record.child_key_commitment.tree_id=uniform(0x66);record.child_key_commitment.root=uniform(0x77);if(!pqkey->GetPublicKey(record.public_key))return 3;
    llmq::pq::ProviderServiceAuthorization authorization;authorization.payload_version=4;authorization.pro_tx_hash=protx;authorization.global_key_version=1;authorization.service.network=llmq::pq::EndpointNetwork::IPV4;authorization.service.address_size=4;authorization.service.address[0]=127;authorization.service.address[3]=1;authorization.service.port=18367;authorization.operator_payout_script=payout;authorization.nevm_address.emplace();std::fill(authorization.nevm_address->begin(),authorization.nevm_address->end(),0x55);authorization.transaction_inputs_hash=inputs_hash;
    auto digest=llmq::pq::GetProviderServiceAuthorizationHash(genesis,record,authorization);if(!digest)return 4;
    const auto ctx=llmq::pq::GetGlobalAuthContext(llmq::pq::GlobalAuthPurpose::PROVIDER_SERVICE);slhdsa::Signature pqsig{};if(!slhdsa::SignDeterministic(*pqkey,Span<const uint8_t>{digest->begin(),digest->size()},ctx,pqsig))return 5;
    CDataStream recordbytes(SER_NETWORK,0);recordbytes<<record;CDataStream childbytes(SER_NETWORK,0);childbytes<<record.child_key_commitment;
    std::array<uint8_t,64> pqsecret{};if(!pqkey->Export(pqsecret))return 6;
    std::printf("\"pq\":{\"genesisHash\":\"%s\",\"seed\":\"%s\",\"secretKey\":\"%s\",\"publicKey\":\"%s\",\"globalRecordHex\":\"%s\",\"childKeyCommitmentHex\":\"%s\",\"authorizationHash\":\"%s\",\"contextHex\":\"%s\",\"signature\":\"%s\"}}\n",hex(genesis).c_str(),hex(seed).c_str(),hex(pqsecret).c_str(),hex(record.public_key).c_str(),hex(recordbytes).c_str(),hex(childbytes).c_str(),hex(*digest).c_str(),hex(ctx).c_str(),hex(pqsig).c_str());
}
