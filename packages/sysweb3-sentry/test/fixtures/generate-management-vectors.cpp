// Public synthetic keys only. Built against pinned Syscoin Core libraries.
#include <crypto/slhdsa/slhdsa.h>
#include <crypto/sha256.h>
#include <hash.h>
#include <streams.h>
#include <bech32.h>
#include <util/strencodings.h>
#include <llmq/pq_global_auth.h>
#include <evo/pq_providertx.h>
#include <dashbls/bls.hpp>
#include <secp256k1.h>
#include <secp256k1_recovery.h>
#include <array>
#include <cstdio>
#include <string>
#include <vector>

template<class R> std::string hex(const R& r) { static const char* h="0123456789abcdef"; std::string s; for(auto c:r){s+=h[(uint8_t)c>>4];s+=h[(uint8_t)c&15];}return s; }
template<class R> uint256 hash256(const R& r) { uint256 out; CHash256().Write(Span<const unsigned char>{reinterpret_cast<const unsigned char*>(r.data()),r.size()}).Finalize(out); return out; }
template<class R> void raw(CDataStream& s,const R& r) {s.write(AsBytes(Span{r}));}
uint256 uniform(unsigned char v) { uint256 h;std::fill(h.begin(),h.end(),v);return h; }
std::string address(const std::array<uint8_t,20>& key) { std::vector<uint8_t> d{0};ConvertBits<8,5,true>([&](uint8_t v){d.push_back(v);},key.begin(),key.end());return bech32::Encode(bech32::Encoding::BECH32,"tsys",d); }
std::vector<uint8_t> secpsign(const uint256& h) {
    auto* ctx=secp256k1_context_create(SECP256K1_CONTEXT_SIGN);std::array<uint8_t,32> sk{};sk.back()=3;
    secp256k1_ecdsa_recoverable_signature sig; if(!secp256k1_ecdsa_sign_recoverable(ctx,&sig,h.begin(),sk.data(),secp256k1_nonce_function_rfc6979,nullptr))std::abort();
    std::vector<uint8_t> out(65);int rec;secp256k1_ecdsa_recoverable_signature_serialize_compact(ctx,out.data()+1,&rec,&sig);out[0]=31+rec;secp256k1_context_destroy(ctx);return out;
}
int main() {
    const auto genesis=uniform(0x44),protx=uniform(0x11),collateral=uniform(0x33);
    std::vector<uint8_t> fundingScript{0,20};fundingScript.insert(fundingScript.end(),20,0x34);
    CDataStream funding(SER_NETWORK,0);funding<<uint32_t{2}<<uint8_t{1}<<uniform(0)<<uint32_t{0xffffffff}<<std::vector<uint8_t>{1,1}<<uint32_t{0xffffffff}<<uint8_t{1}<<uint64_t{1000000}<<fundingScript<<uint32_t{0};
    const auto prevtx=hash256(funding);
    CDataStream inputs(SER_NETWORK,0);inputs<<prevtx<<uint32_t{0};const auto inputhash=hash256(inputs);
    std::array<uint8_t,20> owner{},voting{},payoutkey{};owner.fill(0x66);voting.fill(0x77);payoutkey.fill(0x88);
    std::vector<uint8_t> payout{0,20};payout.insert(payout.end(),payoutkey.begin(),payoutkey.end());
    std::array<uint8_t,16> service{};service[10]=service[11]=0xff;service[12]=127;service[15]=1;
    const std::array<uint8_t,2> port{0x47,0xbf};std::vector<uint8_t> blssk(32);blssk.back()=1;
    const auto bls=bls::PrivateKey::FromByteVector(blssk);const auto blspub=bls.GetG1Element().Serialize(false);
    CDataStream registration(SER_GETHASH,0);registration<<uint16_t{2}<<uint16_t{0}<<uint16_t{0}<<collateral<<uint32_t{2};
    raw(registration,service);raw(registration,port);
    raw(registration,owner);raw(registration,blspub);raw(registration,voting);
    registration<<uint16_t{250}<<payout<<inputhash;const auto reghash=hash256(registration);
    auto reversed_hash=std::vector<uint8_t>(reghash.begin(),reghash.end());std::reverse(reversed_hash.begin(),reversed_hash.end());
    const std::string message=address(payoutkey)+"|250|"+address(owner)+"|"+address(voting)+"|"+hex(reversed_hash);
    CDataStream ms(SER_GETHASH,0);ms<<std::string{"Syscoin Signed Message:\n"}<<message;const auto messagehash=hash256(ms);
    CDataStream registrar(SER_GETHASH,0);registrar<<uint16_t{2}<<protx<<uint16_t{0};raw(registrar,blspub);raw(registrar,voting);registrar<<payout<<inputhash;
    const auto registrarhash=hash256(registrar);
    CDataStream revoke(SER_GETHASH,0);revoke<<uint16_t{2}<<protx<<uint16_t{2}<<inputhash;const auto revokehash=hash256(revoke);
    const auto revokesig=bls::BasicSchemeMPL().Sign(bls,std::vector<uint8_t>(revokehash.begin(),revokehash.end())).Serialize(false);
    std::printf("{\"fundingTransaction\":\"%s\",\"legacyRegistration\":{\"preimage\":\"%s\",\"payloadHash\":\"%s\",\"message\":\"%s\",\"digest\":\"%s\",\"signature\":\"%s\"},\"legacyRegistrar\":{\"preimage\":\"%s\",\"digest\":\"%s\",\"signature\":\"%s\"},\"legacyRevoke\":{\"preimage\":\"%s\",\"digest\":\"%s\",\"signature\":\"%s\"},",hex(funding).c_str(),hex(registration).c_str(),hex(reghash).c_str(),message.c_str(),hex(messagehash).c_str(),hex(secpsign(messagehash)).c_str(),hex(registrar).c_str(),hex(registrarhash).c_str(),hex(secpsign(registrarhash)).c_str(),hex(revoke).c_str(),hex(revokehash).c_str(),hex(revokesig).c_str());
    slhdsa::KeyGenerationSeed seed{};for(size_t i=0;i<seed.size();++i)seed[i]=i;auto key=slhdsa::GenerateSecretKey(seed);if(!key)return 1;
    llmq::pq::GlobalKeyRecord record;record.key_version=1;record.activated_height=1440;record.child_key_commitment.generation=1;record.child_key_commitment.first_epoch=7;record.child_key_commitment.tree_id=uniform(0x66);record.child_key_commitment.root=uniform(0x77);if(!key->GetPublicKey(record.public_key))return 2;
    llmq::pq::ProviderRevokeAuthorization auth;auth.payload_version=3;auth.pro_tx_hash=protx;auth.global_key_version=1;auth.reason=2;auth.transaction_inputs_hash=inputhash;
    auto revoke_pq_hash=llmq::pq::GetProviderRevokeAuthorizationHash(genesis,record,auth);if(!revoke_pq_hash)return 3;
    slhdsa::Signature revoke_pq_sig{};auto ctx=llmq::pq::GetGlobalAuthContext(llmq::pq::GlobalAuthPurpose::PROVIDER_REVOKE);if(!slhdsa::SignDeterministic(*key,Span<const uint8_t>{revoke_pq_hash->begin(),32},ctx,revoke_pq_sig))return 4;
    auto candidate=record;candidate.activated_height=0;
    llmq::pq::GlobalKeyTxPayload op;op.pro_tx_hash=protx;op.candidate=candidate;op.transaction_inputs_hash=inputhash;
    auto ownerhash=llmq::pq::GetGlobalOwnerRegistrationAuthorizationHash(genesis,op);if(!ownerhash)return 5;
    auto pophash=llmq::pq::GetGlobalRegistrationAuthorizationHash(genesis,protx,candidate,inputhash);if(!pophash)return 6;
    slhdsa::Signature popsig{};ctx=llmq::pq::GetGlobalAuthContext(llmq::pq::GlobalAuthPurpose::GLOBAL_REGISTRATION);if(!slhdsa::SignDeterministic(*key,Span<const uint8_t>{pophash->begin(),32},ctx,popsig))return 7;
    std::printf("\"pqRevoke\":{\"digest\":\"%s\",\"signature\":\"%s\"},\"globalInitial\":{\"ownerDigest\":\"%s\",\"ownerSignature\":\"%s\",\"operatorDigest\":\"%s\",\"operatorSignature\":\"%s\"},",hex(*revoke_pq_hash).c_str(),hex(revoke_pq_sig).c_str(),hex(*ownerhash).c_str(),hex(secpsign(*ownerhash)).c_str(),hex(*pophash).c_str(),hex(popsig).c_str());
    const auto signpq=[&](uint256 digest,std::string context){slhdsa::Signature out{};if(!slhdsa::SignDeterministic(*key,Span<const uint8_t>{digest.begin(),32},Span<const uint8_t>{reinterpret_cast<const uint8_t*>(context.data()),context.size()},out))std::abort();return out;};
    std::array<uint8_t,32> pqvoting{};pqvoting.fill(0x99);
    CDataStream pqreg(SER_GETHASH,0);pqreg<<uint16_t{3}<<uint16_t{0}<<uint16_t{0}<<collateral<<uint32_t{2};raw(pqreg,service);raw(pqreg,port);raw(pqreg,owner);raw(pqreg,voting);pqreg<<uint16_t{250}<<payout<<inputhash<<pqvoting<<record.public_key;
    CDataStream pqregauth(SER_GETHASH,0);pqregauth<<std::string{"SYS_PQ_OWNER_PROREG_V1"}<<genesis<<int32_t{80}<<hash256(pqreg);const auto pqregdigest=hash256(pqregauth);
    CDataStream pqregistrar(SER_GETHASH,0);pqregistrar<<uint16_t{3}<<protx<<uint16_t{0};raw(pqregistrar,voting);pqregistrar<<payout<<inputhash<<pqvoting<<record.public_key<<uint32_t{1};
    CDataStream pqregistrarauth(SER_GETHASH,0);pqregistrarauth<<std::string{"SYS_PQ_OWNER_REGISTRAR_V1"}<<genesis<<int32_t{82}<<hash256(pqregistrar);const auto pqregistrardigest=hash256(pqregistrarauth);
    op.version=2;op.owner_key_version=1;const auto pqownerhash=llmq::pq::GetGlobalOwnerRegistrationAuthorizationHash(genesis,op);if(!pqownerhash)return 8;
    auto next=record;next.key_version=2;next.activated_height=0;slhdsa::KeyGenerationSeed nextseed{};nextseed.fill(1);auto nextkey=slhdsa::GenerateSecretKey(nextseed);if(!nextkey||!nextkey->GetPublicKey(next.public_key))return 9;
    const auto rotation=llmq::pq::GetGlobalRotationAuthorizationHash(genesis,protx,record,next,inputhash);if(!rotation)return 10;
    std::printf("\"pqOwnerRegistration\":{\"preimage\":\"%s\",\"digest\":\"%s\",\"proofHash\":\"%s\"},\"pqRegistrar\":{\"preimage\":\"%s\",\"digest\":\"%s\",\"updateSignatureHash\":\"%s\",\"proofHash\":\"%s\"},\"globalPQOwner\":{\"digest\":\"%s\",\"signatureHash\":\"%s\"},\"globalRotation\":{\"candidatePublicKey\":\"%s\",\"digest\":\"%s\",\"signatureHash\":\"%s\"}}\n",hex(pqreg).c_str(),hex(pqregdigest).c_str(),hex(hash256(signpq(pqregdigest,"SYS_PQ_OWNER_PROOF_V1"))).c_str(),hex(pqregistrar).c_str(),hex(pqregistrardigest).c_str(),hex(hash256(signpq(pqregistrardigest,"SYS_PQ_OWNER_UPDATE_V1"))).c_str(),hex(hash256(signpq(pqregistrardigest,"SYS_PQ_OWNER_PROOF_V1"))).c_str(),hex(*pqownerhash).c_str(),hex(hash256(signpq(*pqownerhash,"SYS_PQ_GLOBAL_OWNER_REGISTER_V2"))).c_str(),hex(next.public_key).c_str(),hex(*rotation).c_str(),hex(hash256(signpq(*rotation,"SYS_PQ_GLOBAL_ROTATE_V1"))).c_str());
}
