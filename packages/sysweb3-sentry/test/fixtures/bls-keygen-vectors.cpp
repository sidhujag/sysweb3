// Copyright (c) 2026 The Syscoin Core developers
// Distributed under the MIT software license.
// Generate public synthetic vectors with Core's bundled BasicSchemeMPL.
// Build against the legacy Core dashbls library, not a replacement BLS implementation.
#include <dashbls/bls.hpp>
#include <cstdio>
#include <string>
#include <vector>

template <class R> std::string Hex(const R& bytes)
{
    static constexpr char hex[] = "0123456789abcdef";
    std::string out;
    for (const auto value : bytes) {
        out += hex[static_cast<unsigned char>(value) >> 4];
        out += hex[static_cast<unsigned char>(value) & 15];
    }
    return out;
}

int main()
{
    std::vector<std::vector<uint8_t>> seeds{
        std::vector<uint8_t>(32, 0), std::vector<uint8_t>(32, 1), std::vector<uint8_t>(32, 255),
    };
    std::vector<uint8_t> sequence(32);
    for (size_t i = 0; i < sequence.size(); ++i) sequence[i] = i;
    seeds.push_back(sequence);
    std::puts("[");
    for (size_t i = 0; i < seeds.size(); ++i) {
        const auto key = bls::BasicSchemeMPL().KeyGen(seeds[i]);
        std::printf("  {\"seed\":\"%s\",\"secretKey\":\"%s\",\"publicKey\":\"%s\"}%s\n",
            Hex(seeds[i]).c_str(), Hex(key.Serialize()).c_str(),
            Hex(key.GetG1Element().Serialize(false)).c_str(), i + 1 == seeds.size() ? "" : ",");
    }
    std::puts("]");
}
