// Copyright © 2017-2020 Trust Wallet.
//
// This file is part of Trust. The full Trust copyright notice, including
// terms governing use, modification, and redistribution, is contained in the
// file LICENSE at the root of the source code distribution tree.

#include "Signer.h"
#include "Extrinsic.h"
#include "../Hash.h"
#include "../PrivateKey.h"
#include <random>
extern "C" {
#include "sr25519/sr25519.h"
}

namespace TW::Polkadot {

static constexpr size_t hashTreshold = 256;

inline std::vector<uint8_t> operator"" _unhex(const char *c, size_t s) {
    assert(s % 2 == 0);

    std::string hex{c, c + s};
    std::vector<uint8_t> v;

    int len = hex.length();
    std::string newString;
    for (auto i = 0; i < len; i += 2) {
        std::string byte = hex.substr(i, 2);
        char chr = (char)strtol(byte.c_str(), nullptr, 16);
        v.push_back(chr);
    }

    return v;
}

inline std::vector<uint8_t> operator"" _v(const char *c, size_t s) {
    return std::vector<uint8_t>{c, c + s};
}

inline std::string hex(const std::vector<uint8_t> &v) {
    assert(!v.empty());
    static const auto *alphabet = "0123456789abcdef";
    std::string out(v.size() * 2, 0);

    for (auto i = 0u; i < v.size(); i++) {
        out[i * 2] = alphabet[v[i] >> 4];
        out[i * 2 + 1] = alphabet[v[i] & 0x0F];
    }

    return out;
}

inline std::vector<uint8_t>
randomKeypair(size_t initseed = std::random_device()()) {
    std::mt19937 gen(initseed);
    std::vector<uint8_t> seed(SR25519_SEED_SIZE, 0);
    std::generate(seed.begin(), seed.end(), [&gen]() { return (uint8_t)gen(); });

    std::vector<uint8_t> kp(SR25519_KEYPAIR_SIZE, 0);
    sr25519_keypair_from_seed(kp.data(), seed.data());

    return kp;
}

#define USE_SR25519 0

Proto::SigningOutput Signer::sign(const Proto::SigningInput &input) noexcept {
#if USE_SR25519
    // auto kp = randomKeypair();
    // TODO replace with our private key
    auto kp = "4c1250e05afcd79e74f6c035aee10248841090e009b6fd7ba6a98d5dc743250cafa4b32c608e3ee2ba624850b3f14c75841af84b16798bf1ee4a3875aa37a2cee661e416406384fe1ca091980958576d2bff7c461636e9f22c895f444905ea1f"_unhex;

    Data publicKeyData = Data(kp.begin() + SR25519_SECRET_SIZE, kp.end());
    Data signature(SR25519_SIGNATURE_SIZE, 0);
    PublicKey publicKey(publicKeyData, TWPublicKeyTypeSR25519);
#else
    auto privateKey = PrivateKey(Data(input.private_key().begin(), input.private_key().end()));
    auto publicKey = privateKey.getPublicKey(TWPublicKeyTypeED25519);
#endif
    auto extrinsic = Extrinsic(input);
    auto payload = extrinsic.encodePayload();
    // check if need to hash
    if (payload.size() > hashTreshold) {
        payload = Hash::blake2b(payload, 32);
    }
#if USE_SR25519
    sr25519_sign(signature.data(), kp.data() + SR25519_SECRET_SIZE, kp.data(),
                 payload.data(), (size_t)payload.size());
#else
    Data signature = privateKey.sign(payload, TWCurveED25519);
#endif
    auto encoded = extrinsic.encodeSignature(publicKey, signature);

    auto protoOutput = Proto::SigningOutput();
    protoOutput.set_encoded(encoded.data(), encoded.size());
    return protoOutput;
}

} // namespace TW::Polkadot
