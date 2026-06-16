#include "plugin.h"

#include <cstring>

namespace {

// Decode a hex string (optional 0x prefix) into exactly outLen bytes. Used for
// the JSON-blob mix dial args, where binary keys travel as hex.
bool hexDecode(const std::string& hex, void* out, size_t outLen) {
    std::string h = hex;
    if (h.rfind("0x", 0) == 0 || h.rfind("0X", 0) == 0) h = h.substr(2);
    if (h.size() != outLen * 2) return false;
    auto nib = [](char c) -> int {
        if (c >= '0' && c <= '9') return c - '0';
        if (c >= 'a' && c <= 'f') return c - 'a' + 10;
        if (c >= 'A' && c <= 'F') return c - 'A' + 10;
        return -1;
    };
    auto* o = static_cast<uint8_t*>(out);
    for (size_t i = 0; i < outLen; ++i) {
        int hi = nib(h[i * 2]), lo = nib(h[i * 2 + 1]);
        if (hi < 0 || lo < 0) return false;
        o[i] = static_cast<uint8_t>((hi << 4) | lo);
    }
    return true;
}

}  // namespace

StdLogosResult Libp2pModuleImpl::mixGeneratePrivKey() {
    if (!ctx) return {false, {}, "No libp2p context"};

    libp2p_curve25519_key_t key{};
    libp2p_mix_generate_priv_key(&key);

    return {true, std::string(reinterpret_cast<const char*>(&key), sizeof(key)), ""};
}

StdLogosResult Libp2pModuleImpl::mixPublicKey(const std::string& privKey) {
    if (!ctx) return {false, {}, "No libp2p context"};

    if (privKey.size() != sizeof(libp2p_curve25519_key_t)) {
        return {false, {}, "Invalid private key size"};
    }

    libp2p_curve25519_key_t inKey{};
    libp2p_curve25519_key_t outKey{};
    memcpy(&inKey, privKey.data(), sizeof(inKey));

    libp2p_mix_public_key(inKey, &outKey);

    return {true, std::string(reinterpret_cast<const char*>(&outKey), sizeof(outKey)), ""};
}

StdLogosResult Libp2pModuleImpl::mixDial(const std::string& argsJson)
{
    if (!ctx) return {false, {}, "No libp2p context"};

    std::string peerId, multiaddr, proto;
    try {
        auto a = nlohmann::json::parse(argsJson);
        peerId = a.at("peerId").get<std::string>();
        multiaddr = a.at("multiaddr").get<std::string>();
        proto = a.at("proto").get<std::string>();
    } catch (...) {
        return {false, {}, "mixDial: bad args json (need {peerId,multiaddr,proto})"};
    }

    auto* p = new SyncPromise();
    auto f = p->get_future();
    int ret = libp2p_mix_dial(ctx, peerId.c_str(), multiaddr.c_str(), proto.c_str(),
                              &Libp2pModuleImpl::promiseConnectionCallback, p);
    if (ret != RET_OK) { delete p; return {false, {}, "Failed to mix dial"}; }

    auto r = awaitResult(f);
    if (!r.ok) return {false, {}, r.message};

    auto* stream = static_cast<libp2p_stream_t*>(r.extra);
    if (stream) {
        uint64_t streamId = addStream(stream);
        return {true, streamId, ""};
    }
    return {true, 0, ""};
}

StdLogosResult Libp2pModuleImpl::mixDialWithReply(const std::string& argsJson)
{
    if (!ctx) return {false, {}, "No libp2p context"};

    std::string peerId, multiaddr, proto;
    int expectReply = 0;
    int numSurbs = 0;
    try {
        auto a = nlohmann::json::parse(argsJson);
        peerId = a.at("peerId").get<std::string>();
        multiaddr = a.at("multiaddr").get<std::string>();
        proto = a.at("proto").get<std::string>();
        expectReply = a.value("expectReply", 0);
        numSurbs = a.value("numSurbs", 0);
    } catch (...) {
        return {false, {},
                "mixDialWithReply: bad args json (need {peerId,multiaddr,proto,expectReply,numSurbs})"};
    }

    auto* p = new SyncPromise();
    auto f = p->get_future();
    int ret = libp2p_mix_dial_with_reply(ctx, peerId.c_str(), multiaddr.c_str(),
                                         proto.c_str(), expectReply,
                                         static_cast<uint8_t>(numSurbs),
                                         &Libp2pModuleImpl::promiseConnectionCallback, p);
    if (ret != RET_OK) { delete p; return {false, {}, "Failed to mix dial with reply"}; }

    auto r = awaitResult(f);
    if (!r.ok) return {false, {}, r.message};

    auto* stream = static_cast<libp2p_stream_t*>(r.extra);
    if (stream) {
        uint64_t streamId = addStream(stream);
        return {true, streamId, ""};
    }
    return {true, 0, ""};
}

StdLogosResult Libp2pModuleImpl::mixRegisterDestReadBehavior(const std::string& argsJson)
{
    if (!ctx) return {false, {}, "No libp2p context"};

    std::string proto;
    int behavior = 0;
    uint32_t sizeParam = 0;
    try {
        auto a = nlohmann::json::parse(argsJson);
        proto = a.at("proto").get<std::string>();
        behavior = a.at("behavior").get<int>();
        sizeParam = a.value("sizeParam", 0u);
    } catch (...) {
        return {false, {},
                "mixRegisterDestReadBehavior: bad args json (need {proto,behavior,sizeParam})"};
    }

    auto* p = new SyncPromise();
    auto f = p->get_future();
    int ret = libp2p_mix_register_dest_read_behavior(
        ctx, proto.c_str(),
        static_cast<Libp2pMixReadBehavior>(behavior), sizeParam,
        &Libp2pModuleImpl::promiseCallback, p);
    if (ret != RET_OK) { delete p; return {false, {}, "Failed to register dest read behavior"}; }

    auto r = awaitResult(f);
    if (!r.ok) return {false, {}, r.message};
    return {true, {}, ""};
}

StdLogosResult Libp2pModuleImpl::mixSetNodeInfo(const std::string& argsJson)
{
    if (!ctx) return {false, {}, "No libp2p context"};

    std::string multiaddr, keyHex;
    try {
        auto a = nlohmann::json::parse(argsJson);
        multiaddr = a.at("multiaddr").get<std::string>();
        keyHex = a.at("mixPrivKeyHex").get<std::string>();
    } catch (...) {
        return {false, {}, "mixSetNodeInfo: bad args json (need {multiaddr,mixPrivKeyHex})"};
    }

    libp2p_curve25519_key_t key{};
    if (keyHex.size() != sizeof(key) * 2) {
        return {false, {}, "mixPrivKeyHex must be 64 hex chars"};
    }
    auto nib = [](char c) -> int {
        if (c >= '0' && c <= '9') return c - '0';
        if (c >= 'a' && c <= 'f') return c - 'a' + 10;
        if (c >= 'A' && c <= 'F') return c - 'A' + 10;
        return -1;
    };
    for (size_t i = 0; i < sizeof(key); ++i) {
        int hi = nib(keyHex[i * 2]), lo = nib(keyHex[i * 2 + 1]);
        if (hi < 0 || lo < 0) return {false, {}, "mixPrivKeyHex not valid hex"};
        reinterpret_cast<uint8_t*>(&key)[i] = static_cast<uint8_t>((hi << 4) | lo);
    }

    auto* p = new SyncPromise();
    auto f = p->get_future();
    int ret = libp2p_mix_set_node_info(ctx, multiaddr.c_str(), key,
                                       &Libp2pModuleImpl::promiseCallback, p);
    if (ret != RET_OK) { delete p; return {false, {}, "Failed to set node info"}; }

    auto r = awaitResult(f);
    if (!r.ok) return {false, {}, r.message};
    return {true, {}, ""};
}

StdLogosResult Libp2pModuleImpl::mixNodepoolAdd(const std::string& argsJson)
{
    if (!ctx) return {false, {}, "No libp2p context"};

    std::string peerId, multiaddr, mixPubKeyHex, libp2pPubKeyHex;
    try {
        auto a = nlohmann::json::parse(argsJson);
        peerId = a.at("peerId").get<std::string>();
        multiaddr = a.at("multiaddr").get<std::string>();
        mixPubKeyHex = a.at("mixPubKey").get<std::string>();
        libp2pPubKeyHex = a.at("libp2pPubKey").get<std::string>();
    } catch (...) {
        return {false, {},
                "mixNodepoolAdd: bad args json (need {peerId,multiaddr,mixPubKey,libp2pPubKey} hex keys)"};
    }

    libp2p_curve25519_key_t mixKey{};
    libp2p_secp256k1_pubkey_t lpKey{};
    if (!hexDecode(mixPubKeyHex, &mixKey, sizeof(mixKey))) {
        return {false, {}, "mixPubKey must be hex for a curve25519 key"};
    }
    if (!hexDecode(libp2pPubKeyHex, &lpKey, sizeof(lpKey))) {
        return {false, {}, "libp2pPubKey must be hex for a secp256k1 pubkey"};
    }

    auto* p = new SyncPromise();
    auto f = p->get_future();
    int ret = libp2p_mix_nodepool_add(ctx, peerId.c_str(), multiaddr.c_str(),
                                      mixKey, lpKey,
                                      &Libp2pModuleImpl::promiseCallback, p);
    if (ret != RET_OK) { delete p; return {false, {}, "Failed to add to nodepool"}; }

    auto r = awaitResult(f);
    if (!r.ok) return {false, {}, r.message};
    return {true, {}, ""};
}
