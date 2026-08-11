#include "plugin.h"

StdLogosResult Libp2pModuleImpl::mixGeneratePrivKey() {
    if (!ctx) {
        auto created = createContext();
        if (!created.success) return created;
    }
    return callSyncWith("Failed to generate mix private key",
        [&](SyncPromise* p) {
            return libp2p_static_mix_generate_priv_key(&Libp2pModuleImpl::cbStr, p);
        },
        [](const SyncResult& r) -> StdLogosResult {
            return {true, r.message, ""};
        });
}

StdLogosResult Libp2pModuleImpl::mixPublicKey(const std::string& privKeyHex) {
    if (!ctx) {
        auto created = createContext();
        if (!created.success) return created;
    }
    return callSyncWith("Failed to derive mix public key",
        [&](SyncPromise* p) {
            return libp2p_static_mix_public_key(nimffi_str(privKeyHex.c_str()),
                                                &Libp2pModuleImpl::cbStr, p);
        },
        [](const SyncResult& r) -> StdLogosResult {
            return {true, r.message, ""};
        });
}

StdLogosResult Libp2pModuleImpl::mixDial(const std::string& argsJson)
{
    std::string peerId, multiaddr, proto;
    try {
        auto a = nlohmann::json::parse(argsJson);
        peerId = a.at("peerId").get<std::string>();
        multiaddr = a.at("multiaddr").get<std::string>();
        proto = a.at("proto").get<std::string>();
    } catch (...) {
        return {false, {}, "mixDial: bad args json (need {peerId,multiaddr,proto})"};
    }

    MixDialRequest req{};
    req.peerId = nimffi_str(peerId.c_str());
    req.multiaddr = nimffi_str(multiaddr.c_str());
    req.proto = nimffi_str(proto.c_str());

    return callSyncWith("Failed to mix dial",
        [&](SyncPromise* p) {
            return libp2p_ctx_mix_dial(ctx, &req, &Libp2pModuleImpl::cbDial, p);
        },
        [](const SyncResult& r) -> StdLogosResult {
            if (r.data.is_number()) return {true, r.data, ""};
            return {true, 0, ""};
        });
}

StdLogosResult Libp2pModuleImpl::mixDialWithReply(const std::string& argsJson)
{
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

    MixDialRequest req{};
    req.peerId = nimffi_str(peerId.c_str());
    req.multiaddr = nimffi_str(multiaddr.c_str());
    req.proto = nimffi_str(proto.c_str());
    req.expectReply = expectReply != 0;
    req.numSurbs = numSurbs;

    return callSyncWith("Failed to mix dial with reply",
        [&](SyncPromise* p) {
            return libp2p_ctx_mix_dial(ctx, &req, &Libp2pModuleImpl::cbDial, p);
        },
        [](const SyncResult& r) -> StdLogosResult {
            if (r.data.is_number()) return {true, r.data, ""};
            return {true, 0, ""};
        });
}

StdLogosResult Libp2pModuleImpl::mixRegisterDestReadBehavior(const std::string& argsJson)
{
    std::string proto;
    int behavior = 0;
    int64_t sizeParam = 0;
    try {
        auto a = nlohmann::json::parse(argsJson);
        proto = a.at("proto").get<std::string>();
        behavior = a.at("behavior").get<int>();
        sizeParam = a.value("sizeParam", 0);
    } catch (...) {
        return {false, {},
                "mixRegisterDestReadBehavior: bad args json (need {proto,behavior,sizeParam})"};
    }
    if (behavior != MIX_READ_BEHAVIOR_READ_EXACTLY &&
        behavior != MIX_READ_BEHAVIOR_READ_LP) {
        return {false, {}, "mixRegisterDestReadBehavior: behavior must be 0 (read_exactly) or 1 (read_lp)"};
    }

    MixRegisterDestReadRequest req{};
    req.proto = nimffi_str(proto.c_str());
    req.behavior = static_cast<MixReadBehavior>(behavior);
    req.sizeParam = sizeParam;

    return callSync("Failed to register dest read behavior",
        [&](SyncPromise* p) {
            return libp2p_ctx_mix_register_dest_read_behavior(
                ctx, &req, &Libp2pModuleImpl::cbBool, p);
        });
}

StdLogosResult Libp2pModuleImpl::mixSetNodeInfo(const std::string& argsJson)
{
    std::string multiaddr, keyHex;
    try {
        auto a = nlohmann::json::parse(argsJson);
        multiaddr = a.at("multiaddr").get<std::string>();
        keyHex = a.at("mixPrivKeyHex").get<std::string>();
    } catch (...) {
        return {false, {}, "mixSetNodeInfo: bad args json (need {multiaddr,mixPrivKeyHex})"};
    }

    MixSetNodeInfoRequest req{};
    req.multiaddr = nimffi_str(multiaddr.c_str());
    req.mixPrivKeyHex = nimffi_str(keyHex.c_str());

    return callSync("Failed to set node info",
        [&](SyncPromise* p) {
            return libp2p_ctx_mix_set_node_info(ctx, &req,
                                                &Libp2pModuleImpl::cbBool, p);
        });
}

StdLogosResult Libp2pModuleImpl::mixNodepoolAdd(const std::string& argsJson)
{
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

    MixNodepoolAddRequest req{};
    req.peerId = nimffi_str(peerId.c_str());
    req.multiaddr = nimffi_str(multiaddr.c_str());
    req.mixPubKeyHex = nimffi_str(mixPubKeyHex.c_str());
    req.libp2pPubKeyHex = nimffi_str(libp2pPubKeyHex.c_str());

    return callSync("Failed to add to nodepool",
        [&](SyncPromise* p) {
            return libp2p_ctx_mix_nodepool_add(ctx, &req,
                                               &Libp2pModuleImpl::cbBool, p);
        });
}
