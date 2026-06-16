#include "plugin.h"

#include <algorithm>
#include <cstring>
#include <string>

#include <QString>
#include <QTimer>

#include "logos_api.h"
#include "liblogos_rln_module_api.h"

// logos_sdk.h is emitted by the universal codegen (module/.lgx build) and
// defines the concrete LogosModules struct that modules() dereferences. The
// unit-test build does not run codegen, so guard it: there, the daemon
// modules().api fallback is simply unavailable and LogosAPI must come from the
// explicit initLogos(hex) hook (the rln boundary tests assert clean failure
// when neither is set).
#if __has_include("logos_sdk.h")
#include "logos_sdk.h"
#define LIBP2P_HAVE_LOGOS_SDK 1
#endif

using json = nlohmann::json;

LogosAPI* Libp2pModuleImpl::ensureLogosAPI() {
    if (!m_logosAPI && isContextReady()) {
#ifdef LIBP2P_HAVE_LOGOS_SDK
        m_logosAPI = modules().api;
#endif
    }
    return m_logosAPI;
}

namespace {

bool hexToBytes32(const std::string& hex, uint8_t out[32]) {
    std::string h = hex;
    if (h.rfind("0x", 0) == 0 || h.rfind("0X", 0) == 0) h = h.substr(2);
    if (h.size() != 64) return false;
    for (size_t i = 0; i < 32; ++i) {
        auto nib = [](char c) -> int {
            if (c >= '0' && c <= '9') return c - '0';
            if (c >= 'a' && c <= 'f') return c - 'a' + 10;
            if (c >= 'A' && c <= 'F') return c - 'A' + 10;
            return -1;
        };
        int hi = nib(h[i * 2]), lo = nib(h[i * 2 + 1]);
        if (hi < 0 || lo < 0) return false;
        out[i] = static_cast<uint8_t>((hi << 4) | lo);
    }
    return true;
}

}  // namespace

bool Libp2pModuleImpl::initLogos(const std::string& apiHandleHex) {
    if (apiHandleHex.empty()) return false;
    uintptr_t raw = 0;
    try {
        raw = static_cast<uintptr_t>(std::stoull(apiHandleHex, nullptr, 16));
    } catch (...) {
        return false;
    }
    if (raw == 0) return false;
    m_logosAPI = reinterpret_cast<LogosAPI*>(raw);
    return true;
}

// Runs on the libp2p thread (the cbind poll loop). Routes the two LEZ reads
// the OnchainLEZGroupManager needs into the rln module via a synchronous
// cross-module call (acceptable v1 — this is NOT the Qt thread, so it does
// not stall module RPC dispatch). Timeout is explicit per the cpp-sdk gotcha.
int Libp2pModuleImpl::rlnFetcherTrampoline(const char* methodName, const char* params,
                                           Libp2pMixRlnFetchCallback callback,
                                           void* callbackData, void* fetcherData) {
    auto fail = [&](const char* msg) -> int {
        if (callback) callback(1, msg, msg ? std::strlen(msg) : 0, callbackData);
        return 1;
    };

    auto* self = static_cast<Libp2pModuleImpl*>(fetcherData);
    if (!self) return fail("rln fetcher: no module context");
    LogosAPI* api = self->ensureLogosAPI();
    if (!api) return fail("rln fetcher: LogosAPI not set");

    const std::string m = methodName ? methodName : "";
    const std::string p = params ? params : "";

    LiblogosRlnModule rln(api);
    std::string resp;

    if (m == "get_valid_roots") {
        resp = rln.get_valid_roots(p);
    } else if (m == "get_merkle_proofs") {
        // params = "<configAccount>,<index>"; the module takes a JSON array
        // of leaf indices. We request the single index the GM asked for.
        const auto comma = p.find(',');
        const std::string account = comma == std::string::npos ? p : p.substr(0, comma);
        const std::string index = comma == std::string::npos ? "" : p.substr(comma + 1);
        const std::string leafJson = "[" + index + "]";
        resp = rln.get_merkle_proofs(account, leafJson);
    } else {
        return fail("rln fetcher: unknown method");
    }

    if (resp.empty()) return fail("rln fetcher: empty response");
    if (callback) callback(0, resp.data(), resp.size(), callbackData);
    return 0;
}

StdLogosResult Libp2pModuleImpl::rlnEnable(const std::string& configJson) {
    // Capture the LEZ config account so rlnRegister can reuse it, and so a
    // host that only calls rlnEnable still has it available.
    try {
        auto j = json::parse(configJson);
        if (j.contains("configAccount")) m_rlnConfigAccount = j["configAccount"].get<std::string>();
        if (j.contains("epochDurationSeconds"))
            m_rlnEpochSeconds = j["epochDurationSeconds"].get<double>();
    } catch (...) {
        return {false, {}, "invalid config json"};
    }

    if (libp2p_mix_rln_enable(configJson.c_str()) != 0) {
        return {false, {}, "libp2p_mix_rln_enable failed"};
    }
    if (libp2p_mix_rln_set_fetcher(&Libp2pModuleImpl::rlnFetcherTrampoline, this) != 0) {
        return {false, {}, "libp2p_mix_rln_set_fetcher failed"};
    }
    return {true, {}, ""};
}

StdLogosResult Libp2pModuleImpl::rlnSetIdentity(const std::string& idSecretHashHex,
                                                int64_t leafIndex) {
    uint8_t secret[32];
    if (!hexToBytes32(idSecretHashHex, secret)) {
        return {false, {}, "idSecretHash must be 32-byte hex"};
    }
    if (libp2p_mix_rln_set_identity(secret, 32, leafIndex) != 0) {
        return {false, {}, "libp2p_mix_rln_set_identity failed"};
    }
    return {true, {}, ""};
}

StdLogosResult Libp2pModuleImpl::rlnIsReady() {
    return {true, libp2p_mix_rln_is_ready() == 1, ""};
}

StdLogosResult Libp2pModuleImpl::rlnStartPolling() {
    if (libp2p_mix_rln_start_polling() != 0) {
        return {false, {}, "libp2p_mix_rln_start_polling failed"};
    }
    return {true, {}, ""};
}

StdLogosResult Libp2pModuleImpl::rlnRegister(const std::string& argsJson) {
    std::string configAccount, holdingAccount, seed;
    int rate = 0;
    try {
        auto a = json::parse(argsJson);
        configAccount = a.at("config").get<std::string>();
        holdingAccount = a.at("wallet").get<std::string>();
        rate = a.at("rate").get<int>();
        // Optional: decouple the identity SEED from the funding/signing account.
        // generate_identity is a pure function of 32 bytes of entropy, while
        // register_member uses `wallet` only as the tx funder/signer. Passing a
        // distinct seed per node lets ONE funded account register N distinct
        // identities (needed for multi-node per-hop mix RLN). Defaults to wallet.
        seed = a.value("seed", holdingAccount);
    } catch (...) {
        return {false, {}, "rlnRegister: bad args json (need {config,wallet,rate}, optional seed)"};
    }

    LogosAPI* api = ensureLogosAPI();
    if (!api) return {false, {}, "LogosAPI not set (call initLogos)"};

    LiblogosRlnModule rln(api);

    // 1. Derive the identity (idCommitment + idSecretHash) from the seed.
    //    idSecretHash is what proofs use; idCommitment is the leaf.
    const std::string idJson = rln.generate_identity(seed);
    if (idJson.empty()) return {false, {}, "generate_identity failed"};

    std::string idCommitment, idSecretHash;
    try {
        auto j = json::parse(idJson);
        idCommitment = j.at("id_commitment").get<std::string>();
        idSecretHash = j.at("id_secret_hash").get<std::string>();
    } catch (...) {
        return {false, {}, "generate_identity: bad response"};
    }

    // 2. Register the membership on-chain (wallet must be open + synced).
    const std::string regJson =
        rln.register_member(configAccount, holdingAccount, idCommitment, rate);
    if (regJson.empty()) return {false, {}, "register_member failed"};

    int64_t leafIndex = -1;
    try {
        auto j = json::parse(regJson);
        leafIndex = j.at("leaf_index").get<int64_t>();
    } catch (...) {
        return {false, {}, "register_member: bad response"};
    }

    // 3. Attach the credential + leaf so the GM can generate proofs once the
    //    membership PDA is visible (pushed via rlnRefreshProof).
    auto setRes = rlnSetIdentity(idSecretHash, leafIndex);
    if (!setRes.success) return setRes;
    m_rlnLeafIndex = leafIndex;

    // Drive readiness from inside the module: a Qt-thread timer fetches+pushes
    // the merkle proof until ready, then keeps it fresh. No host loop needed.
    startRlnRefreshTimer();

    return {true, json{{"leaf_index", leafIndex}, {"id_commitment", idCommitment}}, ""};
}

void Libp2pModuleImpl::startRlnRefreshTimer() {
    if (m_rlnRefreshTimer) return;  // already running (re-register is a no-op)

    // Poll fast until the membership lands in the tree and the proof is cached,
    // then back off to the epoch cadence to keep the root window fresh.
    const int fastMs = 5000;
    const int slowMs = std::max(1000, static_cast<int>(m_rlnEpochSeconds * 1000.0));

    m_rlnRefreshTimer = new QTimer();
    m_rlnRefreshTimer->setInterval(fastMs);
    // 3-arg connect with the timer as context: the lambda runs on the timer's
    // (Qt/module) thread, where rlnRefreshProof's cross-module call is safe, and
    // the connection drops automatically when the timer is destroyed.
    QObject::connect(m_rlnRefreshTimer, &QTimer::timeout, m_rlnRefreshTimer,
                     [this, slowMs]() {
                         // Soft failures (membership not in tree yet) are expected
                         // early; the next tick retries.
                         rlnRefreshProof();
                         if (libp2p_mix_rln_is_ready() == 1 &&
                             m_rlnRefreshTimer->interval() != slowMs) {
                             m_rlnRefreshTimer->setInterval(slowMs);
                         }
                     });
    m_rlnRefreshTimer->start();
}

void Libp2pModuleImpl::stopRlnRefreshTimer() {
    if (!m_rlnRefreshTimer) return;
    m_rlnRefreshTimer->stop();
    m_rlnRefreshTimer->deleteLater();
    m_rlnRefreshTimer = nullptr;
}

StdLogosResult Libp2pModuleImpl::rlnRefreshProof() {
    if (m_rlnConfigAccount.empty()) return {false, {}, "RLN config account not set (call rlnEnable)"};
    if (m_rlnLeafIndex < 0) return {false, {}, "no leaf index (call rlnRegister first)"};

    LogosAPI* api = ensureLogosAPI();
    if (!api) return {false, {}, "LogosAPI not set"};
    LiblogosRlnModule rln(api);

    // Fetch on THIS (Qt/RPC) thread — cross-module calls are safe here.
    const std::string leafJson = "[" + std::to_string(m_rlnLeafIndex) + "]";
    const std::string arr = rln.get_merkle_proofs(m_rlnConfigAccount, leafJson);
    if (arr.empty()) return {false, {}, "get_merkle_proofs returned empty"};

    // get_merkle_proofs returns a JSON array [{...}]; push element [0].
    std::string proofObj;
    try {
        auto j = json::parse(arr);
        if (!j.is_array() || j.empty()) return {false, {}, "no merkle proof available yet"};
        proofObj = j[0].dump();
    } catch (...) {
        return {false, {}, "get_merkle_proofs: bad response"};
    }

    if (libp2p_mix_rln_set_cached_proof(proofObj.c_str()) != 0) {
        return {false, {}, "libp2p_mix_rln_set_cached_proof failed (unparseable/empty proof)"};
    }
    return {true, {}, ""};
}
