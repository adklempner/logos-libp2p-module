#include "plugin.h"

#include <algorithm>
#include <string>
#include <utility>

#include <QString>
#include <QTimer>

#include "logos_api.h"
#include "rln_client.h"

using json = nlohmann::json;

// Cross-module RLN calls go over the LogosAPI/QtRO transport (see
// rln_client.h — the deployed rln module predates logos-protocol, so the
// builder's LpClient path cannot reach it). A host may inject a handle via
// initLogos(hex); otherwise the module process lazily constructs its own
// LogosAPI (registry discovery is process-global). Construction must happen
// on the Qt thread — rlnEnable warms it up so the drain timer only ever
// reuses the existing instance.
LogosAPI* Libp2pModuleImpl::ensureLogosAPI() {
    if (!m_logosAPI) {
        m_logosAPI = new LogosAPI(QStringLiteral("libp2p_module"));
        m_ownsLogosAPI = true;
    }
    return m_logosAPI;
}

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

// Runs on the Nim dispatch (libp2p) thread. Enqueue ONLY — any blocking or
// cross-module (QtRO) call here would stall the chronos loop or deadlock
// against owner-thread marshaling. The Qt-thread drain timer serves the
// request and answers via the rlnMixFetchReply request.
void Libp2pModuleImpl::onRlnFetchRequest(const RlnFetchRequestEvent* evt, void* ud) {
    auto* self = static_cast<Libp2pModuleImpl*>(ud);
    if (!self || !evt) return;
    try {
        RlnFetchPending req;
        req.requestId = evt->requestId;
        req.method = nfStr(evt->methodName);
        req.params = nfStr(evt->paramsJson);
        std::lock_guard<std::mutex> lock(self->m_rlnFetchMutex);
        self->m_rlnFetchQueue.push_back(std::move(req));
    } catch (...) {}
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

    // rlnEnable must precede start() (spam protection cannot be toggled on a
    // mounted mix protocol), so the context may not exist yet.
    if (!ctx) {
        auto created = createContext();
        if (!created.success) return created;
    }

    auto res = callSync("Failed to enable rln", [&](SyncPromise* p) {
        return libp2p_ctx_rln_mix_enable(ctx, nimffi_str(configJson.c_str()),
                                         &Libp2pModuleImpl::cbBool, p);
    });
    if (!res.success) return res;

    ensureLogosAPI();
    // Every node that verifies proofs needs the drain (not just registered
    // senders), so it starts here rather than in rlnRegister.
    startRlnFetchDrainTimer();
    return {true, {}, ""};
}

void Libp2pModuleImpl::startRlnFetchDrainTimer() {
    if (m_rlnFetchDrainTimer) return;  // already running (re-enable is a no-op)

    // 200ms keeps worst-case event-to-answer latency well inside nim's 3s
    // awaitRootRefresh window while staying idle-cheap (empty-queue check only).
    m_rlnFetchDrainTimer = new QTimer();
    m_rlnFetchDrainTimer->setInterval(200);
    // Same 3-arg connect pattern as startRlnRefreshTimer: lambda runs on the
    // timer's (Qt/module) thread where cross-module calls are safe.
    QObject::connect(m_rlnFetchDrainTimer, &QTimer::timeout, m_rlnFetchDrainTimer,
                     [this]() { rlnFetchDrain(); });
    m_rlnFetchDrainTimer->start();
}

void Libp2pModuleImpl::stopRlnFetchDrainTimer() {
    if (!m_rlnFetchDrainTimer) return;
    m_rlnFetchDrainTimer->stop();
    m_rlnFetchDrainTimer->deleteLater();
    m_rlnFetchDrainTimer = nullptr;
}

void Libp2pModuleImpl::rlnFetchReply(uint64_t requestId, const std::string& error,
                                     const std::string& resultJson) {
    if (!ctx) return;
    RlnFetchReplyRequest req{};
    req.requestId = requestId;
    req.error = nimffi_str(error.c_str());
    req.resultJson = nimffi_str(resultJson.c_str());
    // Fire-and-forget: the request is encoded synchronously before submit and
    // the null reply callback frees the call box, so nothing here may block on
    // the nim loop.
    libp2p_ctx_rln_mix_fetch_reply(ctx, &req, nullptr, nullptr);
}

void Libp2pModuleImpl::rlnFetchDrain() {
    std::deque<RlnFetchPending> pending;
    {
        std::lock_guard<std::mutex> lock(m_rlnFetchMutex);
        pending.swap(m_rlnFetchQueue);
    }
    if (pending.empty()) return;

    // One get_valid_roots read serves every queued roots request in this pass
    // plus the proactive SetValidRoots push below.
    std::string roots;
    bool readRoots = false;
    auto fetchRoots = [&]() -> const std::string& {
        if (!readRoots) {
            readRoots = true;
            if (!m_rlnConfigAccount.empty()) {
                RlnModuleClient rln(ensureLogosAPI());
                roots = rln.get_valid_roots(m_rlnConfigAccount);
            }
        }
        return roots;
    };

    for (const auto& req : pending) {
        std::string result, error;
        if (req.method == "get_valid_roots") {
            result = fetchRoots();
            if (result.empty()) {
                error = "rln fetch: no valid roots available (config account unset or read failed)";
            }
        } else if (req.method == "generate_proof") {
            // The deployed rln module's wire (rln_client.h) exposes no proof
            // generation; the send that triggered this fetch fails and the
            // next send re-requests. Serving this lands with the rln-module
            // API migration.
            error = "rln fetch: generate_proof not served by this host";
        } else {
            error = "rln fetch: unknown method '" + req.method + "'";
        }
        rlnFetchReply(req.requestId, error, result);
    }

    // Keep the verifier's window fresh off the same read. Empty = transient
    // read failure; nim re-requests after its throttle interval, so dropping
    // it here is safe.
    if (readRoots && !roots.empty()) {
        callSync("Failed to set valid roots", [&](SyncPromise* p) {
            return libp2p_ctx_rln_mix_set_valid_roots(ctx, nimffi_str(roots.c_str()),
                                                      &Libp2pModuleImpl::cbBool, p);
        });
    }
}

StdLogosResult Libp2pModuleImpl::rlnIsReady() {
    return callSyncWith("Failed to query rln readiness",
        [&](SyncPromise* p) {
            return libp2p_ctx_rln_mix_is_ready(ctx, &Libp2pModuleImpl::cbBoolValue, p);
        },
        [](const SyncResult& r) -> StdLogosResult {
            return {true, r.data.is_boolean() && r.data.get<bool>(), ""};
        });
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
    RlnModuleClient rln(api);

    // 1. Derive the identity (idCommitment) from the seed; idCommitment is the
    //    on-chain leaf.
    const std::string idJson = rln.generate_identity(seed);
    if (idJson.empty()) return {false, {}, "generate_identity failed"};

    std::string idCommitment;
    try {
        auto j = json::parse(idJson);
        idCommitment = j.at("id_commitment").get<std::string>();
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

    // 3. Record the leaf so rlnRefreshProof can fetch the matching proof once
    //    the membership PDA is visible.
    m_rlnLeafIndex = leafIndex;

    // Drive readiness from inside the module: a Qt-thread timer fetches+pushes
    // the proof until ready, then keeps it fresh. No host loop needed.
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
                         auto ready = rlnIsReady();
                         if (ready.success && ready.value.is_boolean() &&
                             ready.value.get<bool>() &&
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

    RlnModuleClient rln(ensureLogosAPI());

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

    // The SetCachedProof request expects the raw proof blob as proofSize bytes
    // of hex; the deployed rln module only serves the merkle proof JSON, so
    // this push is rejected until the rln-module API migration serves a real
    // proof.
    return callSync("Failed to set cached proof", [&](SyncPromise* p) {
        return libp2p_ctx_rln_mix_set_cached_proof(ctx, nimffi_str(proofObj.c_str()),
                                                   &Libp2pModuleImpl::cbBool, p);
    });
}
