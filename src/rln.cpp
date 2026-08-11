#include "plugin.h"

#include <ctime>
#include <string>
#include <utility>

#include <QString>
#include <QTimer>

#include "logos_api.h"
#include "rln_client.h"

using json = nlohmann::json;

// Cross-module RLN calls go over the LogosAPI/QtRO transport (see
// rln_client.h). A host may inject a handle via initLogos(hex); otherwise the
// module process lazily constructs its own LogosAPI (registry discovery is
// process-global). Construction must happen on the Qt thread — rlnEnable
// warms it up so the drain timer only ever reuses the existing instance.
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

namespace {
// Fetch replies carry failures in-band as the module's tstr-dialect envelope
// {"error":{"class","kind","message"}}, so the mix layer switches on the same
// typed object in every path.
std::string fetchError(const char* cls, const char* kind, const std::string& message) {
    return json{{"error", {{"class", cls}, {"kind", kind}, {"message", message}}}}.dump();
}

std::string transportError(const std::string& message) {
    return fetchError("transient", "client_failure", message);
}

// Serves a "generate_proof" fetch: params {"signal_hex":…} (a bare JSON
// string is tolerated as the hex). The proof's epoch binds to the CALLER's
// Unix-seconds clock — this module is the sending consumer, so now() is the
// timestamp the message carries.
std::string serveGenerateProof(RlnModuleClient& rln, const std::string& registryId,
                               const std::string& rlnIdentifierHex,
                               const std::string& paramsJson) {
    std::string signalHex;
    const json p = json::parse(paramsJson, nullptr, false);
    if (p.is_object() && p.contains("signal_hex") && p["signal_hex"].is_string()) {
        signalHex = p["signal_hex"].get<std::string>();
    } else if (p.is_string()) {
        signalHex = p.get<std::string>();
    }
    if (signalHex.empty()) {
        return fetchError("permanent", "invalid_argument",
                          "generate_proof: params carry no signal_hex");
    }

    const std::string ts = std::to_string(static_cast<long long>(std::time(nullptr)));
    auto r = rln.generateProof(registryId, rlnIdentifierHex, signalHex, ts);
    if (r.ok) return r.value;  // the RateLimitProof object, verbatim
    // r.error is always a valid JSON object dump (rln_client guarantees it).
    return "{\"error\":" + r.error + "}";
}
}  // namespace

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
    // The scope every membership-module call is made under; required — no
    // default scope exists on that wire.
    try {
        auto j = json::parse(configJson);
        m_rlnRegistryId = j.at("registry_id").get<std::string>();
        m_rlnIdentifierHex = j.at("rln_identifier_hex").get<std::string>();
        // Bare lowercase hex everywhere downstream: the module wire tolerates
        // 0x but the cbind's decoder need not.
        if (m_rlnIdentifierHex.rfind("0x", 0) == 0 || m_rlnIdentifierHex.rfind("0X", 0) == 0) {
            m_rlnIdentifierHex = m_rlnIdentifierHex.substr(2);
        }
        m_rlnEpochSizeSec = j.value("epoch_size_sec", static_cast<int64_t>(10));
    } catch (...) {
        return {false, {},
                "rlnEnable: bad config json (need {registry_id, rln_identifier_hex}, "
                "optional epoch_size_sec)"};
    }
    if (m_rlnRegistryId.empty() || m_rlnIdentifierHex.empty() || m_rlnEpochSizeSec <= 0) {
        return {false, {},
                "rlnEnable: registry_id and rln_identifier_hex must be non-empty and "
                "epoch_size_sec positive"};
    }

    // rlnEnable must precede start() (spam protection cannot be toggled on a
    // mounted mix protocol), so the context may not exist yet.
    if (!ctx) {
        auto created = createContext();
        if (!created.success) return created;
    }

    // The cbind speaks its own config vocabulary, not this method's: the mix
    // wire proof is fixed at 301 bytes, and the verifier recomputes external
    // nullifiers from rlnIdentifierHex — omitting it makes every peer proof
    // fail verification.
    const std::string cbindCfg = json{
        {"proofSize", 301},
        {"rlnIdentifierHex", m_rlnIdentifierHex},
    }.dump();
    auto res = callSync("Failed to enable rln", [&](SyncPromise* p) {
        return libp2p_ctx_rln_mix_enable(ctx, nimffi_str(cbindCfg.c_str()),
                                         &Libp2pModuleImpl::cbBool, p);
    });
    if (!res.success) return res;

    ensureLogosAPI();
    // Configure the membership module (epoch base + warm the registry's root
    // window). A failure here (module not up yet) is non-fatal: the refresh
    // poller retries until start() lands.
    rlnStartModule();
    // Every node that verifies proofs needs the drain (not just registered
    // senders).
    startRlnFetchDrainTimer();
    startRlnRefreshTimer();
    return {true, {}, ""};
}

bool Libp2pModuleImpl::rlnStartModule() {
    RlnModuleClient rln(ensureLogosAPI());
    const json cfg{{"epoch_size_sec", m_rlnEpochSizeSec},
                   {"registries", json::array({m_rlnRegistryId})}};
    m_rlnModuleStarted = rln.start(cfg.dump()).ok;
    return m_rlnModuleStarted;
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

    RlnModuleClient rln(ensureLogosAPI());

    // One get_valid_roots read serves every queued roots request in this pass
    // plus the proactive SetValidRoots push below.
    std::string rootsReply;  // fetch-contract payload: roots object or {"error":…}
    std::string rootsJson;   // the module's {"valid_roots":[…]} when the read succeeded
    bool readRoots = false;
    auto fetchRoots = [&]() -> const std::string& {
        if (!readRoots) {
            readRoots = true;
            const std::string raw = rln.getValidRoots(m_rlnRegistryId);
            if (raw.empty()) {
                rootsReply =
                    transportError("get_valid_roots: no reply from liblogos_rln_module");
            } else {
                // {"valid_roots":[…]} or the module's in-band {"error":…} —
                // both already the fetch-contract shape, pass through verbatim.
                rootsReply = raw;
                const json j = json::parse(raw, nullptr, false);
                if (j.is_object() && j.contains("valid_roots")) rootsJson = raw;
            }
        }
        return rootsReply;
    };

    for (const auto& req : pending) {
        std::string payload;
        if (req.method == "get_valid_roots") {
            payload = fetchRoots();
        } else if (req.method == "generate_proof") {
            payload = serveGenerateProof(rln, m_rlnRegistryId, m_rlnIdentifierHex,
                                         req.params);
        } else {
            payload = fetchError("permanent", "invalid_argument",
                                 "unknown rln fetch method '" + req.method + "'");
        }
        rlnFetchReply(req.requestId, "", payload);
    }

    // Keep the verifier's window fresh off the same read. A failed read is
    // dropped here: nim re-requests after its throttle interval.
    if (!rootsJson.empty()) {
        callSync("Failed to set valid roots", [&](SyncPromise* p) {
            return libp2p_ctx_rln_mix_set_valid_roots(ctx, nimffi_str(rootsJson.c_str()),
                                                      &Libp2pModuleImpl::cbBool, p);
        });
    }
}

StdLogosResult Libp2pModuleImpl::rlnIsReady() {
    // Proofs are only servable once the scope's membership is active in the
    // membership module; the flag is latched by the refresh poller.
    if (!m_rlnMembershipActive) return {true, false, ""};
    return callSyncWith("Failed to query rln readiness",
        [&](SyncPromise* p) {
            return libp2p_ctx_rln_mix_is_ready(ctx, &Libp2pModuleImpl::cbBoolValue, p);
        },
        [](const SyncResult& r) -> StdLogosResult {
            return {true, r.data.is_boolean() && r.data.get<bool>(), ""};
        });
}

StdLogosResult Libp2pModuleImpl::rlnRegister(const std::string& argsJson) {
    (void)argsJson;
    return {false, {},
            "rlnRegister: retired — register via liblogos_rln_module (the RLN "
            "membership module) for the scope passed to rlnEnable; this module only "
            "consumes proofs and roots for that scope"};
}

void Libp2pModuleImpl::startRlnRefreshTimer() {
    if (m_rlnRefreshTimer) return;  // already running (re-enable is a no-op)

    // Poll until the membership module accepted start() AND the scope's
    // membership reads "active", then stop — everything afterwards is
    // request-driven through the fetch drain.
    m_rlnRefreshTimer = new QTimer();
    m_rlnRefreshTimer->setInterval(5000);
    // 3-arg connect with the timer as context: the lambda runs on the timer's
    // (Qt/module) thread, where cross-module calls are safe, and the
    // connection drops automatically when the timer is destroyed.
    QObject::connect(m_rlnRefreshTimer, &QTimer::timeout, m_rlnRefreshTimer, [this]() {
        if (!m_rlnModuleStarted && !rlnStartModule()) return;  // module not up yet
        RlnModuleClient rln(ensureLogosAPI());
        const std::string reply =
            rln.getMembershipState(m_rlnRegistryId, m_rlnIdentifierHex);
        const json j = json::parse(reply, nullptr, false);
        if (j.is_object() && j.value("state", std::string()) == "active") {
            m_rlnMembershipActive = true;
            stopRlnRefreshTimer();
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
    return {false, {},
            "rlnRefreshProof: retired — module proving replaced the cached-proof "
            "push (proofs are generated per message via the rln fetch bridge)"};
}
