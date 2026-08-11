#pragma once

#include <atomic>
#include <chrono>
#include <climits>
#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <deque>
#include <functional>
#include <future>
#include <map>
#include <memory>
#include <mutex>
#include <shared_mutex>
#include <sstream>
#include <stdexcept>
#include <string>
#include <unordered_map>
#include <vector>

#include <nlohmann/json.hpp>

#include "logos_json.h"
#include "logos_result.h"
#include <logos_module_context.h>

// The nim-ffi generated header is header-only C: it declares the exported Nim
// symbols inside its own `extern "C"` block and exposes the async API as
// `static inline` wrappers plus C++-linkage callback typedefs. It must NOT be
// wrapped in an extra `extern "C"` here, or the reply-callback typedefs would
// take C linkage and no longer match the C++ static callbacks we pass in.
// The mix and mix-RLN surface is part of this same generated header.
#include <libp2p.h>

#include "config.h"
#include "metric.h"
#include "topic_queues.h"
#include "utils.h"

// Timeouts (milliseconds) for the sync-over-async libp2p bridge. nim-ffi never
// cancels a handler, so these bound the C++ wait only: a call that outlives its
// timeout keeps running and still resolves (and reclaims) its promise later.
inline constexpr int kDefaultOpTimeoutMs = 10000;
inline constexpr int kNewContextTimeoutMs = 5000;
// Added on top of a caller-supplied op timeout so the C++ await outlives the
// libp2p operation it wraps instead of racing it.
inline constexpr int kAwaitSlackMs = 5000;

// LogosAPI is the cross-module client factory; forward-declared so this
// codegen-scanned header stays free of Qt/SDK includes (rln.cpp pulls them).
class LogosAPI;
// QTimer is forward-declared for the same reason; the in-module proof-refresh
// timer is created/used only in rln.cpp, which includes the Qt headers.
class QTimer;

// Result type for internal sync-over-async operations.
struct SyncResult {
    bool ok = false;
    std::string message;
    std::vector<uint8_t> buffer;
    nlohmann::json data;
    LibP2PCtx* newCtx = nullptr;
};

// libp2p logs treat levels as inclusive minimum thresholds:
// `Trace` emits trace and above, `Debug` emits debug and above, etc.
// `None` is the lowest threshold, so it emits all logs; use `Fatal` for the
// quietest built-in threshold.
enum class LogLevel : int64_t {
    None = LOG_LEVEL_NONE,     // All logs.
    Trace = LOG_LEVEL_TRACE,   // Trace and above.
    Debug = LOG_LEVEL_DEBUG,   // Debug and above.
    Info = LOG_LEVEL_INFO,     // Info and above.
    Notice = LOG_LEVEL_NOTICE, // Notice and above.
    Warn = LOG_LEVEL_WARN,     // Warn and above.
    Error = LOG_LEVEL_ERROR,   // Error and above.
    Fatal = LOG_LEVEL_FATAL,   // Fatal only.
};

// Maps a level name onto LogLevel. The name is what crosses the module
// boundary — LIDL has no enum, and the numeric LOG_LEVEL_* values belong to the
// Nim binding, so they are no contract for a caller in another language.
inline bool parseLogLevel(const std::string& name, LogLevel& out) {
    if (name == "none") { out = LogLevel::None; return true; }
    if (name == "trace") { out = LogLevel::Trace; return true; }
    if (name == "debug") { out = LogLevel::Debug; return true; }
    if (name == "info") { out = LogLevel::Info; return true; }
    if (name == "notice") { out = LogLevel::Notice; return true; }
    if (name == "warn") { out = LogLevel::Warn; return true; }
    if (name == "error") { out = LogLevel::Error; return true; }
    if (name == "fatal") { out = LogLevel::Fatal; return true; }
    return false;
}

enum class KeyScheme : int64_t {
    Rsa = KEY_SCHEME_RSA,
    Ed25519 = KEY_SCHEME_ED25519,
    Secp256k1 = KEY_SCHEME_SECP256K1,
    Ecdsa = KEY_SCHEME_ECDSA,
};

// Maps a scheme name onto KeyScheme, matching the vocabulary metadata.json
// documents for the `keyType` config key. The name is what crosses the module
// boundary — LIDL has no enum, and the numeric KEY_SCHEME_* values belong to
// the Nim binding, so they are no contract for a caller in another language.
inline bool parseKeyScheme(const std::string& name, KeyScheme& out) {
    if (name == "rsa") { out = KeyScheme::Rsa; return true; }
    if (name == "ed25519") { out = KeyScheme::Ed25519; return true; }
    if (name == "secp256k1") { out = KeyScheme::Secp256k1; return true; }
    if (name == "ecdsa") { out = KeyScheme::Ecdsa; return true; }
    return false;
}

using SyncPromise = std::promise<SyncResult>;

// Resolves and reclaims a heap SyncPromise. Every libp2p callback owns its
// promise and ends by handing the result back through here.
inline void finishPromise(SyncPromise* p, SyncResult r) {
    p->set_value(std::move(r));
    delete p;
}

// Seeds a SyncResult from the (err_code, err_msg) pair every nim-ffi reply
// callback receives. err_msg is a NUL-terminated copy owned by the binding and
// valid only during the callback. err_code 0 (NIMFFI_RET_OK) means success.
inline SyncResult replyBase(int errCode, const char* errMsg) {
    SyncResult r;
    r.ok = (errCode == NIMFFI_RET_OK);
    if (!r.ok) r.message = errMsg ? std::string(errMsg) : std::string();
    return r;
}

// Awaits a future with timeout. Returns a failed result on timeout.
inline SyncResult awaitResult(std::future<SyncResult>& f, int timeoutMs = kDefaultOpTimeoutMs) {
    if (f.wait_for(std::chrono::milliseconds(timeoutMs)) == std::future_status::ready) {
        return f.get();
    }
    SyncResult r;
    r.message = "timeout";
    return r;
}

// Wraps a resolved buffer as a successful result. Buffers are raw bytes
// (publicKey/kadGetValue/stream reads), so they're base64-encoded to keep
// `value` a valid UTF-8 JSON string.
inline StdLogosResult bufferToResult(const SyncResult& r) {
    return {true, base64Encode(r.buffer), ""};
}

// Non-throwing JSON parse — malformed cbinding output yields a failed result
// instead of propagating an exception.
inline StdLogosResult parseJsonResponse(const std::string& s, const char* errPrefix) {
    auto j = nlohmann::json::parse(s, nullptr, false);
    if (j.is_discarded()) {
        return {false, {}, std::string(errPrefix) + ": invalid JSON"};
    }
    return {true, j, ""};
}

// Await long enough to outlast a caller-supplied op timeout, falling back to the
// default when the op carries no timeout of its own.
inline int awaitTimeoutFor(int64_t opTimeoutMs) {
    if (opTimeoutMs <= 0) return kDefaultOpTimeoutMs;
    int64_t v = opTimeoutMs + kAwaitSlackMs;
    return v > INT_MAX ? INT_MAX : static_cast<int>(v);
}

// Maps a resolved SyncResult's structured payload into a result, substituting an
// empty default when the callback produced no data (e.g. ok with zero items).
inline StdLogosResult jsonResult(const SyncResult& r, nlohmann::json emptyDefault) {
    if (r.data.is_null()) return {true, std::move(emptyDefault), ""};
    return {true, r.data, ""};
}

class Libp2pModuleImpl : public LogosModuleContext {
public:
    Libp2pModuleImpl(const Libp2pModuleOptions& options = Libp2pModuleOptions::load());
    ~Libp2pModuleImpl();

    std::function<void(const std::string& eventName, const std::string& data)> emitEvent;

    static StdLogosResult setLogLevel(const std::string& level);

    bool ok();
    StdLogosResult status();

    StdLogosResult createNode(const std::string& config);
    StdLogosResult getNodeInfo(const std::string& field);

    StdLogosResult start();
    StdLogosResult stop();
    StdLogosResult newPrivateKey(const std::string& scheme);
    StdLogosResult publicKey();

    StdLogosResult connectPeer(const std::string& peerId, const std::vector<std::string>& multiaddrs, int64_t timeoutMs);
    StdLogosResult disconnectPeer(const std::string& peerId);
    StdLogosResult peerInfo();
    StdLogosResult connectedPeers(int64_t direction);
    StdLogosResult dial(const std::string& peerId, const std::string& proto);

    StdLogosResult circuitRelayReserve(const std::string& relayPeerId, const std::vector<std::string>& relayAddrs);
    StdLogosResult dialCircuitRelay(const std::string& dstPeerId, const std::string& multiaddr, const std::string& proto);

    StdLogosResult mountProtocol(const std::string& proto);

    StdLogosResult streamReadExactly(uint64_t streamId, uint64_t len);
    StdLogosResult streamReadLp(uint64_t streamId, uint64_t maxSize);
    StdLogosResult streamWrite(uint64_t streamId, const std::string& data);
    StdLogosResult streamWriteLp(uint64_t streamId, const std::string& data);
    StdLogosResult streamClose(uint64_t streamId);
    StdLogosResult streamCloseWithEOF(uint64_t streamId);
    StdLogosResult streamRelease(uint64_t streamId);

    StdLogosResult protocolRequest(const std::string& argsJson);
    StdLogosResult streamReadLpJson(const std::string& argsJson);
    StdLogosResult streamWriteLpJson(const std::string& argsJson);
    StdLogosResult streamCloseJson(const std::string& argsJson);
    StdLogosResult streamReleaseJson(const std::string& argsJson);
    StdLogosResult protocolAcceptStream(const std::string& argsJson);

    StdLogosResult gossipsubPublish(const std::string& topic, const std::string& data);
    StdLogosResult gossipsubSubscribe(const std::string& topic);
    StdLogosResult gossipsubUnsubscribe(const std::string& topic);
    StdLogosResult gossipsubNextMessage(const std::string& topic, int64_t timeoutMs);

    StdLogosResult toCid(const std::string& key);
    StdLogosResult kadFindNode(const std::string& peerId);
    StdLogosResult kadPutValue(const std::string& key, const std::string& value);
    StdLogosResult kadGetValue(const std::string& key, int64_t quorum);
    StdLogosResult kadAddProvider(const std::string& cid);
    StdLogosResult kadStartProviding(const std::string& cid);
    StdLogosResult kadStopProviding(const std::string& cid);
    StdLogosResult kadGetProviders(const std::string& cid);
    StdLogosResult kadGetRandomRecords();

    // Mix key material crosses the module boundary hex-encoded, matching the
    // cbind's own key encoding.
    StdLogosResult mixGeneratePrivKey();
    StdLogosResult mixPublicKey(const std::string& privKeyHex);
    // Mix dial methods take a single JSON-blob arg to survive the
    // universal-codegen QtRO dispatch (which drops multi-string / int / uint
    // signatures), same as mixSetNodeInfo. Keys per method:
    //   mixDial:                 {peerId, multiaddr, proto}
    //   mixDialWithReply:        {peerId, multiaddr, proto, expectReply, numSurbs}
    //   mixRegisterDestReadBehavior: {proto, behavior, sizeParam}
    //   mixNodepoolAdd:          {peerId, multiaddr, mixPubKey, libp2pPubKey}
    //                            (mixPubKey/libp2pPubKey are hex-encoded keys)
    StdLogosResult mixDial(const std::string& argsJson);
    StdLogosResult mixDialWithReply(const std::string& argsJson);
    StdLogosResult mixRegisterDestReadBehavior(const std::string& argsJson);
    // Mounts the mix protocol with this node's routing identity — the
    // call-time alternative to config-driven mounting (mountMix). Args are a
    // single JSON object to survive the universal-codegen QtRO dispatch (which
    // drops multi-string signatures): {"multiaddr": <str>, "mixPrivKeyHex":
    // <64-hex-char curve25519 priv key>}.
    StdLogosResult mixSetNodeInfo(const std::string& argsJson);
    StdLogosResult mixNodepoolAdd(const std::string& argsJson);

    /* ----------- RLN spam protection (LEZ-backed) ----------- */

    // Wires the LogosAPI handle used to route the RLN fetcher into the rln
    // module. Encoded as a hex string because the universal codegen doesn't
    // recognise opaque pointer types directly (host passes
    // QString::number(reinterpret_cast<quintptr>(api), 16)).
    bool initLogos(const std::string& apiHandleHex);

    // Enable RLN spam protection on the mix protocol. configJson keys: the
    // cbind reads `proofSize` (0 disables the proof field); `configAccount`
    // and `epochDurationSeconds` are captured module-side for the fetch/
    // refresh plumbing. MUST be called before mix mounts (spam protection
    // changes the wire packet size).
    StdLogosResult rlnEnable(const std::string& configJson);
    StdLogosResult rlnIsReady();
    // Self-registration (v1, no gifter): register this node's membership via
    // the rln module and record the on-chain leaf for the proof refresh.
    // Args are passed as a single JSON object so the call survives the
    // universal-codegen QtRO dispatch (which only marshals single-string /
    // (string,int) signatures cleanly — multi-string / int64 args are dropped).
    // JSON keys: {"config": <configAccount>, "wallet": <holdingAccount>,
    //             "rate": <int>}.
    StdLogosResult rlnRegister(const std::string& argsJson);
    // Fetch this node's merkle proof from the rln module (on the Qt/RPC thread,
    // where cross-module calls are safe) and push it via the SetCachedProof
    // request. Call repeatedly after rlnRegister until rlnIsReady() is true —
    // the membership takes a few blocks to land in the on-chain tree.
    StdLogosResult rlnRefreshProof();

    StdLogosResult discoStart();
    StdLogosResult discoStop();
    StdLogosResult discoStartAdvertising(const std::string& serviceId, const std::string& serviceData, const std::string& advertisement);
    StdLogosResult discoStopAdvertising(const std::string& serviceId);
    StdLogosResult discoRegisterInterest(const std::string& serviceId);
    StdLogosResult discoUnregisterInterest(const std::string& serviceId);
    StdLogosResult discoLookup(const std::string& serviceId, const std::string& serviceData);
    StdLogosResult discoRandomLookup();
    StdLogosResult createXpr(const std::vector<std::string>& addrs,
                             const std::map<std::string, std::vector<uint8_t>>& services,
                             uint64_t seqNo);
    StdLogosResult decodeXpr(const std::string& xpr);

    StdLogosResult peerstoreGetPeers();
    StdLogosResult peerstoreGetPeerInfo(const std::string& peerId);
    StdLogosResult peerstoreAddPeer(const std::string& peerId, const std::vector<std::string>& addrs, const std::vector<std::string>& protos);
    StdLogosResult peerstoreSetPeerAddresses(const std::string& peerId, const std::vector<std::string>& addrs);
    StdLogosResult peerstoreSetPeerProtocols(const std::string& peerId, const std::vector<std::string>& protos);
    StdLogosResult peerstoreDeletePeer(const std::string& peerId);

    LogosMap collectMetrics();

private:
    LibP2PCtx* ctx = nullptr;
    Libp2pConfig m_libp2pConfig = {};

    // Set when construction fails; surfaced through status() since the
    // constructor cannot signal failure to the codegen default-constructor.
    std::string m_initError;

    // Backing storage the Libp2pConfig's NimFfiStr/seq views borrow from; it
    // must outlive every libp2p_ctx_create call. Built once in applyOptions and
    // never mutated afterwards, so the views stay valid.
    std::vector<std::string> m_addrs;
    std::vector<NimFfiStr> m_addrsFfi;

    std::vector<std::string> m_bootstrapPeerIds;
    std::vector<std::vector<std::string>> m_bootstrapAddrs;
    std::vector<std::vector<NimFfiStr>> m_bootstrapAddrsFfi;
    std::vector<BootstrapNode> m_bootstrapNodes;

    SecureBytes m_privKey;

    // Backing storage for the MixConfig string views (same lifetime rule as
    // m_addrs: must outlive every libp2p_ctx_create call).
    std::string m_mixPrivKeyHex;
    std::string m_mixMultiaddr;

    // Creates a context from `cfg` without adopting it as the member `ctx`.
    SyncResult spawnContext(Libp2pConfig& cfg);

    // The Nim side owns stream lifetimes and hands out opaque uint64 stream
    // ids; the wrapper forwards them verbatim, so no local stream table.

    TopicQueues m_topicQueues;

    std::mutex m_inboundStreamMutex;
    std::condition_variable m_inboundStreamCond;
    std::unordered_map<std::string, std::deque<uint64_t>> m_inboundStreamQueues;

    void applyOptions(const Libp2pModuleOptions& options);
    StdLogosResult createContext();
    void destroyContext();
    StdLogosResult nodeInfoBoundPorts();

    // Reply trampolines: one per generated response type. Each turns the typed
    // (err_code, reply, err_msg) callback into a SyncResult and resolves the
    // promise handed in as user_data.
    static void cbBool(int ec, const bool* reply, const char* em, void* ud);
    // Like cbBool, but keeps the reply value (for calls whose bool IS the
    // answer, e.g. rln readiness) instead of treating it as a bare ack.
    static void cbBoolValue(int ec, const bool* reply, const char* em, void* ud);
    static void cbBytes(int ec, const NimFfiBytes* reply, const char* em, void* ud);
    static void cbStr(int ec, const NimFfiStr* reply, const char* em, void* ud);
    static void cbRead(int ec, const ReadResponse* reply, const char* em, void* ud);
    static void cbCreate(int ec, LibP2PCtx* newCtx, const char* em, void* ud);
    static void cbPeerInfo(int ec, const PeerInfoResponse* reply, const char* em, void* ud);
    static void cbPeers(int ec, const PeersResponse* reply, const char* em, void* ud);
    static void cbDial(int ec, const DialResponse* reply, const char* em, void* ud);
    static void cbPublish(int ec, const PublishResponse* reply, const char* em, void* ud);
    static void cbProviders(int ec, const ProvidersResponse* reply, const char* em, void* ud);
    static void cbRecords(int ec, const ExtendedRecordsResponse* reply, const char* em, void* ud);
    static void cbRecord(int ec, const ExtendedPeerRecordEntry* reply, const char* em, void* ud);
    static void cbReservation(int ec, const ReservationResponse* reply, const char* em, void* ud);
    static void cbPeerStoreEntry(int ec, const PeerStoreEntryResponse* reply, const char* em, void* ud);

    // Event listeners registered on the context; the Nim side pushes here.
    static void onIncomingStream(const IncomingStreamEvent* evt, void* ud);
    static void onPubsubMessage(const PubsubMessageEvent* evt, void* ud);

    using EmitEventFn = std::function<void(const std::string& eventName, const std::string& data)>;

    // Lock-guarded snapshot of `emitEvent`, taken on the caller thread before any worker can emit, so worker threads never read the public field unsynchronized.
    mutable std::shared_mutex m_emitEventLock;
    EmitEventFn m_emitEventSnapshot;
    void publishEmitEvent();
    void emitEventSafe(const std::string& name, const std::string& data) const;

    // RLN: LogosAPI handle (set via initLogos) used to route the mix RLN
    // fetch requests into the rln module, and the LEZ config-account those
    // fetches query.
    LogosAPI* m_logosAPI = nullptr;
    std::string m_rlnConfigAccount;
    // This node's on-chain RLN membership leaf (set by rlnRegister), used by
    // rlnRefreshProof to fetch the matching merkle proof.
    int64_t m_rlnLeafIndex = -1;
    // Keep-fresh cadence (seconds) for the proof-refresh timer once ready;
    // captured from rlnEnable's epochDurationSeconds. The pre-ready phase polls
    // faster (see startRlnRefreshTimer).
    double m_rlnEpochSeconds = 10.0;
    // Self-scheduling timer on the module's Qt thread (where cross-module calls
    // are safe) that drives rlnRefreshProof after registration, so the module
    // reaches and maintains readiness without a host-side refresh loop.
    QTimer* m_rlnRefreshTimer = nullptr;
    void startRlnRefreshTimer();
    void stopRlnRefreshTimer();

    // On-demand fetch drain: when the nim spam-protection layer needs data
    // only the host can serve (a proof, a fresh valid-roots window), it fires
    // an on_rln_fetch_request event. The listener runs on the Nim dispatch
    // (libp2p) thread and enqueues ONLY — any blocking or cross-module (QtRO)
    // call there would stall the chronos loop or deadlock against owner-thread
    // marshaling. This Qt-thread timer drains the queue, makes the cross-module
    // reads (safe on the Qt thread), answers each request id via the
    // rlnMixFetchReply request, and re-pushes fresh roots via the
    // SetValidRoots request. Concurrent roots requests coalesce into one read,
    // but every request id gets its own reply.
    struct RlnFetchPending {
        uint64_t requestId = 0;
        std::string method;
        std::string params;
    };
    std::mutex m_rlnFetchMutex;
    std::deque<RlnFetchPending> m_rlnFetchQueue;
    QTimer* m_rlnFetchDrainTimer = nullptr;
    static void onRlnFetchRequest(const RlnFetchRequestEvent* evt, void* ud);
    void startRlnFetchDrainTimer();
    void stopRlnFetchDrainTimer();
    void rlnFetchDrain();
    // Fire-and-forget submit of a fetch answer; never blocks on the nim loop.
    void rlnFetchReply(uint64_t requestId, const std::string& error,
                       const std::string& resultJson);

    // Resolves the LogosAPI used by the vendored RlnModuleClient transport:
    // prefers the explicit initLogos(hex) handle, else lazily constructs one
    // for this module process (Qt thread only — rlnEnable warms it up).
    LogosAPI* ensureLogosAPI();
    bool m_ownsLogosAPI = false;

    // Wraps the new-promise / invoke / await / clean-up dance shared by every
    // sync-over-async libp2p op. `invoke(SyncPromise*)` calls the cbinding and
    // returns its sync ret. The Transform overload maps the resolved SyncResult
    // into the final StdLogosResult. `awaitMs` bounds the wait; ops carrying a
    // caller timeout pass awaitTimeoutFor(theirTimeout) so the await outlasts it.
    template <class Invoke>
    StdLogosResult callSync(const char* errPrefix, Invoke&& invoke, int awaitMs = kDefaultOpTimeoutMs) {
        return callSyncWith(errPrefix, std::forward<Invoke>(invoke),
            [](const SyncResult&) -> StdLogosResult { return {true, {}, ""}; }, awaitMs);
    }

    template <class Invoke, class Transform>
    StdLogosResult callSyncWith(const char* errPrefix, Invoke&& invoke, Transform&& transform,
                                int awaitMs = kDefaultOpTimeoutMs) {
        if (!ctx) return {false, {}, "No libp2p context"};
        return callStaticWith(errPrefix, std::forward<Invoke>(invoke),
                              std::forward<Transform>(transform), awaitMs);
    }

    // Same dance without the context check, for the `{.ffiStatic.}` bindings:
    // they take no ctx and run on the library's own static context.
    template <class Invoke, class Transform>
    static StdLogosResult callStaticWith(const char* errPrefix, Invoke&& invoke, Transform&& transform,
                                         int awaitMs = kDefaultOpTimeoutMs) {
        auto* p = new SyncPromise();
        auto f = p->get_future();
        int ret = invoke(p);
        if (ret != 0) {
            // A submit-time failure (encode/OOM/missing-callback) fires the
            // reply callback synchronously — which owns and deletes p — before
            // returning non-zero. Reclaim p only in the (unexpected) case the
            // callback didn't run, so we never double-free.
            if (f.wait_for(std::chrono::seconds(0)) != std::future_status::ready) {
                delete p;
            }
            return {false, {}, std::string(errPrefix) +
                " (ret=" + std::to_string(ret) + ")"};
        }
        auto r = awaitResult(f, awaitMs);
        if (!r.ok) return {false, {}, std::string(errPrefix) + ": " + r.message};
        return transform(r);
    }
};

inline StdLogosResult setLogLevel(const std::string& level) {
    return Libp2pModuleImpl::setLogLevel(level);
}
