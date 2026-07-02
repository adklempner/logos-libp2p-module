#include "plugin.h"

#include <string>
#include <vector>

#include <QString>
#include <QTimer>

#include "logos_api.h"
#include "liblogos_rln_module_api.h"

using json = nlohmann::json;

// Server side. The register callback fires on the libp2p thread (where a
// cross-module QtRO call would deadlock, exactly like the rln fetcher), so it
// only enqueues the job; gifterDrainQueue runs on the module's Qt thread and
// does the on-chain register_member there, then completes the async response.
void Libp2pModuleImpl::gifterRegisterCallback(uint64_t handle,
                                              const char* idCommitmentHex,
                                              uint64_t rateLimit, void* userData) {
    auto* self = static_cast<Libp2pModuleImpl*>(userData);
    if (!self) return;
    GifterJob job{handle, idCommitmentHex ? std::string(idCommitmentHex) : std::string(),
                  static_cast<int>(rateLimit)};
    {
        std::lock_guard<std::mutex> lk(self->m_gifterQueueMutex);
        self->m_gifterQueue.push(std::move(job));
    }
}

void Libp2pModuleImpl::gifterDoRegister(uint64_t handle, const std::string& idCommitment,
                                        int rate) {
    auto complete = [&](const json& j) {
        const std::string s = j.dump();
        libp2p_gifter_complete(handle, s.c_str());
    };

    LogosAPI* api = ensureLogosAPI();
    if (!api) {
        complete(json{{"ok", false}, {"error", "LogosAPI not set"}});
        return;
    }

    LiblogosRlnModule rln(api);
    const std::string regJson =
        rln.register_member(m_gifterConfig, m_gifterWallet, idCommitment, rate);
    if (regJson.empty()) {
        complete(json{{"ok", false}, {"error", "register_member failed"}});
        return;
    }

    int64_t leafIndex = -1;
    try {
        auto j = json::parse(regJson);
        leafIndex = j.at("leaf_index").get<int64_t>();
    } catch (...) {
        complete(json{{"ok", false},
                      {"error", "register_member: bad response: " + regJson}});
        return;
    }

    complete(json{{"ok", true},
                  {"leaf_index", leafIndex},
                  {"config_account", m_gifterConfig}});
}

void Libp2pModuleImpl::stopGifterTimer() {
    if (!m_gifterTimer) return;
    m_gifterTimer->stop();
    m_gifterTimer->deleteLater();
    m_gifterTimer = nullptr;
}

void Libp2pModuleImpl::gifterDrainQueue() {
    std::vector<GifterJob> jobs;
    {
        std::lock_guard<std::mutex> lk(m_gifterQueueMutex);
        while (!m_gifterQueue.empty()) {
            jobs.push_back(std::move(m_gifterQueue.front()));
            m_gifterQueue.pop();
        }
    }
    // Process sequentially on this (Qt) thread: each register_member submits one
    // funded tx, so serial processing keeps the gifter wallet's nonce ordered.
    for (const auto& job : jobs) {
        gifterDoRegister(job.handle, job.idCommitment, job.rate);
    }
}

StdLogosResult Libp2pModuleImpl::rlnGifterServe(const std::string& argsJson) {
    if (!ctx) return {false, {}, "No libp2p context"};

    std::vector<std::string> allowlist;
    try {
        auto a = json::parse(argsJson);
        m_gifterConfig = a.at("config").get<std::string>();
        m_gifterWallet = a.at("wallet").get<std::string>();
        if (a.contains("allowlist")) {
            for (const auto& e : a["allowlist"]) allowlist.push_back(e.get<std::string>());
        }
    } catch (...) {
        return {false, {}, "rlnGifterServe: bad args json (need {config,wallet,allowlist})"};
    }

    // Drain timer on the module's Qt thread (created here, where cross-module
    // calls are safe). 3-arg connect with the timer as context so the lambda
    // runs on this thread and drops automatically when the timer is destroyed.
    if (!m_gifterTimer) {
        m_gifterTimer = new QTimer();
        m_gifterTimer->setInterval(200);
        QObject::connect(m_gifterTimer, &QTimer::timeout, m_gifterTimer,
                         [this]() { gifterDrainQueue(); });
        m_gifterTimer->start();
    }

    json cfg;
    cfg["allowlist"] = allowlist;
    const std::string cfgJson = cfg.dump();

    auto* p = new SyncPromise();
    auto f = p->get_future();
    int ret = libp2p_gifter_serve(ctx, cfgJson.c_str(),
                                  &Libp2pModuleImpl::promiseCallback, p,
                                  &Libp2pModuleImpl::gifterRegisterCallback, this);
    if (ret != RET_OK) { delete p; return {false, {}, "libp2p_gifter_serve dispatch failed"}; }

    auto r = awaitResult(f, 30000);
    if (!r.ok) return {false, {}, r.message};
    return {true, {}, ""};
}

StdLogosResult Libp2pModuleImpl::rlnGifterRequest(const std::string& argsJson) {
    if (!ctx) return {false, {}, "No libp2p context"};

    std::string gifterPeerId, gifterMultiaddr, configAccount, seed, authKey;
    int rate = 0;
    try {
        auto a = json::parse(argsJson);
        gifterPeerId = a.at("gifterPeerId").get<std::string>();
        gifterMultiaddr = a.at("gifterMultiaddr").get<std::string>();
        configAccount = a.at("config").get<std::string>();
        seed = a.at("seed").get<std::string>();
        rate = a.at("rate").get<int>();
        authKey = a.value("authKey", std::string());
    } catch (...) {
        return {false, {},
                "rlnGifterRequest: bad args json (need {gifterPeerId,gifterMultiaddr,config,seed,rate}, optional authKey)"};
    }

    LogosAPI* api = ensureLogosAPI();
    if (!api) return {false, {}, "LogosAPI not set (call initLogos)"};
    LiblogosRlnModule rln(api);

    // 1. Derive our own identity locally. The idSecretHash never leaves this
    //    node; only the idCommitment is sent to the gifter.
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

    // 2. Request an allocation from the gifter (dial + EIP-191 auth + reply),
    //    all on the libp2p thread inside the cbind.
    json reqArgs;
    reqArgs["gifterPeerId"] = gifterPeerId;
    reqArgs["gifterMultiaddr"] = gifterMultiaddr;
    reqArgs["idCommitment"] = idCommitment;
    reqArgs["rate"] = rate;
    if (!authKey.empty()) reqArgs["authKey"] = authKey;
    const std::string reqJson = reqArgs.dump();

    auto* p = new SyncPromise();
    auto f = p->get_future();
    int ret = libp2p_gifter_request(ctx, reqJson.c_str(),
                                    &Libp2pModuleImpl::promiseCallback, p);
    if (ret != RET_OK) { delete p; return {false, {}, "libp2p_gifter_request dispatch failed"}; }

    auto r = awaitResult(f, 180000);
    if (!r.ok) return {false, {}, r.message};

    int64_t leafIndex = -1;
    try {
        auto j = json::parse(r.message);
        leafIndex = j.at("leaf_index").get<int64_t>();
    } catch (...) {
        return {false, {}, "gifter response: bad json: " + r.message};
    }

    // 3. Adopt the granted membership: attach the credential + leaf and drive
    //    proof refresh, exactly as self-registration does. The config account
    //    for proof fetches comes from rlnEnable; set it here too if provided.
    if (m_rlnConfigAccount.empty()) m_rlnConfigAccount = configAccount;
    auto setRes = rlnSetIdentity(idSecretHash, leafIndex);
    if (!setRes.success) return setRes;
    m_rlnLeafIndex = leafIndex;
    startRlnRefreshTimer();

    return {true,
            json{{"leaf_index", leafIndex}, {"id_commitment", idCommitment},
                 {"auth_success", true}},
            ""};
}
