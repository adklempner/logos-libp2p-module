#include "rln_client.h"

#include <QJsonDocument>
#include <QString>
#include <QVariant>
#include <QVariantList>

#include <nlohmann/json.hpp>

#include "logos_api.h"
#include "logos_api_client.h"

namespace {
using json = nlohmann::json;

const QString kRlnModule = QStringLiteral("liblogos_rln_module");

// The module's documented 90 s budget for calls that may perform one
// registry read (generate_proof on a cold merkle-path miss, get_valid_roots,
// get_membership_state; ≤70 s worst case per read) — passed explicitly since
// the QtRO default (~20 s) would cut them off.
constexpr int kRegistryReadTimeoutMs = 90000;
// start() applies config and spawns maintenance workers without a
// synchronous registry read.
constexpr int kStartTimeoutMs = 20000;

json synthError(const std::string& message) {
    return json{{"class", "transient"}, {"kind", "client_failure"}, {"message", message}};
}

// Non-throwing parse: discarded on failure.
json tryParse(const std::string& s) { return json::parse(s, nullptr, false); }

// Normalizes a QtRO reply to raw JSON text: a string reply verbatim, a
// structured (map/list) reply through QJsonDocument.
std::string replyToRawJson(const QVariant& reply) {
    std::string raw = reply.toString().toStdString();
    if (raw.empty() && reply.isValid()) {
        const QJsonDocument doc = QJsonDocument::fromVariant(reply);
        if (!doc.isNull()) raw = doc.toJson(QJsonDocument::Compact).toStdString();
    }
    return raw;
}

// Unwraps a `result`-dialect reply: the LogosResult envelope
// {"success","value","error"}, tolerating the double-encoded form (a JSON
// string containing the envelope).
RlnModuleResult unwrapResultEnvelope(const QVariant& reply, const char* method) {
    RlnModuleResult out;

    const std::string raw = replyToRawJson(reply);
    if (raw.empty()) {
        out.error = synthError(std::string(method) +
                               ": empty reply from liblogos_rln_module").dump();
        return out;
    }

    json env = tryParse(raw);
    if (env.is_string()) env = tryParse(env.get<std::string>());  // double-encoded
    if (!env.is_object() || !env.contains("success")) {
        out.error = synthError(std::string(method) + ": unrecognized reply: " + raw).dump();
        return out;
    }

    if (env["success"].is_boolean() && env["success"].get<bool>()) {
        json value = env.value("value", json());
        if (value.is_string()) {
            // The value itself may arrive JSON-encoded; unwrap when it parses.
            json inner = tryParse(value.get<std::string>());
            if (!inner.is_discarded()) value = std::move(inner);
        }
        out.ok = true;
        out.value = value.is_string() ? value.get<std::string>() : value.dump();
        return out;
    }

    // error is the JSON-encoded typed object {"class","kind","message"}.
    json errObj;
    if (env.contains("error")) {
        errObj = env["error"].is_string() ? tryParse(env["error"].get<std::string>())
                                          : env["error"];
    }
    if (!errObj.is_object() || !errObj.contains("class")) {
        const std::string detail =
            env.contains("error")
                ? (env["error"].is_string() ? env["error"].get<std::string>()
                                            : env["error"].dump())
                : std::string("no error detail");
        errObj = synthError(std::string(method) + ": " + detail);
    }
    out.error = errObj.dump();
    return out;
}

std::string invokeToString(LogosAPIClient* client, const QString& method,
                           const QVariantList& args, int timeoutMs) {
    if (!client) return {};
    return client->invokeRemoteMethod(kRlnModule, method, args, Timeout(timeoutMs))
        .toString()
        .toStdString();
}
}  // namespace

RlnModuleClient::RlnModuleClient(LogosAPI* api)
    : m_client(api ? api->getClient(kRlnModule) : nullptr) {}

RlnModuleResult RlnModuleClient::start(const std::string& configJson) {
    if (!m_client) {
        RlnModuleResult r;
        r.error = synthError("start: no rln module client").dump();
        return r;
    }
    const QVariantList args{QString::fromStdString(configJson)};
    const QVariant reply = m_client->invokeRemoteMethod(
        kRlnModule, QStringLiteral("start"), args, Timeout(kStartTimeoutMs));
    return unwrapResultEnvelope(reply, "start");
}

RlnModuleResult RlnModuleClient::generateProof(const std::string& registryId,
                                               const std::string& rlnIdentifierHex,
                                               const std::string& signalHex,
                                               const std::string& timestampStr) {
    if (!m_client) {
        RlnModuleResult r;
        r.error = synthError("generate_proof: no rln module client").dump();
        return r;
    }
    const QVariantList args{QString::fromStdString(registryId),
                            QString::fromStdString(rlnIdentifierHex),
                            QString::fromStdString(signalHex),
                            QString::fromStdString(timestampStr)};
    const QVariant reply = m_client->invokeRemoteMethod(
        kRlnModule, QStringLiteral("generate_proof"), args,
        Timeout(kRegistryReadTimeoutMs));
    return unwrapResultEnvelope(reply, "generate_proof");
}

std::string RlnModuleClient::getValidRoots(const std::string& registryId) {
    const QVariantList args{QString::fromStdString(registryId)};
    return invokeToString(m_client, QStringLiteral("get_valid_roots"), args,
                          kRegistryReadTimeoutMs);
}

std::string RlnModuleClient::getMembershipState(const std::string& registryId,
                                                const std::string& rlnIdentifierHex) {
    const QVariantList args{QString::fromStdString(registryId),
                            QString::fromStdString(rlnIdentifierHex)};
    return invokeToString(m_client, QStringLiteral("get_membership_state"), args,
                          kRegistryReadTimeoutMs);
}
