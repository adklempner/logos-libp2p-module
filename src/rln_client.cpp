#include "rln_client.h"

#include <QString>
#include <QVariant>
#include <QVariantList>

#include "logos_api.h"
#include "logos_api_client.h"

namespace {
const QString kRlnModule = QStringLiteral("liblogos_rln_module");

std::string invokeToString(LogosAPIClient* client, const QString& method,
                           const QVariantList& args) {
    if (!client) return {};
    return client->invokeRemoteMethod(kRlnModule, method, args).toString().toStdString();
}
}  // namespace

RlnModuleClient::RlnModuleClient(LogosAPI* api)
    : m_client(api ? api->getClient(kRlnModule) : nullptr) {}

std::string RlnModuleClient::get_valid_roots(const std::string& rlnAccountIdHex) {
    return invokeToString(m_client, QStringLiteral("get_valid_roots"),
                          {QString::fromStdString(rlnAccountIdHex)});
}

std::string RlnModuleClient::get_merkle_proofs(const std::string& configAccountId,
                                               const std::string& leafIndicesJson) {
    return invokeToString(m_client, QStringLiteral("get_merkle_proofs"),
                          {QString::fromStdString(configAccountId),
                           QString::fromStdString(leafIndicesJson)});
}

std::string RlnModuleClient::generate_identity(const std::string& walletAccountId) {
    return invokeToString(m_client, QStringLiteral("generate_identity"),
                          {QString::fromStdString(walletAccountId)});
}

std::string RlnModuleClient::register_member(const std::string& configAccountId,
                                             const std::string& userHoldingAccountId,
                                             const std::string& idCommitmentHex,
                                             int64_t rateLimit) {
    return invokeToString(m_client, QStringLiteral("register_member"),
                          {QString::fromStdString(configAccountId),
                           QString::fromStdString(userHoldingAccountId),
                           QString::fromStdString(idCommitmentHex),
                           QVariant::fromValue<qlonglong>(rateLimit)});
}
