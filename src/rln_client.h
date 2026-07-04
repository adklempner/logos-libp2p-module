#pragma once

#include <cstdint>
#include <string>

class LogosAPI;
class LogosAPIClient;

// Hand-vendored std-typed client for liblogos_rln_module over the
// LogosAPI/QtRO transport — the ApiStyle::Std shape the previous
// module-builder generated for this dependency. The current builder forces
// Qt-free LpClient (lp_invoke) wrappers for universal modules, but the
// deployed rln module .lgx is a pre-protocol build the lp path cannot reach
// (the module process SIGSEGVs on the first lp_invoke), while this transport
// is the one the running deployment already proves. Replace with the
// generated modules().liblogos_rln_module once the rln module ships as a
// protocol build.
//
// Only included from .cpp files — plugin.h is codegen-scanned and must stay
// free of Qt/SDK includes.
class RlnModuleClient {
public:
    explicit RlnModuleClient(LogosAPI* api);

    std::string get_valid_roots(const std::string& rlnAccountIdHex);
    std::string get_merkle_proofs(const std::string& configAccountId,
                                  const std::string& leafIndicesJson);
    std::string generate_identity(const std::string& walletAccountId);
    std::string register_member(const std::string& configAccountId,
                                const std::string& userHoldingAccountId,
                                const std::string& idCommitmentHex,
                                int64_t rateLimit);

private:
    LogosAPIClient* m_client;
};
