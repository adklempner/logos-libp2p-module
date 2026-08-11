#pragma once

#include <string>

class LogosAPI;
class LogosAPIClient;

// Hand-vendored std-typed client for liblogos_rln_module — the RLN
// membership module (contract: src/liblogos_rln_module.lidl, v0.4.0) — over
// the LogosAPI/QtRO transport. Every call is scoped by the arg pair
// (registry_id, rln_identifier_hex); the module holds no default scope.
//
// Two reply dialects, split by the method's declared return type:
// - `result` methods (start, generateProof) return the LogosResult envelope
//   {"success","value","error"} — on failure `error` is the JSON-encoded
//   typed object {"class","kind","message"}. RlnModuleResult carries the
//   unwrapped value or that error object; the unwrap tolerates the
//   double-encoded form (a JSON string containing the envelope, a known SDK
//   wire quirk).
// - `tstr` methods (getValidRoots, getMembershipState) return compact JSON
//   as-is; "" marks a transport failure, module-side failures arrive in-band
//   as {"error":{"class","kind","message"}}.
//
// Only included from .cpp files — plugin.h is codegen-scanned and must stay
// free of Qt/SDK includes.
struct RlnModuleResult {
    bool ok = false;
    // ok: the envelope's value as compact JSON (an object/array dump, or a
    // bare scalar's string form).
    std::string value;
    // !ok: the typed error object JSON {"class","kind","message"} — the
    // module's own object when it produced one, else a synthesized
    // {"class":"transient","kind":"client_failure","message":…}.
    std::string error;
};

class RlnModuleClient {
public:
    explicit RlnModuleClient(LogosAPI* api);

    RlnModuleResult start(const std::string& configJson);
    RlnModuleResult generateProof(const std::string& registryId,
                                  const std::string& rlnIdentifierHex,
                                  const std::string& signalHex,
                                  const std::string& timestampStr);
    std::string getValidRoots(const std::string& registryId);
    std::string getMembershipState(const std::string& registryId,
                                   const std::string& rlnIdentifierHex);

private:
    LogosAPIClient* m_client;
};
