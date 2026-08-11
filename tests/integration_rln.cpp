#include <logos_test.h>
#include <plugin.h>
#include <memory>
#include "test_helpers.h"

// In-process boundary tests for the RLN method surface. The cross-module
// fetch routing and the full membership->proof->ready flow need a live rln
// module + LSSA sequencer (Phase 5 daemon harness). Here we assert the
// module-side methods are wired to the cbind and behave correctly at the C
// boundary.

LOGOS_TEST(rln_enable_and_readiness_gate) {
    auto node = std::make_unique<Libp2pModuleImpl>(Libp2pModuleOptions{});
    LOGOS_ASSERT_TRUE(node->start().success);

    // Not enabled yet -> not ready.
    auto pre = node->rlnIsReady();
    LOGOS_ASSERT_TRUE(pre.success);
    LOGOS_ASSERT_FALSE(pre.value.get<bool>());

    // enable installs the spam-protection hook (proofSize > 0 keeps readiness
    // gated) and captures the (registry_id, rln_identifier_hex) scope for the
    // membership-module calls. The cross-module start() is attempted but its
    // failure (no membership module in this process) is non-fatal.
    auto en = node->rlnEnable(
        "{\"proofSize\":128,"
        "\"registry_id\":\"logos:testnet:0011\","
        "\"rln_identifier_hex\":\"0x0000000000000000000000000000000000000000000000000000000000000001\","
        "\"epoch_size_sec\":10}");
    LOGOS_ASSERT_TRUE(en.success);

    // Membership not active (no membership module) -> not ready.
    auto ready = node->rlnIsReady();
    LOGOS_ASSERT_TRUE(ready.success);
    LOGOS_ASSERT_FALSE(ready.value.get<bool>());

    // A config missing the required scope keys is rejected up front.
    LOGOS_ASSERT_FALSE(node->rlnEnable("{\"proofSize\":128}").success);

    // Double-enable is rejected by the cbind rather than crashing.
    LOGOS_ASSERT_FALSE(node->rlnEnable(
        "{\"proofSize\":128,"
        "\"registry_id\":\"logos:testnet:0011\","
        "\"rln_identifier_hex\":\"0x0000000000000000000000000000000000000000000000000000000000000001\"}")
        .success);

    LOGOS_ASSERT_TRUE(node->stop().success);
}

LOGOS_TEST(rln_retired_methods_fail_cleanly) {
    auto node = std::make_unique<Libp2pModuleImpl>(Libp2pModuleOptions{});
    LOGOS_ASSERT_TRUE(node->start().success);

    // Registration and the cached-proof push moved into the membership
    // module; the retained QtRO surface reports the retirement as an error.
    auto reg = node->rlnRegister(R"({"config":"cfgacct","wallet":"holdacct","rate":100})");
    LOGOS_ASSERT_FALSE(reg.success);
    LOGOS_ASSERT_FALSE(node->rlnRefreshProof().success);

    LOGOS_ASSERT_TRUE(node->stop().success);
}
