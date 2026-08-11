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
    // gated on a cached proof).
    auto en = node->rlnEnable(
        "{\"proofSize\":128,"
        "\"epochDurationSeconds\":10.0,\"configAccount\":\"testacct\"}");
    LOGOS_ASSERT_TRUE(en.success);

    // No proof pushed yet -> not ready.
    auto ready = node->rlnIsReady();
    LOGOS_ASSERT_TRUE(ready.success);
    LOGOS_ASSERT_FALSE(ready.value.get<bool>());

    // Double-enable is rejected by the cbind rather than crashing.
    LOGOS_ASSERT_FALSE(node->rlnEnable("{\"proofSize\":128}").success);

    LOGOS_ASSERT_TRUE(node->stop().success);
}

LOGOS_TEST(rln_register_requires_logos_api) {
    auto node = std::make_unique<Libp2pModuleImpl>(Libp2pModuleOptions{});
    LOGOS_ASSERT_TRUE(node->start().success);

    // Without initLogos the cross-module register flow fails cleanly.
    auto reg = node->rlnRegister(R"({"config":"cfgacct","wallet":"holdacct","rate":100})");
    LOGOS_ASSERT_FALSE(reg.success);

    LOGOS_ASSERT_TRUE(node->stop().success);
}
