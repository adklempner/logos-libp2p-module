#include <logos_test.h>
#include <plugin.h>
#include <memory>
#include "test_helpers.h"

// In-process boundary tests for the RLN method surface. The cross-module
// fetcher routing and the full membership->proof->ready flow need a live rln
// module + LSSA sequencer (Phase 5 daemon harness); the SpamProtection
// factory -> group-manager -> readiness transition itself is covered by the
// plugin's own test_cbind_rln. Here we assert the module-side methods are
// wired to the cbind and behave correctly at the C boundary.

LOGOS_TEST(rln_enable_and_readiness_gate) {
    auto node = std::make_unique<Libp2pModuleImpl>(Libp2pModuleOptions{});
    LOGOS_ASSERT_TRUE(node->start().success);

    // enable registers the SpamProtection factory + installs the fetcher.
    auto en = node->rlnEnable(
        "{\"useOnchainLEZ\":true,\"userMessageLimit\":100,"
        "\"epochDurationSeconds\":10.0,\"configAccount\":\"testacct\"}");
    LOGOS_ASSERT_TRUE(en.success);

    // No group manager mounted yet -> not ready, and polling/identity are
    // graceful no-ops rather than crashes.
    auto ready = node->rlnIsReady();
    LOGOS_ASSERT_TRUE(ready.success);
    LOGOS_ASSERT_FALSE(ready.value.get<bool>());

    LOGOS_ASSERT_FALSE(node->rlnStartPolling().success);

    LOGOS_ASSERT_TRUE(node->stop().success);
}

LOGOS_TEST(rln_set_identity_validates_hex) {
    auto node = std::make_unique<Libp2pModuleImpl>(Libp2pModuleOptions{});
    LOGOS_ASSERT_TRUE(node->start().success);

    // Bad hex is rejected by the module before reaching the cbind.
    LOGOS_ASSERT_FALSE(node->rlnSetIdentity("not-hex", 0).success);
    LOGOS_ASSERT_FALSE(node->rlnSetIdentity(std::string(63, 'a'), 0).success);

    // Well-formed 32-byte hex parses, but with no group manager mounted the
    // cbind reports failure (rather than crashing).
    LOGOS_ASSERT_FALSE(node->rlnSetIdentity(std::string(64, 'a'), 0).success);

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
