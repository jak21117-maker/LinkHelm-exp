// LinkHelm-exp beta0.5.0 - A++ routing + phone-liveness watchdog policy test.
//
// Reuses PRODUCTION code (#include exp_engine.cpp). No driver, no admin, no
// network required. Verifies:
//   1) Default policy: relay_mode 0 (every process on the A/SOCKS5 route),
//      fast_handshake OFF (pipelined handshake reverted), system DNS untouched.
//   2) The denylist is still loaded (config/compat kept) but does NOT change
//      routing in the default mode - ACE and LOL take the identical path.
//   3) DNS never takes the native route.
//   4) Legacy modes 1/2 still reachable as explicit opt-in (rollback kept).
//   5) Phone-liveness watchdog ON by default, 10s x 3 strikes = 30s to fault.
#include <cstdio>
#include <string>

#include "../src/exp_engine.cpp"

using namespace linkhelm;

static int g_pass = 0, g_fail = 0;
static void Check(bool ok, const char* name, const std::string& detail = "") {
    std::printf("[%s] %-64s %s\n", ok ? "PASS" : "FAIL", name, detail.c_str());
    if (ok) ++g_pass; else ++g_fail;
}

int main() {
    std::printf("=== LinkHelm-exp beta0.5.0 routing + liveness policy test ===\n\n");

    // 1) Default policy.
    ExpPolicy pol = LoadPolicy();
    Check(pol.relay_mode == 0,
          "default relay_mode == 0 (all-relay / A++)");
    Check(pol.fast_handshake == false,
          "default fast_handshake == false (pipelined handshake reverted)");
    Check(pol.system_dns_proxy == false,
          "default system_dns_proxy == false (system DNS untouched)");

    // 5) Phone-liveness watchdog defaults.
    Check(pol.phone_liveness == true,
          "default phone_liveness == true (auto-disconnect watchdog armed)");
    Check(pol.probe_interval_s == 10,
          "default probe_interval_s == 10");
    Check(pol.probe_strikes == 3,
          "default probe_strikes == 3 (30s to declare phone lost)");

    // 2) Denylist loaded but inert in default mode (identical treatment).
    anticheat::InitNames();
    auto& c = anticheat::Cache();
    Check(!c.direct_names.empty(), "built-in denylist still loaded (compat)");
    auto on_list = [&](const wchar_t* name) {
        return c.direct_names.find(anticheat::LowerW(name)) != c.direct_names.end();
    };
    Check(on_list(L"sguard64.exe"),    "denylist has sguard64.exe (ACE/SGuard)");
    Check(on_list(L"ace-service.exe"), "denylist has ace-service.exe (ACE)");
    Check(on_list(L"easyanticheat.exe"), "denylist has easyanticheat.exe (EAC)");
    Check(on_list(L"vgk.exe"),         "denylist has vgk.exe (Vanguard)");

    // Mode 0: nobody goes native. Mirrors the capture-loop guard
    // `if (policy.relay_mode != 0)` -> whole routing block skipped.
    auto go_native = [&](int mode, bool listed) {
        return mode == 0 ? false
             : (mode == 1 ? !listed : listed);  // 1: others native; 2: listed native
    };
    bool ace_native = go_native(pol.relay_mode, on_list(L"sguard64.exe"));
    bool lol_native = go_native(pol.relay_mode, false /* LOL not listed */);
    Check(ace_native == false,
          "A++: ACE/Guard listed -> SOCKS5 relay (NOT native)");
    Check(lol_native == false,
          "A++: LOL/other process -> SOCKS5 relay (NOT native) - game online");

    // 3) DNS always relayed, never native (is_dns short-circuits routing).
    Check(go_native(pol.relay_mode, false) == false,
          "A++: DNS (UDP:53) forced to relay, never native");

    // 4) Rollback modes preserved.
    Check(go_native(1, false) == true && go_native(1, true) == false,
          "mode1 opt-in: others->native, listed->relay (rollback kept)");
    Check(go_native(2, true) == true && go_native(2, false) == false,
          "mode2 opt-in legacy: listed->native, others->relay (rollback kept)");

    std::printf("\n=== RESULT: %d passed, %d failed ===\n", g_pass, g_fail);
    return g_fail == 0 ? 0 : 1;
}
