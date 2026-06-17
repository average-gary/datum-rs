//! Phase 2 compile-only check: confirm the pinned `stratum-core` rev is
//! reachable and the three import paths datum-rs's later phases will actually
//! use still resolve. If SRI restructures, this test breaks early and loud.

// Bare `use` statements are themselves a compile-time path check. If any of
// these paths get renamed or moved upstream, this test file fails to compile.
#[allow(unused_imports)]
use stratum_core::channels_sv2::server::extended::ExtendedChannel;
#[allow(unused_imports)]
use stratum_core::handlers_sv2::HandleMiningMessagesFromClientAsync;
#[allow(unused_imports)]
use stratum_core::mining_sv2::SubmitSharesExtended;

// `HandleMiningMessagesFromClientAsync` uses `impl Trait` in return position
// (via `#[trait_variant::make(Send)]`), so it is not dyn-compatible — we
// can't reference it through `dyn ...`. Use a generic-bound function instead;
// the existence of the bound proves the trait path resolves.
#[allow(dead_code)]
fn _bound_check<T: HandleMiningMessagesFromClientAsync>(_: &T) {}

#[test]
fn sri_imports_resolve() {
    // `type_name` of a concrete type forces full resolution.
    let _ = std::any::type_name::<ExtendedChannel>();
    let _ = std::any::type_name::<SubmitSharesExtended>();
}
