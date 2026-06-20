---
status: investigating
trigger: "UAT Gap 2 from Phase 67.1"
created: 2026-06-20T13:45:00Z
updated: 2026-06-20T13:45:00Z
---

## Current Focus

hypothesis: "Broken intra-doc links in dlp-agent: doc comments reference items that either don't exist, are private, or are in other crates without proper path resolution"
test: "Read each file with warnings and inspect the doc links at the reported line/column"
expecting: "Each link will be either a private item reference, a non-existent symbol, or a cross-crate reference without full path"
next_action: "Read the five reported files at the specific line locations to inspect each broken link"

## Symptoms

expected: "Running `cargo doc -p dlp-agent --no-deps` completes without emitting any rustdoc warnings."
actual: "`cargo doc -p dlp-agent --no-deps` emits multiple rustdoc warnings about unresolved and private intra-doc links in dlp-agent source files."
errors: |
  warning: unresolved link to `load_default`
     --> dlp-agent\src\config.rs:418:24
  warning: public documentation for `enumerate_active_sessions_pub` links to private item `enumerate_active_sessions`
     --> dlp-agent\src\ui_spawner.rs:109:29
  warning: unresolved link to `remove_client`
    --> dlp-agent\src\ipc\pipe2.rs:60:60
  warning: unresolved link to `ClassificationCache`
     --> dlp-agent\src\hook_ipc.rs:173:33
  warning: unresolved link to `BypassAlert`
     --> dlp-agent\src\hook_ipc.rs:216:32
  warning: unresolved link to `OfflineManager::offline_decision`
     --> dlp-agent\src\hook_ipc.rs:315:11
  warning: unresolved link to `UI_CONNECT_TIMEOUT_SECS`
     --> dlp-agent\src\password_stop.rs:262:26
reproduction: "Run `cargo doc -p dlp-agent --no-deps` in the project root."
started: "Discovered during UAT of phase 67.1"

## Eliminated

## Evidence

- timestamp: 2026-06-20T13:45:00Z
  checked: "config.rs line 418"
  found: "[`load_default`] is used in doc comment for `effective_config_path()`, but `load_default` is defined as a method on `AgentConfig` (impl block), not a free function. The link `load_default` without path resolution fails because rustdoc cannot resolve it from outside the impl block context."
  implication: "Need to use proper path like `AgentConfig::load_default` or `Self::load_default`"

- timestamp: 2026-06-20T13:45:00Z
  checked: "ui_spawner.rs line 109"
  found: "[`enumerate_active_sessions`] links to a private function `fn enumerate_active_sessions()` at line 120. The public wrapper `enumerate_active_sessions_pub` documents itself as wrapping the private function."
  implication: "Private items cannot be linked in public docs. Either make the function pub(crate) and use `crate::ui_spawner::enumerate_active_sessions`, or remove the link and use backticks only."

- timestamp: 2026-06-20T13:45:00Z
  checked: "ipc/pipe2.rs line 60"
  found: "[`remove_client`] links to `Broadcaster::remove_client` which is a public method at line 74, but the link lacks the struct prefix. In rustdoc, `[`remove_client`]` alone won't resolve to a method on `Broadcaster`."
  implication: "Need to use `[Broadcaster::remove_client]` or `[Self::remove_client]` from within the impl block."

- timestamp: 2026-06-20T13:45:00Z
  checked: "hook_ipc.rs line 173"
  found: "[`ClassificationCache`] is referenced in the doc comment for `CacheAccessor` trait, but `ClassificationCache` is defined in `crate::classification_cache` module. The bare name `ClassificationCache` may not resolve without a path prefix like `crate::classification_cache::ClassificationCache`."
  implication: "Need to use full path `crate::classification_cache::ClassificationCache` or ensure the type is in scope with a `use` statement that rustdoc can follow."

- timestamp: 2026-06-20T13:45:00Z
  checked: "hook_ipc.rs line 216"
  found: "[`BypassAlert`] is referenced in doc comment for `with_bypass_channel`. `BypassAlert` is from `dlp_common::hook_ipc::BypassAlert` (external crate). The bare name won't resolve cross-crate."
  implication: "Need to use full path `dlp_common::hook_ipc::BypassAlert` in the doc link."

- timestamp: 2026-06-20T13:45:00Z
  checked: "hook_ipc.rs line 315"
  found: "[`OfflineManager::offline_decision`] links to a method in `crate::offline::OfflineManager`. The path may not resolve because `offline` module may not be public or the link syntax may need adjustment."
  implication: "Need to verify module visibility and use correct path like `crate::offline::OfflineManager::offline_decision` or just `OfflineManager::offline_decision` if module is in scope."

- timestamp: 2026-06-20T13:45:00Z
  checked: "password_stop.rs line 262"
  found: "[`UI_CONNECT_TIMEOUT_SECS`] is referenced in doc comment for `initiate_stop`. This is likely a `const` defined in the same file or a module. Need to verify if it's `pub` and what its exact path is."
  implication: "If the constant is private or not in scope, the link fails. Need to either make it pub or use correct path."

## Resolution

root_cause: ""
fix: ""
verification: ""
files_changed: []
