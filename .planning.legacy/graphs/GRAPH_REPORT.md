# Graph Report - .  (2026-04-15)

## Corpus Check
- 89 files · ~138,833 words
- Verdict: corpus is large enough that graph structure adds value.

## Summary
- 1298 nodes · 1984 edges · 82 communities detected
- Extraction: 100% EXTRACTED · 0% INFERRED · 0% AMBIGUOUS
- Token cost: 0 input · 0 output

## Community Hubs (Navigation)
- [[_COMMUNITY_Community 0|Community 0]]
- [[_COMMUNITY_Community 1|Community 1]]
- [[_COMMUNITY_Community 2|Community 2]]
- [[_COMMUNITY_Community 3|Community 3]]
- [[_COMMUNITY_Community 4|Community 4]]
- [[_COMMUNITY_Community 5|Community 5]]
- [[_COMMUNITY_Community 6|Community 6]]
- [[_COMMUNITY_Community 7|Community 7]]
- [[_COMMUNITY_Community 8|Community 8]]
- [[_COMMUNITY_Community 9|Community 9]]
- [[_COMMUNITY_Community 10|Community 10]]
- [[_COMMUNITY_Community 11|Community 11]]
- [[_COMMUNITY_Community 12|Community 12]]
- [[_COMMUNITY_Community 13|Community 13]]
- [[_COMMUNITY_Community 14|Community 14]]
- [[_COMMUNITY_Community 15|Community 15]]
- [[_COMMUNITY_Community 16|Community 16]]
- [[_COMMUNITY_Community 17|Community 17]]
- [[_COMMUNITY_Community 18|Community 18]]
- [[_COMMUNITY_Community 19|Community 19]]
- [[_COMMUNITY_Community 20|Community 20]]
- [[_COMMUNITY_Community 21|Community 21]]
- [[_COMMUNITY_Community 22|Community 22]]
- [[_COMMUNITY_Community 23|Community 23]]
- [[_COMMUNITY_Community 24|Community 24]]
- [[_COMMUNITY_Community 25|Community 25]]
- [[_COMMUNITY_Community 26|Community 26]]
- [[_COMMUNITY_Community 27|Community 27]]
- [[_COMMUNITY_Community 28|Community 28]]
- [[_COMMUNITY_Community 29|Community 29]]
- [[_COMMUNITY_Community 30|Community 30]]
- [[_COMMUNITY_Community 31|Community 31]]
- [[_COMMUNITY_Community 32|Community 32]]
- [[_COMMUNITY_Community 33|Community 33]]
- [[_COMMUNITY_Community 34|Community 34]]
- [[_COMMUNITY_Community 35|Community 35]]
- [[_COMMUNITY_Community 36|Community 36]]
- [[_COMMUNITY_Community 37|Community 37]]
- [[_COMMUNITY_Community 38|Community 38]]
- [[_COMMUNITY_Community 39|Community 39]]
- [[_COMMUNITY_Community 40|Community 40]]
- [[_COMMUNITY_Community 41|Community 41]]
- [[_COMMUNITY_Community 42|Community 42]]
- [[_COMMUNITY_Community 43|Community 43]]
- [[_COMMUNITY_Community 44|Community 44]]
- [[_COMMUNITY_Community 45|Community 45]]
- [[_COMMUNITY_Community 46|Community 46]]
- [[_COMMUNITY_Community 47|Community 47]]
- [[_COMMUNITY_Community 48|Community 48]]
- [[_COMMUNITY_Community 49|Community 49]]
- [[_COMMUNITY_Community 50|Community 50]]
- [[_COMMUNITY_Community 51|Community 51]]
- [[_COMMUNITY_Community 52|Community 52]]
- [[_COMMUNITY_Community 53|Community 53]]
- [[_COMMUNITY_Community 54|Community 54]]
- [[_COMMUNITY_Community 55|Community 55]]
- [[_COMMUNITY_Community 56|Community 56]]
- [[_COMMUNITY_Community 57|Community 57]]
- [[_COMMUNITY_Community 58|Community 58]]
- [[_COMMUNITY_Community 59|Community 59]]
- [[_COMMUNITY_Community 60|Community 60]]
- [[_COMMUNITY_Community 61|Community 61]]
- [[_COMMUNITY_Community 62|Community 62]]
- [[_COMMUNITY_Community 63|Community 63]]
- [[_COMMUNITY_Community 64|Community 64]]
- [[_COMMUNITY_Community 65|Community 65]]
- [[_COMMUNITY_Community 66|Community 66]]
- [[_COMMUNITY_Community 67|Community 67]]
- [[_COMMUNITY_Community 68|Community 68]]
- [[_COMMUNITY_Community 69|Community 69]]
- [[_COMMUNITY_Community 70|Community 70]]
- [[_COMMUNITY_Community 71|Community 71]]
- [[_COMMUNITY_Community 72|Community 72]]
- [[_COMMUNITY_Community 73|Community 73]]
- [[_COMMUNITY_Community 74|Community 74]]
- [[_COMMUNITY_Community 75|Community 75]]
- [[_COMMUNITY_Community 76|Community 76]]
- [[_COMMUNITY_Community 77|Community 77]]
- [[_COMMUNITY_Community 78|Community 78]]
- [[_COMMUNITY_Community 79|Community 79]]
- [[_COMMUNITY_Community 80|Community 80]]
- [[_COMMUNITY_Community 81|Community 81]]

## God Nodes (most connected - your core abstractions)
1. `spawn_admin_app()` - 25 edges
2. `mint_admin_jwt()` - 20 edges
3. `handle_event()` - 13 edges
4. `SmbMonitor` - 13 edges
5. `EngineClient` - 12 edges
6. `main()` - 11 edges
7. `draw_screen()` - 11 edges
8. `IdentityResolver` - 11 edges
9. `parse_json()` - 11 edges
10. `Cache` - 10 edges

## Surprising Connections (you probably didn't know these)
- `main()` --calls--> `extract_connect_flag()`  [EXTRACTED]
  dlp-user-ui\src\main.rs → dlp-admin-cli\src\main.rs
- `main()` --calls--> `load_ldap_config()`  [EXTRACTED]
  dlp-user-ui\src\main.rs → dlp-server\src\main.rs
- `main()` --calls--> `shutdown_signal()`  [EXTRACTED]
  dlp-user-ui\src\main.rs → dlp-server\src\main.rs
- `main()` --calls--> `print_help()`  [EXTRACTED]
  dlp-user-ui\src\main.rs → dlp-server\src\main.rs
- `main()` --calls--> `run()`  [EXTRACTED]
  dlp-user-ui\src\main.rs → dlp-admin-cli\src\main.rs

## Communities

### Community 0 - "Community 0"
Cohesion: 0.01
Nodes (33): make_event(), make_request(), make_response(), parse_json(), required_field(), start_engine_with_json_response(), start_engine_with_status(), test_audit_event_access_context_local() (+25 more)

### Community 1 - "Community 1"
Cohesion: 0.04
Nodes (50): admin_router(), AgentConfigPayload, AlertRouterConfigPayload, AuthHashResponse, HealthResponse, LdapConfigPayload, mint_admin_jwt(), PolicyPayload (+42 more)

### Community 2 - "Community 2"
Cohesion: 0.05
Nodes (23): abac_action_to_dlp(), make_request(), start_error_engine(), start_mock_engine(), start_mock_engine_response(), start_policy_engine(), test_agent_cache_hit_real_engine(), test_agent_to_real_engine_e2e() (+15 more)

### Community 3 - "Community 3"
Cohesion: 0.09
Nodes (21): emit_connected_events(), emit_disconnected_events(), enumerate_connected_shares(), extract_server_name(), matches_whitelist(), NetworkShareDetector, poll_loop(), SmbMonitor (+13 more)

### Community 4 - "Community 4"
Cohesion: 0.08
Nodes (20): AdClient, AdClientError, AdRequest, do_resolve_groups(), do_resolve_sid(), find_local_ipv4(), get_ad_site_name(), get_device_trust() (+12 more)

### Community 5 - "Community 5"
Cohesion: 0.11
Nodes (38): action_agent_list(), action_change_admin_password(), action_create_policy(), action_delete_policy(), action_get_policy(), action_list_policies(), action_load_alert_config(), action_load_siem_config() (+30 more)

### Community 6 - "Community 6"
Cohesion: 0.09
Nodes (17): AgentConfigPayload, AuditBuffer, LdapConfigPayload, make_event(), os_version_string(), ServerClient, ServerClientError, test_audit_buffer_debug() (+9 more)

### Community 7 - "Community 7"
Cohesion: 0.11
Nodes (20): extract_profile_username(), fallback_from_env(), lookup_account_name(), query_session_user(), query_token_identity(), resolve_console_user(), resolve_console_user_inner(), SessionIdentityError (+12 more)

### Community 8 - "Community 8"
Cohesion: 0.13
Nodes (15): ClipboardEvent, ClipboardListener, hook_procedure(), read_wide_string(), SendableHhook, test_clipboard_event_preview_length(), test_clipboard_listener_new(), test_clipboard_listener_stop() (+7 more)

### Community 9 - "Community 9"
Cohesion: 0.09
Nodes (6): event_kind_to_action(), FileAction, InterceptionEngine, is_excluded(), register_watch_paths(), test_interception_engine_default()

### Community 10 - "Community 10"
Cohesion: 0.14
Nodes (19): accept_loop(), cleanup_pipe(), client_loop(), connect_and_run(), create_pipe(), dispatch(), handle_agent_msg(), handle_client() (+11 more)

### Community 11 - "Community 11"
Cohesion: 0.15
Nodes (14): Cache, CacheEntry, CacheKey, fail_closed_response(), hash_str(), make_response(), test_cache_clear(), test_cache_insert_get() (+6 more)

### Community 12 - "Community 12"
Cohesion: 0.16
Nodes (17): AuditEmitter, AuditError, emit(), emit_audit(), EmitContext, get_application_metadata(), get_file_owner_sid(), get_process_image_path() (+9 more)

### Community 13 - "Community 13"
Cohesion: 0.08
Nodes (14): AccessContext, Action, AgentInfo, Decision, DeviceTrust, Environment, EvaluateRequest, EvaluateResponse (+6 more)

### Community 14 - "Community 14"
Cohesion: 0.13
Nodes (12): classify_text(), contains_credit_card_pattern(), contains_ssn_pattern(), ContentClassifier, PatternRule, test_classify_credit_card_dashes(), test_classify_credit_card_raw(), test_classify_empty() (+4 more)

### Community 15 - "Community 15"
Cohesion: 0.13
Nodes (8): AuditAccessContext, AuditEvent, EventType, test_audit_event_builder(), test_audit_event_serde(), test_correlation_id_always_present(), test_skip_serializing_none_fields(), test_with_application()

### Community 16 - "Community 16"
Cohesion: 0.16
Nodes (9): extract_drive_letter(), register_usb_notifications(), test_drive_letter_case_insensitive(), test_on_drive_arrival_removal(), test_should_block_non_usb_drive(), test_should_block_write_t1_t2_allowed(), test_should_block_write_t4_usb(), test_usb_detector_default() (+1 more)

### Community 17 - "Community 17"
Cohesion: 0.13
Nodes (9): content_classification(), path_classification(), PolicyMapper, test_content_classification_confidential_keyword(), test_content_classification_empty_file(), test_content_classification_nonexistent_file(), test_content_classification_plain_text(), test_content_classification_ssn() (+1 more)

### Community 18 - "Community 18"
Cohesion: 0.16
Nodes (14): AdminUsername, change_password(), ChangePasswordRequest, Claims, ensure_test_secret(), jwt_secret(), login(), LoginRequest (+6 more)

### Community 19 - "Community 19"
Cohesion: 0.14
Nodes (6): AgentConfig, test_agent_config_save_preserves_server_url(), test_agent_config_save_roundtrip(), test_load_missing_file_returns_default(), test_resolve_watch_paths_configured(), test_resolve_watch_paths_default()

### Community 20 - "Community 20"
Cohesion: 0.19
Nodes (7): close_handle(), get_current_thread(), IdentityError, IdentityResolver, test_identity_resolver_default(), test_windows_identity_to_subject(), WindowsIdentity

### Community 21 - "Community 21"
Cohesion: 0.23
Nodes (10): build_probe_request(), make_request(), make_response(), OfflineManager, test_build_probe_request(), test_offline_decision_cache_hit(), test_offline_decision_cache_miss_t1_allowed(), test_offline_decision_cache_miss_t4_denied() (+2 more)

### Community 22 - "Community 22"
Cohesion: 0.19
Nodes (10): AlertError, AlertRouter, AlertRouterConfigRow, SmtpConfig, test_alert_router_disabled_default(), test_hot_reload(), test_load_config_port_overflow(), test_load_config_roundtrip() (+2 more)

### Community 23 - "Community 23"
Cohesion: 0.25
Nodes (18): draw(), draw_agent_list(), draw_alert_config(), draw_confirm(), draw_hints(), draw_input(), draw_json_detail(), draw_menu() (+10 more)

### Community 24 - "Community 24"
Cohesion: 0.18
Nodes (9): ElkConfig, SiemConfigRow, SiemConnector, SiemError, SplunkConfig, SplunkEvent, test_new_with_in_memory_db(), test_relay_events_empty_is_noop() (+1 more)

### Community 25 - "Community 25"
Cohesion: 0.27
Nodes (15): message_count(), read_exact(), run_mock_pipe_server(), setup_pipe(), start_mock_pipe_server(), teardown_pipe(), test_confidential_triggers_t3_alert(), test_credit_card_triggers_t4_alert() (+7 more)

### Community 26 - "Community 26"
Cohesion: 0.23
Nodes (12): Config, ensure_admin_user(), extract_connect_flag(), get_flag(), load_ldap_config(), main(), parse_config(), print_help() (+4 more)

### Community 27 - "Community 27"
Cohesion: 0.24
Nodes (13): acquire_instance_mutex(), async_run_console(), config_poll_loop(), init_logging(), report_scm_status(), resolve_ui_binary(), revert_stop(), run_console() (+5 more)

### Community 28 - "Community 28"
Cohesion: 0.27
Nodes (2): EngineClient, load_identity()

### Community 29 - "Community 29"
Cohesion: 0.2
Nodes (5): EngineClient, EngineClientError, Inner, test_engine_client_default(), test_engine_client_new()

### Community 30 - "Community 30"
Cohesion: 0.22
Nodes (9): enumerate_active_sessions(), enumerate_active_sessions_pub(), get_session_user_token(), init(), kill_all(), kill_session(), SendableHandle, spawn_ui_in_session() (+1 more)

### Community 31 - "Community 31"
Cohesion: 0.24
Nodes (6): accept_loop(), Broadcaster, create_pipe(), handle_client(), pipe_mode(), serve_with_ready()

### Community 32 - "Community 32"
Cohesion: 0.26
Nodes (10): accept_loop(), create_pipe(), handle_client(), pipe_mode(), route(), Router, serve(), serve_with_ready() (+2 more)

### Community 33 - "Community 33"
Cohesion: 0.44
Nodes (11): Get-CurrentService(), Get-DlpAgentServiceStatus(), New-DlpAgentService(), Remove-DlpAgentService(), Remove-ServiceIfExists(), Start-DlpAgentService(), Stop-DlpAgentService(), Test-BinaryExists() (+3 more)

### Community 34 - "Community 34"
Cohesion: 0.18
Nodes (1): Classification

### Community 35 - "Community 35"
Cohesion: 0.18
Nodes (3): AgentInfoResponse, HeartbeatRequest, RegisterRequest

### Community 36 - "Community 36"
Cohesion: 0.25
Nodes (7): DlpApp, get_current_session_id(), install_crash_hook(), Message, run(), spawn_ipc_tasks(), UiState

### Community 37 - "Community 37"
Cohesion: 0.35
Nodes (10): align4(), build_dlgtemplate(), capture_justification(), dlg_proc(), OverrideDialogResult, push_i16(), push_u16(), push_u32() (+2 more)

### Community 38 - "Community 38"
Cohesion: 0.4
Nodes (9): Get-ServerProcess(), Show-AgentStatus(), Show-ServerStatus(), Start-Agent(), Start-Server(), Stop-Agent(), Stop-Server(), Test-ServerRunning() (+1 more)

### Community 39 - "Community 39"
Cohesion: 0.2
Nodes (6): App, ConfirmPurpose, InputPurpose, PasswordPurpose, Screen, StatusKind

### Community 40 - "Community 40"
Cohesion: 0.29
Nodes (4): make_request(), start_error_engine(), test_engine_400_no_retry(), test_engine_500_retry_exhausted()

### Community 41 - "Community 41"
Cohesion: 0.22
Nodes (4): EventCount, EventQuery, store_events_sync(), test_store_events_sync_admin_action()

### Community 42 - "Community 42"
Cohesion: 0.28
Nodes (3): addr_to_url(), probe_health(), resolve_engine_url()

### Community 43 - "Community 43"
Cohesion: 0.42
Nodes (8): init_tables(), new_pool(), test_alert_router_config_seed_row(), test_global_agent_config_seed_row(), test_idempotent_init(), test_ldap_config_seed_row(), test_new_pool_in_memory(), test_tables_created()

### Community 44 - "Community 44"
Cohesion: 0.33
Nodes (5): create_policy(), get_policy(), get_policy_versions(), list_policies(), update_policy()

### Community 45 - "Community 45"
Cohesion: 0.67
Nodes (8): assert_admin_audit_event(), mint_jwt(), seed_admin_user(), test_app(), test_password_change_emits_admin_audit_event(), test_policy_create_emits_admin_audit_event(), test_policy_delete_emits_admin_audit_event(), test_policy_update_emits_admin_audit_event()

### Community 46 - "Community 46"
Cohesion: 0.46
Nodes (5): flush(), read_exact(), read_frame(), write_all(), write_frame()

### Community 47 - "Community 47"
Cohesion: 0.25
Nodes (2): CreateExceptionRequest, Exception

### Community 48 - "Community 48"
Cohesion: 0.25
Nodes (2): PolicySyncer, SyncError

### Community 49 - "Community 49"
Cohesion: 0.33
Nodes (3): RespawnRequest, run(), start()

### Community 50 - "Community 50"
Cohesion: 0.57
Nodes (6): enumerate_active_sessions(), handle_session_end(), handle_session_start(), run(), session_loop(), start()

### Community 51 - "Community 51"
Cohesion: 0.43
Nodes (3): PipeSecurity, test_pipe_security_as_ptr_non_null(), test_pipe_security_creates_successfully()

### Community 52 - "Community 52"
Cohesion: 0.62
Nodes (6): get_ldap_config_requires_auth(), get_ldap_config_returns_defaults(), mint_admin_jwt(), put_ldap_config_rejects_cache_ttl_too_low(), put_ldap_config_updates_and_returns_new_config(), test_app()

### Community 53 - "Community 53"
Cohesion: 0.52
Nodes (5): handle_agent_msg(), open_pipe(), read_loop(), run_listener(), SendableHandle

### Community 54 - "Community 54"
Cohesion: 0.53
Nodes (4): Pipe1AgentMsg, Pipe1UiMsg, Pipe2AgentMsg, Pipe3UiMsg

### Community 55 - "Community 55"
Cohesion: 0.33
Nodes (2): AppError, AppState

### Community 56 - "Community 56"
Cohesion: 0.53
Nodes (4): classify_and_alert(), handle_clipboard_change(), run_monitor(), start()

### Community 57 - "Community 57"
Cohesion: 0.4
Nodes (2): init(), load_default_icon()

### Community 58 - "Community 58"
Cohesion: 0.7
Nodes (4): prompt_line(), prompt_password(), read_masked_input(), run()

### Community 59 - "Community 59"
Cohesion: 0.7
Nodes (4): build_deny_everyone_dacl(), harden_agent_process(), harden_process(), harden_ui_process()

### Community 60 - "Community 60"
Cohesion: 0.7
Nodes (4): open_pipe(), pipe_name(), send_clipboard_alert(), send_ui_ready()

### Community 61 - "Community 61"
Cohesion: 0.5
Nodes (0): 

### Community 62 - "Community 62"
Cohesion: 0.5
Nodes (1): BlockDialogResult

### Community 63 - "Community 63"
Cohesion: 0.67
Nodes (1): AppEvent

### Community 64 - "Community 64"
Cohesion: 1.0
Nodes (2): main(), write_ico()

### Community 65 - "Community 65"
Cohesion: 0.67
Nodes (0): 

### Community 66 - "Community 66"
Cohesion: 0.67
Nodes (0): 

### Community 67 - "Community 67"
Cohesion: 1.0
Nodes (0): 

### Community 68 - "Community 68"
Cohesion: 1.0
Nodes (0): 

### Community 69 - "Community 69"
Cohesion: 1.0
Nodes (0): 

### Community 70 - "Community 70"
Cohesion: 1.0
Nodes (0): 

### Community 71 - "Community 71"
Cohesion: 1.0
Nodes (0): 

### Community 72 - "Community 72"
Cohesion: 1.0
Nodes (0): 

### Community 73 - "Community 73"
Cohesion: 1.0
Nodes (0): 

### Community 74 - "Community 74"
Cohesion: 1.0
Nodes (0): 

### Community 75 - "Community 75"
Cohesion: 1.0
Nodes (0): 

### Community 76 - "Community 76"
Cohesion: 1.0
Nodes (0): 

### Community 77 - "Community 77"
Cohesion: 1.0
Nodes (0): 

### Community 78 - "Community 78"
Cohesion: 1.0
Nodes (0): 

### Community 79 - "Community 79"
Cohesion: 1.0
Nodes (0): 

### Community 80 - "Community 80"
Cohesion: 1.0
Nodes (0): 

### Community 81 - "Community 81"
Cohesion: 1.0
Nodes (0): 

## Knowledge Gaps
- **69 isolated node(s):** `StatusKind`, `InputPurpose`, `ConfirmPurpose`, `PasswordPurpose`, `Screen` (+64 more)
  These have ≤1 connection - possible missing edges or undocumented components.
- **Thin community `Community 67`** (2 nodes): `registry.rs`, `read_registry_string()`
  Too small to be a meaningful cluster - may be noise or needs more connections extracted.
- **Thin community `Community 68`** (2 nodes): `mod.rs`, `run_event_loop()`
  Too small to be a meaningful cluster - may be noise or needs more connections extracted.
- **Thin community `Community 69`** (2 nodes): `server.rs`, `start_all()`
  Too small to be a meaningful cluster - may be noise or needs more connections extracted.
- **Thin community `Community 70`** (2 nodes): `notifications.rs`, `show_toast()`
  Too small to be a meaningful cluster - may be noise or needs more connections extracted.
- **Thin community `Community 71`** (2 nodes): `read_clipboard()`, `clipboard.rs`
  Too small to be a meaningful cluster - may be noise or needs more connections extracted.
- **Thin community `Community 72`** (1 nodes): `fix_admin_api.py`
  Too small to be a meaningful cluster - may be noise or needs more connections extracted.
- **Thin community `Community 73`** (1 nodes): `update_plan.py`
  Too small to be a meaningful cluster - may be noise or needs more connections extracted.
- **Thin community `Community 74`** (1 nodes): `write_db_rs.py`
  Too small to be a meaningful cluster - may be noise or needs more connections extracted.
- **Thin community `Community 75`** (1 nodes): `mod.rs`
  Too small to be a meaningful cluster - may be noise or needs more connections extracted.
- **Thin community `Community 76`** (1 nodes): `lib.rs`
  Too small to be a meaningful cluster - may be noise or needs more connections extracted.
- **Thin community `Community 77`** (1 nodes): `mod.rs`
  Too small to be a meaningful cluster - may be noise or needs more connections extracted.
- **Thin community `Community 78`** (1 nodes): `mod.rs`
  Too small to be a meaningful cluster - may be noise or needs more connections extracted.
- **Thin community `Community 79`** (1 nodes): `mod.rs`
  Too small to be a meaningful cluster - may be noise or needs more connections extracted.
- **Thin community `Community 80`** (1 nodes): `lib.rs`
  Too small to be a meaningful cluster - may be noise or needs more connections extracted.
- **Thin community `Community 81`** (1 nodes): `mod.rs`
  Too small to be a meaningful cluster - may be noise or needs more connections extracted.

## Suggested Questions
_Questions this graph is uniquely positioned to answer:_

- **What connects `StatusKind`, `InputPurpose`, `ConfirmPurpose` to the rest of the system?**
  _69 weakly-connected nodes found - possible documentation gaps or missing edges._
- **Should `Community 0` be split into smaller, more focused modules?**
  _Cohesion score 0.01 - nodes in this community are weakly interconnected._
- **Should `Community 1` be split into smaller, more focused modules?**
  _Cohesion score 0.04 - nodes in this community are weakly interconnected._
- **Should `Community 2` be split into smaller, more focused modules?**
  _Cohesion score 0.05 - nodes in this community are weakly interconnected._
- **Should `Community 3` be split into smaller, more focused modules?**
  _Cohesion score 0.09 - nodes in this community are weakly interconnected._
- **Should `Community 4` be split into smaller, more focused modules?**
  _Cohesion score 0.08 - nodes in this community are weakly interconnected._
- **Should `Community 5` be split into smaller, more focused modules?**
  _Cohesion score 0.11 - nodes in this community are weakly interconnected._