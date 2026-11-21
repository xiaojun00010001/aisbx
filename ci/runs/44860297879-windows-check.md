# CI run 44860297879 (windows-check)

- commit: 4e4a1bc4beb389fcfea6414b1a038cb65defd8bf
- job status: success

```text
    Checking aisbx-protocol v0.1.0 (D:\a\aisbx\aisbx\crates\aisbx-protocol)
    Checking aisbx-policy v0.1.0 (D:\a\aisbx\aisbx\crates\aisbx-policy)
    Checking aisbx v0.1.0 (D:\a\aisbx\aisbx\crates\aisbx)
    Finished `dev` profile [unoptimized + debuginfo] target(s) in 1.36s
   Compiling aisbx-policy v0.1.0 (D:\a\aisbx\aisbx\crates\aisbx-policy)
   Compiling aisbx-protocol v0.1.0 (D:\a\aisbx\aisbx\crates\aisbx-protocol)
   Compiling aisbx v0.1.0 (D:\a\aisbx\aisbx\crates\aisbx)
    Finished `test` profile [unoptimized + debuginfo] target(s) in 1.50s
     Running unittests src\main.rs (target\debug\deps\aisbx-1daf49f899338031.exe)

running 20 tests
test backend::tests::net_escalation_capability_is_explicit ... ok
test backend::tests::backend_name_is_stable ... ok
test capabilities::tests::status_capability_values_are_legal ... ok
test capabilities::tests::capability_keys_match_the_shared_contract ... ok
test capabilities::tests::top_level_shape_is_identical ... ok
test common::stderr_scan::tests::distinguishes_access_kind_by_heuristic ... ok
test common::stderr_scan::tests::extracts_dotnet_unauthorized_path ... ok
test common::stderr_scan::tests::extracts_powershell_denied_path ... ok
test common::stderr_scan::tests::extracts_python_quoted_path ... ok
test common::stderr_scan::tests::extracts_shell_style_path ... ok
test common::stderr_scan::tests::extracts_touch_style_path ... ok
test common::stderr_scan::tests::extracts_windows_python_denied_path ... ok
test common::stderr_scan::tests::filters_system_noise ... ok
test common::stderr_scan::tests::filters_windows_system_noise ... ok
test common::stderr_scan::tests::ignores_lines_without_denial_semantics ... ok
test common::stderr_scan::tests::keeps_user_paths_under_var_folders ... ok
test common::stderr_scan::tests::recognises_windows_absolute_paths ... ok
test common::stderr_scan::tests::recognizes_readonly_filesystem_denial ... ok
test common::stderr_scan::tests::rust_style_error_has_no_path ... ok
test common::stderr_scan::tests::still_filters_toolchain_cache_under_var_folders ... ok

test result: ok. 20 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out; finished in 0.00s

     Running unittests src\lib.rs (target\debug\deps\aisbx_policy-b85715c543d11a2d.exe)

running 8 tests
test tests::parse_minimal ... ok
test tests::escalation_modes ... ok
test tests::pipe_name_override ... ok
test tests::parse_full_contract ... ok
test tests::reject_bad_cpu_and_zero_procs ... ok
test tests::reject_bad_task ... ok
test tests::reject_unknown_fields ... ok
test tests::violation_capture_defaults_off ... ok

test result: ok. 8 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out; finished in 0.00s

     Running unittests src\lib.rs (target\debug\deps\aisbx_protocol-d552c43253fa6228.exe)

running 10 tests
test tests::capability_groups_missing_keys_are_unavailable ... ok
test tests::decision_semantics ... ok
test tests::capabilities_level_and_require_full ... ok
test tests::capability_groups_from_flat_keys ... ok
test tests::escalation_request_roundtrip ... ok
test tests::grant_from_pending_file_and_net ... ok
test tests::status_roundtrip_file_pending ... ok
test tests::status_roundtrip_net_pending ... ok
test tests::unattributed_pending_is_not_actionable ... ok
test tests::unknown_kind_is_not_actionable ... ok

test result: ok. 10 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out; finished in 0.00s

   Doc-tests aisbx_policy

running 0 tests

test result: ok. 0 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out; finished in 0.00s

   Doc-tests aisbx_protocol

running 0 tests

test result: ok. 0 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out; finished in 0.00s

```
