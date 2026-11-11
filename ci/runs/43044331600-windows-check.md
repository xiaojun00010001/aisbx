# CI run 43044331600 (windows-check)

- commit: 398d3d59f487b3b7ca0f2064a813116485917218
- job status: success

```text
    Checking aisbx-policy v0.1.0 (D:\a\aisbx\aisbx\crates\aisbx-policy)
    Checking aisbx v0.1.0 (D:\a\aisbx\aisbx\crates\aisbx)
    Finished `dev` profile [unoptimized + debuginfo] target(s) in 0.78s
   Compiling aisbx-policy v0.1.0 (D:\a\aisbx\aisbx\crates\aisbx-policy)
   Compiling aisbx v0.1.0 (D:\a\aisbx\aisbx\crates\aisbx)
    Finished `test` profile [unoptimized + debuginfo] target(s) in 1.46s
     Running unittests src\main.rs (target\debug\deps\aisbx-d6f059a4e892c04f.exe)

running 18 tests
test capabilities::tests::top_level_shape_is_identical ... ok
test capabilities::tests::status_capability_values_are_legal ... ok
test common::stderr_scan::tests::distinguishes_access_kind_by_heuristic ... ok
test capabilities::tests::capability_keys_match_the_shared_contract ... ok
test common::stderr_scan::tests::extracts_dotnet_unauthorized_path ... ok
test common::stderr_scan::tests::extracts_powershell_denied_path ... ok
test common::stderr_scan::tests::extracts_python_quoted_path ... ok
test common::stderr_scan::tests::extracts_shell_style_path ... ok
test common::stderr_scan::tests::extracts_touch_style_path ... ok
test common::stderr_scan::tests::extracts_windows_python_denied_path ... ok
test common::stderr_scan::tests::filters_system_noise ... ok
test common::stderr_scan::tests::ignores_lines_without_denial_semantics ... ok
test common::stderr_scan::tests::filters_windows_system_noise ... ok
test common::stderr_scan::tests::keeps_user_paths_under_var_folders ... ok
test common::stderr_scan::tests::recognises_windows_absolute_paths ... ok
test common::stderr_scan::tests::recognizes_readonly_filesystem_denial ... ok
test common::stderr_scan::tests::rust_style_error_has_no_path ... ok
test common::stderr_scan::tests::still_filters_toolchain_cache_under_var_folders ... ok

test result: ok. 18 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out; finished in 0.00s

     Running unittests src\lib.rs (target\debug\deps\aisbx_policy-b85715c543d11a2d.exe)

running 8 tests
test tests::pipe_name_override ... ok
test tests::escalation_modes ... ok
test tests::parse_minimal ... ok
test tests::parse_full_contract ... ok
test tests::reject_bad_cpu_and_zero_procs ... ok
test tests::reject_bad_task ... ok
test tests::violation_capture_defaults_off ... ok
test tests::reject_unknown_fields ... ok

test result: ok. 8 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out; finished in 0.00s

   Doc-tests aisbx_policy

running 0 tests

test result: ok. 0 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out; finished in 0.00s

```
