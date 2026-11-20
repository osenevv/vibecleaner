# VibeGuard benchmark

- Timestamp: 2026-11-20T01:17:43Z
- Mode requested: offline
- Mode observed: offline
- Scan threshold: 0.75
- Report threshold: 0.75
- Cases: 30
- Input tokens: 0
- Estimated cost: $0.000000 at $0.10 / 1M input tokens

## Metrics at 0.75

| precision | recall | f1 | fpr | tp | fp | fn |
| --- | --- | --- | --- | --- | --- | --- |
| 1.000 | 1.000 | 1.000 | 0.000 | 15 | 0 | 0 |

## Per detector

| detector | tp | fp | fn | precision | recall | f1 |
| --- | --- | --- | --- | --- | --- | --- |
| D1 | 2 | 0 | 0 | 1.000 | 1.000 | 1.000 |
| D2 | 2 | 0 | 0 | 1.000 | 1.000 | 1.000 |
| D3 | 2 | 0 | 0 | 1.000 | 1.000 | 1.000 |
| D4 | 2 | 0 | 0 | 1.000 | 1.000 | 1.000 |
| D5 | 2 | 0 | 0 | 1.000 | 1.000 | 1.000 |
| D6a | 2 | 0 | 0 | 1.000 | 1.000 | 1.000 |
| D6b | 1 | 0 | 0 | 1.000 | 1.000 | 1.000 |
| D7a | 1 | 0 | 0 | 1.000 | 1.000 | 1.000 |
| D7b | 1 | 0 | 0 | 1.000 | 1.000 | 1.000 |

## Per layer

| layer | detectors | tp | fp | fn | precision | recall | f1 |
| --- | --- | --- | --- | --- | --- | --- | --- |
| layer1 | D1 D2 D6a | 6 | 0 | 0 | 1.000 | 1.000 | 1.000 |
| layer2 | D3 D4 D5 D6b D7a D7b | 9 | 0 | 0 | 1.000 | 1.000 | 1.000 |

## Latency

mean 0.0116s, p50 0.0075s, p95 0.0352s over 30 cases

## Per case

| case | expected | predicted | result | latency |
| --- | --- | --- | --- | --- |
| positive/p01_dotenv_secrets | D1 | D1 | ok | 0.0241s |
| positive/p02_source_secrets | D1 | D1 | ok | 0.0071s |
| positive/p03_migration_rls_gaps | D2 | D2 | ok | 0.0040s |
| positive/p04_cors_wildcard_credentials | D2 | D2 | ok | 0.0095s |
| positive/p05_unauth_refund | D3 | D3 | ok | 0.0072s |
| positive/p06_unauth_invite | D3 | D3 | ok | 0.0047s |
| positive/p07_idor_body_user | D4 | D4 | ok | 0.0095s |
| positive/p08_client_price_checkout | D4 | D4 | ok | 0.0067s |
| positive/p09_system_prompt_concat | D5 | D5 | ok | 0.0076s |
| positive/p10_unbounded_shell_tool | D5 | D5 | ok | 0.0068s |
| positive/p11_silent_exception | D6a | D6a | ok | 0.0123s |
| positive/p12_god_billing_module | D6a | D6a | ok | 0.0776s |
| positive/p13_stubbed_shipping_quote | D6b | D6b | ok | 0.0061s |
| positive/p14_n_plus_one_orders | D7a | D7a | ok | 0.0085s |
| positive/p15_raw_json_body | D7b | D7b | ok | 0.0054s |
| negative/n01_router_level_auth | — | — | ok | 0.0089s |
| negative/n02_middleware_matcher | — | — | ok | 0.0075s |
| negative/n03_logged_value_error | — | — | ok | 0.0080s |
| negative/n04_catch_log_rethrow | — | — | ok | 0.0060s |
| negative/n05_publishable_keys | — | — | ok | 0.0036s |
| negative/n06_env_example | — | — | ok | 0.0048s |
| negative/n07_rls_later_migration | — | — | ok | 0.0049s |
| negative/n08_cors_allowlist | — | — | ok | 0.0070s |
| negative/n09_session_owner_check | — | — | ok | 0.0088s |
| negative/n10_server_price_lookup | — | — | ok | 0.0093s |
| negative/n11_guarded_agent | — | — | ok | 0.0117s |
| negative/n12_batched_pagination | — | — | ok | 0.0099s |
| negative/n13_schema_validated_body | — | — | ok | 0.0100s |
| negative/n14_config_enums_and_tests | — | — | ok | 0.0057s |
| negative/n15_cohesive_rate_table | — | — | ok | 0.0443s |
