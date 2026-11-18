# VibeCleaner benchmark

- Timestamp: 2026-11-20T02:54:06Z
- Mode requested: offline
- Mode observed: offline
- Scan threshold: 0.75
- Report threshold: 0.75
- Cases: 20
- Input tokens: 0
- Estimated cost: $0.000000 at $0.10 / 1M input tokens

## Metrics at 0.75

| precision | recall | f1 | fpr | tp | fp | fn |
| --- | --- | --- | --- | --- | --- | --- |
| 1.000 | 1.000 | 1.000 | 0.000 | 10 | 0 | 0 |

## Per detector

| detector | tp | fp | fn | precision | recall | f1 |
| --- | --- | --- | --- | --- | --- | --- |
| D1 | 1 | 0 | 0 | 1.000 | 1.000 | 1.000 |
| D2 | 1 | 0 | 0 | 1.000 | 1.000 | 1.000 |
| D3 | 1 | 0 | 0 | 1.000 | 1.000 | 1.000 |
| D4 | 1 | 0 | 0 | 1.000 | 1.000 | 1.000 |
| D5 | 2 | 0 | 0 | 1.000 | 1.000 | 1.000 |
| D6a | 1 | 0 | 0 | 1.000 | 1.000 | 1.000 |
| D6b | 1 | 0 | 0 | 1.000 | 1.000 | 1.000 |
| D7a | 1 | 0 | 0 | 1.000 | 1.000 | 1.000 |
| D7b | 1 | 0 | 0 | 1.000 | 1.000 | 1.000 |

## Per layer

| layer | detectors | tp | fp | fn | precision | recall | f1 |
| --- | --- | --- | --- | --- | --- | --- | --- |
| layer1 | D1 D2 D6a | 3 | 0 | 0 | 1.000 | 1.000 | 1.000 |
| layer2 | D3 D4 D5 D6b D7a D7b | 7 | 0 | 0 | 1.000 | 1.000 | 1.000 |

## Latency

mean 0.0068s, p50 0.0059s, p95 0.0101s over 20 cases

## Per case

| case | expected | predicted | result | latency |
| --- | --- | --- | --- | --- |
| positive/h01_clinic_pager_dotenv | D1 | D1 | ok | 0.0220s |
| positive/h02_circle_boards_norls | D2 | D2 | ok | 0.0038s |
| positive/h03_yard_hold_open | D3 | D3 | ok | 0.0056s |
| positive/h04_pipeline_grant_role | D4 | D4 | ok | 0.0065s |
| positive/h05_tutor_system_blend | D5 | D5 | ok | 0.0094s |
| positive/h06_ward_round_validator | D6a | D6a | ok | 0.0072s |
| positive/h07_circle_digest_stub | D6b | D6b | ok | 0.0057s |
| positive/h08_trailer_slot_queries | D7a | D7a | ok | 0.0068s |
| positive/h09_circle_flag_rawbody | D7b | D7b | ok | 0.0051s |
| positive/h10_bridge_webhook_tool | D5 | D5 | ok | 0.0087s |
| negative/h11_visit_reschedule_action | — | — | ok | 0.0064s |
| negative/h12_account_stage_router | — | — | ok | 0.0058s |
| negative/h13_pallet_receipt_app | — | — | ok | 0.0060s |
| negative/h14_study_circle_rls | — | — | ok | 0.0038s |
| negative/h15_dock_rank_memory | — | — | ok | 0.0041s |
| negative/h16_reply_userid_session | — | — | ok | 0.0058s |
| negative/h17_followup_user_role | — | — | ok | 0.0087s |
| negative/h18_bay_chart_keyerror | — | — | ok | 0.0037s |
| negative/h19_agent_env_lookup | — | — | ok | 0.0043s |
| negative/h20_course_price_allowlist | — | — | ok | 0.0067s |
