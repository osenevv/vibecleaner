# VibeCleaner benchmark

- Timestamp: 2026-11-20T02:28:31Z
- Mode requested: offline
- Mode observed: offline
- Scan threshold: 0.75
- Report threshold: 0.75
- Cases: 24
- Input tokens: 0
- Estimated cost: $0.000000 at $0.10 / 1M input tokens

## Metrics at 0.75

| precision | recall | f1 | fpr | tp | fp | fn |
| --- | --- | --- | --- | --- | --- | --- |
| 0.600 | 0.750 | 0.667 | 0.250 | 9 | 6 | 3 |

## Per detector

| detector | tp | fp | fn | precision | recall | f1 |
| --- | --- | --- | --- | --- | --- | --- |
| D1 | 1 | 0 | 0 | 1.000 | 1.000 | 1.000 |
| D2 | 1 | 0 | 0 | 1.000 | 1.000 | 1.000 |
| D3 | 2 | 4 | 0 | 0.333 | 1.000 | 0.500 |
| D4 | 1 | 0 | 1 | 1.000 | 0.500 | 0.667 |
| D5 | 1 | 0 | 1 | 1.000 | 0.500 | 0.667 |
| D6a | 1 | 0 | 0 | 1.000 | 1.000 | 1.000 |
| D6b | 1 | 0 | 0 | 1.000 | 1.000 | 1.000 |
| D7a | 1 | 2 | 0 | 0.333 | 1.000 | 0.500 |
| D7b | 0 | 0 | 1 | n/a | 0.000 | n/a |

## Per layer

| layer | detectors | tp | fp | fn | precision | recall | f1 |
| --- | --- | --- | --- | --- | --- | --- | --- |
| layer1 | D1 D2 D6a | 3 | 0 | 0 | 1.000 | 1.000 | 1.000 |
| layer2 | D3 D4 D5 D6b D7a D7b | 6 | 6 | 3 | 0.500 | 0.667 | 0.571 |

## Latency

mean 0.0106s, p50 0.0085s, p95 0.0123s over 24 cases

## Per case

| case | expected | predicted | result | latency |
| --- | --- | --- | --- | --- |
| positive/b01_vet_pager_dotenv | D1 | D1 | ok | 0.0562s |
| positive/b02_podcast_show_rls | D2 | D2 | ok | 0.0042s |
| positive/b03_cafeteria_blackout_post | D3 | D3 | ok | 0.0088s |
| positive/b04_meter_settlement_open | D3 | D3 | ok | 0.0115s |
| positive/b05_listing_org_query | D4 | D7a | FP D7a; FN D4 | 0.0076s |
| positive/b06_club_dues_amount | D4 | D4 | ok | 0.0124s |
| positive/b07_matter_standing_prompt | D5 | — | FN D5 | 0.0113s |
| positive/b08_tote_shell_tool | D5 | D3,D5 | FP D3 | 0.0103s |
| positive/b09_hire_validator_legacy | D6a | D6a | ok | 0.0086s |
| positive/b10_ferry_quote_stub | D6b | D3,D6b | FP D3 | 0.0067s |
| positive/b11_squad_promise_fanout | D7a | D7a | ok | 0.0074s |
| positive/b12_donor_note_rawbody | D7b | — | FN D7b | 0.0076s |
| negative/b01_vet_dispense_router | — | — | ok | 0.0119s |
| negative/b02_matter_middleware | — | — | ok | 0.0069s |
| negative/b03_meter_session_match | — | — | ok | 0.0080s |
| negative/b04_contest_fee_catalog | — | D3 | FP D3 | 0.0082s |
| negative/b05_itinerary_user_role | — | — | ok | 0.0085s |
| negative/b06_bay_allowlist_tool | — | D3 | FP D3 | 0.0119s |
| negative/b07_episode_batch_page | — | D7a | FP D7a | 0.0105s |
| negative/b08_pledge_timeout_log | — | — | ok | 0.0108s |
| negative/b09_brokerage_fee_table | — | — | ok | 0.0058s |
| negative/b10_hire_packet_rls | — | — | ok | 0.0050s |
| negative/b11_lunch_env_example | — | — | ok | 0.0051s |
| negative/b12_membership_freeze_gate | — | — | ok | 0.0089s |
