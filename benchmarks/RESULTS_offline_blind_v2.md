# VibeGuard benchmark

- Timestamp: 2026-11-20T12:29:29Z
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
| 1.000 | 1.000 | 1.000 | 0.000 | 12 | 0 | 0 |

FPR is the share of clean cases with a finding from a labeled detector (D1, D2, D3, D4, D5, D6a, D6b, D7a, D7b). Detectors outside that set are listed separately and do not move precision, recall, or FPR.

## Per detector

| detector | tp | fp | fn | precision | recall | f1 |
| --- | --- | --- | --- | --- | --- | --- |
| D1 | 1 | 0 | 0 | 1.000 | 1.000 | 1.000 |
| D2 | 1 | 0 | 0 | 1.000 | 1.000 | 1.000 |
| D3 | 2 | 0 | 0 | 1.000 | 1.000 | 1.000 |
| D4 | 2 | 0 | 0 | 1.000 | 1.000 | 1.000 |
| D5 | 2 | 0 | 0 | 1.000 | 1.000 | 1.000 |
| D6a | 1 | 0 | 0 | 1.000 | 1.000 | 1.000 |
| D6b | 1 | 0 | 0 | 1.000 | 1.000 | 1.000 |
| D7a | 1 | 0 | 0 | 1.000 | 1.000 | 1.000 |
| D7b | 1 | 0 | 0 | 1.000 | 1.000 | 1.000 |

## Per layer

| layer | detectors | tp | fp | fn | precision | recall | f1 |
| --- | --- | --- | --- | --- | --- | --- | --- |
| layer1 | D1 D2 D6a | 3 | 0 | 0 | 1.000 | 1.000 | 1.000 |
| layer2 | D3 D4 D5 D6b D7a D7b | 9 | 0 | 0 | 1.000 | 1.000 | 1.000 |

## Unscored detectors

These detectors are outside the label set. Their hits are listed here and do not count toward precision, recall, or FPR:

- D9: 1 case(s)

## Latency

mean 0.0626s, p50 0.0618s, p95 0.0780s over 24 cases

## Per case

| case | expected | predicted | result | latency |
| --- | --- | --- | --- | --- |
| positive/b01_vet_pager_dotenv | D1 | D1 | ok | 0.0596s |
| positive/b02_podcast_show_rls | D2 | D2 | ok | 0.0455s |
| positive/b03_cafeteria_blackout_post | D3 | D3 | ok | 0.0597s |
| positive/b04_meter_settlement_open | D3 | D3 | ok | 0.0706s |
| positive/b05_listing_org_query | D4 | D4 | ok | 0.0606s |
| positive/b06_club_dues_amount | D4 | D4 | ok | 0.0680s |
| positive/b07_matter_standing_prompt | D5 | D5 | ok | 0.0627s |
| positive/b08_tote_shell_tool | D5 | D5 | ok | 0.0599s |
| positive/b09_hire_validator_legacy | D6a | D6a | ok | 0.0757s |
| positive/b10_ferry_quote_stub | D6b | D6b | ok | 0.0834s |
| positive/b11_squad_promise_fanout | D7a | D7a | ok | 0.0658s |
| positive/b12_donor_note_rawbody | D7b | D7b | ok | 0.0655s |
| negative/b01_vet_dispense_router | — | — | ok | 0.0783s |
| negative/b02_matter_middleware | — | — | ok | 0.0601s |
| negative/b03_meter_session_match | — | — | ok | 0.0611s |
| negative/b04_contest_fee_catalog | — | — | ok | 0.0616s |
| negative/b05_itinerary_user_role | — | — | ok | 0.0622s |
| negative/b06_bay_allowlist_tool | — | — | ok | 0.0621s |
| negative/b07_episode_batch_page | — | — | ok | 0.0675s |
| negative/b08_pledge_timeout_log | — | — | ok | 0.0677s |
| negative/b09_brokerage_fee_table | — | — | ok | 0.0507s |
| negative/b10_hire_packet_rls | — | — | ok | 0.0457s |
| negative/b11_lunch_env_example | — | — | ok | 0.0488s |
| negative/b12_membership_freeze_gate | — | — | ok | 0.0606s |
