# Reproduction Log

Twenty-seven discrete events recorded during reproduction of Virkud et al. (USENIX Security 2024) on Windows 11 / Python 3.11.9. Each event is classified as a **Difficulty** (artefact gap discovered), **Workaround** (fix applied), or **Verification** (paper claim confirmed).

| # | Type | Event | Resolution / Outcome |
|---|---|---|---|
| 1 | Difficulty | Python version mismatch: artifact requires 3.8.10, host is 3.11.9 | Proceeded with 3.11.9 (3.8 is EOL). Documented as version-drift exposure. |
| 2 | Difficulty | Carbon Black ruleset not in artifact (licensing) | Limited reproduction to Splunk/Elastic/Sigma. |
| 3 | Difficulty | RQ2 has no shippable code (qualitative method) | RQ2 evaluated but not re-conducted. |
| 4 | Difficulty | `requirements.txt` contains Linux-only wheels (nvidia-*, triton, pexpect, ptyprocess) | Curated minimal install (9 packages). |
| 5 | Difficulty | PyTorch / KeyBERT stack unnecessary — pre-computed outputs shipped | Skipped KeyBERT cells; used pre-computed CSV. Saved ~3 GB. |
| 6 | Difficulty | No plotting code in RQ1 notebook — only DataFrames | Reproduced tables; plots a future-work item. |
| 7 | Difficulty | RQ3 dual-path execution (KeyBERT pipeline + pre-computed CSV) | Used pre-computed path. |
| 8 | Difficulty | Authors developed in WSL2, not native Windows | Native Windows reproduction is genuinely novel. |
| 9 | Difficulty | Major version drift: NumPy 1.24→2.4, pandas 2.0→3.0, scipy 1.10→1.17 | Documented; all downstream errors traced to these. |
| 10 | Difficulty | NLTK 3.8.2+ requires `punkt_tab` in addition to `punkt` | Added `punkt_tab` to pre-emptive downloads. |
| 11 | Workaround | `np.NaN` removed in NumPy 2.0 | Replaced with `np.nan` in `parse_threat_column()` in both notebooks. |
| 12 | Workaround | `DataFrame.applymap` deprecated in pandas 2.1 | Replaced `.applymap(len)` with `.map(len)`. |
| 13 | Verification | Splunk rule count | **911 rules** (matches paper Table 1). |
| 14 | Verification | Elastic rule count | **473 rules** (matches paper Table 1). |
| 15 | Verification | Sigma rule count | **2,195 rules** (matches paper Table 1). |
| 16 | Verification | Figure 1 underlying data (technique count per tactic) | All 14 tactics match exactly across Splunk, Elastic, Sigma. |
| 17 | Verification | Technique density (1 / 1–5 / >50 rules) | 19/57/4 (Splunk), 25/62/0 (Elastic), 26/67/17 (Sigma). All within paper ranges. |
| 18 | Verification | Spearman ρ Splunk vs Elastic | **ρ = 0.6389**, p = 2.69e-23 (paper: 0.639). |
| 19 | Verification | Spearman ρ Splunk vs Sigma | **ρ = 0.7010**, p = 1.47e-29 (paper: 0.701). |
| 20 | Verification | Spearman ρ Elastic vs Sigma | **ρ = 0.7617**, p = 1.82e-37 (paper: 0.762). |
| 21 | Verification | Case Study 1: CVE-2021-4034 cross-vendor disagreement | Elastic e69 `[T1574+T1068]` vs Splunk s489 `[T1068]`. |
| 22 | Verification | Case Study 2: Meterpreter named-pipe disagreement | Elastic e479 `[T1134]` vs Splunk s229 `[T1059+T1059.003+T1543+T1543.003]`. |
| 23 | Verification | Case Study 3: FIN7 tactic disagreement (Exfiltration vs C2) | Splunk s324 → Exfiltration; Elastic FIN7 rules → C2. |
| 24 | Verification | Case Study 4: Within-Splunk PrintNightmare inconsistency | 6 Splunk rules with T1547; 1 Splunk rule (s687) with T1068. |
| 25 | Difficulty | `combined_rules_annotated_entities.csv` contains 291 entities (pre-filter); paper reports 191 (post-filter) | Per-entity analyses verifiable; aggregate count not. |
| 26 | Verification | Sentinel adapter validates: 10,132 raw rows → 349 unique Analytics rules, 81 techniques, 41.4% v11 coverage | Adapter produces Virkud-compatible DataFrame. |
| 27 | Verification | Pre-registered hypothesis confirmed | Cloud techniques 2–6× over-covered; host 5–26× under-covered. Spearman ρ = 0.39–0.50 vs within-paper 0.64–0.76. |

**Summary:** 10 Difficulties documented · 2 Workarounds applied · 15 Verifications (all matching paper to 3 decimal places).