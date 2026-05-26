# Extension: Microsoft Sentinel as a 5th Ruleset

This directory contains the original contribution of this project: extending Virkud et al.'s 4-ruleset ATT&CK coverage analysis with Microsoft Sentinel.

## Module Structure

| File | Role |
|---|---|
| `notebooks/sentinel_adapter.py` | Loads Microsoft Sentinel CSV; filters (Analytics only, dedupe by DetectionId, drop null TechniqueId); produces a DataFrame structurally compatible with Virkud et al.'s `splunk` / `elastic` / `sigma` DataFrames. Also provides analysis helpers. |
| `notebooks/virkud_loader.py` | Wraps the data-loading logic from Virkud et al.'s original RQ1 notebook into reusable functions. Includes the `np.NaN`→`np.nan` patch (NumPy 2.0 compatibility). |
| `notebooks/sentinel_rq1_analysis.ipynb` | Clean analysis notebook that imports both modules, loads all 5 rulesets, and runs the three core analyses. |
| `outputs/coverage_summary.csv` | Per-ruleset technique coverage stats. |
| `outputs/hypothesis_test.csv` | Per-technique rule counts for pre-registered hypothesis test. |
| `outputs/sentinel_unique_techniques.txt` | Techniques covered by Sentinel but not by Splunk/Elastic (and vice versa). |
| `sentinel_data/MicrosoftSentinel.csv` | Microsoft Sentinel ATT&CK detection feed (snapshot dated 2022-08-07). |

## Pre-Registered Hypothesis

Before any analysis was conducted, this work pre-registered the following hypothesis:

> Microsoft Sentinel, as a cloud-native SIEM with strong identity and cloud-workload focus, will show measurably higher coverage of techniques relevant to cloud and identity attack chains (T1078, T1098, T1530, T1110) than the three on-host EDR products in the original paper, and may show comparable or lower coverage of techniques requiring on-host telemetry (T1547, T1543, T1574, T1055).

**Result:** Confirmed at high magnitude. See main [README](../README.md#quick-results) for headline numbers.