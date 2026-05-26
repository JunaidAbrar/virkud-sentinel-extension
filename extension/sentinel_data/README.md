# Microsoft Sentinel ATT&CK Feed

The file `MicrosoftSentinel.csv` in this directory is a public ATT&CK-tagged feed of Microsoft Sentinel detection rules, published by the Microsoft Threat Intelligence Center (MSTIC).

## Source

- **Original URL**: https://github.com/microsoft/mstic/blob/master/PublicFeeds/MITREATT%26CK/MicrosoftSentinel.csv
- **Raw URL**: https://raw.githubusercontent.com/microsoft/mstic/master/PublicFeeds/MITREATT%26CK/MicrosoftSentinel.csv
- **Snapshot date**: 2022-08-07 (the `IngestedDate` field on every row in the file)
- **Size**: ~23 MB, 10,132 rows × 18 columns

## Schema

| Column | Description |
|---|---|
| `Tactic` | ATT&CK tactic (e.g., InitialAccess, Persistence) |
| `TechniqueId` | ATT&CK technique ID (e.g., T1078, T1190) |
| `Platform` | Target platform (Azure, Azure AD, AWS, Windows, Linux, etc.) |
| `DetectionType` | Analytics / Hunting / Fusion |
| `DetectionService` | Source feed (Azure Sentinel Community Github, Microsoft Sentinel Fusion, Microsoft Built-in Alerts) |
| `DetectionId` | UUID for the rule |
| `DetectionName` | Human-readable rule name |
| `DetectionDescription` | Rule description |
| `Query` | KQL detection query |
| `DetectionSeverity` | Low / Medium / High / Informational |
| ... | Additional metadata fields |

## Filtering Applied by `sentinel_adapter.py`

1. **`DetectionType == 'Analytics'`** — drops Hunting queries and Fusion correlations to match Virkud et al.'s "rule" definition
2. **Deduplicate by `DetectionId`** — same rule appears once per supported platform; we keep one row per unique rule
3. **Drop rows with null or 'N.A.' `TechniqueId`**
4. **Apply parent-technique aggregation** — `T1003.001` → `T1003` to match Virkud et al.'s `drop_subtechniques()` convention

After filtering: 10,132 raw rows → **349 unique Analytics rules** covering 81 unique parent techniques (41.4% of ATT&CK v11).

## Licensing

The Microsoft Sentinel CSV is published by Microsoft and is subject to Microsoft's licensing terms. See the [microsoft/mstic repository](https://github.com/microsoft/mstic) for current terms. It is included in this repository for reproducibility convenience; the canonical source is the URL above.