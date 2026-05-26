# Reproduction of Virkud et al. (USENIX Security 2024)

This directory contains patched versions of Virkud et al.'s original RQ1 and RQ3 analysis notebooks. The originals are at [github.com/avirkud/endpoint-detection-mitreattack](https://github.com/avirkud/endpoint-detection-mitreattack) (release `sec24-ae-final`).

## What's Patched

Two patches were applied to make the notebooks run on Python 3.11.9 with current pandas / NumPy versions:

1. **`np.NaN` → `np.nan`** (in `parse_threat_column()`) — `np.NaN` was removed in NumPy 2.0 (June 2024). The lowercase `np.nan` works in all NumPy versions.
2. **`.applymap(len)` → `.map(len)`** — `DataFrame.applymap` was deprecated in pandas 2.1 (August 2023).

All other notebook content is unchanged from the original.

## Data Files Required

These notebooks require the data files from Virkud et al.'s original artifact (not redistributed here):

- `techniques.csv`
- `splunk_rules.csv`
- `elastic_rules.csv`
- `sigma_rules.csv`
- `malpedia.txt`
- `rulesets_software.csv`, `rulesets_groups.csv`, `rulesets_campaigns.csv`
- `combined_rules_annotated_entities.csv`

To get them:

```bash
git clone https://github.com/avirkud/endpoint-detection-mitreattack.git original
cd original && git checkout sec24-ae-final
```

Then edit the `data_filepath` variable at the top of each notebook to point to `original/data/`.

## Reproduction Status

All quantitative findings from Virkud et al.'s Sections 4 and 6 were reproduced exactly. See the [REPRODUCTION_LOG.md](../REPRODUCTION_LOG.md) at the repo root for the detailed event log.

## Carbon Black

The paper's analysis includes Carbon Black as a fourth ruleset, but Carbon Black rule data is not in the original artifact (licensing constraint). This reproduction covers Splunk, Elastic, and Sigma only — the three publicly-available rulesets.