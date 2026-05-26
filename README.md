# Microsoft Sentinel Extension: MITRE ATT&CK Coverage Asymmetry

A reproduction and extension of *"How does Endpoint Detection use the MITRE ATT&CK Framework?"* (Virkud, Inam, Riddle, Liu, Wang, & Bates — USENIX Security 2024).

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![Python 3.11](https://img.shields.io/badge/python-3.11-blue.svg)](https://www.python.org/downloads/release/python-3119/)
[![Reproduction: USENIX Security 2024](https://img.shields.io/badge/reproduces-USENIX%20Security%202024-green)](https://www.usenix.org/conference/usenixsecurity24)

> **Headline finding:** Microsoft Sentinel covers ATT&CK techniques **2–6× more** for cloud and identity attacks than the on-host EDR products in the original paper, but **5–26× less** for host-only techniques. This adds a third failure mode to the paper's critique of ATT&CK-as-security-metric: **ATT&CK coverage is partly an artefact of telemetry architecture, not just detection effort.**

## Quick Results

| Technique | Splunk | Elastic | Sigma | **Sentinel** |
|---|---:|---:|---:|---:|
| T1078 Valid Accounts (cloud/identity) | 39 | 13 | 52 | **78** |
| T1098 Account Manipulation (cloud/identity) | 6 | 7 | 23 | **38** |
| T1110 Brute Force / Password Spraying (cloud/identity) | 15 | 11 | 22 | **29** |
| T1547 Boot or Logon Autostart (host) | 15 | 23 | 50 | **2** |
| T1543 Create/Modify System Process (host) | 16 | 26 | 46 | **1** |
| T1055 Process Injection (host) | 21 | 12 | 35 | **1** |

**Coverage:** Splunk 52.4% · Elastic 48.2% · Sigma 79.1% · **Sentinel 41.4%** of ATT&CK v11

**Spearman rank correlation (technique-priority similarity):**
- Within original paper: ρ = 0.64–0.76
- Sentinel vs each ruleset: **ρ = 0.39–0.50** (all p < 0.001)

## What This Project Does

1. **Reproduces** the main findings of Virkud et al. (RQ1 coverage analysis + all four RQ3 case studies) on a modern environment (Windows 11, Python 3.11), matching paper values to three decimal places.
2. **Extends** the analysis by adding **Microsoft Sentinel** as a fifth ruleset (~349 Analytics rules), a major commercial SIEM that was absent from the original paper.
3. **Tests a pre-registered hypothesis** that Sentinel — as a cloud-native SIEM — would show systematically different ATT&CK coverage than the on-host EDR products. The hypothesis is strongly confirmed.
4. **Documents 27 reproduction events**, including five distinct version-drift workarounds (NumPy 2.0, pandas 3.0, NLTK 3.9, Linux-only CUDA wheels, etc.) encountered during cross-platform reproduction.

See **[REPORT.docx](docs/INFO5001_Research_Report.docx)** for the full 36-page analysis.
See **[REPRODUCTION_LOG.md](REPRODUCTION_LOG.md)** for the chronological event log.

## Repository Structure
.
├── README.md                       ← You are here
├── REPRODUCTION_LOG.md             ← 27-event chronological log
├── LICENSE                         ← MIT
│
├── extension/                      ← This work's primary contribution
│   ├── notebooks/
│   │   ├── sentinel_adapter.py     ← Loads & transforms Sentinel CSV
│   │   ├── virkud_loader.py        ← Wraps original notebook loaders
│   │   └── sentinel_rq1_analysis.ipynb
│   ├── outputs/                    ← Results (CSVs, technique lists)
│   └── sentinel_data/              ← Microsoft Sentinel ATT&CK feed
│
├── reproduction/                   ← Patched reproduction of original
│   └── code/
│       ├── RQ1_Analysis.ipynb      ← np.NaN → np.nan, .applymap → .map
│       └── RQ3_Analysis.ipynb      ← Same patches
│
└── docs/                           ← Full written report

## Reproducing These Results

```bash
# 1. Clone
git clone https://github.com/JunaidAbrar/virkud-sentinel-extension.git
cd virkud-sentinel-extension

# 2. Get the original Virkud et al. data (Splunk/Elastic/Sigma)
git clone https://github.com/avirkud/endpoint-detection-mitreattack.git original
cd original && git checkout sec24-ae-final && cd ..

# 3. Set up Python environment
python -m venv .venv
.venv\Scripts\Activate.ps1     # Windows
# source .venv/bin/activate    # macOS/Linux
pip install pandas numpy scipy nltk matplotlib seaborn jupyter ipykernel
python -c "import nltk; [nltk.download(p) for p in ['stopwords','punkt','punkt_tab','words','wordnet']]"

# 4. Point notebook to Virkud data
# Edit VIRKUD_DATA path in sentinel_rq1_analysis.ipynb to point to ./original/data

# 5. Run analysis
jupyter notebook extension/notebooks/sentinel_rq1_analysis.ipynb
```

## Data Sources

- **Splunk / Elastic / Sigma rule data**: from Virkud et al.'s [original artifact](https://github.com/avirkud/endpoint-detection-mitreattack) (release `sec24-ae-final`, October 2022 snapshot)
- **Microsoft Sentinel rule data**: from [microsoft/mstic public feed](https://github.com/microsoft/mstic/blob/master/PublicFeeds/MITREATT%26CK/MicrosoftSentinel.csv) (snapshot dated August 2022). The CSV is included in this repo at `extension/sentinel_data/MicrosoftSentinel.csv` for convenience.

## Citation

If you build on this work, please cite both the original paper and this extension:

```bibtex
@inproceedings{virkud2024endpoint,
  title={How does Endpoint Detection use the MITRE ATT\&CK Framework?},
  author={Virkud, Apurva and Inam, Muhammad Adil and Riddle, Andy and Liu, Jason and Wang, Gang and Bates, Adam},
  booktitle={USENIX Security Symposium},
  year={2024}
}

@misc{razeen2026sentinel,
  title={Microsoft Sentinel Extension: MITRE ATT\&CK Coverage Asymmetry},
  author={Razeen, Junaid Abrar},
  year={2026},
  howpublished={\url{https://github.com/JunaidAbrar/virkud-sentinel-extension}},
  note={Reproduction and extension of Virkud et al. (USENIX Security 2024)}
}
```

## Academic Context

This work was produced as part of **INFO 5001 (Cyber Security)** at **Adelaide University**, Master of Information Technology (Computing and Innovation), in May–June 2026. The course coordinator (Dr. Md Mokammel Haque) characterised the Sentinel extension direction as potentially publishable; this repository accompanies the formal report submitted for assessment.

## License

This project is licensed under the MIT License — see [LICENSE](LICENSE) for details.

The original Virkud et al. artifact is under its own license (see their [repository](https://github.com/avirkud/endpoint-detection-mitreattack)). The Microsoft Sentinel CSV is published by Microsoft under its own terms (see [microsoft/mstic](https://github.com/microsoft/mstic)).

## Acknowledgments

- Virkud, Inam, Riddle, Liu, Wang & Bates for the original paper and well-engineered artifact
- The Microsoft Threat Intelligence Center (MSTIC) for publishing the Sentinel detection feed
- Dr. Md Mokammel Haque for supervision and encouragement