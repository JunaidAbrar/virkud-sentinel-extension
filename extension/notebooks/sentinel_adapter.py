"""
Sentinel Adapter — Phase 3 of INFO 5001 Research Project

Transforms the Microsoft Sentinel ATT&CK CSV into a dataframe
structurally compatible with Virkud et al.'s splunk/elastic/sigma
dataframes, and provides analysis helpers for cross-ruleset
comparison.

Author: Junaid Abrar Razeen
Date: May 2026
"""

import os
import pandas as pd
import numpy as np


# ----------------------------------------------------------------------
# Constants
# ----------------------------------------------------------------------

# ATT&CK v11 — matches Virkud's analysis (191 techniques, 14 tactics)
ATTACK_V11_TECHNIQUE_COUNT = 191

# Cloud-focused techniques we pre-registered as our hypothesis:
# Sentinel should over-cover these vs host-focused products.
PREREG_CLOUD_TECHNIQUES = {
    'T1078': 'Valid Accounts',
    'T1098': 'Account Manipulation',
    'T1530': 'Data from Cloud Storage',
    'T1110': 'Brute Force (incl. password spraying)',
    'T1538': 'Cloud Service Dashboard',
    'T1526': 'Cloud Service Discovery',
    'T1580': 'Cloud Infrastructure Discovery',
    'T1538': 'Cloud Service Dashboard',
    'T1136': 'Create Account',
    'T1556': 'Modify Authentication Process',
}

# Host-focused techniques we pre-registered as our hypothesis:
# Sentinel should under-cover these vs on-host EDR products.
PREREG_HOST_TECHNIQUES = {
    'T1547': 'Boot or Logon Autostart Execution',
    'T1543': 'Create or Modify System Process',
    'T1546': 'Event Triggered Execution',
    'T1014': 'Rootkit',
    'T1574': 'Hijack Execution Flow',
    'T1055': 'Process Injection',
}


# ----------------------------------------------------------------------
# Helpers (matching Virkud's conventions)
# ----------------------------------------------------------------------

def drop_subtechniques(x):
    """Truncate sub-techniques to parent: T1003.001 -> T1003.
    Matches Virkud's helper function exactly.
    """
    if type(x) == float:
        return x
    techniques = set()
    for t in x:
        techniques.add(t[0:5])
    return techniques


def map_tactic(technique, techniques_df):
    """Map a technique ID to its tactic(s), matching Virkud's
    map_tactic function.
    """
    try:
        tactic = techniques_df[techniques_df['technique'] == technique]['tactics'].drop_duplicates()
        return tactic.values[0]
    except Exception:
        return 'unknown'


# ----------------------------------------------------------------------
# Sentinel Loader
# ----------------------------------------------------------------------

def load_sentinel(csv_path: str, verbose: bool = True) -> pd.DataFrame:
    """Load and transform Microsoft Sentinel CSV into Virkud-compatible
    dataframe structure.

    Pipeline:
      1. Load raw CSV
      2. Drop nulls and 'N.A.' TechniqueIds
      3. Filter to DetectionType == 'Analytics' only
      4. Deduplicate by DetectionId (one row per unique rule)
      5. Aggregate platforms and tactics into lists per rule
      6. Apply drop_subtechniques (parent-technique aggregation)
      7. Construct rule_index in Virkud's 'sentinel<N>' format

    Returns:
      pd.DataFrame with columns matching Virkud's structure.
    """
    df = pd.read_csv(csv_path)
    if verbose:
        print(f'[adapter] Loaded {len(df)} raw rows from {csv_path}')

    # Drop invalid TechniqueId
    df = df[df['TechniqueId'].notna() & (df['TechniqueId'] != 'N.A.')]
    if verbose:
        print(f'[adapter] After TechniqueId filter: {len(df)} rows')

    # Filter to Analytics rules only (Virkud-equivalent)
    df = df[df['DetectionType'] == 'Analytics']
    if verbose:
        print(f'[adapter] After Analytics filter: {len(df)} rows')

    # Handle null Platform/Tactic values before grouping
    df = df.copy()
    df['Platform'] = df['Platform'].fillna('Unknown')
    df['Tactic'] = df['Tactic'].fillna('Unknown')

    # Aggregate per DetectionId
    grouped = df.groupby('DetectionId').agg({
        'TechniqueId': lambda x: list(set(x)),
        'Platform': lambda x: sorted(set(x)),
        'Tactic': lambda x: sorted(set(x)),
        'DetectionName': 'first',
        'DetectionDescription': 'first',
        'DetectionSeverity': 'first',
        'DetectionService': 'first',
        'Query': 'first',
        'DetectionUrl': 'first',
        'IngestedDate': 'first',
    }).reset_index()

    if verbose:
        print(f'[adapter] After deduplication: {len(grouped)} unique rules')

    # Apply drop_subtechniques (T1003.001 -> T1003)
    grouped['mitre_attack_id'] = grouped['TechniqueId'].apply(
        lambda x: list(drop_subtechniques(set(x)))
    )

    # Drop rules with empty technique list after subtechnique merge
    grouped = grouped[grouped['mitre_attack_id'].apply(lambda x: len(x) > 0)]

    # Build rule_index matching Virkud format
    grouped = grouped.reset_index(drop=True)
    grouped['rule_index'] = grouped.index.map(lambda i: f'sentinel{i}')

    # Rename columns to match Virkud convention
    sentinel = grouped.rename(columns={
        'DetectionName': 'name',
        'DetectionDescription': 'description',
        'DetectionSeverity': 'severity',
        'DetectionService': 'source',
        'Query': 'query',
        'Platform': 'platforms',
        'Tactic': 'tactics_raw',
    })

    # Final column ordering
    cols_first = ['rule_index', 'mitre_attack_id', 'name', 'description',
                  'severity', 'platforms', 'source', 'tactics_raw', 'query',
                  'DetectionUrl', 'IngestedDate']
    sentinel = sentinel[cols_first]

    if verbose:
        unique_techs = set(t for techs in sentinel['mitre_attack_id'] for t in techs)
        print(f'[adapter] Final dataframe: {len(sentinel)} rules')
        print(f'[adapter] Unique techniques: {len(unique_techs)}')

    return sentinel


# ----------------------------------------------------------------------
# Per-Ruleset Analysis Helpers
# ----------------------------------------------------------------------

def compute_technique_counts(ruleset_df, technique_col='mitre_attack_id'):
    """For a ruleset, count how many rules implement each technique.
    Returns a pd.Series indexed by technique ID, values are rule counts.
    Matches Virkud's splunk_mitre_counts logic.
    """
    counts = {}
    for row in ruleset_df[technique_col]:
        if type(row) == float:
            continue
        for technique in row:
            counts[technique] = counts.get(technique, 0) + 1
    return pd.Series(counts, name='count').sort_values()


def technique_coverage_summary(sentinel, splunk, elastic, sigma, techniques_df,
                                attack_v11_total=ATTACK_V11_TECHNIQUE_COUNT):
    """Build a summary table of technique coverage across all 4
    (or 5 if carbon_black is added) rulesets.
    
    Returns a dataframe with the count of techniques covered by
    each ruleset and the percent of ATT&CK v11.
    """
    valid_techniques = set(techniques_df['technique'].drop_duplicates())

    def coverage(df):
        techs = set()
        for row in df['mitre_attack_id']:
            if type(row) == float:
                continue
            for t in row:
                if t in valid_techniques:
                    techs.add(t)
        return techs

    sent_techs = coverage(sentinel)
    splunk_techs = coverage(splunk)
    elastic_techs = coverage(elastic)
    sigma_techs = coverage(sigma)

    summary = pd.DataFrame({
        '# Rules': [len(splunk), len(elastic), len(sigma), len(sentinel)],
        '# Unique Techniques': [len(splunk_techs), len(elastic_techs),
                                len(sigma_techs), len(sent_techs)],
        '% Coverage (ATT&CK v11)': [
            f'{100 * len(splunk_techs) / attack_v11_total:.1f}%',
            f'{100 * len(elastic_techs) / attack_v11_total:.1f}%',
            f'{100 * len(sigma_techs) / attack_v11_total:.1f}%',
            f'{100 * len(sent_techs) / attack_v11_total:.1f}%',
        ],
    }, index=['Splunk', 'Elastic', 'Sigma', 'Sentinel'])

    return summary, {
        'splunk': splunk_techs,
        'elastic': elastic_techs,
        'sigma': sigma_techs,
        'sentinel': sent_techs,
    }


def techniques_unique_to_sentinel(coverage_sets):
    """Find techniques that Sentinel covers but no other commercial
    ruleset (Splunk, Elastic) covers. This tests the cloud-coverage
    hypothesis.
    
    Note: We exclude Sigma from this comparison because Sigma is
    crowdsourced and has different coverage characteristics. This
    matches Virkud's main analysis (which separates Sigma into
    Appendix A).
    """
    sentinel = coverage_sets['sentinel']
    splunk = coverage_sets['splunk']
    elastic = coverage_sets['elastic']

    return {
        'sentinel_only_vs_commercial': sentinel - splunk - elastic,
        'sentinel_overlap_with_commercial': sentinel & (splunk | elastic),
        'covered_by_others_not_sentinel': (splunk | elastic) - sentinel,
    }


def test_prereg_hypothesis(sentinel, splunk, elastic, sigma):
    """Test the pre-registered hypothesis:
    Sentinel over-covers cloud/identity techniques vs on-host EDRs
    Sentinel under- or comparably-covers host-only techniques.
    
    Returns a DataFrame comparing rule counts per technique
    across all 4 rulesets, for both prereg cloud and host technique
    sets.
    """
    rulesets = {'Splunk': splunk, 'Elastic': elastic,
                'Sigma': sigma, 'Sentinel': sentinel}

    counts_per_ruleset = {
        name: compute_technique_counts(df)
        for name, df in rulesets.items()
    }

    def build_row(tid, label, category):
        return {
            'Technique': tid,
            'Name': label,
            'Category': category,
            'Splunk': int(counts_per_ruleset['Splunk'].get(tid, 0)),
            'Elastic': int(counts_per_ruleset['Elastic'].get(tid, 0)),
            'Sigma': int(counts_per_ruleset['Sigma'].get(tid, 0)),
            'Sentinel': int(counts_per_ruleset['Sentinel'].get(tid, 0)),
        }

    rows = []
    for tid, name in PREREG_CLOUD_TECHNIQUES.items():
        rows.append(build_row(tid, name, 'Cloud/Identity (prereg)'))
    for tid, name in PREREG_HOST_TECHNIQUES.items():
        rows.append(build_row(tid, name, 'Host (prereg)'))

    return pd.DataFrame(rows)


def coverage_percent_per_technique(ruleset_df, techniques_df):
    """For each ATT&CK technique, what % of the ruleset is dedicated
    to it. This is the input to the Spearman rank correlation.
    Matches Virkud's technique_coverage_percent calculation.
    """
    valid_techniques = set(techniques_df['technique'].drop_duplicates())
    counts = compute_technique_counts(ruleset_df)

    # Filter to only valid ATT&CK v11 techniques
    counts = counts[counts.index.isin(valid_techniques)]

    total_rules = len(ruleset_df)
    return counts / total_rules


if __name__ == '__main__':
    # Sanity check — run this script directly to verify the adapter
    csv_path = os.path.join('..', 'sentinel_data', 'MicrosoftSentinel.csv')
    sentinel = load_sentinel(csv_path, verbose=True)

    print('\n=== Sentinel dataframe summary ===')
    print(f'Rules: {len(sentinel)}')
    print(f'Columns: {list(sentinel.columns)}')

    all_techniques = set()
    for techs in sentinel['mitre_attack_id']:
        all_techniques.update(techs)
    print(f'Unique parent techniques: {len(all_techniques)}')
    print(f'Estimated coverage of ATT&CK v11: '
          f'{len(all_techniques) / ATTACK_V11_TECHNIQUE_COUNT * 100:.1f}%')

    print('\n=== Severity distribution ===')
    print(sentinel['severity'].value_counts())