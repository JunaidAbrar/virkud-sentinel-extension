"""
Virkud Loader — Helper module to load Splunk, Elastic, Sigma, and
the ATT&CK techniques CSV from the original Virkud artifact.

This mirrors the data-loading logic in code/RQ1 Analysis.ipynb but
packages it into reusable functions. Includes the np.NaN -> np.nan
patch we applied during reproduction.

Author: Junaid Abrar Razeen
Date: May 2026
"""

import json
import os
import pandas as pd
import numpy as np


# ----------------------------------------------------------------------
# Helpers from Virkud's notebooks (patched for NumPy 2.x compatibility)
# ----------------------------------------------------------------------

def load_ids(x):
    if type(x) == str:
        return json.loads(x.replace("'", '"'))
    return x


def drop_subtechniques(x):
    if type(x) == float:
        return x
    techniques = set()
    for t in x:
        techniques.add(t[0:5])
    return techniques


def parse_threat_column(threat):
    """Patched: np.NaN -> np.nan (NumPy 2.0 compatibility)"""
    if type(threat) != float:
        threat_list = json.loads(threat.replace("'", '"'))
        threat_techniques = set()
        for threat in threat_list:
            techs = threat.get('technique', [])
            for technique in techs:
                threat_techniques.add(technique['id'])
        if threat_techniques:
            return list(threat_techniques)
    return np.nan


def get_sigma_techniques(tags, valid_techniques):
    if type(tags) == float:
        return []
    rule_techniques = set()
    for tag in tags:
        if tag.startswith('attack.t'):
            technique = tag[7:12].upper()
            if technique in valid_techniques:
                rule_techniques.add(technique.upper())
    return list(rule_techniques)


# ----------------------------------------------------------------------
# Loaders
# ----------------------------------------------------------------------

def load_techniques(data_filepath: str) -> pd.DataFrame:
    """Load the ATT&CK v11 techniques CSV."""
    return pd.read_csv(os.path.join(data_filepath, 'techniques.csv'))


def load_splunk(data_filepath: str) -> pd.DataFrame:
    splunk = pd.read_csv(os.path.join(data_filepath, 'splunk_rules.csv'))
    splunk['rule_index'] = splunk['rule_index'].apply(lambda x: 'splunk' + str(x))
    splunk['mitre_attack_id'] = (
        splunk['tags.mitre_attack_id']
        .apply(load_ids)
        .apply(drop_subtechniques)
        .apply(lambda x: list(x) if type(x) == set else [])
    )
    splunk = splunk[splunk['mitre_attack_id'].apply(lambda x: len(x) > 0)]
    return splunk


def load_elastic(data_filepath: str) -> pd.DataFrame:
    elastic = pd.read_csv(os.path.join(data_filepath, 'elastic_rules.csv'))
    elastic = elastic[elastic['metadata.maturity'] == 'production']
    elastic['rule_index'] = elastic['rule_index'].apply(lambda x: 'elastic' + str(x))
    elastic['mitre_attack_id'] = elastic['rule.threat'].apply(parse_threat_column)
    elastic = elastic[pd.notna(elastic['mitre_attack_id'])]
    return elastic


def load_sigma(data_filepath: str, techniques_df: pd.DataFrame) -> pd.DataFrame:
    sigma = pd.read_csv(os.path.join(data_filepath, 'sigma_rules.csv'))
    sigma = sigma.rename({'Unnamed: 0': 'rule_index'}, axis=1)
    sigma['rule_index'] = sigma['rule_index'].apply(lambda x: 'sigma' + str(x))
    sigma = sigma[sigma['status'].apply(
        lambda x: x in ('experimental', 'test', 'stable'))]

    valid_techniques = set(techniques_df['technique'].drop_duplicates())
    sigma['mitre_attack_id'] = sigma['tags'].apply(
        lambda tags: get_sigma_techniques(load_ids(tags), valid_techniques))
    sigma = sigma[sigma['mitre_attack_id'].apply(lambda x: len(x) > 0)]
    return sigma


def load_all_virkud(data_filepath: str, verbose: bool = True):
    """One-call helper to load all four Virkud rulesets at once.
    Returns (techniques, splunk, elastic, sigma).
    """
    techniques = load_techniques(data_filepath)
    if verbose:
        print(f'[virkud] Loaded {len(techniques)} technique-tactic rows')

    splunk = load_splunk(data_filepath)
    if verbose:
        print(f'[virkud] Splunk: {len(splunk)} rules')

    elastic = load_elastic(data_filepath)
    if verbose:
        print(f'[virkud] Elastic: {len(elastic)} rules')

    sigma = load_sigma(data_filepath, techniques)
    if verbose:
        print(f'[virkud] Sigma: {len(sigma)} rules')

    return techniques, splunk, elastic, sigma