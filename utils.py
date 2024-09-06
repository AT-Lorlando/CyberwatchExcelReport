from prompt_toolkit import prompt
from prompt_toolkit.completion import PathCompleter
import pandas as pd


class Args:
    def __init__(self, value, need_value, _help):
        self.value = value
        self.need_value = need_value
        self.help = _help

    def set(self, value):
        self.value = value


def get_df_interactive():
    data_df = read_csv_file_from_prompt("CVE csv path: ")
    cpe_df = read_csv_file_from_prompt("CPE csv path: ")
    patch_df = read_csv_file_from_prompt("Patch csv path: ")
    issue_df = read_csv_file_from_prompt("SecIssue csv path: ")

    old_cve_dfs = []
    while True:
        try:
            old_cve_df = read_csv_file_from_prompt(
                f"Old CVE csv path {len(old_cve_dfs)+1}: ", is_needed=False
            )
            if old_cve_df is None:
                break
            old_cve_dfs.append(old_cve_df)
        except Exception as e:
            print(f"Error reading old CVE: {e}. Please try again.")

    return data_df, cpe_df, patch_df, issue_df, old_cve_dfs


def get_df(data_df_path, cpe_df_path, patch_df_path, issue_df_path, old_cve_dfs_paths):
    data_df = read_csv_file_from_path(data_df_path)
    cpe_df = read_csv_file_from_path(cpe_df_path)
    patch_df = read_csv_file_from_path(patch_df_path)
    issue_df = read_csv_file_from_path(issue_df_path)

    old_cve_dfs = []
    if "," in old_cve_dfs_paths:
        for path in old_cve_dfs_paths.split(","):
            try:
                old_cve_df = read_csv_file_from_path(path)
                old_cve_dfs.append(old_cve_df)
            except Exception as e:
                print(f"Error reading old CVE: {e}. Please try again.")
    elif old_cve_dfs_paths:
        old_cve_df = read_csv_file_from_path(old_cve_dfs_paths)
        old_cve_dfs.append(old_cve_df)
    return data_df, cpe_df, patch_df, issue_df, old_cve_dfs


def read_csv_file_from_prompt(prompt_text, is_needed=True) -> pd.DataFrame or None:
    path_completer = PathCompleter(only_directories=False)
    while True:
        path = prompt(prompt_text, completer=path_completer)
        if not path:
            if is_needed:
                print("Please provide a valid path.")
                continue
            return None
        try:
            df = pd.read_csv(
                path, parse_dates=False, delimiter=";", decimal=",", encoding="utf-8"
            )
            return df
        except Exception as e:
            print(f"Error reading {path}: {e}. Please try again.")


def read_csv_file_from_path(path) -> pd.DataFrame:
    return pd.read_csv(
        path, parse_dates=False, delimiter=";", decimal=",", encoding="utf-8"
    )


def get_legend_df(date):
    descriptions = {
        "Audit": f"Ce rapport a été généré en utilisant un scan du {date}.",
        "---": "---",
        "Data": f"Données brutes formalisées.",
        "CVE Scan": f"Synthèse des CVE d'après le dernier scan, permet de savoir quelles CVE affectent quels systèmes sur quels composants",
        "CPE Scan": f"Synthèse des CPE d'après le dernier scan, permet de savoir quelles technologies sont scannées",
        "Patch Scan": f"Synthèse des actions correctives à appliquer",
        "Security issue Scan": f"Scan des défauts de sécurité sur les sytèmes (application / OS obsolète, etc.)",
        "old nX CVE Scan": f"Données brutes formalisées de l'ancien Scan n°X",
        "Analysis": f"Graphiques analysant l'état actuel",
        "----": "----",
        "Published Date": "Date de publication de la CVE",
        "Last Reviewed Date": "Date de dernière révision de la CVE",
        "Domain": "Domaine du serveur affecté",
        "Surface": "Surface d'attaque du serveur affecté",
        "Server": "Serveur/Host/Image docker affecté",
        "CVE Code": "Code de la CVE",
        "CVSS Score": "Common Vulnerability Scoring System, sert à évaluer la gravité d'une faille de 0 à 10",
        "CVSS Temporal Score": "Score CVSS avec prise en compte de la temporalité (l'évolution de la faille, remédiation, etc.)",
        "CVSS Environmental Score": "Score CVSS avec prise en compte de l'environnement (surface d'attaque, etc.)",
        "CVSS Computed Score": "Score CVSS avec prise en compte de la temporalité et de l'environnement",
        "Criticity": "Criticité de la CVE, basée sur le score CVSS (C1 = critique, C2 = élevé, C3 = moyen, C4 = faible)",
        "Component": "Composant affecté par la vulnérabilité",
        "Product": "Produit affecté par la vulnérabilité",
        "Version": "Version du produit affecté",
        "Patch": "Version pour lesquelles la vulnérabilité est corrigée",
        "Score EPSS": "Exploit Prediction Scoring System, évalue la probabilité d'exploitation d'une vulnérabilité",
        "Maturity": "Niveau de maturité de la vulnérabilité (ex. : preuve de concept, exploitation active)",
        "Content": "Contenu associé à la vulnérabilité (ex. : description détaillée, preuves de concept)",
        "Vector": "Vecteur d'attaque de la vulnérabilité",
        "Environmental Vector": "Vecteur environnemental de la vulnérabilité",
        "Temporal Vector": "Vecteur temporel de la vulnérabilité",
        "CWE Code": "Common Weakness Enumeration, identifiant de la faiblesse commune sur laquelle repose la vulnérabilité",
        "Related CWEs": "Faiblesses communes liées à la vulnérabilité",
        "Related CAPECs": "Common Attack Pattern Enumeration and Classification, modèles d'attaque liés",
        "Related ATK": "Attaques liées à la vulnérabilité repertoriées dans l'ATK (Attack Tree Knowledge) du MITRE",
        "Cisa Reference": "Référence CISA (Cybersecurity and Infrastructure Security Agency)",
        "CertFR References": "Références CertFR (Centre gouvernemental de veille, d'alerte et de réponse aux attaques informatiques)",
        "Priority": "Priorité de traitement de la CVE, basée sur la criticité, le score EPSS, la maturité, références, etc.",
        "Status": "Statut de la CVE par rapport aux anciens scans (New, Updated, Unchanged, Deleted) | Une CVE 'Deleted' peut aussi bien avoir été rejetée par le Nist que fixée par une action corrective",
        "Update CISA": "Indique si la CVE est documentée par le CISA depuis le dernier scan",
        "Update CVSS": "Indique si le score de la CVE a été réévaluée par le Nist depuis le dernier scan",
        "Update EPSS": "Indique l'EPSS de la CVE a été réévaluée par le Nist depuis le dernier scan",
        "Update Maturity": "Indique si la maturité de la CVE a été réévaluée par le Nist depuis le dernier scan",
    }
    data = {
        "Donnée": list(descriptions.keys()),
        "Description": list(descriptions.values()),
    }
    df_legende = pd.DataFrame(data)
    return df_legende
