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
    else:
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
            df = pd.read_csv(path, delimiter=";", decimal=",", encoding="utf-8")
            return df
        except Exception as e:
            print(f"Error reading {path}: {e}. Please try again.")


def read_csv_file_from_path(path) -> pd.DataFrame:
    return pd.read_csv(path, delimiter=";", decimal=",", encoding="utf-8")
