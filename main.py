import sys
from prompt_toolkit import prompt
from prompt_toolkit.completion import PathCompleter
import pandas as pd
from report import ReportGenerator


MATURITY_LEVELS = {
    "high": 3,
    "functional": 2,
    "proof-of-concept": 1,
    "unproven": 0,
}


class Args:
    def __init__(self, value, need_value, _help):
        self.value = value
        self.need_value = need_value
        self.help = _help

    def set(self, value):
        self.value = value


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


def get_news_from_scans(row, old_row, score_col) -> tuple:
    # The cve is on the old df
    # If one the CONDITIONS change, indicate it
    # Either, it's an "old" cve
    # Use ↓↑⬆️⬇️
    status = None
    update = None
    if (
        row["Cisa Reference"] != old_row["Cisa Reference"]
        or row["Maturity"] != old_row["Maturity"]
        or row["Score EPSS"] != old_row["Score EPSS"]
        or row[score_col] != old_row[score_col]
    ):
        status = "Updated"
        update = ""
        if row["Cisa Reference"] != old_row["Cisa Reference"]:
            update += "Cisa Reference " + ("✅" if row["Cisa Reference"] else "")
        if row["Maturity"] != old_row["Maturity"]:
            update += "Maturity " + (
                "↑"
                if MATURITY_LEVELS[row["Maturity"]]
                > MATURITY_LEVELS[old_row["Maturity"]]
                else "↓"
            )
        if row["Score EPSS"] != old_row["Score EPSS"]:
            update += "EPSS " + (
                "↑" if row["Score EPSS"] > old_row["Score EPSS"] else "↓"
            )
        if row[score_col] != old_row[score_col]:
            update += "Score " + ("↑" if row[score_col] > old_row[score_col] else "↓")
    else:
        status = "Known"
    return status, update


def compute_dataframe(dataframe, old_df, score_col) -> pd.DataFrame:
    # Add a new column to the dataframe to calculate the priority
    dataframe["Priority"] = 6
    conditions = [
        dataframe["Cisa Reference"] == "Yes",
        dataframe["Maturity"] == "high",
        dataframe["Score EPSS"] >= 0.8,
        dataframe[score_col] >= 9,
    ]
    dataframe.loc[dataframe[score_col] >= 7, "Priority"] -= 1
    for condition in conditions:
        dataframe.loc[condition, "Priority"] = 5
    for condition in conditions:
        dataframe.loc[condition, "Priority"] -= 1

    dataframe["Priority"] = "P" + dataframe["Priority"].astype(str)

    # Compare old and actual scan
    if old_df is not None:
        dataframe["Status"] = "New"
        dataframe["New"] = ""
        for index, row in dataframe.iterrows():
            join = old_df.loc[
                (old_df["Server"] == row["Server"])
                & (old_df["CVE Code"] == row["CVE Code"])
                & (old_df["Component"] == row["Component"])
            ]
            if not join.empty:
                for index2, row2 in join.iterrows():
                    status, update = get_news_from_scans(row, row2, score_col)
                    dataframe.loc[index, "Status"] = status
                    dataframe.loc[index, "New"] = update

    # Return a summary for the CVE scan
    clone = dataframe.copy()
    base_agg = {
        "Component": lambda x: ", ".join(x),
        "Product": "first",
        "Version": "first",
        "Update": lambda x: ", ".join(x),
        "Criticity": "first",
        "Priority": "first",
        "Score EPSS": "first",
        score_col: "first",
        "Maturity": "first",
        "Cisa Reference": "first",
        "Priority": "first",
        "Status": "first",
        "New": "first",
    }
    score_agg = {
        "CVSS Score": "first",
        "CVSS Environmental Score": "first",
        "CVSS Temporal Score": "first",
        "CVSS Computed Score": "first",
    }
    score_agg.pop(score_col)
    optional_agg = {
        "Surface": "first",
        "Vector": "first",
        "Environmental Vector": "first",
        "Temporal Vector": "first",
        "Related CWEs": "first",
        "Related CAPECs": "first",
        "Related ATK": "first",
        "CertFR References": "first",
    }
    useless_cols = [
        "Criticity",
        "Surface",
        "Vector",
        "Environmental Vector",
        "Temporal Vector",
        "Related CWEs",
        "Related CAPECs",
        "Related ATK",
        "CertFR References",
        "CVSS Score",
        "CVSS Temporal Score",
        "CVSS Computed Score",
        "CVSS Environmental Score",
    ]
    useless_cols.remove(score_col)
    agg = {}
    for obj in [base_agg, score_agg, optional_agg]:
        for col, rule in obj.items():
            if col in list(clone.columns) and col not in useless_cols:
                agg[col] = rule
    clone = clone.groupby(["CVE Code", "Server"]).agg(agg).reset_index()
    clone.sort_values(
        by=["Priority", "Score EPSS"], ascending=[True, False], inplace=True
    )
    return clone


def parse_dataframe(df):
    if df.empty:
        df.loc[0, df.columns[0]] = "No data to display"
        return
    numeric_cols = [
        "CVSS Score",
        "CVSS Temporal Score",
        "CVSS Environmental Score",
        "CVSS Computed Score",
        "Score EPSS",
    ]
    replace_dict = {"Undefined": 0, "None": 0, pd.NA: 0}
    numeric_cols = [col for col in numeric_cols if col in list(df.columns)]
    for col in numeric_cols:
        df[col] = df[col].replace(replace_dict)
        df[col].fillna(0)

    df[numeric_cols] = df[numeric_cols].astype(float)


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


def get_sheets(
    data_df, cpe_df, patch_df, issue_df, old_cve_dfs=[], score_col="CVSS Computed Score"
):
    parse_dataframe(data_df)
    parse_dataframe(cpe_df)
    parse_dataframe(patch_df)
    parse_dataframe(issue_df)
    cpe_df.sort_values(by="Total", ascending=False, inplace=True)
    patch_df.sort_values(by="CVE Number", ascending=False, inplace=True)

    for i, df in enumerate(old_cve_dfs):
        parse_dataframe(df)
        if (
            "Status" not in old_cve_dfs[i].columns
        ):  # If the status column is present, the dataframe is already computed
            compute_dataframe(
                old_cve_dfs[i],
                old_cve_dfs[i + 1] if i + 1 < len(old_cve_dfs) else None,
                score_col,
            )

    cve_df = compute_dataframe(
        data_df,
        old_cve_dfs[0] if len(old_cve_dfs) > 0 else None,
        score_col=score_col,
    )
    sheets = {
        "Data": data_df,
        "CVE Scan": cve_df,
        "CPE Scan": cpe_df,
        "Patch Scan": patch_df,
        "Security issues Scan": issue_df,
    }
    for i, old_cve_df in enumerate(old_cve_dfs, start=1):
        sheets.update({f"old n{i} CVE Scan": old_cve_df})
    return sheets


if __name__ == "__main__":
    args = sys.argv[1:]
    params = {
        "-i": Args(False, False, "Launch in an interactive way"),
        "-cve": Args("", True, "Path to the CVE csv input"),
        "-cpe": Args("", True, "Path to the CPE csv input"),
        "-patch": Args("", True, "Path to the Patch csv input"),
        "-issue": Args("", True, "Path to the Security Issue csv input"),
        "-olds": Args([], True, "Path to the olds CVE csv input, separated by ','"),
    }
    for i in range(len(args)):
        if args[i] in params:
            if params[args[i]].need_value:
                if not len(args) > i + 1:
                    print(f"{args[i]} need a value: {params[args[i]].help}")
                    exit(0)
                params[args[i]].set(args[i + 1])
                i += 1
            else:
                params[args[i]].set(True)
        elif args[i].startswith("-"):
            print(f"param {args[i]} unknown")

    data_df, cpe_df, patch_df, issue_df, old_cve_dfs = (
        get_df_interactive()
        if params["-i"].value
        else get_df(
            params["-cve"].value,
            params["-cpe"].value,
            params["-patch"].value,
            params["-issue"].value,
            params["-olds"].value,
        )
    )

    xls_sheets = get_sheets(
        data_df,
        cpe_df,
        patch_df,
        issue_df,
        old_cve_dfs,
        score_col="CVSS Computed Score",
    )
    generator = ReportGenerator(xls_sheets, score_col="CVSS Computed Score")
    generator.generate_report(f"test.xlsx")
