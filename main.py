import sys
from report import ReportGenerator
from utils import get_df, get_df_interactive, Args

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

    generator = ReportGenerator(
        data_df,
        cpe_df,
        patch_df,
        issue_df,
        old_cve_dfs,
        score_col="CVSS Computed Score",
        groupby=["CVE Code", "Server"],
    )
    # generator.generate_report(f"test.xlsx")
    generator.generate_synthesis(
        f"synthesis.xlsx",
        subset=["Server", "CVE Code", "Product"],
        groupby=["CVE Code", "Server", "Status"],
    )
