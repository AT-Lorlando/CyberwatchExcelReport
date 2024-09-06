import sys
from report import ReportGenerator
from utils import get_df, get_df_interactive, Args

if __name__ == "__main__":
    args = sys.argv[1:]
    params = {
        "-i": Args(False, False, "Launch in an interactive way"),
        "-name": Args("", True, "Name of the output files"),
        "-date": Args("", True, "Date of the scan"),
        "-format": Args(
            "%Y-%m-%d", True, "Date format inside the csv, default is %Y-%m-%d"
        ),
        "-cve": Args("", True, "Path to the CVE csv input"),
        "-cpe": Args("", True, "Path to the CPE csv input"),
        "-patch": Args("", True, "Path to the Patch csv input"),
        "-issue": Args("", True, "Path to the Security Issue csv input"),
        "-olds": Args([], True, "Path to the olds CVE csv input, separated by ','"),
    }
    if "-h" in args or "--help" in args:
        print("Usage:")
        for param, arg in params.items():
            print(f"{param}: {arg.help}")
        exit(0)
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

    # Group by CVE: a line by CVE, affecting multiple servers and multiple components
    # Ex: CVE-2020-1234, Server1 | server2, Component1 | Component2,
    # Group by CVE Code and Server: a line by CVE and by server, but multiple components
    # Ex: CVE-2020-1234, Server1, Component1 | Component2,
    #     CVE-2020-1234, Server2, Component1 | Component2,
    # Group by CVE Code, Server, Component : a line by CVE, by server, and by component (most detailed)
    # Ex: CVE-2020-1234, Server1, Component1,
    #     CVE-2020-1234, Server1, Component2,
    #     CVE-2020-1234, Server2, Component1,
    #     CVE-2020-1234, Server2, Component2,
    generator = ReportGenerator(
        data_df,
        cpe_df,
        patch_df,
        issue_df,
        old_cve_dfs,
        score_col="CVSS Computed Score",
        groupby=["CVE Code"],
        # groupby=["CVE Code", "Server"],
        date_format=params["-format"].value,
    )
    generator.generate_report(f"AUDIT_{params['-name'].value}", params["-date"].value)
    generator.generate_synthesis(
        f"AUDIT_SYNTHESIS_{params['-name'].value}",
        params["-date"].value,
        subset=["Server", "CVE Code", "Product"],
        groupby=["CVE Code", "Server", "Status"],
    )
