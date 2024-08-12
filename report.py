from openpyxl import load_workbook
from openpyxl.styles import Font, PatternFill
from openpyxl.utils import get_column_letter
from openpyxl.formatting.rule import ColorScaleRule, CellIsRule
from openpyxl.worksheet.table import Table, TableStyleInfo
from openpyxl.drawing.image import Image
from openpyxl.worksheet.worksheet import Worksheet
import pandas as pd
from charts import ChartGenerator

MATURITY_LEVELS = {
    "high": 3,
    "functional": 2,
    "proof-of-concept": 1,
    "unproven": 0,
}


class ReportGenerator:
    # A constant dictionary to map colums to their types, like numeric or string, verbose or not, etc.
    COLUMN_TYPES = {}
    CRITICITY_COLORS = {
        "C1": "FFFF7575",  # Red
        "C2": "FFFABF8F",  # Orange
        "C3": "FFFFE575",  # Yellow
        "C4": "FF00B050",  # Green
        "C0": "FF5A8AC6",  # Blue (default)
    }
    PRIORITY_COLORS = {
        "P1": "FFF8696B",  # Red
        "P2": "FFfa9395",  # Orange
        "P3": "FFfcc6c7",  # Yellow
        "P4": "FFcad9ed",  # Green
        "P5": "FF8fafd8",  # Blue (default)
        "P6": "FF5A8AC6",  # Blue (default)
    }
    MATURITY_COLORS = {
        "high": "FFFF7575",  # Red
        "functional": "FFFEC4B8",  # Orange
        "proof-of-concept": "FFFFE575",  # Yellow
        "unproven": "FFFFF6C9",  # Green
    }
    COLOR_SCALE = {
        "min": "FF5A8AC6",
        "max": "FFF8696B",
        "mid": "FFFFFFFF",
    }
    STYLE = TableStyleInfo(
        name="TableStyleMedium2",
        showFirstColumn=False,
        showLastColumn=False,
        showRowStripes=True,
        showColumnStripes=True,
    )

    def __init__(
        self,
        data_df,
        cpe_df,
        patch_df,
        issue_df,
        old_cve_dfs,
        score_col="CVSS Computed Score",
        groupby=["CVE Code", "Server"],
    ):
        self.dataframe = data_df
        self.cpe_df = cpe_df
        self.patch_df = patch_df
        self.issue_df = issue_df
        self.old_cve_dfs = old_cve_dfs
        self.score_col = score_col
        self.groupby = groupby
        self.get_sheets()

    def get_sheets(self):
        parse_dataframe(self.dataframe)
        parse_dataframe(self.cpe_df)
        parse_dataframe(self.patch_df)
        parse_dataframe(self.issue_df)
        self.cpe_df.sort_values(by="Total", ascending=False, inplace=True)
        self.patch_df.sort_values(by="CVE Number", ascending=False, inplace=True)

        for i, df in enumerate(self.old_cve_dfs):
            parse_dataframe(df)
            if (
                "Status" not in self.old_cve_dfs[i].columns
            ):  # If the status column is present, the dataframe is already computed
                compute_dataframe(
                    self.old_cve_dfs[i],
                    self.old_cve_dfs[i + 1] if i + 1 < len(self.old_cve_dfs) else None,
                    self.score_col,
                    groupby=self.groupby,
                )

        compute_dataframe(
            self.dataframe,
            self.old_cve_dfs[0] if len(self.old_cve_dfs) > 0 else None,
            score_col=self.score_col,
            groupby=self.groupby,
        )
        self.cve_df = group_df(self.dataframe, self.score_col, groupby=self.groupby)
        self.sheets = {
            "Data": self.dataframe,
            "CVE Scan": self.cve_df,
            "CPE Scan": self.cpe_df,
            "Patch Scan": self.patch_df,
            "Security issues Scan": self.issue_df,
        }
        for i, old_cve_df in enumerate(self.old_cve_dfs, start=1):
            self.sheets.update({f"old n{i} CVE Scan": old_cve_df})

    def apply_conditional_formatting(
        self,
        ws: Worksheet,
        df: pd.DataFrame,
        color_scale_columns=["CVSS Computed Score"],
    ):
        if not isinstance(color_scale_columns, list):
            color_scale_columns = [color_scale_columns]
        # Apply a background color to the header row
        for col_num in range(1, df.shape[1] + 1):
            cell = ws[f"{get_column_letter(col_num)}1"]
            cell.font = Font(color="FFFFFF")

        # Apply conditional formatting to the criticity column with CellRule
        if "Criticity" in list(df.columns):
            criticity_col = get_column_letter(list(df.columns).index("Criticity") + 1)
            for criterion, color in self.CRITICITY_COLORS.items():
                ws.conditional_formatting.add(
                    f"{criticity_col}2:{criticity_col}{ws.max_row}",
                    CellIsRule(
                        operator="equal",
                        formula=[f'"{criterion}"'],
                        stopIfTrue=True,
                        fill=PatternFill(
                            start_color=color, end_color=color, fill_type="solid"
                        ),
                    ),
                )

        # Apply conditional formatting to the criticity column with CellRule
        if "Priority" in list(df.columns):
            criticity_col = get_column_letter(list(df.columns).index("Priority") + 1)
            for criterion, color in self.PRIORITY_COLORS.items():
                ws.conditional_formatting.add(
                    f"{criticity_col}2:{criticity_col}{ws.max_row}",
                    CellIsRule(
                        operator="equal",
                        formula=[f'"{criterion}"'],
                        stopIfTrue=True,
                        fill=PatternFill(
                            start_color=color, end_color=color, fill_type="solid"
                        ),
                    ),
                )

        # Apply conditional formatting to the maturity column with CellRule
        if "Maturity" in list(df.columns):
            maturity_col = get_column_letter(list(df.columns).index("Maturity") + 1)
            for criterion, color in self.MATURITY_COLORS.items():
                ws.conditional_formatting.add(
                    f"{maturity_col}2:{maturity_col}{ws.max_row}",
                    CellIsRule(
                        operator="equal",
                        formula=[f'"{criterion}"'],
                        stopIfTrue=True,
                        fill=PatternFill(
                            start_color=color, end_color=color, fill_type="solid"
                        ),
                    ),
                )

        # Apply conditional formatting to the EPSS column with a color scale and percentage format
        for col_name in color_scale_columns:
            if col_name in list(df.columns):
                col = get_column_letter(list(df.columns).index(col_name) + 1)
                ws.conditional_formatting.add(
                    col + "2:" + col + str(ws.max_row),
                    ColorScaleRule(
                        start_type="percent",
                        start_value=1,
                        start_color=self.COLOR_SCALE["min"],
                        mid_type="num",
                        mid_value=4,
                        mid_color=self.COLOR_SCALE["mid"],
                        end_type="percent",
                        end_value=100,
                        end_color=self.COLOR_SCALE["max"],
                    ),
                )

        # Apply conditional formatting to the EPSS column with a color scale and percentage format
        if "Score EPSS" in list(df.columns):
            col = get_column_letter(list(df.columns).index("Score EPSS") + 1)
            ws.conditional_formatting.add(
                col + "2:" + col + str(ws.max_row),
                ColorScaleRule(
                    start_type="percent",
                    start_value=1,
                    start_color=self.COLOR_SCALE["min"],
                    mid_type="num",
                    mid_value=0.05,
                    mid_color=self.COLOR_SCALE["mid"],
                    end_type="percent",
                    end_value=100,
                    end_color=self.COLOR_SCALE["max"],
                ),
            )
            for row in range(2, ws.max_row + 1):
                cell = ws[col + str(row)]
                cell.number_format = "0.000%"

        if "Total" in list(df.columns):
            col = get_column_letter(list(df.columns).index("Total") + 1)
            ws.conditional_formatting.add(
                col + "2:" + col + str(ws.max_row),
                ColorScaleRule(
                    start_type="percent",
                    start_value=1,
                    start_color=self.COLOR_SCALE["min"],
                    mid_type="percent",
                    mid_value=20,
                    mid_color=self.COLOR_SCALE["mid"],
                    end_type="percent",
                    end_value=100,
                    end_color=self.COLOR_SCALE["max"],
                ),
            )

        if "CVE Number" in list(df.columns):
            col = get_column_letter(list(df.columns).index("CVE Number") + 1)
            ws.conditional_formatting.add(
                col + "2:" + col + str(ws.max_row),
                ColorScaleRule(
                    start_type="percent",
                    start_value=1,
                    start_color=self.COLOR_SCALE["min"],
                    mid_type="percent",
                    mid_value=20,
                    mid_color=self.COLOR_SCALE["mid"],
                    end_type="percent",
                    end_value=100,
                    end_color=self.COLOR_SCALE["max"],
                ),
            )

        # Apply conditional formatting to the CISA column with CellRule
        if "Cisa Reference" in list(df.columns):
            cisa_col = get_column_letter(list(df.columns).index("Cisa Reference") + 1)
            ws.conditional_formatting.add(
                f"{cisa_col}2:{cisa_col}{ws.max_row}",
                CellIsRule(
                    operator="equal",
                    formula=['"Yes"'],
                    stopIfTrue=True,
                    fill=PatternFill(
                        start_color="00B050", end_color="00B050", fill_type="solid"
                    ),
                ),
            )

        # Adjust column width for non-verbose columns
        max_width = 25
        for col in ws.columns:
            max_length = 0
            column = col[0].column_letter
            for cell in col:
                try:
                    if len(str(cell.value)) > max_length:
                        max_length = len(cell.value)
                except:
                    pass
            adjusted_width = max_length + 5
            ws.column_dimensions[column].width = (
                adjusted_width if adjusted_width < max_width else max_width
            )

    def apply_charts(self, ws, by_scans=True):
        chart_generator = ChartGenerator(self.dataframe, self.old_cve_dfs, "")
        images = [
            chart_generator.generate_cwe_chart(),
            chart_generator.generate_capec_chart(),
            # chart_generator.generate_cve_by_group_chart(
            #     group_columns=["Server", "Priority"]
            # ),
            chart_generator.generate_cve_by_group_chart(
                group_columns=["Domain", "Server", "Priority"]
            ),
            chart_generator.generate_mean_cvss_by_group_chart(group_column="Domain"),
            chart_generator.generate_mean_cvss_by_group_chart(group_column="Server"),
            chart_generator.generate_criticity_by_group_chart(group_column="Domain"),
            chart_generator.generate_criticity_by_group_chart(group_column="Server"),
            chart_generator.generate_priority_by_group_chart(group_column="Domain"),
            chart_generator.generate_priority_by_group_chart(group_column="Server"),
            chart_generator.generate_cve_by_date_chart(),
            chart_generator.generate_cve_by_scan_chart() if by_scans else None,
            chart_generator.generate_mean_cvss_by_scan_chart() if by_scans else None,
        ]
        idx = 0
        for image in images:
            if not image:
                continue
            img = Image(image)
            col = 1 + (idx // 2) * 11
            row = 1 + (idx % 2) * 25
            letter = get_column_letter(col)
            print(f"Adding image at {col} - {letter}{row}")
            ws.add_image(img, f"{letter}{row}")
            idx += 1

    def add_table_from_df(self, ws: Worksheet, df: pd.DataFrame, name):
        table = Table(
            displayName=name.replace(" ", "_"),
            ref=f"A1:{get_column_letter(df.shape[1])}{len(df)+1}",
        )
        table.tableStyleInfo = self.STYLE
        ws.add_table(table)

    def generate_report(self, filename):
        with pd.ExcelWriter(filename, engine="openpyxl") as writer:
            for sheet_name, df in self.sheets.items():
                if df is not None:
                    print(f"Writing {sheet_name} sheet")
                    df.to_excel(writer, sheet_name=sheet_name, index=False)

        wb = load_workbook(filename)

        for sheet_name, df in self.sheets.items():
            try:
                ws = wb[sheet_name]
                print(f"Applying formatting to {sheet_name} sheet")
                self.add_table_from_df(ws, df, sheet_name)
            except:
                print(f"Sheet {sheet_name} not found")
            if df is not None:
                ws = wb[sheet_name]
                self.apply_conditional_formatting(
                    ws, df, color_scale_columns=[self.score_col]
                )

        graph_sheet = wb.create_sheet("Analysis")
        self.apply_charts(graph_sheet, by_scans=len(self.sheets) > 5)
        wb.save(filename)

    def generate_synthesis(
        self,
        filename,
        subset=["Server", "CVE Code", "Product"],
        groupby=["CVE Code", "Server", "Status"],
    ):
        """
        Generate a single excel file with all the CVE from every scan in a single sheet
        if a cve is present in multiple scans, the latest scan will be kept
        """
        synthesis_df = pd.concat([self.dataframe] + self.old_cve_dfs)
        # If a CVE is in the old scan but not in the self.dataframe, it means it's been fixed
        # The comparison is done on the rows CVE Code, Server, and Product
        # Set its status to "Fixed"
        keys = ["CVE Code", "Server", "Product"]
        for i, old_cve_df in enumerate(self.old_cve_dfs):
            fixed_cves = old_cve_df[
                ~old_cve_df.set_index(keys).index.isin(
                    self.dataframe.set_index(keys).index
                )
            ]
            fixed_cves_index = synthesis_df.set_index(keys).index.isin(
                fixed_cves.set_index(keys).index
            )
            synthesis_df.loc[fixed_cves_index, "Status"] = "Fixed"

        synthesis_df = synthesis_df.drop_duplicates(subset=subset, keep="first")
        synthesis_df = group_df(synthesis_df, self.score_col, groupby=groupby)

        with pd.ExcelWriter(filename, engine="openpyxl") as writer:
            synthesis_df.to_excel(writer, sheet_name="Synthesis", index=False)
        wb = load_workbook(filename)
        ws = wb["Synthesis"]
        self.apply_conditional_formatting(
            ws, synthesis_df, color_scale_columns=[self.score_col]
        )
        self.add_table_from_df(ws, synthesis_df, "Synthesis")
        wb.save(filename)


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


def compute_dataframe(
    dataframe, old_df, score_col, groupby=["CVE Code", "Server"]
) -> pd.DataFrame:
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


def group_df(dataframe, score_col, groupby=["CVE Code", "Server"]):
    clone = dataframe.copy()
    base_agg = {
        "Component": lambda x: " | ".join(x),
        "Product": "first",
        "Version": "first",
        "Update": lambda x: " | ".join(x),
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
        "Product",
        "Version",
    ]
    useless_cols.remove(score_col)
    agg = {}
    for obj in [base_agg, score_agg, optional_agg]:
        for col, rule in obj.items():
            if (
                col in list(clone.columns)
                and col not in useless_cols
                and col not in groupby
            ):
                agg[col] = rule
    clone = clone.groupby(groupby).agg(agg).reset_index()
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
