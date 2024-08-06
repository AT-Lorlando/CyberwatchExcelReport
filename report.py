from openpyxl import load_workbook
from openpyxl.styles import Font, PatternFill
from openpyxl.utils import get_column_letter
from openpyxl.formatting.rule import ColorScaleRule, CellIsRule
from openpyxl.worksheet.table import Table, TableStyleInfo
from openpyxl.drawing.image import Image
from openpyxl.worksheet.worksheet import Worksheet
import pandas as pd
from charts_generator import ChartGenerator


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

    def __init__(self, sheets, score_col="CVSS Computed Score"):
        self.sheets = sheets
        self.df_array = []
        for sheet in sheets.values():
            if sheet is not None:
                self.df_array.append(sheet)
        self.dataframe = self.df_array[0]
        self.cve_df = self.df_array[1]
        self.correctif_df = self.df_array[2]
        self.cpe_df = self.df_array[3]
        self.security_df = self.df_array[4]
        self.old_cve_dfs = self.df_array[5:] if len(self.df_array) > 5 else []
        self.old_cve_df = self.old_cve_dfs[0] if self.old_cve_dfs else None
        self.score_col = score_col

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

    def apply_charts(self, ws):
        chart_generator = ChartGenerator(self.dataframe, "")
        images = [
            chart_generator.generate_cwe_chart(),
            chart_generator.generate_capec_chart(),
            # chart_generator.generate_cve_by_group_chart(
            #     group_columns=["Server", "Priority"]
            # ),
            enerate_cve_by_group_chart(group_columns=["Domain", "Server", "Priority"]),
            # chart_generator.generate_mean_cvss_by_group_chart(group_column="Domain"),
            chart_generator.generate_mean_cvss_by_group_chart(group_column="Server"),
            # chart_generator.generate_criticity_by_group_chart(group_column="Domain"),
            chart_generator.generate_criticity_by_group_chart(group_column="Server"),
            # chart_generator.generate_priority_by_group_chart(group_column="Domain"),
            chart_generator.generate_priority_by_group_chart(group_column="Server"),
            chart_generator.generate_cve_by_date_chart(),
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
        self.apply_charts(graph_sheet)

        wb.save(filename)
