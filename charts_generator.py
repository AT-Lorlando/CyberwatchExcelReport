import plotly.express as px
import plotly.io as pio
import pandas as pd


# headers : Published Date;Last Reviewed Date;Domain;Surface;Server;CVE Code;CVSS Score;CVSS Temporal Score;CVSS Environmental Score;CVSS Computed Score;Criticity;Component;Product;Version;Update;Score EPSS;Maturity;Content;Vector;Environmental Vector;Temporal Vector;CWE Code;Related CWEs;Related CAPECs;Related ATK;Cisa Reference;CertFR References
# The headers are the columns of the CSV file


class ChartGenerator:
    # Constants
    MARGIN = dict(l=20, r=20, t=40, b=10)
    CRITICITY_COLORS = {
        "C1": "#FF7575",  # Red
        "C2": "#FABF8F",  # Orange
        "C3": "#FFE575",  # Yellow
        "C4": "#00B050",  # Green
        "C0": "#5A8AC6",  # Blue
    }
    CRITICITY_ORDER = ["C0", "C4", "C3", "C2", "C1"]
    PRIORITY_COLORS = {
        "P6": "#5A8AC6",  # Blue (default)
        "P5": "#8fafd8",  # Blue (default)
        "P4": "#cad9ed",  # Green
        "P3": "#fcc6c7",  # Yellow
        "P2": "#fa9395",  # Orange
        "P1": "#F8696B",  # Red
    }

    def __init__(self, df, path):
        """
        Initialize the ChartGenerator with a DataFrame and output path.

        :param df: pandas DataFrame containing the data
        :param path: str, path to save the generated charts
        """
        self.df = df
        self.path = path

    def _normalize(self, fig):
        """Normalize the layout of the figure."""
        fig.update_layout(
            autosize=False,
            margin=self.MARGIN,
        )

    def _save_figure(self, fig, filename):
        """Save the figure to the specified path and return the full path."""
        full_path = f"{self.path}/{filename}" if self.path else filename
        print(f"Saving figure to {full_path}")
        try:
            pio.write_image(fig, full_path)
        except Exception as e:
            print(f"Error saving figure: {e}")
        return full_path

    def _has_required_columns(self, required_columns):
        """Check if the DataFrame has the required columns."""
        return all(column in self.df.columns for column in required_columns)

    def generate_cwe_chart(self):
        print("Generating CWE chart")
        """Generate and save a treemap of the top CWE codes."""
        required_columns = ["CWE Code"]
        if not self._has_required_columns(required_columns):
            print(f"Missing required columns for CWE chart: {required_columns}")
            return None

        cwe_df = self.df.copy()
        replace_dict = {"NVD-CWE-noinfo": pd.NA, "NVD-CWE-Other": pd.NA}
        cwe_df.replace(replace_dict, inplace=True)
        cwe_df.dropna(subset=["CWE Code"], inplace=True)

        cwe_counts = cwe_df["CWE Code"].value_counts().head(10)
        cwe_counts.index = cwe_counts.index + " (" + cwe_counts.values.astype(str) + ")"
        cwe_df = pd.DataFrame(
            {"CWE Code": cwe_counts.index, "Frequency": cwe_counts.values}
        )
        fig = px.treemap(
            cwe_df, path=["CWE Code"], values="Frequency", title="Top CWE Codes"
        )
        self._normalize(fig)
        cwe_chart_path = self._save_figure(fig, "cwe_chart.png")
        return cwe_chart_path

    def generate_capec_chart(self):
        """Generate and save a treemap of the top related CAPECs."""
        required_columns = ["Related CAPECs"]
        if not self._has_required_columns(required_columns):
            print(f"Missing required columns for CAPEC chart: {required_columns}")
            return None

        capec_df = self.df.copy()
        capec_df.replace(
            {"NVD-CWE-noinfo": pd.NA, "NVD-CWE-Other": pd.NA}, inplace=True
        )
        capec_df.dropna(subset=["Related CAPECs"], inplace=True)

        capec_counts = capec_df["Related CAPECs"].value_counts().head(10)
        capec_counts.index = (
            capec_counts.index.str.split(" / ").str[0]
            + " ("
            + capec_counts.values.astype(str)
            + ")"
        )
        capec_df = pd.DataFrame(
            {"Related CAPECs": capec_counts.index, "Frequency": capec_counts.values}
        )

        fig = px.treemap(
            capec_df,
            path=["Related CAPECs"],
            values="Frequency",
            title="Top Related CAPECs",
        )
        self._normalize(fig)
        capec_chart_path = self._save_figure(fig, "capec_chart.png")
        return capec_chart_path

    def generate_cve_by_group_chart(self, group_columns):
        """Generate and save a sunburst chart of the domain and server distribution."""
        required_columns = group_columns
        if not self._has_required_columns(required_columns):
            print(
                f"Missing required columns for CVE by domain chart: {required_columns}"
            )
            return None

        domain_counts = self.df.groupby(group_columns).size().reset_index(name="Counts")

        fig = px.sunburst(
            domain_counts,
            path=group_columns,
            values="Counts",
            title=f"{' / '.join(group_columns)} Distribution",
        )
        fig.update_traces(textinfo="label+value")
        self._normalize(fig)
        path = self._save_figure(fig, f"cve_by_{'_'.join(group_columns)}_chart.png")
        return path

    def generate_mean_cvss_by_group_chart(self, group_column):
        """Generate and save a bar chart of the average CVSS computed score per domain."""
        required_columns = [group_column, "CVSS Computed Score"]
        if not self._has_required_columns(required_columns):
            print(
                f"Missing required columns for mean CVSS by domain chart: {required_columns}"
            )
            return None

        scores = (
            self.df.groupby(group_column)["CVSS Computed Score"]
            .mean()
            .sort_values(ascending=False)
        )
        scores_df = pd.DataFrame(
            {group_column: scores.index, "Average Score": scores.values}
        )

        fig = px.bar(
            scores_df,
            x=group_column,
            y="Average Score",
            title=f"Average CVSS Computed Score per {group_column}",
        )
        fig.update_yaxes(range=[0, 10])
        self._normalize(fig)
        path = self._save_figure(fig, f"mean_cvss_by_{group_column}_chart.png")
        return path

    def generate_criticity_by_group_chart(self, group_column):
        """Generate and save a stacked bar chart of the criticity distribution per domain."""
        required_columns = [group_column, "Criticity"]
        if not self._has_required_columns(required_columns):
            print(
                f"Missing required columns for criticity by domain chart: {required_columns}"
            )
            return None

        criticity_counts = (
            self.df.groupby([group_column, "Criticity"])
            .size()
            .reset_index(name="Counts")
        )
        criticity_counts["Criticity"] = pd.Categorical(
            criticity_counts["Criticity"], categories=self.CRITICITY_ORDER, ordered=True
        )

        fig = px.bar(
            criticity_counts,
            x=group_column,
            y="Counts",
            color="Criticity",
            title=f"Criticity Distribution per {group_column}",
            color_discrete_map=self.CRITICITY_COLORS,
            category_orders={"Criticity": self.CRITICITY_ORDER},
        )
        fig.for_each_trace(
            lambda trace: trace.update(
                legendgroup=trace.name,
                showlegend=True,
                legendrank=self.CRITICITY_ORDER.index(trace.name),
            )
        )
        self._normalize(fig)
        path = self._save_figure(fig, f"criticity_by_{group_column}_chart.png")
        return path

    def generate_priority_by_group_chart(self, group_column):
        """Generate and save a stacked bar chart of the priority distribution per domain."""
        required_columns = [group_column, "Priority"]
        if not self._has_required_columns(required_columns):
            print(
                f"Missing required columns for priority by domain chart: {required_columns}"
            )
            return None

        priority_counts = (
            self.df.groupby([group_column, "Priority"])
            .size()
            .reset_index(name="Counts")
        )
        priority_counts["Priority"] = pd.Categorical(
            priority_counts["Priority"],
            categories=list(self.PRIORITY_COLORS.keys()),
            ordered=True,
        )

        fig = px.bar(
            priority_counts,
            x=group_column,
            y="Counts",
            color="Priority",
            title=f"Priority Distribution per {group_column}",
            color_discrete_map=self.PRIORITY_COLORS,
            category_orders={"Priority": list(self.PRIORITY_COLORS.keys())},
        )
        fig.for_each_trace(
            lambda trace: trace.update(
                legendgroup=trace.name,
                showlegend=True,
                legendrank=list(self.PRIORITY_COLORS.keys())[::-1].index(trace.name),
            )
        )
        self._normalize(fig)
        path = self._save_figure(fig, f"priority_by_{group_column}_chart.png")
        return path

    # A graph with a line of number of cve for each day with "Publication Date" as x-axis and "Number of CVEs" as y-axis
    def generate_cve_by_date_chart(self):
        required_columns = ["Published Date"]
        if not self._has_required_columns(required_columns):
            print(f"Missing required columns for CVE by date chart: {required_columns}")
            return None

        # group by month and year
        cve_by_date = (
            self.df.groupby("Published Date").size().reset_index(name="Number of CVEs")
        )
        cve_by_date_df = pd.DataFrame(cve_by_date)
        # drop "Unknown" values
        cve_by_date_df = cve_by_date_df[cve_by_date_df["Published Date"] != "Unknown"]
        # date = YYYY-MM-DD
        # Group by year-mm to simplify the chart
        cve_by_date_df["Published Date"] = (
            cve_by_date_df["Published Date"].str.split("-").str[0]
            + "-"
            + cve_by_date_df["Published Date"].str.split("-").str[1]
        )
        cve_by_date_df = cve_by_date_df.groupby("Published Date").sum().reset_index()

        # smooth the line
        cve_by_date_df["Number of CVEs"] = (
            cve_by_date_df["Number of CVEs"].rolling(window=2).mean()
        )
        fig = px.line(
            cve_by_date_df,
            x="Published Date",
            y="Number of CVEs",
            title="Number of CVEs by Date",
        )

        self._normalize(fig)
        path = self._save_figure(fig, "cve_by_date_chart.png")
        return path

    # with every df in old_dfs, we can generate a chart with the number of cve for each priority in each scans (a df = a scan)
    # the x-axis is the df index and the y-axis is the number of cve of the priority
    # Create a new df with the number of cve for each priority in each scan
    # A line = a priority
    # with "Number of CVEs" as y-axis and "Scan" as x-axis
    # The title is "Number of CVEs by Priority in each Scan"
    # Add value on the line
    def generate_cve_by_scan_chart(self):
        every_df = [self.df] + self.old_dfs.copy()
        every_df = every_df[::-1]
        data = []
        for i, df in enumerate(every_df):
            # Count P0 even if there is no P0 cve
            priority_counts = (
                df["Priority"]
                .value_counts()
                .reindex(list(self.PRIORITY_COLORS.keys()), fill_value=0)
            )
            priority_counts = priority_counts.reset_index()
            priority_counts.columns = ["Priority", "Number of CVEs"]
            priority_counts["Scan"] = f"Scan {1+i-len(every_df)}"
            data.append(priority_counts)

        data = pd.concat(data)
        fig = px.line(
            data,
            x="Scan",
            y="Number of CVEs",
            color="Priority",
            title="Number of CVEs by Priority in each Scan",
            text="Number of CVEs",
        )
        fig.update_traces(textposition="top center")
        fig.update_yaxes(type="log")
        fig.update_yaxes(tickvals=[10**i for i in range(1, 8)])
        # Set the colors of the lines to the priority colors
        for i, priority in enumerate(self.PRIORITY_COLORS.keys()):
            fig.for_each_trace(
                lambda trace: trace.update(
                    line=dict(color=self.PRIORITY_COLORS[trace.name])
                )
            )
        self._normalize(fig)
        path = self._save_figure(fig, "cve_by_scan_chart.png")
        return path

    # with every df in old_dfs, we can generate a chart with the mean of the cvss computed score for each scan
    # the x-axis is the df index and the y-axis is the mean of the cvss computed score
    def generate_mean_cvss_by_scan_chart(self):
        every_df = [self.df] + self.old_dfs.copy()
        every_df = every_df[::-1]
        data = []
        for i, df in enumerate(every_df):
            # round the mean to 2 decimals
            mean_cvss = df["CVSS Computed Score"].mean()
            mean_cvss = round(mean_cvss, 2)
            data.append({"Scan": f"Scan {1+i-len(every_df)}", "Mean CVSS": mean_cvss})
        data = pd.DataFrame(data)
        fig = px.line(
            data, x="Scan", y="Mean CVSS", title="Mean CVSS by Scan", text="Mean CVSS"
        )
        fig.update_traces(textposition="top center")
        fig.update_yaxes(range=[0, 10])

        self._normalize(fig)
        path = self._save_figure(fig, "mean_cvss_by_scan_chart.png")
        return path
