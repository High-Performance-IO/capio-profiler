from textual.app import App, ComposeResult
from textual.widgets import Header, Footer, Static, Tabs, Tab, DataTable
from textual.containers import Vertical


class TraceViewer(App):
    CSS = """
    #tables_container {
        height: 1fr;
    }
    
    #trace_info {
        padding: 1 2;    
    }
    """

    def __init__(self, traces, **kwargs):
        super().__init__(**kwargs)
        self.traces = traces
        self.selected_trace = 0

    def compose(self) -> ComposeResult:
        yield Header()

        yield Tabs(*[
            Tab(f"{t['name']}@{t['pid']}", id=f"tab-{i}")
            for i, t in enumerate(self.traces)
        ], id="trace_tabs")

        with Vertical():
            yield Static("", id="trace_info")

            yield Tabs(
                Tab("GLOBAL view", id="sub-global"),
                Tab("CAPIO routines", id="sub-functions"),
                id="detail_tabs"
            )

            with Vertical(id="tables_container"):
                yield DataTable(id="global_table")
                yield DataTable(id="function_table")

        yield Footer()

    def on_mount(self):
        self.title = "CAPIO Profiler Tool"
        self.query_one("#function_table").display = False
        self.update_trace()


    def on_tabs_tab_activated(self, event: Tabs.TabActivated):
        # Top-level trace selection
        if event.tabs.id == "trace_tabs":
            tab_id = event.tab.id
            self.selected_trace = int(tab_id.split("-")[-1])
            self.update_trace()

        # Sub-tabs (show/hide tables)
        elif event.tabs.id == "detail_tabs":
            self.update_subtabs(event.tab.id)

    def update_subtabs(self, tab_id: str):
        global_table = self.query_one("#global_table")
        function_table = self.query_one("#function_table")

        if tab_id == "sub-global":
            global_table.display = True
            function_table.display = False
        else:
            global_table.display = False
            function_table.display = True

    def update_trace(self):
        trace = self.traces[self.selected_trace]

        # Info header
        self.query_one("#trace_info", Static).update(
            f"Trace: {trace['name']} | PID: {trace['pid']} | "
            f"Total Exec Time: {trace['total_exec_time']:.3f}s"
        )

        # Populate Global table
        global_table = self.query_one("#global_table", DataTable)
        global_table.clear(columns=True)
        global_table.add_columns(*trace["global"]["headers"])
        for row in trace["global"]["data"]:
            global_table.add_row(*map(str, row))

        global_table.cursor_type = "row"

        # Populate Function table
        function_table = self.query_one("#function_table", DataTable)
        function_table.clear(columns=True)
        function_table.add_columns(*trace["function"]["headers"])
        for row in trace["function"]["data"]:
            function_table.add_row(*map(str, row))

        function_table.cursor_type = "row"

