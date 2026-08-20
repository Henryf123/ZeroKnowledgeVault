from textual.screen import Screen 
from textual.widgets import Header, Footer, Button, Input, Label, Static
from textual.containers import Vertical, Horizontal, Grid, Center
from textual.app import ComposeResult

class LoginScreen(Screen):
    def compose(self) -> ComposeResult:
        with Center():
            yield Vertical(
                Static("VAULT LOGIN", id="login_header"),
                Label("Master Password"),
                Input(placeholder="Enter password to unlock...", password=True, id="password_input"),
                Vertical(
                    Button("Unlock Vault", variant="primary", id="login_btn"),
                    Button("Restore Backup (.zip)", variant="default", id="restore_btn"),
                    id="login_buttons"
                ),
                id="login_box"
            )

    def on_button_pressed(self, event: Button.Pressed) -> None:
        if event.button.id == "login_btn":
            pw = self.query_one("#password_input", Input).value
            if pw:
                self.app.attempt_login(pw)
        elif event.button.id == "restore_btn":
            self.app.restore_vault()

class ConfirmDeleteModal(Screen):
    def __init__(self, count: int):
        super().__init__()
        self.count = count

    def compose(self) -> ComposeResult:
        with Center():
            yield Vertical(
                Static("CONFIRM DELETION", id="modal_header"),
                Label(f"Are you sure you want to permanently delete {self.count} selected file(s)?"),
                Label("This action cannot be undone and the data will be shredded.", id="modal_warning"),
                Horizontal(
                    Button("Delete", variant="error", id="confirm_delete_btn"),
                    Button("Cancel", variant="default", id="cancel_delete_btn"),
                    classes="modal_buttons"
                ),
                id="delete_modal_box"
            )

    def on_button_pressed(self, event: Button.Pressed) -> None:
        if event.button.id == "confirm_delete_btn":
            self.dismiss(True)
        else:
            self.dismiss(False)

class AddRecordModal(Screen):
    def __init__(self, file_name: str):
        super().__init__()
        self.file_name = file_name

    def compose(self) -> ComposeResult:
        with Center():
            yield Vertical(
                Static("IMPORT DOCUMENT", id="modal_header"),
                Label(f"File: {self.file_name}"),
                Input(placeholder="Title (Blank = keep original name)", id="m_title", max_length=100),
                Input(placeholder="Company", id="m_company", max_length=100),
                Input(placeholder="Tax Year (Numbers only)", id="m_year", max_length=4),
                Input(placeholder="Tags (comma separated)", id="m_tags", max_length=200),
                Horizontal(
                    Button("Save to Vault", variant="success", id="save_meta"),
                    Button("Cancel", variant="error", id="cancel_meta"),
                    classes="modal_buttons"
                ),
                id="import_modal_box"
            )

    def on_button_pressed(self, event: Button.Pressed) -> None:
        if event.button.id == "save_meta":
            title = self.query_one("#m_title", Input).value.strip()
            company = self.query_one("#m_company", Input).value.strip()
            year = self.query_one("#m_year", Input).value.strip()
            tags = self.query_one("#m_tags", Input).value.strip()

            if year and not year.isdigit():
                self.app.notify("Tax Year must be a number", severity="error")
                return
            
            if not company:
                self.app.notify("Company name is required", severity="error")
                return

            self.dismiss({
                "title": title,
                "company": company,
                "year": year,
                "tags": tags
            })
        else:
            self.dismiss(None)