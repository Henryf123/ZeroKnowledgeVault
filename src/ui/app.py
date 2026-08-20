import uuid, os, io, json, zipfile, sqlite3, shutil
from pathlib import Path
from textual import work
from textual.app import App, ComposeResult
from textual.widgets import Header, Footer, DataTable, Input, Button, Label, Select, Static
from textual.containers import Horizontal, Vertical
from textual.binding import Binding
from cryptography.exceptions import InvalidTag

from src.ui.screens import LoginScreen, AddRecordModal, ConfirmDeleteModal
from src.ui.file_picker import pick_files
from src.crypto import (
    derive_kek,
    encrypt_payload,
    decrypt_payload,
    stream_encrypt,
    stream_decrypt,
    _derive_backup_key,
)
from src.config import STORAGE_DIR, DB_PATH, BASE_DIR
from src.workspace import (
    get_temp_dir,
    open_folder_in_finder,
    shred_path,
    save_zip_path,
    pick_zip_path,
    get_file_hash,
    is_safe_path,
)
from src.database import get_db, checkpoint_db

class VaultApp(App):
    BINDINGS = [
        Binding("ctrl+q", "quit", "Quit", show=True),
        Binding("space", "toggle_selection", "Mark", show=False),
        Binding("a", "select_all", "Select All", show=False),
        Binding("d", "delete_selected", "Delete", show=False),
        Binding("v", "view_selected", "View", show=False),
    ]

    CSS = """
    #sidebar { width: 32; border-right: tall $primary; padding: 0 1; background: $surface; overflow-y: auto; }
    DataTable { width: 1fr; border: tall $primary; margin: 1; }
    .sidebar-section { border: solid $primary; padding: 0 1; margin-bottom: 1; height: auto; }
    .sidebar-label { text-style: bold; color: $accent; margin: 0; padding: 0; }
    Button { margin-bottom: 0; height: 1; border: none; }
    Input { margin-bottom: 0; border: tall $primary; height: 3; }
    Select { margin-bottom: 0; border: tall $primary; height: 3; }
    #selected_count { color: $accent; text-align: center; margin-bottom: 0; border-bottom: hkey $primary; }
    #login_box, #delete_modal_box, #import_modal_box { width: 60; height: auto; border: thick $primary; padding: 1 2; background: $surface; }
    #login_header, #modal_header { text-align: center; text-style: bold; margin-bottom: 1; border-bottom: double $primary; }
    """

    def __init__(self, db_conn):
        super().__init__()
        self.db = db_conn
        self.dek = None
        self.active_temp_dir = None
        self.marked_uuids = set()
        self.search_mode = "title"

    def on_mount(self):
        self.push_screen(LoginScreen())

    def attempt_login(self, password):
        try:
            cursor = self.db.cursor()
            cursor.execute("SELECT pbkdf2_salt, encrypted_dek FROM vault_config")
            row = cursor.fetchone()
            
            if not row:
                salt = os.urandom(16)
                kek = derive_kek(password, salt)
                dek = os.urandom(32)
                enc_dek = encrypt_payload(dek, kek, b"vault-master-key")
                cursor.execute("INSERT INTO vault_config (pbkdf2_salt, encrypted_dek) VALUES (?, ?)", (salt, enc_dek))
                self.db.commit()
                self.dek = dek
            else:
                kek = derive_kek(password, row['pbkdf2_salt'])
                self.dek = decrypt_payload(row['encrypted_dek'], kek, b"vault-master-key")
            
            if self.screen.id != "_default":
                self.pop_screen()
            self.refresh_table()
            
        except InvalidTag:
            self.notify("Invalid Master Password", severity="error")
        except sqlite3.Error as e:
            self.notify(f"Database Error: {e}", severity="error")

    def compose(self) -> ComposeResult:
        yield Header()
        with Horizontal():
            with Vertical(id="sidebar"):
                with Vertical(classes="sidebar-section"):
                    yield Label("SEARCH", classes="sidebar-label")
                    yield Input(placeholder="Filter...", id="search_input")
                    yield Select(options=[("Title", "title"), ("Company", "company"), ("Tag", "tag"), ("Year", "year")], value="title", id="filter_select")
                with Vertical(classes="sidebar-section"):
                    yield Label("SELECTION", classes="sidebar-label")
                    yield Label("Selected: 0", id="selected_count")
                    yield Button("View Marked (V)", variant="primary", id="view_btn")
                    yield Button("Mark (Space)", id="mark_btn")
                    yield Button("Select All (A)", id="select_all_btn")
                    yield Button("Delete Selected", variant="error", id="delete_btn")
                with Vertical(classes="sidebar-section"):
                    yield Label("VAULT ACTIONS", classes="sidebar-label")
                    yield Button("Import Files", variant="success", id="import_btn")
                    yield Button("Export Backup", id="export_btn")
                    yield Button("Quit Vault", variant="default", id="quit_btn")
            yield DataTable(id="record_table")
        yield Footer()

    def refresh_table(self, search_term=""):
        if self.dek is None:
            return

        table = self.query_one(DataTable)
        table.cursor_type = "row"
        table.clear(columns=True)
        table.add_columns("SEL", "Year", "Company", "Title", "Tags")
        
        try:
            cursor = self.db.cursor()
            cursor.execute("SELECT file_uuid, encrypted_metadata FROM records")
            for row in cursor.fetchall():
                f_uuid = row['file_uuid']
                try:
                    meta_bytes = decrypt_payload(row['encrypted_metadata'], self.dek, f_uuid.encode())
                    meta = json.loads(meta_bytes.decode('utf-8'))
                    
                    term = (search_term or "").lower()
                    val = str(meta.get(self.search_mode, '')).lower()
                    
                    if not term or term in val:
                        mark = "[X]" if f_uuid in self.marked_uuids else "[ ]"
                        table.add_row(
                            mark, 
                            meta.get('year', '-'), 
                            meta.get('company', '-'), 
                            meta.get('title', 'Untitled'), 
                            meta.get('tags', ''), 
                            key=f_uuid
                        )
                except (InvalidTag, json.JSONDecodeError, KeyError, UnicodeDecodeError):
                    table.add_row("!", "ERR", "CORRUPT", f"ID: {f_uuid[:8]}", "Decryption Failed")
        except sqlite3.Error as e:
            self.notify(f"Database Query Failed: {e}", severity="error")
            
        self.query_one("#selected_count", Label).update(f"Selected: {len(self.marked_uuids)}")

    def on_input_changed(self, event: Input.Changed):
        if event.input.id == "search_input": 
            self.refresh_table(event.value)

    def on_select_changed(self, event: Select.Changed):
        if self.dek is None:
            return
            
        if event.select.id == "filter_select":
            self.search_mode = str(event.value)
            search_input = self.query_one("#search_input", Input).value
            self.refresh_table(search_input)

    @work
    async def on_button_pressed(self, event: Button.Pressed):
        btn_id = event.button.id
        if btn_id == "mark_btn": self.action_toggle_selection()
        elif btn_id == "view_btn": self.action_view_selected()
        elif btn_id == "delete_btn": await self.action_delete_selected()
        elif btn_id == "export_btn": self.export_vault()
        elif btn_id == "import_btn":
            if not self.dek: return
            paths = pick_files()
            if not paths: return
            for p in paths:
                meta = await self.push_screen_wait(AddRecordModal(Path(p).name))
                if meta: self.ingest_file(Path(p), meta)
            self.refresh_table()
        elif btn_id == "quit_btn": self.app.exit()

    def action_toggle_selection(self):
        table = self.query_one(DataTable)
        try:
            row_key = table.coordinate_to_cell_key(table.cursor_coordinate).row_key
            f_uuid = str(row_key.value)
            if f_uuid in self.marked_uuids: self.marked_uuids.remove(f_uuid)
            else: self.marked_uuids.add(f_uuid)
            self.refresh_table(self.query_one("#search_input", Input).value)
        except (KeyError, IndexError, ValueError):
            pass

    def action_select_all(self):
        table = self.query_one(DataTable)
        for row_key in table.rows:
            self.marked_uuids.add(str(row_key.value))
        self.refresh_table(self.query_one("#search_input", Input).value)

    async def action_delete_selected(self):
        uuids = list(self.marked_uuids)
        if not uuids: return
        if await self.push_screen_wait(ConfirmDeleteModal(len(uuids))):
            for f_uuid in uuids:
                shred_path(STORAGE_DIR / f"{f_uuid}.bin")
                self.db.execute("DELETE FROM records WHERE file_uuid = ?", (f_uuid,))
            self.db.commit()
            self.marked_uuids.clear()
            self.refresh_table()
            self.notify(f"Deleted {len(uuids)} files")

    def action_view_selected(self):
        if not self.marked_uuids:
            try:
                row_key = self.query_one(DataTable).coordinate_to_cell_key(self.query_one(DataTable).cursor_coordinate).row_key
                self.process_view_request([str(row_key.value)])
            except (KeyError, IndexError, ValueError):
                self.notify("No selection")
            return
        self.process_view_request(list(self.marked_uuids))

    def export_vault(self):
        if not self.dek:
            self.notify("Must be logged in to export", severity="error")
            return

        checkpoint_db(self.db)
        dest = save_zip_path()
        if not dest: return
        
        try:
            db_hash = get_file_hash(DB_PATH)
            
            zip_buffer = io.BytesIO()
            with zipfile.ZipFile(zip_buffer, 'w', zipfile.ZIP_DEFLATED) as zf:
                zf.write(DB_PATH, arcname="vault.db")
                zf.writestr("manifest.txt", db_hash)
                for f in STORAGE_DIR.glob("*.bin"):
                    zf.write(f, arcname=f"encrypted_storage/{f.name}")
            
            zip_bytes = zip_buffer.getvalue()

            cursor = self.db.cursor()
            cursor.execute("SELECT pbkdf2_salt, encrypted_dek FROM vault_config")
            row = cursor.fetchone()
            if not row:
                self.notify("Vault configuration missing", severity="error")
                return

            pbkdf2_salt = row['pbkdf2_salt']
            enc_dek = row['encrypted_dek']

            backup_salt = os.urandom(16)
            backup_key = _derive_backup_key(self.dek, backup_salt)
            enc_zip = encrypt_payload(zip_bytes, backup_key, b"backup-envelope")
            
            enc_dek_len = len(enc_dek).to_bytes(2, 'big')
            payload = pbkdf2_salt + enc_dek_len + enc_dek + backup_salt + enc_zip
            
            with open(dest, "wb") as f:
                f.write(payload)
                
            self.notify("Encrypted Backup Exported")
        except (sqlite3.Error, OSError) as e:
            self.notify(f"Export Failed: {e}", severity="error")

    def restore_vault(self):
        zip_path = pick_zip_path()
        if not zip_path: return
        password = self.query_one("#password_input", Input).value
        if not password:
            self.notify("Enter password first to decrypt backup", severity="warning")
            return

        try:
            data = Path(zip_path).read_bytes()
            if len(data) < 34:
                raise ValueError("Corrupted or invalid backup package")

            pbkdf2_salt = data[:16]
            enc_dek_len = int.from_bytes(data[16:18], 'big')
            pos = 18
            enc_dek = data[pos:pos + enc_dek_len]
            pos += enc_dek_len
            backup_salt = data[pos:pos + 16]
            pos += 16
            encrypted_payload = data[pos:]

            kek = derive_kek(password, pbkdf2_salt)
            dek = decrypt_payload(enc_dek, kek, b"vault-master-key")
            backup_key = _derive_backup_key(dek, backup_salt)
            dec_zip_bytes = decrypt_payload(encrypted_payload, backup_key, b"backup-envelope")
            
            zip_buffer = io.BytesIO(dec_zip_bytes)
            temp_extract_dir = get_temp_dir()
            
            try:
                with zipfile.ZipFile(zip_buffer, 'r') as zf:
                    for m in zf.infolist():
                        target_path = temp_extract_dir / m.filename
                        if not is_safe_path(temp_extract_dir, target_path):
                            raise ValueError(f"Security: Malicious path detected in archive ({m.filename})")
                        zf.extract(m, path=temp_extract_dir)

                manifest_path = temp_extract_dir / "manifest.txt"
                temp_db_path = temp_extract_dir / "vault.db"

                if not manifest_path.exists() or not temp_db_path.exists():
                    raise ValueError("Integrity Failure: Missing manifest or database in backup")

                manifest_hash = manifest_path.read_text().strip()
                if manifest_hash != get_file_hash(temp_db_path):
                    raise ValueError("Integrity Failure: Database hash mismatch with manifest")

                if self.db:
                    try:
                        checkpoint_db(self.db)
                        self.db.close()
                    except sqlite3.Error:
                        pass

                shutil.copy2(temp_db_path, DB_PATH)

                temp_storage = temp_extract_dir / "encrypted_storage"
                if temp_storage.exists() and temp_storage.is_dir():
                    for bin_file in temp_storage.glob("*.bin"):
                        shutil.copy2(bin_file, STORAGE_DIR / bin_file.name)
            finally:
                shred_path(temp_extract_dir)

            self.db = get_db()
            self.dek = None
            self.marked_uuids.clear()
            self.attempt_login(password)
            self.notify("Vault Restored Successfully")

        except InvalidTag:
            if not self.db: self.db = get_db()
            self.notify("Wrong password or corrupted backup", severity="error")
        except (ValueError, OSError, sqlite3.Error, zipfile.BadZipFile) as e:
            if not self.db: self.db = get_db()
            self.notify(f"Restore Failed: {e}", severity="error")
            
    def process_view_request(self, uuids: list):
        if not self.active_temp_dir: self.active_temp_dir = get_temp_dir()
        for f_uuid in uuids:
            try:
                cursor = self.db.cursor()
                cursor.execute("SELECT encrypted_metadata FROM records WHERE file_uuid = ?", (f_uuid,))
                row = cursor.fetchone()
                if not row: continue

                meta = json.loads(decrypt_payload(row['encrypted_metadata'], self.dek, f_uuid.encode()).decode('utf-8'))
                dec_path = self.active_temp_dir / f"{meta['title']}{meta.get('file_extension', '')}"
                stream_decrypt(STORAGE_DIR / f"{f_uuid}.bin", dec_path, self.dek, f_uuid)
            except (InvalidTag, json.JSONDecodeError, sqlite3.Error, OSError) as e:
                self.notify(f"View Failure: {e}", severity="error")
        open_folder_in_finder(self.active_temp_dir)

    def ingest_file(self, path: Path, meta: dict):
        file_uuid = str(uuid.uuid4())
        try:
            meta_json = json.dumps({
                "title": meta['title'] or path.stem,
                "company": meta['company'],
                "year": meta['year'],
                "tags": meta['tags'],
                "file_extension": path.suffix
            }).encode('utf-8')
            
            enc_meta = encrypt_payload(meta_json, self.dek, file_uuid.encode())
            stream_encrypt(path, STORAGE_DIR / f"{file_uuid}.bin", self.dek, file_uuid)
            
            self.db.execute("INSERT INTO records (file_uuid, encrypted_metadata) VALUES (?, ?)", (file_uuid, enc_meta))
            self.db.commit()
        except (sqlite3.Error, OSError, InvalidTag) as e:
            self.notify(f"Import Error: {e}", severity="error")

    def action_quit(self): self.app.exit()