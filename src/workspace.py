import os, shutil, tempfile, subprocess, hashlib
from pathlib import Path 
from src.config import TEMP_PREFIX

def get_temp_dir() -> Path:
    return Path(tempfile.mkdtemp(prefix=TEMP_PREFIX))

def open_folder_in_finder(path: Path):
    subprocess.run(["open", str(path)], check=False)

def get_file_hash(path: Path) -> str:
    sha256 = hashlib.sha256()
    with open(path, "rb") as f:
        while chunk := f.read(8192):
            sha256.update(chunk)
    return sha256.hexdigest()

def is_safe_path(basedir: Path, target: Path) -> bool:
    try:
        return os.path.commonpath([basedir.resolve(), target.resolve()]) == str(basedir.resolve())
    except (ValueError, OSError):
        return False

def save_zip_path():
    script = 'POSIX path of (choose file name with prompt "Export Backup" default name "Vault_Backup.zip")'
    try:
        proc = subprocess.run(["osascript"], input=script, capture_output=True, text=True)
        return proc.stdout.strip() if proc.returncode == 0 and proc.stdout.strip() else None
    except (OSError, subprocess.SubprocessError):
        return None

def pick_zip_path():
    script = 'POSIX path of (choose file with prompt "Select Backup Zip" of type {"zip"})'
    try:
        proc = subprocess.run(["osascript"], input=script, capture_output=True, text=True)
        return proc.stdout.strip() if proc.returncode == 0 and proc.stdout.strip() else None
    except (OSError, subprocess.SubprocessError):
        return None

def shred_path(path: Path):
    if not path or not path.exists():
        return
    if path.is_file():
        size = path.stat().st_size
        with open(path, "wb") as f:
            f.write(os.urandom(size))
            f.flush()
            os.fsync(f.fileno()) 
        path.unlink()
    elif path.is_dir():
        for item in path.iterdir():
            shred_path(item)
        try:
            path.rmdir()
        except OSError:
            pass

def startup_cleanup():
    temp_root = Path(tempfile.gettempdir())
    for folder in temp_root.glob(f"{TEMP_PREFIX}*"):
        try:
            shutil.rmtree(folder)
        except OSError:
            pass