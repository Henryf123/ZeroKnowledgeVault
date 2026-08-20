import os 
import sys 
from pathlib import Path 

BASE_DIR = Path(__file__).parent.parent
STORAGE_DIR = BASE_DIR / "encrypted_storage"
DB_PATH = BASE_DIR / "vault.db"
TEMP_PREFIX = "myvault_temp_"

STORAGE_DIR.mkdir(exist_ok=True)

IS_MAC = sys.platform == "darwin"