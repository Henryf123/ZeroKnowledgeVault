import subprocess
from pathlib import Path

def pick_files():
    script = """
    set theFiles to choose file with prompt "Select Documents to Vault" of type {"pdf", "png", "jpg", "jpeg", "txt", "csv"} with multiple selections allowed
    set thePaths to ""
    repeat with aFile in theFiles
        set thePaths to thePaths & POSIX path of aFile & "\n"
    end repeat
    return thePaths
    """
    try:
        proc = subprocess.run(
            ["osascript"],
            input=script,
            capture_output=True,
            text=True
        )
        if proc.returncode != 0:
            return [] 
        out = proc.stdout.strip()
        return [p for p in out.split("\n") if p] if out else []
    except (OSError, subprocess.SubprocessError):
        return []