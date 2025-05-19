import sys
from pathlib import Path

def get_base_dir():
    if getattr(sys, 'frozen', False):
        # Running as a compiled .exe
        return Path(sys.executable).resolve().parent
    else:
        # Running from script
        return Path(__file__).resolve().parent

BASE_DIR = get_base_dir()