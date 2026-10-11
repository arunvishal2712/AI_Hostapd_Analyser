"""Shared locations.

RUNTIME holds the heavy, machine-specific parts (portable Node, Flowise
node_modules, Flowise database + login). It lives outside the project
folder (Windows: %LOCALAPPDATA%\\HostapdAIAnalyzer) so Documents/OneDrive
sync, Controlled Folder Access and indexing never touch 1500+ npm packages.
Override with the HOSTAPD_RUNTIME environment variable.
"""
import os
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent


def runtime_dir() -> Path:
    if os.environ.get("HOSTAPD_RUNTIME"):
        return Path(os.environ["HOSTAPD_RUNTIME"])
    if os.environ.get("LOCALAPPDATA"):
        return Path(os.environ["LOCALAPPDATA"]) / "HostapdAIAnalyzer"
    return ROOT / ".runtime"


RUNTIME = runtime_dir()
FLOWISE_DATA = RUNTIME / "flowise_data"
FLOWISE_LOGIN_FILE = FLOWISE_DATA / "login.json"
CURRENT_TEST_FILE = ROOT / "output" / "current_test.json"
