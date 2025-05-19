import sys
import os
import json
import requests
from pathlib import Path
from PyQt5.QtWidgets import QApplication, QMessageBox
from PyQt5.QtCore import QTimer
from main_window import MainWindow
from paths import BASE_DIR

def ensure_known_web_storage():
    os.makedirs(BASE_DIR / "storage", exist_ok=True)
    known_web_path = BASE_DIR / "storage" / "known_web.json"
    if not os.path.isfile(known_web_path):
        with open(known_web_path, 'w') as f:
            json.dump({}, f)
            
def check_known_web_content():
    known_web_path = BASE_DIR / "storage" / "known_web.json"
    try:
        with open(known_web_path, 'r') as f:
            data = json.load(f)
            if not data:
                return False
            return True
    except (json.JSONDecodeError, FileNotFoundError) as e:
        return False

def is_captive_portal():
    # Windows URL
    url = "http://www.msftconnecttest.com/connecttest.txt"
    url_legacy = "http://www.msftncsi.com/ncsi.txt"
    expected_resp = "Microsoft Connect Test"
    expected_resp_legacy = "Microsoft NCSI"
    try:
        response = requests.get(url, allow_redirects=True, timeout=5)
        response_legacy = requests.get(url_legacy, allow_redirects=True, timeout=5)
        text_response = response.text
        text_response_legacy = response_legacy.text
        if text_response != expected_resp or text_response_legacy != expected_resp_legacy:
            return True
        else:
            return False
    except requests.RequestException as e:
        return False

def main():
    ensure_known_web_storage()
    app = QApplication(sys.argv)
    
    has_known_webs = check_known_web_content()
    is_captive = is_captive_portal()
    
    if is_captive and has_known_webs:
        window = MainWindow()
        window.show()
        sys.exit(app.exec_())

if __name__ == "__main__":
    main()