import sys
import os
import json
import requests
from PyQt5.QtWidgets import QApplication, QMessageBox
from PyQt5.QtCore import QTimer
from main_window import MainWindow

def ensure_known_web_storage():
    os.makedirs("storage", exist_ok=True)
    known_web_path = "storage/known_web.json"
    if not os.path.isfile(known_web_path):
        with open(known_web_path, 'w') as f:
            json.dump({}, f)

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
        print("Error:", e)
        return False


def main():
    ensure_known_web_storage()
    app = QApplication(sys.argv)

    if not is_captive_portal():
        confirm = QMessageBox.question(
            None,
            "No Captive Portal",
            "No captive portal detected. Do you want to configure Captive Portal Authenticator?",
            QMessageBox.Yes | QMessageBox.No
        )
        if confirm == QMessageBox.No:
            sys.exit(0)
            
    window = MainWindow()
    window.show()
    sys.exit(app.exec_())

if __name__ == "__main__":
    main()