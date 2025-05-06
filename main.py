import sys
import os
import json
from PyQt5.QtWidgets import QApplication
from main_window import MainWindow

def ensure_known_web_storage():
    os.makedirs("storage", exist_ok=True)
    known_web_path = "storage/known_web.json"
    if not os.path.isfile(known_web_path):
        with open(known_web_path, 'w') as f:
            json.dump({}, f)

def main():
    ensure_known_web_storage()
    app = QApplication(sys.argv)
    window = MainWindow()
    window.show()
    sys.exit(app.exec_())

if __name__ == "__main__":
    main()