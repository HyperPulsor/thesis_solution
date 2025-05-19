import sys
import json
import os
from PyQt5.QtWidgets import QApplication, QWidget, QVBoxLayout, QPushButton, QLabel, QMessageBox, QComboBox, QHBoxLayout
from PyQt5.QtGui import QIcon
from edit_window import EditWindow
from delete_window import DeleteWindow
from paths import BASE_DIR

def ensure_known_web_storage():
    os.makedirs(BASE_DIR / "storage", exist_ok=True)
    known_web_path = BASE_DIR / "storage" / "known_web.json"
    if not os.path.isfile(known_web_path):
        with open(known_web_path, 'w') as f:
            json.dump({}, f)

class ConfigTool(QWidget):
    def __init__(self):
        super().__init__()
        self.setWindowTitle("Configuration Tool")
        self.setWindowIcon(QIcon("static/favicon.png"))
        self.setGeometry(200, 200, 500, 150)

        self.edit_window = EditWindow()
        self.edit_window.website_saved.connect(self.load_known_sites)
        
        self.delete_window = DeleteWindow(self.edit_window)
        self.delete_window.website_deleted.connect(self.load_known_sites)

        self.button_edit = QPushButton("Save Trusted Domain")
        self.button_edit.clicked.connect(self.toggle_edit_window)
        
        self.button_set_active = QPushButton("Set as Active")
        self.button_set_active.clicked.connect(self.set_active_domain)

        self.button_delete = QPushButton("Delete Trusted Domain")
        self.button_delete.clicked.connect(self.toggle_delete_window)
        
        self.active_domain_label = QLabel("Current Active Domain!")
        self.active_domain_label.setStyleSheet("""
            font-weight: bold;
            color: #2e7d32; /* Green */
            background-color: #e8f5e9;
            padding: 6px;
            border: 1px solid #c8e6c9;
            border-radius: 4px;
        """)
        self.active_domain_label.hide()
        
        self.dropdown = QComboBox()
        self.load_known_sites()
        self.dropdown.currentIndexChanged.connect(self.on_dropdown_change)
        
        self.network_notice = QLabel("Note: Make sure you are connected to the internet when saving trusted Domains.")
        self.network_notice.setStyleSheet("font-weight: bold;")
        self.network_notice.setWordWrap(True)
        
        self.button_layout = QHBoxLayout()
        self.button_layout.setContentsMargins(0, 0, 0, 0)
        self.button_layout.addWidget(self.dropdown, stretch=4)
        self.button_layout.addWidget(self.button_set_active, stretch=1)
        
        self.button_container = QWidget()
        self.button_container.setLayout(self.button_layout)

        layout = QVBoxLayout()
        layout.addWidget(self.network_notice)
        layout.addWidget(self.button_container)
        layout.addWidget(self.active_domain_label)
        layout.addWidget(self.button_edit)
        layout.addWidget(self.button_delete)

        self.setLayout(layout)
        
    def get_known_webs(self):
        known_web_path = BASE_DIR / "storage" / "known_web.json"
        with open(known_web_path) as f:
            return json.load(f)
        
    def on_dropdown_change(self, index):
        selected_domain = self.dropdown.itemText(index)
        known_webs = self.get_known_webs()
        
        if selected_domain in known_webs and known_webs[selected_domain].get("active"):
            self.active_domain_label.show()
        else:
            self.active_domain_label.hide()

    def toggle_edit_window(self):
        self.delete_window.hide()
        self.edit_window.show()

    def toggle_delete_window(self):
        self.edit_window.hide()
        self.delete_window.show()
        
    def set_active_domain(self):
        known_web_path = BASE_DIR / "storage" / "known_web.json"
        selected_domain = self.dropdown.currentText()
        if not selected_domain:
            QMessageBox.warning(self, "Warning", "Please select a valid domain.")
            return
        try:
            with open(known_web_path, "r") as f:
                known_webs = json.load(f)

            for domain in known_webs:
                known_webs[domain]["active"] = (domain == selected_domain)

            with open(known_web_path, "w") as f:
                json.dump(known_webs, f, indent=2)

            QMessageBox.information(self, "Success", f"'{selected_domain}' is now the active domain.")
            self.active_domain_label.show()
        except Exception as e:
            QMessageBox.critical(self, "Error", f"Failed to set active domain:\n{e}")
            
    def load_known_sites(self):
        known_web_path = BASE_DIR / "storage" / "known_web.json"
        self.dropdown.clear()
        active_domain = None
        try:
            with open(known_web_path, 'r') as f:
                known_webs = json.load(f)
            for domain in known_webs.keys():
                self.dropdown.addItem(domain)
                if known_webs[domain].get("active"):
                    active_domain = domain
            if active_domain:
                self.dropdown.setCurrentText(active_domain)
                self.active_domain_label.show()
            else:
                self.active_domain_label.hide()
        except (FileNotFoundError, json.JSONDecodeError):
            self.dropdown.addItem("No known sites found")
        self.update_set_active_button_state()
        
    def update_set_active_button_state(self):
        text = self.dropdown.currentText().strip()
        if text == "":
            self.button_set_active.setEnabled(False)
        else:
            self.button_set_active.setEnabled(True)

if __name__ == "__main__":
    ensure_known_web_storage()
    app = QApplication(sys.argv)
    tool = ConfigTool()
    tool.show()
    sys.exit(app.exec_())