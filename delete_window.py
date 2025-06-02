import os
import json
from PyQt5.QtWidgets import QWidget, QLabel, QComboBox, QTextEdit, QPushButton, QVBoxLayout, QMessageBox
from PyQt5.QtGui import QIcon
from PyQt5.QtCore import pyqtSignal
from edit_window import EditWindow
from paths import BASE_DIR

class DeleteWindow(QWidget):
    website_deleted = pyqtSignal()
    def __init__(self, shared_edit_window: EditWindow):
        super().__init__()
        self.setWindowTitle("Delete Known Domains")
        self.setWindowIcon(QIcon(f"{BASE_DIR}/static/favicon.png"))
        self.setGeometry(150, 150, 400, 300)
        
        self.window_edit = shared_edit_window
        self.window_edit.website_saved.connect(self.load_known_domain)
        
        self.msg_box = QMessageBox()
        self.msg_box.setIcon(QMessageBox.Critical)
        self.msg_box.setText("Error")
        self.msg_box.setInformativeText("Error.")
        self.msg_box.setWindowTitle("Error")
        
        self.delete_button = QPushButton("Delete")
        self.delete_button.clicked.connect(self.delete_known_web)
        self.delete_button.setEnabled(False)
        
        self.dropdown_label = QLabel("Select Known Domain:")
        self.dropdown_label.setStyleSheet("font-weight: bold;")
        
        self.dropdown = QComboBox()
        self.text_area = QTextEdit()
        self.dropdown.currentTextChanged.connect(self.fetch_selected_domain)
        self.load_known_domain()
    
        self.text_area.setReadOnly(True)
        
        self.ssl_info_label = QLabel("SSL Information:")
        self.ssl_info_label.setStyleSheet("font-weight: bold;")
        self.ssl_info_label.setBuddy(self.text_area)
        
        self.layout = QVBoxLayout()
        self.layout.addWidget(self.dropdown_label)
        self.layout.addWidget(self.dropdown)
        self.layout.addWidget(self.ssl_info_label)
        self.layout.addWidget(self.text_area)
        self.layout.addWidget(self.delete_button)
        self.setLayout(self.layout)
    
    def load_known_domain(self):
        known_web_path = BASE_DIR / "storage" / "known_web.json"
        self.dropdown.clear()
        try:
            with open(known_web_path, 'r') as f:
                known_webs = json.load(f)
            for domain in known_webs.keys():
                self.dropdown.addItem(domain)
        except (FileNotFoundError, json.JSONDecodeError):
            self.dropdown.addItem("No known sites found")
    
    def get_known_webs(self):
        known_web_path = BASE_DIR / "storage" / "known_web.json"
        with open(known_web_path) as f:
            return json.load(f)
    
    def fetch_selected_domain(self):
        self.text_area.clear()
        known_webs = self.get_known_webs()
        self.selected_dropdown_domain = self.dropdown.currentText()
        self.selected_domain = known_webs.get(self.selected_dropdown_domain)
        self.delete_button.setEnabled(True)
        
        if not self.selected_domain:
            self.text_area.setText("No data available.")
            self.delete_button.setEnabled(False)
            return
        
        subject = self.selected_domain.get("subject", {})
        issuer = self.selected_domain.get("issuer", {})
        fingerprint = self.selected_domain.get("fingerprint", None)

        self.text_area.append("SSL Certificate Issued To:")
        self.text_area.append(f"Common Name (CN): {subject.get('commonName', None)}")
        self.text_area.append(f"Organization (O): {subject.get('organizationName', None)}")
        self.text_area.append(f"Organizational Unit (OU): {subject.get('organizationalUnit', None)}\n")

        self.text_area.append("SSL Certificate Issued By:")
        self.text_area.append(f"Common Name (CN): {issuer.get('commonName', None)}")
        self.text_area.append(f"Organization (O): {issuer.get('organizationName', None)}")
        self.text_area.append(f"Organizational Unit (OU): {issuer.get('organizationalUnit', None)}\n")
        
        self.text_area.append(f"SHA-256 Fingerprint:\n{fingerprint}")
    
    def delete_known_web(self):
        selected_temp_domain = self.selected_dropdown_domain
        if not self.selected_domain:
            return

        file_path = BASE_DIR / "storage" / "known_web.json"
        if not os.path.exists(file_path):
            return

        confirm = QMessageBox.question(
            self,
            "Confirm Delete",
            f"Are you sure you want to delete '{selected_temp_domain}' from known websites?",
            QMessageBox.Yes | QMessageBox.No
        )

        if confirm == QMessageBox.Yes:
            try:
                with open(file_path, "r") as f:
                    known_webs = json.load(f)
                
                if selected_temp_domain in known_webs:
                    del known_webs[selected_temp_domain]

                    with open(file_path, "w") as f:
                        json.dump(known_webs, f, indent=2)

                    self.load_known_domain()
                    self.msg_box.setIcon(QMessageBox.Information)
                    self.msg_box.setText("Success")
                    self.msg_box.setWindowTitle("Deleted")
                    self.msg_box.setInformativeText(f"Domain for '{selected_temp_domain}' has been deleted.")
                    self.msg_box.setWindowIcon(QIcon(f"{BASE_DIR}/static/favicon.png"))
                    self.msg_box.exec_()
                    self.website_deleted.emit()
                else:
                    QMessageBox.warning(self, "Warning", f"'Domain {selected_temp_domain}' not found in file.")
            except Exception as e:
                QMessageBox.critical(self, "Error", f"Failed to delete domain: {e}")