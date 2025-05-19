import requests
import ssl
import socket
import hashlib
import os
import json
from urllib.parse import urlparse
from PyQt5.QtWidgets import QWidget, QLabel, QLineEdit, QPushButton, QVBoxLayout, QMessageBox, QTextEdit, QHBoxLayout
from PyQt5.QtGui import QIcon
from PyQt5.QtCore import pyqtSignal
from paths import BASE_DIR

class EditWindow(QWidget):
    website_saved = pyqtSignal()
    def __init__(self):
        super().__init__()
        self.setWindowTitle("Save Known Websites")
        self.setWindowIcon(QIcon("static/favicon.png"))
        self.setGeometry(150, 150, 400, 300)
        
        self.msg_box = QMessageBox()
        self.msg_box.setIcon(QMessageBox.Critical)
        self.msg_box.setText("Error")
        self.msg_box.setInformativeText("Please enter a valid HTTPS URL.")
        self.msg_box.setWindowTitle("Error")
        
        self.text_area = QTextEdit()
        self.text_area.setReadOnly(True)
        
        self.ssl_info_label = QLabel("SSL Information:")
        self.ssl_info_label.setStyleSheet("font-weight: bold;")
        self.ssl_info_label.setBuddy(self.text_area)

        self.input_box_url = QLineEdit()
        self.input_box_url.setPlaceholderText("Enter Web URL (e.g. https://example.com)")

        self.label_enter_url = QLabel("Enter HTTPS Web URL:")
        self.label_enter_url.setStyleSheet("font-weight: bold;")
        self.label_enter_url.setBuddy(self.input_box_url)

        self.submit_button = QPushButton("Fetch")
        self.submit_button.clicked.connect(self.fetch_known_web)
        
        self.save_button = QPushButton("Save")
        self.save_button.clicked.connect(self.save_known_web)
        self.save_button.setEnabled(False)
        
        button_layout = QHBoxLayout()
        button_layout.addWidget(self.submit_button)
        button_layout.addWidget(self.save_button)
        
        self.layout = QVBoxLayout()
        self.layout.addWidget(self.label_enter_url)
        self.layout.addWidget(self.input_box_url)
        self.layout.addWidget(self.ssl_info_label)
        self.layout.addWidget(self.text_area)
        self.layout.addLayout(button_layout)
        self.setLayout(self.layout)

    def request_url(self):
        url = self.get_url()
        try:
            response = requests.get(url, allow_redirects=True, timeout=10)
            final_url = response.url
            return final_url
        except Exception as e:
            self.msg_box.exec_()
            return
    
    def fetch_known_web(self):
        self.text_area.clear()
        final_url = self.request_url()
        parsed = urlparse(final_url)
        if parsed.scheme != "https":
            self.msg_box.exec_()
            return
        self.hostname = parsed.hostname
        port = parsed.port or 443
        try:
            context = ssl.create_default_context()
            with socket.create_connection((self.hostname, port)) as sock:
                with context.wrap_socket(sock, server_hostname=self.hostname) as ssock:
                    cert = ssock.getpeercert()
                    der_cert = ssock.getpeercert(binary_form=True)
                    fingerprint = hashlib.sha256(der_cert).hexdigest()
                    
                    subject = dict(x[0] for x in cert.get('subject', []))
                    issuer = dict(x[0] for x in cert.get('issuer', []))
                    
                    self.last_cert_data = {
                        "subject": {
                            "commonName": subject.get("commonName", None),
                            "organizationName": subject.get("organizationName", None),
                            "organizationalUnit": subject.get("organizationalUnitName", None)
                        },
                        "issuer": {
                            "commonName": issuer.get("commonName", None),
                            "organizationName": issuer.get("organizationName", None),
                            "organizationalUnit": issuer.get("organizationalUnitName", None)
                        },
                        "fingerprint": fingerprint
                    }
                    self.last_hostname = self.hostname
                    self.save_button.setEnabled(True)

                    self.text_area.append("SSL Certificate Issued To:")
                    self.text_area.append(f"Common Name (CN): {subject.get('commonName', None)}")
                    self.text_area.append(f"Organization (O): {subject.get('organizationName', None)}")
                    self.text_area.append(f"Organizational Unit (OU): {subject.get('organizationalUnitName', None)}\n")

                    self.text_area.append("SSL Certificate Issued By:")
                    self.text_area.append(f"Common Name (CN): {issuer.get('commonName', None)}")
                    self.text_area.append(f"Organization (O): {issuer.get('organizationName', None)}")
                    self.text_area.append(f"Organizational Unit (OU): {issuer.get('organizationalUnitName', None)}\n")

                    self.text_area.append(f"SHA-256 Fingerprint:\n{fingerprint}")
        except Exception as e:
            self.msg_box.exec_()
    
    def save_known_web(self):
        confirm = QMessageBox.question(
            self,
            "Confirm Save",
            f"Are you sure you want to Save '{self.hostname}'?",
            QMessageBox.Yes | QMessageBox.No
        )
        if confirm == QMessageBox.Yes:
            try:
                os.makedirs("storage", exist_ok=True)
                file_path = BASE_DIR / "storage" / "known_web.json"
                if os.path.exists(file_path):
                    with open(file_path, "r") as f:
                        known_webs = json.load(f)
                else:
                    known_webs = {}
                
                cert_data = {
                    "subject": {
                        "commonName": self.last_cert_data["subject"].get("commonName"),
                        "organizationName": self.last_cert_data["subject"].get("organizationName"),
                        "organizationalUnit": self.last_cert_data["subject"].get("organizationalUnit")
                    },
                    "issuer": {
                        "commonName": self.last_cert_data["issuer"].get("commonName"),
                        "organizationName": self.last_cert_data["issuer"].get("organizationName"),
                        "organizationalUnit": self.last_cert_data["issuer"].get("organizationalUnit")
                    },
                    "fingerprint": self.last_cert_data.get("fingerprint"),
                    "active": False
                }
                
                known_webs[self.last_hostname] = cert_data
                
                with open(file_path, "w") as f:
                    json.dump(known_webs, f, indent=2)
                self.msg_box.setIcon(QMessageBox.Information)
                self.msg_box.setText("Success")
                self.msg_box.setWindowTitle("Saved")
                self.msg_box.setInformativeText(f"Certificate for '{self.last_hostname}' saved.")
                self.msg_box.exec_()
                self.save_button.setEnabled(False)
                self.website_saved.emit()
            except Exception as e:
                self.msg_box.setIcon(QMessageBox.Critical)
                self.msg_box.setText("Error")
                self.msg_box.setWindowTitle("Save Failed")
                self.msg_box.setInformativeText(f"Failed to save: {e}")
                self.msg_box.exec_()
            
    def close_window(self):
        self.hide()

    def get_url(self):
        return self.input_box_url.text().strip()
    