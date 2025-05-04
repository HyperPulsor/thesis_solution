import sys
import socket
import ssl
import requests
import hashlib
import json
from urllib.parse import urlparse
from PyQt5.QtWidgets import (QApplication, 
                             QMainWindow, 
                             QTextEdit, 
                             QPushButton, 
                             QVBoxLayout, 
                             QWidget,
                             QLabel,
                             QLineEdit,
                             QMessageBox,
                             QComboBox)
from PyQt5.QtGui import QIcon
from PyQt5.QtCore import Qt

class MainWindow(QMainWindow):
    def __init__(self):
        super().__init__()
        self.setWindowTitle("SSL Certificate Verifier")
        self.setWindowIcon(QIcon("static/favicon.png"))
        self.setGeometry(100, 100, 800, 600)
        
        self.window1 = AnotherWindow()
        
        self.msg = QMessageBox()
        self.msg.setIcon(QMessageBox.Critical)
        self.msg.setText("Error")
        self.msg.setInformativeText("Please enter a URL in 'Set Legitimate Web' window.")
        self.msg.setWindowTitle("Error")
        
        self.text_area = QTextEdit()
        self.text_area.setReadOnly(True)
        
        self.text_area_issues = QTextEdit()
        self.text_area_issues.setReadOnly(True)
        
        self.button_set_legit_web = QPushButton("Set Legitimate Web")
        self.button_set_legit_web.clicked.connect(self.toggle_window)
        
        self.button_verify = QPushButton("Verify Web Authenticity")
        self.button_verify.clicked.connect(self.get_ssl_cert_captive)
        
        self.button_save_web = QPushButton("Edit Known Websites")
        self.button_save_web.clicked.connect(self.toggle_window)
        
        self.final_redirect_label = QLabel("Final Redirected URL: ")
        self.final_redirect_label.setStyleSheet("font-weight: bold;")
        
        self.ssl_info_label = QLabel("Web SSL Information:")
        self.ssl_info_label.setStyleSheet("font-weight: bold;")
        self.ssl_info_label.setBuddy(self.text_area)
        
        self.dropdown_label = QLabel("Select Known Trusted Website:")
        self.dropdown_label.setStyleSheet("font-weight: bold;")
        self.dropdown = QComboBox()
        self.load_known_sites()
        
        self.issues_label = QLabel("Identified Issues:")
        self.issues_label.setStyleSheet("font-weight: bold;")
        self.issues_label.setWordWrap(True)
        self.issues_label.setBuddy(self.text_area_issues)
        
        self.result_label = QLabel("")
        self.result_label.setText("Ready to verify!")
        self.result_label.setStyleSheet("""
            background-color: #d9edf7;
            font-size: 17px;
            color: #31708f;
            border: 1px solid #bce8f1;""")
        self.result_label.setAlignment(Qt.AlignCenter)
        
        self.layout = QVBoxLayout()
        self.layout.addWidget(self.dropdown_label)
        self.layout.addWidget(self.dropdown)
        self.layout.addWidget(self.button_save_web)
        self.layout.addWidget(self.button_verify)
        self.layout.addWidget(self.final_redirect_label)
        self.layout.addWidget(self.ssl_info_label)
        self.layout.addWidget(self.text_area)
        self.layout.addWidget(self.issues_label)
        self.layout.addWidget(self.text_area_issues)
        self.layout.addWidget(self.result_label)
        
        self.container = QWidget()
        self.container.setLayout(self.layout)
        
        self.setCentralWidget(self.container)
        
    def toggle_window(self, checked):
        if self.window1.isVisible():
            self.window1.hide()
        else:
            self.window1.show()
    
    def load_known_sites(self):
        self.dropdown.clear()
        try:
            with open('storage/known_web.json', 'r') as f:
                known_webs = json.load(f)
            for domain in known_webs.keys():
                self.dropdown.addItem(domain)
        except (FileNotFoundError, json.JSONDecodeError):
            self.dropdown.addItem("No known sites found")
    
    def get_known_webs(self):
        with open('storage/known_web.json') as f:
            d = json.load(f)
        return d
            
    def request_url(self):
        # url = "http://www.msftconnecttest.com/redirect"
        # url = "https://sso.ui.ac.id/cas/login?service=https://sts.ms.ui.ac.id/Login.aspx"
        url = "https://sso-ui-ac-id.work.gd/"
        try:
            response = requests.get(url, allow_redirects=True, timeout=10)
            final_url = response.url
            self.final_redirect_label.setText(f"Final Redirected URL: {final_url}")
            return final_url
        except Exception as e:
            self.text_area.setText(f"Failed to get redirected URL: {e}")
            return
    
    def compare_ssl_to_known(self, subject, issuer, fingerprint, known_cert_data):
        issues = []

        subject_fields = {
            "Common Name": ("commonName", subject.get("commonName"), known_cert_data["subject"]["commonName"]),
            "Organization Name": ("organizationName", subject.get("organizationName"), known_cert_data["subject"]["organizationName"]),
            "Organizational Unit": ("organizationalUnit", subject.get("organizationalUnit"), known_cert_data["subject"]["organizationalUnit"])
        }

        for label, (key, current_val, known_val) in subject_fields.items():
            if current_val != known_val:
                issues.append(f"{label} mismatch: expected '{known_val}', got '{current_val}'")

        issuer_fields = {
            "Issuer Common Name": ("commonName", issuer.get("commonName"), known_cert_data["issuer"]["commonName"]),
            "Issuer Organization Name": ("organizationName", issuer.get("organizationName"), known_cert_data["issuer"]["organizationName"]),
            "Issuer Organizational Unit": ("organizationalUnit", issuer.get("organizationalUnit"), known_cert_data["issuer"]["organizationalUnit"])
        }

        for label, (key, current_val, known_val) in issuer_fields.items():
            if current_val != known_val:
                issues.append(f"{label} mismatch: expected '{known_val}', got '{current_val}'")

        if fingerprint.lower() != known_cert_data["fingerprint"].lower():
            issues.append("SHA-256 fingerprint mismatch")
        
        if issues:
            self.text_area_issues.setText("SSL Certificate MISMATCH detected!")
            self.result_label.setStyleSheet("""
                background-color: #f2dede;
                font-size: 17px;
                color: #a94442;
                border: 1px solid #ebccd1;""")
            self.result_label.setText("Website Identity Could Not Be Verified")
            for issue in issues:
                self.text_area_issues.append(f"- {issue}")
        else:
            self.text_area_issues.setText("None")
            self.result_label.setStyleSheet("""
                background-color: #dff0d8;
                font-size: 17px;
                color: #3c763d;
                border: 1px solid #d6e9c6;""")
            self.result_label.setText("Website Successfully Verified")
        
        
    def get_ssl_cert_captive(self):
        self.text_area.clear()
        final_url = self.request_url()
        list_known_webs = self.get_known_webs()
        selected_domain = self.dropdown.currentText()
        
        ui_web = list_known_webs[selected_domain]

        parsed = urlparse(final_url)
        if parsed.scheme != "https":
            self.text_area.append("Redirected URL is not HTTPS. No SSL certificate to retrieve.")
            return

        hostname = parsed.hostname
        port = parsed.port or 443
        try:
            context = ssl.create_default_context()
            with socket.create_connection((hostname, port)) as sock:
                with context.wrap_socket(sock, server_hostname=hostname) as ssock:
                    cert = ssock.getpeercert()
                    
                    der_cert = ssock.getpeercert(binary_form=True)
                    fingerprint = hashlib.sha256(der_cert).hexdigest()
                    
                    subject = dict(x[0] for x in cert.get('subject', []))
                    issuer = dict(x[0] for x in cert.get('issuer', []))
                    
                    common_name = subject.get('commonName', '<Not Part Of Certificate>')
                    organization = subject.get('organizationName', '<Not Part Of Certificate>')
                    org_unit = subject.get('organizationalUnitName', '<Not Part Of Certificate>')
                    
                    issuer_common_name = issuer.get('commonName', '<Not Part Of Certificate>')
                    issuer_organization = issuer.get('organizationName', '<Not Part Of Certificate>')
                    issuer_org_unit = issuer.get('organizationalUnitName', '<Not Part Of Certificate>')
                    
                    self.text_area.append("SSL Certificate Issued To:")
                    self.text_area.append(f"Common Name (CN): {common_name}")
                    self.text_area.append(f"Organization (O): {organization}")
                    self.text_area.append(f"Organizational Unit (OU): {org_unit} \n")
                    
                    self.text_area.append("SSL Certificate Issued By:")
                    self.text_area.append(f"Common Name (CN): {issuer_common_name}")
                    self.text_area.append(f"Organization (O): {issuer_organization}")
                    self.text_area.append(f"Organizational Unit (OU): {issuer_org_unit} \n")
                    
                    self.text_area.append(f"SHA-256 Fingerprint: \n {fingerprint}")
                    self.compare_ssl_to_known(subject=subject, issuer=issuer, fingerprint=fingerprint, known_cert_data=ui_web)
                    
        except Exception as e:
            self.text_area.setText(f"Error retrieving certificate: {e}")
            
class AnotherWindow(QWidget):
    def __init__(self):
        super().__init__()
        self.setWindowTitle("Edit Known Websites")
        self.setWindowIcon(QIcon("static/favicon.png"))
        self.setGeometry(150, 150, 400, 100)
        
        self.input_box_url = QLineEdit()
        self.input_box_url.setPlaceholderText("Enter Web URL (e.g. https://example.com)")
        
        self.label_enter_url = QLabel("Enter HTTPS Web URL:")
        self.label_enter_url.setStyleSheet("font-weight: bold;")
        self.label_enter_url.setBuddy(self.input_box_url)
        
        self.submit_button = QPushButton("Fetch")
        self.submit_button.clicked.connect(self.request_url)
        
        self.layout = QVBoxLayout()
        self.layout.addWidget(self.label_enter_url)
        self.layout.addWidget(self.input_box_url)
        self.layout.addWidget(self.submit_button)
        self.setLayout(self.layout)
    
    def request_url(self):
        url = self.get_url()
        try:
            response = requests.get(url, allow_redirects=True, timeout=10)
            final_url = response.url
            return final_url
        except Exception as e:
            self.text_area.setText(f"Failed to get redirected URL: {e}")
            return
    
    def close_window(self):
        self.hide()
    
    def get_url(self):
        return self.input_box_url.text().strip()

def main():
    app = QApplication(sys.argv)
    window = MainWindow()
    window.show()
    sys.exit(app.exec_())

if __name__ == "__main__":
    main()