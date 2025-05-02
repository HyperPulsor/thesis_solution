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
                             QMessageBox)
from PyQt5.QtGui import QIcon

class MainWindow(QMainWindow):
    def __init__(self):
        super().__init__()
        self.setWindowTitle("SSL Certificate Verifier")
        self.setWindowIcon(QIcon("static/favicon.png"))
        self.setGeometry(100, 100, 600, 400)
        
        self.window1 = AnotherWindow()
        
        self.msg = QMessageBox()
        self.msg.setIcon(QMessageBox.Critical)
        self.msg.setText("Error")
        self.msg.setInformativeText("Please enter a URL in 'Set Legitimate Web' window.")
        self.msg.setWindowTitle("Error")
        
        self.text_area = QTextEdit()
        self.text_area.setReadOnly(True)
        
        self.button_set_legit_web = QPushButton("Set Legitimate Web")
        self.button_set_legit_web.clicked.connect(self.toggle_window1)
        
        self.button_verify = QPushButton("Verify Web Authenticity")
        self.button_verify.clicked.connect(self.get_ssl_cert_captive)
        
        self.layout = QVBoxLayout()
        # self.layout.addWidget(self.button_set_legit_web)
        self.layout.addWidget(self.button_verify)
        self.layout.addWidget(self.text_area)
        
        self.container = QWidget()
        self.container.setLayout(self.layout)
        
        self.setCentralWidget(self.container)
        
    # def handle_verify_click(self):
    #     url = self.window1.get_url()
    #     if not url:
    #         self.msg.exec_()
    #         return
    #     self.get_ssl_cert_captive(url)
    
    def get_known_webs(self):
        with open('storage/known_web.json') as f:
            d = json.load(f)
        return d
    
    def toggle_window1(self, checked):
        if self.window1.isVisible():
            self.window1.hide()
        else:
            self.window1.show()
            
    def request_url(self):
        # url = "http://www.msftconnecttest.com/redirect"
        url = "https://sso-ui-ac-id.work.gd/"
        try:
            response = requests.get(url, allow_redirects=True, timeout=10)
            final_url = response.url
            self.text_area.append(f"Final redirected URL: {final_url}\n")
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
            self.text_area.append("\n⚠️ SSL Certificate MISMATCH detected!")
            for issue in issues:
                self.text_area.append(f"- {issue}")
            return False
        else:
            self.text_area.append("\n✅ SSL Certificate matches known legitimate site.")
            return True
        
        
    def get_ssl_cert_captive(self):
        final_url = self.request_url()
        list_known_webs = self.get_known_webs()
        
        # TODO: Change to scale
        ui_web = list_known_webs["sso.ui.ac.id"]

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
                    sha256_digest = hashlib.sha256(der_cert).hexdigest()
                    fingerprint = ":".join(sha256_digest[i:i+2].upper() for i in range(0, len(sha256_digest), 2))
                    
                    subject = dict(x[0] for x in cert.get('subject', []))
                    issuer = dict(x[0] for x in cert.get('issuer', []))
                    
                    common_name = subject.get('commonName', 'N/A')
                    organization = subject.get('organizationName', 'N/A')
                    org_unit = subject.get('organizationalUnitName', 'N/A')
                    
                    issuer_common_name = issuer.get('commonName', 'N/A')
                    issuer_organization = issuer.get('organizationName', 'N/A')
                    issuer_org_unit = issuer.get('organizationalUnitName', 'N/A')
                    
                    self.text_area.append("SSL Certificate Issued To:")
                    self.text_area.append(f"Common Name (CN): {common_name}")
                    self.text_area.append(f"Organization (O): {organization}")
                    self.text_area.append(f"Organizational Unit (OU): {org_unit} \n")
                    
                    self.text_area.append("SSL Certificate Issued By:")
                    self.text_area.append(f"Common Name (CN): {issuer_common_name}")
                    self.text_area.append(f"Organization (O): {issuer_organization}")
                    self.text_area.append(f"Organizational Unit (OU): {issuer_org_unit} \n")
                    
                    self.text_area.append(f"SHA-256 Fingerprint: \n {fingerprint}")
                    isLegit = self.compare_ssl_to_known(subject=subject, issuer=issuer, fingerprint=fingerprint, known_cert_data=ui_web)
                    print(isLegit)
                    
        except Exception as e:
            self.text_area.setText(f"Error retrieving certificate: {e}")
            
class AnotherWindow(QWidget):
    def __init__(self):
        super().__init__()
        self.setWindowTitle("Set Legitimate Web")
        self.setWindowIcon(QIcon("static/favicon.png"))
        self.setGeometry(150, 150, 400, 150)
        
        self.input_box_url = QLineEdit()
        self.input_box_url.setPlaceholderText("Enter Web URL (e.g. https://example.com)")
        
        self.submit_button = QPushButton("Submit")
        self.submit_button.clicked.connect(self.close_window)
        
        self.layout = QVBoxLayout()
        self.label = QLabel("Another Window")
        self.layout.addWidget(self.label)
        self.layout.addWidget(self.input_box_url)
        self.layout.addWidget(self.submit_button)
        self.setLayout(self.layout)
    
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