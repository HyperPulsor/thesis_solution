import socket
import ssl
import requests
import hashlib
import json
from urllib.parse import urlparse
from PyQt5.QtWidgets import (QMainWindow, QTextEdit, QPushButton, QVBoxLayout, QWidget,
                             QLabel, QMessageBox, QComboBox)
from PyQt5.QtGui import QIcon
from PyQt5.QtCore import Qt
from edit_window import EditWindow
from delete_window import DeleteWindow

class MainWindow(QMainWindow):
    def __init__(self):
        super().__init__()
        self.setWindowTitle("Captive Portal Authenticator")
        self.setWindowIcon(QIcon("static/favicon.png"))
        self.setGeometry(100, 100, 800, 600)

        self.window1 = EditWindow()
        self.window1.website_saved.connect(self.load_known_sites)
        
        self.window2 = DeleteWindow(self.window1)
        self.window2.website_deleted.connect(self.load_known_sites)
        
        self.msg = QMessageBox()
        self.msg.setIcon(QMessageBox.Critical)
        self.msg.setText("Error")
        self.msg.setInformativeText("Please enter a URL in 'Set Legitimate Web' window.")
        self.msg.setWindowTitle("Error")

        self.text_area = QTextEdit()
        self.text_area.setReadOnly(True)

        self.text_area_issues = QTextEdit()
        self.text_area_issues.setReadOnly(True)

        self.button_verify = QPushButton("Verify Web Authenticity")
        self.button_verify.clicked.connect(self.get_ssl_cert_captive)

        self.button_save_web = QPushButton("Save Known Domains")
        self.button_save_web.clicked.connect(self.toggle_window)
        
        self.button_delete_web = QPushButton("Delete Known Domains")
        self.button_delete_web.clicked.connect(self.toggle_window2)

        self.final_redirect_label = QLabel("Final Redirected URL: ")
        self.final_redirect_label.setStyleSheet("font-weight: bold;")

        self.ssl_info_label = QLabel("SSL Information:")
        self.ssl_info_label.setStyleSheet("font-weight: bold;")
        self.ssl_info_label.setBuddy(self.text_area)

        self.dropdown_label = QLabel("Select Known Trusted Domain:")
        self.dropdown_label.setStyleSheet("font-weight: bold;")
        
        self.dropdown = QComboBox()
        self.load_known_sites()

        self.issues_label = QLabel("Identified Issues:")
        self.issues_label.setStyleSheet("font-weight: bold;")
        self.issues_label.setWordWrap(True)
        self.issues_label.setBuddy(self.text_area_issues)

        self.result_label = QLabel("Ready to verify!")
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
        self.layout.addWidget(self.button_delete_web)
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

    def toggle_window(self, checked=None):
        if self.window1.isVisible():
            self.window1.hide()
        else:
            self.window1.show()
    
    def toggle_window2(self, checked=None):
        if self.window2.isVisible():
            self.window2.hide()
        else:
            self.window2.show()

    def load_known_sites(self):
        self.dropdown.clear()
        try:
            with open('storage/known_web.json', 'r') as f:
                known_webs = json.load(f)
            for domain in known_webs.keys():
                self.dropdown.addItem(domain)
        except (FileNotFoundError, json.JSONDecodeError):
            self.dropdown.addItem("No known sites found")
        self.update_verify_button_state()
            
    def update_verify_button_state(self):
        if self.dropdown.currentText().strip() == "":
            self.button_verify.setEnabled(False)
        else:
            self.button_verify.setEnabled(True)

    def get_known_webs(self):
        with open('storage/known_web.json') as f:
            return json.load(f)

    def request_url(self):
        url = "http://www.msftconnecttest.com/redirect"
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

        issuer_fields = {
            "Issuer Common Name": ("commonName", issuer.get("commonName"), known_cert_data["issuer"]["commonName"]),
            "Issuer Organization Name": ("organizationName", issuer.get("organizationName"), known_cert_data["issuer"]["organizationName"]),
            "Issuer Organizational Unit": ("organizationalUnit", issuer.get("organizationalUnit"), known_cert_data["issuer"]["organizationalUnit"])
        }

        for label, (_, current_val, known_val) in subject_fields.items():
            if current_val != known_val:
                issues.append(f"{label} mismatch: expected '{known_val}', got '{current_val}'")

        for label, (_, current_val, known_val) in issuer_fields.items():
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
            self.result_label.setText("Domain Identity Could Not Be Verified")
            for issue in issues:
                self.text_area_issues.append(f"- {issue}")
        else:
            self.text_area_issues.setText("None")
            self.result_label.setStyleSheet("""
                background-color: #dff0d8;
                font-size: 17px;
                color: #3c763d;
                border: 1px solid #d6e9c6;""")
            self.result_label.setText("Domain Identity Successfully Verified")

    def get_ssl_cert_captive(self):
        self.text_area.clear()
        final_url = self.request_url()
        if not final_url:
            return
        list_known_webs = self.get_known_webs()
        selected_domain = self.dropdown.currentText()
        known_domain = list_known_webs.get(selected_domain, {})

        parsed = urlparse(final_url)
        if parsed.scheme != "https":
            self.text_area.setText("Redirected URL is not HTTPS. No SSL certificate to retrieve.")
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

                    self.text_area.append("SSL Certificate Issued To:")
                    self.text_area.append(f"Common Name (CN): {subject.get('commonName', None)}")
                    self.text_area.append(f"Organization (O): {subject.get('organizationName', None)}")
                    self.text_area.append(f"Organizational Unit (OU): {subject.get('organizationalUnitName', None)}\n")

                    self.text_area.append("SSL Certificate Issued By:")
                    self.text_area.append(f"Common Name (CN): {issuer.get('commonName', None)}")
                    self.text_area.append(f"Organization (O): {issuer.get('organizationName', None)}")
                    self.text_area.append(f"Organizational Unit (OU): {issuer.get('organizationalUnitName', None)}\n")

                    self.text_area.append(f"SHA-256 Fingerprint:\n{fingerprint}")
                    self.compare_ssl_to_known(subject, issuer, fingerprint, known_domain)
        except Exception as e:
            self.text_area.setText(f"Error retrieving certificate: {e}")
