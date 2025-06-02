import socket
import ssl
import requests
import hashlib
import json
import subprocess
import webbrowser
from urllib.parse import urlparse
from PyQt5.QtWidgets import (QMainWindow, QTextEdit, QPushButton, QVBoxLayout, QWidget, QHBoxLayout,
                             QLabel, QMessageBox, QComboBox)
from PyQt5.QtGui import QIcon
from PyQt5.QtCore import Qt, QTimer
from edit_window import EditWindow
from delete_window import DeleteWindow
from paths import BASE_DIR

class MainWindow(QMainWindow):
    def __init__(self):
        super().__init__()
        self.setWindowTitle("Captive Portal Authenticator")
        self.setWindowIcon(QIcon(f"{BASE_DIR}/static/favicon.png"))
        self.setGeometry(100, 100, 800, 600)
        
        self.button_set_active = QPushButton("Set as Active")
        self.button_set_active.clicked.connect(self.set_active_domain)
        
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
        
        self.text_area_url = QTextEdit()
        self.text_area_url.setReadOnly(True)

        self.text_area_issues = QTextEdit()
        self.text_area_issues.setReadOnly(True)
        
        self.text_area_url.setFixedHeight(45)
        self.text_area.setFixedHeight(210)

        self.button_verify = QPushButton("Verify Web Authenticity")
        self.button_verify.clicked.connect(self.get_ssl_cert_captive)

        self.button_save_web = QPushButton("Save Known Domains")
        self.button_save_web.clicked.connect(self.toggle_window)
        
        self.button_delete_web = QPushButton("Delete Known Domains")
        self.button_delete_web.clicked.connect(self.toggle_window2)

        self.final_redirect_label = QLabel("Final Redirected URL: ")
        self.final_redirect_label.setStyleSheet("font-weight: bold;")
        self.final_redirect_label.setBuddy(self.text_area_url)

        self.ssl_info_label = QLabel("SSL Information:")
        self.ssl_info_label.setStyleSheet("font-weight: bold;")
        self.ssl_info_label.setBuddy(self.text_area)

        self.dropdown_label = QLabel("Selected Known Trusted Domain:")
        self.dropdown_label.setStyleSheet("font-weight: bold;")
        
        self.dropdown = QComboBox()
        self.load_known_sites()
        self.dropdown.setEnabled(False)
        self.dropdown.currentIndexChanged.connect(self.on_dropdown_change)

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
        
        self.button_layout = QHBoxLayout()
        self.button_layout.setContentsMargins(0, 0, 0, 0)
        self.button_layout.addWidget(self.dropdown, stretch=4)
        # self.button_layout.addWidget(self.button_set_active, stretch=1)
        
        self.button_container = QWidget()
        self.button_container.setLayout(self.button_layout)

        self.layout = QVBoxLayout()
        self.layout.addWidget(self.dropdown_label)
        self.layout.addWidget(self.button_container)
        self.layout.addWidget(self.active_domain_label)
        # self.layout.addWidget(self.button_save_web)
        # self.layout.addWidget(self.button_delete_web)
        self.layout.addWidget(self.final_redirect_label)
        self.layout.addWidget(self.text_area_url)
        self.layout.addWidget(self.ssl_info_label)
        self.layout.addWidget(self.text_area)
        self.layout.addWidget(self.issues_label)
        self.layout.addWidget(self.text_area_issues)
        self.layout.addWidget(self.result_label)

        self.container = QWidget()
        self.container.setLayout(self.layout)

        self.setCentralWidget(self.container)
        
        self.get_ssl_cert_captive()
        
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

        
    def on_dropdown_change(self, index):
        selected_domain = self.dropdown.itemText(index)
        known_webs = self.get_known_webs()
        
        if selected_domain in known_webs and known_webs[selected_domain].get("active"):
            self.active_domain_label.show()
        else:
            self.active_domain_label.hide()
            
        if selected_domain in known_webs:
            self.get_ssl_cert_captive()
        
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
            
    def update_verify_button_state(self):
        if self.dropdown.currentText().strip() == "":
            self.button_verify.setEnabled(False)
        else:
            self.button_verify.setEnabled(True)
            
    def update_set_active_button_state(self):
        text = self.dropdown.currentText().strip()
        if text == "":
            self.button_set_active.setEnabled(False)
        else:
            self.button_set_active.setEnabled(True)

    def get_known_webs(self):
        known_web_path = BASE_DIR / "storage" / "known_web.json"
        with open(known_web_path) as f:
            return json.load(f)

    def request_url(self):
        url = "http://www.msftconnecttest.com/redirect"
        try:
            response = requests.get(url, allow_redirects=True, timeout=10)
            final_url = response.url
            self.text_area_url.setText(final_url)
            return final_url
        except Exception as e:
            self.text_area_url.setText(f"Failed to get redirected URL: {e}")
            return

    def compare_ssl_to_known(self, subject, issuer, fingerprint, known_cert_data, hostname):
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
            self.block_access(hostname)
            self.text_area_issues.setText("SSL Certificate MISMATCH detected!")
            self.result_label.setStyleSheet("""
                background-color: #f2dede;
                font-weight: bold;
                font-size: 17px;
                color: #a94442;
                border: 1px solid #ebccd1;""")
            self.result_label.setText("Domain Identity Could Not Be Verified")
            for issue in issues:
                self.text_area_issues.append(f"- {issue}")
        else:
            webbrowser.open(self.text_area_url.toPlainText())
            self.text_area_issues.setText("None")
            self.result_label.setStyleSheet("""
                background-color: #dff0d8;
                font-weight: bold;
                font-size: 17px;
                color: #3c763d;
                border: 1px solid #d6e9c6;""")
            self.result_label.setText("Domain Identity Successfully Verified")
        QTimer.singleShot(10000, self.close)

    def get_ssl_cert_captive(self):
        self.text_area.clear()
        final_url = self.request_url()
        if not final_url:
            return
        list_known_webs = self.get_known_webs()
        selected_domain = self.dropdown.currentText()
        
        if not list_known_webs or selected_domain not in list_known_webs:
            self.text_area.setText("No known domain selected or available for comparison.")
            return
        
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
                    self.compare_ssl_to_known(subject, issuer, fingerprint, known_domain, hostname)
        except Exception as e:
            self.text_area.setText(f"Error retrieving certificate: {e}")
    
    def block_access(self, hostname):
        ip_address = socket.gethostbyname(hostname)
        rule_name = f"BlockCaptivePortal{hostname}"
        command = f'netsh advfirewall firewall add rule name="{rule_name}" dir=out action=block remoteip={ip_address}'
        try:
            if self.firewall_rule_exists(rule_name):
                return
            subprocess.run(command, shell=True, check=True)
            print(f"Blocked {ip_address} via Windows Firewall")
        except subprocess.CalledProcessError as e:
            print(f"Failed to add rule: {e}")
        except PermissionError:
            print("Permission denied: Run as administrator.")

    def firewall_rule_exists(self, rule_name):
        command = f'netsh advfirewall firewall show rule name="{rule_name}"'
        result = subprocess.run(command, shell=True, capture_output=True, text=True)
        return "No rules match" not in result.stdout