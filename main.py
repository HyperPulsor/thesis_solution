import sys
import socket
import ssl
import pprint
import requests
from urllib.parse import urlparse
from PyQt5.QtWidgets import QApplication, QMainWindow, QTextEdit, QPushButton, QVBoxLayout, QWidget

class MainWindow(QMainWindow):
    def __init__(self):
        super().__init__()
        self.setWindowTitle("SSL Certificate Viewer")
        self.setGeometry(100, 100, 600, 400)

        self.text_area = QTextEdit()
        self.text_area.setReadOnly(True)

        self.button = QPushButton("Verify Captive Portal")
        self.button.clicked.connect(self.get_ssl_cert_captive)
        
        self.button = QPushButton("Manage Known")

        layout = QVBoxLayout()
        layout.addWidget(self.button)
        layout.addWidget(self.text_area)

        container = QWidget()
        container.setLayout(layout)
        self.setCentralWidget(container)
        
        
    def get_ssl_cert_captive(self):
        try:
            response = requests.get("http://www.msftconnecttest.com/redirect", allow_redirects=True, timeout=5)
            final_url = response.url
            self.text_area.append(f"Final redirected URL:\n{final_url}\n")
        except Exception as e:
            self.text_area.setText(f"Failed to get redirected URL: {e}")
            return

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
                    self.text_area.append(pprint.pformat(cert))
        except Exception as e:
            self.text_area.setText(f"Error retrieving certificate: {e}")

def main():
    app = QApplication(sys.argv)
    window = MainWindow()
    window.show()
    sys.exit(app.exec_())

if __name__ == "__main__":
    main()