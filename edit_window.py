import requests
from urllib.parse import urlparse
from PyQt5.QtWidgets import QWidget, QLabel, QLineEdit, QPushButton, QVBoxLayout
from PyQt5.QtGui import QIcon

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
            print(f"Final Redirected URL: {final_url}")
            return final_url
        except Exception as e:
            print(f"Failed to get redirected URL: {e}")
            return

    def close_window(self):
        self.hide()

    def get_url(self):
        return self.input_box_url.text().strip()