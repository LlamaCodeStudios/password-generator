# vault.py – Part 1/2
import sys, os, json, base64, secrets, string, traceback, warnings
from PyQt6.QtWidgets import (
    QApplication, QWidget, QLabel, QLineEdit, QPushButton,
    QVBoxLayout, QHBoxLayout, QMessageBox, QSpinBox, QListWidget,
    QInputDialog
)
from PyQt6.QtCore import Qt
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes
from cryptography.fernet import Fernet

warnings.filterwarnings("ignore", category=DeprecationWarning)

def generate_salt(): return secrets.token_bytes(16)

def derive_key(password, salt):
    kdf = PBKDF2HMAC(algorithm=hashes.SHA256(), length=32, salt=salt, iterations=390_000)
    return base64.urlsafe_b64encode(kdf.derive(password.encode()))

def encrypt_data(data, key): return Fernet(key).encrypt(json.dumps(data).encode())

def decrypt_data(enc_bytes, key): return json.loads(Fernet(key).decrypt(enc_bytes))

def generate_password(length=12):
    chars = string.ascii_letters + string.digits + string.punctuation
    return ''.join(secrets.choice(chars) for _ in range(length))

def get_all_usernames():
    return [f.split("_")[1].split(".")[0] for f in os.listdir() if f.startswith("vault_") and f.endswith(".dat")]

class SetupScreen(QWidget):
    def __init__(self, require_auth=False, master_key=None):
        super().__init__()
        self.setWindowTitle("Vault Setup")
        self.setFixedSize(400, 220)
        self.require_auth = require_auth
        self.master_key = master_key
        self.init_ui()

    def init_ui(self):
        layout = QVBoxLayout()
        self.user_input = QLineEdit()
        self.pass_input = QLineEdit()
        self.pass_input.setEchoMode(QLineEdit.EchoMode.Password)

        layout.addWidget(QLabel("New username:"))
        layout.addWidget(self.user_input)
        layout.addWidget(QLabel("Master password:"))
        layout.addWidget(self.pass_input)

        btn = QPushButton("Create Vault")
        btn.clicked.connect(self.create_user)
        layout.addWidget(btn)
        self.setLayout(layout)

    def create_user(self):
        username = self.user_input.text().strip()
        password = self.pass_input.text()

        if not username or not password:
            QMessageBox.warning(self, "Missing", "Fill in both fields.")
            return

        if username in get_all_usernames():
            QMessageBox.warning(self, "Exists", f"User '{username}' already exists.")
            return

        if self.require_auth:
            pwd, ok = QInputDialog.getText(self, "Verify Master Key", "Enter current master password:", QLineEdit.EchoMode.Password)
            if not ok or not pwd or derive_key(pwd, generate_salt()) != self.master_key:
                QMessageBox.critical(self, "Access Denied", "Incorrect master password.")
                return

        salt = generate_salt()
        key = derive_key(password, salt)
        with open(f"salt_{username}.dat", "wb") as f: f.write(salt)
        vault = {"auth_check": "valid"}
        with open(f"vault_{username}.dat", "wb") as f: f.write(encrypt_data(vault, key))

        QMessageBox.information(self, "Created", f"Vault for '{username}' created.")
        self.login = LoginScreen()
        self.login.show()
        self.close()

class LoginScreen(QWidget):
    def __init__(self):
        super().__init__()
        self.setWindowTitle("Vault Login")
        self.setFixedSize(400, 200)
        self.init_ui()

    def init_ui(self):
        layout = QVBoxLayout()
        self.user_input = QLineEdit()
        self.pass_input = QLineEdit()
        self.pass_input.setEchoMode(QLineEdit.EchoMode.Password)

        layout.addWidget(QLabel("Username:"))
        layout.addWidget(self.user_input)
        layout.addWidget(QLabel("Master Password:"))
        layout.addWidget(self.pass_input)

        btn_row = QHBoxLayout()
        login_btn = QPushButton("Login")
        login_btn.clicked.connect(self.authenticate)
        setup_btn = QPushButton("Add New User")
        setup_btn.clicked.connect(self.launch_setup)
        btn_row.addWidget(login_btn)
        btn_row.addWidget(setup_btn)

        layout.addLayout(btn_row)
        self.setLayout(layout)

    def authenticate(self):
        username = self.user_input.text().strip()
        password = self.pass_input.text()
        salt_path = f"salt_{username}.dat"
        vault_path = f"vault_{username}.dat"

        if not os.path.exists(salt_path) or not os.path.exists(vault_path):
            QMessageBox.warning(self, "Not Found", "User not found.")
            return
        try:
            with open(salt_path, "rb") as f: salt = f.read()
            key = derive_key(password, salt)
            with open(vault_path, "rb") as f: vault = decrypt_data(f.read(), key)
            if vault.get("auth_check") != "valid": raise ValueError("Invalid auth marker")
            self.vault_ui = VaultApp(username, key)
            self.vault_ui.show()
            self.close()
        except:
            QMessageBox.critical(self, "Error", "Login failed.")

    def launch_setup(self):
        require_auth = len(get_all_usernames()) > 0
        self.setup_window = SetupScreen(require_auth=require_auth, master_key=self.pass_input.text())
        self.setup_window.show()
        self.close()
class VaultApp(QWidget):
    def __init__(self, username, key):
        super().__init__()
        self.username = username
        self.key = key
        self.vault_file = f"vault_{username}.dat"
        self.salt_file = f"salt_{username}.dat"
        with open(self.vault_file, "rb") as f:
            self.vault = decrypt_data(f.read(), self.key)

        self.setWindowTitle(f"Vault – {self.username}")
        self.setFixedSize(600, 500)
        self.init_ui()

    def init_ui(self):
        layout = QVBoxLayout()
        self.list_widget = QListWidget()
        self.refresh_list()
        layout.addWidget(self.list_widget)

        btn_row = QHBoxLayout()
        for label, handler in [
            ("Add Entry", self.add_entry),
            ("View Entry", self.view_entry),
            ("Password Generator", self.launch_generator),
            ("Logout", self.logout)
        ]:
            btn = QPushButton(label)
            btn.clicked.connect(handler)
            btn_row.addWidget(btn)

        layout.addLayout(btn_row)
        self.setLayout(layout)

    def refresh_list(self):
        self.list_widget.clear()
        for label in self.vault:
            if label != "auth_check":
                entry = self.vault[label]
                self.list_widget.addItem(f"{entry['site']} – {entry['username']}")

    def add_entry(self):
        label, ok1 = QInputDialog.getText(self, "Label", "Entry name:")
        site, ok2 = QInputDialog.getText(self, "Site", "Site address:")
        username, ok3 = QInputDialog.getText(self, "Username", "Login username:")
        password, ok4 = QInputDialog.getText(self, "Password", "Login password:", QLineEdit.EchoMode.Password)
        if not all([ok1, ok2, ok3, ok4]): return
        self.vault[label] = {"site": site, "username": username, "password": password}
        with open(self.vault_file, "wb") as f:
            f.write(encrypt_data(self.vault, self.key))
        self.refresh_list()

    def view_entry(self):
        index = self.list_widget.currentRow()
        if index == -1:
            QMessageBox.warning(self, "No Selection", "Select an entry first.")
            return
        label = [k for k in self.vault if k != "auth_check"][index]
        entry = self.vault[label]

        dlg = QMessageBox(self)
        dlg.setWindowTitle(label)
        dlg.setText(f"Site: {entry['site']}\nUsername: {entry['username']}\nPassword: {entry['password']}")
        copy_btn = QPushButton("Copy Credentials...")
        copy_btn.clicked.connect(lambda: self.copy_dialog(label))
        dlg.addButton(copy_btn, QMessageBox.ButtonRole.ActionRole)
        dlg.addButton("Close", QMessageBox.ButtonRole.RejectRole)
        dlg.exec()

    def copy_dialog(self, label):
        dlg = QMessageBox(self)
        dlg.setWindowTitle("Copy Credentials")
        dlg.setText("Choose a field to copy:")
        site_btn = dlg.addButton("Site", QMessageBox.ButtonRole.ActionRole)
        user_btn = dlg.addButton("Username", QMessageBox.ButtonRole.ActionRole)
        pass_btn = dlg.addButton("Password", QMessageBox.ButtonRole.ActionRole)
        dlg.addButton("Cancel", QMessageBox.ButtonRole.RejectRole)
        dlg.exec()

        field = None
        if dlg.clickedButton() == site_btn: field = "site"
        elif dlg.clickedButton() == user_btn: field = "username"
        elif dlg.clickedButton() == pass_btn: field = "password"
        if field:
            self.reauth_and_copy(label, field)

    def reauth_and_copy(self, label, field):
        entry = self.vault[label]
        pwd, ok = QInputDialog.getText(self, "Authenticate", "Re-enter master password:", QLineEdit.EchoMode.Password)
        if not ok or not pwd: return
        with open(self.salt_file, "rb") as f: salt = f.read()
        if derive_key(pwd, salt) != self.key:
            QMessageBox.critical(self, "Access Denied", "Incorrect master password.")
            return
        QApplication.instance().clipboard().setText(entry[field])
        QMessageBox.information(self, "Copied", f"{field.capitalize()} copied to clipboard.")

    def launch_generator(self):
        self.generator = PasswordGeneratorApp()
        self.generator.show()

    def logout(self):
        self.close()
        self.login_screen = LoginScreen()
        self.login_screen.show()

class PasswordGeneratorApp(QWidget):
    def __init__(self):
        super().__init__()
        self.setWindowTitle("Password Generator")
        self.setFixedSize(400, 200)
        self.init_ui()

    def init_ui(self):
        layout = QVBoxLayout()
        row = QHBoxLayout()
        row.addWidget(QLabel("Length:"))
        self.length_input = QSpinBox()
        self.length_input.setRange(1, 9999)
        self.length_input.setValue(12)
        row.addWidget(self.length_input)
        layout.addLayout(row)

        self.output = QLabel("Your password will appear here.")
        self.output.setTextInteractionFlags(Qt.TextInteractionFlag.TextSelectableByMouse)
        self.generate_btn = QPushButton("Generate")
        self.generate_btn.clicked.connect(self.generate)
        self.copy_btn = QPushButton("Copy")
        self.copy_btn.setEnabled(False)
        self.copy_btn.clicked.connect(self.copy)

        layout.addWidget(self.generate_btn)
        layout.addWidget(self.output)
        layout.addWidget(self.copy_btn)
        self.setLayout(layout)

    def generate(self):
        length = self.length_input.value()
        if length > 300:
            QMessageBox.warning(self, "Warning", "Passwords over 300 characters may not be supported by all services.")
        pwd = generate_password(length)
        self.output.setText(pwd)
        self.copy_btn.setEnabled(True)

    def copy(self):
        QApplication.instance().clipboard().setText(self.output.text())
        QMessageBox.information(self, "Copied", "Password copied to clipboard.")

def handle_exception(exc_type, exc_value, exc_traceback):
    error_msg = "".join(traceback.format_exception(exc_type, exc_value, exc_traceback))
    with open("crashlog.txt", "a") as f:
        f.write(error_msg + "\n" + "="*60 + "\n")

    dlg = QMessageBox()
    dlg.setIcon(QMessageBox.Icon.Critical)
    dlg.setWindowTitle("Application Crash")
    dlg.setText("An unexpected error occurred. A crash log has been saved.")
    dlg.setDetailedText(error_msg)
    dlg.exec()

sys.excepthook = handle_exception

def main():
    app = QApplication(sys.argv)
    start_on_login = len(get_all_usernames()) > 0
    window = LoginScreen() if start_on_login else SetupScreen()
    window.show()
    sys.exit(app.exec())

if __name__ == "__main__":
    main()
