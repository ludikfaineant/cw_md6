import sys, os
import ctypes
from PyQt5.QtWidgets import (
    QApplication,
    QMainWindow,
    QVBoxLayout,
    QHBoxLayout,
    QPushButton,
    QLabel,
    QLineEdit,
    QTextEdit,
    QFileDialog,
    QMessageBox,
    QCheckBox,
    QWidget,
    QMenu,
    QAction,
)
from PyQt5.QtCore import Qt
import re
import random
import string
import fitz


def extract_pdf_text(file_path):
    doc = fitz.open(file_path)
    text = ""
    for page_num in range(len(doc)):
        page = doc.load_page(page_num)
        text += page.get_text("text")
    return text


class MD6Hash:
    def __init__(self, library_path):
        self.lib = ctypes.CDLL(library_path)
        self.lib.MD6FromFile.argtypes = [
            ctypes.c_char_p,
            ctypes.c_char_p,
            ctypes.c_int,
        ]
        self.lib.MD6FromFile.restype = ctypes.c_char_p

        self.lib.MD6FromInput.argtypes = [
            ctypes.c_char_p,
            ctypes.c_char_p,
            ctypes.c_int,
        ]
        self.lib.MD6FromInput.restype = ctypes.c_char_p

    def compute_md6_hash_from_file(self, file_path, key, output_length):
        return self.lib.MD6FromFile(
            ctypes.c_char_p(file_path),
            ctypes.c_char_p(key),
            ctypes.c_int(output_length),
        )

    def compute_md6_hash_from_input(self, data, key, output_length):
        return self.lib.MD6FromInput(
            ctypes.c_char_p(data),
            ctypes.c_char_p(key),
            ctypes.c_int(output_length),
        )


class HashComparerApp(QMainWindow):
    def __init__(self):
        super().__init__()

        self.setWindowTitle("MD6")
        self.setGeometry(100, 100, 800, 550)

        self.create_menu()

        self.use_file_content_checkbox = QCheckBox("Use File Content")
        self.use_file_content_checkbox.setChecked(False)
        self.use_file_content_checkbox.stateChanged.connect(self.toggle_input_mode)

        self.use_key_checkbox = QCheckBox("Use Key")
        self.use_key_checkbox.setChecked(False)
        self.use_key_checkbox.stateChanged.connect(self.toggle_key_input)

        self.file_path_input = QLineEdit(self)
        self.file_path_input.setReadOnly(True)

        self.browse_file_button = QPushButton("Browse", self)
        self.browse_file_button.clicked.connect(self.browse_file)

        self.file_path_label = QLabel("File Path", self)

        self.manual_input_text = QTextEdit(self)
        self.manual_input_text.setReadOnly(False)

        self.computed_hash_var = QLineEdit(self)
        self.computed_hash_var.setReadOnly(True)

        self.key_input_label = QLabel("Key Input")
        self.key_input_field = QLineEdit(self)
        self.key_input_field.setPlaceholderText("Enter key here...")
        self.key_input_field.setReadOnly(False)

        self.compute_hash_button = QPushButton("Compute Hash", self)
        self.compute_hash_button.clicked.connect(self.compute_hash)
        self.compare_hash_button = QPushButton("Compare Hash", self)
        self.compare_hash_button.clicked.connect(self.compare_hash)

        self.generate_key_button = QPushButton("Generate Key", self)
        self.generate_key_button.clicked.connect(self.generate_key)

        self.clear_input_button = QPushButton("Clear Input", self)
        self.clear_input_button.setFixedSize(100, 30)
        self.clear_input_button.clicked.connect(self.clear_manual_input)

        file_layout = QVBoxLayout()
        file_layout.setContentsMargins(10, 10, 10, 0)
        file_layout.setSpacing(10)

        file_path_layout = QHBoxLayout()
        file_path_layout.addWidget(self.file_path_input)
        file_path_layout.addWidget(self.browse_file_button)

        self.file_content_label = QLabel("File Content", self)
        file_layout.addWidget(self.use_file_content_checkbox)
        file_layout.addWidget(self.file_path_label)
        file_layout.addLayout(file_path_layout)

        file_layout.addWidget(self.file_content_label)
        file_layout.addWidget(self.manual_input_text)

        hash_layout = QVBoxLayout()
        hash_layout.setContentsMargins(10, 0, 10, 0)
        hash_layout.setSpacing(10)
        clear_layout = QHBoxLayout()
        clear_layout.addWidget(self.use_key_checkbox)
        clear_layout.addWidget(self.clear_input_button, alignment=Qt.AlignRight)

        hash_layout.addLayout(clear_layout)
        hash_layout.addWidget(self.key_input_label)

        key_layout = QHBoxLayout()
        key_layout.addWidget(self.key_input_field)
        key_layout.addWidget(self.generate_key_button)

        hash_layout.addLayout(key_layout)
        hash_layout.addWidget(QLabel("Computed Hash"))

        compute_hash = QHBoxLayout()
        compute_hash.addWidget(self.computed_hash_var)
        compute_hash.addWidget(self.compare_hash_button)
        compute_hash.addWidget(self.compute_hash_button)
        hash_layout.addLayout(compute_hash)

        comparison_layout = QVBoxLayout()
        comparison_layout.setContentsMargins(10, 10, 10, 10)
        comparison_layout.setSpacing(10)

        central_widget = QWidget(self)
        central_layout = QVBoxLayout(central_widget)
        central_layout.setContentsMargins(10, 0, 10, 10)
        central_layout.setSpacing(15)

        central_layout.addLayout(file_layout)
        central_layout.addLayout(hash_layout)
        central_layout.addLayout(comparison_layout)

        self.setCentralWidget(central_widget)

        self.key_min_length = 8
        self.key_max_length = 64
        self.key_allowed_characters = r"^[a-zA-Z0-9#!@$]*$"

        self.toggle_input_mode()
        self.toggle_key_input()

    def clear_manual_input(self):
        """Очистить поле ручного ввода."""
        self.manual_input_text.clear()

    def create_menu(self):
        """Создание меню."""
        menu_bar = self.menuBar()

        file_menu = QMenu("Menu", self)
        menu_bar.addMenu(file_menu)

        open_hash_action = QAction("Load Hash", self)
        open_hash_action.triggered.connect(self.load_hash)
        file_menu.addAction(open_hash_action)

        save_hash_action = QAction("Save Hash", self)
        save_hash_action.triggered.connect(self.save_hash)
        file_menu.addAction(save_hash_action)

        quit_action = QAction("Exit", self)
        quit_action.triggered.connect(self.quit)
        file_menu.addAction(quit_action)

        help_menu = QMenu("Help", self)
        menu_bar.addMenu(help_menu)

        about_action = QAction("About", self)
        about_action.triggered.connect(self.show_about)
        help_menu.addAction(about_action)

    def toggle_input_mode(self):
        """Переключение между режимами файла и ввода вручную."""
        if self.use_file_content_checkbox.isChecked():
            self.manual_input_text.setReadOnly(True)
            self.file_path_label.setVisible(True)
            self.file_path_input.setVisible(True)
            self.file_content_label.setText("File Content")
            self.manual_input_text.setPlaceholderText(
                "File content will be displayed here."
            )
            self.browse_file_button.setVisible(True)
        else:
            self.manual_input_text.setReadOnly(False)
            self.file_path_label.setVisible(False)
            self.file_path_input.setVisible(False)
            self.file_content_label.setText("Manual Input")
            self.manual_input_text.setPlaceholderText("Enter text manually.")
            self.browse_file_button.setVisible(False)

    def toggle_key_input(self):
        """Показать или скрыть поле ввода ключа в зависимости от состояния чекбокса."""
        if self.use_key_checkbox.isChecked():
            self.key_input_label.setVisible(True)
            self.key_input_field.setVisible(True)
            self.generate_key_button.setVisible(True)
        else:
            self.key_input_label.setVisible(False)
            self.key_input_field.setVisible(False)
            self.generate_key_button.setVisible(False)

    def is_key_valid(self, key):
        """Проверка валидности ключа по длине и разрешённым символам."""
        if len(key) < self.key_min_length or len(key) > self.key_max_length:
            return False
        return bool(re.match(self.key_allowed_characters, key))

    def generate_key(self):
        """Генерация случайного ключа, соответствующего ограничениям."""
        characters = string.ascii_letters + string.digits + "#!@$"
        random_key = "".join(
            random.choice(characters) for _ in range(self.key_max_length)
        )
        self.key_input_field.setText(random_key)

    def load_hash(self):
        """Загрузить хэш из файла."""
        file_path, _ = QFileDialog.getOpenFileName(
            self, "Load Hash", "", "Text Files (*.txt);;All Files (*)"
        )
        if file_path:
            try:
                with open(file_path, "r") as file:
                    hash_value = file.read().strip()
                    if not hash_value:
                        QMessageBox.warning(self, "Warning", "The file is empty.")
                        return
                    self.computed_hash_var.setText(hash_value)
                    QMessageBox.information(
                        self, "Success", "Hash loaded successfully."
                    )
            except Exception as e:
                QMessageBox.critical(
                    self, "Error", f"An error occurred while loading the hash:\n{e}"
                )

    def save_hash(self):
        """Сохранить вычисленный хеш в файл."""
        file_path, _ = QFileDialog.getSaveFileName(
            self, "Save Hash", "", "Text Files (*.txt);;All Files (*)"
        )
        if file_path:
            with open(file_path, "w") as file:
                file.write(self.computed_hash_var.text())
            QMessageBox.information(self, "Success", "Hash saved successfully.")

    def browse_file(self):
        """Выбрать файл и отобразить его содержимое, если файл в UTF-8 или PDF."""
        file_path, _ = QFileDialog.getOpenFileName(
            self, "Open File", "", "All Files (*)"
        )
        if not file_path:
            return

        self.file_path_input.setText(file_path)

        try:
            if file_path.lower().endswith(".pdf"):
                text = extract_pdf_text(file_path)
                self.manual_input_text.setText(
                    text if text else "No text found in PDF."
                )
            else:
                with open(file_path, "rb") as f:
                    file_content = f.read()
                    try:
                        decoded_content = file_content.decode("utf-8")
                        self.manual_input_text.setText(decoded_content)
                    except UnicodeDecodeError:
                        self.manual_input_text.setText(
                            "The file cannot be decoded as UTF-8."
                        )
        except Exception as e:
            QMessageBox.critical(
                self, "Error", f"An error occurred while reading the file:\n{e}"
            )

    def compute_hash(self):
        """Вычислить хэш с использованием файла или ручного ввода."""
        try:
            key = (
                self.key_input_field.text().encode("utf-8")
                if self.use_key_checkbox.isChecked()
                else b""
            )

            if self.use_key_checkbox.isChecked() and not self.is_key_valid(
                key.decode()
            ):
                QMessageBox.warning(self, "Warning", "Invalid key!")
                return

            if self.use_file_content_checkbox.isChecked():
                file_path = self.file_path_input.text().strip()
                if not os.path.exists(file_path):
                    QMessageBox.critical(self, "Error", "File not found!")
                    return

                md6 = MD6Hash("./libmd6.so")
                result = md6.compute_md6_hash_from_file(
                    file_path.encode("utf-8"), key, 32
                )
            else:
                data = self.manual_input_text.toPlainText().encode("utf-8")
                if not data:
                    QMessageBox.warning(self, "Warning", "Input is empty!")
                    return

                md6 = MD6Hash("./libmd6.so")
                result = md6.compute_md6_hash_from_input(data, key, 32)

            if result:
                self.computed_hash_var.setText(result.decode())
            else:
                QMessageBox.warning(
                    self, "Warning", "Hash computation returned no result."
                )
        except Exception as e:
            QMessageBox.critical(self, "Error", f"An error occurred:\n{e}")

    def compare_hash(self):
        """Сравнить ранее вычисленный хэш с текущим."""
        try:
            key = (
                self.key_input_field.text().encode("utf-8")
                if self.use_key_checkbox.isChecked()
                else b""
            )

            if self.use_key_checkbox.isChecked() and not self.is_key_valid(
                key.decode()
            ):
                QMessageBox.warning(self, "Warning", "Invalid key!")
                return

            if self.use_file_content_checkbox.isChecked():
                file_path = self.file_path_input.text().strip()
                if not os.path.exists(file_path):
                    QMessageBox.critical(self, "Error", "File not found!")
                    return

                md6 = MD6Hash("./libmd6.so")
                result = md6.compute_md6_hash_from_file(
                    file_path.encode("utf-8"), key, 32
                )
            else:
                data = self.manual_input_text.toPlainText().encode("utf-8")
                if not data:
                    QMessageBox.warning(self, "Warning", "Input is empty!")
                    return

                md6 = MD6Hash("./libmd6.so")
                result = md6.compute_md6_hash_from_input(data, key, 32)

            if result.decode("utf-8") == self.computed_hash_var.text().strip():
                QMessageBox.information(self, "Match", "Hashes match!")
            else:
                QMessageBox.warning(self, "Mismatch", "Hashes do not match.")

        except Exception as e:
            QMessageBox.critical(self, "Error", f"An error occurred:\n{e}")

    def quit(self):
        """Выход из программы."""
        QApplication.quit()

    def show_about(self):
        """Окно информации о программе."""
        QMessageBox.information(
            self,
            "About",
            "MD6 Hash Comparer\n\nA simple tool to compare MD6 hashes of files.",
        )


if __name__ == "__main__":
    app = QApplication(sys.argv)
    window = HashComparerApp()
    window.show()
    sys.exit(app.exec_())
