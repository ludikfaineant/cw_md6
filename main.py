import sys, os
import hashlib
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
    QDialog,
    QFormLayout,
    QSpinBox,
    QWidget,
    QMenuBar,
    QMenu,
    QAction,
)
from PyQt5.QtCore import Qt
import re
import random
import string
import subprocess


class HashComparerApp(QMainWindow):
    def __init__(self):
        super().__init__()

        self.setWindowTitle("MD6")
        self.setGeometry(100, 100, 700, 550)

        # Создание меню
        self.create_menu()

        # Главный layout
        main_layout = QVBoxLayout()

        # Переключатель между режимами файла и ввода вручную
        self.use_file_content_checkbox = QCheckBox("Use File Content")
        self.use_file_content_checkbox.setChecked(False)
        self.use_file_content_checkbox.stateChanged.connect(self.toggle_input_mode)

        # Переключатель для использования ключа
        self.use_key_checkbox = QCheckBox("Use Key")
        self.use_key_checkbox.setChecked(False)
        self.use_key_checkbox.stateChanged.connect(self.toggle_key_input)

        # Метки и поля для ввода
        self.file_path_input = QLineEdit(self)
        self.file_path_input.setReadOnly(True)

        self.browse_file_button = QPushButton("Browse", self)
        self.browse_file_button.clicked.connect(self.browse_file)

        # В разделе "Метки и поля для ввода" добавляем кнопку выбора файла

        self.file_path_label = QLabel("File Path", self)

        self.manual_input_text = QTextEdit(self)
        self.manual_input_text.setReadOnly(False)

        self.computed_hash_var = QLineEdit(self)
        self.computed_hash_var.setReadOnly(True)

        # Поле для ввода ключа (сначала скрыто)
        self.key_input_label = QLabel("Key Input")
        self.key_input_field = QLineEdit(self)
        self.key_input_field.setPlaceholderText("Enter key here...")
        self.key_input_field.setReadOnly(False)

        # Кнопка для вычисления хеша
        self.compute_hash_button = QPushButton("Compute Hash", self)
        self.compute_hash_button.clicked.connect(self.compute_hash)
        self.compare_hash_button = QPushButton("Compare Hash", self)
        self.compare_hash_button.clicked.connect(self.compare_hash)
        # Кнопка для генерации случайного ключа
        self.generate_key_button = QPushButton("Generate Key", self)
        self.generate_key_button.clicked.connect(self.generate_key)

        # Размещение элементов на форме
        file_layout = QVBoxLayout()
        file_layout.setContentsMargins(10, 10, 10, 10)
        file_layout.setSpacing(10)

        file_path_layout = QHBoxLayout()
        file_path_layout.addWidget(self.file_path_input)
        file_path_layout.addWidget(self.browse_file_button)

        # В разделе "Метки и поля для ввода"

        self.file_content_label = QLabel("File Content", self)
        file_layout.addWidget(self.use_file_content_checkbox)
        file_layout.addWidget(self.file_path_label)
        file_layout.addLayout(file_path_layout)

        file_layout.addWidget(self.file_content_label)
        file_layout.addWidget(self.manual_input_text)

        hash_layout = QVBoxLayout()
        hash_layout.setContentsMargins(10, 10, 10, 10)
        hash_layout.setSpacing(10)

        hash_layout.addWidget(self.use_key_checkbox)
        hash_layout.addWidget(self.key_input_label)  # Добавляем метку для ввода ключа

        # Горизонтальный layout для поля ввода ключа и кнопки генерации ключа
        key_layout = QHBoxLayout()
        key_layout.addWidget(self.key_input_field)
        key_layout.addWidget(self.generate_key_button)

        hash_layout.addLayout(key_layout)  # Добавляем горизонтальный layout
        hash_layout.addWidget(QLabel("Computed Hash"))

        compute_hash = QHBoxLayout()
        compute_hash.addWidget(self.computed_hash_var)
        compute_hash.addWidget(self.compare_hash_button)
        compute_hash.addWidget(self.compute_hash_button)
        hash_layout.addLayout(compute_hash)

        comparison_layout = QVBoxLayout()
        comparison_layout.setContentsMargins(10, 10, 10, 10)
        comparison_layout.setSpacing(10)

        # Скомпоновка всех layout'ов
        central_widget = QWidget(self)
        central_layout = QVBoxLayout(central_widget)
        central_layout.setContentsMargins(10, 10, 10, 10)
        central_layout.setSpacing(15)

        central_layout.addLayout(file_layout)
        central_layout.addLayout(hash_layout)
        central_layout.addLayout(comparison_layout)

        self.setCentralWidget(central_widget)

        # Переменные для хранения настроек
        self.key_min_length = 8
        self.key_max_length = 32
        self.key_allowed_characters = r"^[a-zA-Z0-9#!@$]*$"

        self.toggle_input_mode()
        self.toggle_key_input()

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

    def compute_hash(self):
        """Вычислить хеш на основе контента и выбранного ключа."""
        content = self.manual_input_text.toPlainText().strip()

        if not content:
            QMessageBox.critical(
                self, "Input Error", "Please enter some content to compute the hash."
            )
            return

        key = (
            self.key_input_field.text().strip()
            if self.use_key_checkbox.isChecked()
            else ""
        )

        if self.use_key_checkbox.isChecked() and not self.is_key_valid(key):
            QMessageBox.critical(
                self,
                "Invalid Key",
                f"Key must be between {self.key_min_length} and {self.key_max_length} characters and match the allowed pattern.\n"
                "Allowed characters: lowercase letters (a-z), uppercase letters (A-Z), and digits (0-9).",
            )
            return

        # Смешиваем контент и ключ
        combined_content = content + key

        try:
            # Важно передавать правильный формат (строка в Go, не байты)
            process = subprocess.Popen(
                ["./md6hash"],  # Пусть к Go-программе
                stdin=subprocess.PIPE,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,  # Это важно, чтобы передавать строки
            )

            # Передаем строку в Go-программу
            stdout, stderr = process.communicate(input=combined_content)

            if process.returncode != 0:
                print(f"Error output: {stderr}")  # Печать ошибки
                QMessageBox.critical(
                    self, "Error", f"Failed to compute MD6 hash:\n{stderr}"
                )
                return
            computed_hash = stdout.strip()
            self.computed_hash_var.setText(computed_hash)
        except Exception as e:
            print(f"Exception: {e}")  # Печать исключений
            QMessageBox.critical(
                self, "Error", f"An unexpected error occurred:\n{str(e)}"
            )

    def compare_hash(self):
        """Сравнить вычисленный хэш с загруженным."""
        computed_hash = self.computed_hash_var.text().strip()
        content = self.manual_input_text.toPlainText().strip()

        if not content:
            QMessageBox.critical(self, "Error", "No content to compute hash from.")
            return

        if not computed_hash:
            QMessageBox.warning(self, "Warning", "No hash loaded or computed.")
            return

        key = (
            self.key_input_field.text().strip()
            if self.use_key_checkbox.isChecked()
            else ""
        )

        # Смешиваем контент и ключ для вычисления
        combined_content = content + key
        try:
            # Важно передавать правильный формат (строка в Go, не байты)
            process = subprocess.Popen(
                ["./md6hash"],  # Пусть к Go-программе
                stdin=subprocess.PIPE,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,  # Это важно, чтобы передавать строки
            )

            # Передаем строку в Go-программу
            stdout, stderr = process.communicate(input=combined_content)

            if process.returncode != 0:
                print(f"Error output: {stderr}")  # Печать ошибки
                QMessageBox.critical(
                    self, "Error", f"Failed to compute MD6 hash:\n{stderr}"
                )
                return
            hash = stdout.strip()
            self.computed_hash_var.setText(computed_hash)
        except Exception as e:
            print(f"Exception: {e}")  # Печать исключений
            QMessageBox.critical(
                self, "Error", f"An unexpected error occurred:\n{str(e)}"
            )
        if hash == computed_hash:
            QMessageBox.information(self, "Comparison Result", "Hashes match!")
        else:
            QMessageBox.warning(self, "Comparison Result", "Hashes do not match!")

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

    def browse_file(self):
        """Открыть файл и отобразить его содержимое."""
        file_path, _ = QFileDialog.getOpenFileName(
            self, "Open File", "", "Text Files (*.txt);;All Files (*)"
        )
        if file_path:
            try:
                with open(
                    file_path, "r"
                ) as file:  # Используйте "r" для чтения в текстовом режиме
                    content = file.read()
                    self.manual_input_text.setText(
                        content
                    )  # Отображаем в текстовом поле
                    self.file_path_input.setText(file_path)  # Устанавливаем путь
            except Exception as e:
                QMessageBox.critical(self, "Error", f"Failed to read file: {e}")

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

    def show_about(self):
        """Показать информацию о приложении."""
        QMessageBox.about(
            self,
            "About",
            """Автор: Ларин Анатолий А-18-21

            Приложение для вычисления хэша файлов с использованием алгоритма MD6.
            Данное приложение предоставляет возможности:
            - Вводить данные вручную или загружать файлы для вычисления хэша
            - Сравнивать хэш с загруженным файлом хэша
            - Сохранять и загружать хэши для дальнейшей проверки
            
            Используемые алгоритмы:
            - Алгоритм MD6 (реализован с использованием функции сжатия SHA-256)
            """,
        )

    def quit(self):
        """Закрыть приложение."""
        QApplication.quit()


# Run the application
if __name__ == "__main__":
    app = QApplication(sys.argv)
    window = HashComparerApp()
    window.show()
    sys.exit(app.exec_())
