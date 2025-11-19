# Copyright [2025] [ecki]
# SPDX-License-Identifier: Apache-2.0

"""
Vault Messenger GUI Module

Provides PyQt6-based graphical interface with proper threading,
input validation, and error handling.
"""

import json
import logging
import os
from datetime import datetime
from pathlib import Path
from typing import Dict, List, Optional, Tuple

import PyQt6.QtCore
import PyQt6.QtGui
import PyQt6.QtWidgets
import PySignal

import Message
import vault_config

logger = logging.getLogger(__name__)

# Constants
VALID_PORT_MIN = 1500
VALID_PORT_MAX = 65000
DEFAULT_RECV_PORT = 11000
MESSAGE_DISPLAY_LIMIT = 1000  # Max messages in list


class InputValidator:
    """Centralized input validation utilities."""

    @staticmethod
    def validate_port(port_input: str) -> Tuple[bool, Optional[int], str]:
        """
        Validate port number input.

        Returns:
            Tuple of (is_valid, port_int, error_message)
        """
        try:
            port = int(port_input.strip())
        except ValueError:
            return False, None, "Port must be a number"

        if port < VALID_PORT_MIN or port > VALID_PORT_MAX:
            return (
                False,
                None,
                f"Port must be between {VALID_PORT_MIN} and {VALID_PORT_MAX}",
            )

        return True, port, ""

    @staticmethod
    def validate_ip(ip_input: str) -> Tuple[bool, str]:
        """
        Validate IP address (basic check).

        Returns:
            Tuple of (is_valid, error_message)
        """
        ip_input = ip_input.strip()

        if not ip_input:
            return False, "IP address cannot be empty"

        parts = ip_input.split(".")
        if len(parts) != 4:
            return False, "Invalid IP format (use a.b.c.d)"

        try:
            for part in parts:
                num = int(part)
                if num < 0 or num > 255:
                    return False, f"Invalid IP octet: {num}"
        except ValueError:
            return False, "IP address must contain only numbers and dots"

        return True, ""

    @staticmethod
    def validate_name(name_input: str) -> Tuple[bool, str]:
        """
        Validate user name.

        Returns:
            Tuple of (is_valid, error_message)
        """
        name = name_input.strip()

        if not name:
            return False, "Name cannot be empty"

        if len(name) > 100:
            return False, "Name too long (max 100 characters)"

        # Allow alphanumeric, spaces, hyphens, underscores
        if not all(c.isalnum() or c in " -_" for c in name):
            return False, "Name contains invalid characters"

        return True, ""


class NetworkWorker(PyQt6.QtCore.QObject):
    """Worker thread for network operations (non-blocking)."""

    # Signals
    finished = PySignal.ClassSignal()
    error = PySignal.ClassSignal()
    progress = PySignal.ClassSignal()

    def __init__(self) -> None:
        """Initialize worker."""
        super().__init__()
        self._stop_requested = False

    def stop(self) -> None:
        """Request worker to stop."""
        self._stop_requested = True

    def send_message(self, message: Message.Message, addr: Optional[Tuple[str, int]] = None) -> None:
        """
        Send message (placeholder for actual implementation).

        Args:
            message: Message to send
            addr: Target address
        """
        try:
            # Placeholder: actual sending would happen here
            logger.debug("Sending message from worker thread")
            self.progress.emit(f"Sent: {message.get_type()}")
            self.finished.emit()
        except Exception as e:
            logger.error("Network worker error: %s", e)
            self.error.emit(str(e))


class MessengerGui(PyQt6.QtWidgets.QWidget):
    """
    Main messenger GUI window with improved threading and validation.

    Features:
    - Proper QThread-based worker threads (no blocking GUI)
    - Input validation for all user inputs
    - Secure config file handling
    - Comprehensive error messages
    - Type hints throughout
    """

    def __init__(self) -> None:
        """Initialize GUI."""
        super().__init__()

        self.logger = logging.getLogger(__name__)
        self.logger.info("Initializing MessengerGui")

        # Configuration
        self.config = vault_config.VaultConfig(
            app_name="VaultMessenger",
            use_encryption=True,
        )
        self.config.load()

        # Network state
        self._network_thread: Optional[PyQt6.QtCore.QThread] = None
        self._network_worker: Optional[NetworkWorker] = None
        self._message_count = 0

        # UI Setup
        self._setup_ui()
        self._restore_window_state()
        self._start_network_worker()

        self.logger.info("MessengerGui initialized")

    def _setup_ui(self) -> None:
        """Setup user interface."""
        self.setWindowTitle(
            self.config.get_or_create_string("gui.title", "Vault Messenger")
        )
        self.setGeometry(100, 100, 800, 600)

        layout = PyQt6.QtWidgets.QVBoxLayout()

        # Title
        title_label = PyQt6.QtWidgets.QLabel("Vault Messenger")
        title_font = title_label.font()
        title_font.setPointSize(14)
        title_font.setBold(True)
        title_label.setFont(title_font)
        layout.addWidget(title_label)

        # Output area
        output_label = PyQt6.QtWidgets.QLabel("Messages:")
        layout.addWidget(output_label)

        self.output_box = PyQt6.QtWidgets.QListWidget()
        self.output_box.setMinimumHeight(300)
        layout.addWidget(self.output_box)

        # Input area
        input_label = PyQt6.QtWidgets.QLabel("Your message:")
        layout.addWidget(input_label)

        input_layout = PyQt6.QtWidgets.QHBoxLayout()

        self.textbox = PyQt6.QtWidgets.QLineEdit()
        self.textbox.setMinimumHeight(35)
        self.textbox.setPlaceholderText("Type a message...")
        self.textbox.returnPressed.connect(self._on_click_button_send)
        input_layout.addWidget(self.textbox)

        btn_send = PyQt6.QtWidgets.QPushButton("Send")
        btn_send.setMinimumHeight(35)
        btn_send.clicked.connect(self._on_click_button_send)
        input_layout.addWidget(btn_send)

        layout.addLayout(input_layout)

        # Control buttons
        button_layout = PyQt6.QtWidgets.QHBoxLayout()

        btn_options = PyQt6.QtWidgets.QPushButton("Settings")
        btn_options.clicked.connect(self._on_click_button_options)
        button_layout.addWidget(btn_options)

        btn_state = PyQt6.QtWidgets.QPushButton("Status")
        btn_state.clicked.connect(self._on_click_button_state)
        button_layout.addWidget(btn_state)

        btn_clear = PyQt6.QtWidgets.QPushButton("Clear")
        btn_clear.clicked.connect(self._on_click_button_clear)
        button_layout.addWidget(btn_clear)

        layout.addLayout(button_layout)

        self.setLayout(layout)

    def _start_network_worker(self) -> None:
        """Start network worker thread."""
        try:
            self._network_thread = PyQt6.QtCore.QThread()
            self._network_worker = NetworkWorker()
            self._network_worker.moveToThread(self._network_thread)

            # Connect signals
            self._network_thread.started.connect(self._on_network_worker_started)
            self._network_worker.finished.connect(self._on_network_worker_finished)
            self._network_worker.error.connect(self._on_network_worker_error)

            self._network_thread.start()
            self.logger.info("Network worker thread started")

        except Exception as e:
            self.logger.error("Failed to start network worker: %s", e)
            PyQt6.QtWidgets.QMessageBox.critical(
                self,
                "Initialization Error",
                f"Failed to start network services: {e}",
            )

    def _on_network_worker_started(self) -> None:
        """Called when network worker starts."""
        self.logger.debug("Network worker started")

    def _on_network_worker_finished(self) -> None:
        """Called when network operation finishes."""
        self.logger.debug("Network operation finished")

    def _on_network_worker_error(self, error_msg: str) -> None:
        """
        Called when network error occurs.

        Args:
            error_msg: Error message
        """
        self.logger.error("Network worker error: %s", error_msg)
        self._add_message(f"⚠️ Network Error: {error_msg}")

    def _add_message(self, text: str) -> None:
        """
        Add message to output box with timestamp.

        Args:
            text: Message text
        """
        timestamp = datetime.now().strftime("%H:%M:%S")
        full_text = f"[{timestamp}] {text}"

        self.output_box.addItem(full_text)
        self._message_count += 1

        # Limit message history
        while self.output_box.count() > MESSAGE_DISPLAY_LIMIT:
            self.output_box.takeItem(0)

        # Scroll to bottom
        self.output_box.scrollToBottom()

    def _on_click_button_send(self) -> None:
        """Handle send button click."""
        text = self.textbox.text().strip()

        if not text:
            self._add_message("⚠️ Message cannot be empty")
            return

        if len(text) > 10000:
            PyQt6.QtWidgets.QMessageBox.warning(
                self,
                "Message Too Long",
                "Message exceeds maximum length (10000 characters)",
            )
            return

        try:
            # Create and send message
            msg = Message.Message()
            msg.set_text(text)

            self._add_message(f"→ You: {text}")
            self.textbox.clear()

            self.logger.debug("Message sent: %s", msg.get_id())

        except Message.MessageError as e:
            self.logger.error("Message creation failed: %s", e)
            PyQt6.QtWidgets.QMessageBox.warning(
                self,
                "Message Error",
                f"Failed to create message: {e}",
            )

    def _on_click_button_options(self) -> None:
        """Handle settings button click."""
        try:
            dialog = SettingsDialog(self.config, parent=self)
            if dialog.exec() == PyQt6.QtWidgets.QDialog.DialogCode.Accepted:
                self.config.save()
                self.logger.info("Settings saved")
                self._add_message("✓ Settings updated")
        except Exception as e:
            self.logger.error("Settings dialog error: %s", e)
            PyQt6.QtWidgets.QMessageBox.critical(
                self,
                "Settings Error",
                f"Failed to open settings: {e}",
            )

    def _on_click_button_state(self) -> None:
        """Handle status button click."""
        addr = self.config.get("network.recv_port", DEFAULT_RECV_PORT)
        self._add_message(f"📡 Listening on port {addr}")

    def _on_click_button_clear(self) -> None:
        """Handle clear button click."""
        self.output_box.clear()
        self._message_count = 0
        self.logger.debug("Message history cleared")

    def _restore_window_state(self) -> None:
        """Restore window state from config."""
        try:
            geometry = self.config.get("gui.geometry")
            if geometry and isinstance(geometry, dict):
                self.setGeometry(
                    geometry.get("x", 100),
                    geometry.get("y", 100),
                    geometry.get("width", 800),
                    geometry.get("height", 600),
                )
        except Exception as e:
            self.logger.debug("Failed to restore window state: %s", e)

    def _save_window_state(self) -> None:
        """Save window state to config."""
        try:
            rect = self.geometry()
            self.config.set(
                "gui.geometry",
                {"x": rect.x(), "y": rect.y(), "width": rect.width(), "height": rect.height()},
            )
            self.config.save()
        except Exception as e:
            self.logger.warning("Failed to save window state: %s", e)

    def closeEvent(self, event: PyQt6.QtGui.QCloseEvent) -> None:
        """Handle window close event."""
        self._save_window_state()

        # Stop network worker
        if self._network_worker:
            self._network_worker.stop()

        if self._network_thread:
            self._network_thread.quit()
            self._network_thread.wait(timeout=5000)

        super().closeEvent(event)


class SettingsDialog(PyQt6.QtWidgets.QDialog):
    """Settings dialog with input validation."""

    def __init__(
        self,
        config: vault_config.VaultConfig,
        parent: Optional[PyQt6.QtWidgets.QWidget] = None,
    ) -> None:
        """
        Initialize settings dialog.

        Args:
            config: Configuration object
            parent: Parent widget
        """
        super().__init__(parent)
        self.setWindowTitle("Settings")
        self.setMinimumWidth(400)

        self.config = config
        self.logger = logging.getLogger(__name__)

        self._setup_ui()

    def _setup_ui(self) -> None:
        """Setup settings dialog UI."""
        layout = PyQt6.QtWidgets.QFormLayout()

        # User name
        name_label = PyQt6.QtWidgets.QLabel("Display Name:")
        self.name_input = PyQt6.QtWidgets.QLineEdit()
        self.name_input.setText(self.config.get_or_create_string("user.name", "User"))
        self.name_input.setMaxLength(100)
        layout.addRow(name_label, self.name_input)

        # Port
        port_label = PyQt6.QtWidgets.QLabel("Listen Port:")
        self.port_input = PyQt6.QtWidgets.QLineEdit()
        port_value = str(self.config.get_or_create_int("network.recv_port", DEFAULT_RECV_PORT))
        self.port_input.setText(port_value)
        self.port_input.setValidator(PyQt6.QtGui.QIntValidator(VALID_PORT_MIN, VALID_PORT_MAX))
        layout.addRow(port_label, self.port_input)

        # Buttons
        button_layout = PyQt6.QtWidgets.QHBoxLayout()

        btn_cancel = PyQt6.QtWidgets.QPushButton("Cancel")
        btn_cancel.clicked.connect(self.reject)
        button_layout.addWidget(btn_cancel)

        btn_ok = PyQt6.QtWidgets.QPushButton("OK")
        btn_ok.clicked.connect(self._validate_and_accept)
        button_layout.addWidget(btn_ok)

        layout.addRow(button_layout)

        self.setLayout(layout)

    def _validate_and_accept(self) -> None:
        """Validate inputs and accept dialog."""
        # Validate name
        name = self.name_input.text()
        is_valid, error = InputValidator.validate_name(name)
        if not is_valid:
            PyQt6.QtWidgets.QMessageBox.warning(self, "Invalid Name", error)
            return

        # Validate port
        port_text = self.port_input.text()
        is_valid, port, error = InputValidator.validate_port(port_text)
        if not is_valid:
            PyQt6.QtWidgets.QMessageBox.warning(self, "Invalid Port", error)
            return

        # Save to config
        try:
            self.config.set("user.name", name)
            self.config.set("network.recv_port", port)
            self.logger.info("Settings validated and saved: name=%s, port=%d", name, port)
            self.accept()
        except Exception as e:
            self.logger.error("Failed to save settings: %s", e)
            PyQt6.QtWidgets.QMessageBox.critical(
                self,
                "Save Error",
                f"Failed to save settings: {e}",
            )


def setup_logging(config: vault_config.VaultConfig) -> None:
    """
    Setup logging with file rotation.

    Args:
        config: Configuration object
    """
    import logging.handlers

    log_level = config.get_or_create_string("logging.level", "INFO")
    log_dir = config._config_dir / "logs"
    log_dir.mkdir(exist_ok=True)
    log_file = log_dir / "messenger.log"

    # File handler with rotation
    file_handler = logging.handlers.RotatingFileHandler(
        log_file,
        maxBytes=10_000_000,  # 10 MB
        backupCount=5,
    )
    file_handler.setFormatter(
        logging.Formatter(
            "%(asctime)s - %(name)s - %(levelname)s - %(message)s"
        )
    )

    # Console handler
    console_handler = logging.StreamHandler()
    console_handler.setFormatter(
        logging.Formatter("%(asctime)s - %(levelname)s - %(message)s")
    )

    # Root logger
    root_logger = logging.getLogger()
    root_logger.setLevel(getattr(logging, log_level))
    root_logger.addHandler(file_handler)
    root_logger.addHandler(console_handler)

    logger.info("Logging initialized: level=%s, file=%s", log_level, log_file)


def main() -> None:
    """Main entry point."""
    app = PyQt6.QtWidgets.QApplication([])

    # Setup logging
    config = vault_config.VaultConfig(app_name="VaultMessenger", use_encryption=True)
    config.load()
    setup_logging(config)

    # Create and show window
    window = MessengerGui()
    window.show()

    app.exec()


if __name__ == "__main__":
    main()
