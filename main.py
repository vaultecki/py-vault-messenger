# ============================================================================
# main.py - Complete startup script with full setup
# ============================================================================
#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
Vault Messenger - Secure UDP-based P2P Messenger

Main entry point with complete initialization, error handling,
and proper shutdown procedures.
"""

import logging
import logging.handlers
import sys
from pathlib import Path
from typing import Optional

import PyQt6.QtWidgets
import PyQt6.QtCore

try:
    import vault_config
    from Messenger_GUI import MessengerGui, InputValidator, setup_logging
    import Message
except ImportError as e:
    print(f"ERROR: Failed to import required modules: {e}")
    print("Please install dependencies: pip install -r requirements.txt")
    sys.exit(1)


__version__ = "2.0.0"
__author__ = "Vault Development Team"


class VaultMessengerApp:
    """
    Application controller with lifecycle management.

    Handles:
    - Configuration loading/saving
    - Logging setup
    - Error handling
    - Graceful shutdown
    """

    def __init__(self) -> None:
        """Initialize application."""
        self.logger = logging.getLogger(__name__)
        self.config: Optional[vault_config.VaultConfig] = None
        self.qt_app: Optional[PyQt6.QtWidgets.QApplication] = None
        self.main_window: Optional[MessengerGui] = None

    def initialize(self) -> bool:
        """
        Initialize all application components.

        Returns:
            True if successful, False otherwise
        """
        try:
            print("=" * 70)
            print(f"Vault Messenger v{__version__}")
            print("=" * 70)

            # Step 1: Initialize configuration
            print("\n[1/4] Initializing configuration...")
            self._init_config()
            self.logger.info("Configuration initialized")

            # Step 2: Setup logging
            print("[2/4] Setting up logging...")
            setup_logging(self.config)
            self.logger.info("Logging initialized")

            # Step 3: Create Qt Application
            print("[3/4] Creating Qt application...")
            self.qt_app = PyQt6.QtWidgets.QApplication.instance()
            if self.qt_app is None:
                self.qt_app = PyQt6.QtWidgets.QApplication(sys.argv)

            # Configure Qt application
            self.qt_app.setApplicationName("Vault Messenger")
            self.qt_app.setApplicationVersion(__version__)
            self.logger.info("Qt application created")

            # Step 4: Create main window
            print("[4/4] Creating main window...")
            self.main_window = MessengerGui()
            self.logger.info("Main window created")

            print("✓ Application initialized successfully\n")
            return True

        except vault_config.ConfigError as e:
            self._handle_fatal_error("Configuration Error", str(e))
            return False
        except Exception as e:
            self._handle_fatal_error("Initialization Error", str(e))
            self.logger.exception("Initialization failed")
            return False

    def _init_config(self) -> None:
        """Initialize configuration."""
        try:
            self.config = vault_config.VaultConfig(
                app_name="VaultMessenger",
                use_encryption=True,
            )

            # Load existing or create new config
            self.config.load()

            # Ensure required settings exist
            self.config.get_or_create_string("user.name", "User")
            self.config.get_or_create_int("network.recv_port", 11000)
            self.config.get_or_create_string("logging.level", "INFO")

            self.config.save()

        except vault_config.ConfigError as e:
            raise vault_config.ConfigError(f"Failed to initialize config: {e}") from e

    def run(self) -> int:
        """
        Run the application.

        Returns:
            Exit code
        """
        if not self.initialize():
            return 1

        try:
            if self.main_window:
                self.main_window.show()

            if self.qt_app:
                return self.qt_app.exec()

            return 1

        except Exception as e:
            self.logger.exception("Application crashed: %s", e)
            self._handle_fatal_error("Application Error", f"Application crashed: {e}")
            return 1

    def shutdown(self) -> None:
        """Shutdown application gracefully."""
        try:
            self.logger.info("Shutting down...")

            # Save configuration
            if self.config:
                self.config.save()
                self.logger.debug("Configuration saved")

            # Close main window
            if self.main_window:
                self.main_window.close()
                self.logger.debug("Main window closed")

            # Quit Qt application
            if self.qt_app:
                self.qt_app.quit()

            self.logger.info("Shutdown complete")

        except Exception as e:
            self.logger.error("Error during shutdown: %s", e)

    @staticmethod
    def _handle_fatal_error(title: str, message: str) -> None:
        """
        Show fatal error dialog.

        Args:
            title: Error dialog title
            message: Error message
        """
        # Create minimal Qt app if needed
        app = PyQt6.QtWidgets.QApplication.instance()
        if app is None:
            app = PyQt6.QtWidgets.QApplication(sys.argv)

        # Show error dialog
        PyQt6.QtWidgets.QMessageBox.critical(
            None,
            f"Fatal Error - {title}",
            f"{message}\n\nPlease check the log file for details.",
        )


def setup_signal_handlers(app: VaultMessengerApp) -> None:
    """
    Setup signal handlers for clean shutdown.

    Args:
        app: Application instance
    """
    import signal

    def signal_handler(signum: int, frame) -> None:
        """Handle shutdown signals."""
        print("\n\nReceived shutdown signal, exiting...")
        app.shutdown()
        sys.exit(0)

    # Register signal handlers
    signal.signal(signal.SIGINT, signal_handler)   # Ctrl+C
    signal.signal(signal.SIGTERM, signal_handler)  # Termination


def main() -> int:
    """
    Main entry point.

    Returns:
        Exit code
    """
    # Set UTF-8 encoding
    if sys.stdout.encoding != "utf-8":
        import io
        sys.stdout = io.TextIOWrapper(sys.stdout.buffer, encoding="utf-8")
        sys.stderr = io.TextIOWrapper(sys.stderr.buffer, encoding="utf-8")

    # Create and configure application
    app = VaultMessengerApp()

    # Setup signal handlers
    setup_signal_handlers(app)

    # Run application
    try:
        exit_code = app.run()
    finally:
        app.shutdown()

    return exit_code


if __name__ == "__main__":
    sys.exit(main())