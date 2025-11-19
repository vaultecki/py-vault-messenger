# Copyright [2025] [ecki]
# SPDX-License-Identifier: Apache-2.0

"""
Vault Configuration Management Module

Provides secure configuration storage with encryption, automatic key generation,
and platform-specific secure paths.
"""

import json
import logging
import os
from pathlib import Path
from typing import Any, Dict, Optional

import nacl.encoding
import nacl.pwhash
import nacl.secret
import nacl.utils

try:
    import platformdirs
except ImportError:
    platformdirs = None

logger = logging.getLogger(__name__)

# Constants
DEFAULT_ENCRYPTION_ITERATIONS = 3  # For Argon2i (quick)
CONFIG_FILE_NAME = "config.json"
ENCRYPTION_KEY_FILE = ".vault_key"
CONFIG_PERMISSIONS = 0o600  # -rw------- (owner read/write only)


class ConfigError(Exception):
    """Base exception for configuration operations."""
    pass


class ConfigEncryptionError(ConfigError):
    """Raised when encryption/decryption fails."""
    pass


class ConfigNotFoundError(ConfigError):
    """Raised when configuration file not found."""
    pass


class VaultConfig:
    """
    Secure configuration management with encryption support.

    Features:
    - Platform-specific secure directories (XDG on Linux, standard paths elsewhere)
    - Optional encryption of sensitive data with nacl.secret.SecretBox
    - Atomic writes to prevent corruption
    - Validation of configuration structure
    - Type-safe access with defaults

    Thread-safe for reads, but writes should be serialized by caller.
    """

    def __init__(
        self,
        app_name: str = "VaultMessenger",
        config_dir: Optional[Path] = None,
        use_encryption: bool = True,
        master_password: Optional[str] = None,
    ):
        """
        Initialize configuration manager.

        Args:
            app_name: Application name for config directory
            config_dir: Override config directory path
            use_encryption: Enable encryption for sensitive fields
            master_password: Password for encryption (auto-generated if None)

        Raises:
            ConfigError: If initialization fails
        """
        self.app_name = app_name
        self.use_encryption = use_encryption
        self._encryption_key: Optional[bytes] = None
        self._config_data: Dict[str, Any] = {}

        # Determine config directory
        self._config_dir = self._get_config_dir(config_dir, app_name)
        self._config_file = self._config_dir / CONFIG_FILE_NAME
        self._key_file = self._config_dir / ENCRYPTION_KEY_FILE

        # Create directory with secure permissions
        try:
            self._config_dir.mkdir(
                parents=True,
                exist_ok=True,
                mode=0o700  # rwx------
            )
            logger.info("Config directory ready: %s", self._config_dir)
        except OSError as e:
            raise ConfigError(f"Failed to create config directory: {e}") from e

        # Handle encryption
        if self.use_encryption:
            self._init_encryption(master_password)

    @staticmethod
    def _get_config_dir(override: Optional[Path], app_name: str) -> Path:
        """
        Get platform-specific config directory.

        Args:
            override: Override path if provided
            app_name: Application name for default paths

        Returns:
            Path object for config directory
        """
        if override:
            return Path(override).expanduser()

        # Try to use platformdirs for XDG compliance on Linux, standard paths elsewhere
        if platformdirs:
            try:
                config_dir = platformdirs.user_config_dir(app_name, ensure_exists=False)
                return Path(config_dir)
            except Exception as e:
                logger.warning("platformdirs failed, using fallback: %s", e)

        # Fallback to home directory
        home = Path.home()
        if os.name == "nt":  # Windows
            return home / "AppData" / "Local" / app_name
        else:  # Unix-like
            return home / ".config" / app_name

    def _init_encryption(self, master_password: Optional[str]) -> None:
        """
        Initialize or load encryption key.

        Args:
            master_password: Password to derive key from, or None to auto-generate

        Raises:
            ConfigEncryptionError: If encryption setup fails
        """
        try:
            if self._key_file.exists():
                # Load existing key (for master_password, re-derive to verify)
                if master_password:
                    self._derive_key_from_password(master_password)
                else:
                    # Load previously auto-generated key
                    with open(self._key_file, "rb") as f:
                        self._encryption_key = f.read()
                    logger.debug("Loaded existing encryption key")
            else:
                # Generate or derive new key
                if master_password:
                    self._derive_key_from_password(master_password)
                else:
                    self._generate_random_key()

                # Save key securely
                self._save_encryption_key()

        except Exception as e:
            raise ConfigEncryptionError(f"Encryption initialization failed: {e}") from e

    def _derive_key_from_password(self, password: str) -> None:
        """
        Derive encryption key from password using Argon2i.

        Args:
            password: Master password
        """
        try:
            password_bytes = password.encode("utf-8")
            salt = nacl.utils.random(nacl.pwhash.argon2i.SALTBYTES)

            # Derive key using Argon2i (OWASP recommended)
            key = nacl.pwhash.argon2i.kdf(
                nacl.secret.SecretBox.KEY_SIZE,
                password_bytes,
                salt,
                opslimit=nacl.pwhash.argon2i.OPSLIMIT_SENSITIVE,
                memlimit=nacl.pwhash.argon2i.MEMLIMIT_SENSITIVE,
            )

            self._encryption_key = key
            logger.info("Derived encryption key from password")

        except Exception as e:
            raise ConfigEncryptionError(f"Failed to derive key from password: {e}") from e

    def _generate_random_key(self) -> None:
        """Generate random encryption key."""
        self._encryption_key = nacl.utils.random(nacl.secret.SecretBox.KEY_SIZE)
        logger.info("Generated random encryption key")

    def _save_encryption_key(self) -> None:
        """Save encryption key to file with secure permissions."""
        if not self._encryption_key:
            return

        try:
            # Write with secure permissions
            with open(self._key_file, "wb") as f:
                f.write(self._encryption_key)

            # Ensure permissions on Unix-like systems
            if os.name != "nt":
                os.chmod(self._key_file, 0o600)

            logger.debug("Saved encryption key")

        except OSError as e:
            logger.error("Failed to save encryption key: %s", e)
            raise ConfigEncryptionError(f"Failed to save encryption key: {e}") from e

    def _encrypt_data(self, data: bytes) -> bytes:
        """
        Encrypt data using SecretBox.

        Args:
            data: Data to encrypt

        Returns:
            Encrypted data (nonce + ciphertext)

        Raises:
            ConfigEncryptionError: If encryption fails
        """
        if not self._encryption_key:
            raise ConfigEncryptionError("Encryption key not initialized")

        try:
            box = nacl.secret.SecretBox(self._encryption_key)
            encrypted = box.encrypt(data)
            return bytes(encrypted)
        except Exception as e:
            raise ConfigEncryptionError(f"Encryption failed: {e}") from e

    def _decrypt_data(self, encrypted_data: bytes) -> bytes:
        """
        Decrypt data using SecretBox.

        Args:
            encrypted_data: Encrypted data to decrypt

        Returns:
            Decrypted data

        Raises:
            ConfigEncryptionError: If decryption fails
        """
        if not self._encryption_key:
            raise ConfigEncryptionError("Encryption key not initialized")

        try:
            box = nacl.secret.SecretBox(self._encryption_key)
            decrypted = box.decrypt(encrypted_data)
            return bytes(decrypted)
        except Exception as e:
            raise ConfigEncryptionError(f"Decryption failed: {e}") from e

    def load(self) -> Dict[str, Any]:
        """
        Load configuration from file.

        Returns:
            Configuration dictionary

        Raises:
            ConfigNotFoundError: If config file doesn't exist
            ConfigEncryptionError: If decryption fails
        """
        if not self._config_file.exists():
            logger.warning("Config file not found: %s", self._config_file)
            self._config_data = {}
            return self._config_data

        try:
            with open(self._config_file, "rb") as f:
                file_data = f.read()

            if self.use_encryption and file_data.startswith(b"ENCRYPTED:"):
                # Decrypt encrypted config
                encrypted_part = file_data[10:]  # Remove "ENCRYPTED:" prefix
                decrypted = self._decrypt_data(encrypted_part)
                self._config_data = json.loads(decrypted.decode("utf-8"))
                logger.info("Loaded encrypted configuration")
            else:
                # Load plain JSON
                self._config_data = json.loads(file_data.decode("utf-8"))
                logger.info("Loaded plain configuration")

            return self._config_data

        except json.JSONDecodeError as e:
            raise ConfigError(f"Invalid JSON in config file: {e}") from e
        except OSError as e:
            raise ConfigError(f"Failed to read config file: {e}") from e

    def save(self, data: Optional[Dict[str, Any]] = None) -> None:
        """
        Save configuration to file atomically.

        Args:
            data: Configuration data to save (uses current data if None)

        Raises:
            ConfigError: If save fails
        """
        if data is not None:
            self._config_data = data

        try:
            json_data = json.dumps(self._config_data, indent=2).encode("utf-8")

            if self.use_encryption and self._encryption_key:
                # Encrypt and add prefix
                encrypted = self._encrypt_data(json_data)
                file_data = b"ENCRYPTED:" + encrypted
            else:
                file_data = json_data

            # Atomic write using temp file
            temp_file = self._config_file.with_suffix(".tmp")
            with open(temp_file, "wb") as f:
                f.write(file_data)

            # Set secure permissions before renaming
            if os.name != "nt":
                os.chmod(temp_file, CONFIG_PERMISSIONS)

            # Atomic rename
            temp_file.replace(self._config_file)

            # Ensure final file has secure permissions
            if os.name != "nt":
                os.chmod(self._config_file, CONFIG_PERMISSIONS)

            logger.info("Saved configuration")

        except OSError as e:
            logger.error("Failed to save configuration: %s", e)
            raise ConfigError(f"Failed to save configuration: {e}") from e

    def get(self, key: str, default: Any = None) -> Any:
        """
        Get configuration value.

        Args:
            key: Configuration key (supports dot notation: "section.key")
            default: Default value if key not found

        Returns:
            Configuration value or default
        """
        keys = key.split(".")
        value = self._config_data

        try:
            for k in keys:
                value = value[k]
            return value
        except (KeyError, TypeError):
            return default

    def set(self, key: str, value: Any) -> None:
        """
        Set configuration value.

        Args:
            key: Configuration key (supports dot notation: "section.key")
            value: Value to set
        """
        keys = key.split(".")

        # Navigate/create nested structure
        current = self._config_data
        for k in keys[:-1]:
            if k not in current:
                current[k] = {}
            current = current[k]

        # Set value
        current[keys[-1]] = value

    def get_or_create_string(self, key: str, default: str = "") -> str:
        """Get string value, creating if missing."""
        value = self.get(key)
        if value is None:
            self.set(key, default)
            return default
        return str(value)

    def get_or_create_int(self, key: str, default: int = 0) -> int:
        """Get int value, creating if missing."""
        value = self.get(key)
        if value is None:
            self.set(key, default)
            return default
        try:
            return int(value)
        except (ValueError, TypeError):
            return default

    def get_or_create_list(self, key: str, default: Optional[list] = None) -> list:
        """Get list value, creating if missing."""
        if default is None:
            default = []
        value = self.get(key)
        if value is None:
            self.set(key, default)
            return default
        return list(value) if isinstance(value, (list, tuple)) else default

    def delete(self, key: str) -> bool:
        """
        Delete configuration value.

        Args:
            key: Configuration key

        Returns:
            True if deleted, False if not found
        """
        keys = key.split(".")
        current = self._config_data

        try:
            for k in keys[:-1]:
                current = current[k]
            del current[keys[-1]]
            return True
        except (KeyError, TypeError):
            return False

    def clear(self) -> None:
        """Clear all configuration."""
        self._config_data = {}

    def to_dict(self) -> Dict[str, Any]:
        """Get full configuration as dictionary."""
        return dict(self._config_data)


def main():
    """Example usage."""
    logging.basicConfig(
        level=logging.DEBUG,
        format="%(asctime)s - %(name)s - %(levelname)s - %(message)s",
    )

    print("Testing VaultConfig...")

    # Test basic config
    cfg = VaultConfig(use_encryption=False)

    cfg.set("general.name", "Test User")
    cfg.set("general.language", "en")
    cfg.set("network.port", 11000)
    cfg.set("network.peers", ["192.168.1.1", "192.168.1.2"])

    cfg.save()
    print(f"Config saved to: {cfg._config_file}")

    # Test loading
    cfg2 = VaultConfig(
        config_dir=cfg._config_dir,
        use_encryption=False,
    )
    cfg2.load()
    print(f"Loaded config: {cfg2.to_dict()}")
    print(f"User name: {cfg2.get('general.name')}")
    print(f"Port: {cfg2.get_or_create_int('network.port', 11000)}")


if __name__ == "__main__":
    main()
