# Copyright [2025] [ecki]
# SPDX-License-Identifier: Apache-2.0

"""
Vault Messenger - Test Suite

Comprehensive unit and integration tests for all components.

Run with: python -m pytest test_suite.py -v
"""

import json
import tempfile
import unittest
from pathlib import Path
from typing import Optional

import nacl.utils

import Message
import vault_config
from Messenger_GUI import InputValidator


# ============================================================================
# Configuration Tests
# ============================================================================


class TestVaultConfig(unittest.TestCase):
    """Test vault_config module."""

    def setUp(self) -> None:
        """Set up test fixtures."""
        self.temp_dir = tempfile.TemporaryDirectory()
        self.config_dir = Path(self.temp_dir.name)

    def tearDown(self) -> None:
        """Clean up test fixtures."""
        self.temp_dir.cleanup()

    def test_config_creation(self) -> None:
        """Test creating new configuration."""
        config = vault_config.VaultConfig(
            config_dir=self.config_dir,
            use_encryption=False,
        )

        self.assertIsNotNone(config)
        self.assertEqual(config._config_dir, self.config_dir)

    def test_config_set_and_get(self) -> None:
        """Test setting and getting configuration values."""
        config = vault_config.VaultConfig(
            config_dir=self.config_dir,
            use_encryption=False,
        )

        config.set("test.key", "test_value")
        self.assertEqual(config.get("test.key"), "test_value")

    def test_config_dot_notation(self) -> None:
        """Test nested dot notation access."""
        config = vault_config.VaultConfig(
            config_dir=self.config_dir,
            use_encryption=False,
        )

        config.set("section.subsection.key", "value")
        self.assertEqual(config.get("section.subsection.key"), "value")

    def test_config_get_default(self) -> None:
        """Test default value retrieval."""
        config = vault_config.VaultConfig(
            config_dir=self.config_dir,
            use_encryption=False,
        )

        value = config.get("nonexistent.key", "default")
        self.assertEqual(value, "default")

    def test_config_save_and_load(self) -> None:
        """Test saving and loading configuration."""
        config = vault_config.VaultConfig(
            config_dir=self.config_dir,
            use_encryption=False,
        )

        config.set("user.name", "TestUser")
        config.set("network.port", 12345)
        config.save()

        # Load in new instance
        config2 = vault_config.VaultConfig(
            config_dir=self.config_dir,
            use_encryption=False,
        )
        config2.load()

        self.assertEqual(config2.get("user.name"), "TestUser")
        self.assertEqual(config2.get("network.port"), 12345)

    def test_config_encryption(self) -> None:
        """Test encryption and decryption."""
        config = vault_config.VaultConfig(
            config_dir=self.config_dir,
            use_encryption=True,
        )

        config.set("sensitive.data", "secret123")
        config.save()

        # Verify file is encrypted
        with open(config._config_file, "rb") as f:
            content = f.read()
            self.assertTrue(content.startswith(b"ENCRYPTED:"))

        # Load and verify
        config2 = vault_config.VaultConfig(
            config_dir=self.config_dir,
            use_encryption=True,
        )
        config2.load()
        self.assertEqual(config2.get("sensitive.data"), "secret123")

    def test_config_get_or_create_string(self) -> None:
        """Test get_or_create_string."""
        config = vault_config.VaultConfig(
            config_dir=self.config_dir,
            use_encryption=False,
        )

        value = config.get_or_create_string("new.key", "default_value")
        self.assertEqual(value, "default_value")
        self.assertEqual(config.get("new.key"), "default_value")

    def test_config_get_or_create_int(self) -> None:
        """Test get_or_create_int."""
        config = vault_config.VaultConfig(
            config_dir=self.config_dir,
            use_encryption=False,
        )

        value = config.get_or_create_int("port", 11000)
        self.assertEqual(value, 11000)
        self.assertEqual(config.get("port"), 11000)

    def test_config_delete(self) -> None:
        """Test deleting configuration values."""
        config = vault_config.VaultConfig(
            config_dir=self.config_dir,
            use_encryption=False,
        )

        config.set("temp.key", "value")
        self.assertTrue(config.delete("temp.key"))
        self.assertIsNone(config.get("temp.key"))


# ============================================================================
# Message Tests
# ============================================================================


class TestMessage(unittest.TestCase):
    """Test Message class."""

    def test_message_creation(self) -> None:
        """Test creating a message."""
        msg = Message.Message()
        self.assertIsNotNone(msg)

    def test_set_text(self) -> None:
        """Test setting text message."""
        msg = Message.Message()
        msg.set_text("Hello, World!")

        self.assertEqual(msg.get_type(), "txt")
        self.assertEqual(msg.get_content(), "Hello, World!")

    def test_set_text_empty(self) -> None:
        """Test setting empty text."""
        msg = Message.Message()
        msg.set_text("")

        self.assertEqual(msg.get_content(), "")

    def test_set_text_invalid_type(self) -> None:
        """Test setting text with invalid type."""
        msg = Message.Message()

        with self.assertRaises(TypeError):
            msg.set_text(123)  # type: ignore

    def test_message_uuid_format(self) -> None:
        """Test that UUID is 32-character hex string (128-bit)."""
        msg = Message.Message()
        msg.set_text("test")

        uuid = msg.get_id()
        self.assertEqual(len(uuid), 32)  # 128 bits = 16 bytes = 32 hex chars
        self.assertTrue(all(c in "0123456789abcdef" for c in uuid))

    def test_message_uuid_uniqueness(self) -> None:
        """Test that each message gets unique UUID."""
        msg1 = Message.Message()
        msg1.set_text("test1")

        msg2 = Message.Message()
        msg2.set_text("test2")

        self.assertNotEqual(msg1.get_id(), msg2.get_id())

    def test_message_to_json(self) -> None:
        """Test converting message to JSON."""
        msg = Message.Message()
        msg.set_text("Test message")

        json_list = msg.to_json()
        self.assertIsInstance(json_list, list)
        self.assertGreater(len(json_list), 0)

        # Verify JSON is valid
        for json_str in json_list:
            parsed = json.loads(json_str)
            self.assertIn("id", parsed)
            self.assertIn("content", parsed)

    def test_message_from_json_roundtrip(self) -> None:
        """Test message roundtrip: to_json -> from_json."""
        msg1 = Message.Message()
        original_text = "This is a test message! " * 50

        msg1.set_text(original_text)
        json_list = msg1.to_json()

        # Reconstruct
        msg2 = Message.Message()
        msg2.from_json(json_list)

        self.assertEqual(msg2.get_content(), original_text)
        self.assertEqual(msg2.get_type(), msg1.get_type())

    def test_message_segmentation(self) -> None:
        """Test that large messages are segmented."""
        msg = Message.Message(max_length=500)

        large_text = "x" * 5000
        msg.set_text(large_text)

        json_list = msg.to_json()
        # Should be split into multiple segments
        self.assertGreater(len(json_list), 1)

    def test_message_hash_verification(self) -> None:
        """Test hash verification."""
        msg1 = Message.Message()
        msg1.set_text("Test")

        json_list = msg1.to_json()

        msg2 = Message.Message()
        msg2.from_json(json_list)

        # Should not raise error
        self.assertEqual(msg2.get_content(), "Test")

    def test_message_hash_corruption(self) -> None:
        """Test that corrupted message is rejected."""
        msg1 = Message.Message()
        msg1.set_text("Test")

        json_list = msg1.to_json()

        # Corrupt the hash
        json_dict = json.loads(json_list[-1])
        json_dict["hash"] = "corrupted_hash"
        corrupted_json = json.dumps(json_dict)

        msg2 = Message.Message()

        with self.assertRaises((TypeError, Message.InvalidMessageError)):
            msg2.from_json([json_list[0], corrupted_json])

    def test_set_img(self) -> None:
        """Test setting image message."""
        msg = Message.Message()
        msg.set_img("base64_encoded_image_data")

        self.assertEqual(msg.get_type(), "img")

    def test_set_file(self) -> None:
        """Test setting file message."""
        msg = Message.Message()
        msg.set_file("base64_encoded_file_data")

        self.assertEqual(msg.get_type(), "dat")

    def test_set_ctl(self) -> None:
        """Test setting control message."""
        msg = Message.Message()
        msg.set_ctl(id_to_set="test-id-123", text="ack", part_to_set=0)

        self.assertEqual(msg.get_type(), "ctl")


# ============================================================================
# Input Validation Tests
# ============================================================================


class TestInputValidator(unittest.TestCase):
    """Test input validation utilities."""

    def test_validate_port_valid(self) -> None:
        """Test validating valid port."""
        is_valid, port, error = InputValidator.validate_port("11000")

        self.assertTrue(is_valid)
        self.assertEqual(port, 11000)
        self.assertEqual(error, "")

    def test_validate_port_too_low(self) -> None:
        """Test validating port too low."""
        is_valid, port, error = InputValidator.validate_port("100")

        self.assertFalse(is_valid)
        self.assertIsNone(port)
        self.assertIn("between", error)

    def test_validate_port_too_high(self) -> None:
        """Test validating port too high."""
        is_valid, port, error = InputValidator.validate_port("99999")

        self.assertFalse(is_valid)
        self.assertIsNone(port)
        self.assertIn("between", error)

    def test_validate_port_invalid_format(self) -> None:
        """Test validating port with invalid format."""
        is_valid, port, error = InputValidator.validate_port("not_a_number")

        self.assertFalse(is_valid)
        self.assertIsNone(port)
        self.assertIn("number", error)

    def test_validate_ip_valid(self) -> None:
        """Test validating valid IP."""
        is_valid, error = InputValidator.validate_ip("192.168.1.1")

        self.assertTrue(is_valid)
        self.assertEqual(error, "")

    def test_validate_ip_invalid_octet(self) -> None:
        """Test validating IP with invalid octet."""
        is_valid, error = InputValidator.validate_ip("256.1.1.1")

        self.assertFalse(is_valid)
        self.assertIn("octet", error.lower())

    def test_validate_ip_invalid_format(self) -> None:
        """Test validating IP with invalid format."""
        is_valid, error = InputValidator.validate_ip("192.168.1")

        self.assertFalse(is_valid)
        self.assertIn("format", error.lower())

    def test_validate_name_valid(self) -> None:
        """Test validating valid name."""
        is_valid, error = InputValidator.validate_name("Alice_Smith-123")

        self.assertTrue(is_valid)
        self.assertEqual(error, "")

    def test_validate_name_empty(self) -> None:
        """Test validating empty name."""
        is_valid, error = InputValidator.validate_name("")

        self.assertFalse(is_valid)
        self.assertIn("empty", error.lower())

    def test_validate_name_too_long(self) -> None:
        """Test validating name too long."""
        is_valid, error = InputValidator.validate_name("x" * 101)

        self.assertFalse(is_valid)
        self.assertIn("long", error.lower())

    def test_validate_name_invalid_chars(self) -> None:
        """Test validating name with invalid characters."""
        is_valid, error = InputValidator.validate_name("Alice@Bob")

        self.assertFalse(is_valid)
        self.assertIn("invalid", error.lower())


# ============================================================================
# Integration Tests
# ============================================================================


class TestIntegration(unittest.TestCase):
    """Integration tests across multiple components."""

    def setUp(self) -> None:
        """Set up test fixtures."""
        self.temp_dir = tempfile.TemporaryDirectory()
        self.config_dir = Path(self.temp_dir.name)

    def tearDown(self) -> None:
        """Clean up test fixtures."""
        self.temp_dir.cleanup()

    def test_config_and_message_integration(self) -> None:
        """Test configuration and message working together."""
        # Setup config
        config = vault_config.VaultConfig(
            config_dir=self.config_dir,
            use_encryption=False,
        )
        config.set("user.name", "TestUser")
        config.save()

        # Create message
        msg = Message.Message()
        msg.set_text(f"Hello from {config.get('user.name')}")

        # Verify
        self.assertIn("TestUser", msg.get_content())

    def test_large_message_workflow(self) -> None:
        """Test handling large messages with config."""
        config = vault_config.VaultConfig(
            config_dir=self.config_dir,
            use_encryption=False,
        )

        # Create large message
        large_text = "A" * 50000
        msg = Message.Message(max_length=1000)
        msg.set_text(large_text)

        # Convert to JSON (will be segmented)
        json_segments = msg.to_json()

        # Reconstruct
        msg2 = Message.Message(max_length=1000)
        msg2.from_json(json_segments)

        # Verify
        self.assertEqual(msg2.get_content(), large_text)
        self.assertEqual(len(json_segments), msg.to_json().__len__())


# ============================================================================
# Performance Tests
# ============================================================================


class TestPerformance(unittest.TestCase):
    """Performance and stress tests."""

    def test_message_creation_speed(self) -> None:
        """Test message creation performance."""
        import time

        start = time.time()
        for _ in range(1000):
            msg = Message.Message()
            msg.set_text("Test message")
            _ = msg.get_id()
        elapsed = time.time() - start

        # Should create 1000 messages in < 1 second
        self.assertLess(elapsed, 1.0)

    def test_uuid_uniqueness_stress(self) -> None:
        """Test UUID uniqueness under stress."""
        uuids = set()

        for _ in range(10000):
            msg = Message.Message()
            msg.set_text("test")
            uuids.add(msg.get_id())

        # All UUIDs should be unique
        self.assertEqual(len(uuids), 10000)


# ============================================================================
# Test Runner
# ============================================================================


def run_tests() -> int:
    """
    Run all tests.

    Returns:
        Exit code
    """
    # Create test suite
    loader = unittest.TestLoader()
    suite = unittest.TestSuite()

    # Add all test classes
    suite.addTests(loader.loadTestsFromTestCase(TestVaultConfig))
    suite.addTests(loader.loadTestsFromTestCase(TestMessage))
    suite.addTests(loader.loadTestsFromTestCase(TestInputValidator))
    suite.addTests(loader.loadTestsFromTestCase(TestIntegration))
    suite.addTests(loader.loadTestsFromTestCase(TestPerformance))

    # Run tests
    runner = unittest.TextTestRunner(verbosity=2)
    result = runner.run(suite)

    # Return exit code
    return 0 if result.wasSuccessful() else 1


if __name__ == "__main__":
    import sys

    sys.exit(run_tests())
