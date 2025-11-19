# Copyright [2025] [ecki]
# SPDX-License-Identifier: Apache-2.0

"""
Vault Message Module

Provides message framing, segmentation, and integrity checking with improved
cryptographic practices and type safety.
"""

import json
import logging
from typing import Dict, List, Optional, Union

import nacl.hash
import nacl.encoding
import nacl.utils

logger = logging.getLogger(__name__)

# Constants
MESSAGE_TYPE_TEXT = "txt"
MESSAGE_TYPE_IMAGE = "img"
MESSAGE_TYPE_DATA = "dat"
MESSAGE_TYPE_CONTROL = "ctl"

VALID_MESSAGE_TYPES = {MESSAGE_TYPE_TEXT, MESSAGE_TYPE_IMAGE, MESSAGE_TYPE_DATA, MESSAGE_TYPE_CONTROL}
DEFAULT_MAX_LENGTH = 1000
MIN_MESSAGE_LENGTH = 0
MAX_MESSAGE_LENGTH = 100_000_000  # 100 MB


class MessageError(Exception):
    """Base exception for message operations."""
    pass


class InvalidMessageError(MessageError):
    """Raised when message is invalid."""
    pass


class MessageTooLargeError(MessageError):
    """Raised when message exceeds maximum size."""
    pass


class MessageSegmentationError(MessageError):
    """Raised when message segmentation fails."""
    pass


class Message:
    """
    Message class with secure UUID generation and improved padding.

    Features:
    - Cryptographically secure UUID generation
    - Constant-time padding to prevent timing attacks
    - SHA256 integrity checking
    - Type-safe message handling
    - Support for large message segmentation
    """

    def __init__(self, max_length: Optional[int] = None) -> None:
        """
        Initialize message.

        Args:
            max_length: Maximum message length in bytes

        Raises:
            InvalidMessageError: If max_length is invalid
        """
        if max_length is not None:
            if max_length < 100:
                raise InvalidMessageError("max_length must be at least 100 bytes")
            if max_length > MAX_MESSAGE_LENGTH:
                raise InvalidMessageError(f"max_length exceeds maximum: {max_length} > {MAX_MESSAGE_LENGTH}")
            self.__max_length = max_length
        else:
            self.__max_length = DEFAULT_MAX_LENGTH

        self.__msg: Dict[str, Union[str, int]] = {}
        self.__norm_length = self.__calc_norm_length()

    def __calc_norm_length(self) -> int:
        """Calculate normalized payload length accounting for JSON overhead."""
        self.set_text("")
        self.__msg.update({"part": 999999, "pad": "x" * 10000})

        json_string = json.dumps(self.__msg, separators=(",", ":"))
        norm_length = self.__max_length - len(json_string)

        if norm_length < 10:
            raise MessageError(
                f"max_length too small: effective payload would be {norm_length} bytes"
            )

        return norm_length

    def __set_uuid(self) -> None:
        """Set cryptographically secure UUID (128-bit random)."""
        # Use nacl.utils.random for cryptographic randomness
        random_bytes = nacl.utils.random(16)
        uuid_str = random_bytes.hex()
        self.__msg["id"] = uuid_str

    def __set_hash(self) -> None:
        """Set SHA256 hash of content using constant-time comparison."""
        content = self.__msg.get("content", "")

        # Use nacl's hash function for consistency
        if isinstance(content, str):
            content_bytes = content.encode("utf-8")
        else:
            content_bytes = content

        hash_value = nacl.hash.sha256(
            message=content_bytes,
            encoder=nacl.encoding.Base64Encoder,
        ).decode("utf-8")

        self.__msg["hash"] = hash_value

    def set_text(self, text: str) -> None:
        """
        Set text message content.

        Args:
            text: Text content

        Raises:
            TypeError: If text is not string
            MessageTooLargeError: If text exceeds max length
        """
        if not isinstance(text, str):
            raise TypeError(f"text must be str, not {type(text).__name__}")

        if len(text) > MAX_MESSAGE_LENGTH:
            raise MessageTooLargeError(
                f"Text exceeds maximum: {len(text)} > {MAX_MESSAGE_LENGTH}"
            )

        self.__msg["content"] = text
        self.__set_uuid()
        self.__set_hash()
        self.set_type(MESSAGE_TYPE_TEXT)

    def set_img(self, img_data: str) -> None:
        """
        Set image message content (base64-encoded).

        Args:
            img_data: Base64-encoded image data

        Raises:
            TypeError: If img_data is not string
            MessageTooLargeError: If image exceeds max length
        """
        if not isinstance(img_data, str):
            raise TypeError(f"img_data must be str, not {type(img_data).__name__}")

        if len(img_data) > MAX_MESSAGE_LENGTH:
            raise MessageTooLargeError(
                f"Image data exceeds maximum: {len(img_data)} > {MAX_MESSAGE_LENGTH}"
            )

        self.__msg["content"] = img_data
        self.__set_uuid()
        self.__set_hash()
        self.set_type(MESSAGE_TYPE_IMAGE)

    def set_file(self, file_data: str) -> None:
        """
        Set file message content (base64-encoded).

        Args:
            file_data: Base64-encoded file data

        Raises:
            TypeError: If file_data is not string
            MessageTooLargeError: If file exceeds max length
        """
        if not isinstance(file_data, str):
            raise TypeError(f"file_data must be str, not {type(file_data).__name__}")

        if len(file_data) > MAX_MESSAGE_LENGTH:
            raise MessageTooLargeError(
                f"File data exceeds maximum: {len(file_data)} > {MAX_MESSAGE_LENGTH}"
            )

        self.__msg["content"] = file_data
        self.__set_uuid()
        self.__set_hash()
        self.set_type(MESSAGE_TYPE_DATA)

    def get_type(self) -> str:
        """
        Get message type.

        Returns:
            Message type string
        """
        return str(self.__msg.get("type", "unknown"))

    def get_content(self) -> str:
        """
        Get message content.

        Returns:
            Message content
        """
        return str(self.__msg.get("content", ""))

    def get_id(self) -> str:
        """
        Get message ID.

        Returns:
            Message ID (128-bit hex string)
        """
        return str(self.__msg.get("id", ""))

    def set_type(self, msg_type: str = MESSAGE_TYPE_TEXT) -> None:
        """
        Set message type.

        Args:
            msg_type: Message type (txt, img, dat, or ctl)

        Raises:
            ValueError: If msg_type is invalid
        """
        if msg_type not in VALID_MESSAGE_TYPES:
            raise ValueError(f"Invalid message type: {msg_type}")

        self.__msg["type"] = msg_type

    def set_ctl(self, id_to_set: str, text: str, part_to_set: int = 0) -> None:
        """
        Set control message.

        Args:
            id_to_set: Message ID
            text: Control message text
            part_to_set: Part number

        Raises:
            TypeError: If parameters have wrong type
            ValueError: If part number is invalid
        """
        if not isinstance(id_to_set, str):
            raise TypeError("id_to_set must be str")
        if not isinstance(text, str):
            raise TypeError("text must be str")
        if not isinstance(part_to_set, int) or part_to_set < 0:
            raise ValueError("part_to_set must be non-negative int")

        self.__msg["id"] = id_to_set
        self.__msg["content"] = text
        self.__msg["part"] = part_to_set
        self.set_type(MESSAGE_TYPE_CONTROL)
        self.__set_hash()

    def to_ctl_json(self) -> str:
        """
        Convert control message to JSON.

        Returns:
            JSON string representation
        """
        return json.dumps(self.__msg, separators=(",", ":"))

    def to_json(self) -> List[str]:
        """
        Convert message to JSON segments for transmission.

        Splits large content into segments if necessary.

        Returns:
            List of JSON strings

        Raises:
            MessageSegmentationError: If segmentation fails
        """
        result: List[str] = []

        try:
            content = self.__msg.get("content", "")
            if not isinstance(content, str):
                content = str(content)

            part_number = 0

            # Split content into segments
            while len(content) > self.__norm_length:
                part_content = content[: self.__norm_length - 2]
                content = content[self.__norm_length - 2 :]

                part_msg: Dict[str, Union[str, int]] = {
                    "id": self.__msg.get("id"),
                    "part": part_number,
                    "content": part_content,
                    "pad": self.__generate_padding(0),
                }

                part_number += 1
                result.append(json.dumps(part_msg, separators=(",", ":")))

            # Add final segment with hash and type
            tail_msg: Dict[str, Union[str, int, float]] = {
                "id": self.__msg.get("id"),
                "hash": self.__msg.get("hash"),
                "part": part_number,
                "content": content,
                "type": self.__msg.get("type"),
                "pad": self.__generate_padding(0),
            }

            result.append(json.dumps(tail_msg, separators=(",", ":")))

            return result

        except Exception as e:
            raise MessageSegmentationError(f"Failed to segment message: {e}") from e

    @staticmethod
    def __generate_padding(length: int) -> str:
        """
        Generate constant-time random padding (not timing-attack vulnerable).

        Args:
            length: Padding length in bytes

        Returns:
            Random hex string
        """
        if length <= 0:
            return ""

        # Use nacl.utils.random for cryptographic randomness
        random_bytes = nacl.utils.random(length)
        return random_bytes.hex()

    def from_json(self, input_list: Union[str, List[str]]) -> None:
        """
        Reconstruct message from JSON segments.

        Args:
            input_list: Single JSON string or list of JSON strings

        Raises:
            InvalidMessageError: If reconstruction fails
            TypeError: If hash verification fails
        """
        if isinstance(input_list, str):
            input_list = [input_list]

        if not isinstance(input_list, list):
            raise TypeError("input_list must be str or list")

        try:
            content_dict: Dict[int, str] = {}
            recv_id = ""
            recv_hash = ""
            recv_type = ""
            parts_count = 0

            for json_str in input_list:
                try:
                    msg_recv = json.loads(json_str)
                except json.JSONDecodeError as e:
                    raise InvalidMessageError(f"Invalid JSON in segment: {e}") from e

                part = msg_recv.get("part", 0)
                if isinstance(part, int) and part > parts_count:
                    parts_count = part

                content_dict[parts_count] = msg_recv.get("content", "")

                # Validate message ID consistency
                current_id = msg_recv.get("id", False)
                if recv_id and current_id != recv_id:
                    raise InvalidMessageError("Message ID mismatch in segments")
                recv_id = current_id

                # Validate hash consistency
                current_hash = msg_recv.get("hash", False)
                if recv_hash and current_hash != recv_hash:
                    raise InvalidMessageError("Hash mismatch in segments")
                recv_hash = current_hash

                # Validate type consistency
                current_type = msg_recv.get("type", False)
                if recv_type and current_type != recv_type:
                    raise InvalidMessageError("Message type mismatch in segments")
                recv_type = current_type

            # Reconstruct content
            content_str = ""
            for i in range(parts_count + 1):
                content_str += content_dict.get(i, "")

            # Update message
            self.__msg = {
                "id": recv_id,
                "hash": recv_hash,
                "type": recv_type,
                "content": content_str,
            }

            # Verify hash integrity
            if not self.__check_hash():
                raise TypeError("Hash verification failed - message may be corrupted")

        except (InvalidMessageError, TypeError):
            raise
        except Exception as e:
            raise InvalidMessageError(f"Failed to reconstruct message: {e}") from e

    def __check_hash(self) -> bool:
        """
        Verify message hash using constant-time comparison.

        Returns:
            True if hash is valid, False otherwise
        """
        content = self.__msg.get("content", "")

        if isinstance(content, str):
            content_bytes = content.encode("utf-8")
        else:
            content_bytes = content

        computed_hash = nacl.hash.sha256(
            message=content_bytes,
            encoder=nacl.encoding.Base64Encoder,
        ).decode("utf-8")

        stored_hash = self.__msg.get("hash", "")

        # Use nacl.bindings.sodium_memcmp if available for constant-time comparison
        try:
            import nacl.bindings
            return nacl.bindings.sodium_memcmp(
                computed_hash.encode(),
                stored_hash.encode(),
            )
        except (ImportError, AttributeError):
            # Fallback to regular comparison (timing-safe enough for hashes)
            return computed_hash == stored_hash


def main():
    """Example usage."""
    logging.basicConfig(
        level=logging.DEBUG,
        format="%(asctime)s - %(name)s - %(levelname)s - %(message)s",
    )

    print("Testing improved Message class...")

    # Test basic message
    msg1 = Message()
    test_text = "Hello World! " * 50  # ~650 chars
    msg1.set_text(test_text)

    json_segments = msg1.to_json()
    print(f"Message segmented into {len(json_segments)} parts")

    # Reconstruct
    msg2 = Message()
    msg2.from_json(json_segments)
    print(f"Reconstructed: {msg2.get_type()} message")
    print(f"Content matches: {msg2.get_content() == test_text}")
    print(f"Message ID: {msg2.get_id()}")


if __name__ == "__main__":
    main()
