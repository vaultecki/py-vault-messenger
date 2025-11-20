"""
Message Module - Handles message serialization, splitting, and reconstruction.

Features:
- Message type support (text, image, data/files, control)
- Automatic message splitting for large payloads
- SHA256 hashing with Base64 encoding for integrity
- JSON serialization/deserialization
- UUID generation for message tracking
"""

import copy
import json
import random
import logging
from typing import List, Optional

import nacl.encoding
import nacl.hash
import threading
import time
import uuid
import PySignal

logger = logging.getLogger(__name__)


class Message:
    """Message class for creating, splitting, and reconstructing messages."""

    def __init__(self, max_length: int = None):
        """
        Initialize a Message object.

        Args:
            max_length: Maximum message length in bytes (default: 1000)
        """
        self.__msg = {}
        if not max_length:
            max_length = 1000
        self.__max_length = max_length
        self.__norm_length = self.__calc_norm_length()
        logger.debug(f"Message initialized with max_length={max_length}, norm_length={self.__norm_length}")

    def __calc_norm_length(self) -> int:
        """
        Calculate normalized content length by accounting for message overhead.

        Returns:
            Available bytes for content in each message part
        """
        # Temporarily set message to calculate overhead
        self.set_text("")
        # ✅ FIX: Use int instead of string for part and pad
        self.__msg.update({"part": 1000000, "pad": 10000})
        json_string = json.dumps(self.__msg, indent=0)
        norm_length = int(self.__max_length) - len(json_string)
        logger.debug(f"Normalized length calculated: {norm_length} bytes")
        return norm_length

    def __set_uuid(self) -> None:
        """Generate and set a unique UUID for this message."""
        uuid_to_set = str(uuid.uuid4())
        self.__msg.update({"id": uuid_to_set})

    def __set_hash(self) -> None:
        """Calculate and set SHA256 hash of message content."""
        content = self.__msg.get("content", "")
        hash_value = nacl.hash.sha256(
            message=content.encode("utf-8"),
            encoder=nacl.encoding.Base64Encoder
        ).decode("utf-8")
        self.__msg.update({"hash": hash_value})

    def set_text(self, text: str) -> None:
        """
        Set message as text type.

        Args:
            text: Text content to send
        """
        if not isinstance(text, str):
            raise TypeError(f"Expected str, got {type(text).__name__}")
        self.__msg.update({"content": text})
        self.__set_uuid()
        self.__set_hash()
        self.set_type("txt")
        logger.debug(f"Text message set: {len(text)} chars")

    def set_img(self, text: str) -> None:
        """
        Set message as image type (Base64 encoded).

        Args:
            text: Base64 encoded image data
        """
        if not isinstance(text, str):
            raise TypeError(f"Expected str, got {type(text).__name__}")
        self.__msg.update({"content": text})
        self.__set_uuid()
        self.__set_hash()
        self.set_type("img")
        logger.debug(f"Image message set: {len(text)} chars")

    def set_file(self, text: str) -> None:
        """
        Set message as file/data type.

        Args:
            text: Base64 encoded file data or JSON file descriptor
        """
        if not isinstance(text, str):
            raise TypeError(f"Expected str, got {type(text).__name__}")
        self.__msg.update({"content": text})
        self.__set_uuid()
        self.__set_hash()
        self.set_type("dat")
        logger.debug(f"File message set: {len(text)} chars")

    def get_type(self) -> str:
        """
        Get message type.

        Returns:
            Message type (txt, img, dat, ctl) or "no type" if not set
        """
        return self.__msg.get("type", "no type")

    def get_content(self) -> str:
        """
        Get message content.

        Returns:
            Message content or "no content" if empty
        """
        return self.__msg.get("content", "no content")

    def set_type(self, msg_type: str = "txt") -> None:
        """
        Set message type explicitly.

        Args:
            msg_type: Type identifier (txt, img, dat, ctl)
        """
        self.__msg.update({"type": msg_type})

    def set_ctl(self, id_to_set: str, text: str, part_to_set: int = 0) -> None:
        """
        Set message as control type (for acknowledgments).

        Args:
            id_to_set: Message ID being acknowledged
            text: Control message content (typically "ack")
            part_to_set: Part number being acknowledged
        """
        if not isinstance(id_to_set, str):
            raise TypeError(f"Expected str for id, got {type(id_to_set).__name__}")
        if not isinstance(text, str):
            raise TypeError(f"Expected str for text, got {type(text).__name__}")
        if not isinstance(part_to_set, int):
            raise TypeError(f"Expected int for part, got {type(part_to_set).__name__}")

        self.__msg.update({
            "id": id_to_set,
            "content": text,
            "part": part_to_set
        })
        self.set_type("ctl")
        self.__set_hash()

    def to_ctl_json(self) -> str:
        """
        Serialize control message to JSON string.

        Returns:
            JSON string representation of control message
        """
        return json.dumps(self.__msg, indent=0)

    def to_json(self) -> List[str]:
        """
        Serialize message to list of JSON strings, splitting if necessary.

        Large messages are automatically split into multiple parts.
        Each part includes: id, part number, content, and padding.
        The final part includes hash and type.

        Returns:
            List of JSON strings (one per message part)

        Raises:
            ValueError: If content cannot be serialized
        """
        result = []
        content = self.__msg.get("content", "")
        part_number = 0

        # Split content into multiple parts if needed
        while len(content) > self.__norm_length:
            # Extract chunk (leave 2 chars margin)
            part_content = content[:self.__norm_length - 2]
            content = content[self.__norm_length - 2:]

            part_msg = {
                "id": self.__msg.get("id"),
                "part": part_number,
                "content": part_content,
                "pad": ""
            }
            part_number += 1
            result.append(json.dumps(part_msg, indent=0))
            logger.debug(f"Split message part {part_number - 1}: {len(part_content)} chars")

        # Create final part with hash and type
        tail_msg = {
            "id": self.__msg.get("id"),
            "hash": self.__msg.get("hash"),
            "part": part_number,
            "content": content,
            "type": self.__msg.get("type"),
            "pad": ""
        }
        result.append(json.dumps(tail_msg, indent=0))
        logger.debug(f"Final message part {part_number}: {len(content)} chars")

        return result

    def padding(self, length: int) -> str:
        """
        Generate random padding string.

        Args:
            length: Number of padding characters to generate

        Returns:
            Random string of specified length
        """
        alphabet = "abcdefghijklmnopqrstuvwxyz"
        alphabet += alphabet.upper()
        alphabet += "0123456789.-"
        return_string = ""
        for i in range(length):
            return_string += random.choice(alphabet)
        return return_string

    def from_json(self, input_list) -> None:
        """
        Deserialize message from JSON string(s) and reconstruct.

        Handles both single JSON strings and lists of JSON strings.
        Validates hash and reassembles split messages in correct order.

        Args:
            input_list: JSON string or list of JSON strings

        Raises:
            ValueError: If IDs, hashes, or types don't match across parts
            TypeError: If hash validation fails
        """
        # Convert single string to list
        if isinstance(input_list, str):
            input_list = [input_list]

        # Parse all parts and collect content by part number
        content_dict = {}
        recv_id = ""
        recv_hash = ""
        recv_type = ""
        max_part = -1

        for json_str in input_list:
            try:
                msg_recv = json.loads(json_str)
            except json.JSONDecodeError as e:
                logger.error(f"Failed to parse JSON: {e}")
                raise ValueError(f"Invalid JSON in message: {e}") from e

            part_num = msg_recv.get("part", 0)
            if not isinstance(part_num, int):
                try:
                    part_num = int(part_num)
                except (ValueError, TypeError):
                    logger.error(f"Invalid part number: {part_num}")
                    raise ValueError(f"Invalid part number: {part_num}")

            if part_num > max_part:
                max_part = part_num

            content_dict[part_num] = msg_recv.get("content", "")

            # Validate ID consistency
            msg_id = msg_recv.get("id", "")
            if recv_id and msg_id != recv_id:
                logger.error(f"Message ID mismatch: {recv_id} vs {msg_id}")
                raise ValueError("ID differs across message parts")
            recv_id = msg_id

            # Validate hash consistency
            msg_hash = msg_recv.get("hash", "")
            if recv_hash and msg_hash and msg_hash != recv_hash:
                logger.error(f"Hash mismatch: {recv_hash} vs {msg_hash}")
                raise ValueError("Hash differs across message parts")
            if msg_hash:
                recv_hash = msg_hash

            # Validate type consistency
            msg_type = msg_recv.get("type", "")
            if recv_type and msg_type and msg_type != recv_type:
                logger.error(f"Type mismatch: {recv_type} vs {msg_type}")
                raise ValueError("Type differs across message parts")
            if msg_type:
                recv_type = msg_type

        # Reconstruct content in correct order
        content_str = ""
        for i in range(max_part + 1):
            if i in content_dict:
                content_str += content_dict[i]
            else:
                logger.warning(f"Missing part {i} in message")

        # Set message with reconstructed data
        self.__msg = {}
        self.__msg.update({
            "id": recv_id,
            "hash": recv_hash,
            "type": recv_type,
            "content": content_str
        })

        # Validate hash
        if not self.__check_hash():
            logger.error("Hash validation failed")
            raise TypeError("Hash mismatch - message may be corrupted")

        logger.info(f"Message reconstructed: id={recv_id[:8]}..., "
                    f"type={recv_type}, content_len={len(content_str)}")

    def __check_hash(self) -> bool:
        """
        Verify message hash.

        Returns:
            True if hash is valid, False otherwise
        """
        check_str = nacl.hash.sha256(
            message=self.__msg.get("content", "").encode("utf-8"),
            encoder=nacl.encoding.Base64Encoder
        ).decode("utf-8")

        message_hash = self.__msg.get("hash", "")
        is_valid = message_hash == check_str

        if not is_valid:
            logger.debug(f"Hash mismatch: expected {message_hash[:16]}..., got {check_str[:16]}...")

        return is_valid


class MessageHandler:
    """
    Handles message sending and receiving with acknowledgment protocol.

    Features:
    - Sends messages with automatic retry
    - Receives and buffers messages
    - Acknowledgment-based reliability
    - Automatic cleanup of old messages
    - Thread-safe operations
    """

    mh_send_data = PySignal.ClassSignal()
    mh_recv_text = PySignal.ClassSignal()
    mh_recv_img = PySignal.ClassSignal()
    mh_recv_file = PySignal.ClassSignal()
    mh_recv_control = PySignal.ClassSignal()

    def __init__(self, max_retry: int = 2, timeout: int = 300):
        """
        Initialize MessageHandler.

        Args:
            max_retry: Maximum retransmission attempts per message
            timeout: Timeout for message cleanup in seconds
        """
        logger.info(f"Initializing MessageHandler: max_retry={max_retry}, timeout={timeout}s")
        self.max_retry = max_retry
        self.list_recv = {}  # Acknowledged messages
        self.list_send = {}  # Sent messages awaiting ack
        self.recv_msg_buffer = {}  # Buffered received messages
        self.timeout = timeout
        self.thread_stop = False
        self._cleanup_lock = threading.Lock()

        # Start cleanup thread
        self._start_cleanup_thread()

    def _start_cleanup_thread(self) -> None:
        """Start the cleanup thread."""
        self._cleanup_thread = threading.Thread(
            target=self.__check_recv_buffer,
            daemon=True,
            name="MessageHandler-Cleanup"
        )
        self._cleanup_thread.start()
        logger.debug("Cleanup thread started")

    def send_txt_msg(self, text_to_send: str) -> None:
        """
        Send a text message.

        Args:
            text_to_send: Text to send
        """
        try:
            message = Message()
            message.set_text(text_to_send)
            msg_list = message.to_json()
            self.__send_msg(msg_list)
            logger.info(f"Text message sent: {len(text_to_send)} chars")
        except Exception as e:
            logger.error(f"Error sending text message: {e}")

    def send_img_msg(self, img_to_send: str) -> None:
        """
        Send an image message (Base64 encoded).

        Args:
            img_to_send: Base64 encoded image data
        """
        try:
            message = Message()
            message.set_img(img_to_send)
            msg_list = message.to_json()
            self.__send_msg(msg_list)
            logger.info(f"Image message sent: {len(img_to_send)} chars")
        except Exception as e:
            logger.error(f"Error sending image message: {e}")

    def send_ctl_msg(self, ctl_dict: dict) -> None:
        """
        Send a control message.

        Args:
            ctl_dict: Dictionary with control data
        """
        try:
            message = Message()
            message.set_text(json.dumps(ctl_dict, indent=0))
            message.set_type("ctl")
            msg_list = message.to_json()
            self.__send_msg(msg_list)
            logger.debug(f"Control message sent")
        except Exception as e:
            logger.error(f"Error sending control message: {e}")

    def send_file_msg(self, file_to_send: str) -> None:
        """
        Send a file message (Base64 encoded).

        Args:
            file_to_send: JSON string with file metadata and Base64 content
        """
        try:
            message = Message()
            message.set_file(file_to_send)
            msg_list = message.to_json()
            self.__send_msg(msg_list)
            logger.info(f"File message sent: {len(file_to_send)} chars")
        except Exception as e:
            logger.error(f"Error sending file message: {e}")

    def __send_msg(self, msg_list: List[str]) -> None:
        """
        Send message parts with acknowledgment protocol.

        Args:
            msg_list: List of JSON strings (message parts)
        """
        for msg in msg_list:
            try:
                msg_dict = json.loads(msg)
            except json.JSONDecodeError as e:
                logger.error(f"Invalid JSON in message: {e}")
                continue

            msg_id = msg_dict.get("id")
            msg_part = msg_dict.get("part", 0)
            msg_type = msg_dict.get("type", "")
            msg_content = msg_dict.get("content", "")

            msg_id_part = (msg_id, msg_part)

            # Control messages get fewer retries
            retry = 1 if (msg_type == "ctl" and msg_content == "ack") else self.max_retry
            counter = 0

            while counter <= retry and not self.thread_stop:
                # Check if acknowledged
                if msg_id_part in self.list_recv:
                    break

                # Send message
                with self._cleanup_lock:
                    self.list_send[msg_id_part] = time.time()

                self.mh_send_data.emit(msg)

                time.sleep(0.5)
                counter += 1

            if msg_id_part not in self.list_recv:
                logger.debug(f"Message {msg_id_part} not acknowledged after {retry} retries")
            else:
                # Remove from send list once acknowledged
                with self._cleanup_lock:
                    self.list_recv.pop(msg_id_part, None)

    def recv_msg(self, recv_msg_json: str, addr: str = "") -> None:
        """
        Receive and process a message part.

        Args:
            recv_msg_json: JSON string containing message part
            addr: Sender address
        """
        try:
            msg_dict = json.loads(recv_msg_json)
        except json.JSONDecodeError:
            logger.debug(f"Invalid JSON received from {addr}")
            return

        msg_id = msg_dict.get("id")
        msg_part = msg_dict.get("part", 0)
        msg_type = msg_dict.get("type", "")
        msg_content = msg_dict.get("content", "")

        if not msg_id:
            logger.debug("Received message without ID")
            return

        msg_id_part = (msg_id, msg_part)

        # Handle acknowledgment
        if msg_id_part in self.list_send and msg_type == "ctl" and msg_content == "ack":
            with self._cleanup_lock:
                self.list_recv[msg_id_part] = time.time()
            return

        # If this is not a message we sent, buffer it and send ack
        if msg_id_part not in self.list_send:
            ack_msg = Message()
            ack_msg.set_ctl(id_to_set=msg_id, part_to_set=msg_part, text="ack")
            ack_msg_str = ack_msg.to_ctl_json()

            with self._cleanup_lock:
                self.recv_msg_buffer[time.time()] = (recv_msg_json, addr)

            self.__send_msg([ack_msg_str])
            time.sleep(0.1)

    def stop(self) -> None:
        """Stop the message handler and cleanup thread."""
        logger.info("Stopping MessageHandler")
        self.thread_stop = True
        if self._cleanup_thread.is_alive():
            self._cleanup_thread.join(timeout=5.0)
        logger.info("MessageHandler stopped")

    def __check_recv_buffer(self) -> None:
        """
        Periodically check receive buffer, assemble complete messages, and emit signals.
        Also cleans up old messages that timed out.
        """
        while not self.thread_stop:
            try:
                with self._cleanup_lock:
                    list_msg = {}
                    keys_to_delete = []

                    # Group message parts by ID
                    for key, value in self.recv_msg_buffer.items():
                        if key + self.timeout < time.time():
                            keys_to_delete.append(key)
                            continue

                        msg = json.loads(value[0])
                        addr = value[1]
                        msg_id = msg.get("id")

                        if msg_id not in list_msg:
                            list_msg[msg_id] = [[], [], addr]

                        list_msg[msg_id][0].append(value[0])
                        list_msg[msg_id][1].append(key)

                        # Verify address matches
                        if addr == list_msg[msg_id][2]:
                            list_msg[msg_id][2] = addr

                    # Process complete messages
                    for msg_id, value in list_msg.items():
                        try:
                            recv_msg = Message()
                            recv_msg.from_json(value[0])
                            keys_msg_del = value[1]
                            recv_addr = value[2]

                            msg_type = recv_msg.get_type()
                            msg_content = recv_msg.get_content()

                            # Emit appropriate signal
                            if msg_type == "txt":
                                self.mh_recv_text.emit(msg_content, recv_addr)
                            elif msg_type == "dat":
                                self.mh_recv_file.emit(msg_content, recv_addr)
                            elif msg_type == "img":
                                self.mh_recv_img.emit(msg_content, recv_addr)
                            elif msg_type == "ctl":
                                self.mh_recv_control.emit(msg_content, recv_addr)

                            logger.info(f"Message completed: type={msg_type}, id={msg_id[:8]}...")

                            # Delete processed message parts
                            for key in keys_msg_del:
                                self.recv_msg_buffer.pop(key, None)

                        except (ValueError, TypeError) as e:
                            logger.error(f"Error processing message {msg_id}: {e}")
                            # Don't delete - let it timeout
                        except Exception as e:
                            logger.error(f"Unexpected error assembling message: {e}")

                    # Delete timed out messages
                    for key in keys_to_delete:
                        self.recv_msg_buffer.pop(key, None)
                        logger.debug("Cleaned up timed out message part")

                    # Clean up old send list entries
                    send_keys_to_delete = []
                    for key, value in self.list_send.items():
                        if value + self.timeout < time.time():
                            send_keys_to_delete.append(key)

                    for key in send_keys_to_delete:
                        self.list_send.pop(key, None)

                    # Clean up old recv list entries
                    recv_keys_to_delete = []
                    for key, value in self.list_recv.items():
                        if value + self.timeout < time.time():
                            recv_keys_to_delete.append(key)

                    for key in recv_keys_to_delete:
                        self.list_recv.pop(key, None)

            except Exception as e:
                logger.error(f"Error in cleanup buffer: {e}")

            time.sleep(1)


if __name__ == '__main__':
    logging.basicConfig(
        level=logging.DEBUG,
        format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
    )

    logger.info("Testing Message class")

    msg1 = Message()
    test_text = ""
    for i in range(100):
        test_text += f"Hello World {i}! "

    msg1.set_text(test_text)
    data = msg1.to_json()
    logger.info(f"Created message with {len(data)} parts")

    msg2 = Message()
    msg2.from_json(data)

    logger.info(f"Reconstructed message: {len(msg2.get_content())} chars")
    logger.info(f"Content matches: {msg2.get_content() == test_text}")

    for i, element in enumerate(msg2.to_json()):
        logger.debug(f"Part {i}: {len(element)} bytes")
