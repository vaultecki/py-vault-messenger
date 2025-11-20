"""
Messenger GUI - Complete implementation with Vault v2 API

Changes in v2:
- Proper dual-key handling (encryption + signing keys)
- Correct vault_udp_socket integration
- Config migration for new key format
- Thread-safe encryption management
"""

import Message
import config_manager
import base64
import libs.udp.vault_ip as helper_ip
import libs.multicast.vault_multicast as helper_multicast
import libs.multicast.vault_multicast_service_discovery as multicast_gui
import libs.udp.vault_udp_socket as helper_udp
import libs.udp.vault_udp_socket_helper as vault_udp_socket_helper
import datetime
import json
import os
import random
import threading
import time
import logging

import PyQt6.QtCore
import PyQt6.QtGui
import PyQt6.QtWidgets
import PIL
import PIL.ImageQt
import PySignal

logger = logging.getLogger(__name__)


def migrate_legacy_config(data):
    """
    Migrate legacy config format (single key) to new format (dual keys).

    Args:
        data: Config dictionary

    Returns:
        Updated data dictionary
    """
    if "pub_key" in data and "priv_key" in data:
        logger.info("Detected legacy config format - generating new key pairs")
        enc_pub, enc_priv, sign_pub, sign_priv = vault_udp_socket_helper.generate_keys_asym()

        data.update({
            "enc_pub_key": enc_pub,
            "enc_priv_key": enc_priv,
            "sign_pub_key": sign_pub,
            "sign_priv_key": sign_priv
        })

        # Remove old keys
        data.pop("pub_key", None)
        data.pop("priv_key", None)

        logger.info("Config migrated to new dual-key format")

    return data


class MessengerGui:
    """Main GUI class for Messenger application."""

    gui_send_text = PySignal.ClassSignal()
    gui_send_img = PySignal.ClassSignal()
    gui_send_file = PySignal.ClassSignal()

    def __init__(self):
        logger.info("Initializing MessengerGui")

        # Configuration Setup
        self.config_manager = config_manager.ConfigManager("Messenger", "config.json")
        self.data = self.config_manager.data

        # Migrate legacy config if needed
        self.data = migrate_legacy_config(self.data)

        addr = self.data.get("addr", [])
        recv_port = self.data.get("recv_port", random.randint(1500, 65000))
        self.data.update({"recv_port": recv_port})

        # ✅ FIX: Dual Key Setup (encryption + signing)
        enc_priv = self.data.get("enc_priv_key")
        enc_pub = self.data.get("enc_pub_key", "")
        sign_priv = self.data.get("sign_priv_key")
        sign_pub = self.data.get("sign_pub_key", "")

        # Generate new keys if not present
        if not enc_priv or not sign_priv:
            logger.info("Generating new key pairs")
            enc_pub, enc_priv, sign_pub, sign_priv = vault_udp_socket_helper.generate_keys_asym()
            self.data.update({
                "enc_pub_key": enc_pub,
                "enc_priv_key": enc_priv,
                "sign_pub_key": sign_pub,
                "sign_priv_key": sign_priv
            })
            self.config_manager.save()

        # Store for later use in control messages
        self.enc_pub_key = enc_pub
        self.sign_pub_key = sign_pub

        self.bsd_type = self.data.get("bsd_type", "BertMessenger")
        self.data.update({"bsd_type": self.bsd_type})
        self.bsd_publisher = helper_multicast.VaultMultiPublisher(timeout=2)

        # UI Setup
        self.app = PyQt6.QtWidgets.QApplication([])
        self.main_window = PyQt6.QtWidgets.QWidget()
        self.main_window.setWindowTitle(self.data.get("title", "Messenger"))
        self.layout = PyQt6.QtWidgets.QGridLayout()
        self.main_window.setLayout(self.layout)
        self.main_window.show()

        if self.data.get("icon", False):
            self.main_window.setWindowIcon(PyQt6.QtGui.QIcon(self.data.get("icon")))

        self.check_addr_in_config()
        self._setup_ui()

        # ✅ Socket and Messaging Setup
        self.sock = helper_udp.UDPSocketClass(recv_port=recv_port)

        # ✅ FIX: Set private keys in encryption handler
        try:
            self.sock._encryption.set_private_keys(enc_priv, sign_priv)
            logger.info("Private keys configured in encryption handler")
        except Exception as e:
            logger.error(f"Failed to set private keys: {e}")
            raise

        threading.Thread(target=self.thread_start_sock, daemon=True).start()
        self.mh = Message.MessageHandler()

        # Signal Connections
        self.mh.mh_send_data.connect(self.sock.send_data)
        self.sock.udp_recv_data.connect(self.mh.recv_msg)

        # Text
        self.mh.mh_recv_text.connect(self.on_recv_text)
        self.gui_send_text.connect(self.mh.send_txt_msg)

        # Image
        self.mh.mh_recv_img.connect(self.on_recv_img)
        self.gui_send_img.connect(self.mh.send_img_msg)

        # File
        self.mh.mh_recv_file.connect(self.on_recv_file)
        self.gui_send_file.connect(self.mh.send_file_msg)

        self.stop_update_ctl_send = False
        self.ignore_addr = []
        self.addr_box = None
        threading.Thread(target=self._update_ctl_send_loop, daemon=True).start()

        # Control Messages
        self.mh.mh_recv_control.connect(self.on_recv_ctl)
        self.addr_name = self.data.get("addr_name", {})

        # Message Box Management
        self.mbox_data = {}
        self.img_to_show = None
        self.img_window = None
        self.mb_timer = PyQt6.QtCore.QTimer()
        self.mb_timer.timeout.connect(self.timer_mbox_check)
        self.mb_timer.start(2000)

        logger.info("MessengerGui initialized successfully")

    def _setup_ui(self):
        """Setup User Interface Elements"""
        # Output Label
        output_label = PyQt6.QtWidgets.QLabel("Ausgabe:")
        self.layout.addWidget(output_label, 0, 0)

        # Output ListBox
        self.output_box = PyQt6.QtWidgets.QListWidget()
        self.output_box.addItem("Hallo")
        self.layout.addWidget(self.output_box, 1, 0, 1, 6)

        # Input Label
        self.tb_label = PyQt6.QtWidgets.QLabel("Eingabe:")
        self.layout.addWidget(self.tb_label, 2, 0)

        # Input Textbox
        self.textbox = PyQt6.QtWidgets.QLineEdit()
        self.textbox.setMinimumSize(100, 35)
        self.layout.addWidget(self.textbox, 3, 0, 1, 4)

        # Send Button
        btn_send = PyQt6.QtWidgets.QPushButton("Send")
        btn_send.setMinimumSize(50, 35)
        btn_send.clicked.connect(self.on_click_button_send)
        self.layout.addWidget(btn_send, 3, 4, 1, 2)

        # Options Button
        btn_options = PyQt6.QtWidgets.QPushButton("Einstellungen")
        btn_options.clicked.connect(self.on_click_button_options)
        self.layout.addWidget(btn_options, 4, 0, 1, 2)

        # State Button
        btn_current_state = PyQt6.QtWidgets.QPushButton("Aktueller Zustand")
        btn_current_state.clicked.connect(self.on_click_button_state)
        self.layout.addWidget(btn_current_state, 4, 2, 1, 1)

        # Reset Button
        btn_reset = PyQt6.QtWidgets.QPushButton("Reset")
        btn_reset.clicked.connect(self.on_click_button_reset)
        self.layout.addWidget(btn_reset, 4, 3, 1, 1)

        # Send Image Button
        btn_send_img = PyQt6.QtWidgets.QPushButton("Bild senden")
        btn_send_img.clicked.connect(self.on_click_btn_send_img)
        self.layout.addWidget(btn_send_img, 4, 4, 1, 2)

        # Send File Button
        btn_send_file = PyQt6.QtWidgets.QPushButton("Datei senden")
        btn_send_file.clicked.connect(self.on_click_button_send_file)
        self.layout.addWidget(btn_send_file, 5, 1, 1, 3)

        self.options_window = None
        if not self.data.get("addr"):
            self.on_click_button_options()

    def on_recv_ctl(self, data="", addr=""):
        """Handle control messages (key exchange, connection requests)"""
        logger.debug(f"Control data received from {addr}")

        try:
            data = json.loads(data)
        except (json.JSONDecodeError, ValueError) as e:
            logger.warning(f"Invalid control data from {addr}: {e}")
            return

        name = data.get("name", "")
        enc_key = data.get("enc_key", "")  # ✅ New field names
        sign_key = data.get("sign_key", "")  # ✅ New field names
        addr_data = data.get("addr", "")

        if not addr_data or not enc_key or not sign_key:
            logger.warning(f"Control message missing required fields from {addr}")
            return

        # ✅ FIX: Convert addr_data to tuple for consistency
        if isinstance(addr_data, (list, tuple)) and len(addr_data) >= 2:
            addr_tuple = (addr_data[0], addr_data[1])
        else:
            logger.error(f"Invalid address format in control message: {addr_data}")
            return

        # ✅ FIX: Update peer keys using new API
        try:
            self.sock._encryption.update_peer_keys(addr_tuple, enc_key, sign_key)
            logger.debug(f"Updated peer keys for {addr_tuple}")
        except Exception as e:
            logger.error(f"Failed to update peer keys: {e}")
            return

        # Check if this is a new connection
        if addr and not self.sock.has_peer(addr_tuple):  # ✅ FIX: Use has_peer()
            text = f"New incoming connection from {name}\n\nWant to use for the session (Ok), Save in config, Ignore?\n"
            title = "New Connection"
            buttons = {"Ok": False, "Save": False, "Ignore": False}
            self.mbox_data = {
                "text": text,
                "title": title,
                "button": buttons,
                "name": name,
                "addr_data": addr_tuple,
                "type": "addr"
            }

    def timer_mbox_check(self):
        """Check if message boxes need to be opened"""
        if self.mbox_data.get("type", "") == "addr":
            self.open_mbox_addr_window(self.mbox_data)
            self.mbox_data = {}

        if self.img_to_show:
            msg_box = PyQt6.QtWidgets.QMessageBox()
            msg_box.setText("You received new image. Do you want to open it?")
            msg_box.addButton(PyQt6.QtWidgets.QMessageBox.StandardButton.Yes)
            msg_box.addButton(PyQt6.QtWidgets.QMessageBox.StandardButton.No)
            res = msg_box.exec()
            if res == PyQt6.QtWidgets.QMessageBox.StandardButton.Yes:
                self.img_window = MessengerPictures(self.img_to_show)
                self.img_to_show = None
                self.img_window.show()
            else:
                self.img_to_show = None

    def check_addr_in_config(self):
        """Remove old connections from config (older than 7 days)"""
        now = time.time()
        timeout = 60 * 60 * 24 * 7  # 7 days
        addresses = []

        for addr in self.data.get("addr", []):
            if len(addr) >= 3 and (float(addr[2]) + float(timeout)) < now:
                logger.debug(f"Removing old connection: {addr}")
            else:
                addresses.append(addr)

        self.data.update({"addr": addresses})

    def open_mbox_addr_window(self, mbox_data):
        """Open message box for new connection"""
        if not self.addr_box:
            self.addr_box = MessengerGuiMessageBox(mbox_data)
            self.addr_box.close_window.connect(self.close_mbox_addr_window)
            self.addr_box.show()

    def close_mbox_addr_window(self, mbox_data):
        """Handle response from address message box"""
        if mbox_data:
            logger.debug(f"Address box response: {mbox_data}")
            button_ok = mbox_data.get("button", {}).get("Ok", False)
            button_save = mbox_data.get("button", {}).get("Save", False)
            button_ignore = mbox_data.get("button", {}).get("Ignore", False)
            name = mbox_data.get("name")
            addr_data = mbox_data.get("addr_data")

            if not addr_data or len(addr_data) < 2:
                logger.warning("Invalid address data in mbox response")
                self.addr_box = None
                return

            # ✅ addr_data is already a tuple
            recv_ip = addr_data[0]
            recv_port = addr_data[1]
            time_str = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")

            if button_save:
                # Save for later sessions
                self.data.update({"addr": [[recv_ip, recv_port, time_str]]})
                self.sock.add_peer((recv_ip, recv_port))

                if name:
                    self.addr_name.update({recv_ip: (name, time.time())})
                    self.data.update({"addr_name": self.addr_name})

                self.config_manager.save()
                logger.info(f"Saved new address: {recv_ip}:{recv_port}")

            elif button_ok:
                # Use for this session only
                self.data.update({"addr": [[recv_ip, recv_port, time_str]]})
                self.sock.add_peer((recv_ip, recv_port))

                if name:
                    self.addr_name.update({recv_ip: (name, time.time())})

                logger.info(f"Using address: {recv_ip}:{recv_port}")

            else:  # button_ignore
                self.ignore_addr.append((recv_ip, recv_port))
                if name:
                    self.addr_name.update({recv_ip: (name, time.time())})
                logger.debug(f"Ignoring address: {recv_ip}:{recv_port}")

        self.addr_box = None

    def _update_ctl_send_loop(self):
        """Background loop for periodic control message updates"""
        while not self.stop_update_ctl_send:
            try:
                self.update_ctl_send()
            except Exception as e:
                logger.error(f"Error in control send loop: {e}")

            time.sleep(10)

    def update_ctl_send(self):
        """Send control message with our public keys and address"""
        try:
            ipv4_list, ipv6_list = helper_ip.get_ip_addresses()
            ip = ipv4_list[0] if ipv4_list else "127.0.0.1"

            recv_port = self.sock.recv_port
            name = self.data.get("name", "Test")

            # ✅ FIX: Send both encryption and signing keys
            bsd_data = {
                "addr": (ip, recv_port),
                "name": name,
                "enc_key": self.enc_pub_key,  # ✅ Public encryption key
                "sign_key": self.sign_pub_key,  # ✅ Public signing key
                "type": self.bsd_type
            }
            self.bsd_publisher.update_message(json.dumps(bsd_data))

            ctl_data = {
                "addr": (ip, recv_port),
                "name": name,
                "enc_key": self.enc_pub_key,  # ✅ Public encryption key
                "sign_key": self.sign_pub_key  # ✅ Public signing key
            }
            self.mh.send_ctl_msg(ctl_data)
            logger.debug(f"Sent control update from {ip}:{recv_port}")
        except Exception as e:
            logger.error(f"Failed to send control message: {e}")

    def on_click_button_send(self):
        """Handle send button click"""
        if not self.textbox.text():
            last_item_index = self.output_box.count() - 1
            if last_item_index >= 0:
                item = self.output_box.item(last_item_index).text()
                if not item == "Bitte text eingeben":
                    self.output_box.addItem("Bitte text eingeben")
        else:
            time_str = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
            text = self.textbox.text()
            threading.Thread(
                target=self.send_text,
                args=[text],
                daemon=True
            ).start()
            self.output_box.addItem(f"{time_str}: try sending: {text}")
            self.textbox.setText("")
            logger.info(f"Sending text: {text}")

    def send_text(self, text):
        """Send text message"""
        self.gui_send_text.emit(text)

    def on_recv_text(self, text, addr=""):
        """Handle received text message"""
        time_str = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")

        if addr and isinstance(addr, tuple) and len(addr) >= 1:
            sender_name = self.addr_name.get(addr[0], ("Unknown", 0))[0]
            self.output_box.addItem(
                f"{time_str}: from: {sender_name} received: {text}"
            )
        else:
            self.output_box.addItem(f"{time_str}: received: {text}")

        logger.info(f"Text received from {addr}: {text[:50]}")

    def on_recv_img(self, img_str="", addr=""):
        """Handle received image"""
        try:
            img_bytes = base64.b64decode(img_str)
            time_str = datetime.datetime.now().strftime("%Y%m%d_%H:%M:%S")

            if addr and isinstance(addr, tuple) and len(addr) >= 1:
                sender_name = self.addr_name.get(addr[0], ("Unknown", 0))[0]
                self.output_box.addItem(
                    f"{time_str}: from: {sender_name} received image ({len(img_bytes)} bytes)"
                )
            else:
                self.output_box.addItem(f"{time_str}: received image ({len(img_bytes)} bytes)")

            if img_bytes:
                self.img_to_show = img_bytes
                logger.info(f"Image received from {addr}: {len(img_bytes)} bytes")
        except Exception as e:
            logger.error(f"Error processing received image: {e}")

    def on_recv_file(self, message_content, addr=""):
        """Handle received file"""
        try:
            send_file = json.loads(message_content)
            filename = send_file.get("Dateiname")
            file_str = send_file.get("Inhalt")

            if not filename or not file_str:
                logger.warning("Invalid file message structure")
                return

            file_byte = base64.b64decode(file_str)
            filename_result = PyQt6.QtWidgets.QFileDialog.getSaveFileName(
                None, "Save File", filename, "Image File (*.*)"
            )

            if filename_result and filename_result[0]:
                with open(filename_result[0], mode='wb') as f:
                    f.write(file_byte)
                logger.info(f"File saved: {filename_result[0]}")
        except Exception as e:
            logger.error(f"Error processing received file: {e}")

    def on_click_button_send_file(self):
        """Handle send file button"""
        try:
            file_dialog = PyQt6.QtWidgets.QFileDialog()
            file_dialog.setFileMode(PyQt6.QtWidgets.QFileDialog.FileMode.ExistingFile)
            if file_dialog.exec():
                filename = file_dialog.selectedFiles()
                if filename:
                    with open(filename[0], mode='rb') as f:
                        file_byte = f.read()
                    file_str = base64.b64encode(file_byte).decode('utf-8')
                    send_files = {
                        "Dateiname": os.path.basename(filename[0]),
                        "Inhalt": file_str
                    }
                    message_content = json.dumps(send_files)
                    self.gui_send_file.emit(message_content)
                    logger.info(f"Sending file: {filename[0]}")
        except Exception as e:
            logger.error(f"Error sending file: {e}")

    def on_click_button_options(self):
        """Show options dialog"""
        self.options_window = MessengerGuiOptions(self.data)
        self.options_window.close_window.connect(self.on_close_options_window)
        self.options_window.show()

    def on_close_options_window(self, options_data):
        """Handle options window close"""
        logger.debug(f"Options closed with data: {bool(options_data)}")

        if not options_data:
            options_data = self.data

        for key, value in options_data.items():
            self.data.update({key: value})

        if self.options_window:
            self.options_window.close_window.disconnect(self.on_close_options_window)
            self.options_window = None

        self.config_manager.save()
        threading.Thread(target=self.thread_start_sock, daemon=True).start()

    def thread_start_sock(self):
        """Update socket with configured addresses"""
        addr = self.data.get("addr", [])

        for address in addr:
            if len(address) >= 2:
                try:
                    self.sock.add_peer((address[0], address[1]))
                    logger.debug(f"Added peer: {address[0]}:{address[1]}")
                except Exception as e:
                    logger.error(f"Error adding peer {address}: {e}")

        try:
            recv_port = int(self.data.get("recv_port", 11000))
            self.sock.update_recv_port(recv_port)
            logger.info(f"Updated receive port to {recv_port}")
        except Exception as e:
            logger.error(f"Error updating receive port: {e}")

    def on_click_button_state(self):
        """Display current socket state"""
        try:
            stats = self.sock.get_stats()
            last_item_index = self.output_box.count() - 1

            state_msg = f"Peers: {stats['peer_count']}, MTU: {stats['mtu']}, Port: {stats['recv_port']}"

            if last_item_index < 1 or state_msg != self.output_box.item(last_item_index).text():
                self.output_box.addItem(state_msg)

            logger.debug(f"State: {state_msg}")
        except Exception as e:
            logger.error(f"Error getting socket state: {e}")

    def on_click_btn_send_img(self):
        """Handle send image button"""
        try:
            time_str = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
            dialog = PyQt6.QtWidgets.QFileDialog(None)
            dialog.setFileMode(PyQt6.QtWidgets.QFileDialog.FileMode.AnyFile)
            dialog.setDirectory(os.path.expanduser("~") + "/Downloads/")
            dialog.setNameFilter("Image files (*.img *.png *.jpg *.gif)")

            if dialog.exec():
                filename = dialog.selectedFiles()
                if filename and filename[0]:
                    with open(filename[0], "rb") as file:
                        data = file.read()
                    data_str = base64.b64encode(data).decode('utf-8')
                    self.output_box.addItem(f"{time_str}: try sending: {filename[0]}")
                    threading.Thread(
                        target=self.send_img,
                        args=[data_str],
                        daemon=True
                    ).start()
                    logger.info(f"Sending image: {filename[0]}")
        except Exception as e:
            logger.error(f"Error sending image: {e}")

    def send_img(self, img_str):
        """Send image message"""
        self.gui_send_img.emit(img_str)

    def on_click_button_reset(self):
        """Clear output box"""
        self.output_box.clear()
        self.output_box.addItem("Ausgabelist wurde gelöscht")

    def run(self):
        """Run the application"""
        self.app.exec()

    def stop(self):
        """Stop the application"""
        logger.info("Stopping MessengerGui")
        self.stop_update_ctl_send = True
        self.sock.stop()
        self.mh.stop()
        self.bsd_publisher.stop()
        logger.info("MessengerGui stopped")


class MessengerPictures(PyQt6.QtWidgets.QWidget):
    """Window for displaying received images"""

    def __init__(self, data=""):
        super().__init__()
        self.layout = PyQt6.QtWidgets.QVBoxLayout()
        self.setLayout(self.layout)

        # Image label
        self.img_label = PyQt6.QtWidgets.QLabel("test")
        self.layout.addWidget(self.img_label)

        # Menu bar
        menu_bar = PyQt6.QtWidgets.QMenuBar()
        self.layout.setMenuBar(menu_bar)

        # File menu
        file_menu = PyQt6.QtWidgets.QMenu("&File", self)
        menu_bar.addMenu(file_menu)
        self.save_action = file_menu.addAction("💾 Save")
        self.save_action.setShortcut("Ctrl+S")
        self.save_action.triggered.connect(self.on_triggered_save)
        file_menu.addSeparator()
        self.exit_action = file_menu.addAction("❌ Exit")
        self.exit_action.triggered.connect(self.on_triggered_exit)

        # Help menu
        help_menu = PyQt6.QtWidgets.QMenu("&Help", self)
        menu_bar.addMenu(help_menu)
        self.test1_action = help_menu.addAction("test1")
        self.test2_action = help_menu.addAction("test2")

        self.show_pict(data)

    def show_pict(self, img):
        """Display image"""
        if img:
            qp = PyQt6.QtGui.QPixmap()
            qp.loadFromData(img, "png")
            self.img_label.setPixmap(qp)
        else:
            self.img_label.setText("")

    def on_triggered_save(self):
        """Save image to file"""
        time_str = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        images_path = os.path.expanduser("~") + "/Downloads/"
        filename = f'{images_path}recv_image_{time_str}.png'
        dialog = PyQt6.QtWidgets.QFileDialog.getSaveFileName(
            None, "Save Image", filename,
            "Image File (*.img *.png *.jpg *.gif)"
        )

    def on_triggered_exit(self):
        """Close window"""
        self.close()


class MessengerGuiMessageBox(PyQt6.QtWidgets.QWidget):
    """Message box for connection requests"""

    close_window = PySignal.ClassSignal()

    def __init__(self, data):
        super().__init__()
        layout = PyQt6.QtWidgets.QVBoxLayout()
        self.data = data
        self.setLayout(layout)

        text_label = PyQt6.QtWidgets.QLabel()
        text_label.setText(str(self.data.get("text", "no text popup")))
        self.setWindowTitle(self.data.get("title", "No Title"))
        layout.addWidget(text_label)
        layout.addWidget(self.generate_buttons())

    def generate_buttons(self):
        """Generate buttons from button dict"""
        widget = PyQt6.QtWidgets.QWidget()
        layout = PyQt6.QtWidgets.QHBoxLayout()

        for button in self.data.get("button", {}):
            push_button = PyQt6.QtWidgets.QPushButton(button)
            push_button.clicked.connect(self.on_button_click)
            layout.addWidget(push_button)

        widget.setLayout(layout)
        return widget

    def on_button_click(self):
        """Handle button click"""
        sender = self.sender()
        button_text = sender.text()
        logger.debug(f"Button clicked: {button_text}")

        if button_text:
            buttons = self.data.get("button", {})
            buttons.update({button_text: True})
            self.data.update({"button": buttons})

        self.close()

    def closeEvent(self, a0: PyQt6.QtGui.QCloseEvent):
        """Handle window close"""
        self.on_click_close()

    def on_click_close(self):
        """Close and emit signal"""
        self.close_window.emit(self.data)
        self.close()


class MessengerGuiOptions(PyQt6.QtWidgets.QWidget):
    """Options dialog window"""

    close_window = PySignal.ClassSignal()

    def __init__(self, data):
        super().__init__()
        self.grid_layout = PyQt6.QtWidgets.QVBoxLayout()
        self.data = data
        self.setLayout(self.grid_layout)

        # Name input
        name_label = PyQt6.QtWidgets.QLabel("Name:")
        self.grid_layout.addWidget(name_label)
        random_id_number = random.randint(0, 1000000000)
        self.textbox_name = PyQt6.QtWidgets.QLineEdit(
            str(self.data.get("name", f"Dave-{random_id_number}"))
        )
        self.grid_layout.addWidget(self.textbox_name)

        # Address inputs
        self.textboxes_addr = []
        addresses = self.data.get("addr", [])
        for address in addresses:
            if len(address) >= 2:
                self.grid_layout.addWidget(self.ip_port_addr_widget(address))

        # Add IP from BSD button
        bsd_add = PyQt6.QtWidgets.QPushButton("Add IP from BSD")
        bsd_add.clicked.connect(self.on_click_add_ip_bsd)
        self.grid_layout.addWidget(bsd_add)
        self.bsd = None

        # Cancel button
        btn_cancel = PyQt6.QtWidgets.QPushButton("Cancel")
        btn_cancel.clicked.connect(self.on_click_close)
        self.grid_layout.addWidget(btn_cancel)

        # OK button
        btn_ok = PyQt6.QtWidgets.QPushButton("Ok")
        btn_ok.clicked.connect(self.on_click_btn_ok)
        self.grid_layout.addWidget(btn_ok)

    def on_click_add_ip_bsd(self):
        """Open BSD service discovery"""
        try:
            self.bsd = multicast_gui.VaultServiceDiscovery(type_filter="BertMessenger")
            self.bsd.return_signal.connect(self.on_bsd_return)
            self.bsd.show()
        except Exception as e:
            logger.error(f"Error opening BSD service discovery: {e}")

    def on_bsd_return(self, value):
        """Handle BSD service discovery return"""
        logger.debug(f"BSD returned: {value}")

        return_ip = value.get("addr", ("", 0))[0] if value.get("addr") else ""
        return_port = value.get("addr", ("", 0))[1] if value.get("addr") else 0

        if not return_ip or not return_port:
            logger.warning("Invalid address from BSD")
            return

        do_add = False

        # Check if address already exists
        for i in range(len(self.textboxes_addr)):
            ip_existing = str(self.textboxes_addr[i][0].text())
            port_existing = str(self.textboxes_addr[i][1].text())

            if (str(return_ip) != ip_existing or str(return_port) != port_existing) and \
                    str(return_ip) not in helper_ip.get_ipv4_addresses():
                do_add = True
                break

        if do_add:
            self.grid_layout.addWidget(self.ip_port_addr_widget([return_ip, return_port]))
            logger.info(f"Added address from BSD: {return_ip}:{return_port}")

        if self.bsd and not self.bsd.isVisible():
            self.bsd.stop()
            self.bsd = None

    def ip_port_addr_widget(self, addr):
        """Create IP/Port input widget"""
        layout = PyQt6.QtWidgets.QHBoxLayout()
        widget = PyQt6.QtWidgets.QWidget()

        label_ip = PyQt6.QtWidgets.QLabel("IP:")
        layout.addWidget(label_ip)

        textbox_addr_ip = PyQt6.QtWidgets.QLineEdit(str(addr[0]))
        layout.addWidget(textbox_addr_ip)

        label_port = PyQt6.QtWidgets.QLabel("Port:")
        layout.addWidget(label_port)

        textbox_addr_port = PyQt6.QtWidgets.QLineEdit(str(addr[1]))
        layout.addWidget(textbox_addr_port)

        self.textboxes_addr.append((textbox_addr_ip, textbox_addr_port))
        widget.setLayout(layout)
        return widget

    def closeEvent(self, a0: PyQt6.QtGui.QCloseEvent):
        """Handle options window close"""
        self.on_click_close()

    def on_click_btn_ok(self):
        """Handle OK button"""
        try:
            addr = []
            for addr_number in range(len(self.textboxes_addr)):
                try:
                    ip = self.textboxes_addr[addr_number][0].text()
                    port = int(self.textboxes_addr[addr_number][1].text())
                    now = time.time()
                    addr.append([ip, port, now])
                    logger.debug(f"Parsed address: {ip}:{port}")
                except ValueError as e:
                    logger.error(f"Invalid port value: {e}")
                    PyQt6.QtWidgets.QMessageBox.warning(
                        self, "Error", f"Invalid port: {self.textboxes_addr[addr_number][1].text()}"
                    )
                    return

            self.data.update({
                "addr": addr,
                "name": self.textbox_name.text()
            })
            logger.info(f"Options updated with {len(addr)} addresses")
        except Exception as e:
            logger.error(f"Error in OK button handler: {e}")
            PyQt6.QtWidgets.QMessageBox.critical(self, "Error", str(e))

        self.on_click_close()

    def on_click_close(self):
        """Close options window"""
        self.close_window.emit(self.data)
        self.close()


if __name__ == '__main__':
    logging.basicConfig(
        level=logging.INFO,
        format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
    )

    logger.info("Starting Messenger Application")
    gui = MessengerGui()
    gui.run()
    gui.stop()
