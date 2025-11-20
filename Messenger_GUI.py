import Messenger.Message
import bert_utils.bert_helper
import bert_utils.helper_ip
import bert_utils.helper_multicast
import bert_utils.gui.BertrandtServiceDiscovery
import bert_utils.helper_udp
import datetime
import json
import os
import random
import threading
import time

import Message
import PyQt6.QtCore
import PyQt6.QtGui
import PyQt6.QtWidgets
import PIL
import PIL.ImageQt
import PySignal


# TODO UDP & Encryption from Helper

class MessengerGui:
    gui_send_text = PySignal.ClassSignal()
    gui_send_img = PySignal.ClassSignal()
    gui_send_file = PySignal.ClassSignal()

    def __init__(self):
        self.filename = "{}/{}".format(os.getcwd(), "config/config.json")
        self.data = bert_utils.bert_helper.json_file_read(self.filename)
        addr = self.data.get("addr", "")
        recv_port = self.data.get("recv_port", random.randint(1500, 65000))
        self.data.update({"recv_port": recv_port})

        self.priv_key = self.data.get("priv_key")
        self.pub_key = self.data.get("pub_key", "")
        if not self.priv_key:
            self.pub_key, self.priv_key = bert_utils.bert_helper.generate_keys_asym()
        if not self.pub_key:
            self.pub_key = bert_utils.bert_helper.generate_pub_key(self.priv_key)
        self.data.update({"pub_key": self.pub_key})
        self.data.update({"priv_key": self.priv_key})
        bert_utils.bert_helper.json_file_write(self.data, self.filename)

        self.bsd_type = self.data.get("bsd_type", "BertMessenger")
        self.data.update({"bsd_type": self.bsd_type})
        self.bsd_publisher = bert_utils.helper_multicast.BertMultiPublisher(timeout=2)

        self.app = PyQt6.QtWidgets.QApplication([])
        self.main_window = PyQt6.QtWidgets.QWidget()
        self.main_window.setWindowTitle(self.data.get("title", "Messenger"))
        self.layout = PyQt6.QtWidgets.QGridLayout()
        self.main_window.setLayout(self.layout)
        self.main_window.show()
        # icon settings
        if self.data.get("icon", False):
            self.main_window.setWindowIcon(PyQt6.QtGui.QIcon(self.data.get("icon")))
        self.check_addr_in_config()
        # label
        output_label = PyQt6.QtWidgets.QLabel("Ausgabe:")
        self.layout.addWidget(output_label, 0, 0)
        # listbox
        self.output_box = PyQt6.QtWidgets.QListWidget()
        self.output_box.addItem("Hallo")
        self.layout.addWidget(self.output_box, 1, 0, 1, 6)
        # label
        self.tb_label = PyQt6.QtWidgets.QLabel("Eingabe:")
        self.layout.addWidget(self.tb_label, 2, 0)
        # textbox
        self.textbox = PyQt6.QtWidgets.QLineEdit()
        self.textbox.setMinimumSize(100, 35)
        self.layout.addWidget(self.textbox, 3, 0, 1, 4)
        # button send
        btn_send = PyQt6.QtWidgets.QPushButton("Send")
        btn_send.setMinimumSize(50, 35)
        btn_send.clicked.connect(self.on_click_button_send)
        self.layout.addWidget(btn_send, 3, 4, 1, 2)
        # button options
        btn_options = PyQt6.QtWidgets.QPushButton("Einstellungen")
        btn_options.clicked.connect(self.on_click_button_options)
        self.layout.addWidget(btn_options, 4, 0, 1, 2)
        # button state
        btn_current_state = PyQt6.QtWidgets.QPushButton("Aktueller Zustand")
        btn_current_state.clicked.connect(self.on_click_button_state)
        self.layout.addWidget(btn_current_state, 4, 2, 1, 1)
        # button reset
        btn_reset = PyQt6.QtWidgets.QPushButton("Reset")
        btn_reset.clicked.connect(self.on_click_button_reset)
        self.layout.addWidget(btn_reset, 4, 3, 1, 1)
        # button send image
        btn_send_img = PyQt6.QtWidgets.QPushButton("Bild senden")
        btn_send_img.clicked.connect(self.on_click_btn_send_img)
        self.layout.addWidget(btn_send_img, 4, 4, 1, 2)
        # button send datei
        btn_send_file = PyQt6.QtWidgets.QPushButton("Datei senden")
        btn_send_file.clicked.connect(self.on_click_button_send_file)
        self.layout.addWidget(btn_send_file, 5, 1, 1, 3)

        self.options_window = None
        if not addr:
            self.on_click_button_options()

        # additional settings
        self.sock = bert_utils.helper_udp.UDPSocketClass(recv_port=recv_port)
        threading.Timer(0.5, self.thread_start_sock).start()
        self.mh = Message.MessageHandler()
        # self.me = Message.MessageEncryption(self.priv_key)
        self.sock.pkse.set_private_key(self.priv_key)

        # sending from mh -> sock to all
        self.mh.mh_send_data.connect(self.sock.send_data)

        # recv sock -> mh
        self.sock.udp_recv_data.connect(self.mh.recv_msg)

        # mh recv/ send text <-> gui
        self.mh.mh_recv_text.connect(self.on_recv_text)
        self.gui_send_text.connect(self.mh.send_txt_msg)

        # mh recv/ send img <-> gui
        self.mh.mh_recv_img.connect(self.on_recv_img)
        self.gui_send_img.connect(self.mh.send_img_msg)

        self.mh.mh_recv_file.connect(self.on_recv_file)
        self.gui_send_file.connect(self.mh.send_file_msg)

        self.stop_update_ctl_send = False
        self.ignore_addr = []
        self.addr_box = None
        threading.Timer(5, self.update_ctl_send).start()

        # mh recv control message -> gui
        self.mh.mh_recv_control.connect(self.on_recv_ctl)
        self.addr_name = self.data.get("addr_name", {})

        self.mbox_data = {}
        self.img_to_show = None
        self.img_window = None
        self.mb_timer = PyQt6.QtCore.QTimer()
        self.mb_timer.timeout.connect(self.timer_mbox_check)
        self.mb_timer.start(2000)

    def on_recv_ctl(self, data="", addr=""):
        # data = json.dumps({"name": "irgs", "addr": ["127.0.0.1", 32272], "key": "12345"})
        # addr = ("127.0.0.1", 32272)
        print("ctl data: {} from: {}".format(data.replace("\n", ""), addr))
        try:
            data = json.loads(data)
        except:
            return
        name = data.get("name", "")
        key = data.get("key", "")
        addr_data = data.get("addr", "")
        self.sock.pkse.update_key(addr_data, key)
        if addr[0] != addr_data[0]:
            return
        if addr and addr_data not in self.sock.mask_addresses and addr_data not in self.ignore_addr and not self.addr_box:
            # print("new addr {}".format(addr_data))
            text = "New incoming connection from {}\n\nWant to use for the session (Ok), Save in config, Ignore?\n".format(
                name)
            title = "New Connection"
            buttons = {"Ok": False, "Save": False, "Ignore": False}
            self.mbox_data = {"text": text, "title": title, "button": buttons, "name": name, "addr_data": addr_data,
                              "type": "addr"}

    def timer_mbox_check(self):
        # print("timer mbox")
        # print(self.mbox_data)
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

    def check_addr_in_config(self):  # TODO
        now = time.time()
        timeout = 60 * 60 * 24 * 7
        addresses = []
        for addr in self.data.get("addr", ""):
            if (float(addr[2]) + float(timeout)) < now:
                # print("Old connections has been deleted")
                pass
            else:
                # print("Neu")
                addresses.append(addr)
        self.data.update({"addr": addresses})
        # print(self.data)

    def open_mbox_addr_window(self, mbox_data):
        print("open mbox")
        if not self.addr_box:
            self.addr_box = MessengerGuiMessageBox(mbox_data)
            self.addr_box.close_window.connect(self.close_mbox_addr_window)
            self.addr_box.show()

    def close_mbox_addr_window(self, mbox_data):
        print("close mbox")
        if mbox_data:
            print("Data recv: {}".format(mbox_data))
            button_ok = mbox_data.get("button", {}).get("Ok", False)
            button_save = mbox_data.get("button", {}).get("Save", False)
            button_ignore = mbox_data.get("button", {}).get("Ignore", False)
            name = mbox_data.get("name")
            addr_data = mbox_data.get("addr_data")
            recv_ip = addr_data[0]
            recv_port = addr_data[1]
            addr = []
            time_str = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
            addr.append([recv_ip, recv_port, time_str])
            if button_save:
                # self.data.update({"addr": addr_data})
                self.data.update({"addr": addr})
                self.sock.update(addr=addr_data)
                if name:
                    self.addr_name.update({str(addr_data[0]): (name, time.time())})
                    self.data.update({"name": self.addr_name})
                bert_utils.bert_helper.json_file_write(self.data, self.filename)
            elif button_ok:
                self.data.update({"addr": addr})
                self.sock.update(addr=addr_data)
                if name:
                    self.addr_name.update({tuple(addr_data): (name, time.time())})
            else:
                self.ignore_addr.append(addr_data)
                if name:
                    self.addr_name.update({tuple(addr_data): (name, time.time())})
            self.addr_box = None
        self.addr_box = None

    def update_ctl_send(self):
        ip = bert_utils.helper_ip.get_ips()[0][0]
        recv_port = self.sock.recv_port
        name = self.data.get("name", "Test")
        key = self.pub_key
        bsd_data = {"addr": (ip, recv_port), "name": name, "key": key, "type": self.bsd_type}
        self.bsd_publisher.update_message(json.dumps(bsd_data))
        ctl_data = {"addr": (ip, recv_port), "name": name, "key": key}
        self.mh.send_ctl_msg(ctl_data)
        if not self.stop_update_ctl_send:
            threading.Timer(10, self.update_ctl_send).start()

    def on_click_button_send(self):
        if not self.textbox.text():
            last_item_index = self.output_box.count() - 1
            item = self.output_box.item(last_item_index).text()
            if not item == "Bitte text eingeben":
                self.output_box.addItem("Bitte text eingeben")
        else:
            time_str = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")

            threading.Timer(0.1, self.send_text, args=[self.textbox.text()]).start()
            self.output_box.addItem("{}: try sending: {}".format(time_str, self.textbox.text()))
            self.textbox.setText("")

    def send_text(self, text):
        self.gui_send_text.emit(text)

    def on_recv_text(self, text, addr=""):
        time_str = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")

        if addr and self.addr_name.get(tuple(addr), ("", 1))[0]:
            self.output_box.addItem(
                "{}: from: {} received: {}".format(time_str, self.addr_name.get(addr[0], ("", 1))[0], text))
        else:
            self.output_box.addItem("{}: received: {}".format(time_str, text))

    def on_recv_img(self, img_str="", addr=""):
        # print(img_str)
        img_bytes = bert_utils.bert_helper.from_base64_byte(img_str)
        time_str = datetime.datetime.now().strftime("%Y%m%d_%H:%M:%S")

        if addr and self.addr_name.get(addr[0], ("", 1))[0]:
            self.output_box.addItem(
                "{}: from: {} received: {}".format(time_str, self.addr_name.get(addr[0], ("", 1))[0], img_bytes))
        else:
            self.output_box.addItem("{}: received: {}".format(time_str, img_bytes))

        if img_bytes:
            self.img_to_show = img_bytes

    def on_recv_file(self, message_content, addr=""):

        """recv data message, convert data to byte and filename, opens file dialog, save byte as under choosen filename

        :param message_content: message that we recv
        :type message_content: str

        """

        # Json loads, nachricht inhalt, send file == dict
        send_file = json.loads(message_content)
        filename = send_file.get("Dateiname")
        file_str = send_file.get("Inhalt")
        # from base64 byte
        file_byte = bert_utils.bert_helper.from_base64_byte(file_str)
        #safe dialog,
        filename = PyQt6.QtWidgets.QFileDialog.getSaveFileName(None, "Save File", filename, "Image File (*.*)")  # filename as String
        if filename:
            f = open(filename[0], mode='wb')
            f.write(file_byte)
            f.close()

    def on_click_button_send_file(self):

        """opens file dialog, choose file, create data message, send data message

        """
        file_dialog = PyQt6.QtWidgets.QFileDialog()
        file_dialog.setFileMode(PyQt6.QtWidgets.QFileDialog.FileMode.ExistingFile)
        file_dialog.getOpenFileName()
        filename = file_dialog.selectedFiles()
        if filename:
            f = open(filename[0], mode='rb')
            file_byte = f.read()
            file_str = bert_utils.bert_helper.to_base64_str(file_byte)
            # file_bytes = bert_utils.bert_helper.to_base64_str(file_str)
            send_files = {"Dateiname": filename, "Inhalt": file_str}
            message_content = json.dumps(send_files)
            self.gui_send_file.emit(message_content)

    def on_click_button_options(self):
        self.options_window = MessengerGuiOptions(self.data)
        self.options_window.close_window.connect(self.on_close_options_window)
        self.options_window.show()

    def on_close_options_window(self, options_data):
        print("Options data: {}".format(options_data))
        if not options_data:
            print("no data recv")
            options_data = self.data
        for key, value in options_data.items():
            self.data.update({key: value})
        self.options_window.close_window.disconnect(self.on_close_options_window)
        self.options_window = None
        bert_utils.bert_helper.json_file_write(self.data, self.filename)
        threading.Timer(0.5, self.thread_start_sock).start()

    def thread_start_sock(self):
        # print(self.data.get("addr"))
        # print(type(self.data.get("addr")))
        addr = self.data.get("addr", "")
        for address in addr:
            self.sock.update(address, recv_port=self.data.get("recv_port", ""))

    def on_click_button_state(self):
        cur_state = ["127.0.0.1", "5000"]
        last_item_index = self.output_box.count()
        last_item_index = last_item_index - 1
        for addr in self.sock.mask_addresses:
            cur_state = "Send-Address: {} RecvPort: {}".format(addr, self.sock.recv_port)
            if last_item_index < 1:
                self.output_box.addItem(cur_state)
            elif not cur_state == self.output_box.item(last_item_index).text():
                self.output_box.addItem(cur_state)

    def on_click_btn_send_img(self):
        time_str = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        # filename = PyQt6.QtWidgets.QFileDialog.getOpenFileName(None, "Open file", 'C://images/', "Image files (*.img *.png *.jpg *.gif)") # filename as String
        dialog = PyQt6.QtWidgets.QFileDialog(None)
        dialog.setFileMode(PyQt6.QtWidgets.QFileDialog.FileMode.AnyFile)
        dialog.setDirectory(os.path.expanduser("~") + "/Downloads/")
        dialog.setNameFilter("Image files (*.img *.png *.jpg *.gif)")
        if dialog.exec():
            filename = dialog.selectedFiles()
            if filename[0]:
                file = open(filename[0], "rb")
                data = file.read()
                data_str = bert_utils.bert_helper.to_base64_str(data)
                self.output_box.addItem("{}: try sending: {}".format(time_str, filename[0]))
                threading.Timer(1, self.send_img, args=[data_str]).start()

    def send_img(self, img_str):
        self.gui_send_img.emit(img_str)

    def on_click_button_reset(self):
        self.output_box.clear()
        self.output_box.addItem("Ausgabelist wurde gelöscht")

    # todo timer function removing to long unused addr, user
    # when no addr survives - ?unconnect send, connect options?

    def run(self):
        self.app.exec()

    def stop(self):
        self.stop_update_ctl_send = True
        self.sock.stop()
        self.mh.stop()
        self.bsd_publisher.stop()


class MessengerPictures(PyQt6.QtWidgets.QWidget):
    def __init__(self, data=""):
        super().__init__()
        self.layout = PyQt6.QtWidgets.QVBoxLayout()
        self.setLayout(self.layout)

        # Qwidgets
        # img label
        self.img_label = PyQt6.QtWidgets.QLabel("test")
        self.layout.addWidget(self.img_label)

        # menu bar
        menu_bar = PyQt6.QtWidgets.QMenuBar()
        self.layout.setMenuBar(menu_bar)

        # file menu
        file_menu = PyQt6.QtWidgets.QMenu("&File", self)
        menu_bar.addMenu(file_menu)
        self.save_action = file_menu.addAction("💾 Save")
        self.save_action.setShortcut("Ctrl+S")
        self.save_action.triggered.connect(self.on_triggered_save)
        file_menu.addSeparator()
        self.exit_action = file_menu.addAction("❌ Exit")
        self.exit_action.triggered.connect(self.on_triggered_exit)
        # help menu
        help_menu = PyQt6.QtWidgets.QMenu("&Help", self)
        menu_bar.addMenu(help_menu)
        self.test1_action = help_menu.addAction("test1")
        self.test2_action = help_menu.addAction("test2")

        self.show_pict(data)

    def show_pict(self, img):
        if img:
            qp = PyQt6.QtGui.QPixmap()
            qp.loadFromData(img, "png")
            self.img_label.setPixmap(qp)
            self.img_label.setPixmap(qp)
        else:
            self.img_label.setText("")

    def on_triggered_save(self):
        time_str = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        images_path = os.path.expanduser("~") + "/Downloads/"
        filename = '{}\\recv_image_{}.png'.format(images_path, time_str)
        dialog = PyQt6.QtWidgets.QFileDialog.getSaveFileName(None, "Save Image", filename,
                                                             "Image File (*.img *.png *.jpg *.gif)")

    def on_triggered_exit(self):
        self.close()


class MessengerGuiMessageBox(PyQt6.QtWidgets.QWidget):
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
        widget = PyQt6.QtWidgets.QWidget()
        layout = PyQt6.QtWidgets.QHBoxLayout()
        for button in self.data.get("button", {"close": False}):
            push_button = PyQt6.QtWidgets.QPushButton(button)
            push_button.clicked.connect(self.on_button_click)
            layout.addWidget(push_button)
        widget.setLayout(layout)
        return widget

    def on_button_click(self):
        sender = self.sender()
        button_text = sender.text()
        print("Button {} clicked".format(button_text))
        if button_text:
            buttons = self.data.get("button", {})
            buttons.update({button_text: True})
            self.data.update({"button": buttons})
            print(self.data.get("button"))
        self.close()

    def closeEvent(self, a0: PyQt6.QtGui.QCloseEvent):
        self.on_click_close()

    def on_click_close(self):
        self.close_window.emit(self.data)
        self.close()


class MessengerGuiOptions(PyQt6.QtWidgets.QWidget):
    close_window = PySignal.ClassSignal()

    def __init__(self, data):
        super().__init__()
        self.grid_layout = PyQt6.QtWidgets.QVBoxLayout()
        self.data = data
        self.setLayout(self.grid_layout)

        name_label = PyQt6.QtWidgets.QLabel("Name:")
        self.grid_layout.addWidget(name_label)
        random_id_number = random.randint(0, 1000000000)
        self.textbox_name = PyQt6.QtWidgets.QLineEdit(str(self.data.get("name", "Dave-{}".format(random_id_number))))
        self.grid_layout.addWidget(self.textbox_name)

        # text boxes
        self.textboxes_addr = []
        addresses = self.data.get("addr", ("127.0.0.1", 11000))
        for address in addresses:
            self.grid_layout.addWidget(self.ip_port_addr_widget(address))

        bsd_add = PyQt6.QtWidgets.QPushButton("Add IP from BSD")
        bsd_add.clicked.connect(self.on_click_add_ip_bsd)
        self.grid_layout.addWidget(bsd_add)
        self.bsd = None
        # buttons
        btn_cancel = PyQt6.QtWidgets.QPushButton("Cancel")
        btn_cancel.clicked.connect(self.on_click_close)
        self.grid_layout.addWidget(btn_cancel)
        btn_ok = PyQt6.QtWidgets.QPushButton("Ok")
        btn_ok.clicked.connect(self.on_click_btn_ok)
        self.grid_layout.addWidget(btn_ok)

    def on_click_add_ip_bsd(self):
        self.bsd = bert_utils.gui.BertrandtServiceDiscovery.BertrandtServiceDiscovery(type_filter="BertMessenger")
        self.bsd.return_signal.connect(self.on_bsd_return)
        self.bsd.show()

    def on_bsd_return(self, value):
        print("Mainwindow: {}".format(value))
        # value = {'addr': ['192.168.72.23', 48521], 'name': 'Sebastian', 'key': '', 'type': 'BertMessenger'}
        # bsp: {'addr': ['192.168.72.23', 48521], 'name': 'Sebastian', 'key': '', 'type': 'BertMessenger'}
        return_ip = value.get("addr", "")[0]
        return_port = value.get("addr", "")[1]
        do_add = False
        if return_ip and return_port:
            for i in range(0, len(self.textboxes_addr)):
                if str(return_ip) != str(self.textboxes_addr[i][0].text()) or str(return_port) != str(
                        self.textboxes_addr[i][1].text()) and str(return_ip) not in bert_utils.helper_ip.get_ips():
                    do_add = True
        if do_add:
            self.grid_layout.addWidget(self.ip_port_addr_widget(value.get("addr")))
            # key zurück geben -> self.data, am rücksprung punkt dann an message encrypt geben

        if not self.bsd.isVisible():
            self.bsd = None

    def ip_port_addr_widget(self, addr):
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
        self.on_click_close()

    def on_click_btn_ok(self):
        try:
            addr = []
            # print(len(self.textboxes_addr))
            for addr_number in range(0, len(self.textboxes_addr)):
                now = time.time()
                # print("IP: {}, Port: {}".format(self.textboxes_addr[addr_number][0].text(), self.textboxes_addr[addr_number][1].text()))
                addr.append(
                    [self.textboxes_addr[addr_number][0].text(), int(self.textboxes_addr[addr_number][1].text()), now])
            # print(addr)
            self.data.update({"addr": addr, "name": self.textbox_name.text()})
            print(self.data)
        except Exception as e:
            print("{}".format(e))
            pass
        self.on_click_close()

    def on_click_close(self):
        self.close_window.emit(self.data)
        self.close()


if __name__ == '__main__':
    gui = MessengerGui()
    gui.run()
    gui.stop()
