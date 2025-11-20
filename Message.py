import copy
import json
import random

import nacl.encoding
import nacl.hash
import socket
import threading
import time
import uuid
import PySignal
import bert_utils.bert_helper


class Message:
    def __init__(self, max_length=None):
        self.__msg = {}
        if not max_length:
            # TODO get amx length from mtu or helper_udp
            max_length = 1000
        self.__max_length = max_length
        self.__norm_length = self.__calc_norm_length()

    def __calc_norm_length(self):
        self.set_text("")
        self.__msg.update({"part": "1000000", "pad": "10000"})
        json_string = json.dumps(self.__msg, indent=0)
        return int(self.__max_length)-len(json_string)

    def __set_uuid(self):
        uuid_to_set = str(uuid.uuid4())
        # print("id: {}".format(uuid_to_set))
        self.__msg.update({"id": uuid_to_set})

    def __set_hash(self):
        self.__msg.update({"hash": nacl.hash.sha256(message=self.__msg.get("content", "").encode("utf-8"), encoder=nacl.encoding.Base64Encoder).decode("utf-8")})

    def set_text(self, text):
        self.__msg.update({"content": text})
        self.__set_uuid()
        self.__set_hash()
        self.set_type("txt")

    def set_img(self, text):
        self.__msg.update({"content": text})
        self.__set_uuid()
        self.__set_hash()
        self.set_type("img")

    def set_file(self, text):
        """set content of message, create new uuid/ hash, set message type

        :param text: content of message
        :type : str
        """
        self.__msg.update({"content": text})
        self.__set_uuid()
        self.__set_hash()
        self.set_type("dat")

    def get_type(self):
        return self.__msg.get("type", "no type")

    def get_content(self):
        return self.__msg.get("content", "no content")

    def set_type(self, msg_type="txt"):
        self.__msg.update({"type": msg_type})

    def set_ctl(self, id_to_set, text, part_to_set=0):
        self.__msg.update({"id": id_to_set, "content": text, "part": part_to_set})
        self.set_type("ctl")
        self.__set_hash()

    def to_ctl_json(self):
        return json.dumps(self.__msg, indent=0)

    def to_json(self):
        result = []
        content = self.__msg.get("content")
        part_number = 0

        while len(content) > self.__norm_length:
            part_content = content[:self.__norm_length-2]
            content = content[self.__norm_length-2:]
            part_msg = {}
            part_msg.update({"id": self.__msg.get("id"), "part": part_number, "content": part_content, "pad": ""})
            # padding = self.padding(self.__max_length - len(json.dumps(part_msg, indent=0)))
            # part_msg.update({"pad": padding})
            part_number += 1
            result.append(json.dumps(part_msg, indent=0))

        tail_msg = {}
        tail_msg.update({"id": self.__msg.get("id"), "hash": self.__msg.get("hash"), "part": part_number, "content": content, "type": self.__msg.get("type"), "pad": ""})
        # padding = self.padding(self.__max_length - len(json.dumps(tail_msg, indent=0)))
        # tail_msg.update({"pad": padding})
        result.append(json.dumps(tail_msg, indent=0))
        return result

    def padding(self, length):
        alphabet = "abcdefghijklmnopqrstuvwxyz"
        alphabet += alphabet.upper()
        alphabet += "0123456789.-"
        return_string = ""
        for i in range(length):
            return_string += random.choice(alphabet)
        return return_string

    def from_json(self, input_list):
        if type(input_list) == str:
            input_list = [input_list]

        content_dict = {}
        recv_id = ""
        recv_hash = ""
        recv_type = ""
        parts = 0
        for json_str in input_list:
            msg_recv = json.loads(json_str)
            if msg_recv.get("part", 0) > parts:
                parts = msg_recv.get("part", 0)
            content_dict.update({parts: msg_recv.get("content", "")})
            if recv_id and msg_recv.get("id", False) != recv_id:
                raise ValueError("id differs")
            recv_id = msg_recv.get("id", 0)
            if recv_hash and msg_recv.get("hash", False) != recv_hash:
                raise ValueError("hash differs")
            recv_hash = msg_recv.get("hash", 0)
            if recv_type and msg_recv.get("type", False) != recv_type:
                raise ValueError("type differs")
            recv_type = msg_recv.get("type", 0)

        content_str = ""
        for number_part, content_part in content_dict.items():
            content_str += content_part

        self.__msg = {}
        self.__msg.update({"id": recv_id, "hash": recv_hash, "type": recv_type, "content": content_str})
        if not self.__check_hash():
            raise TypeError("hash missmatch")

    def __check_hash(self):
        check_str = nacl.hash.sha256(message=self.__msg.get("content", "").encode("utf-8"), encoder=nacl.encoding.Base64Encoder).decode("utf-8")
        if self.__msg.get("hash", "") != check_str:
            return False
        return True

    # def SetData(self, file_name):
    #     f = open(file_name, "r")
    #     print(f.read())


class MessageHandler:
    mh_send_data = PySignal.ClassSignal()
    mh_recv_text = PySignal.ClassSignal()
    mh_recv_img = PySignal.ClassSignal()
    mh_recv_file = PySignal.ClassSignal()
    mh_recv_control = PySignal.ClassSignal()

    def __init__(self, max_retry=2, timeout=300):
        self.max_retry = max_retry
        self.list_recv = {}
        self.list_send = {}
        self.recv_msg_buffer = {}
        self.timeout = timeout
        self.keys = bert_utils.bert_helper.generate_keys_asym()
        # self.filename = "{}/{}".format(os.getcwd(), "config/config.json")
        # self.data = bert_utils.bert_helper.json_file_read(self.filename)
        # self.data.update({"pub_key": self.keys[0]})
        # self.data.update({"pri_key": self.keys[1]})
        # bert_utils.bert_helper.json_file_write(self.data, self.filename)
        self.thread_stop = False
        threading.Timer(1, self.__check_recv_buffer).start()

    def send_txt_msg(self, text_to_send):
        message = Message()
        message.set_text(text_to_send)
        msg_list = message.to_json()
        self.__send_msg(msg_list)

    def send_img_msg(self, img_to_send):
        message = Message()
        message.set_img(img_to_send)
        msg_list = message.to_json()
        self.__send_msg(msg_list)

    def send_ctl_msg(self, ctl_dict):
        message = Message()
        message.set_text(json.dumps(ctl_dict, indent=0))
        message.set_type("ctl")
        msg_list = message.to_json()
        self.__send_msg(msg_list)

    def send_file_msg(self, file_to_send):
        """create a message, insert file data in message, split message and send splitted message

        :param file_to_send: describe of file and content of file
        :type file_to_send: str

        """
        message = Message()
        message.set_file(file_to_send)
        msg_list = message.to_json()
        self.__send_msg(msg_list)

    def __send_msg(self, msg_list):
        for msg in msg_list:
            # print("on send:{} ".format(msg.replace("\n", "")))
            msg_id_part = (json.loads(msg).get("id"), json.loads(msg).get("part"))
            msg_id_type = json.loads(msg).get("type")
            msg_id_content = json.loads(msg).get("content")
            retry = self.max_retry
            if msg_id_type == "ctl" and msg_id_content == "ack":
                retry = 1
            counter = 0

            list_recv_data = copy.deepcopy(self.list_recv)
            while counter <= retry and msg_id_part not in list_recv_data.keys() and not self.thread_stop:
                # print("Send: {} - {}".format(msg_id_part, list_recv_data))
                self.list_send.update({msg_id_part: time.time()})
                # print(self.list_send)

                # msg_in_byte = bert_utils.bert_helper.to_base64(msg)  # encrypted_msg
                # msg_encrypted = bert_utils.bert_helper.encrypt_asym(self.keys[0], msg_in_byte)
                self.mh_send_data.emit(msg)

                time.sleep(0.5)
                counter += 1
                list_recv_data = copy.deepcopy(self.list_recv)

            if msg_id_part not in self.list_recv.keys():
                # print("id {}/ part {} not confirmed".format(msg_id_part[0], msg_id_part[1]))
                pass
            else:
                self.list_recv.pop(msg_id_part)

    def recv_msg(self, recv_msg_json, addr=""):
        # print("Recv: {} from {}".format(recv_msg_json.replace("\n", ""), addr))
        # decrypted_recv_msg_bytes = bert_utils.bert_helper.decrypt_asym(self.keys[1], recv_msg)   # decrypt
        # recv_msg_json = bert_utils.bert_helper.from_base64_str(decrypted_recv_msg_bytes)
        try:
            # print(recv_msg_json)
            json.loads(recv_msg_json)
        except:
            return
        msg_id_part = (json.loads(recv_msg_json).get("id", False), json.loads(recv_msg_json).get("part", 0))
        # print("Recv part {}".format(msg_id_part))
        if not msg_id_part[0]:
            return
        msg_type = json.loads(recv_msg_json).get("type", False)
        msg_content = json.loads(recv_msg_json).get("content", False)
        if msg_id_part in self.list_send.keys() and msg_type == "ctl" and msg_content == "ack" and msg_id_part not in self.list_recv.keys():
            self.list_recv.update({msg_id_part: time.time()})
            # print("Recv: {} - {}".format(msg_id_part, self.list_recv.keys()))
        # print("{} / {} - {} / {}".format(msg_id_part, self.list_send.keys(), msg_type, msg_content.replace("\n", "")))
        if msg_id_part not in self.list_send.keys() and not (msg_type == "ctl" and msg_content == "ack"):
            # print("{} - {}".format(msg_id_part, self.list_send))
            ack_msg = Message()
            ack_msg.set_ctl(id_to_set=msg_id_part[0], part_to_set=msg_id_part[1], text="ack")
            ack_msg_str = ack_msg.to_ctl_json()
            # print(ack_msg_str.replace("\n", ""))
            self.recv_msg_buffer.update({time.time(): (recv_msg_json, addr)})
            self.__send_msg([ack_msg_str])
            time.sleep(0.1)

    def stop(self):
        self.thread_stop = True

    def __check_recv_buffer(self):
        list_msg = {}
        keys_to_delete = []
        for key, value in self.recv_msg_buffer.items():
            if key + self.timeout < time.time():
                keys_to_delete.append(key)
            msg = json.loads(value[0])
            addr = value[1]
            msg_id = msg.get("id", False)
            msg_id_list = list_msg.get(msg_id, [[], [], addr])
            msg_id_list[0].append(value[0])
            msg_id_list[1].append(key)
            if addr == msg_id_list[2]:
                list_msg.update({msg_id: msg_id_list})
        for msg_id, value in list_msg.items():
            # keys_msg_del = []
            try:
                recv_msg = Message()
                recv_msg.from_json(value[0])
                keys_msg_del = value[1]
                recv_addr = value[2]
                if recv_msg.get_type() == "txt":
                    self.mh_recv_text.emit(recv_msg.get_content(), recv_addr)
                if recv_msg.get_type() == "dat":
                    self.mh_recv_file.emit(recv_msg.get_content(), recv_addr)
                if recv_msg.get_type() == "img":
                    self.mh_recv_img.emit(recv_msg.get_content(), recv_addr)
                if recv_msg.get_type() == "ctl":
                    self.mh_recv_control.emit(recv_msg.get_content(), recv_addr)
            except:
                keys_msg_del = []
            for key in keys_msg_del:
                self.recv_msg_buffer.pop(key)
        for key in keys_to_delete:
            self.recv_msg_buffer.pop(key)
        send_keys_to_delete = []
        # print("{} - {}".format(time.time(), self.list_send))
        for key, value in self.list_send.items():
            if value + self.timeout < time.time():
                send_keys_to_delete.append(key)
        for key in send_keys_to_delete:
            self.list_send.pop(key)
        recv_keys_to_delete = []
        for key, value in self.list_recv.items():
            if value + self.timeout < time.time():
                recv_keys_to_delete.append(key)
        for key in recv_keys_to_delete:
            self.list_recv.pop(key)
        if not self.thread_stop:
            threading.Timer(1, self.__check_recv_buffer).start()


if __name__ == '__main__':
    msg1 = Message()
    test_text = ""
    for i in range(100):
        test_text += "Hello World {}! ".format(i)
    msg1.set_text(test_text)
    data = msg1.to_json()
    print(data)
    msg2 = Message()
    msg2.from_json(data)
    for element in msg2.to_json():
        print("length: {}; msg: {}".format(len(element), element.replace("\n", "")))

