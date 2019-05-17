#!/usr/bin/python

import sys
import socket
import threading

wr = None


class Writer(threading.Thread):
    def __init__(self, file):
        threading.Thread.__init__(self)
        self._list = list()
        self._file = open(file, "w")
        self._event = threading.Event()

    def run(self):
        while True:
            if len(self._list) > 0:
                a = self._list.pop()
                self._file.write(a.decode("UTF-8"))
                self._file.flush()
            self._event.wait()

    def add(self, event):
        self._list.append(event)
        self._event.set()


class Reader(threading.Thread):
    def __init__(self, socket):
        threading.Thread.__init__(self)
        self._sock = socket

    def run(self):
        try:
            v = self._sock.recv(4096)
            wr.add(v)
            self._sock.close()
        except Exception as err:
            print(err)


def listen(port, file):
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.bind(("", port))
    s.listen(500)
    global wr
    wr = Writer(file)
    wr.start()
    while True:
        try:
            a, h = s.accept()
            print(h)
            r = Reader(a)
            r.start()
        except IOError as err:
            print(err)


if __name__ == "__main__":
    listen(82, sys.argv[1])
