#!/usr/bin/env python3
import os.path as path


class Module:
    def __init__(self, incoming=False, verbose=False, options=None):
        # extract the file name from __file__. __file__ is proxymodules/name.py
        self.name = path.splitext(path.basename(__file__))[0]
        self.description = 'Remove HTTP header from data'
        self.incoming = incoming  # incoming means module is on -im chain

    def detect_linebreak(self, data):
        line = data.split(b'\n', 1)[0]
        if line.endswith(b'\r'):
            return b'\r\n' * 2
        else:
            return b'\n' * 2

    def execute(self, data):
        delimiter = self.detect_linebreak(data)
        if delimiter in data:
            data = data.split(delimiter, 1)[1]
        return data


if __name__ == '__main__':
    print('This module is not supposed to be executed alone!')
