from __future__ import print_function, absolute_import, division
import collections
import textwrap
from optparse import OptionParser
import codecs as c
import time
import array
import contextlib
import json
import sys
import random
import logging
import os.path as path
from cpppo.dotdict import dotdict
from cpppo.server.enip import parser

try:
    from future_builtins import zip, map  # Use Python 3 "lazy" zip, map
except ImportError:
    pass

FORMAT = ('%(asctime)-15s %(threadName)-15s'
          ' %(levelname)-8s %(module)-15s:%(lineno)-8s %(message)s')
log_filename = 'parser_ethernet_log.log'
logging.basicConfig(format=FORMAT, filename=log_filename)
log = logging.getLogger()


class Module:
    def __init__(self, incoming=False, verbose=False, options=None):
        # extract the file name from __file__. __file__ is proxymodules/name.py
        self.name = path.splitext(path.basename(__file__))[0]
        self.description = 'Print a hexdump of the received data and check the Ethernet ip frame'
        # self.incoming = incoming  # incoming means module is on -im chain
        self.len = 16
        self.rules = None
        # self.logfile = ('in-' if incoming else 'out-') + \
        #             time.strftime('%Y%m%d-%H%M%S.') + str(time.time()).split('.')[1]
        self.logfile = 'parser_ethernet_log.log'
        if options is not None:
            if 'length' in options.keys():
                self.len = int(options['length'])
            if 'logfile' in options.keys():
                self.logfile = options['logfile']
            if 'rules' in options.keys():
                self.rules = options['rules']
        self.handle = None

    def __del__(self):
        if self.handle is not None:
            self.handle.close()

    def help(self):
        return '\tlength: bytes per line (int)'

    def execute(self, data):
        print(data)
        flag = False
        try:
            flag = test_parser(data, self.rules)
        except:
            print('cannot parse*****' + str(data))
            pass

        if flag:
            if self.handle is None:
                self.handle = open(self.logfile, 'ab', 0)  # unbuffered
                # 'ab'means append the content to the file opened in binary without clear it at first
                print('Logging to file', self.logfile)
            logentry = bytes('attack was detected on ' + time.strftime('%Y%m%d-%H%M%S') + ' ' + str(time.time()) + '\n',
                             'utf-8')
            # logentry += bytes(str(message+b'\n').encode('utf-8'))

            logentry += b'-' * 20 + b'\n'
            self.handle.write(logentry)
            print(flag)
            data = b''
            print(data)
            print('message successfully blocked')
            return data

        else:
            return data


def test_parser(result, rules):
    flag = False
    data = dotdict()
    data.enip = {}
    source = result
    # b'\x6f\x00   require to be hex in this format
    with parser.enip_machine() as machine:
        with contextlib.closing(machine.run(source=source, data=data)) as engine:
            for m, s in engine:
                pass
    result = data.enip
    for item in result.values():
        print(item)
    print(result)
    if rules is not None:
        rule = rules.split('-', 1)
        print(rule)
        print(result.command)
        # print(result.function_code+'------------------')
        # print('------------------')
        if rule[0] == 'b':
            blocked_fun = rule[1].split('|')
            for item in blocked_fun:
                print(item)
                if result.command == int(item):
                    flag = True
                    print(flag)
                    return flag
    return flag
    # source_result = parser.enip_encode( data.enip )
    # print(source_result)
