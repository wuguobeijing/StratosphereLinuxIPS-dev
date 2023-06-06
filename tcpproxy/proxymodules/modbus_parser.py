
# -------------------------------------------------------------------------- #

from __future__ import print_function
import collections
import textwrap
from optparse import OptionParser
import codecs as c
import time
from pymodbus.factory import ClientDecoder, ServerDecoder
from pymodbus.transaction import ModbusSocketFramer
from pymodbus.compat import IS_PYTHON3

import logging
import os.path as path
# -------------------------------------------------------------------------- #
# -------------------------------------------------------------------------- #

FORMAT = ('%(asctime)-15s %(threadName)-15s'
          ' %(levelname)-8s %(module)-15s:%(lineno)-8s %(message)s')
log_filename = 'parser_modbus_log.log'
logging.basicConfig(format=FORMAT, filename=log_filename)
log = logging.getLogger()

# -------------------------------------------------------------------------- #
# build a module to use the modbus_parser
# -------------------------------------------------------------------------- #
class Module:
    def __init__(self, incoming=False, verbose=False, options=None):
        # extract the file name from __file__. __file__ is proxymodules/name.py
        self.name = path.splitext(path.basename(__file__))[0]
        self.description = 'Print a hexdump of the received data and check the modbus frame'
        #self.incoming = incoming  # incoming means module is on -im chain
        self.len = 16
        self.rules = None
        # self.logfile = ('in-' if incoming else 'out-') + \
        #             time.strftime('%Y%m%d-%H%M%S.') + str(time.time()).split('.')[1]
        self.logfile = 'parser_error_log.log'
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
        result1 = [] #存储一整行的数据内容
        digits = 2
        for i in range(0, len(data),  len(data)):
            s = data[i:i +len(data)]
            hexa = ''.join(['%0*X' % (digits, x) for x in s])
            result1.append(hexa)
            result2 = ''.join(result1)
        option1 = get_options()

        framer = lookup = {
            'tcp': ModbusSocketFramer,
        }.get('tcp', ModbusSocketFramer)

        # print(self.rules)
        # rule = self.rules.split('-', 1)
        # print(rule)
        # print(rule[0])
        # if rule[0] == 'b':
        #     blocked_fun = rule[1].split('|')
        #     for item in blocked_fun:
        #         print(item)

        decoder = Decoder(framer, self.rules, False)
        for message in get_messages(option1, result2):
            print(self.rules)
            flag = decoder.decode(message)
            print(flag)

            if flag:
                if self.handle is None:
                    self.handle = open(self.logfile, 'ab', 0)  # unbuffered
                    # 'ab'means append the content to the file opened in binary without clear it at first
                    print('Logging to file', self.logfile)
                logentry = bytes('attack was detected on '+time.strftime('%Y%m%d-%H%M%S') + ' ' + str(time.time()) + '\n', 'utf-8')
                logentry += bytes(str(message+b'\n').encode('utf-8'))
                #logentry += data+b'\n'
                logentry += b'-' * 20 + b'\n'
                self.handle.write(logentry)
                print(flag)
                data = b''
                print(data)
                print('message successfully blocked')
                return data
            else:
                return data

# -------------------------------------------------------------------------- #
# build a quick wrapper around the framers
# -------------------------------------------------------------------------- #

class Decoder(object):

    def __init__(self, framer, rules, encode=False):
        """ Initialize a new instance of the decoder

        :param framer: The framer to use
        :param encode: If the message needs to be encoded
        """
        self.framer = framer
        self.encode = encode
        self.modbus_rules = rules

    def decode(self, message):
        """ Attempt to decode the supplied message

        :param message: The messge to decode
        """
        if IS_PYTHON3:
            value = message if self.encode else c.encode(message, 'hex_codec')
        else:
            value = message if self.encode else message.encode('hex')
        print("="*80)
        print("Decoding Message %s" % value)
        print("="*80)
        decoders = [
            self.framer(ServerDecoder(), client=None),
            #self.framer(ClientDecoder(), client=None)
        ]
        for decoder in decoders:
            print("%s" % decoder.decoder.__class__.__name__)
            print("-"*80)
            try:
                decoder.addToFrame(message)
                if decoder.checkFrame():
                    unit = decoder._header.get("uid", 0x01)
                    decoder.advanceFrame()
                    flag = decoder.processIncomingPacket(message, self.report, self.modbus_rules, unit)
                    print(flag)
                    return flag
                else:
                    self.check_errors(decoder, message)
            except Exception as ex:
                self.check_errors(decoder, message)

    def check_errors(self, decoder, message):
        """ Attempt to find message errors

        :param message: The message to find errors in
        """
        log.error("Unable to parse message - {} with {}".format(message,decoder))

    def report(self, message):
        """ The callback to print the message information

        :param message: The message to print
        """
        print("%-15s = %s" % ('name', message.__class__.__name__))
        for (k, v) in message.__dict__.items():
            if isinstance(v, dict):
                print("%-15s =" % k)
                for kk, vv in v.items():
                    print("  %-12s => %s" % (kk, vv))

            elif isinstance(v, collections.Iterable):
                print("%-15s =" % k)
                value = str([int(x) for x  in v])
                for line in textwrap.wrap(value, 60):
                    print("%-15s . %s" % ("", line))
            else:
                #if k == 'unit_id' and v == 1:
                #    print('error')
                print("%-15s = %s" % (k, hex(v)))            #用于打印匹配的内容
        print("%-15s = %s" % ('documentation', message.__doc__))



# -------------------------------------------------------------------------- #
# and decode our message
# -------------------------------------------------------------------------- #
def get_options():
    """ A helper method to parse the command line options

    :returns: The options manager
    """
    parser = OptionParser()

    parser.add_option("-p", "--parser",
                      help="The type of parser to use "
                           "(tcp, rtu, binary, ascii)",
                      dest="parser", default="tcp")

    parser.add_option("-D", "--debug",
                      help="Enable debug tracing",
                      action="store_true", dest="debug", default=False)

    # parser.add_option("-m", "--message",
    #                   help="The message to parse",
    #                   dest="message", default=None)

    parser.add_option("-a", "--ascii",
                      help="The indicates that the message is ascii",
                      action="store_false", dest="ascii", default=True)

    parser.add_option("-b", "--binary",
                      help="The indicates that the message is binary",
                      action="store_false", dest="ascii",default=False)

    parser.add_option("-f", "--file",
                      help="The file containing messages to parse",
                      dest="file", default=None)

    parser.add_option("-t", "--transaction",
                      help="If the incoming message is in hexadecimal format",
                      action="store_true", dest="transaction", default=False)

    #print(1234)
    # (opt, arg) = parser.parse_args()
    opt={'parser': 'tcp', 'debug': False, 'ascii': False, 'file': None, 'transaction': False}
    #(opt)

    return opt


def get_messages(option, result):
    """ A helper method to generate the messages to parse

    :param options: The option manager
    :returns: The message iterator to parse
    """
    if result:

        if True:
            if not IS_PYTHON3:
                result = result.decode('hex')
            else:
                result = c.decode(result.encode(), 'hex_codec')
        yield result
    elif option.file:
        with open(option.file, "r") as handle:
            for line in handle:
                if line.startswith('#'): continue
                if not option.ascii:
                    line = line.strip()
                    line = line.decode('hex')
                yield line

#
# def main():
#     """ The main runner function
#     """
#     option = get_options()
#
#     framer = lookup = {
#         'tcp':    ModbusSocketFramer,
#         'rtu':    ModbusRtuFramer,
#         'binary': ModbusBinaryFramer,
#         'ascii':  ModbusAsciiFramer,
#     }.get(option.parser, ModbusSocketFramer)
#
#     decoder = Decoder(framer, option.ascii)
#     for message in get_messages(option):
#         decoder.decode(message)


if __name__ == "__main__":
    print ('This module is not supposed to be executed alone!')