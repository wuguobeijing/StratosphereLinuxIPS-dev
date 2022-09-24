#!/usr/bin/env python3
import os.path as path
import paho.mqtt.client as mqtt
from distutils.util import strtobool


class Module:
    def __init__(self, incoming=False, verbose=False, options=None):
        # extract the file name from __file__. __file__ is proxymodules/name.py
        self.name = path.splitext(path.basename(__file__))[0]
        self.description = 'Publish the data to an MQTT server'
        self.incoming = incoming  # incoming means module is on -im chain
        self.client_id = ''
        self.username = None
        self.password = None
        self.server = None
        self.port = 1883
        self.topic = ''
        self.hex = False
        if options is not None:
            if 'clientid' in options.keys():
                self.client_id = options['clientid']
            if 'server' in options.keys():
                self.server = options['server']
            if 'username' in options.keys():
                self.username = options['username']
            if 'password' in options.keys():
                self.password = options['password']
            if 'port' in options.keys():
                try:
                    self.port = int(options['port'])
                    if self.port not in range(1, 65536):
                        raise ValueError
                except ValueError:
                    print(f'port: invalid port {options["port"]}, using default {self.port}')
            if 'topic' in options.keys():
                self.topic = options['topic']
            if 'hex' in options.keys():
                try:
                    self.hex = bool(strtobool(options['hex']))
                except ValueError:
                    print(f'hex: {options["hex"]} is not a bool value, falling back to default value {self.hex}.')

        if self.server is not None:
            self.mqtt = mqtt.Client(self.client_id)
            if self.username is not None or self.password is not None:
                self.mqtt.username_pw_set(self.username, self.password)
            self.mqtt.connect(self.server, self.port)
        else:
            self.mqtt = None

    def execute(self, data):
        if self.mqtt is not None:
            if not self.mqtt.is_connected():
                self.mqtt.reconnect()
            if self.hex is True:
                self.mqtt.publish(self.topic, data.hex())
            else:
                self.mqtt.publish(self.topic, data)
        return data

    def help(self):
        h = '\tserver: server to connect to, required\n'
        h += ('\tclientid: what to use as client_id, default is empty\n'
              '\tusername: username\n'
              '\tpassword: password\n'
              '\tport: port to connect to, default 1883\n'
              '\ttopic: topic to publish to, default is empty\n'
              '\thex: encode data as hex before sending it. AAAA becomes 41414141.')
        return h


if __name__ == '__main__':
    print('This module is not supposed to be executed alone!')
