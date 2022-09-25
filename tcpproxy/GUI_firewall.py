import ctypes
import inspect
import json
import pickle
import xlrd
import xlwt
from tkinter import *
from tkinter import messagebox
from tkinter.messagebox import askyesno, showwarning

from kafka import KafkaConsumer
from kafka.errors import NoBrokersAvailable

import GUI_iptables
import argparse
import sys
import threading
import socket
import socks
import time
import select
import errno
import numpy as np
import subprocess
from new_model import reveive_model

LOG_LINE_NUM = 0


class MY_GUI():
    def __init__(self, init_window, fun1, fun2, fun3, fun4):
        self.init_window = init_window
        self.set_init_window(fun1, fun2, fun3, fun4)

    # 设置窗口

    def set_init_window(self, fun1, fun2, fun3, fun4):
        self.init_window.title("代理型边缘工业防火墙 v-1.0")  # 窗口名
        self.init_window.geometry('840x480+430+160')  # 290 160为窗口大小，+10 +10 定义窗口弹出时的默认展示位置
        # self.init_window_name.geometry('1068x681+10+10')
        self.init_window["bg"] = "DimGray"  # 窗口背景色，其他背景色见：blog.csdn.net/chl0000/article/details/7657887
        # 标签
        self.frame_top = Frame(self.init_window, relief=RAISED, borderwidth=2)
        self.frame_top.pack(padx=2, pady=2, ipady=2, ipadx=2, side='top')
        self.iptables_button = Button(self.frame_top, text="退出", bg="Snow", width=4, height=2,
                                      command=fun3, relief='solid', font=("newspaper", 17))
        self.iptables_button.pack(anchor=E, side='right')
        self.iptables_button = Button(self.frame_top, text="iptables", bg="Snow", width=10, height=2,
                                      command=self.open_iptables, relief='solid', font=("newspaper", 17))
        self.iptables_button.pack(anchor=E, side='right')
        self.set_init_rules_button = Button(self.frame_top, text="加载边缘防护规则", bg="Snow", width=12, height=2,
                                            command=fun4, relief='solid', font=("newspaper", 12))
        self.set_init_rules_button.pack(anchor=E, side='right')
        self.indus_firewall_Label = Label(self.frame_top, text="工业防火墙", bg="Gainsboro", width=25,
                                          height=2, relief='solid', font=("newspaper", 12))
        self.indus_firewall_Label.pack(side='left', anchor=CENTER)

        self.frame_down = Frame(self.init_window, relief=RAISED, borderwidth=2)
        self.frame_down.pack(padx=12, pady=12, ipady=12, ipadx=12, side='top')

        self.log_manage_button = Button(self.frame_down, text="日志管理", bg="lightblue", width=22, height=2,
                                        command=self.open_log, font=("newspaper", 12))
        self.log_manage_button.pack(side='bottom', anchor=CENTER)
        # self.log_manage_button = Button(self.frame_down, text="开启服务", bg="lightblue", width=22, height=2,
        #                                 command=self.open_receive_model, font=("newspaper", 12))
        # self.log_manage_button.pack(side='bottom', anchor=CENTER)

        self.frame_show_rule = Frame(self.frame_down)
        self.frame_show_rule.pack(padx=12, pady=12, ipady=12, ipadx=12, side='bottom')
        self.rule_printout_Scroll = Scrollbar(self.frame_show_rule)
        self.rule_printout_Scroll.pack(side='right', fill='y')
        self.rule_printout = Listbox(self.frame_show_rule, yscrollcommand=self.rule_printout_Scroll.set, width=100,
                                     height=1)
        self.rule_printout.pack(side='right', fill=BOTH)
        self.rule_printout_Scroll.config(command=self.rule_printout.yview)

        self.frame_funcions_button = Frame(self.frame_down, relief=RAISED, borderwidth=1)
        self.frame_funcions_button.pack(padx=2, pady=2, ipady=2, ipadx=2, side='bottom')
        self.help_button = Button(self.frame_funcions_button, text="帮助", bg="lightblue", width=22, height=2,
                                  command=self.open_help, font=("newspaper", 12)).pack(side='left', anchor='w')
        self.add_rule_button = Button(self.frame_funcions_button, text="添加规则", bg="lightblue", width=22, height=2,
                                      command=fun1, font=("newspaper", 12)).pack(side='left', anchor='center')
        self.del_rule_button = Button(self.frame_funcions_button, text="删除规则", bg="lightblue", width=22, height=2,
                                      command=fun2, font=("newspaper", 12)).pack(side='left', anchor='e')

        self.frame_funcions_input1 = Frame(self.frame_down, relief=RAISED, borderwidth=1)
        self.frame_funcions_input1.pack(padx=2, pady=2, ipady=2, ipadx=2, side='left')
        self.frame_funcions_input1_ip = Frame(self.frame_funcions_input1, borderwidth=1)
        self.frame_funcions_input1_ip.pack(padx=2, pady=2, ipady=2, ipadx=2, side='top')
        self.tip_Label = Label(self.frame_funcions_input1_ip, text="目标ip *", bg="Snow", width=8, height=2,
                               font=("newspaper", 9))
        self.tip_Label.pack(side='left', anchor=CENTER)
        self.tip_input = Text(self.frame_funcions_input1_ip, width=15, height=2)
        self.tip_input.pack(side='left', anchor=CENTER)
        self.lip_Label = Label(self.frame_funcions_input1_ip, text="监听ip *", bg="Snow", width=8, height=2,
                               font=("newspaper", 9))
        self.lip_Label.pack(side='left', anchor=CENTER)
        self.lip_input = Text(self.frame_funcions_input1_ip, width=15, height=2)
        self.lip_input.pack(side='left', anchor=CENTER)

        self.frame_funcions_input1_port = Frame(self.frame_funcions_input1, borderwidth=1)
        self.frame_funcions_input1_port.pack(padx=2, pady=2, ipady=2, ipadx=2)
        self.tp_Label = Label(self.frame_funcions_input1_port, text="目标端口 *", bg="Snow", width=8,
                              height=2, font=("newspaper", 9))
        self.tp_Label.pack(side='left', anchor=CENTER)
        self.tp_input = Text(self.frame_funcions_input1_port, width=15, height=2)
        self.tp_input.pack(side='left', anchor=CENTER)
        self.lp_Label = Label(self.frame_funcions_input1_port, text="监听端口 *", bg="Snow", width=8,
                              height=2, font=("newspaper", 9))
        self.lp_Label.pack(side='left', anchor=CENTER)
        self.lp_input = Text(self.frame_funcions_input1_port, width=15, height=2)
        self.lp_input.pack(side='left', anchor=CENTER)

        self.frame_funcions_input2 = Frame(self.frame_down)
        self.frame_funcions_input2.pack(padx=2, pady=2, ipady=5, ipadx=2)
        self.in_module_Label = Label(self.frame_funcions_input2, text="输入防护模块", width=28, height=1,
                                     font=("newspaper", 12), bg="Snow")
        self.in_module_Label.pack(side='top', anchor=CENTER)
        self.in_module_input = Text(self.frame_funcions_input2, width=33, height=2)
        self.in_module_input.pack(side='top', anchor=CENTER)
        self.out_module_Label = Label(self.frame_funcions_input2, text="输出防护模块", width=28, height=1,
                                      font=("newspaper", 12), bg="Snow")
        self.out_module_Label.pack(side='top', anchor=CENTER)
        self.out_module_input = Text(self.frame_funcions_input2, width=33, height=2)
        self.out_module_input.pack(side='top', anchor=CENTER)
        self.varlog = IntVar()  # 定义var1整型变量用来存放选择行为返回值
        self.log_choice = Checkbutton(self.frame_funcions_input2, text='记录日志', variable=self.varlog, onvalue=1,
                                      offvalue=0)
        self.log_choice.pack(side='top', anchor=CENTER)

    def open_iptables(self):
        iptables_window = Toplevel(self.init_window)
        IP_window = GUI_iptables.MY_IP_GUI(iptables_window)
        IP_window.set_IP_window()
        iptables_window.mainloop()

    def open_log(self):
        log_window = Toplevel(self.init_window)
        LOG_window = MY_LOG_GUI(log_window)
        LOG_window.set_log_window()
        LOG_window.read_common_log()
        log_window.mainloop()

    def open_help(self):
        help_window0 = Toplevel(self.init_window)
        HELP_window = MY_HELP_GUI(help_window0)
        HELP_window.set_HELP_window0()
        help_window0.mainloop()


class MY_HELP_GUI():
    def __init__(self, help_window0):
        self.help_window0 = help_window0

    def set_HELP_window0(self):
        self.help_window0.title("帮助文档")  # 窗口名
        self.help_window0.geometry('640x420+670+360')
        self.frame_top = Frame(self.help_window0, relief=RAISED, borderwidth=2)
        self.frame_top.pack(padx=2, pady=2, ipady=2, ipadx=2, side='top')
        self.text_Scroll = Scrollbar(self.frame_top)
        self.text_Scroll.pack(side='right', fill='y')
        self.help_input = Text(self.frame_top, yscrollcommand=self.text_Scroll.set, width=70, height=60,
                               font=("newspaper", 12))
        self.help_input.pack(side='right', fill=BOTH)
        self.help_input.insert(END, '（1）隔离和对传统网络流量的访问控制功能。工业防火墙首先在分层之间起到隔离作用，并对内部网络或来自互联网的攻击流量起到访问控制作用。 '
                                    '\n（2）网络层报文访问控制。对数据包的进行分层解析后按照iptables规则进行网络层的访问控制，同时针对一些可识别的特定的网络攻击进行阻截。'
                                    '\n（3）深度工业协议解析过滤。包含在工控协议内部的攻击行为可以直接通过网络防火墙，因此工业防火墙重点就是对工业协议内部详细解析，通过白名单规则过滤。'
                                    '\n'
                                    '\n工业控制网络防火墙的代理部署方式'
                                    '\n'
                                    '\n防火墙功能开发'
                                    '\n通用网络威胁防护'
                                    '\n①实现不同局域网网络之间的转发，利用NAT技术完成网络连接部署。'
                                    '\n②实现指定端口的代理：例如，保护控制器的502端口不能被直接访问到，需要通过代理端口完成通讯。'
                                    '\n③可以阻止不在白名单当中的ip地址访问代理服务器。'
                                    '\n④预防轻量级dos攻击'
                                    '\n⑤丢弃 Fragments 碎片数据包 (碎片数据包攻击的后果: 可能导致正常数据包丢失)'
                                    '\n⑥丢弃异常的 XMAS 数据包 (异常的 XMAS 数据包攻击的后果: 可能导致某些系统崩溃)'
                                    '\n⑦丢弃 NULL 空数据包'
                                    '\n⑧允许有限的 TCP RST 请求'
                                    '\n⑨防止端口嗅探'
                                    '\n（1） Modbus TCP协议防护'
                                    '\nModbus是一种串行通信协议，是Modicon公司（现在的施耐德电气 Schneider Electric）于1979年为使用可编程逻辑控制器（PLC）通信而发表。Modbus已经成为工业领域通信协议的业界标准，并且现在是工业电子设备之间常用的连接方式。针对下列使用Modbus协议通讯的网络可能存在的安全威胁，我们开发了相应的安全防护功能：'
                                    '\n①Modbus数据包大小或长度有问题（与长度位不符）'
                                    '\n②502端口上的非Modbus报文'
                                    '\n③并不是点对点的流量（从服务器发往多个客户端）：禁止在一个连接已经建立的情况下，进行一个新的连接，在阻断新连接的情况下不干扰原来的连接。'
                                    '\n④功能码不可识别（可理解为非Modbus报文）'
                                    '\n⑤拦截具有指定功能码、设备码（Unit_id）、请求内容长度的数据包'
                                    '\n⑥拦截事务处理标识号不连续的数据包'
                                    '\n⑦对上述所有应用层防护功能检测到的异常行为进行日志记录        '
                                    '\n'
                                    '\n（2）Ethernet IP协议'
                                    '\nEthernet IP指的是"以太网工业协议"(Ethernet Industrial Protocol)。它定义了一个开放的工业标准，将传统的以太网与工业协议相结合。该标准是由国际控制网络和开放设备网络供应商协会 (ODVA)在工业以太网协会的协助下联合开发的，并于2000年3月推出。Ethernet IP是基于TCP/IP系列协议，因此采用以原有的形式OSI层模型中较低的4层。'
                                    '\nEthernet IP是开放的网络技术，它是基于在工业通讯领域广为证实的通用工业协议CIP（Common Industrial Protocol, 原控制和信息协议），支持您在同一链路上完整实现以生产者/消费者模式驱动的设备组态、实时控制、信息采集等全部网络功能。针对这一协议，我们实现的防护功能有：'
                                    '\n①Ethernet IP的显示非连接数据包大小或长度有问题'
                                    '\n②44818端口上的非Ethernet IP报文'
                                    '\n③功能码不可识别（可理解为非Ethernet IP报文）'
                                    '\n④拦截具有指定功能码、发送者内容（sender context）的数据包'
                                    '\n⑤拦截具有不正确的状态位的数据包'
                                    '\n⑥对上述所有应用层防护功能检测到的异常行为进行日志记录'
                                    '\n'
                                    '\n防火墙规则部署方法'
                                    '\n软件界面基本情况如您所见，'
                                    '\n最上方左侧四个输入栏为用户配置代理端口地址（实际操作时为安全增强装置的代理端口）与目标端口地址（实际操作时为控制器端口）的输入栏。'
                                    '\n最上方右侧为用户需要在代理服务器当中使用的功能模块，输入防护模块对从目标端口发往代理端口的数据包进行操作，输出防护模块对从代理端口发往目标端口的数据包进行操作，一般情况下就使用输出防护模块，因为安全威胁主要来源于外部。例如若需要部署modbus防火墙，并且在针对协议基础的审计之外实现针对特定的功能码15、16的拦截，就在输出防护模块当中按照一定的输入规则（modbus_parser:rules=b-15|16）来完成部署。'
                                    '\n工业防火墙主界面就是登陆后的初始界面'
                                    '\n中间三个按钮靠左侧的为帮助文档，包括各部分如何进行输入以及如何进行规则管理的说明。'
                                    '\n中间三个按钮靠中和靠右的为针对上方部署的规则的管理按钮，在上方填写完一个规则过后，点击添加规则即可在后台开启一个代理服务器程序，并且显示在⑤当中；如果在⑤当中选择一条已经添加的规则，则可以通过点击删除规则来结束这一代理；'
                                    '\n下方的滚动栏为显示现有规则的规则列表。'
                                    '\n最下方的按钮为日志管理界面的打开按钮，如果在上方的记录日志单选框内选择了“√”，则日志界面就可以查询到所有违规的数据包及该数据包的相关违规信息；此外所有的规则添加时间与其他管理信息都会默认存储到日志文件当中，便于管理人员进行运维。'
                                    '\n通用防火墙界面具体的功能。通过单击主页面的iptables按钮即可进入iptables防火墙部署页面：该页面包含五个功能按钮：①帮助：打开iptables规则部署的帮助文档。②添加推荐规则：打开包含各类可以一键部署的推荐规则界面。③添加自定义规则：通过用户自己输入规则来进行配置的自定义规则添加按钮。④指定规则管理：通过选择自己想要查看的表并点击“指定规则管理”按钮来进入相应的表，进而对表中的规则进行操作。⑤删除所有规则：快速删除全部规则以便从新进行配置。'
                                    '\n当点开iptables按钮后即可进入内嵌通用防火墙界面'
                                    '\n推荐规则页面在点击推荐规则按钮后即可打开，包括几部分规则，在选择了一条推荐规则之后，这条规则就会变化相应按钮背景颜色，提示管理员已经配置完成，避免重复部署。'
                                    '\n推荐规则页面'
                                    '\n在点击了指定规则表规则管理按钮后，用户在选择指定表管理之后弹出的页面，用户可以在该页面中查看表内规则或者删除某一条规则。')


class MY_LOG_GUI():
    def __init__(self, log_window):
        self.log_window = log_window

    def set_log_window(self):
        self.log_window.title("result log")  # 窗口名
        self.log_window.geometry('540x620+480+260')
        self.log_top = Frame(self.log_window, relief=RAISED, borderwidth=2)
        self.log_top.pack(padx=2, pady=2, ipady=2, ipadx=2, side='top')
        self.log_common = Frame(self.log_top)
        self.log_common.pack(padx=2, pady=2, ipady=2, ipadx=2, side='top')
        self.log_printout_Scroll = Scrollbar(self.log_common)
        self.log_printout_Scroll.pack(side='right', fill='y')
        self.show_common_log = Text(self.log_common, yscrollcommand=self.log_printout_Scroll.set, width=68, height=15)
        self.show_common_log.pack(side='right', fill=BOTH)
        self.log_printout_Scroll.config(command=self.show_common_log.yview)

        self.log_specific = Frame(self.log_top)
        self.log_specific.pack(padx=2, pady=2, ipady=2, ipadx=2, side='bottom')
        self.log_spe_Scroll = Scrollbar(self.log_specific)
        self.log_spe_Scroll.pack(side='right', fill='y')
        self.show_spe_log = Text(self.log_specific, yscrollcommand=self.log_spe_Scroll.set, width=68, height=15)
        self.show_spe_log.pack(side='right', fill=BOTH)
        self.log_spe_Scroll.config(command=self.show_spe_log.yview)

        self.log_modbus_button = Button(self.log_top, text="modbus", bg="lightblue", width=16, height=2,
                                        command=self.read_modbus_log, font=("newspaper", 12))
        self.log_modbus_button.pack(side='left', anchor='w', padx=10)
        self.log_tcpip_button = Button(self.log_top, text="Tcp Ip", bg="lightblue", width=16, height=2,
                                       command=self.read_modbus_log, font=("newspaper", 12))
        self.log_tcpip_button.pack(side='left', anchor='w', padx=10)
        self.log_EtherIP_button = Button(self.log_top, text="Ethernet IP", bg="lightblue", width=16, height=2,
                                         command=self.read_ethernet_log, font=("newspaper", 12))
        self.log_EtherIP_button.pack(side='left', anchor='w', padx=10)

    def read_common_log(self):
        file_path = 'firewall_log.log'
        # print('打开文件：', file_path)
        if file_path is not None:
            with open(file=file_path, mode='r+', encoding='utf-8') as file:
                file_text = file.read()
            self.show_common_log.insert('insert', file_text)

    def read_modbus_log(self):
        file_path = 'parser_modbus_log.log'
        # print('打开文件：', file_path)
        if file_path is not None:
            try:
                with open(file=file_path, mode='r+', encoding='utf-8') as file:
                    file_text = file.read()
                self.show_spe_log.insert('insert', file_text)
            except:
                showwarning('error', 'cannot find this file')

    def read_ethernet_log(self):
        file_path = 'parser_ethernet_log.log'
        # print('打开文件：', file_path)
        if file_path is not None:
            with open(file=file_path, mode='r+', encoding='utf-8') as file:
                file_text = file.read()
            self.show_spe_log.insert('insert', file_text)


class Indus_Rule():
    def __init__(self, init_window):
        self.init_window = init_window
        self.gui = MY_GUI(init_window, self.add_rule_start, self.delete_rule, self.close_window, self.add_init_rules)
        self.thread_now = None
        self.thread_num = None
        self.thread_to_delete = None
        self.rule_list = [[], [], [], [], [], [], []]
        self.init_rule_list = {}
        # self.current_thread = None
        self.__running = None
        # self.main_thread_now = None
        self.main__running = None
        self.init_tip = None
        self.init_tp = None
        self.init_lip = None
        self.init_lp = None
        self.init_im = None
        self.init_om = None
        self.init_log = None
        self.rules_count = 0

    def add_rule_start(self):
        thread = threading.Thread(target=self.add_rule)
        self.main_thread_now = thread
        self.main__running = threading.Event()
        thread.start()

    def add_init_rules(self):
        thread = threading.Thread(target=self.add_init_rule)
        self.main_thread_now = thread
        self.main__running = threading.Event()
        thread.start()

    def close_window(self):
        try:
            ans = askyesno(title='Warning', message='are you sure to exit?')
            if ans:
                # if self.main__running is not None:
                #     self.main__running.clear()
                # threading.Event.clear()
                self.thread_to_delete = threading.current_thread()
                print(self.thread_to_delete)
                print(type(self.thread_to_delete))
                if self.thread_to_delete.is_alive() == True:
                    # self.thread_to_delete.clear()
                    # self.main__running.clear()
                    print('')
                    # self.stop_thread()
                self.init_window.destroy()
                main()
            else:
                return
        except:
            print('can not close')

    def parse_init_args(self):
        tip, tp, lip, lp, im, om, log = self.init_tip, self.init_tp, self.init_lip, self.init_lp, \
                                        self.init_im, self.init_om, self.init_log
        # print(om)
        parser = argparse.ArgumentParser(description='Simple TCP proxy for data ' +
                                                     'interception and ' +
                                                     'modification. ' +
                                                     'Select modules to handle ' +
                                                     'the intercepted traffic.')

        parser.add_argument('-ti', '--targetip', dest='target_ip', default=tip,
                            help='remote target IP or host name')
        parser.add_argument('-tp', '--targetport', dest='target_port', type=int, default=tp,
                            help='remote target port')
        parser.add_argument('-li', '--listenip', dest='listen_ip',
                            default=lip, help='IP address/host name to listen for incoming data')
        parser.add_argument('-lp', '--listenport', dest='listen_port', type=int,
                            default=lp, help='port to listen on')
        parser.add_argument('-pi', '--proxy-ip', dest='proxy_ip', default=None,
                            help='IP address/host name of proxy')
        parser.add_argument('-pp', '--proxy-port', dest='proxy_port', type=int,
                            default=1080, help='proxy port', )
        parser.add_argument('-pt', '--proxy-type', dest='proxy_type', default='SOCKS5',
                            choices=['SOCKS4', 'SOCKS5', 'HTTP'],
                            type=str.upper, help='proxy type. Options are SOCKS5 (default), SOCKS4, HTTP')
        parser.add_argument('-v', '--verbose', dest='verbose', default=False,
                            action='store_true',
                            help='More verbose output of status information')
        parser.add_argument('-n', '--no-chain', dest='no_chain_modules',
                            action='store_true', default=False,
                            help='Don\'t send output from one module to the ' + 'next one')
        parser.add_argument('--list', dest='list', action='store_true',
                            help='list available modules')
        parser.add_argument('-lo', '--list-options', dest='help_modules', default=None,
                            help='Print help of selected module')
        parser.add_argument('-s', '--ssl', dest='use_ssl', action='store_true',
                            default=False, help='detect SSL/TLS as well as STARTTLS')
        parser.add_argument('-sc', '--server-certificate', default='mitm.pem',
                            help='server certificate in PEM format (default: %(default)s)')
        parser.add_argument('-sk', '--server-key', default='mitm.pem',
                            help='server key in PEM format (default: %(default)s)')
        parser.add_argument('-cc', '--client-certificate', default=None,
                            help='client certificate in PEM format in case client authentication is required by the target')
        parser.add_argument('-ck', '--client-key', default=None,
                            help='client key in PEM format in case client authentication is required by the target')
        if om != '':
            parser.add_argument('-om', '--outmodules', dest='out_modules', default=om.replace('\'', ''),
                                help='comma-separated list of modules to modify data' +
                                     ' before sending to remote target.')
        else:
            parser.add_argument('-om', '--outmodules', dest='out_modules',
                                help='comma-separated list of modules to modify data' +
                                     ' before sending to remote target.')
        if im != '':
            parser.add_argument('-im', '--inmodules', dest='in_modules', default=im.replace('\'', ''),
                                help='comma-separated list of modules to modify data' +
                                     ' received from the remote target.')
        else:
            parser.add_argument('-im', '--inmodules', dest='in_modules',
                                help='comma-separated list of modules to modify data' +
                                     ' received from the remote target.')
        if log == 1:
            parser.add_argument('-l', '--log', dest='logfile', default='firewall_log.log',
                                help='Log all data to a file before modules are run.')
        else:
            parser.add_argument('-l', '--log', dest='logfile', default=None,
                                help='Log all data to a file before modules are run.')
        return parser.parse_args()

    def parse_args(self):  # 把页面中提取出的字段读取到parser表达式模块中
        tip, tp, lip, lp, im, om, log = self.set_parse()
        parser = argparse.ArgumentParser(description='Simple TCP proxy for data ' +
                                                     'interception and ' +
                                                     'modification. ' +
                                                     'Select modules to handle ' +
                                                     'the intercepted traffic.')

        parser.add_argument('-ti', '--targetip', dest='target_ip', default=tip,
                            help='remote target IP or host name')

        parser.add_argument('-tp', '--targetport', dest='target_port', type=int, default=tp,
                            help='remote target port')

        parser.add_argument('-li', '--listenip', dest='listen_ip',
                            default=lip, help='IP address/host name to listen for ' +
                                              'incoming data')

        parser.add_argument('-lp', '--listenport', dest='listen_port', type=int,
                            default=lp, help='port to listen on')

        parser.add_argument('-pi', '--proxy-ip', dest='proxy_ip', default=None,
                            help='IP address/host name of proxy')

        parser.add_argument('-pp', '--proxy-port', dest='proxy_port', type=int,
                            default=1080, help='proxy port', )

        parser.add_argument('-pt', '--proxy-type', dest='proxy_type', default='SOCKS5',
                            choices=['SOCKS4', 'SOCKS5', 'HTTP'],
                            type=str.upper, help='proxy type. Options are SOCKS5 (default), SOCKS4, HTTP')
        parser.add_argument('-v', '--verbose', dest='verbose', default=False,
                            action='store_true',
                            help='More verbose output of status information')

        parser.add_argument('-n', '--no-chain', dest='no_chain_modules',
                            action='store_true', default=False,
                            help='Don\'t send output from one module to the ' + 'next one')

        parser.add_argument('--list', dest='list', action='store_true',
                            help='list available modules')

        parser.add_argument('-lo', '--list-options', dest='help_modules', default=None,
                            help='Print help of selected module')

        parser.add_argument('-s', '--ssl', dest='use_ssl', action='store_true',
                            default=False, help='detect SSL/TLS as well as STARTTLS')

        parser.add_argument('-sc', '--server-certificate', default='mitm.pem',
                            help='server certificate in PEM format (default: %(default)s)')

        parser.add_argument('-sk', '--server-key', default='mitm.pem',
                            help='server key in PEM format (default: %(default)s)')

        parser.add_argument('-cc', '--client-certificate', default=None,
                            help='client certificate in PEM format in case client authentication is required by the target')

        parser.add_argument('-ck', '--client-key', default=None,
                            help='client key in PEM format in case client authentication is required by the target')

        if om != '':
            parser.add_argument('-om', '--outmodules', dest='out_modules', default=om.replace('\'', ''),
                                help='comma-separated list of modules to modify data' +
                                     ' before sending to remote target.')
        else:
            parser.add_argument('-om', '--outmodules', dest='out_modules',
                                help='comma-separated list of modules to modify data' +
                                     ' before sending to remote target.')

        if im != '':
            parser.add_argument('-im', '--inmodules', dest='in_modules', default=im.replace('\'', ''),
                                help='comma-separated list of modules to modify data' +
                                     ' received from the remote target.')
        else:
            parser.add_argument('-im', '--inmodules', dest='in_modules',
                                help='comma-separated list of modules to modify data' +
                                     ' received from the remote target.')
        if log == 1:
            parser.add_argument('-l', '--log', dest='logfile', default='firewall_log.log',
                                help='Log all data to a file before modules are run.')
        else:
            parser.add_argument('-l', '--log', dest='logfile', default=None,
                                help='Log all data to a file before modules are run.')

        return parser.parse_args()

    def set_parse(self):  # 把页面当中填入的文字提取出来
        target_ip = self.gui.tip_input.get(1.0, END).strip().replace("\n", "")
        target_port = self.gui.tp_input.get(1.0, END).strip().replace("\n", "")
        listen_ip = self.gui.lip_input.get(1.0, END).strip().replace("\n", "")
        listen_port = self.gui.lp_input.get(1.0, END).strip().replace("\n", "")
        in_module = self.gui.in_module_input.get(1.0, END).strip("'").replace("\n", "")
        out_module = self.gui.out_module_input.get(1.0, END).strip("'").replace("\n", "")
        log = self.gui.varlog.get()
        if target_ip == '':
            showwarning('警告', 'tip cannot be empty')
            sys.exit(10)
        if target_port == '':
            showwarning('警告', 'tp cannot be empty')
            sys.exit(11)
        if listen_ip == '':
            showwarning('警告', 'lip cannot be empty')
            sys.exit(12)
        if listen_port == '':
            showwarning('警告', 'lp cannot be empty')
            sys.exit(13)
        return target_ip, target_port, listen_ip, listen_port, in_module, out_module, log

    def add_rule(self):
        self.parse_args()
        proxy_thread = threading.Thread(target=self.run)
        self.thread_now = proxy_thread
        self.__running = threading.Event()
        print(self.thread_now)
        proxy_thread.start()
        # self.add_to_list()

    def add_init_rule(self):
        data_path = 'log/init_rules.xls'  # excle表格路径，需传入绝对路径
        try:
            data = xlrd.open_workbook(data_path)
            sheetname = data.sheet_names()[0]  # excle表格内sheet名
            print(sheetname)
            sheet1 = data.sheet_by_name('Sheet1')
            col = sheet1.col_values(0)
            print(col)
            for i in range(len(col)):
                self.rules_count += 1
                row = sheet1.row_values(i)
                print(row)
                self.init_tip = row[0]
                self.init_tp = row[1]
                self.init_lip = row[2]
                self.init_lp = row[3]
                self.init_im = row[4]
                self.init_om = row[5]
                print(self.parse_init_args())
                self.init_add_to_list()
                print(123)
                proxy_thread = threading.Thread(target=self.init_run)
                self.thread_now = proxy_thread
                self.__running = threading.Event()
                proxy_thread.start()
                print(1234)

        except:
            showwarning('notice', 'can not find file')

    def get_threadnow(self):
        return self.thread_now

    def delete_rule(self):
        try:
            rule_index = self.gui.rule_printout.index(ACTIVE)
            print(rule_index)
            self.thread_to_delete = self.rule_list[0][rule_index]
            print(self.thread_to_delete)
            print(type(self.thread_to_delete))
            if self.thread_to_delete.is_alive() == True:
                # self.thread_to_delete.clear()
                # self.main__running.clear()
                self.stop_thread()
            self.gui.rule_printout.delete(ACTIVE)
            for i in range(7):
                del self.rule_list[i][rule_index]

            data = xlrd.open_workbook('log/init_rules.xls')
            sheetname = data.sheet_names()[0]  # excle表格内sheet名
            print(sheetname)
            table = data.sheet_by_name('Sheet1')
            print(table)
            row = table.nrows  # 行数
            print(row)
            col = table.ncols  # 列数
            print(col)
            workbook = xlwt.Workbook(encoding='ascii')
            worksheet = workbook.add_sheet('Sheet1')
            style = xlwt.XFStyle()  # 初始化样式
            font = xlwt.Font()  # 为样式创建字体
            for i in range(col):
                n = 0
                cols = table.col_values(i)
                for k in range(len(cols)):
                    if k != rule_index:
                        worksheet.write(n, i, cols[k])
                n += 1
            workbook.save('log/init_rules.xls')  # 保存文件
            # datamatrix = [] # 生成一个nrows行ncols列，且元素均为0的初始矩阵
            # for x in range(row):
            #     matrix1=[0]
            #     datamatrix.append(matrix1)
            # n = 0
            # for x in range(col):
            #     cols = table.col_values(x) # 把list转换为矩阵进行矩阵操作
            #     print(cols)
            #     datamatrix[n,x] = cols  # 按列把数据存进矩阵中
            #     n+=1
            # print(datamatrix)
            # workbook = xlwt.Workbook(encoding='ascii')
            # worksheet = workbook.add_sheet('My Worksheet')
            # style = xlwt.XFStyle()  # 初始化样式
            # font = xlwt.Font()  # 为样式创建字体
            # for i in range(len(filtered_boxs)):
            #     for j in range(len(filtered_boxs[0])):
            #         worksheet.write(i, j, filtered_boxs[i,j])  # 不带样式的写入
            # workbook.save('log/init_rules.xls')
        except:
            showwarning('警告', '没有删除规则')

    def _async_raise(self, exctype):  # 删除线程
        """raises the exception, performs cleanup if needed"""
        tid = self.thread_to_delete.ident
        print(tid, exctype)
        tid = ctypes.c_long(tid)
        print(tid)
        if not inspect.isclass(exctype):
            print(exctype)
            exctype = type(exctype)
        print(exctype)
        res = ctypes.pythonapi.PyThreadState_SetAsyncExc(tid, ctypes.py_object(exctype))
        print(res)
        if res == 0:
            raise ValueError("invalid thread id")
        elif res != 1:
            # """if it returns a number greater than one, you're in trouble,
            # and you should call it again with exc=NULL to revert the effect"""
            ctypes.pythonapi.PyThreadState_SetAsyncExc(tid, None)
            raise SystemError("PyThreadState_SetAsyncExc failed")

    def stop_thread(self):  # 调用删除线程
        self._async_raise(SystemExit)
        print('------/n-------------/n------------/n=---------')

    def add_to_list(self):
        # print(self.thread_num)

        self.rule_list[0].append(self.main_thread_now)
        self.rule_list[1].append(self.gui.tip_input.get(1.0, END).strip().replace("\n", ""))
        self.rule_list[2].append(self.gui.tp_input.get(1.0, END).strip().replace("\n", ""))
        self.rule_list[3].append(self.gui.lip_input.get(1.0, END).strip().replace("\n", ""))
        self.rule_list[4].append(self.gui.lp_input.get(1.0, END).strip().replace("\n", ""))
        self.rule_list[5].append(self.gui.in_module_input.get(1.0, END).strip().replace("\n", ""))
        self.rule_list[6].append(self.gui.out_module_input.get(1.0, END).strip().replace("\n", ""))
        show_list = []
        arr = np.array(self.rule_list)
        try:
            data = xlrd.open_workbook('log/init_rules.xls')
            sheetname = data.sheet_names()[0]  # excle表格内sheet名
        except:
            workbook = xlwt.Workbook(encoding='ascii')
            worksheet = workbook.add_sheet('Sheet1')
            workbook.save('log/init_rules.xls')  # 保存文件

        data = xlrd.open_workbook('log/init_rules.xls')
        sheetname = data.sheet_names()[0]  # excle表格内sheet名
        print(sheetname)
        table = data.sheet_by_name('Sheet1')
        print(table)
        row = table.nrows  # 行数
        print(row)
        col = table.ncols  # 列数
        print(col)
        workbook = xlwt.Workbook(encoding='ascii')
        worksheet = workbook.add_sheet('Sheet1', cell_overwrite_ok=True)
        style = xlwt.XFStyle()  # 初始化样式
        font = xlwt.Font()  # 为样式创建字体
        font.name = 'Times New Roman'
        style.font = font  # 设定样式
        for i in range(col):
            n = 0
            cols = table.col_values(i)
            print(cols)
            for k in range(len(cols)):
                worksheet.write(n, i, cols[k])
            n += 1
        for j in range(6):
            worksheet.write(row, j, arr[(j + 1)][(len(arr[0]) - 1)])  # 不带样式的写入
        workbook.save('log/init_rules.xls')  # 保存文件

        for t in range(len(arr[0])):
            # print(arr[1:5, t])
            tipstr = 'tip = ' + ''.join(arr[1, t])
            tpstr = ' : ' + ''.join(arr[2, t])
            lipstr = '      lip = ' + ''.join(arr[3, t])
            lpstr = ' : ' + ''.join(arr[4, t])
            imstr = ''
            omstr = ''
            if arr[5, t] == None:
                imstr = '     input module = ' + ''.join(arr[5, t])
            if arr[6, t] == None:
                omstr = '     output module = ' + ''.join(arr[6, t])
            rulestr = tipstr + tpstr + lipstr + lpstr + imstr + omstr
            print(rulestr)
            show_list.append(rulestr)
            print(show_list)
        self.gui.rule_printout.delete(0, "end")
        for item in show_list:
            self.gui.rule_printout.insert(END, item)

    def init_add_to_list(self):
        # print(self.thread_num)
        args = self.parse_init_args()
        self.init_rule_list[0] = self.main_thread_now
        self.init_rule_list[1] = args.target_ip
        self.init_rule_list[2] = args.target_port
        self.init_rule_list[3] = args.listen_ip
        self.init_rule_list[4] = args.listen_port
        self.init_rule_list[5] = args.in_modules
        self.init_rule_list[6] = args.out_modules

        self.rule_list[0].append(self.main_thread_now)
        self.rule_list[1].append(args.target_ip)
        self.rule_list[2].append(args.target_port)
        self.rule_list[3].append(args.listen_ip)
        self.rule_list[4].append(args.listen_port)
        self.rule_list[5].append(args.in_modules)
        self.rule_list[6].append(args.out_modules)
        show_list = []

        tipstr = 'tip = ' + ''.join(self.init_rule_list[1])
        tpstr = ' : ' + ''.join(str(self.init_rule_list[2]))
        lipstr = '      lip = ' + ''.join(self.init_rule_list[3])
        lpstr = ' : ' + ''.join(str(self.init_rule_list[4]))
        imstr = ''
        omstr = ''
        if self.init_rule_list[5] == None:
            imstr = '     input module = ' + ''.join(str(self.init_rule_list[5]))
        if self.init_rule_list[6] == None:
            omstr = '     output module = ' + ''.join(str(self.init_rule_list[6]))
        rulestr = tipstr + tpstr + lipstr + lpstr + imstr + omstr
        print(rulestr)
        show_list.append(rulestr)
        print(show_list)
        for item in show_list:
            self.gui.rule_printout.insert(END, item)

    def is_valid_ip4(self, ip):
        # some rudimentary checks if ip is actually a valid IP
        octets = ip.split('.')
        if len(octets) != 4:
            return False
        return octets[0] != 0 and all(0 <= int(octet) <= 255 for octet in octets)

    def generate_module_list(self, modstring, incoming=False, verbose=False):
        # This method receives the comma-separated module list, imports the modules
        # and creates a Module instance for each module. A list of these instances
        # is then returned.
        # The incoming parameter is True when the modules belong to the incoming
        # chain (-im)
        # modstring looks like mod1,mod2:key=val,mod3:key=val:key2=val2,mod4 ...
        modlist = []
        namelist = modstring.split(',')
        for n in namelist:
            name, options = self.parse_module_options(n)
            try:
                __import__('proxymodules.' + name)
                modlist.append(sys.modules['proxymodules.' + name].Module(incoming, verbose, options))
            except ImportError:
                print('Module %s not found' % name)
                sys.exit(3)
        return modlist

    def parse_module_options(self, n):
        # n is of the form module_name:key1=val1:key2=val2 ...
        # this method returns the module name and a dict with the options
        n = n.split(':', 1)
        if len(n) == 1:
            # no module options present
            return n[0], None
        name = n[0]
        optionlist = n[1].split(':')
        options = {}
        for op in optionlist:
            try:
                k, v = op.split('=')
                options[k] = v
            except ValueError:
                print(op, ' is not valid!')
                sys.exit(23)
        return name, options

    def update_module_hosts(self, modules, source, destination):
        # set source and destination IP/port for each module
        # source and destination are ('IP', port) tuples
        # this can only be done once local and remote connections have been established
        if modules is not None:
            for m in modules:
                if hasattr(m, 'source'):
                    m.source = source
                if hasattr(m, 'destination'):
                    m.destination = destination

    def receive_from(self, s):
        # receive data from a socket until no more data is there
        b = b""
        while True:
            data = s.recv(4096)
            b += data
            if not data or len(data) < 4096:
                break
        return b

    def handle_data(self, data, modules, dont_chain, incoming, verbose):
        # execute each active module on the data. If dont_chain is set, feed the
        # output of one plugin to the following plugin. Not every plugin will
        # necessarily modify the data, though.
        # 使用模块处理接收到的data
        for m in modules:
            self.vprint(("> > > > in: " if incoming else "< < < < out: ") + m.name, verbose)
            if dont_chain:
                m.execute(data)
            else:
                data = m.execute(data)
        return data

    def is_client_hello(self, sock):
        firstbytes = sock.recv(128, socket.MSG_PEEK)
        return (len(firstbytes) >= 3 and
                firstbytes[0] == 0x16 and
                firstbytes[1:3] in [b"\x03\x00",
                                    b"\x03\x01",
                                    b"\x03\x02",
                                    b"\x03\x03",
                                    b"\x02\x00"])

    def start_proxy_thread(self, local_socket, args, in_modules, out_modules):
        # This method is executed in a thread. It will relay data between the local
        # host and the remote host, while letting modules work on the data before
        # passing it on.
        # 获取data-->d
        remote_socket = socks.socksocket()

        if args.proxy_ip:
            proxy_types = {'SOCKS5': socks.SOCKS5, 'SOCKS4': socks.SOCKS4, 'HTTP': socks.HTTP}
            remote_socket.set_proxy(proxy_types[args.proxy_type], args.proxy_ip, args.proxy_port)

        try:
            remote_socket.connect((args.target_ip, args.target_port))
            self.vprint('Connected to %s:%d' % remote_socket.getpeername(), args.verbose)
            self.log(args.logfile, 'Connected to %s:%d' % remote_socket.getpeername())
        except socket.error as serr:
            if serr.errno == errno.ECONNREFUSED:
                for s in [remote_socket, local_socket]:
                    s.close()
                print(f'{time.strftime("%Y%m%d-%H%M%S")}, {args.target_ip}:{args.target_port}- Connection refused')
                self.log(args.logfile,
                         f'{time.strftime("%Y%m%d-%H%M%S")}, {args.target_ip}:{args.target_port}- Connection refused')
                return None
            elif serr.errno == errno.ETIMEDOUT:
                for s in [remote_socket, local_socket]:
                    s.close()
                print(f'{time.strftime("%Y%m%d-%H%M%S")}, {args.target_ip}:{args.target_port}- Connection timed out')
                self.log(args.logfile,
                         f'{time.strftime("%Y%m%d-%H%M%S")}, {args.target_ip}:{args.target_port}- Connection timed out')
                return None
            else:
                for s in [remote_socket, local_socket]:
                    s.close()
                raise serr

        try:
            self.update_module_hosts(out_modules, local_socket.getpeername(), remote_socket.getpeername())
            self.update_module_hosts(in_modules, remote_socket.getpeername(), local_socket.getpeername())
        except socket.error as serr:
            if serr.errno == errno.ENOTCONN:
                # kind of a blind shot at fixing issue #15
                # I don't yet understand how this error can happen, but if it happens I'll just shut down the thread
                # the connection is not in a useful state anymore
                for s in [remote_socket, local_socket]:
                    s.close()
                return None
            else:
                for s in [remote_socket, local_socket]:
                    s.close()
                print(f"{time.strftime('%Y%m%d-%H%M%S')}: Socket exception in start_proxy_thread")
                raise serr

        # This loop ends when no more data is received on either the local or the
        # remote socket
        running = True
        while running:
            read_sockets, _, _ = select.select([remote_socket, local_socket], [], [])

            for sock in read_sockets:
                try:
                    peer = sock.getpeername()
                except socket.error as serr:
                    if serr.errno == errno.ENOTCONN:
                        # kind of a blind shot at fixing issue #15
                        # I don't yet understand how this error can happen, but if it happens I'll just shut down the thread
                        # the connection is not in a useful state anymore
                        for s in [remote_socket, local_socket]:
                            s.close()
                        running = False
                        break
                    else:
                        print(f"{time.strftime('%Y%m%d-%H%M%S')}: Socket exception in start_proxy_thread")
                        raise serr

                data = self.receive_from(sock)
                self.log(args.logfile, 'Received %d bytes' % len(data))

                if sock == local_socket:
                    if len(data):
                        # self.log(args.logfile, b'< < < out\n' + data)
                        if out_modules is not None:
                            data = self.handle_data(data, out_modules,
                                                    args.no_chain_modules,
                                                    False,  # incoming data?
                                                    args.verbose)
                        remote_socket.send(data.encode() if isinstance(data, str) else data)
                    else:
                        self.vprint("Connection from local client %s:%d closed" % peer, args.verbose)
                        self.log(args.logfile, "Connection from local client %s:%d closed" % peer)
                        remote_socket.close()
                        running = False
                        break
                elif sock == remote_socket:
                    if len(data):
                        # self.log(args.logfile, b'> > > in\n' + data)
                        if in_modules is not None:
                            data = self.handle_data(data, in_modules,
                                                    args.no_chain_modules,
                                                    True,  # incoming data?
                                                    args.verbose)
                        local_socket.send(data)
                    else:
                        self.vprint("Connection to remote server %s:%d closed" % peer, args.verbose)
                        self.log(args.logfile, "Connection to remote server %s:%d closed" % peer)
                        local_socket.close()
                        running = False
                        break

    def log(self, handle, message, message_only=False):
        # if message_only is True, only the message will be logged
        # otherwise the message will be prefixed with a timestamp and a line is
        # written after the message to make the log file easier to read
        if not isinstance(message, bytes):
            message = bytes(message, 'ascii')
        if handle is None:
            return
        if not message_only:
            logentry = bytes("%s %s\n" % (time.strftime('%Y%m%d-%H%M%S'), str(time.time())), 'ascii')
        else:
            logentry = b''
        logentry += message
        if not message_only:
            logentry += b'\n' + b'-' * 20 + b'\n'
        handle.write(logentry)

    def vprint(self, msg, is_verbose):
        # this will print msg, but only if is_verbose is True
        if is_verbose:
            print(msg)

    def run(self):  # 调用start_proxy_thread
        # args = self.args
        args = self.parse_args()
        # args = {'target_ip': '192.168.0.100',
        #         'target_port': 502,
        #         'listen_ip': '192.168.0.100',
        #         'listen_port': 1080,
        #         'proxy_ip': None,
        #         'proxy_port': 1080,
        #         'proxy_type': 'SOCKS5',
        #         'out_modules': 'modbus_parser',
        #         'in_modules': None,
        #         'verbose': False,
        #         'no_chain_modules': False,
        #         'logfile': None,
        #         'list': False,
        #         'help_modules': None,
        #         'use_ssl': False,
        #         'server_certificate': 'mitm.pem',
        #         'server_key': 'mitm.pem',
        #         'client_certificate': None,
        #         'client_key': None}
        print(__name__)
        print(args)
        if args.logfile is not None:
            try:
                args.logfile = open(args.logfile, 'ab', 0)  # unbuffered
            except Exception as ex:
                showwarning('警告', 'file cannot be open')
                print('Error opening logfile')
                print(ex)
                sys.exit(4)

        # if args.list:
        #     self.list_modules()
        #     sys.exit(0)

        # if args.help_modules is not None:
        #     print_module_help(args.help_modules)
        #     sys.exit(0)
        if args.listen_ip != '0.0.0.0' and not self.is_valid_ip4(args.listen_ip):
            try:
                ip = socket.gethostbyname(args.listen_ip)
            except socket.gaierror:
                ip = False
            if ip is False:
                showwarning('警告', 'ip not valid')
                print('%s is not a valid IP address or host name' % args.listen_ip)
                sys.exit(1)
            else:
                args.listen_ip = ip

        if not self.is_valid_ip4(args.target_ip):
            try:
                ip = socket.gethostbyname(args.target_ip)
            except socket.gaierror:
                ip = False
            if ip is False:
                showwarning('警告', 'ip not valid')
                print('%s is not a valid IP address or host name' % args.target_ip)
                sys.exit(2)
            else:
                args.target_ip = ip

        if args.in_modules is not None:
            in_modules = self.generate_module_list(args.in_modules, incoming=True, verbose=args.verbose)
        else:
            in_modules = None

        if args.out_modules is not None:
            out_modules = self.generate_module_list(args.out_modules, incoming=False, verbose=args.verbose)
            print(args.out_modules)
        else:
            out_modules = None

        # this is the socket we will listen on for incoming connections
        proxy_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        proxy_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)

        try:
            proxy_socket.bind((args.listen_ip, args.listen_port))
        except socket.error as e:
            showwarning('警告', 'listen address can not be bind')
            print(e.strerror)
            sys.exit(5)
        self.add_to_list()
        self.gui.tip_input.delete(1.0, END)
        self.gui.tp_input.delete(1.0, END)
        self.gui.lip_input.delete(1.0, END)
        self.gui.lp_input.delete(1.0, END)
        self.gui.in_module_input.delete(1.0, END)
        self.gui.out_module_input.delete(1.0, END)
        proxy_socket.listen(100)
        self.log(args.logfile, str(args))

        # endless loop until ctrl+c
        # try:
        while True:
            in_socket, in_addrinfo = proxy_socket.accept()
            self.vprint('Connection from %s:%d' % in_addrinfo, args.verbose)
            self.log(args.logfile, 'Connection from %s:%d' % in_addrinfo)
            proxy_thread = threading.Thread(target=self.start_proxy_thread,
                                            args=(in_socket, args, in_modules, out_modules))
            self.log(args.logfile, "Starting proxy thread " + proxy_thread.name)
            thread_now = threading.current_thread()
            print(thread_now)
            proxy_thread.start()

    def init_run(self):
        # args = self.args
        args = self.parse_init_args()
        # self.init_add_to_list()
        print(__name__)
        print(args)
        if args.logfile is not None:
            try:
                args.logfile = open(args.logfile, 'ab', 0)  # unbuffered
            except Exception as ex:
                showwarning('警告', 'file cannot be open')
                print('Error opening logfile')
                print(ex)
                sys.exit(4)

        if args.listen_ip != '0.0.0.0' and not self.is_valid_ip4(args.listen_ip):
            try:
                ip = socket.gethostbyname(args.listen_ip)
            except socket.gaierror:
                ip = False
            if ip is False:
                showwarning('警告', 'ip not valid')
                print('%s is not a valid IP address or host name' % args.listen_ip)
                sys.exit(1)
            else:
                args.listen_ip = ip

        if not self.is_valid_ip4(args.target_ip):
            try:
                ip = socket.gethostbyname(args.target_ip)
            except socket.gaierror:
                ip = False
            if ip is False:
                showwarning('警告', 'ip not valid')
                print('%s is not a valid IP address or host name' % args.target_ip)
                sys.exit(2)
            else:
                args.target_ip = ip

        if args.in_modules is not None:
            in_modules = self.generate_module_list(args.in_modules, incoming=True, verbose=args.verbose)
        else:
            in_modules = None

        if args.out_modules is not None:
            out_modules = self.generate_module_list(args.out_modules, incoming=False, verbose=args.verbose)
            print(args.out_modules)
        else:
            out_modules = None

        # this is the socket we will listen on for incoming connections
        proxy_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        proxy_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)

        try:
            proxy_socket.bind((args.listen_ip, args.listen_port))
        except socket.error as e:
            showwarning('警告', 'listen address can not be bind')
            print(e.strerror)
            sys.exit(5)
        proxy_socket.listen(100)
        self.log(args.logfile, str(args))

        # endless loop until ctrl+c
        # try:
        while True:
            in_socket, in_addrinfo = proxy_socket.accept()
            self.vprint('Connection from %s:%d' % in_addrinfo, args.verbose)
            self.log(args.logfile, 'Connection from %s:%d' % in_addrinfo)
            proxy_thread = threading.Thread(target=self.start_proxy_thread,
                                            args=(in_socket, args, in_modules, out_modules))
            self.log(args.logfile, "Starting proxy thread " + proxy_thread.name)
            thread_now = threading.current_thread()
            print(thread_now)
            proxy_thread.start()


def gui_start():
    init_window = Tk()  # 实例化出一个父窗口
    tool = Indus_Rule(init_window)
    # Main_window = MY_GUI(init_window)
    # 设置根窗口默认属性
    # Main_window.set_init_window()
    init_window.mainloop()  # 父窗口进入事件循环，可以理解为保持窗口运行，否则界面不展示


def main():
    window = Tk()
    window.title('欢迎进入工业防火墙V1.0')
    window.geometry('450x300')
    window["bg"] = "PaleGoldenrod"
    # 标签 用户名密码
    canvas = Canvas(window, height=300, width=500)
    imagefile = PhotoImage(file='login.png')
    image = canvas.create_image(220, 150, anchor='center', image=imagefile)
    canvas.pack(side='top')

    Label(window, text='用户名:', bg="white").place(x=100, y=150)
    Label(window, text='密码:', bg="white").place(x=100, y=190)
    # 用户名输入框
    var_usr_name = StringVar()
    entry_usr_name = Entry(window, textvariable=var_usr_name)
    entry_usr_name.place(x=160, y=150)
    # 密码输入框
    var_usr_pwd = StringVar()
    entry_usr_pwd = Entry(window, textvariable=var_usr_pwd, show='*')
    entry_usr_pwd.place(x=160, y=190)
    time.sleep(2)

    # 登录函数
    def usr_log_in():
        # 输入框获取用户名密码
        usr_name = var_usr_name.get()
        usr_pwd = var_usr_pwd.get()
        # 从本地字典获取用户信息，如果没有则新建本地数据库
        try:
            with open('usr_info.pickle', 'rb') as usr_file:
                usrs_info = pickle.load(usr_file)
        except FileNotFoundError:
            with open('usr_info.pickle', 'wb') as usr_file:
                usrs_info = {'admin': 'admin'}
                pickle.dump(usrs_info, usr_file)
        # 判断用户名和密码是否匹配
        # if usr_name =='admin':

        if usr_name in usrs_info:
            if usr_pwd == usrs_info[usr_name]:
                print(usr_name)
                print(usr_pwd)
                messagebox.showinfo(title='welcome',
                                    message='欢迎您：' + usr_name)
                window.destroy()
                gui_start()
            else:
                messagebox.showerror(message='密码错误')
        # 用户名密码不能为空
        elif usr_name == '' or usr_pwd == '':
            messagebox.showerror(message='用户名或密码为空')
        # 不在数据库中弹出是否注册的框
        else:
            is_signup = messagebox.askyesno('欢迎', '您还没有注册，是否现在注册')
            if is_signup:
                usr_sign_up()

    # 注册函数
    def usr_sign_up():
        # 确认注册时的相应函数
        def signtowcg():
            # 获取输入框内的内容
            nn = new_name.get()
            np = new_pwd.get()
            npf = new_pwd_confirm.get()
            rk = register_key.get()
            if rk == 'adminbuaa':
                # 本地加载已有用户信息,如果没有则已有用户信息为空
                try:
                    with open('usr_info.pickle', 'rb') as usr_file:
                        exist_usr_info = pickle.load(usr_file)
                except FileNotFoundError:
                    exist_usr_info = {}

                    # 检查用户名存在、密码为空、密码前后不一致
                if nn in exist_usr_info:
                    messagebox.showerror('错误', '用户名已存在')
                elif np == '' or nn == '':
                    messagebox.showerror('错误', '用户名或密码为空')
                elif np != npf:
                    messagebox.showerror('错误', '密码前后不一致')
                # 注册信息没有问题则将用户名密码写入数据库
                else:
                    exist_usr_info[nn] = np
                    with open('usr_info.pickle', 'wb') as usr_file:
                        pickle.dump(exist_usr_info, usr_file)
                    messagebox.showinfo('欢迎', '注册成功')
                    # 注册成功关闭注册框
                    window_sign_up.destroy()
            else:
                showwarning('warning', 'register key is incorrect')

        # 新建注册界面
        window_sign_up = Toplevel(window)
        window_sign_up.geometry('350x200')
        window_sign_up.title('注册')
        # 用户名变量及标签、输入框
        new_name = StringVar()
        Label(window_sign_up, text='用户名：').place(x=10, y=10)
        Entry(window_sign_up, textvariable=new_name).place(x=150, y=10)
        # 密码变量及标签、输入框
        new_pwd = StringVar()
        Label(window_sign_up, text='请输入密码：').place(x=10, y=50)
        Entry(window_sign_up, textvariable=new_pwd, show='*').place(x=150, y=50)
        # 重复密码变量及标签、输入框
        new_pwd_confirm = StringVar()
        Label(window_sign_up, text='请再次输入密码：').place(x=10, y=90)
        Entry(window_sign_up, textvariable=new_pwd_confirm, show='*').place(x=150, y=90)
        # register key
        register_key = StringVar()
        Label(window_sign_up, text='register key：').place(x=10, y=130)
        Entry(window_sign_up, textvariable=register_key, show='*').place(x=150, y=130)
        # 确认注册按钮及位置
        bt_confirm_sign_up = Button(window_sign_up, text='确认注册',
                                    command=signtowcg)
        bt_confirm_sign_up.place(x=150, y=170)

    # 退出的函数
    def usr_sign_quit():
        window.destroy()

    # 登录 注册按钮
    bt_login = Button(window, text='登录', command=usr_log_in)
    bt_login.place(x=140, y=230)
    bt_logup = Button(window, text='注册', command=usr_sign_up)
    bt_logup.place(x=210, y=230)
    bt_logquit = Button(window, text='退出', command=usr_sign_quit)
    bt_logquit.place(x=280, y=230)
    # 主循环
    window.mainloop()
    # gui_start()


def open_receive():
    try:
        print("kafka is ready for open")
        consumer = KafkaConsumer('new_train_topic',
                                 value_deserializer=lambda m: json.loads(m.decode('ascii')),
                                 bootstrap_servers='wuguo-buaa:9092', group_id='edge_group')
        reveive_model(consumer)
    except NoBrokersAvailable:
        print("please open kafka server first")


if __name__ == '__main__':
    t1 = threading.Thread(target=main, args=())
    t2 = threading.Thread(target=open_receive, args=())

    # 3. 守护线程 setDaemon()  语法：子线程名.setDaemon()
    # 主线程执行完，子线程也跟着结束，默认False，要True
    t1.setDaemon(True)
    t2.setDaemon(True)

    # 4. 开启子线程  start()
    t1.start()
    t2.start()
    t1.join()
    t2.join()

    # thread_main = threading.Thread(main())
    # kafka_thread = threading.Thread(open_receive())
    # thread_main.setDaemon(True)
    # kafka_thread.setDaemon(True)
    # kafka_thread.start()
    # thread_main.start()
