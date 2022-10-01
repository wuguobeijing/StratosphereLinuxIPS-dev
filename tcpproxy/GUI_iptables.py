from tkinter import *
import subprocess
from tkinter.messagebox import askyesno, showwarning, showinfo
import iptc

auto_nat_color = 'lightblue'
deny_forward_color = 'lightblue'
deny_ping_color = 'lightblue'
deny_scan_color = 'lightblue'
deny_flooding_color = 'lightblue'
drop_fragments_color = 'lightblue'
drop_XMAS_color = 'lightblue'
drop_null_color = 'lightblue'
drop_multirst_color = 'lightblue'
drop_invalid_color = 'lightblue'


class MY_IP_GUI():
    def __init__(self, iptables_window):
        self.iptables_window = iptables_window

    def set_IP_window(self):
        self.iptables_window.title("Iptables Firewall")  # 窗口名
        self.iptables_window.geometry('640x420+470+260')
        self.iptables_window["bg"] = "PaleGoldenrod"
        self.frame_top = Frame(self.iptables_window, relief=RAISED, borderwidth=2)
        self.frame_top.pack(padx=2, pady=2, ipady=2, ipadx=2, side='top')
        self.iptables_button = Button(self.frame_top, text="帮助", bg="lightblue", width=15, height=2,
                                      command=self.open_help)
        self.iptables_button.pack(anchor=E, side='right')
        self.indus_firewall_Label = Label(self.frame_top, text="Iptables firewall", bg="lightyellow", width=123,
                                          height=2)
        self.indus_firewall_Label.pack(side='left', anchor=CENTER)
        self.frame_down = Frame(self.iptables_window, borderwidth=2)
        self.frame_down.pack(padx=2, pady=2, ipady=2, ipadx=2, side='top')
        self.add_suggest_button = Button(self.frame_down, text="添加推荐规则", bg="lightblue", width=50, height=2,
                                         command=self.add_suggest_rule)
        self.add_suggest_button.pack(anchor=N, side='top', pady=10)
        self.rule_input = Text(self.frame_down, width=50, height=2)
        self.rule_input.pack(side='top', anchor=N)
        self.add_self_button = Button(self.frame_down, text="添加自定义规则", bg="lightblue", width=50, height=2,
                                      command=self.add_self_rules)
        self.add_self_button.pack(anchor=N, side='top')
        self.flush_all_button = Button(self.frame_down, text="删除所有规则", bg="lightblue", width=50, height=2,
                                       command=self.flushall)
        self.flush_all_button.pack(anchor=N, side='bottom', pady=10)
        self.rule_manage_button = Button(self.frame_down, text="指定规则管理", bg="lightblue", width=50, height=2,
                                         command=self.rule_manipulate)
        self.rule_manage_button.pack(anchor=N, side='bottom')
        self.choose_table = LabelFrame(self.frame_down, text="选择表", width=50, height=2)
        self.choose_table.pack(anchor=N, side='top', pady=5)
        TABLES = [('Filter', 1), ('NAT', 2), ('Raw', 3), ('Mangle', 4)]
        self.table_num = IntVar()
        self.table_num.set(1)
        for TABLE, num in TABLES:
            b = Radiobutton(self.choose_table, text=TABLE, variable=self.table_num, value=num)
            b.pack(side='left', anchor=N, padx=10)

    def add_suggest_rule(self):
        suggest_rule_window = Toplevel(self.iptables_window)
        SUGGEST_RULE_window = SUGGEST_RULE_GUI(suggest_rule_window)
        SUGGEST_RULE_window.set_SUGGEST_RULE_window()
        suggest_rule_window.mainloop()

    def rule_manipulate(self):
        self.num = self.table_num.get()
        rule_window = Toplevel(self.iptables_window)
        RULE_window = MY_RULE_GUI(rule_window, self.num)
        RULE_window.set_RULE_window()
        RULE_window.show_table_rules()
        rule_window.mainloop()

    def open_help(self):
        help_window = Toplevel(self.iptables_window)
        HELP_window = MY_HELP_GUI(help_window)
        HELP_window.set_HELP_window()
        help_window.mainloop()

    def add_self_rules(self):
        rules_content = self.rule_input.get(1.0, END).strip().replace("\n", "")
        rules = rules_content.split()
        if len(rules) > 1:
            try:
                output = subprocess.check_output(rules)
                print('Have %d bytes in output' % len(output))
                print(output)
            except:
                showwarning('警告', '您输入的规则不正确')

        else:
            showwarning('警告', '输入的规则不能为空')

    def flushall(self):
        for chain in iptc.Table(iptc.Table.FILTER).chains:
            chain.flush()
        for chain in iptc.Table(iptc.Table.NAT).chains:
            chain.flush()
        for chain in iptc.Table(iptc.Table.RAW).chains:
            chain.flush()
        for chain in iptc.Table(iptc.Table.MANGLE).chains:
            chain.flush()
        rules_content1 = 'sudo iptables -F'.strip().replace("\n", "")
        rules_content2 = 'sudo iptables -X'.strip().replace("\n", "")
        rules1 = rules_content1.split()
        rules2 = rules_content2.split()
        subprocess.check_output(rules1)
        subprocess.check_output(rules2)
        showinfo('notice', '所有规则均删除')


class MY_HELP_GUI():
    def __init__(self, help_window):
        self.help_window = help_window

    def set_HELP_window(self):
        self.help_window.title("帮助文档")  # 窗口名
        self.help_window.geometry('640x420+670+360')
        self.frame_top = Frame(self.help_window, relief=RAISED, borderwidth=2)
        self.frame_top.pack(padx=2, pady=2, ipady=2, ipadx=2, side='top')
        self.text_Scroll = Scrollbar(self.frame_top)
        self.text_Scroll.pack(side='right', fill='y')
        self.help_input = Text(self.frame_top, yscrollcommand=self.text_Scroll.set, width=70, height=60, font=("newspaper", 12))
        self.help_input.pack(side='right', fill=BOTH)
        self.help_input.insert(END, '1.iptables中的“四表五链”及“堵通策略”A.“四表”是指，iptables的功能——filter, '
                                    'nat, mangle, raw.filter, \n控制数据包是否允许进出及转发（INPUT、OUTPUT、FORWARD）,'
                                    '\n可以控制的链路有input, forward, outputnat, 控制数据包中地址转换，\n可以控制的链路有prerouting,'
                                    ' input, output, postroutingmangle,修改数据包中的原数据，\n可以控制的链路有prerouting,'
                                    ' input, forward, output, postroutingraw,控制nat表中连接追踪机制的启用状况，'
                                    '\n可以控制的链路有prerouting, output注：在centos7中，还有security表，不过这里不作介绍'
                                    '常用命令：-A 追加规则-->iptables -A INPUT\n-D 删除规则-->iptables -D INPUT 1(编号)\n-R 修改规则-->iptables -R '
                                    'INPUT 1 -s 192.168.12.0 -j DROP 取代现行规则，顺序不变(1是位置)\n-I 插入规则-->'
                                    'iptables -I INPUT 1 --dport 80 -j ACCEPT 插入一条规则，原本位置上的规则将会往后移动一个顺位'
                                    '\n-L 查看规则-->iptables -L INPUT 列出规则链中的所有规则'
                                    '\n-N 新的规则-->iptables -N allowed 定义新的规则\n通用参数：'
                                    '\n-p 协议  例：iptables -A INPUT -p tcp'
                                    '\n-s源地址 例：iptables -A INPUT -s 192.168.1.1'
                                    '\n-d目的地址 例：iptables -A INPUT -d 192.168.12.1'
                                    '\n-sport源端口 例:iptables -A INPUT -p tcp --sport 22'
                                    '\n-dport目的端口 例:iptables -A INPUT -p tcp --dport 22'
                                    '\n-i指定入口网卡 例:iptables -A INPUT -i eth0'
                                    '\n-o指定出口网卡 例:iptables -A FORWARD -o eth0\n-j 指定要进行的处理动作\n常用的ACTION：\nDROP：丢弃'
                                    '\nREJECT：明示拒绝\nACCEPT：接受\nSNAT基于原地址的转换\nsource--指定原地址       '
                                    ' \n  比如我们现在要将所有192.168.10.0网段的IP在经过的时候全都转换成172.16.100.1这个假设出来的外网地址：'
                                    '\niptables -t nat -A POSTROUTING -s 192.168.10.0/24 -j SNAT --to-source 172.16.100.1(外网有效ip)'
                                    '\n这样，只要是来自本地网络的试图通过网卡访问网络的，都会被统统转换成172.16.100.1这个IP.'
                                    '\nMASQUERADE(动态伪装）--家用带宽获取的外网ip，就是用到了动态伪装'
                                    '\niptables -t nat -A POSTROUTING -s 192.168.10.0/24 -j MASQUERADE'
                                    '\nDNAT目标地址转换'
                                    '\ndestination-指定目标地址'
                                    '\niptables -t nat -A PREROUTING -d 192.168.10.18 -p tcp --dport 80 -j DNAT --to-destination 172.16.100.2'
                                    '\n10.18访问80端口转换到100.2上'
                                    '\nMASQUERADE：源地址伪装'
                                    '\nREDIRECT：重定向：主要用于实现端口重定向'
                                    '\nMARK：打防火墙标记的'
                                    '\nRETURN：返回 在自定义链执行完毕后使用返回，来返回原规则链。\n链    (chain)'
                                    '\n每个表都有自己的一组内置链，可以对链进行自定义，这样就可以建立一组规则，'
                                    '\nfilter表中的input、output和forward链'
                                    '\n匹配(match)'
                                    '\n每个iptables规则都包含一组匹配以及一个目标，iptables匹配指的是数据包必须匹配的条件，只有当'
                                    '\n数据包满足所有的匹配条件时，iptables才能根据由该规则的目标所指定的动作来处理该数据包'
                                    '\n匹配都在iptable的命令行中指定'
                                    '\nsource--匹配源ip地址或网络'
                                    '\ndestination (-d)--匹配目标ip地址或网络'
                                    '\nprotocol (-p)--匹配ip值'
                                    '\nin-interface (-i)--流入接口(例如，eth0)'
                                    '\nout-interface (-o)--流出接口'
                                    '\nstate--匹配一组连接状态'
                                    '\nstring--匹配应用层数据字节序列'
                                    '\ncomment--在内核内存中为一个规则关联多达256个字节的注释数据'
                                    '\n目标(target)'
                                    '\niptables支持一组目标，用于数据包匹配一条规则时触发一个动作'
                                    '\nACCEPT--允许数据包通过'
                                    '\nDROP--丢弃数据包，不对该数据包做进一步的处理，对接收栈而言，就好像该数据包从来没有被接收一样'
                                    '\nLOG--将数据包信息记录到syslog'
                                    '\nREJECT--丢弃数据包，同时发送适当的响应报文(针对TCP连接的TCP重要数据包或针对UDP数据包的ICMP端口不可达消息)\nRETURN--在调用链中继续处理数据包')


class MY_RULE_GUI():
    def __init__(self, rule_window, table_num):
        self.show_list = [[], [], [], []]
        self.rule_window = rule_window
        self.table_num_choose = table_num
        self.table_choose = None
        self.table_name = None

    def set_RULE_window(self):
        self.rule_window.title("rule management")  # 窗口名
        self.rule_window.geometry('1040x320+370+360')
        self.frame_top = Frame(self.rule_window, relief=RAISED, borderwidth=2)
        self.frame_top.pack(padx=2, pady=2, ipady=2, ipadx=2, side='top')
        self.rules_select = Frame(self.frame_top)
        self.rules_select.pack(padx=2, pady=2, ipady=2, ipadx=2, side='top')
        self.rules_Scroll = Scrollbar(self.rules_select)
        self.rules_Scroll.pack(side='right', fill='y')
        self.rule_printout = Listbox(self.rules_select, yscrollcommand=self.rules_Scroll.set, width=200, height=5)
        self.rule_printout.pack(side='right', fill=BOTH)
        self.rules_Scroll.config(command=self.rule_printout.yview)
        self.flushtable_button = Button(self.frame_top, text="删除表内规则", bg="lightblue", width=20, height=2,
                                        command=self.flushtable)
        self.flushtable_button.pack(anchor=W, side='left', padx=50)
        self.delete_rule_button = Button(self.frame_top, text="删除此条规则", bg="lightblue", width=20, height=2,
                                         command=self.delete_rule)
        self.delete_rule_button.pack(anchor=W, side='left', padx=50)

    def show_table_rules(self):
        if self.table_num_choose == 1:
            iptc.Table(iptc.Table.FILTER).refresh()
            self.table_choose = iptc.Table(iptc.Table.FILTER)
            self.table_name = 'filter'
        if self.table_num_choose == 2:
            iptc.Table(iptc.Table.NAT).refresh()
            self.table_choose = iptc.Table(iptc.Table.NAT)
            self.table_name = 'nat'
        if self.table_num_choose == 3:
            iptc.Table(iptc.Table.RAW).refresh()
            self.table_choose = iptc.Table(iptc.Table.RAW)
            self.table_name = 'raw'
        if self.table_num_choose == 4:
            iptc.Table(iptc.Table.MANGLE).refresh()
            self.table_choose = iptc.Table(iptc.Table.MANGLE)
            self.table_name = 'mangle'

        print(self.table_choose)
        print(type(self.table_choose))
        for chain in self.table_choose.chains:
            for rule in chain.rules:
                rule_print = ''
                rule_print += str(chain.name)
                rule_print += ("Rule" + "proto:" + str(rule.protocol) + "src:" + str(rule.src) + "dst:" + str(rule.dst)
                               + "in:" + str(rule.in_interface) + "out:" + str(rule.out_interface))
                rule_print += str(rule.target.name)
                self.show_list[0].append(rule_print)
                self.show_list[1].append(str(chain.name))
                self.show_list[2].append(chain)
                self.show_list[3].append(rule)
                print(self.show_list[0])
                print(self.show_list[1])
                print(self.show_list[2])
                print(self.show_list[3])
        for item in self.show_list[0]:
            self.rule_printout.insert(END, item)

    def flushtable(self):
        for chain in self.table_choose.chains:
            chain.flush()

        self.show_list[0].clear()
        self.show_list[1].clear()
        self.show_list[2].clear()
        self.show_list[3].clear()
        self.rule_printout.delete(0, 'end')
        showinfo('NOTICE', 'table is empty now')

    def delete_rule(self):
        rule_index = self.rule_printout.index(ACTIVE) + 1

        rules_content = ('sudo iptables -t %s -D %s %d' % (
        self.table_name, self.show_list[1][rule_index - 1], rule_index)).strip().replace("\n", "")
        rules = rules_content.split()
        output = subprocess.check_output(rules)
        print('Have %d bytes in output' % len(output))
        print(output)
        self.rule_printout.delete(ACTIVE)
        chain = self.show_list[2][rule_index - 1]
        chain.delete_rule(self.show_list[3][rule_index - 1])
        print(self.show_list)
        self.show_list[1].pop(rule_index - 1)
        self.show_list[0].pop(rule_index - 1)
        self.show_list[2].pop(rule_index - 1)
        self.show_list[3].pop(rule_index - 1)
        print(self.show_list)
        showinfo('NOTICE', '规则已删除')


class SUGGEST_RULE_GUI():
    def __init__(self, suggest_rule_window):
        self.suggest_rule_window = suggest_rule_window

    def set_SUGGEST_RULE_window(self):
        global auto_nat_color, deny_forward_color, deny_ping_color, deny_scan_color, deny_flooding_color, drop_fragments_color, \
            drop_XMAS_color, drop_null_color, drop_multirst_color, drop_invalid_color
        self.suggest_rule_window.title("Rules recommend")  # 窗口名
        self.suggest_rule_window.geometry('680x400+670+360')
        self.frame_top = Frame(self.suggest_rule_window, relief=RAISED, borderwidth=2)
        self.frame_top.pack(padx=2, pady=2, ipady=2, ipadx=2, side='top')

        self.frame_top = Frame(self.suggest_rule_window, relief=RAISED, borderwidth=2)
        self.frame_top.pack(padx=2, pady=2, ipady=2, ipadx=2, side='top')
        self.POSTROUTING_button = Button(self.frame_top, text="跨局域网转发", bg=auto_nat_color, width=20, height=2,
                                         command=self.post_masquerade)
        self.POSTROUTING_button.pack(anchor=W, side='left')
        self.deny_forward_button = Button(self.frame_top, text="禁止转发", bg=deny_forward_color, width=20, height=2,
                                          command=self.deny_forward)
        self.deny_forward_button.pack(anchor=W, side='left')
        self.deny_ping_button = Button(self.frame_top, text="禁止ping", bg=deny_ping_color, width=20, height=2,
                                       command=self.deny_ping)
        self.deny_ping_button.pack(anchor=W, side='left')
        self.exit_button = Button(self.frame_top, text="exit", bg="LightSalmon", width=20, height=2,
                                  command=self.exit)
        self.exit_button.pack(anchor=W, side='left')
        self.frame_2 = Frame(self.suggest_rule_window, relief=RAISED, borderwidth=2)
        self.frame_2.pack(padx=2, pady=2, ipady=2, ipadx=2, side='top')

        self.frame_2_1 = Frame(self.frame_2, relief=RAISED, borderwidth=1)
        self.frame_2_1.pack(padx=2, pady=2, ipady=2, ipadx=2, side='left')
        self.frame_funcions_input1_ip = Frame(self.frame_2_1, borderwidth=1)
        self.frame_funcions_input1_ip.pack(padx=2, pady=2, ipady=2, ipadx=2, side='top')
        self.dstip_Label = Label(self.frame_funcions_input1_ip, text="dst ip", bg="lightyellow", width=10, height=2)
        self.dstip_Label.pack(side='left', anchor=CENTER)
        self.dstip_input = Text(self.frame_funcions_input1_ip, width=18, height=2)
        self.dstip_input.pack(side='left', anchor=CENTER)
        self.sendip_Label = Label(self.frame_funcions_input1_ip, text="send to ip", bg="lightyellow", width=10,
                                  height=2)
        self.sendip_Label.pack(side='left', anchor=CENTER)
        self.sendip_input = Text(self.frame_funcions_input1_ip, width=18, height=2)
        self.sendip_input.pack(side='left', anchor=CENTER)

        self.frame_2_2 = Frame(self.frame_2_1, borderwidth=1)
        self.frame_2_2.pack(padx=2, pady=2, ipady=2, ipadx=2)
        self.dstp_Label = Label(self.frame_2_2, text="dst port", bg="lightyellow", width=10,
                                height=2)
        self.dstp_Label.pack(side='left', anchor=CENTER)
        self.dstp_input = Text(self.frame_2_2, width=18, height=2)
        self.dstp_input.pack(side='left', anchor=CENTER)
        self.sendp_Label = Label(self.frame_2_2, text="send to port", bg="lightyellow", width=10,
                                 height=2)
        self.sendp_Label.pack(side='left', anchor=CENTER)
        self.sendp_input = Text(self.frame_2_2, width=18, height=2)
        self.sendp_input.pack(side='left', anchor=CENTER)
        self.set_proxy_button = Button(self.frame_2, text="设置代理", bg="lightblue", width=15, height=3,
                                       command=self.set_proxy)
        self.set_proxy_button.pack(anchor=E, side='right')

        self.frame_3 = Frame(self.suggest_rule_window, relief=RAISED, borderwidth=2)
        self.frame_3.pack(padx=2, pady=2, ipady=2, ipadx=2, side='top')
        self.whitelist_input = Text(self.frame_3, width=18, height=2)
        self.whitelist_input.pack(side='left', anchor=CENTER)
        self.whitelist_button = Button(self.frame_3, text="添加白名单", bg="lightblue", width=15, height=1,
                                       command=self.add_whitelist)
        self.whitelist_button.pack(side='left', anchor=CENTER)
        self.blacklist_input = Text(self.frame_3, width=18, height=2)
        self.blacklist_input.pack(side='left', anchor=CENTER)
        self.blacklist_button = Button(self.frame_3, text="添加黑名单", bg="lightblue", width=15, height=1,
                                       command=self.add_blacklist)
        self.blacklist_button.pack(side='left', anchor=CENTER)
        self.frame_4 = Frame(self.suggest_rule_window, relief=RAISED, borderwidth=2)
        self.frame_4.pack(padx=2, pady=2, ipady=2, ipadx=2, side='top')
        self.deny_scan_button = Button(self.frame_4, text="防止端口扫描", bg=deny_scan_color, width=20, height=2,
                                       command=self.deny_scan)
        self.deny_scan_button.pack(side='left', anchor=CENTER)
        self.deny_flooding_button = Button(self.frame_4, text="防止泛洪攻击", bg=deny_flooding_color, width=20, height=2,
                                           command=self.deny_flooding)
        self.deny_flooding_button.pack(side='left', anchor=CENTER)
        self.frame_5 = Frame(self.suggest_rule_window, relief=RAISED, borderwidth=2)
        self.frame_5.pack(padx=2, pady=2, ipady=2, ipadx=2, side='top')
        self.deny_fragments_button = Button(self.frame_5, text="丢弃碎片数据包", bg=drop_fragments_color, width=14, height=1,
                                            command=self.drop_fragments)
        self.deny_fragments_button.pack(side='left', anchor=CENTER)
        self.deny_XMAS_button = Button(self.frame_5, text="丢弃异常XMAS", bg=drop_XMAS_color, width=14, height=1,
                                       command=self.drop_XMAS)
        self.deny_XMAS_button.pack(side='left', anchor=CENTER)

        self.deny_null_button = Button(self.frame_5, text="丢弃null数据包", bg=drop_null_color, width=14, height=1,
                                       command=self.drop_null)
        self.deny_null_button.pack(side='left', anchor=CENTER)
        self.deny_multi_rst_button = Button(self.frame_5, text="丢弃重复RST请求", bg=drop_multirst_color, width=14, height=1,
                                            command=self.deny_multirst)
        self.deny_multi_rst_button.pack(side='left', anchor=CENTER)
        self.deny_invalid_button = Button(self.frame_5, text="丢弃无效数据包", bg=drop_invalid_color, width=14, height=1,
                                          command=self.drop_invalid)
        self.deny_invalid_button.pack(side='left', anchor=CENTER)

    def exit(self):
        try:
            ans = askyesno(title='Warning', message='are you sure to exit?')
            if ans:
                self.suggest_rule_window.destroy()
            else:
                return
        except:
            print('can not close')

    def post_masquerade(self):
        global auto_nat_color
        rules_content1 = 'sudo iptables -t nat -A POSTROUTING -s 192.168.0.0/24 -d 192.168.1.0/24 -p tcp -j MASQUERADE'.strip().replace(
            "\n", "")
        rules_content2 = 'sudo iptables -t nat -A POSTROUTING -o eth0 -j MASQUERADE'.strip().replace("\n", "")
        rules1 = rules_content1.split()
        rules2 = rules_content2.split()
        subprocess.check_output(rules1)
        subprocess.check_output(rules2)
        self.POSTROUTING_button.configure(bg="LightSkyBlue")
        auto_nat_color = 'Wheat'

    def deny_forward(self):
        global deny_forward_color
        rules_content = 'sudo iptables -A FORWARD -j REJECT'.strip().replace("\n", "")
        rules = rules_content.split()
        output = subprocess.check_output(rules)
        print('Have %d bytes in output' % len(output))
        print(output)
        self.deny_forward_button.configure(bg="LightSkyBlue")
        deny_forward_color = 'Wheat'

    def deny_ping(self):
        global deny_ping_color
        rules_content = 'sudo iptables -A FORWARD -p icmp -m icmp --icmp-type echo-request -j DROP'.strip().replace(
            "\n", "")
        rules = rules_content.split()
        output = subprocess.check_output(rules)
        print('Have %d bytes in output' % len(output))
        print(output)
        self.deny_ping_button.configure(bg="LightSkyBlue")
        deny_ping_color = 'Wheat'

    def set_proxy(self):
        dstip = self.dstip_input.get(1.0, END).strip().replace("\n", "")
        dstp = self.dstp_input.get(1.0, END).strip().replace("\n", "")
        sendip = self.sendip_input.get(1.0, END).strip().replace("\n", "")
        sendp = self.sendp_input.get(1.0, END).strip().replace("\n", "")
        rules_content = ('sudo iptables -t nat -A PREROUTING -d %s -dport %s -p tcp -j DNAT --to-destination %s:%s' % (
        dstip, dstp, sendip, sendp)).strip().replace("\n", "")
        rules = rules_content.split()
        output = subprocess.check_output(rules)
        print('Have %d bytes in output' % len(output))
        print(output)
        showinfo('NOTICE', '代理已成功添加')

    def add_whitelist(self):
        whiteip = self.whitelist_input.get(1.0, END).strip().replace("\n", "")
        rules_content = ('sudo iptables -t nat -A PREROUTING -s %s -p all -j ACCEPT' % whiteip).strip().replace("\n",
                                                                                                                "")
        rules = rules_content.split()
        output = subprocess.check_output(rules)
        print('Have %d bytes in output' % len(output))
        print(output)
        showinfo('NOTICE', '白名单已成功添加')

    def add_blacklist(self):
        blackip = self.blacklist_input.get(1.0, END).strip().replace("\n", "")
        rules_content = ('sudo iptables -t filter -A FORWARD -s %s -p tcp -j DROP' % blackip).strip().replace("\n", "")
        rules = rules_content.split()
        output = subprocess.check_output(rules)
        print('Have %d bytes in output' % len(output))
        print(output)
        showinfo('NOTICE', '黑名单已成功添加')

    def deny_scan(self):
        global deny_scan_color
        rules_content = 'sudo iptables -A FORWARD -p tcp --tcp-flags SYN,ACK,FIN,RST RST -m limit --limit 1/s -j ACCEPT'.strip().replace(
            "\n", "")
        rules = rules_content.split()
        output = subprocess.check_output(rules)
        print('Have %d bytes in output' % len(output))
        print(output)
        self.deny_scan_button.configure(bg="LightSkyBlue")
        deny_scan_color = 'Wheat'

    def deny_flooding(self):
        global deny_flooding_color
        rules_content = 'sudo iptables -A FORWARD -p icmp --icmp-type echo-request -m limit --limit 1/s -j ACCEPT'.strip().replace(
            "\n", "")
        rules = rules_content.split()
        output = subprocess.check_output(rules)
        print('Have %d bytes in output' % len(output))
        print(output)
        self.deny_flooding_button.configure(bg="LightSkyBlue")
        deny_flooding_color = 'Wheat'

    def drop_fragments(self):
        global drop_fragments_color
        rules_content = 'sudo iptables -A FORWARD -p tcp ! --syn -m state --state NEW -j DROP'.strip().replace("\n", "")
        rules = rules_content.split()
        output = subprocess.check_output(rules)
        print('Have %d bytes in output' % len(output))
        print(output)
        self.deny_fragments_button.configure(bg="LightSkyBlue")
        drop_fragments_color = 'Wheat'

    def drop_XMAS(self):
        global drop_XMAS_color
        subprocess.check_output(
            'sudo iptables -A INPUT -p tcp --tcp-flags ALL ALL -j DROP'.strip().replace("\n", "").split())
        subprocess.check_output(
            'sudo iptables -A INPUT -p tcp --tcp-flags ALL FIN,PSH,URG -j DROP'.strip().replace("\n", "").split())
        subprocess.check_output(
            'sudo iptables -A INPUT -p tcp --tcp-flags ALL SYN,RST,ACK,FIN,URG -j DROP'.strip().replace("\n",
                                                                                                        "").split())
        self.deny_XMAS_button.configure(bg="LightSkyBlue")
        drop_XMAS_color = 'Wheat'

    def drop_null(self):
        global drop_null_color
        rules_content = 'sudo iptables -A OUTPUT -p tcp --tcp-flags ALL NONE -j DROP'.strip().replace("\n", "")
        rules = rules_content.split()
        output = subprocess.check_output(rules)
        print('Have %d bytes in output' % len(output))
        print(output)
        self.deny_null_button.configure(bg="LightSkyBlue")
        drop_null_color = 'Wheat'

    def drop_invalid(self):
        global drop_invalid_color
        subprocess.check_output(
            'sudo iptables -A INPUT -m state --state INVALID -j DROP'.strip().replace("\n", "").split())
        subprocess.check_output(
            'sudo iptables -A FORWARD -m state --state INVALID -j DROP'.strip().replace("\n", "").split())
        subprocess.check_output(
            'sudo iptables -A OUTPUT -m state --state INVALID -j DROP'.strip().replace("\n", "").split())
        self.deny_invalid_button.configure(bg="LightSkyBlue")
        drop_invalid_color = 'Wheat'

    def deny_multirst(self):
        global drop_multirst_color
        rules_content = 'sudo iptables -A INPUT -p tcp -m tcp --tcp-flags RST RST -m limit --limit 10/second --limit-burst 30 -j ACCEPT'.strip().replace(
            "\n", "")
        rules = rules_content.split()
        output = subprocess.check_output(rules)
        print('Have %d bytes in output' % len(output))
        print(output)
        self.deny_multi_rst_button.configure(bg="LightSkyBlue")
        drop_multirst_color = 'Wheat'
