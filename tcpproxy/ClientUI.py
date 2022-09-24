# import tkinter as Tkinter
# import tkinter.font as tkFont
# import socket
# import _thread as thread
# import time
# import sys
#
#
# class ClientUI():
#     title = 'Python在线聊天-客户端V1.0'
#     local = '192.168.0.100'
#     port = 8808
#     global clientSock;
#     flag = False
#
#     # 初始化类的相关属性，类似于Java的构造方法
#     def __init__(self):
#         self.root = Tkinter.Tk()
#         self.root.title(self.title)
#
#         # 窗口面板,用4个面板布局
#         self.frame = [Tkinter.Frame(), Tkinter.Frame(), Tkinter.Frame(), Tkinter.Frame()]
#
#         # 显示消息Text右边的滚动条
#         self.chatTextScrollBar = Tkinter.Scrollbar(self.frame[0])
#         self.chatTextScrollBar.pack(side=Tkinter.RIGHT, fill=Tkinter.Y)
#
#         # 显示消息Text，并绑定上面的滚动条
#         ft = tkFont.Font(family='Fixdsys', size=11)
#         self.chatText = Tkinter.Listbox(self.frame[0], width=70, height=18, font=ft)
#         self.chatText['yscrollcommand'] = self.chatTextScrollBar.set
#         self.chatText.pack(expand=1, fill=Tkinter.BOTH)
#         self.chatTextScrollBar['command'] = self.chatText.yview()
#         self.frame[0].pack(expand=1, fill=Tkinter.BOTH)
#
#         # 标签，分开消息显示Text和消息输入Text
#         label = Tkinter.Label(self.frame[1], height=2)
#         label.pack(fill=Tkinter.BOTH)
#         self.frame[1].pack(expand=1, fill=Tkinter.BOTH)
#
#         # 输入消息Text的滚动条
#         self.inputTextScrollBar = Tkinter.Scrollbar(self.frame[2])
#         self.inputTextScrollBar.pack(side=Tkinter.RIGHT, fill=Tkinter.Y)
#
#         # 输入消息Text，并与滚动条绑定
#         ft = tkFont.Font(family='Fixdsys', size=11)
#         self.inputText = Tkinter.Text(self.frame[2], width=70, height=8, font=ft)
#         self.inputText['yscrollcommand'] = self.inputTextScrollBar.set
#         self.inputText.pack(expand=1, fill=Tkinter.BOTH)
#         self.inputTextScrollBar['command'] = self.chatText.yview()
#         self.frame[2].pack(expand=1, fill=Tkinter.BOTH)
#
#         # 发送消息按钮
#         self.sendButton = Tkinter.Button(self.frame[3], text=' 发 送 ', width=10, command=self.sendMessage)
#         self.sendButton.pack(expand=1, side=Tkinter.BOTTOM and Tkinter.RIGHT, padx=15, pady=8)
#
#         # 关闭按钮
#         self.closeButton = Tkinter.Button(self.frame[3], text=' 关 闭 ', width=10, command=self.close)
#         self.closeButton.pack(expand=1, side=Tkinter.RIGHT, padx=15, pady=8)
#         self.frame[3].pack(expand=1, fill=Tkinter.BOTH)
#
#         # 接收消息
#
#     def receiveMessage(self):
#         try:
#             # 建立Socket连接
#             self.clientSock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
#             print(123)
#             self.clientSock.connect((self.local, self.port))
#             self.flag = True
#         except:
#             self.flag = False
#             self.chatText.insert(Tkinter.END, '您还未与服务器端建立连接，请检查服务器端是否已经启动')
#             return
#
#         self.buffer = 1024
#         self.clientSock.send('Y')
#         while True:
#             try:
#                 if self.flag == True:
#                     # 连接建立，接收服务器端消息
#                     self.serverMsg = self.clientSock.recv(self.buffer)
#                     if self.serverMsg == 'Y':
#                         self.chatText.insert(Tkinter.END, '客户端已经与服务器端建立连接......')
#                     elif self.serverMsg == 'N':
#                         self.chatText.insert(Tkinter.END, '客户端与服务器端建立连接失败......')
#                     elif not self.serverMsg:
#                         continue
#                     else:
#                         theTime = time.strftime("%Y-%m-%d %H:%M:%S", time.localtime())
#                         self.chatText.insert(Tkinter.END, '服务器端 ' + theTime + ' 说：\n')
#                         self.chatText.insert(Tkinter.END, '  ' + self.serverMsg)
#                 else:
#                     break
#             except EOFError as msg:
#                 raise msg
#                 self.clientSock.close()
#                 break
#
#                 # 发送消息
#
#     def sendMessage(self):
#         # 得到用户在Text中输入的消息
#         message = self.inputText.get('1.0', Tkinter.END)
#         # 格式化当前的时间
#         theTime = time.strftime("%Y-%m-%d %H:%M:%S", time.localtime())
#         self.chatText.insert(Tkinter.END, '客户端器 ' + theTime + ' 说：\n')
#         self.chatText.insert(Tkinter.END, '  ' + message + '\n')
#         if self.flag == True:
#             # 将消息发送到服务器端
#             self.clientSock.send(message);
#         else:
#             # Socket连接没有建立，提示用户
#             self.chatText.insert(Tkinter.END, '您还未与服务器端建立连接，服务器端无法收到您的消息\n')
#             # 清空用户在Text中输入的消息
#         self.inputText.delete(0.0, message.__len__() - 1.0)
#
#         # 关闭消息窗口并退出
#
#     def close(self):
#         sys.exit()
#
#         # 启动线程接收服务器端的消息
#
#     def startNewThread(self):
#         # 启动一个新线程来接收服务器端的消息
#         # thread.start_new_thread(function,args[,kwargs])函数原型，
#         # 其中function参数是将要调用的线程函数，args是传递给线程函数的参数，它必须是个元组类型，而kwargs是可选的参数
#         # receiveMessage函数不需要参数，就传一个空元组
#         thread.start_new_thread(self.receiveMessage, ())
#
#
# def main():
#     client = ClientUI()
#     client.startNewThread()
#     client.root.mainloop()
#
#
# if __name__ == '__main__':
#     main()

import threading
import socket

#接受信息函数
def rec(upd):
    while True:
        #接收消息，最多为1024字节
        data = upd.recvfrom(1024)
        #data为一个元组，info为信息内容，frm为发送者ip和端口号
        info, frm = data
        #设置编码格式
        info = info.decode("utf-8")
        print("收到来自"+str(frm)+'的消息：'+info)

#发送信息函数
def send(udp,dest_ip,dest_port):
    while True:
        data = input("请输入要发送的数据:")
        #发送消息
        udp.sendto(data.encode("utf-8"), (dest_ip, dest_port))


def main():
    #创建套接字
    udp = socket.socket(socket.AF_INET,socket.SOCK_DGRAM)
    #设置固定端口
    port_self = int(input("请输入本地端口号"))
    udp.bind(("",port_self))
    dest_ip = input("请输入对方ip：")
    dest_port = int(input("请输入端口号"))
    #创建接收进程
    t1 = threading.Thread(target=rec, args=(udp,))
    #创建发送进程
    t2 = threading.Thread(target=send, args=(udp, dest_ip, dest_port))
    #开始接收进程
    t1.start()
    #开始发送进程
    t2.start()


if __name__ == '__main__':
    main()