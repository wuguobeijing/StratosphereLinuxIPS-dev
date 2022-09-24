import json
import socket
import tqdm
import os
import gzip
import os
import tarfile

from kafka import KafkaConsumer


def received():
    # 设置服务器的ip和 port
    # 服务器信息
    sever_host = '192.168.0.100'
    sever_port = 2234
    # 传输数据间隔符
    SEPARATOR = '<SEPARATOR>'

    # 文件缓冲区
    Buffersize = 4096 * 10
    s = socket.socket()
    s.bind((sever_host, sever_port))

    # 设置监听数
    s.listen(128)
    print(f'服务器监听{sever_host}:{sever_port}')

    # 接收客户端连接
    client_socket, address = s.accept()
    # 打印客户端ip
    print(f'客户端{address}连接')

    # 接收客户端信息
    received = client_socket.recv(Buffersize).decode(errors='ignore')
    filename, file_size = received.split(SEPARATOR)
    # 获取文件的名字,大小
    filename = os.path.basename(filename)
    file_size = int(file_size)
    print(file_size)

    # 文件接收处理
    progress = tqdm.tqdm(range(file_size), f'接收{filename}', unit='B', unit_divisor=1024, unit_scale=True)

    with open("/home/wuguo-buaa/PycharmProjects/StratosphereLinuxIPS-dev/modules/flowmldetection/" + filename,
              'wb') as f:
        for _ in progress:
            # 从客户端读取数据
            bytes_read = client_socket.recv(Buffersize)
            # 如果没有数据传输内容
            if not bytes_read:
                break
            # 读取写入
            f.write(bytes_read)
            # 更新进度条
            progress.update(len(bytes_read))
    # 关闭资源
    client_socket.close()
    s.close()


def un_gz(file_name):
    """ungz zip file"""
    f_name = file_name.replace(".gz", "")
    # 获取文件的名称，去掉
    g_file = gzip.GzipFile(file_name)
    # 创建gzip对象
    open(f_name, "wb+").write(g_file.read())
    # gzip对象用read()打开后，写入open()建立的文件里。
    g_file.close()  # 关闭gzip对象


def un_tar(file_name):
    # untar zip file
    tar = tarfile.open(file_name)
    names = tar.getnames()
    if os.path.isdir(file_name.split('.tar')[0]):
        pass
    else:
        os.mkdir(file_name.split('.tar')[0])
    # 由于解压后是许多文件，预先建立同名文件夹
    for name in names:
        tar.extract(name, file_name.split('.tar')[0])
    tar.close()


def reveive_model(consumer):
    # consumer = KafkaConsumer('new_train_topic', value_deserializer=lambda m: json.loads(m.decode('ascii')),
    #                          bootstrap_servers='wuguo-buaa:9092', group_id='edge_group')
    for message in consumer:
        if message.value['type'] == 'new_model_k' and message.value['model_host'] == 'k':
            received()
            un_gz("/home/wuguo-buaa/PycharmProjects/StratosphereLinuxIPS-dev/modules/flowmldetection/model.tar.gz")
            un_tar("/home/wuguo-buaa/PycharmProjects/StratosphereLinuxIPS-dev/modules/flowmldetection/model.tar")
            os.remove("/home/wuguo-buaa/PycharmProjects/StratosphereLinuxIPS-dev/modules/flowmldetection/model.tar")


if __name__ == '__main__':
    consumer = KafkaConsumer('new_train_topic', value_deserializer=lambda m: json.loads(m.decode('ascii')),
                             bootstrap_servers='wuguo-buaa:9092', group_id='edge_group')
    reveive_model(consumer)
    consumer.close()
