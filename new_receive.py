import json
import socket
import subprocess

import tqdm
import os
import gzip
import os
import tarfile

import yaml
from kafka import KafkaConsumer
from loguru import logger

from slips_NGFW import Slips


def received(content, port):
    # 设置服务器的ip和 port
    # 服务器信息
    sever_host = '192.168.0.100'
    sever_port = port
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
    if content == 'new_model':
        path_name = 'modules/flowmldetection/'
    elif content == 'new_conf':
        path_name = ''
    with open("/home/wuguo-buaa/PycharmProjects/StratosphereLinuxIPS-dev/" + path_name + filename,
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


def set_yaml(path, offset):
    data = {
        'kafka': {
            'prefix': offset
        }
    }
    with open(path, 'w', encoding='utf-8') as f:
        yaml.dump(data, f)


def read_yaml(path):
    with open(path, encoding='utf8') as yaml_file:
        # 解析yaml
        yamlfile = yaml.load(yaml_file, Loader=yaml.FullLoader)
        prefix = yamlfile["kafka"]['prefix']
        logger.log(1, prefix)
        return prefix


def reveive_model(consumer):
    old_prefix = read_yaml(path='/home/wuguo-buaa/PycharmProjects/StratosphereLinuxIPS-dev/config.yaml')
    print(old_prefix)
    for message in consumer:
        print(message)
        if old_prefix >= message.offset:
            logger.log(1, "offset incorrect")
            pass
        else:
            set_yaml(path='/home/wuguo-buaa/PycharmProjects/StratosphereLinuxIPS-dev/config.yaml',
                     offset=message.offset)
            if message.value['type'] == 'new_model_k' and message.value['model_host'] == 'k':
                received('new_model', 2234)
                un_gz("/home/wuguo-buaa/PycharmProjects/StratosphereLinuxIPS-dev/modules/flowmldetection/model.tar.gz")
                un_tar("/home/wuguo-buaa/PycharmProjects/StratosphereLinuxIPS-dev/modules/flowmldetection/model.tar")
                os.remove("/home/wuguo-buaa/PycharmProjects/StratosphereLinuxIPS-dev/modules/flowmldetection/model.tar")
            elif message.value['type'] == 'new_slips_order' and message.value['model_host'] == 'k':
                interface_path = message.value['order_param']['interface']
                slips_rule = ["/home/wuguo-buaa/anaconda3/envs/slips/bin/python",
                              "/home/wuguo-buaa/PycharmProjects/StratosphereLinuxIPS-dev/slips.py",
                              "-c", "/home/wuguo-buaa/PycharmProjects/StratosphereLinuxIPS-dev/slips.conf", "-i",
                              interface_path]
                print(slips_rule)
                p = subprocess.Popen(slips_rule, shell=True, stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
                output, err = p.communicate()
                print(output)
            elif message.value['type'] == 'new_slips_conf' and message.value['model_host'] == 'k':
                received('new_conf', 2235)


if __name__ == '__main__':
    consumer = KafkaConsumer('new_train_topic', value_deserializer=lambda m: json.loads(m.decode('ascii')),
                             bootstrap_servers='wuguo-buaa:9092', group_id='edge_group')
    reveive_model(consumer)
    consumer.close()
