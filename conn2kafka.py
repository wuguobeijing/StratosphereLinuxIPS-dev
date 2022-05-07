import json
# Local imports
import os
import threading

import numpy as np
# Local imports
from kafka import KafkaProducer, KafkaAdminClient
from loguru import logger
from zat import log_to_dataframe


def jitter(arr):
    stdev = .02 * (max(arr) - min(arr))
    return arr + np.random.randn(len(arr)) * stdev


def extract_normal_log(zeek_log):
    log_to_df = log_to_dataframe.LogToDataFrame()
    zeek_df = log_to_df.create_dataframe(zeek_log)

    #
    # # Print out the head of the dataframe
    # logger.log('INFO', zeek_df.head())
    # # Print out the types of the columns
    # logger.log('INFO', zeek_df.dtypes)
    #
    # # Print out size and memory usage
    # logger.log('INFO', 'DF Shape: {:s}'.format(str(zeek_df.shape)))
    # logger.log('INFO', 'DF Memory:')
    # memory_usage = zeek_df.memory_usage(deep=True)
    # total = memory_usage.sum()
    # for item in memory_usage.items():
    #     logger.log('INFO', '\t {:s}: \t{:.2f} MB'.format(item[0], item[1] / 1e6))
    # logger.log('INFO', 'DF Total: {:.2f} GB'.format(total / (1e9)))
    return zeek_df


def df2json(df, orient='records'):
    df_json = df.to_json(orient=orient, force_ascii=False)
    return json.loads(df_json)


def write_to_producer(producer, zeek_dataframe, topic):
    msg_list = df2json(zeek_dataframe)
    for item in msg_list:
        producer.send(topic, item).add_callback(on_send_success).add_errback(on_send_error)
    producer.close(timeout=10000)


# ！TODO
#   use for row in reader

def try_df2json(log_file):
    zeek_df = extract_normal_log(log_file)
    print(zeek_df)
    json_file = df2json(zeek_df)
    for item in json_file:
        print(type(json.dumps(item)), item)


def on_send_success(record_metadata):
    # print(record_metadata.topic)
    # print(record_metadata.offset)
    pass

def on_send_error(excp):
    logger.error('error' + str(excp))
    # handle exception


def reset(path_log):
    i = 0
    path = path_log
    filelist = os.listdir(path)  # 该文件夹下所有文件（包括文件夹）
    for files in filelist:  # 遍历所有文件
        i = i + 1
        Olddir = os.path.join(path, files)  # 原来的文件路径
        if os.path.isdir(Olddir):
            continue
        filename = os.path.splitext(files)[0]
        filetype = os.path.splitext(files)[1]
        filePath = path + filename + filetype

        alter(filePath, "   ", "\t")


def alter(file, old_str, new_str):
    with open(file, "r", encoding="utf-8") as f1, open("%s.bak" % file, "w", encoding="utf-8") as f2:
        for line in f1:
            if old_str in line:
                line = line.replace(old_str, new_str)
            f2.write(line)
    os.remove(file)
    os.rename("%s.bak" % file, file)


class myThread(threading.Thread):
    def __init__(self, log_file, log_path):
        threading.Thread.__init__(self)
        self.log_file = log_file
        self.log_path = log_path

    def run(self):
        producer = KafkaProducer(bootstrap_servers='wuguo-buaa:9092',
                                 value_serializer=lambda m: json.dumps(m).encode('ascii'))
        logger.info(self.log_file)
        # reset(path+'/')
        topic = 'iot_topic'
        logger.info(topic)
        zeek_df = extract_normal_log(self.log_path + '/' + self.log_file)
        write_to_producer(producer, zeek_df, topic=topic)
        print(self.log_file)
        producer.close()

if __name__ == '__main__':
    # Create a Pandas dataframe from a Zeek log
    # try_df2json()
    logger.add('./output/conn_kafka.log')  # 创建了一个文件名为runtime的log文件
    logger.debug("This's a log message in file")
    admin_client = KafkaAdminClient(bootstrap_servers="wuguo-buaa:9092", client_id='edge_client')
    admin_client.list_topics()

    # file_path = '/media/wuguo-buaa/LENOVO_USB_HDD/iot-data/iot_23_datasets_small/opt/Malware-Project/BigDataset' \
    #             '/IoTScenarios/CTU-IoT-Malware-Capture-1-1/bro'
    list_file = []
    capture_34 = "/media/wuguo-buaa/LENOVO_USB_HDD/iot-data/iot_23_datasets_small/opt/Malware-Project/BigDataset/IoTScenarios/CTU-IoT-Malware-Capture-34-1/bro"
    list_file.append(capture_34)
    capture_43 = "/media/wuguo-buaa/LENOVO_USB_HDD/iot-data/iot_23_datasets_small/opt/Malware-Project/BigDataset/IoTScenarios/CTU-IoT-Malware-Capture-43-1/bro"
    list_file.append(capture_43)
    capture_44 = "/media/wuguo-buaa/LENOVO_USB_HDD/iot-data/iot_23_datasets_small/opt/Malware-Project/BigDataset/IoTScenarios/CTU-IoT-Malware-Capture-44-1/bro"
    list_file.append(capture_44)
    capture_49 = "/media/wuguo-buaa/LENOVO_USB_HDD/iot-data/iot_23_datasets_small/opt/Malware-Project/BigDataset/IoTScenarios/CTU-IoT-Malware-Capture-49-1/bro"
    list_file.append(capture_49)
    capture_52 = "/media/wuguo-buaa/LENOVO_USB_HDD/iot-data/iot_23_datasets_small/opt/Malware-Project/BigDataset/IoTScenarios/CTU-IoT-Malware-Capture-52-1/bro"
    list_file.append(capture_52)
    capture_20 = "/media/wuguo-buaa/LENOVO_USB_HDD/iot-data/iot_23_datasets_small/opt/Malware-Project/BigDataset/IoTScenarios/CTU-IoT-Malware-Capture-20-1/bro"
    list_file.append(capture_20)
    capture_21 = "/media/wuguo-buaa/LENOVO_USB_HDD/iot-data/iot_23_datasets_small/opt/Malware-Project/BigDataset/IoTScenarios/CTU-IoT-Malware-Capture-21-1/bro"
    list_file.append(capture_21)
    capture_42 = "/media/wuguo-buaa/LENOVO_USB_HDD/iot-data/iot_23_datasets_small/opt/Malware-Project/BigDataset/IoTScenarios/CTU-IoT-Malware-Capture-42-1/bro"
    list_file.append(capture_42)
    capture_60 = "/media/wuguo-buaa/LENOVO_USB_HDD/iot-data/iot_23_datasets_small/opt/Malware-Project/BigDataset/IoTScenarios/CTU-IoT-Malware-Capture-60-1/bro"
    list_file.append(capture_60)
    capture_17 = "/media/wuguo-buaa/LENOVO_USB_HDD/iot-data/iot_23_datasets_small/opt/Malware-Project/BigDataset/IoTScenarios/CTU-IoT-Malware-Capture-17-1/bro"
    list_file.append(capture_17)
    capture_36 = "/media/wuguo-buaa/LENOVO_USB_HDD/iot-data/iot_23_datasets_small/opt/Malware-Project/BigDataset/IoTScenarios/CTU-IoT-Malware-Capture-36-1/bro"
    list_file.append(capture_36)
    capture_33 = "/media/wuguo-buaa/LENOVO_USB_HDD/iot-data/iot_23_datasets_small/opt/Malware-Project/BigDataset/IoTScenarios/CTU-IoT-Malware-Capture-33-1/bro"
    list_file.append(capture_33)
    capture_8 = "/media/wuguo-buaa/LENOVO_USB_HDD/iot-data/iot_23_datasets_small/opt/Malware-Project/BigDataset/IoTScenarios/CTU-IoT-Malware-Capture-8-1/bro"
    list_file.append(capture_8)
    capture_35 = "/media/wuguo-buaa/LENOVO_USB_HDD/iot-data/iot_23_datasets_small/opt/Malware-Project/BigDataset/IoTScenarios/CTU-IoT-Malware-Capture-35-1/bro"
    list_file.append(capture_35)
    capture_48 = "/media/wuguo-buaa/LENOVO_USB_HDD/iot-data/iot_23_datasets_small/opt/Malware-Project/BigDataset/IoTScenarios/CTU-IoT-Malware-Capture-48-1/bro"
    list_file.append(capture_48)
    capture_39 = "/media/wuguo-buaa/LENOVO_USB_HDD/iot-data/iot_23_datasets_small/opt/Malware-Project/BigDataset/IoTScenarios/CTU-IoT-Malware-Capture-39-1/bro"
    list_file.append(capture_39)
    capture_7 = "/media/wuguo-buaa/LENOVO_USB_HDD/iot-data/iot_23_datasets_small/opt/Malware-Project/BigDataset/IoTScenarios/CTU-IoT-Malware-Capture-7-1/bro"
    list_file.append(capture_7)
    capture_9 = "/media/wuguo-buaa/LENOVO_USB_HDD/iot-data/iot_23_datasets_small/opt/Malware-Project/BigDataset/IoTScenarios/CTU-IoT-Malware-Capture-9-1/bro"
    list_file.append(capture_9)
    capture_3 = "/media/wuguo-buaa/LENOVO_USB_HDD/iot-data/iot_23_datasets_small/opt/Malware-Project/BigDataset/IoTScenarios/CTU-IoT-Malware-Capture-3-1/bro"
    list_file.append(capture_3)
    capture_1 = "/media/wuguo-buaa/LENOVO_USB_HDD/iot-data/iot_23_datasets_small/opt/Malware-Project/BigDataset/IoTScenarios/CTU-IoT-Malware-Capture-1-1/bro"
    list_file.append(capture_1)
    path = list_file[0].split('bro')[0] + 'split_files'

    #    logger.info(path)
    for file in os.listdir(path):
        thread = myThread(file, path)
        thread.start()
        thread.join()
        # time.sleep(10)

    # for file in os.listdir(path):
    #     reset(list_file + '/')
    #     topic = file.split('.log')[0] + '_iot_topic'
    #     logger.info(topic)
    #     zeek_df = extract_normal_log(file_path + '/' + file)
    #     write_to_producer(producer, zeek_df, topic=topic)

