import json

import pandas as pd
import sklearn
from sklearn.manifold import TSNE
from sklearn.decomposition import PCA
from sklearn.discriminant_analysis import LinearDiscriminantAnalysis
from sklearn.cluster import KMeans
import matplotlib.pyplot as plt
import numpy as np
from zat import log_to_dataframe
from zat import dataframe_to_matrix
# Local imports
import zat
import os
import sys
import argparse

# Local imports
from kafka import KafkaProducer, KafkaAdminClient, KafkaConsumer
from kafka.admin import NewTopic
from loguru import logger
from zat.log_to_dataframe import LogToDataFrame


def jitter(arr):
    stdev = .02*(max(arr)-min(arr))
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

# TODO
#   use for row in reader

def try_df2json(log_file):
    zeek_df = extract_normal_log(log_file)
    print(zeek_df)
    json_file = df2json(zeek_df)
    for item in json_file:
        print(type(json.dumps(item)), item)


def on_send_success(record_metadata):
    print(record_metadata.topic)
    print(record_metadata.offset)


def on_send_error(excp):
    logger.error('error' + str(excp))
    # handle exception


if __name__ == '__main__':
    # Create a Pandas dataframe from a Zeek log
    # try_df2json()
    logger.add('./output/kafka.log')  # 创建了一个文件名为runtime的log文件
    logger.debug("This's a log message in file")
    # for file in os.listdir('zeek_files'):
        # try_df2json('zeek_files/'+file)
        # zeek_df = extract_normal_log('zeek_files/' + file)
        # print(zeek_df.head(), file)
        # print(type(zeek_df['id.orig_p'][0]))
        # # Use the DataframeToMatrix class (handles categorical data!)
        # to_matrix = dataframe_to_matrix.DataFrameToMatrix()
        # try:
        #     zeek_matrix = to_matrix.fit_transform(zeek_df)
        #     print(zeek_matrix, zeek_matrix.shape)
        #     kmeans = KMeans(n_clusters=3).fit_predict(zeek_matrix)
        #     pca = PCA(n_components=2).fit_transform(zeek_matrix)
        #     print(kmeans,pca)
        #     break
        # except Exception as ex:
        #     print(ex)
        # Now we're ready for scikit-learn!

        # break
    admin_client = KafkaAdminClient(bootstrap_servers="wuguo-buaa:9092", client_id='edge_client')
    admin_client.list_topics()
    consumer = KafkaConsumer('Topic_list', value_deserializer=lambda m: json.loads(m.decode('ascii')),
                             bootstrap_servers='wuguo-buaa:9092', group_id='edge_group', auto_offset_reset='earliest',
                             enable_auto_commit=False, consumer_timeout_ms=5000)
    exist_topic = []
    for message in consumer:
        # print(message, message.topic, str(message.value))
        exist_topic.append(message.value["type"])
    consumer.close()
    print(exist_topic)
    producer = KafkaProducer(bootstrap_servers='wuguo-buaa:9092',
                             value_serializer=lambda m: json.dumps(m).encode('ascii'))
    for file in os.listdir('zeek_files'):
        topic = file.split('.',)[0]+'_topic'
        logger.info(topic)
        if topic not in exist_topic:
            topic_list = []
            json_content = {"type": topic}
            producer.send('Topic_list', json_content)
            topic_list.append(NewTopic(name=topic, num_partitions=1, replication_factor=1))
            admin_client.create_topics(new_topics=topic_list, validate_only=True)
        zeek_df = extract_normal_log('zeek_files/'+file)
        write_to_producer(producer, zeek_df, topic=topic)
        # f = open('zeek_files/'+file, 'w')
        # f.truncate()
        # f.close()
    producer.close()

    # # Example to populate a Pandas dataframe from a zeek log reader
    #
    # # Collect args from the command line
    # parser = argparse.ArgumentParser()
    # parser.add_argument('zeek_log', type=str, default='zeek_files/files.log', help='Specify a zeek JSON log to '
    #                                                                                'convert to DataFrame')
    # args, commands = parser.parse_known_args()
    #
    # # Check for unknown args
    # if commands:
    #     print('Unrecognized args: %s' % commands)
    #     sys.exit(1)
    #
    # # File may have a tilde in it
    # if args.zeek_log:
    #     args.zeek_log = os.path.expanduser(args.zeek_log)
    #
    #     # Create a Pandas dataframe from a Zeek log
    #     log_to_df = JSONLogToDataFrame()
    #     zeek_df = log_to_df.create_dataframe(args.zeek_log)
    #
    #     # Print out the head of the dataframe
    #     print(zeek_df.head())
    #
    #     # Print out the types of the columns
    #     print(zeek_df.dtypes)
    #
    #     # Print out size and memory usage
    #     print('DF Shape: {:s}'.format(str(zeek_df.shape)))
    #     print('DF Memory:')
    #     memory_usage = zeek_df.memory_usage(deep=True)
    #     total = memory_usage.sum()
    #     for item in memory_usage.items():
    #         print('\t {:s}: \t{:.2f} MB'.format(item[0], item[1]/1e6))
    #     print('DF Total: {:.2f} GB'.format(total/(1e9)))
