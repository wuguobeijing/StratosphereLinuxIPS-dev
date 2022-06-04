# Must imports
import numpy
import yaml
from kafka import KafkaProducer

from slips_files.common.abstracts import Module
import multiprocessing
from slips_files.core.database import __database__
from slips_files.common.slips_utils import utils
import pandas as pd
import pyarrow.parquet as pq
import pyarrow as pa

from autogluon.tabular import TabularDataset, TabularPredictor

import configparser
import time
from sklearn.linear_model import SGDClassifier
from sklearn.preprocessing import StandardScaler
import pickle
import pandas as pd
import json
import datetime
import socket
import tqdm
import os


def send(filename):
    # 传输数据间隔符
    SEPARATOR = 'sep'
    # 服务器信息
    host = '192.168.0.133'
    port = 1234
    # 文件缓冲区
    Buffersize = 4096 * 10
    # 传输文件名字
    filename = filename
    # 文件大小
    file_size = os.path.getsize(filename)
    # 创建socket链接
    s = socket.socket()
    print(f'服务器连接中{host}:{port}')
    s.connect((host, port))
    print('与服务器连接成功')

    # 发送文件名字和文件大小，必须进行编码处理
    s.send(f'{filename}{SEPARATOR}{file_size}'.encode())

    # 文件传输
    progress = tqdm.tqdm(range(file_size), f'发送{filename}', unit='B', unit_divisor=1024)

    with open(filename, 'rb') as f:
        # 读取文件
        for _ in progress:
            bytes_read = f.read(Buffersize)
            if not bytes_read:
                break
            # sendall 确保网络忙碌的时候，数据仍然可以传输
            s.sendall(bytes_read)
            progress.update(len(bytes_read))
    # 关闭资源
    s.close()


def warn(*args, **kwargs):
    pass


import warnings
warnings.warn = warn


def set_yaml(path, proto_name, origstate_name, appproto_name):
    data = {
        'name_unique': {
            'proto_name': proto_name,
            'origstate_name': origstate_name,
            'appproto_name': appproto_name},
    }
    with open(path, 'w', encoding='utf-8') as f:
        yaml.dump(data, f)


def read_yaml(path):
    with open(path, encoding='utf8') as yaml_file:
        # 解析yaml
        yamlfile = yaml.load(yaml_file, Loader=yaml.FullLoader)
        proto_name = yamlfile["name_unique"]['proto_name']
        origstate_name = yamlfile["name_unique"]['origstate_name']
        appproto_name = yamlfile["name_unique"]['appproto_name']
        print(proto_name,origstate_name,appproto_name)
        return proto_name, origstate_name, appproto_name


class Module(Module, multiprocessing.Process):
    # Name: short name of the module. Do not use spaces
    name = 'flowmldetection'
    description = 'Train or test a Machine Learning model to detect malicious flows'
    authors = ['Guo Wu']

    def __init__(self, outputqueue, config):
        multiprocessing.Process.__init__(self)
        self.outputqueue = outputqueue
        # In case you need to read the slips.conf configuration file for your own configurations
        self.config = config
        # Start the DB
        __database__.start(self.config)
        # Subscribe to the channel
        self.c1 = __database__.subscribe('new_flow')
        self.fieldseparator = __database__.getFieldSeparator()
        # Set the output queue of our database instance
        __database__.setOutputQueue(self.outputqueue)
        # Read the configuration
        self.read_configuration()
        # Channel timeout
        self.timeout = 0
        # Minum amount of new lables needed to trigger the train
        self.minimum_lables_to_retrain = 650
        # To plot the scores of training
        # self.scores = []
        # The scaler trained during training and to use during testing
        self.scaler = StandardScaler()

    def read_configuration(self):
        """ Read the configuration file for what we need """
        try:
            self.mode = self.config.get('flowmldetection', 'mode')
        except (configparser.NoOptionError, configparser.NoSectionError, NameError):
            # There is a conf, but there is no option, or no section or no configuration file specified
            # Default to test
            self.mode = 'test'

    def print(self, text, verbose=1, debug=0):
        """
        Function to use to print text using the outputqueue of slips.
        Slips then decides how, when and where to print this text by taking all the processes into account
        :param verbose:
            0 - don't print
            1 - basic operation/proof of work
            2 - log I/O operations and filenames
            3 - log database/profile/timewindow changes
        :param debug:
            0 - don't print
            1 - print exceptions
            2 - unsupported and unhandled types (cases that may cause errors)
            3 - red warnings that needs examination - developer warnings
        :param text: text to print. Can include format like 'Test {}'.format('here')
        """

        levels = f'{verbose}{debug}'
        self.outputqueue.put(f"{levels}|{self.name}|{text}")

    def train(self):
        """
        Train a model based on the flows we receive and the labels
        """
        try:
            # Process the labels to have only Normal and Malware
            self.flows.label = self.flows.label.str.replace(r'(^.*ormal.*$)', 'Normal')
            self.flows.label = self.flows.label.str.replace(r'(^.*alware.*$)', 'Malware')
            self.flows.label = self.flows.label.str.replace(r'(^.*alicious.*$)', 'Malware')

            # Separate
            y_flow = self.flows['label']
            X_flow = self.flows.drop('label', axis=1)
            X_flow = X_flow.drop('module_labels', axis=1)

            # Normalize this batch of data so far. This can get progressivle slow

            self.scaler.fit(X_flow)
            X_flow = self.scaler.fit_transform(X_flow)
            self.print((X_flow), 1, 1)

            # Train
            try:
                self.clf.partial_fit(X_flow, y_flow)
                # See score so far in training
                score = self.clf.score(X_flow, y_flow)

                # To debug the training score
                # self.scores.append(score)

                self.print(f'Training Score: {score}', 1, 1)
                self.print(f'    Model Parameters: {self.clf.coef_}', 1, 1)
            except Exception as inst:
                self.print('Error while calling clf.train()')
                self.print(len(X_flow))
                self.print(y_flow)
                self.print(type(inst))
                self.print(inst)

            # Debug code to store a plot in a png of the scores
            # plt.plot(self.scores)
            # plt.savefig('train-scores.png')

            # Store the models on disk
            self.store_model()

        except Exception as inst:
            self.print('Error in train()')
            self.print(type(inst))
            self.print(inst)

    def train_self(self):
        """
        Train a model based on the flows we receive and the labels
        """
        filename = '/home/wuguo-buaa/PycharmProjects/StratosphereLinuxIPS-dev/output/data.parquet'
        try:
            send(filename)
        except Exception as insp:
            print(insp)

    def process_features(self, dataset):
        '''
        Discards some features of the dataset and can create new.
        Clean the dataset
        '''
        try:
            # Discard some type of flows that they dont have ports
            dataset = dataset[dataset.proto != 'arp']
            dataset = dataset[dataset.proto != 'ARP']
            dataset = dataset[dataset.proto != 'icmp']
            dataset = dataset[dataset.proto != 'igmp']
            dataset = dataset[dataset.proto != 'ipv6-icmp']
            # For now, discard the ports
            try:
                dataset = dataset.drop('appproto', axis=1)
            except ValueError:
                pass
            try:
                dataset = dataset.drop('daddr', axis=1)
            except ValueError:
                pass
            try:
                dataset = dataset.drop('saddr', axis=1)
            except ValueError:
                pass
            try:
                dataset = dataset.drop('ts', axis=1)
            except ValueError:
                pass
            try:
                dataset = dataset.drop('origstate', axis=1)
            except ValueError:
                pass
            try:
                dataset = dataset.drop('flow_type', axis=1)
            except ValueError:
                pass

            # Convert state to categorical
            dataset.state = dataset.state.str.replace(r'(^.*NotEstablished.*$)', '0')
            dataset.state = dataset.state.str.replace(r'(^.*Established.*$)', '1')
            dataset.state = dataset.state.astype('float64')

            # Convert proto to categorical. For now we only have few states, so we can hardcode...
            # We dont use the data to create categories because in testing mode
            # we dont see all the protocols
            # Also we dont store the Categorizer because the user can retrain
            # with its own data.
            dataset.proto = dataset.proto.str.lower()
            dataset.proto = dataset.proto.str.replace(r'(^.*tcp.*$)', '0')
            dataset.proto = dataset.proto.str.replace(r'(^.*udp.*$)', '1')
            dataset.proto = dataset.proto.str.replace(r'(^.*icmp.*$)', '2')
            dataset.proto = dataset.proto.str.replace(r'(^.*icmp-ipv6.*$)', '3')
            dataset.proto = dataset.proto.str.replace(r'(^.*arp.*$)', '4')
            dataset.proto = dataset.proto.astype('float64')
            try:
                # Convert dport to float
                dataset.dport = dataset.dport.astype('float')
            except ValueError:
                pass
            try:
                # Convert sport to float
                dataset.sport = dataset.sport.astype('float')
            except ValueError:
                pass
            try:
                # Convert Dur to float
                dataset.dur = dataset.dur.astype('float')
            except ValueError:
                pass
            try:
                # Convert TotPkts to float
                dataset.pkts = dataset.pkts.astype('float')
            except ValueError:
                pass
            try:
                # Convert SrcPkts to float
                dataset.spkts = dataset.spkts.astype('float')
            except ValueError:
                pass
            try:
                # Convert TotBytes to float
                dataset.allbytes = dataset.allbytes.astype('float')
            except ValueError:
                pass
            try:
                # Convert SrcBytes to float
                dataset.sbytes = dataset.sbytes.astype('float')
            except ValueError:
                pass
            return dataset
        except Exception as inst:
            # Stop the timer
            self.print('Error in process_features()')
            self.print(type(inst))
            self.print(inst)

    def process_features_self(self, dataset):
        try:
            # del dataset['Unnamed: 0']
            df = dataset.drop(columns=['ts', 'saddr', 'sport', 'daddr', 'dport', 'flow_type',
                                       'module_labels'])
            df = pd.get_dummies(df, columns=['proto'])
            df = pd.get_dummies(df, columns=['origstate'])
            df = pd.get_dummies(df, columns=['state'])
            df = pd.get_dummies(df, columns=['appproto'])
            df[['proto_unknown', 'origstate_unknown', 'appproto_unknown']] = 0
            df.astype(float)
            return df
        except Exception as inst:
            self.print('Error in process_features_self()')
            self.print(type(inst))
            self.print(inst)

    def process_features_detect_self(self, dataset, df_todetect):
        try:
            # del dataset['Unnamed: 0']
            # df = dataset.drop(columns=['ts', 'saddr', 'sport', 'daddr', 'dport', 'flow_type',
            #                            'module_labels'])
            df_todetect['dur'] = dataset['dur']
            df_todetect['pkts'] = dataset['pkts']
            df_todetect['allbytes'] = dataset['allbytes']
            df_todetect['spkts'] = dataset['spkts']
            df_todetect['sbytes'] = dataset['sbytes']
            if dataset['proto'].values in self.proto_name:
                setattr(df_todetect, str('proto_'+dataset['proto'].values), 1)
            else:
                df_todetect[str('proto_unknown')] = 1
            if dataset['origstate'].values in self.origstate_name:
                df_todetect[str('origstate_'+dataset['origstate'].values)] = 1
            else:
                df_todetect[str('origstate_unknown')] = 1
            if dataset['appproto'].values in self.appproto_name:
                df_todetect[str('appproto_'+dataset['appproto'].values)] = 1
            else:
                df_todetect[str('appproto_unknown')] = 1
            df_todetect[str('state_' + dataset['state'].values)] = 1
            df_todetect.astype(float)
            return df_todetect
        except Exception as inst:
            self.print('Error in process_features_detect_self()')
            self.print(type(inst))
            self.print(inst)

    def process_flows(self, method='self'):
        """
        Process all the flwos in the DB
        Store the pandas df in self.flows
        """
        try:
            # We get all the flows so far
            # because this retraining happens in batches
            flows = __database__.get_all_flows()

            # Check how many different labels are in the DB
            # We need both normal and malware
            labels = __database__.get_labels()
            if len(labels) == 1:
                # Only 1 label has flows
                # There are not enough different labels, so insert two flows
                # that are fake but representative of a normal and malware flow
                # they are only for the training process
                # At least 1 flow of each label is required
                # self.print(f'Amount of labeled flows: {labels}', 0, 1)
                flows.append(
                    {'ts': 1594417039.029793, 'dur': '1.9424750804901123', 'saddr': '10.7.10.101', 'sport': '49733',
                     'daddr': '40.70.224.145', 'dport': '443', 'proto': 'tcp', 'origstate': 'SRPA_SPA',
                     'state': 'Established', 'pkts': 84, 'allbytes': 42764, 'spkts': 37, 'sbytes': 25517,
                     'appproto': 'ssl', 'label': 'Malware', 'module_labels': {'flowalerts-long-connection': 'Malware'}})
                flows.append({'ts': 1382355032.706468, 'dur': '10.896695', 'saddr': '147.32.83.52', 'sport': '47956',
                              'daddr': '80.242.138.72', 'dport': '80', 'proto': 'tcp', 'origstate': 'SRPA_SPA',
                              'state': 'Established', 'pkts': 67, 'allbytes': 67696, 'spkts': 1, 'sbytes': 100,
                              'appproto': 'http', 'label': 'Normal',
                              'module_labels': {'flowalerts-long-connection': 'Normal'}})
                # If there are enough flows, we dont insert them anymore

            # Convert to pandas df
            df_flows = pd.DataFrame(flows)
            # Process features
            if method == 'self':
                proto_name = df_flows['proto'].unique().tolist()
                origstate_name = df_flows['origstate'].unique().tolist()
                appproto_name = df_flows['appproto'].unique().tolist()
                set_yaml(path='/home/wuguo-buaa/PycharmProjects/StratosphereLinuxIPS-dev/modules/flowmldetection'
                              '/config.yaml', proto_name=proto_name, origstate_name=origstate_name,
                         appproto_name=appproto_name)
                df_flows = self.process_features_self(df_flows)
                out_file = '/home/wuguo-buaa/PycharmProjects/StratosphereLinuxIPS-dev/output/data.parquet'
                table = pa.Table.from_pandas(df_flows)
                # Write direct to your parquet file
                pq.write_table(table, out_file)

                # write to this dir and auto name the parquet file
                df_flows.to_csv('/home/wuguo-buaa/PycharmProjects/StratosphereLinuxIPS-dev/output/data.csv', sep=',',
                                index=False)
                producer = KafkaProducer(bootstrap_servers='wuguo-buaa:9092',
                                         value_serializer=lambda m: json.dumps(m).encode('ascii'))
                json_content = {"type": 'new_parquet'}
                producer.send('parquet-topic', json_content).add_callback(self.on_send_success).add_errback(self.on_send_error)
            else:
                df_flows = self.process_features(df_flows)
            # Update the flow to the processed version
            self.flows = df_flows
        except Exception as inst:
            # Stop the timer
            self.print('Error in process_flows()')
            self.print(type(inst))
            self.print(inst)

    def on_send_success(self, record_metadata):
        print(record_metadata.topic)
        print(record_metadata.offset)
        time.sleep(1)
        self.train_self()

    def on_send_error(self, excp):
        print('error' + str(excp))

    # This horrible hack is only to stop sklearn from printing those warnings

    def process_flow(self, df_todetect=None):
        """
        Process one flow. Only used during detection in testing
        Store the pandas df in self.flow
        """
        if df_todetect is None:
            try:
                # Convert the flow to a pandas dataframe
                raw_flow = pd.DataFrame(self.flow_dict, index=[0])
                # Process features
                dflow = self.process_features(raw_flow)
                # Update the flow to the processed version
                self.flow = dflow
            except Exception as inst:
                # Stop the timer
                self.print('Error in process_flow()')
                self.print(type(inst))
                self.print(inst)
        else:
            try:
                # Convert the flow to a pandas dataframe
                raw_flow = pd.DataFrame(self.flow_dict, index=[0])
                # Process features
                dflow = self.process_features_detect_self(raw_flow, df_todetect)
                # Update the flow to the processed version
                self.flow = dflow
            except Exception as inst:
                # Stop the timer
                self.print('Error in process_flow()')
                self.print(type(inst))
                self.print(inst)

    def detect(self):
        """
        Detect this flow with the current model stored
        """
        try:
            # Store the real label if there is one
            y_flow = self.flow['label']
            # remove the real label column
            self.flow = self.flow.drop('label', axis=1)
            # remove the label predictions column of the other modules
            X_flow = self.flow.drop('module_labels', axis=1)
            # Scale the flow
            X_flow = self.scaler.transform(X_flow)
            pred = self.clf.predict(X_flow)
            self.print(X_flow)
            self.print(pred)
            return pred
        except Exception as inst:
            # Stop the timer
            self.print('Error in detect() X_flow:')
            self.print(X_flow)
            self.print(type(inst))
            self.print(inst)

    def detect_self(self):
        """
        Detect this flow with the current auto_gluon model stored
        """
        try:
            pred = self.clf.predict(self.flow)
            self.print(pred)
            return pred
        except Exception as inst:
            # Stop the timer
            self.print('Error in self_detect() X_flow:')
            self.print(self.flow)
            self.print(type(inst))
            self.print(inst)

    def store_model(self):
        """
        Store the trained model on disk
        """
        self.print(f'Storing the trained model and scaler on disk.', 0, 2)
        f = open('./modules/flowmldetection/model.bin', 'wb')
        data = pickle.dumps(self.clf)
        f.write(data)
        f.close()
        g = open('./modules/flowmldetection/scaler.bin', 'wb')
        data = pickle.dumps(self.scaler)
        g.write(data)
        g.close()

    def read_aotogl_model(self):
        """
        Read the trained model from disk
        """
        # try:
        self.print(f'Reading the trained model from disk.', 1, 2)
        model_path = "/home/wuguo-buaa/PycharmProjects/StratosphereLinuxIPS-dev/modules/flowmldetection/exp_ddos"
        self.clf = TabularPredictor.load(model_path)

    def read_model(self):
        """
        Read the trained model from disk
        """
        try:
            self.print(f'Reading the trained model from disk.', 1, 2)
            f = open('./modules/flowmldetection/model.bin', 'rb')
            self.clf = pickle.load(f)
            f.close()
            self.print(f'Reading the trained scaler from disk.', 1, 2)
            g = open('./modules/flowmldetection/scaler.bin', 'rb')
            self.scaler = pickle.load(g)
            g.close()
        except FileNotFoundError:
            # If there is no model, create one empty
            self.print('There was no model. Creating a new empty model.', 1, 2)
            self.clf = SGDClassifier(warm_start=True, loss='hinge', penalty="l1")
        except EOFError:
            self.print('Error reading model from disk. Creating a new empty model.', 1, 2)
            self.clf = SGDClassifier(warm_start=True, loss='hinge', penalty="l1")

    def set_evidence_malicious_flow(self, saddr, sport, daddr, dport, profileid, twid, uid):
        """
        Set the evidence that a flow was detected as malicious
        """
        confidence = 0.1
        threat_level = 'low'
        type_detection = 'flow'
        category = 'Anomaly.Traffic'
        detection_info = str(saddr) + ':' + str(sport) + '-' + str(daddr) + ':' + str(dport)
        type_evidence = 'MaliciousFlow'
        ip_identification = __database__.getIPIdentification(daddr)
        description = f'Malicious flow by ML. Src IP {saddr}:{sport} to {daddr}:{dport} {ip_identification}'
        timestamp = datetime.datetime.now().strftime("%d/%m/%Y-%H:%M:%S")
        __database__.setEvidence(type_evidence, type_detection, detection_info,
                                 threat_level, confidence, description,
                                 timestamp, category, profileid=profileid, twid=twid)

    def shutdown_gracefully(self):
        # Confirm that the module is done processing
        self.store_model()
        __database__.publish('finished_modules', self.name)

    def original_model(self):
        # Load the model first
        # Load the model
        self.read_model()

        while True:
            try:
                message = self.c1.get_message(timeout=self.timeout)

                if message and message['data'] == 'stop_process':
                    self.shutdown_gracefully()
                    return True

                if utils.is_msg_intended_for(message, 'new_flow'):
                    data = message['data']
                    # Convert from json to dict
                    data = json.loads(data)
                    profileid = data['profileid']
                    twid = data['twid']
                    # Get flow that is now in json format
                    flow = data['flow']
                    # Convert flow to a dict
                    flow = json.loads(flow)
                    # Convert the common fields to something that can
                    # be interpreted
                    # Get the uid which is the key
                    uid = next(iter(flow))
                    self.flow_dict = json.loads(flow[uid])

                    if self.mode == 'train':
                        # We are training

                        # Is the amount in the DB of labels enough to retrain?
                        # Use labeled flows
                        labels = __database__.get_labels()
                        sum_labeled_flows = sum([i[1] for i in labels])
                        if sum_labeled_flows >= self.minimum_lables_to_retrain and sum_labeled_flows % self.minimum_lables_to_retrain == 1:
                            # We get here every 'self.minimum_lables_to_retrain' amount of labels
                            # So for example we retrain every 100 labels and only when we have at least 100 labels
                            self.print(
                                f'Training the model with the last group of flows and labels. Total flows: {sum_labeled_flows}.')
                            # Process all flows in the DB and make them ready for pandas
                            self.process_flows(method='original')
                            # Train an algorithm
                            self.train()
                    elif self.mode == 'test':
                        # We are testing, which means using the model to detect
                        self.process_flow()

                        # After processing the flow, it may happen that we delete icmp/arp/etc
                        # so the dataframe can be empty
                        if not self.flow.empty:
                            # Predict
                            pred = self.detect()
                            label = self.flow_dict["label"]

                            # Report
                            if label and label != 'unknown' and label != pred[0]:
                                # If the user specified a label in test mode, and the label
                                # is diff from the prediction, print in debug mode
                                self.print(
                                    f'Report Prediction {pred[0]} for label {label} flow {self.flow_dict["saddr"]}:{self.flow_dict["sport"]} -> {self.flow_dict["daddr"]}:{self.flow_dict["dport"]}/{self.flow_dict["proto"]}',
                                    0, 3)
                            if pred[0] == 'Malware':
                                # Generate an alert
                                self.set_evidence_malicious_flow(self.flow_dict['saddr'], self.flow_dict['sport'],
                                                                 self.flow_dict['daddr'], self.flow_dict['dport'],
                                                                 profileid, twid, uid)
                                self.print(
                                    f'Prediction {pred[0]} for label {label} flow {self.flow_dict["saddr"]}:{self.flow_dict["sport"]} -> {self.flow_dict["daddr"]}:{self.flow_dict["dport"]}/{self.flow_dict["proto"]}',
                                    0, 2)

            except KeyboardInterrupt:
                self.shutdown_gracefully()
                return True
            except Exception as inst:
                # Stop the timer
                self.print('Error in run()')
                self.print(type(inst), 1, 1)
                self.print(inst, 1, 1)
                return True

    def self_defined_model(self):
        # Load the model first
        self.read_aotogl_model()

        while True:
            try:
                message = self.c1.get_message(timeout=self.timeout)

                if message and message['data'] == 'stop_process':
                    self.shutdown_gracefully()
                    return True

                if utils.is_msg_intended_for(message, 'new_flow'):
                    data = message['data']
                    # Convert from json to dict
                    data = json.loads(data)
                    profileid = data['profileid']
                    twid = data['twid']
                    # Get flow that is now in json format
                    flow = data['flow']
                    # Convert flow to a dict
                    flow = json.loads(flow)
                    # Convert the common fields to something that can
                    # be interpreted
                    # Get the uid which is the key
                    uid = next(iter(flow))
                    self.flow_dict = json.loads(flow[uid])

                    if self.mode == 'train':
                        # We are training

                        # Is the amount in the DB of labels enough to retrain?
                        # Use labeled flows
                        labels = __database__.get_labels()
                        sum_labeled_flows = sum([i[1] for i in labels])
                        if sum_labeled_flows >= self.minimum_lables_to_retrain and sum_labeled_flows % self.minimum_lables_to_retrain == 1:
                            # We get here every 'self.minimum_lables_to_retrain' amount of labels
                            # So for example we retrain every 100 labels and only when we have at least 100 labels
                            self.print(
                                f'Training the model with the last group of flows and labels. Total flows: {sum_labeled_flows}.')
                            # Process all flows in the DB and make them ready for pandas
                            self.process_flows()
                            # Train an algorithm
                            # self.train_self()
                    elif self.mode == 'test':
                        # We are testing, which means using the model to detect
                        self.proto_name, self.origstate_name, self.appproto_name = read_yaml(
                            path='/home/wuguo-buaa/PycharmProjects/StratosphereLinuxIPS-dev/modules/flowmldetection/config.yaml')

                        x_labels_basic = ['dur', 'pkts', 'allbytes', 'spkts', 'sbytes']
                        proto_labels, origstate_labels, appproto_labels = [], [], []
                        for item in self.proto_name:
                            proto_labels.append('proto_' + item)
                        for item in self.origstate_name:
                            origstate_labels.append('origstate_' + item)
                        for item in self.appproto_name:
                            appproto_labels.append('appproto_' + item)
                        df_xlables = x_labels_basic + proto_labels + origstate_labels + appproto_labels + [
                            'state_Established', 'state_NotEstablished', 'proto_unknown', 'origstate_unknown',
                            'appproto_unknown']
                        arr = numpy.zeros((1, int(len(df_xlables))))
                        df_todetect = pd.DataFrame(arr, columns=df_xlables)
                        self.process_flow(df_todetect)

                        # After processing the flow, it may happen that we delete icmp/arp/etc
                        # so the dataframe can be empty
                        if not self.flow.empty:
                            # Predict
                            pred = self.detect_self()
                            label = self.flow_dict["label"]

                            # Report
                            if label and label != 'unknown' and label != pred[0]:
                                # If the user specified a label in test mode, and the label
                                # is diff from the prediction, print in debug mode
                                self.print(
                                    f'Report Prediction {pred[0]} for label {label} flow {self.flow_dict["saddr"]}:{self.flow_dict["sport"]} -> {self.flow_dict["daddr"]}:{self.flow_dict["dport"]}/{self.flow_dict["proto"]}',
                                    0, 3)
                            if pred[0] == 'Malware':
                                # Generate an alert
                                self.set_evidence_malicious_flow(self.flow_dict['saddr'], self.flow_dict['sport'],
                                                                 self.flow_dict['daddr'], self.flow_dict['dport'],
                                                                 profileid, twid, uid)
                                self.print(
                                    f'Prediction {pred[0]} for label {label} flow {self.flow_dict["saddr"]}:{self.flow_dict["sport"]} -> {self.flow_dict["daddr"]}:{self.flow_dict["dport"]}/{self.flow_dict["proto"]}',
                                    0, 2)

            except KeyboardInterrupt:
                self.shutdown_gracefully()
                return True
            except Exception as inst:
                # Stop the timer
                self.print('Error in run()')
                self.print(type(inst), 1, 1)
                self.print(inst, 1, 1)
                return True

    def run(self):
        self.self_defined_model()
        # self.original_model()
# # Must imports
# from slips_files.common.abstracts import Module
# import multiprocessing
# from slips_files.core.database import __database__
# from slips_files.common.slips_utils import utils
# import sys
# from loguru import logger
# import configparser
# import time
# from sklearn.linear_model import SGDClassifier
# from sklearn.preprocessing import StandardScaler
# import pickle
# import pandas as pd
# import json
# import platform
# import datetime
# # Only for debbuging
# #from matplotlib import pyplot as plt
#
#
# # This horrible hack is only to stop sklearn from printing those warnings
# def warn(*args, **kwargs):
#     pass
#
# import warnings
# warnings.warn = warn
#
# class Module(Module, multiprocessing.Process):
#     # Name: short name of the module. Do not use spaces
#     name = 'flowmldetection'
#     description = 'Train or test a Machine Learning model to detect malicious flows'
#     authors = ['Sebastian Garcia']
#
#     def __init__(self, outputqueue, config):
#         multiprocessing.Process.__init__(self)
#         self.outputqueue = outputqueue
#         # In case you need to read the slips.conf configuration file for your own configurations
#         self.config = config
#         # Start the DB
#         __database__.start(self.config)
#         # Subscribe to the channel
#         self.c1 = __database__.subscribe('new_flow')
#         self.fieldseparator = __database__.getFieldSeparator()
#         # Set the output queue of our database instance
#         __database__.setOutputQueue(self.outputqueue)
#         # Read the configuration
#         self.read_configuration()
#         # Channel timeout
#         self.timeout = 0.0000001
#         # Minum amount of new lables needed to trigger the train
#         self.minimum_lables_to_retrain = 50
#         # To plot the scores of training
#         #self.scores = []
#         # The scaler trained during training and to use during testing
#         self.print(f'Reading the trained scaler from disk.', 0, 2)
#         g = open('/home/wuguo-buaa/PycharmProjects/StratosphereLinuxIPS-dev/modules/flowmldetection/scaler.bin', 'rb')
#         self.scaler = pickle.load(g)
#         g.close()
#         # self.scaler = StandardScaler()
#
#
#     def read_configuration(self):
#         """ Read the configuration file for what we need """
#         try:
#             self.mode = self.config.get('flowmldetection', 'mode')
#         except (configparser.NoOptionError, configparser.NoSectionError, NameError):
#             # There is a conf, but there is no option, or no section or no configuration file specified
#             # Default to test
#             self.mode = 'test'
#
#     def print(self, text, verbose=1, debug=0):
#         """
#         Function to use to print text using the outputqueue of slips.
#         Slips then decides how, when and where to print this text by taking all the processes into account
#         :param verbose:
#             0 - don't print
#             1 - basic operation/proof of work
#             2 - log I/O operations and filenames
#             3 - log database/profile/timewindow changes
#         :param debug:
#             0 - don't print
#             1 - print exceptions
#             2 - unsupported and unhandled types (cases that may cause errors)
#             3 - red warnings that needs examination - developer warnings
#         :param text: text to print. Can include format like 'Test {}'.format('here')
#         """
#
#         levels = f'{verbose}{debug}'
#         self.outputqueue.put(f"{levels}|{self.name}|{text}")
#
#     def train(self):
#         """
#         Train a model based on the flows we receive and the labels
#         """
#         try:
#             # Process the labels to have only Normal and Malware
#             self.flows.label = self.flows.label.str.replace(r'(^.*ormal.*$)', 'Normal')
#             self.flows.label = self.flows.label.str.replace(r'(^.*alware.*$)', 'Malware')
#             self.flows.label = self.flows.label.str.replace(r'(^.*alicious.*$)', 'Malware')
#
#             # Separate
#             y_flow = self.flows['label']
#             X_flow = self.flows.drop('label', axis=1)
#             X_flow = X_flow.drop('module_labels', axis=1)
#
#             # Normalize this batch of data so far. This can get progressivle slow
#             self.scaler.fit(X_flow)
#             X_flow = self.scaler.fit_transform(X_flow)
#
#             # Train
#             try:
#                 self.clf.partial_fit(X_flow, y_flow, classes=['Malware', 'Normal'])
#             except Exception as inst:
#                 self.print('Error while calling clf.train()')
#                 self.print(type(inst))
#                 self.print(inst)
#             # self.clf.fit(X_flow, y_flow)
#             # See score so far in training
#             score = self.clf.score(X_flow, y_flow)
#
#             # To debug the training score
#             #self.scores.append(score)
#
#             self.print(f'	Training Score: {score}', 1, 1)
#
#             # Debug code to store a plot in a png of the scores
#             #plt.plot(self.scores)
#             #plt.savefig('train-scores.png')
#
#             # Store the models on disk
#             self.store_model()
#
#         except Exception as inst:
#             self.print('Error in train()')
#             self.print(type(inst))
#             self.print(inst)
#
#     def process_features(self, dataset):
#         '''
#         Discards some features of the dataset and can create new.
#         Clean the dataset
#         '''
#         try:
#             # Discard some type of flows that they dont have ports
#             dataset = dataset[dataset.proto != 'arp']
#             dataset = dataset[dataset.proto != 'ARP']
#             dataset = dataset[dataset.proto != 'icmp']
#             dataset = dataset[dataset.proto != 'igmp']
#             dataset = dataset[dataset.proto != 'ipv6-icmp']
#             # For now, discard the ports
#             try:
#                 dataset = dataset.drop('appproto', axis=1)
#             except ValueError:
#                 pass
#             try:
#                 dataset = dataset.drop('daddr', axis=1)
#             except ValueError:
#                 pass
#             try:
#                 dataset = dataset.drop('saddr', axis=1)
#             except ValueError:
#                 pass
#             try:
#                 dataset = dataset.drop('ts', axis=1)
#             except ValueError:
#                 pass
#             try:
#                 dataset = dataset.drop('origstate', axis=1)
#             except ValueError:
#                 pass
#             try:
#                 dataset = dataset.drop('flow_type', axis=1)
#             except ValueError:
#                 pass
#
#             # Convert state to categorical
#             dataset.state = dataset.state.str.replace(r'(^.*NotEstablished.*$)', '0')
#             dataset.state = dataset.state.str.replace(r'(^.*Established.*$)', '1')
#             dataset.state = dataset.state.astype('float64')
#
#             # Convert proto to categorical. For now we only have few states, so we can hardcode...
#             # We dont use the data to create categories because in testing mode
#             # we dont see all the protocols
#             # Also we dont store the Categorizer because the user can retrain
#             # with its own data.
#             dataset.proto = dataset.proto.str.lower()
#             dataset.proto = dataset.proto.str.replace(r'(^.*tcp.*$)', '0')
#             dataset.proto = dataset.proto.str.replace(r'(^.*udp.*$)', '1')
#             dataset.proto = dataset.proto.str.replace(r'(^.*icmp.*$)', '2')
#             dataset.proto = dataset.proto.str.replace(r'(^.*icmp-ipv6.*$)', '3')
#             dataset.proto = dataset.proto.str.replace(r'(^.*arp.*$)', '4')
#             dataset.proto = dataset.proto.astype('float64')
#             try:
#                 # Convert dport to float
#                 dataset.dport = dataset.dport.astype('float')
#             except ValueError:
#                 pass
#             try:
#                 # Convert sport to float
#                 dataset.sport = dataset.sport.astype('float')
#             except ValueError:
#                 pass
#             try:
#                 # Convert Dur to float
#                 dataset.dur = dataset.dur.astype('float')
#             except ValueError:
#                 pass
#             try:
#                 # Convert TotPkts to float
#                 dataset.pkts = dataset.pkts.astype('float')
#             except ValueError:
#                 pass
#             try:
#                 # Convert SrcPkts to float
#                 dataset.spkts = dataset.spkts.astype('float')
#             except ValueError:
#                 pass
#             try:
#                 # Convert TotBytes to float
#                 dataset.allbytes = dataset.allbytes.astype('float')
#             except ValueError:
#                 pass
#             try:
#                 # Convert SrcBytes to float
#                 dataset.sbytes = dataset.sbytes.astype('float')
#             except ValueError:
#                 pass
#             return dataset
#         except Exception as inst:
#             # Stop the timer
#             self.print('Error in process_features()')
#             self.print(type(inst))
#             self.print(inst)
#
#
#     def process_flows(self):
#         """
#         Process all the flwos in the DB
#         Store the pandas df in self.flows
#         """
#         try:
#             # We get all the flows so far
#             # because this retraining happens in batches
#             flows = __database__.get_all_flows()
#
#             # Check how many different labels are in the DB
#             # We need both normal and malware
#             labels = __database__.get_labels()
#             if len(labels) == 1:
#                 # Only 1 label has flows
#                 # There are not enough different labels, so insert two flows
#                 # that are fake but representative of a normal and malware flow
#                 # they are only for the training process
#                 # At least 1 flow of each label is required
#                 #self.print(f'Amount of labeled flows: {labels}', 0, 1)
#                 flows.append({'ts':1594417039.029793 , 'dur': '1.9424750804901123', 'saddr': '10.7.10.101', 'sport': '49733', 'daddr': '40.70.224.145', 'dport': '443', 'proto': 'tcp', 'origstate': 'SRPA_SPA', 'state': 'Established', 'pkts': 84, 'allbytes': 42764, 'spkts': 37, 'sbytes': 25517, 'appproto': 'ssl', 'label': 'Malware', 'module_labels': {'flowalerts-long-connection': 'Malware'}})
#                 flows.append({'ts':1382355032.706468 , 'dur': '10.896695', 'saddr': '147.32.83.52', 'sport': '47956', 'daddr': '80.242.138.72', 'dport': '80', 'proto': 'tcp', 'origstate': 'SRPA_SPA', 'state': 'Established', 'pkts': 67, 'allbytes': 67696, 'spkts': 1, 'sbytes': 100, 'appproto': 'http', 'label': 'Normal', 'module_labels': {'flowalerts-long-connection': 'Normal'}})
#                 # If there are enough flows, we dont insert them anymore
#
#             # Convert to pandas df
#             df_flows = pd.DataFrame(flows)
#
#             # Process features
#             df_flows = self.process_features(df_flows)
#
#             # Update the flow to the processed version
#             self.flows = df_flows
#         except Exception as inst:
#             # Stop the timer
#             self.print('Error in process_flows()')
#             self.print(type(inst))
#             self.print(inst)
#
#     def process_flow(self):
#         """
#         Process one flow. Only used during detection in testing
#         Store the pandas df in self.flow
#         """
#         try:
#             # Convert the flow to a pandas dataframe
#             raw_flow = pd.DataFrame(self.flow_dict, index=[0])
#             # Process features
#             dflow = self.process_features(raw_flow)
#             # Update the flow to the processed version
#             self.flow = dflow
#         except Exception as inst:
#             # Stop the timer
#             self.print('Error in process_flow()')
#             self.print(type(inst))
#             self.print(inst)
#
#     def detect(self):
#         """
#         Detect this flow with the current model stored
#         """
#         try:
#             # Store the real label if there is one
#             # y_flow = self.flow['label']
#             # Drop the real label
#             self.flow = self.flow.drop('label', axis=1)
#             # Drop the label predictions of the other modules
#             X_flow = self.flow.drop('module_labels', axis=1)
#             # Scale the flow
#             # X_flow = self.scaler.fit_transform(X_flow)
#             X_flow = self.scaler.transform(X_flow)
#             print('111'+'\n')
#             pred = self.clf.predict(X_flow)
#             print('000'+'\n')
#             return pred
#         except Exception as inst:
#             # Stop the timer
#             self.print('Error in detect()')
#             self.print(X_flow)
#             self.print(type(inst))
#             self.print(inst)
#
#
#     def store_model(self):
#         """
#         Store the trained model on disk
#         """
#         self.print(f'Storing the trained model and scaler on disk.', 0, 2)
#         f = open('./modules/flowmldetection/model.bin', 'wb')
#         data = pickle.dumps(self.clf)
#         f.write(data)
#         f.close()
#         g = open('./modules/flowmldetection/scaler.bin', 'wb')
#         data = pickle.dumps(self.scaler)
#         g.write(data)
#         g.close()
#
#     def read_model(self):
#         """
#         Read the trained model from disk
#         """
#         try:
#             self.print(f'Reading the trained model from disk.', 1, 2)
#             f = open('/home/wuguo-buaa/PycharmProjects/StratosphereLinuxIPS-dev/modules/flowmldetection/model.bin', 'rb')
#             self.clf = pickle.load(f)
#             f.close()
#             self.print(f'Reading the trained scaler from disk.', 1, 2)
#             g = open('/home/wuguo-buaa/PycharmProjects/StratosphereLinuxIPS-dev/modules/flowmldetection/scaler.bin', 'rb')
#             self.scaler = pickle.load(g)
#             g.close()
#         except FileNotFoundError:
#             # If there is no model, create one empty
#             self.print('There was no model. Creating a new empty model.', 1, 2)
#             print('There was no model. Creating a new empty model.')
#             self.clf = SGDClassifier(warm_start=True, loss='hinge', penalty="l1")
#         except EOFError:
#             self.print('Error reading model from disk. Creating a new empty model.', 1, 2)
#             print('Error reading model from disk. Creating a new empty model.')
#             self.clf = SGDClassifier(warm_start=True, loss='hinge', penalty="l1")
#
#     def set_evidence_malicious_flow(self, saddr, sport, daddr, dport, profileid, twid, uid):
#         """
#         Set the evidence that a flow was detected as malicious
#         """
#         confidence =  0.1
#         threat_level = 'low'
#         type_detection  = 'flow'
#         category = 'Anomaly.Traffic'
#         detection_info = str(saddr) + ':' + str(sport) + '-' + str(daddr) + ':' + str(dport)
#         type_evidence = 'MaliciousFlow'
#         description = f'Malicious flow by ML. Src IP {saddr}:{sport} to {daddr}:{dport}'
#         timestamp = datetime.datetime.now().strftime("%d/%m/%Y-%H:%M:%S")
#         if not twid:
#             twid = ''
#         __database__.setEvidence(type_evidence, type_detection, detection_info,
#                                  threat_level, confidence, description,
#                                  timestamp, category, profileid=profileid, twid=twid)
#
#     def run(self):
#         # Load the model first
#         try:
#             # Load the model
#             self.read_model()
#             logger.add('/home/wuguo-buaa/PycharmProjects/StratosphereLinuxIPS-dev/output/ml.log')
#             while True:
#                 try:
#                     message = self.c1.get_message(timeout=self.timeout)
#
#                     if message and message['data'] == 'stop_process':
#                         # Confirm that the module is done processing
#                         self.store_model()
#                         __database__.publish('finished_modules', self.name)
#                         return True
#                     if utils.is_msg_intended_for(message, 'new_flow'):
#                         data = message['data']
#                         # Convert from json to dict
#                         data = json.loads(data)
#                         profileid = data['profileid']
#                         twid = data['twid']
#                         # Get flow that is now in json format
#                         flow = data['flow']
#                         # Convert flow to a dict
#                         flow = json.loads(flow)
#                         # Convert the common fields to something that can
#                         # be interpreted
#                         # Get the uid which is the key
#                         uid = next(iter(flow))
#                         self.flow_dict = json.loads(flow[uid])
#                         logger.log(1,self.flow_dict)
#
#                         if self.mode == 'train':
#                             # We are training
#
#                             # Is the amount in the DB of labels enough to retrain?
#                             # Use labeled flows
#                             labels = __database__.get_labels()
#                             sum_labeled_flows = sum([i[1] for i in labels])
#                             if sum_labeled_flows >= self.minimum_lables_to_retrain and sum_labeled_flows%self.minimum_lables_to_retrain == 1:
#                                 # We get here every 'self.minimum_lables_to_retrain' amount of labels
#                                 # So for example we retrain every 100 labels and only when we have at least 100 labels
#                                 self.print(f'Training the model with the last group of flows and labels. Total flows: {sum_labeled_flows}.')
#                                 # Process all flows in the DB and make them ready for pandas
#                                 self.process_flows()
#                                 # Train an algorithm
#                                 self.train()
#                         elif self.mode == 'test':
#                             # We are testing, which means using the model to detect
#                             self.process_flow()
#                             logger.log(0,flow)
#                             # After processing the flow, it may happen that we delete icmp/arp/etc
#                             # so the dataframe can be empty
#                             if self.flow.empty:
#                                 continue
#                             print(123)
#                             # Predict
#                             pred = self.detect()
#                             label = self.flow_dict["label"]
#
#                             # Report
#                             if label and label != 'unknown' and label != pred[0]:
#                                 # If the user specified a label in test mode, and the label
#                                 # is diff from the prediction, print in debug mode
#                                 self.print(f'Report Prediction {pred[0]} for label {label} flow {self.flow_dict["saddr"]}:{self.flow_dict["sport"]} -> {self.flow_dict["daddr"]}:{self.flow_dict["dport"]}/{self.flow_dict["proto"]}', 0, 3)
#                             if pred[0] == 'Malware':
#                                 # Generate an alert
#                                 self.set_evidence_malicious_flow(self.flow_dict['saddr'], self.flow_dict['sport'], self.flow_dict['daddr'], self.flow_dict['dport'], profileid, twid, uid)
#                                 self.print(f'Prediction {pred[0]} for label {label} flow {self.flow_dict["saddr"]}:{self.flow_dict["sport"]} -> {self.flow_dict["daddr"]}:{self.flow_dict["dport"]}/{self.flow_dict["proto"]}', 0, 2)
#
#                 except Exception as inst:
#                     # Stop the timer
#                     self.print('Error in run()')
#                     self.print(type(inst))
#                     self.print(inst)
#                     return True
#
#         except KeyboardInterrupt:
#             self.print('Storing the model on disk before stopping')
#             self.store_model()
#             self.print('Model stored')
#             return True
#         except Exception as inst:
#             # Stop the timer
#             self.print('Error in run()')
#             self.print(type(inst))
#             self.print(inst)
#             return True
