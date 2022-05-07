# -*- coding:utf-8 -*-
def Main_split(source):
    # 此处一定要建上target文件夹，不然会报路径错误
    target = source.split('bro/conn.log.labeled')[0]+'split_files/'
    # 文件的行数的计数器
    num = 0
    # 文件序号
    name_num = 1
    # 用于存放数据
    dataStore = []
    old_str = "   "
    new_str = "\t"
    head = "#separator \\x09\n#set_separator	,\n#empty_field	(empty)\n#unset_field	-\n#path	conn\n#open	" \
           "2019-03-15-14-50-49\n#fields	ts	uid	id.orig_h	id.orig_p	id.resp_h	id.resp_p	proto	service	" \
           "duration	orig_bytes	resp_bytes	conn_state	local_orig	local_resp	missed_bytes	history	" \
           "orig_pkts	orig_ip_bytes	resp_pkts	resp_ip_bytes	tunnel_parents	label	detailed-label\n#types	" \
           "time	string	addr	port	addr	port	enum	string	interval	count	count	string	" \
           "bool	bool	count	string	count	count	count	count	set[string]	string	string\n"
    tail = "\n#close	2019-03-15-14-50-54"
    # 设置为UTF-8编码
    with open(source, 'r', encoding='UTF-8') as file_content:
        for line in file_content:
            num += 1
            if old_str in line:
                line = line.replace(old_str, new_str)
            dataStore.append(line)
            # 设定每个文件为20万行
            if num == 200000:
                with open(target + "target_list_" + str(name_num) + ".log", 'w+') as file_target:
                    print(file_target)
                    file_target.write(head)
                    for data in dataStore:
                        file_target.write(data)
                    file_target.write(tail)
                name_num += 1
                num = 0
                dataStore = []

    # 处理最后一个文件，如果最后一个文件行数少于20万行，进行如下处理
    with open(target + "target_list_" + str(name_num) + ".log", 'w+') as file_target:
        file_target.write(head)
        for data in dataStore:
            file_target.write(data)


if __name__ == "__main__":
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
    Main_split(list_file[19]+'/conn.log.labeled')
