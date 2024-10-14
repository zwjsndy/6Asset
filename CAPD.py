#Input: Input assets under the folder./res.txt. 
#Output: Non-aliased assets under the folder./res.txt.
#Aliased Asset Detection Method CAPD.

import ipaddress
import os
import glob
import pandas as pd
import matplotlib.pyplot as plt
import subprocess
import time
from collections import Counter
import re
import torch
import torch.nn as nn
import random
import torch.nn.functional as F
import torch.optim as optim
import numpy as np
import random
from collections import Counter
from tqdm import tqdm

def alias_Detect(b1):  # 输入为(ip,port)
    d1 = {}
    map = {}
    ports = []
    
    temp1 = [word.split('|')[0] for word in b1]
    ports = [word.split('|')[1] for word in b1]
    b2 = convert(temp1)
    b = [word[:16] for word in b2]

    for i, ip in enumerate(b):
        port = ports[i]
        if ip not in d1:
            d1[ip] = [port]
            map[ip] = [temp1[i] + '|' + port]
        else:
            d1[ip].append(port)
            map[ip].append(temp1[i] + '|' + port)

    print('alias_detecting--------')
    res = []
    baseMap = [hex(i)[2] for i in range(16)]
    
    # 预生成随机选择
    random_choices = [random.choice(baseMap) for _ in range(15)]
    
    # 使用 tqdm 进行进度条可视化
    for word in tqdm(d1.keys(), desc="Processing prefixes"):
        for i in range(16):
            y = word + baseMap[i] + ''.join(random_choices)
            y = str2ipv6(y) + '|' + d1[word][0]
            res.append(y)

    temp = Scan(res, '2001:da8:ff:212::7:7', './res', 1)
    temp1 = [word.split(',')[0] for word in temp]
    temp = convert(temp1)
    res1 = [word[:16] for word in temp]
    
    prefix_counts = Counter(res1)
    aliased_prefix = [key for key, count in prefix_counts.items() if count >= 15]
    print(len(aliased_prefix))
    all1 = (item for word in aliased_prefix for item in map[word])
    
    return list(all1)  # 将生成器转换为列表



def Scan(addr_set, source_ip, output_file, tid):
    """
    运用扫描工具检测addr_set地址集中的活跃地址

    Args：
        addr_set：待扫描的地址集合
        source_ip
        output_file
        tid:扫描的线程id

    Return：
        active_addrs：活跃地址集合
    """
    import os
    scan_input = output_file + '/zmap/scan_input_{}.txt'.format(tid)
    scan_output = output_file + '/zmap/scan_output_{}.txt'.format(tid)
    

    
    with open(scan_input, 'w', encoding = 'utf-8') as f:
        for addr in addr_set:
            f.write(addr + '\n')

    active_addrs = set()
    command = 'smap -m f6 -b 10m -f {} --probe_v6 tcp_syn_scan_v6 --output_file_v6 {} --fields source_addr --fields sport'\
    .format(scan_input,scan_output)
   


    print('[+]Scanning {} addresses...'.format(len(addr_set)))
    t_start = time.time()
    p = subprocess.Popen(command, shell=True, stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
    # ret = p.poll()
    while p.poll() == None:
        pass    

    if p.poll() is 0:
        # with open(output_file, 'a', encoding='utf-8') as f:
        # time.sleep(1)

        skip_first_line = True  # 设置一个标志变量

        for line in open(scan_output):
            if skip_first_line:  # 如果是第一行，则跳过
                skip_first_line = False
                continue
            if line != '':
                active_addrs.add(line[:len(line) - 1])  # 添加到集合中，假设line末尾有换行符
            
    print('[+]Over! Scanning duration:{} s'.format(time.time() - t_start))
    print('[+]{} active address+port detected!'
        .format(len(active_addrs)))
    active_addrs1=[]
    for word in active_addrs:
        active_addrs1.append(word.split(',')[0]+'|'+word.split(',')[1])
    active_addrs=active_addrs1
    return active_addrs

def convert(seeds):
    result = []
    for line in seeds:
        line = line.split(":")
        for i in range(len(line)):
            if len(line[i]) == 4:
                continue
            if len(line[i]) < 4 and len(line[i]) > 0:
                zero = "0"*(4 - len(line[i]))
                line[i] = zero + line[i]
            if len(line[i]) == 0:
                zeros = "0000"*(9 - len(line))
                line[i] = zeros
        result.append("".join(line)[:32])
    return result


def stdIPv6(addr: str):
    return ipaddress.ip_address(addr)


def str2ipv6(a: str):
    pattern = re.compile('.{4}')
    addr = ':'.join(pattern.findall(a))
    return str(stdIPv6(addr))


def numConversion(a):
    baseMap = {'0': 0, '1': 1, '2': 2, '3': 3, '4': 4, '5': 5, '6': 6, '7': 7,
               '8': 8, '9': 9, 'a': 10, 'b': 11, 'c': 12, 'd': 13, 'e': 14, 'f': 15}
    result = []
    for item in a:
        temp = []
        for word in item:
            try:
                temp.append(baseMap[word])
            except:
                print(word)
        result.append(temp)
    return result

path='./res.txt'
result1=[]
with open(path, 'r') as f:
    for line in f:
        result1.append(line.strip('\n'))
res=alias_Detect(result1)
print('Proportion of aliased prefix.：',len(res)/len(result1))
with open(path, 'w', encoding = 'utf-8') as f:
    for addr in list(set(result1)-set(res)):
        f.write(addr + '\n')
