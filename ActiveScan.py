#!/usr/bin/python3.6
# encoding:utf-8
import subprocess, os,json, time
from AddrsToSeq import get_rawIP


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



if __name__ == '__main__':
    addr_set = set()
    addr_set.add('2400:da00:2::29')
    addr_set.add('2404:0:8f82:a::201e')
    addr_set.add('2404:0:8e04:9::201e')
    Scan(addr_set)
    print('Over!')
