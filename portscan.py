#!/usr/bin/env python
# -*- coding: utf-8 -*-
'''
desc:适用linux系统的简单端口扫描器，用户通过命令行交互方式输入IP段与端口范围进行端口TCP与UDP扫描，并生成txt文本报告
     python portscan.py -h 查看详情
author: huha
'''

import socket
import threading
import os
import time
import re
import subprocess
import argparse
import struct

HOST = '0.0.0.0'
TCP_TIMEOUT = 0.5
TCP_THREAD_DELAY = 0
THREAD_DELAY = 0
ICMP_DELAY = 1
THREAD_NUMBER = 1000		

class Portscan:
    '''
    端口扫描类
    '''

    def __init__(self):
        self.results = {}
        self.icmpPort_dict = {}

    def udp_sender(self, ip, port):
        '''
        udp发包，发送空的udp数据报给目标ip端口
        :param ip:
        :param port:
        :return:
        '''
        try:
            sock_udp = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            sock_udp.sendto(b"", (ip, port))
            sock_udp.close()
        except:
            pass

    def sniffing(self, host, ips):
        '''
        icmp嗅探，若没有嗅探到对应ip端口的icmp包,说明udp包正常发送；
        将嗅探到的icmp包对应IP与端口填入icmpPort_dict字典中
        :param host:
        :param socket_prot:
        :param ip:
        :param port:
        :return:
        '''
        # 创建raw_socket对象
        sniffer = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_ICMP)
        sniffer.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        sniffer.bind((host, 0))

        # 在捕获的数据包中添加IP头
        sniffer.setsockopt(socket.IPPROTO_IP, socket.IP_HDRINCL, 1)

        # sniffer.settimeout(0.5)
        #　使while条件成立,无论如何会执行循环一次
        addr = [ips[0]]
        while(addr[0] in ips):
            # 接受数据包
            # print('huha')
            recPacket, addr = sniffer.recvfrom(65536)
            icmpHeader = recPacket[20:28]
            icmpPort_hex = recPacket[50:52]
            icmpPort = (icmpPort_hex[0] << 8) + icmpPort_hex[1]
            # 解析icmp数据头字段
            head_type, code, checksum, packetID, sequence = struct.unpack(
                "bbHHh", icmpHeader
            )
            # 正常情况下udp不可达，icmp包类型为３
            if addr[0] in ips:
                if head_type != 3 or code != 3:
                    with open('error.log', 'a') as f:
                        timeArray = time.localtime(time.time())
                        formatTime = time.strftime("%Y-%m-%d %H:%M:%S", timeArray)
                        f.write(formatTime + '[?]Somting wrong with ip ' + addr[0] + ' in port ' + icmpPort + ':' + ' head_type:' +head_type +
                                ' code:' + code)
                else:
                    if self.icmpPort_dict.get(addr[0], []):
                        self.icmpPort_dict[addr[0]].append(icmpPort)
                    else:
                        self.icmpPort_dict[addr[0]] = [icmpPort]
        sniffer.close()

    def check_tcp(self, ip, port):
        '''
        使用套接字对象连接对应IP端口，失败则表示端口未开启,将tcp扫描结果到self.results中
        :param ip:
        :param port:
        :return:
        '''
        sock_tcp = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock_tcp.settimeout(TCP_TIMEOUT)
        status = sock_tcp.connect_ex((ip, port))
        # print(status)
        if status == 0:
            if self.results[ip].get(port, 0):
                self.results[ip][port] = '[+]{0}:{1}/tcp/udp open '.format(ip, port)
            self.results[ip][port] = '[+]{0}:{1}/tcp open '.format(ip, port)
            sock_tcp.close()

    def deal_range(self, range):
        '''
        正则匹配用户输入的port_range,允许范围0~65535
        :param range:
        :return: 端口范围begin和end
        '''
        # re.search(r'(.*)-(.*)', range).group(1) != '' and
        try:
            begin = int(range)
            end = int(range) + 1
            if (int(begin) < 0 or int(end) > 65535):
                print('port number wrong...')
                os._exit(0)
        except:
            # if re.search(r'(\d*)-(\d*)', range):
            #     # print('huha')
            begin = re.search(r'(.*)-(.*)', range).group(1)
            end = int(re.search(r'(.*)-(.*)', range).group(2))+1
            # print(begin, end)
            if int(begin) < 0 or int(end) > 65535:
                print('port number wrong...')
                os._exit(0)
        return begin, end

    def deal_ip(self, ip):
        '''
        正则匹配用户输入的ip
        :param ip:
        :return: 用户指定的ip范围列表
        '''
        ips = []
        if re.search(r'(.*)-(.*)', ip):
            # print('huha')
            ip_split = re.search(r'(.*)-(.*)', ip).group(1).split('.')
            ip_end = re.search(r'(.*)-(.*)', ip).group(2)
            for x in range(int(ip_split[3]), int(ip_end) + 1):
                ip_split[3] = str(x)
                ip = ('.').join(ip_split)
                # 执行系统ping ip地址,检测ip地址是否可以访问
                p = subprocess.Popen(['ping -c 6 ' + ip],
                                     stdin=subprocess.PIPE,
                                     stdout=subprocess.PIPE,
                                     stderr=subprocess.PIPE, shell=True)
                stdout = p.stdout.read().decode()
                if 'Unreachable' and '100% packet loss' not in stdout:
                    ips.append(ip)
                else:
                    # print()
                    with open('error.log', 'a') as f:
                        timeArray = time.localtime(time.time())
                        formatTime = time.strftime("%Y-%m-%d %H:%M:%S", timeArray)
                        if '100% packet loss' in stdout:
                            f.write(formatTime + ' [?]Host ' + ip + ' 100% packet loss!\n')
                        else:
                            f.write(formatTime + ' [?]Host ' + ip + ' Unreachable!\n')

        else:
            p = subprocess.Popen(['ping -c 6 ' + ip],
                                 stdin=subprocess.PIPE,
                                 stdout=subprocess.PIPE,
                                 stderr=subprocess.PIPE, shell=True)
            stdout = p.stdout.read().decode()
            if 'Unreachable' and '100% packet loss' not in stdout:
                ips.append(ip)
            else:
                # print()
                with open('error.log', 'a') as f:
                    timeArray = time.localtime(time.time())
                    formatTime = time.strftime("%Y-%m-%d %H:%M:%S", timeArray)
                    if '100% packet loss' in stdout:
                        f.write(formatTime + ' [?]Host ' + ip + ' 100% packet loss!\n')
                    else:
                        f.write(formatTime+' [?]Host ' + ip + ' Unreachable!\n')
        # print(len(ips))
        self.ips = ips
        return ips

    def run(self, ip, begin, end):
        self.results[ip] = {}
        '''
        对指定ip进行端口进行扫描：开启tcp多端口同时扫描,udp多端口同时法发包
        :param ip:
        :param begin:
        :param end:
        :return:
        '''
        print(ip, 'start...')
        print("[!]working hard...")

        udp_threads = []
        tcp_threads = []

        for port in range(begin, end):
            # print(port)
            udp_threads.append(threading.Thread(target=self.udp_sender, args=(ip, port)))
            tcp_threads.append(threading.Thread(target=self.check_tcp, args=(ip, port)))

        udp_count = 0
        tcp_count = 0
        for thread in udp_threads:
            udp_count += 1
            if udp_count == THREAD_NUMBER/len(self.ips):
                time.sleep(THERAD_DELAY)
                udp_count = 0
            thread.start()

        for thread in udp_threads:
            thread.join()

        for thread in tcp_threads:
            tcp_count += 1
            if tcp_count == THREAD_NUMBER/len(self.ips):
                time.sleep(THERAD_DELAY)
                tcp_count = 0
			thread.start()
            time.sleep(TCP_THREAD_DELAY)

        for thread in tcp_threads:
            thread.join()


if __name__ == '__main__':
    # 获取命令行参数
    parser = argparse.ArgumentParser()
    parser.add_argument("-a", "--target", help="Your target ip, eg:10.10.10.130 or 10.10.10.130-144", required=True)
    parser.add_argument("-p", "--port_range", help="Port range in 0~65535, eg:80 or 80-500", required=True)
    args = parser.parse_args()

    # 计时
    time_start = time.time()

    # 创建端口扫描类实例
    portscan = Portscan()

    begin, end = portscan.deal_range(args.port_range)
    ips = portscan.deal_ip(args.target)
    if not ips:
        print('All ip Unreachable or packet loss!')
        os._exit(0)
    # 创建一个icmp嗅探线程
    thread_icmp = threading.Thread(target=portscan.sniffing, args=(HOST, ips))
    # 设置守护线程,强制在程序退出时退出该线程
    thread_icmp.daemon = True
    thread_icmp.start()

    # 创建线程列表，同时对多个ip进行扫描
    threads = []
    for ip in ips:
        threads.append(threading.Thread(target=portscan.run, args=(ip, int(begin), int(end))))

    for thread in threads:
        thread.start()

    for thread in threads:
        thread.join()

    # 设置阻塞超时
    thread_icmp.join(ICMP_DELAY)

    # 将udp嗅探结果写入portscan.results中
    for ip in portscan.icmpPort_dict:
        for port in range(int(begin), int(end)):
            if port not in portscan.icmpPort_dict[ip]:
                if portscan.results[ip].get(port, 0):
                    portscan.results[ip][port] = '[+]{0}:{1}/tcp/udp open '.format(ip, port)
                portscan.results[ip][port] = '[+]{0}:{1}/udp open '.format(ip, port)

    # 将portscan.results中的结果写入文件
    for ip in portscan.results:
        with open(ip + '.txt', 'w') as f:
            for key in portscan.results[ip]:
                print(portscan.results[ip][key])
                f.write(portscan.results[ip][key] + '\n')

    # 计时结束
    time_end = time.time()
    print('time cost:', "{:.5}".format(time_end - time_start), 'seconds.')