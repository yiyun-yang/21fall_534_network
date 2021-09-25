# -*- coding:utf-8 -*-

"""
@author: Yiyun Yang
@time: 2021/9/25 6:52
"""

from mydig import dns_resolver
import time
from statistics import mean
import dns.rdatatype
import dns.name
import dns.message
import dns.query
import dns.rdataclass
import dns.rdatatype
import dns.resolver
import numpy as np
from matplotlib import pyplot as plt
from prettytable import PrettyTable

top_25_list = ['Google.com', 'Youtube.com', 'Tmall.com', 'Baidu.com', 'Qq.com', 'Sohu.com', 'Facebook.com',
               'Taobao.com', '360.cn', 'Jd.com', 'Amazon.com', 'Yahoo.com', 'Wikipedia.org', 'Weibo.com', 'Sina.com.cn',
               'Zoom.us', 'Xinhuanet.com', 'Live.com', 'Netflix.com', 'Reddit.com', 'Microsoft.com', 'Instagram.com',
               'Office.com', 'Google.com.hk', 'Panda.tv']

google_resolver = dns.resolver.Resolver()
google_resolver.nameservers = ['8.8.8.8']

local_resolver = dns.resolver.Resolver()
local_resolver.nameservers = ['192.168.1.1']


def experiments():
    func_list = [function_1, function_2, function_3]
    label_list = ['experiment_1', 'experiment_2', 'experiment_3']
    time_avg_all = []
    for i, fun in enumerate(func_list):
        time_avg_list = []
        for website in top_25_list:
            time_costs = []
            for _ in range(10):
                try:
                    start_time = time.time()
                    fun(website)
                    end_time = time.time()
                    time_costs.append(end_time - start_time)
                except:
                    continue
            time_avg_list.append(int(mean(time_costs) * 1000))
        time_avg_all.append(time_avg_list)
        x = np.sort(time_avg_list)
        y = 1. * np.arange(len(time_avg_list)) / (len(time_avg_list) - 1)
        plt.plot(x, y, label=label_list[i])
    plt.ylabel('Pr[X<x]')
    plt.xlabel('Average time in msec')
    plt.title('CDF for Average Resolving Time')
    plt.legend()
    plt.savefig("output.png")

    titles = ["websites"]
    for lable in label_list:
        titles.append(lable)
    table = PrettyTable(titles)
    for i in range(25):
        l = [top_25_list[i]]
        for avgs in time_avg_all:
            l.append(avgs[i])
        table.add_row(l)
    print(table)


def function_1(website):
    dns_resolver(website, dns.rdatatype.A, [])


def function_2(website):
    local_resolver.resolve(website, dns.rdatatype.A)


def function_3(website):
    google_resolver.resolve(website, dns.rdatatype.A)


def main():
    experiments()


if __name__ == "__main__":
    experiments()
