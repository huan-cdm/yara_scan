#!/usr/bin/env python3
#author huan666

import sys
import os
from tqdm import tqdm
import time
import psutil
from config import linux_rule_dir
from config import linux_sample_dir
from config import win_sample_dir
from config import mode
from config import fileormemory





def lin_file_list():
    file_list = []

# 遍历规则文件存到列表中
    for root, dirs, files in os.walk(linux_rule_dir):
        for file in tqdm(files,desc="遍历规则文件"):
            time.sleep(0.1)
            file_path = os.path.abspath(os.path.join(root, file))
            file_list.append(file_path)
    return file_list



#windows系统执行函数
def win():
    print("运行在windows系统")
    win_result_list = []
    win_rule_file = lin_file_list()

    for a in tqdm(win_rule_file,desc="样本扫描"):
        time.sleep(0.1)

        if int(mode) == 0:
            win_result = os.popen('.\\yara_engine\\yara64.exe'+' '+a+' '+win_sample_dir+' '+'-r').read()
        elif int(mode) ==1:
            win_result = os.popen('.\\yara_engine\\yara64.exe'+' '+a+' '+win_sample_dir+' '+'-r'+' '+'-s').read()
        else:
            print("配置文件mode字段只允许0/1")

        win_result_list.append(win_result)

    #清空列表中为空的数据
    new_result_list = []
    for c in win_result_list:
        time.sleep(0.1)
        if c != '':
            new_result_list.append(c)
            print(c)

    f2 = open(file='.\\result\\result_file.txt', mode='w')
    for d in tqdm(new_result_list,desc="结果存入到文件"):
        f2.write(str(d)+"\n")
        time.sleep(0.3)
    f2.close()


#linux系统执行函数
def lin():
    print("运行在linux系统")
    result_list = []
    linux_rule_file = lin_file_list()
    for i in tqdm(linux_rule_file,desc="样本扫描"):
        time.sleep(0.1)
        if int(mode) == 0:
            result = os.popen('yara'+' '+i+' '+linux_sample_dir+' '+'-r').read()
        elif int(mode) ==1:
            result = os.popen('yara'+' '+i+' '+linux_sample_dir+' '+'-r'+' '+'-s').read()
        else:
            print("配置文件mode字段只允许0/1")

        result_list.append(result)

    #清空列表中为空的数据
    new_result_list = []
    for j in result_list:
        time.sleep(0.1)
        if j != '':
            new_result_list.append(j)
            print(j)
    
    f1 = open(file='./result/result_file.txt', mode='w')
    for l in tqdm(new_result_list,desc="结果存入到文件"):
        f1.write(str(l)+"\n")
        time.sleep(0.3)
    f1.close()



#遍历win系统进行PID存到列表
def win_pid():
    win_pid_list = []
    for process in psutil.process_iter(attrs=['pid']):
        win_pid_list.append(process.info['pid'])
    return win_pid_list
    
            
       


#程序执行入口
if __name__ == "__main__":
    if int(fileormemory) == 0:
        print("程序正在进行内存扫描......")
        pid = win_pid()
        print(pid)
    elif int(fileormemory) == 1:
        print("程序正在进行文件扫描......")
        if sys.platform.startswith('linux'):
            lin()
        elif sys.platform.startswith('win'):
            win()
        else:
            print("python运行在其他操作系统上")
    else:
        print("配置文件fileormemory字段只允许0/1")