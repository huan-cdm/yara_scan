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
from config import memory_rule_dir





#文件扫描遍历规则文件
def lin_file_list():
    file_list = []

	#遍历规则文件存到列表
    for root, dirs, files in os.walk(linux_rule_dir):
        for file in tqdm(files,desc="文件扫描遍历规则文件"):
            time.sleep(0.1)
            file_path = os.path.abspath(os.path.join(root, file))
            file_list.append(file_path)
    return file_list




#内存扫描遍历规则文件
def memory_file_list():
	file_memory_list = []
	#遍历规则文件存到列表
	for root, dirs, files in os.walk(memory_rule_dir):
		for file1 in tqdm(files,desc="内存扫描遍历规则文件存入列表"):
			time.sleep(0.1)
			file_path = os.path.abspath(os.path.join(root, file1))
			file_memory_list.append(file_path)
	return file_memory_list





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
    processes = psutil.pids()
    for process in tqdm(processes,desc="遍历所有进程ID"):

        try:
            process_info = psutil.Process(process)
            if process_info.name() == 'python.exe' or process_info.name() == 'java.exe' or process_info.name() == 'php.exe':
            	win_pid_list.append(process)
          
        except psutil.NoSuchProcess:
            print(f"PID: {process} not found")
       
    return win_pid_list





#遍历进程PID调用yara引擎
def win_memory():
	print("运行在windows系统")
	#规则文件
	memory_rule_file = memory_file_list()
	#进程PID
	memory_pid = win_pid()
	#定义扫描结果列表
	memory_list = []
	for mi in tqdm(memory_rule_file,desc="遍历内存扫描规则"):
		time.sleep(0.1)
		for mj in tqdm(memory_pid,desc="遍历java、python、php进程ID"):
			time.sleep(0.1)
			#判断是否打印字符串
			if int(mode) == 0:
				memory_win_result = os.popen('.\\yara_engine\\yara64.exe'+' '+mi+' '+str(mj)+' ').read()
				memory_list.append(memory_win_result)
			elif int(mode) == 1:
				memory_win_result = os.popen('.\\yara_engine\\yara64.exe'+' '+mi+' '+str(mj)+' '+'-s').read()
				memory_list.append(memory_win_result)
			else:
				print("配置文件mode字段只允许0/1")


	#清空列表中为空的数据
	memory_new_list = []
	for ma in memory_list:
		if ma != '':
			memory_new_list.append(ma)
			print(ma)

	f3 = open(file='.\\result\\result_file.txt', mode='w')
	for d in tqdm(memory_new_list,desc="结果存入到文件"):
		f3.write(str(d)+"\n")
		time.sleep(0.3)
		f3.close()
            
       




#程序执行入口
if __name__ == "__main__":

    if int(fileormemory) == 0:

        print("程序正在进行内存扫描......")
        if sys.platform.startswith('linux'):
        	print("linux")
        elif sys.platform.startswith('win'):
            win_memory()
        else:
            print("python运行在其他操作系统上")


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