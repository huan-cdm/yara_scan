#Linux/windows系统规则文件目录
linux_rule_dir = "./rule_file"
#linux_rule_dir = "C:\\Users\\101201905004\\Desktop\\yara_scan\\rule_file"



#内存扫描规则文件目录
memory_rule_dir = './memory_rule_file'



#Linux系统样本文件目录
linux_sample_dir = "./target_file"
#linux_sample_dir = "C:\\Users\\101201905004\\Desktop\\yara_scan\\target_file"



#windows系统样本文件目录
#win_sample_dir = ".\\target_file"
win_sample_dir = "C:\\Users\\101201905004\\Desktop\\file"



#扫描结果文件路径
scan_result = "./result/resultfile.txt"



#是否打印字符串
#不打印 value=0
#打印 value=1
mode=0



#配置内存扫描和文件扫描
#内存扫描 value=0
#文件扫描 value=1
fileormemory=0



#配置进程选项,扫描全部进程较慢
#指定进程(java.exe、python.exe、php.exe) value = 0
#所有进程 value = 1
pid_value = 0