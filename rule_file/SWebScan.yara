rule SWebScan
{
	meta:
		tag="SWebScan目录扫描工具"
		type="WIN32&EXE&HACKTOOL"
		result="高危"
		author="huan666"
        describe="网站后台目录扫描工具"
		document="https://github.com/shack2/SWebScan"
	strings:
		$hex0 = { 4D 5A }
		$str0 = "shack2.tools.file"
		$str1 = "SWebVulnsScan"
		$str2 = "SWebScan.exe"
		$str3 = "updateScanStatus"
	condition:
		$hex0 at 0 and $str0 and  $str1 and $str2  and  $str3
}