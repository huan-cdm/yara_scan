rule s_rule
{
	meta:
		tag="s.exe端口扫描工具"
		type="WIN32&EXE&HACKTOOL"
		result="高危"
		author="huan666"
        describe="端口扫描工具"
		document="https://jingyan.baidu.com/article/ab69b2709d43082ca6189f55.html"
	strings:
		$hex0 = { 4D 5A }
		$str0 = "s.exe"
		$str1 = "TCP Port Scanner V1.2 By WinEggDrop"
		$str2 = "/HBanner"
		$str3 = "SYN Scan: About To Scan %u IP For %u Ports Using %d Thread"
		$str4 = "No Port To Scan"
		
	condition:
	//	$hex0 and $str0 and pe.pdb_path == "c:\\Projects\\VS2005\\BrowsingHistoryView\\Release\\BrowsingHistoryView.pdb"
		all of them
}