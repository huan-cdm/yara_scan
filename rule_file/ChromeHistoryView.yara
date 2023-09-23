import "pe"
rule ChromeHistoryView
{
	meta:
		tag="ChromeHistoryView"
		type="WIN32&EXE&HACKTOOL"
		result="高危"
		author="huan666"
        describe="Chrome览器历史记录提取工具"
		document="https://www.nirsoft.net/utils/chrome_history_view.html"
	strings:
		$hex0 = { 4D 5A }
		$str0 = "ChromeHistoryView.exe"
		
	condition:
	//	$hex0 and pe.pdb_path == "z:\\Projects\\VS2005\\ChromeHistoryView\\Release\\ChromeHistoryView.pdb"
		$hex0 and $str0
}