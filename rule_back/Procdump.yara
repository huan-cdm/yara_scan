import "pe"
rule Procdump
{
	meta:
		tag="Procdump提取dump工具"
		type="WIN32&EXE&HACKTOOL"
		result="高危"
		author="huan666"
        describe="Procdump提取dump工具"
		document="https://www.cnblogs.com/chenglee/p/9366399.html"
	strings:
		$hex0 = { 4D 5A }
		$str0 = "ProcDump"
	

	condition:
	//	$hex0 and $str0 and pe.pdb_path == "f:\\Agent\\_work\\17\\s\\x64\\Release\\ProcDump64.pdb"
	//	$hex0 and $str0 and $str1
		all of them
	//	$hex0 and $str0 and pe.pdb_path == "f:\\Agent\\_work\\17\\s\\x64\\Release\\ProcDump64.pdb"
}