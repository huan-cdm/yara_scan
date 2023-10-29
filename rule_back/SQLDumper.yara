rule SQLDumper
{
	meta:
		tag="SQLDumper"
		type="WIN32&EXE&HACKTOOL"
		result="高危"
		author="huan666"
        describe="SQLDumper密码获取工具"
		document="http://windows.dailydownloaded.com/zh/developer-tools/database-software/21112-sql-dumper-download-install/links"
	strings:
		$hex0 = { 4D 5A }
		$str0 = "SQLDumper.exe"
		$str1 = "SQLDumper"
		$str2 = "SQLDumper.Dumper"
		$str3 = "SQLDumper.Dumper.Database"
		$str4 = "SQLDumper.CheckUpdate.resources"
	condition:
		all of them
}