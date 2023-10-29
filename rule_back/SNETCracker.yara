rule SNETCracker
{
	meta:
		tag="SNETCracker内网弱口令爆破工具"
		type="WIN32&EXE&HACKTOOL"
		result="高危"
		author="huan666"
        describe="内网弱口令爆破工具"
		document="https://github.com/shack2/SNETCracker"
	strings:
		$hex0 = { 4D 5A }
		$str0 = "SNETCracker.Properties.Resources"
		$str1 = "SNETCracker"
		$str2 = "SNETCracker.exe"
		$str3 = "Redis"
		$str4 = "MongoServer"
		$str5 = "by shack2"

	condition:
		$hex0 at 0 and $str0 and  $str1 and  $str2  and  $str3  and  $str4  and  $str5
	
}