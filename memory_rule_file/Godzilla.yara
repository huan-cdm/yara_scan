rule Godzilla
{
	meta:
		tag = "Godzilla"
		description = "Godzilla内存马检测规则"
		author = "huan666"
	strings:
		$str1 = "/favicon.ico"
		$str2 = "com/sun/jna/platform/win32/COM/COMInvoker.class"
		$str3 = "/sun/jna/platform/godzilla"
		
		
		
	condition:
		//$str1 and $str2 and $str3 and $str4 and $str5 and $str6
		// all of them
		($str1 and $str2 and $str3) or ($str1 and $str2)
		
}