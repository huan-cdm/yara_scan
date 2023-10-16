rule Godzilla
{
	meta:
		  tag = "Godzilla"
		  description = "Godzilla内存马检测规则"
		  author = "huan666"
	strings:
		   // shellcodeloader模块
		   $str1 = "/favicon.ico"
		   $str2 = "com/sun/jna/platform/win32/COM/COMInvoker.class"
		   $str3 = "/sun/jna/platform/godzilla"
		
		
	condition:
		
		(

		($str1 and $str2 and $str3) 
		or ($str2 and $str3) 
		
		
		)

	
}