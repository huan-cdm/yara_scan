rule Godzilla_memory
{
	meta:
		  tag = "Godzilla_memory"
		  description = "Godzilla内存马检测规则"
		  author = "huan666"
	strings:
		  

		   //memoryshell模块
		   $str1 = "x/AES_BASE64"
		   $str2 = "x/AES_RAW"
		   $str3 = "/favicon.ico"
		   
		
		
	condition:
		   ($str1 and $str3) or ($str2 and $str3)
		

	
}