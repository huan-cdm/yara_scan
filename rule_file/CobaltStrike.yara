rule CobaltStrike
{
	meta:
		tag = "CobaltStrike"
		description = "CobaltStrike木马检测规则"
		author = "huan666"
		
	strings:
        $dex1 = {4D 5A}
		$str1 = "%c%c%c%c%c%c%c%c%cMSSE-%d-server"
		
	condition:

		$dex1 and $str1 and  filesize > 10KB and filesize < 24KB
}