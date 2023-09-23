rule HackBrowserDataHackBrowserData
{
	meta:
		tag="HackBrowserData"
		type="WIN32&EXE&HACKTOOL"
		result="高危"
		author="huan666"
        describe="HackBrowserData密码获取工具"
		document="https://github.com/moonD4rk/HackBrowserData"
	strings:
		$hex0 = { 4D 5A }
		$str0 = "hack-browser-data/core.init"
		$str1 = "hack-browser-data/core.(*Chromium).GetName"
		$str2 = "hack-browser-data/core.PickBrowser"
		$str3 = "hack-browser-data/core.(*Chromium).InitSecretKey"
		$str4 = "hack-browser-data/cmd.Execute.func1"
	condition:
		all of them
}