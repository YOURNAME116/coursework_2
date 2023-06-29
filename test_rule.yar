import "pe"
rule volgmer
{
meta:
    description = "Malformed User Agent"
    ref = "https://www.us-cert.gov/ncas/alerts/TA17-318B"
strings:
    $s = "Mozillar/"
condition:
    (uint16(0) == 0x5A4D and uint16(uint32(0x3c)) == 0x4550) and $s
}

rule VidgrabCode : Vidgrab Family 
{
    meta:
        description = "Vidgrab code tricks"
        author = "Seth Hardy"
        last_modified = "2014-06-20"
        
    strings:
        $divbyzero = { B8 02 00 00 00 48 48 BA 02 00 00 00 83 F2 02 F7 F0 }
        // add eax, ecx; xor byte ptr [eax], ??h; inc ecx
        $xorloop = { 03 C1 80 30 (66 | 58) 41 }
        $junk = { 8B 4? ?? 8B 4? ?? 03 45 08 52 5A }
        
    condition:
        all of them
}

rule VidgrabStrings : Vidgrab Family
{
    meta:
        description = "Vidgrab Identifying Strings"
        author = "Seth Hardy"
        last_modified = "2014-06-20"
        
    strings:
        $ = "IDI_ICON5" wide ascii
        $ = "starter.exe"
        $ = "wmifw.exe"
        $ = "Software\\rar"
        $ = "tmp092.tmp"
        $ = "temp1.exe"
        
    condition:
       3 of them
}

rule Vidgrab : Family
{
    meta:
        description = "Vidgrab"
        author = "Seth Hardy"
        last_modified = "2014-06-20"
        
    condition:
        VidgrabCode or VidgrabStrings
}
rule POETRAT_python {
	
    strings:
        $s1 = "String 1"

    condition:
        $s1
}

rule Rule2 {
	meta:
		description = "Detects Codoso APT Gh0st Malware"
        author = "Florian Roth"
        reference = "https://www.proofpoint.com/us/exploring-bergard-old-malware-new-tricks"
        date = "2016-01-30"
        hash = "bf52ca4d4077ae7e840cf6cd11fdec0bb5be890ddd5687af5cfa581c8c015fcd"
	
    strings:
        $s2 = "This is a test program"

    condition:
        $s2  
} 

 rule APT1_dbg_mess
    {
        meta:
            author = "AlienVault Labs"
            info = "CommentCrew-threat-apt1"

        strings:
            $dbg1 = "Down file ok!" wide ascii
            $dbg2 = "Send file ok!" wide ascii
            $dbg3 = "Command Error!" wide ascii
            $dbg4 = "Pls choose target first!" wide ascii
            $dbg5 = "Alert!" wide ascii
            $dbg6 = "Pls press enter to make sure!" wide ascii
            $dbg7 = "Are you sure to " wide ascii
            $pay1 = "rusinfo.exe" wide ascii
            $pay2 = "cmd.exe" wide ascii
            $pay3 = "AdobeUpdater.exe" wide ascii
            $pay4 = "buildout.exe" wide ascii
            $pay5 = "DefWatch.exe" wide ascii
            $pay6 = "d.exe" wide ascii
            $pay7 = "em.exe" wide ascii
            $pay8 = "IMSCMig.exe" wide ascii
            $pay9 = "localfile.exe" wide ascii
            $pay10 = "md.exe" wide ascii
            $pay11 = "mdm.exe" wide ascii
            $pay12 = "mimikatz.exe" wide ascii
            $pay13 = "msdev.exe" wide ascii
            $pay14 = "ntoskrnl.exe" wide ascii
            $pay15 = "p.exe" wide ascii
            $pay16 = "otepad.exe" wide ascii
            $pay17 = "reg.exe" wide ascii
            $pay18 = "regsvr.exe" wide ascii
            $pay19 = "runinfo.exe" wide ascii
            $pay20 = "AdobeUpdate.exe" wide ascii
            $pay21 = "inetinfo.exe" wide ascii
            $pay22 = "svehost.exe" wide ascii
            $pay23 = "update.exe" wide ascii
            $pay24 = "NTLMHash.exe" wide ascii
            $pay25 = "wpnpinst.exe" wide ascii
            $pay26 = "WSDbg.exe" wide ascii
            $pay27 = "xcmd.exe" wide ascii
            $pay28 = "adobeup.exe" wide ascii
            $pay29 = "0830.bin" wide ascii
            $pay30 = "1001.bin" wide ascii
            $pay31 = "a.bin" wide ascii
            $pay32 = "ISUN32.EXE" wide ascii
            $pay33 = "AcroRD32.EXE" wide ascii
            $pay34 = "INETINFO.EXE" wide ascii

        condition:
            4 of ($dbg*) and 1 of ($pay*)
    }
