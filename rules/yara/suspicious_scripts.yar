rule Suspicious_PowerShell_Encoded {
    meta:
        description = "Detects encoded PowerShell commands often used by malware"
        severity = "high"
        mitre_attack = "T1059.001"
    strings:
        $enc1 = "-EncodedCommand" ascii nocase
        $enc2 = "-enc " ascii nocase
        $enc3 = "FromBase64String" ascii nocase
        $enc4 = "[Convert]::FromBase64" ascii nocase
        $bypass1 = "-ExecutionPolicy Bypass" ascii nocase
        $bypass2 = "Set-ExecutionPolicy Unrestricted" ascii nocase
        $hidden = "-WindowStyle Hidden" ascii nocase
        $noprofile = "-NoProfile" ascii nocase
    condition:
        any of ($enc*) or
        ($bypass1 and $hidden) or
        ($bypass2) or
        ($hidden and $noprofile and any of ($enc*))
}

rule Suspicious_PowerShell_Download {
    meta:
        description = "Detects PowerShell download cradles commonly used for malware delivery"
        severity = "critical"
        mitre_attack = "T1105"
    strings:
        $dl1 = "Net.WebClient" ascii nocase
        $dl2 = "DownloadString" ascii nocase
        $dl3 = "DownloadFile" ascii nocase
        $dl4 = "Invoke-WebRequest" ascii nocase
        $dl5 = "Invoke-RestMethod" ascii nocase
        $dl6 = "Start-BitsTransfer" ascii nocase
        $dl7 = "wget " ascii nocase
        $dl8 = "curl " ascii nocase
        $exec1 = "Invoke-Expression" ascii nocase
        $exec2 = "iex(" ascii nocase
        $exec3 = "iex " ascii nocase
    condition:
        any of ($dl*) and any of ($exec*)
}

rule Suspicious_Batch_Script {
    meta:
        description = "Detects batch scripts with suspicious command combinations"
        severity = "medium"
        mitre_attack = "T1059.003"
    strings:
        $reg_add = "reg add" ascii nocase
        $reg_run = "CurrentVersion\\Run" ascii nocase
        $schtasks = "schtasks /create" ascii nocase
        $netsh_fw = "netsh advfirewall" ascii nocase
        $disable_defender = "DisableAntiSpyware" ascii nocase
        $shadow_delete = "vssadmin delete shadows" ascii nocase
        $wmic_shadow = "wmic shadowcopy delete" ascii nocase
    condition:
        2 of them
}

rule Suspicious_VBScript {
    meta:
        description = "Detects VBScript patterns associated with malware droppers"
        severity = "high"
        mitre_attack = "T1059.005"
    strings:
        $shell = "WScript.Shell" ascii nocase
        $http = "MSXML2.XMLHTTP" ascii nocase
        $stream = "ADODB.Stream" ascii nocase
        $exec = ".Run " ascii nocase
        $create = "CreateObject" ascii nocase
    condition:
        $create and 2 of ($shell, $http, $stream, $exec)
}
