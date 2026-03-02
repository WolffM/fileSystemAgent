rule Registry_Persistence {
    meta:
        description = "Detects references to common registry persistence locations"
        severity = "medium"
        mitre_attack = "T1547.001"
    strings:
        $run1 = "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run" ascii nocase
        $run2 = "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\RunOnce" ascii nocase
        $run3 = "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\RunServices" ascii nocase
        $winlogon = "SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Winlogon" ascii nocase
        $ifeo = "SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Image File Execution Options" ascii nocase
        $appinit = "SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Windows\\AppInit_DLLs" ascii nocase
    condition:
        2 of them
}

rule Scheduled_Task_Creation {
    meta:
        description = "Detects programmatic scheduled task creation for persistence"
        severity = "medium"
        mitre_attack = "T1053.005"
    strings:
        $schtasks = "schtasks" ascii nocase
        $create = "/create" ascii nocase
        $xml = "Register-ScheduledTask" ascii nocase
        $com = "Schedule.Service" ascii nocase
        $at = "at.exe" ascii nocase
    condition:
        ($schtasks and $create) or $xml or $com or $at
}

rule WMI_Persistence {
    meta:
        description = "Detects WMI-based persistence techniques"
        severity = "high"
        mitre_attack = "T1546.003"
    strings:
        $wmi1 = "CommandLineEventConsumer" ascii nocase
        $wmi2 = "ActiveScriptEventConsumer" ascii nocase
        $wmi3 = "__EventFilter" ascii nocase
        $wmi4 = "FilterToConsumerBinding" ascii nocase
        $wmi5 = "Win32_ProcessStartTrace" ascii nocase
    condition:
        2 of them
}

rule Service_Creation_Suspicious {
    meta:
        description = "Detects suspicious service creation commands"
        severity = "high"
        mitre_attack = "T1543.003"
    strings:
        $sc_create = "sc create" ascii nocase
        $sc_config = "sc config" ascii nocase
        $new_service = "New-Service" ascii nocase
        $binpath = "binPath=" ascii nocase
        $cmd = "cmd.exe" ascii nocase
        $powershell = "powershell" ascii nocase
    condition:
        ($sc_create or $sc_config or $new_service) and $binpath and ($cmd or $powershell)
}
