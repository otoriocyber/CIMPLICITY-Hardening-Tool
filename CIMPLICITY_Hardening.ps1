<#
Developed by OTORIO LTD. - www.otorio.com
Version 1.0
Licensed under GPL V3
#>

<#
    .SYNOPSIS
    Tests GE's CIMPLICITY security

    .DESCRIPTION
    Please run the script as Administrator
    Collects data from the following sources:
        * Windows Management Instrumentation (WMI)
        * Windows registry
        * Security Policy
        * Netstat
        * Dirlist
        * Net and Netsh Commands

    Analyzes the collected data in order to alert on security misconfigurations
#>

#IPSEC ports - Verify that these ports fit your machine!
$IPSEC_PORTS = @{'TCP'=[System.Collections.ArrayList]@('32000');'UDP'=[System.Collections.ArrayList]@('32000')}                         

### Globals
$alerts = [System.Collections.ArrayList]@()
$complex_alerts = [System.Collections.Hashtable]@{}

### Consts
$REGISTRY_KEYS = @("HKU\*\SOFTWARE\Policies\Microsoft\Windows\Control Panel\Desktop",
                   "HKLM\SOFTWARE\Policies\Microsoft\Windows\Control Panel\Desktop",
                   "HKLM\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services",
                   "HKLM\SYSTEM\CurrentControlSet\Control\Terminal Server",
                   "HKLM\SYSTEM\CurrentControlSet\Services\LanManServer\Parameters",
                   "HKLM\SYSTEM\CurrentControlSet\Services\EventLog\*")

$WMI_HT = @{"Win32_GroupUser"=@("PartComponent","GroupComponent");
            "Win32_Group"=@("SID","Name","LocalAccount"); 
            "Win32_UserAccount"=@("SID","Name","LocalAccount"); 
            "Win32_LogicalShareAccess"=@("SecuritySetting","Trustee","AccessMask","Type");}
            
            
$KNOWN_SHARES = @("C:\", "C:\Windows")
$SHARE_PATH_REGEX = "\w:\\(?:[\w\\()\.\-\+]+\s?)*[\w()\-\+]"
$CIMPLICITY_FILES_REGEX = @("[\w]*\.cim$", "[\w]*\.gef$")

$AUDIT_TRANSLATION = @{'0'='No Auditing'; '1'='Success'; '2'='Failure'; '3'='Success and Failure'}
$AUDIT_EXPECTED_VALUE = @{'AuditLogonEvents'='3';
                          'AuditAccountLogon'='3';
                          'AuditObjectAccess'='3';
                          'AuditPrivilegeUse'='2';
                          'AuditAccountManage'='3';
                          'AuditPolicyChange'='3';
                          'AuditSystemEvents'='3';
                          'AuditProcessTracking'='3';
                          'AuditDSAccess'='0'}

$PORTS = @{'TCP'=@('135','139','445');'UDP'=@('135','137','138','445')}                 
$LOGS = @("Application", "Security", "System")

$KNOWN_SIDS = @{'*S-1-5-19'='Local Service'; '*S-1-5-20'='Network Service'; '*S-1-5-6'='Service'}
$ADMINISTRATOR_GROUP_SID = 'S-1-5-32-544'


### Data Collection

Function Get-RegistryValues{
    Param(
        [Parameter(Mandatory=$true)]
        [Array]$registry_keys)

    $registry_results = @{}
    foreach($key in $registry_keys){
        try{
        $result = Get-ItemProperty -Path REGISTRY::$key -ErrorAction stop
        }
        catch{
            Write-Host "$($_.Exception.Message)"
        }
        
        $registry_results.Add($key, $result)
    }
    return $registry_results
}
    
Function Get-WMI{
     Param(
        [Parameter(Mandatory=$true)]
        [System.Collections.Hashtable]$wmi_ht)

    $wmi_results = @{}
    foreach($wmi_query in $wmi_ht.keys){
        $result= Get-WmiObject -Class $wmi_query -Property $wmi_ht.$wmi_query
        $wmi_results.add($wmi_query, $result)
    }
    return $wmi_results
}

function Get-OpenPortDetails{
    Param(
        [Parameter(Mandatory=$true)]
        [String]$line,
        
        [Parameter(Mandatory=$true)]
        [String]$protocol)

    $local = $line.Split(':')
    if($local.Count -ne 2){
        return @{}
    }
    $ip, $port = $local
    return @{'Protocol'=$protocol; 'Local IP'=$ip; 'Port'=$port}
}

function Get-Netstat{
    $netstat = netstat -anob
    $open_ports = [System.Collections.ArrayList]@()
    $port_details = @{}
    
    foreach($netstat_line in $netstat){
        $line = $netstat_line.Split(" ") | % { if ($_ -ne $null -and $_ -ne "") { $_ } }
        if($line -eq $null -or $line.Count -eq 0){
            continue
        }
        
        if($line[0] -eq 'TCP'){
            if($port_details.Count -ne 0){
                $open_ports.Add($port_details)
                $port_details = @{}
            }
            if($line[3] -eq 'LISTENING'){
                $port_details = Get-OpenPortDetails $line[1] 'TCP'
            }
        }
        if($line[0] -eq 'UDP'){
            if($port_details.Count -ne 0){
                $open_ports.Add($port_details)
                $port_details = @{}
            }
            if($line[2] -eq '*:*'){
                $port_details = Get-OpenPortDetails $line[1] 'UDP'
            }
        }
        if($line.GetType().Name -eq "String" -and $line.StartsWith('[') -and $port_details.Count -ne 0){
            $program = $line.Trim('[').Trim(']')
            $port_details['Program'] = $program
        }
    }
    return $open_ports
}

Function Get-IniContent{
    Param(
    [Parameter(Mandatory=$true)]
    [string]$FilePath)
    
    $ini = @{}
    switch -regex -file $FilePath
    {
        '^\[(.+)\]' # Section
        {
            $section = $matches[1]
            $ini[$section] = @{}
            $CommentCount = 0
        }
        '^(;.*)$' # Comment
        {
            $value = $matches[1]
            $CommentCount = $CommentCount + 1
            $name = "Comment" + $CommentCount
            $ini[$section][$name] = $value
        }
        '(.+?)\s*= (.*)' # Key
        {
            $name,$value = $matches[1..2]
            $ini[$section][$name] = $value
        }
    }
    return $ini
}

function Get-Secpol{
    Param(
    [Parameter(Mandatory=$true)]
    [string]$path)

    $out = secedit /export /cfg $path 2>&1
    if($out -match "The task has completed successfully*"){
        $secpol = Get-IniContent -filepath $path
        Remove-Item $path
        return $secpol
    }
    Write-Warning "Error running secedit: $out"
    return $false
    
}

function Convert-SidToUser{
    Param(
    [Parameter(Mandatory=$true)]
    [String]$SID,
    
    [Parameter(Mandatory=$true)]
    [Hashtable]$WMI)
    
    $users_info = $WMI["Win32_UserAccount"] | Where {$_.LocalAccount -eq $True}
    if($user_info -eq $null){
        return
    }
    
    foreach($user in $user_info){
        if($user.SID -eq $SID){
            return $user.Name
        }
    }
}
function Convert-SidToGroup{
    Param(
    [Parameter(Mandatory=$true)]
    [String]$SID,
    
    [Parameter(Mandatory=$true)]
    [Hashtable]$WMI)
    
    $group_info = $WMI["Win32_Group"] | Where {$_.LocalAccount -eq $True}
    if($group_info -eq $null){
        return
    }
    
    foreach($group in $group_info){
        if($group.SID -eq $SID){
            return $group.Name
        }
    }
}

function Convert-SidToNames{
    Param(
    [Parameter(Mandatory=$true)]
    [System.Array]$SIDs,
    
    [Parameter(Mandatory=$true)]
    [Hashtable]$WMI)
    
    $names = [System.Collections.ArrayList]@()
    foreach($sid in $SIDs) {
        if($sid -eq $null -or $sid -eq ""){
            Continue
        }
        if(-not $sid.StartsWith('*S')){
            $names.Add($sid)
        }
        elseif($KNOWN_SIDS -contains $sid){
            $names.Add($KNOWN_SIDS[$sid])
        }
        else{
            $group_name = Convert-SidToGroup $sid.TrimStart('*') $WMI
            if($group_name -ne $null){
                $names.Add($group_name)
                Continue
            }
            $user_name = Convert-SidToUser $sid.TrimStart('*') $WMI
            if($user_name -ne $null){
                $names.Add($user_name)
                Continue
            }
        }
    }
    return $names
}

function Get-CimplicityFilesInShares{
    $shares = @{}
    $shares_info = net share
    foreach($line in $shares_info) {
        if($line -match $SHARE_PATH_REGEX) {
            if(-not ($KNOWN_SHARES -contains $Matches[0])){
                $share_name = $Matches[0]
                $shares.Add($share_name, [System.Collections.ArrayList]@()) | Out-Null
                $files = Get-ChildItem -Recurse $share_name 
                foreach($file in $files) {
                    foreach($file_regex in $CIMPLICITY_FILES_REGEX) { 
                        if($file.Name -match $file_regex) {
                            $file_path = $file.FullName
                            $shares[$share_name].Add("$file_path`n`t") | Out-Null
                        }
                    }
                }
                if($shares[$share_name].Count -eq 0) {
                    $shares.Remove($share_name)
                }
            }
        }
    }
    return $shares
}

function Get-IpSecRules{
	$rules = netsh advfirewall consec show rule name=all
	$parsed_rules = [System.Collections.ArrayList]@()
	$result = @{}
	foreach($line in $rules) {
		if($line -eq '' -and $result.Count -ne 0) {
			$parsed_rules.Add($result) | Out-Null
			$result = @{}
		}
		switch -Regex ($line)  {
			'^(.+?): {2,}(.+)' { $result[$Matches[1]] = $Matches[2] }
		}
	}
    return $parsed_rules
}


### Validations
Function Test-PasswordMinimumLength{
    param(
    [Parameter(Mandatory=$true)]
    [Hashtable]$secpol,
    
    [Parameter(Mandatory=$true)]
    [int]$length
    )
    if($secpol["System Access"] -ne $null){
        $min_length = $secpol["System Access"]["MinimumPasswordLength"]
        if($min_length -ne $null -and $min_length -ne "0"){
            if($min_length -as [int] -lt $length){
               $alerts.Add("Minimum number of password characters is $min_length, while $length is recommended") | Out-Null
            }
        }
        else{
            $alerts.Add("Minimum number of password characters is not defined") | Out-Null
        }
    }
}

Function Test-PasswordComplexity{
    param(
    [Parameter(Mandatory=$true)]
    [Hashtable]$secpol
    )
    if($secpol["System Access"] -ne $null){
        $complexity = $secpol["System Access"]["PasswordComplexity"]
        if($complexity -eq $null -or ($complexity -ne "1")){
            $alerts.Add("Password complexity is not enforced") | Out-Null
        }
    }
}

Function Test-PasswordClearText{
    param(
    [Parameter(Mandatory=$true)]
    [Hashtable]$secpol
    )
    if($secpol["System Access"] -ne $null){
        $complexity = $secpol["System Access"]["ClearTextPassword"]

        # Cleartext password is enabled
        if ($complexity -eq $null -or $complexity -ne "0"){
            $alerts.Add("Passwords are stored using reversible encryption") | Out-Null
        }
    }
}

Function Test-AccountLockout{
    param(
    [Parameter(Mandatory=$true)]
    [Hashtable]$secpol,
    
    [Parameter(Mandatory=$true)]
    [int]$min_attempts
    )
    if($secpol["System Access"] -ne $null){
        # Bad Logon attampts
        $logon_attempts = $secpol["System Access"]["LockoutBadCount"]
        if($logon_attempts -ne $null -and $logon_attempts -ne "0"){
            if($logon_attempts -as [int] -lt $min_attempts){
               $alerts.Add("Maximum number of bad logon attempts should be defined to at least $min_attempts") | Out-Null
            }
        }
        else{
            $alerts.Add("Maximum number of bad logon attempts is not defined") | Out-Null
        }
    }
}

Function Test-DefaultGuestAccount{
    param(
    [Parameter(Mandatory=$true)]
    [Hashtable]$secpol
    )
    
    if($secpol["System Access"] -ne $null){
        $account_enabled = $secpol["System Access"]["EnableGuestAccount"]

        if ($account_enabled -eq "1"){
            $alerts.Add("Default Guset account is enabled") | Out-Null
        }
    }
}

Function Test-DefaultAdminAccount{
    param(
    [Parameter(Mandatory=$true)]
    [Hashtable]$secpol
    )
    
    if($secpol["System Access"] -ne $null){
        $account_enabled = $secpol["System Access"]["EnableAdminAccount"]

        if ($account_enabled -eq "1"){
            $alerts.Add("Default Admnistrator account is enabled") | Out-Null
        }
    }
}

Function Test-AdministratorsNumber{
    param(
    [Parameter(Mandatory=$true)]
    [Hashtable]$wmi,
    
    [Parameter(Mandatory=$true)]
    [int]$max_admins
    )
    
    $groupuser_info = $wmi["Win32_GroupUser"]
    if($groupuser_info -eq $null){
        Write-Host "Administrator group info is unavailable"
    }
    
    $admin_group_name = Convert-SidToGroup -SID $ADMINISTRATOR_GROUP_SID -WMI $wmi
    if($admin_group_name -eq $null){
        return
    }
    
    $admin_users = $groupuser_info | Where {$_.GroupComponent -contains $admin_group_name}
    if($admin_users.Count -gt $max_admins){
        $alerts.Add("There are $admin_users.Count administrator users, there shouldn't be more than $max_admins") | Out-Null
    }
}

function Test-DebuggingPrivileges{
    param(
    [Parameter(Mandatory=$true)]
    [Hashtable]$wmi,
    
    [Parameter(Mandatory=$true)]
    [Hashtable]$secpol
    )
    
    $admin_group_name = Convert-SidToGroup -SID $ADMINISTRATOR_GROUP_SID -WMI $wmi
    if($admin_group_name -eq $null){
        return
    }
    
    if($secpol['Privilege Rights'] -ne $null){
        $privileges = Convert-SidToNames -SIDs $secpol["Privilege Rights"]["SeDebugPrivilege"].Split(',') -WMI $wmi
        if(-not ($privileges -contains $admin_group_name)){
            $alerts.Add("Debugging privileges are not allowed only for administrators") | Out-Null    
        }
    }
}

function Test-AuditPolicies{
    param(
    [Parameter(Mandatory=$true)]
    [Hashtable]$secpol
    )
    
    $audit_alerts = $null
    $audits_policies = $secpol["Event Audit"]
    if($audits_policies -eq $null){
        Write-Host "Audit policies data is not available"
    }
    
    foreach($policy in $audits_policies.Keys){
        $expected_value = $AUDIT_TRANSLATION[$AUDIT_EXPECTED_VALUE[$policy]]
        $current_value = $AUDIT_TRANSLATION[$audits_policies[$policy]]
        if($expected_value -ne $current_value){
            if($audit_alerts -eq $null){
                $audit_alerts = [System.Collections.ArrayList]@()
            }
            $audit_alerts.Add("$policy configured to $current_value - should be configured to $expected_value") | Out-Null
        }    
    }
    
    if($audit_alerts -ne $null){
        $complex_alerts.Add("Audits are misconfigured", $audit_alerts) | Out-Null
    }
}

function Test-ScreenSaver{
    param(
    [Parameter(Mandatory=$true)]
    [Hashtable]$registry
    )
    $machine_config = $registry["HKLM\SOFTWARE\Policies\Microsoft\Windows\Control Panel\Desktop"]
    if($machine_config -ne $null){
        if($machine_config.ScreenSaveActive -eq 1 -and $machine_config.ScreenSaverIsSecure -ne 1){
            $alerts.Add("Screen saver is enabled and is not protected by password") | Out-Null
            return
        }
    }
    
    $users_config = $registry["HKU\*\SOFTWARE\Policies\Microsoft\Windows\Control Panel\Desktop"]
    if($users_config -ne $null){
        foreach($user_info in $users_config){
            if($user_info.ScreenSaveActive -eq 1 -and $user_info.ScreenSaverIsSecure -ne 1){
                $alerts.Add("Screen saver is enabled and is not protected by password") | Out-Null
                return
            }
        }
    }
}

function Test-WindowsLogging{
    param(
    [Parameter(Mandatory=$true)]
    [Hashtable]$registry
    )
    
    $disabled_logs = [System.Collections.ArrayList]@()
    $logs_info = $registry["HKLM\SYSTEM\CurrentControlSet\Services\EventLog\*"]
    if($logs_info -ne $null){
        foreach($log in $logs_info){
            if($LOGS -contains $log.PSChildName){
                if($log.MaxSize -eq $null -or $log.MaxSize -eq 0){
                    $disabled_logs.Add($log.PSChildName)
                }
            }
        }
    }
    
    if($disabled_logs.Count -gt 0){
        $logs_names = $disabled_logs -join ", "
        $alerts.Add("Windows logging configuration is disabled for the logs - $logs_names") | Out-Null
    }
}

function Test-RdpDisabled{
    param(
    [Parameter(Mandatory=$true)]
    [Hashtable]$registry
    )
    
    $rdp_policy = $registry["HKLM\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services"]
    if($rdp_policy.fDenyTSConnections -ne $null -and $rdp_policy.fDenyTSConnections -ne 1){
        $alerts.Add("Remote Desktop is enabled") | Out-Null
        return
    }
    
    $rdp_status = $registry["HKLM\SYSTEM\CurrentControlSet\Control\Terminal Server"]
    if($rdp_policy.fDenyTSConnections -ne 1){
        $alerts.Add("Remote Desktop is enabled") | Out-Null
    }
}

function Test-RdpPromptsForPassword{
    param(
    [Parameter(Mandatory=$true)]
    [Hashtable]$registry
    )

    $rdp_status = $registry["HKLM\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services"]
    if($rdp_policy.fPromptForPassword -ne 1){
        $alerts.Add("Remote Desktop services don't always prompt for password upon connections") | Out-Null
    }
}

Function Test-ShareAuthentication{
    Param(
    [Parameter(Mandatory=$true)]
    [System.Collections.Hashtable]$wmi_results)

    $shares = $wmi_results["Win32_LogicalShareAccess"]
    if($shares -eq $null){
        return $null
    }
    $complex_alerts.Add("Folders shared with everyone", [System.Collections.ArrayList]@())
    foreach($share in $shares){

        # The share is a folder, and Everyone account SID is in the Trustee attribute
        if(($share.Trustee -match '(.+)(\"S-1-1-0\")') -and $share.Type -eq 0){
            if($share.SecuritySetting -match '.*Name="(?<name>.*)".*'){
                $name = $matches["name"]
                $complex_alerts["Folders shared with everyone"].Add($name) | Out-Null
            }
        }
    }
}

function Test-AnonymousShareAccess{
    param(
    [Parameter(Mandatory=$true)]
    [Hashtable]$registry
    )
    
    $share_access = $registry["HKLM\SYSTEM\CurrentControlSet\Services\LanManServer\Parameters"]
    if($share_access.RestrictNullSessAccess -ne 1){
        $alerts.Add("Anonymous access to share is not restricted") | Out-Null
    }
}

function Test-AnonymousAccessToNamedPipes{
    param(
    [Parameter(Mandatory=$true)]
    [Hashtable]$registry
    )
    
    $pipe_access = $registry["HKLM\SYSTEM\CurrentControlSet\Services\LanManServer\Parameters"]
    if($pipe_access.NullSessionPipes -eq $null -or $pipe_access.Count -eq 0){
        return
    }
    
    foreach($pipe in $pipe_access.NullSessionPipes){
        if($pipe -ne ""){
            $alerts.Add("Anonymous access to named pipes is not fully restricted") | Out-Null
			return
        }
    }
}

function Test-OpenPorts{
    param(
    [Parameter(Mandatory=$true)]
    [System.Array]$netstat
    )
    
    $ports_list = @{}
    foreach($port in $netstat){
        if($port.Protocol -ne $null -and $PORTS[$port.Protocol] -contains $port.Port){
            $port_number, $protocol, $program = $port.Port, $port.Protocol, $port.Program
            if(-not ($ports_list.Keys -contains "$protocol-$port_number")){
                if($program -ne $null){ 
                    $ports_list.Add("$protocol-$port_number", "$protocol-$port_number($program)") | Out-Null
                } else {
                    $ports_list.Add("$protocol-$port_number", "$protocol-$port_number") | Out-Null
                }
            }
        }
    }
    if($ports_list.Count -ne 0){
        $ports = $ports_list.Values -join ", "
        $alerts.Add("The following ports are opened and should be closed or blocked by firewall - $ports") | Out-Null
    }
}

function Test-CimplicityIpSecRules{
    param(
    [Parameter(Mandatory=$false)]
    [System.Array]$ipsec_rules
    )
    
    if($ipsec_rules -eq $null -or $ipsec_rules.Count -eq 0){
        $alerts.Add("IPsec communication is not defined, CIMPLICITY network traffic may not be encrypted") | Out-Null
		return
    }
	
	foreach($rule in $ipsec_rules){
		if($rule.Enabled -ne 'Yes' -or $rule.Action -ne 'RequireInRequireOut' -or $rule.Endpoint1 -ne 'Any' -or $rule.Endpoint2 -ne 'Any'){
			continue
		}
		if($rule.Protocol -eq 'Any'){
			$IPSEC_PORTS = @{}
			return
		}
		if($rule.Port1 -ne 'Any' -or (-not $IPSEC_PORTS.Keys -contains $rule.Protocol)){
			continue
		}
		if($rule.Port2 -eq 'Any'){
			$IPSEC_PORTS.Remove($rule.Protocol)
		}
		$dest_ports = $rule.Port2.split(',')
		foreach($port in $IPSEC_PORTS[$rule.Protocol]){
			if($dest_ports -contains $port){
				$IPSEC_PORTS[$rule.Protocol].Remove($port)
			}
		}
	}

	$uncovered_ports = [System.Collections.ArrayList]@()
	foreach($protocol in $IPSEC_PORTS.Keys){
		foreach($port in $IPSEC_PORTS[$protocol]){
			$uncovered_ports.Add("$protocol-$port") | Out-Null
		}
	}
	if($uncovered_ports.Count -ne 0){
		$ipsec_info = [System.Collections.ArrayList]@()
		$ipsec_info.Add("IPsec communication is not defined for the CIMPLICITY network traffic in these ports: $uncovered_ports") | Out-Null
		$ipsec_info.Add("The default CIMPLICITY client-server ports were checked, if this endpoint has another rule or uses different ports change the IPSEC_PORTS in the beginning of the script") | Out-Null
		$complex_alerts.Add("IpSes communication is not defined properly for CIMPLICITY communication ports", $ipsec_info) | Out-Null
	}
}

function Test-CimplicityFilesInShares{
    param(
    [Parameter(Mandatory=$true)]
    [Hashtable]$shares
    )
    
    if($shares.Count -eq 0){
        return
    }
    
    $alert_names = $shares.Keys -join ", "
    $alert = "There are CIMPLICITY project/screen files in these shares: $alert_names"
    $complex_alerts.Add($alert, $shares.Values) | Out-Null
}
 
### Results

Function Print-Alerts{
    
    foreach($alert in $alerts){
        Write-Host "`n* $alert"
    }
    foreach($alert in $complex_alerts.Keys){
        if($complex_alerts[$alert].Count -gt 0){
            Write-Host "`n* $alert -"
            foreach($subalert in $complex_alerts[$alert]){
                Write-Host "`t$subalert"
            }
        }
    }
}

#### Run

Write-Host "`n"
Write-Host "##################################"
Write-Host "CIMPLICITY Hardening Tool"
Write-Host "Created by OTORIO - www.otorio.com"
Write-Host "##################################"
Write-Host "`n"

## Collect data
Write-Host "Fetching registry data"
$registry_results = Get-RegistryValues -registry_keys $REGISTRY_KEYS

Write-Host "Fetching WMI data, may take a while"
$wmi_results = Get-WMI -wmi_ht $WMI_HT

Write-host "Fetching security policy data"
$secpol = Get-Secpol -path "\\localhost\admin$\seccfg.conf"

Write-Host "Fetching listening ports"
$netstat = Get-Netstat

Write-host "Fetching IPsec rules"
$ipsec = Get-IpSecRules

Write-host "Fetching CIMPLICITY files data"
$shares_info = Get-CimplicityFilesInShares

## Validate
# Get-SecPol was successful
if ($secpol -ne $false){
    Test-PasswordMinimumLength -secpol $secpol -length 14
    Test-PasswordComplexity -secpol $secpol
    Test-PasswordClearText $secpol
    Test-AccountLockout -secpol $secpol -min_attempts 5
    Test-AuditPolicies $secpol
    Test-DefaultGuestAccount $secpol
    Test-DefaultAdminAccount $secpol
    Test-DebuggingPrivileges $wmi_results $secpol
}

Test-AdministratorsNumber $wmi_results 2    
Test-WindowsLogging $registry_results
Test-ScreenSaver $registry_results
Test-OpenPorts $netstat
Test-ShareAuthentication $wmi_results
Test-AnonymousShareAccess $registry_results
Test-AnonymousAccessToNamedPipes $registry_results
Test-RdpDisabled $registry_results
Test-RdpPromptsForPassword $registry_results
Test-CimplicityIpSecRules $ipsec
Test-CimplicityFilesInShares $shares_info

## Results
Print-Alerts

