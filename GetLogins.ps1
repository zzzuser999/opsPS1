
$maxLoginDate = Get-Date -Date "2021-01-01 00:00:00Z"

#Configure log filters
$ns = @{'ns' = 'http://schemas.microsoft.com/win/2004/08/events/event' }
$usersid_xpath = "//ns:Data[@Name='UserSid']"
$targetsid_xpath = "//ns:Data[@Name='TargetUserSid']"
$logontype_xpath = "//ns:Data[@Name='LogonType']"
    
$events = @()
    
$events += Get-WinEvent -ErrorAction SilentlyContinue  -FilterHashtable  @{ 
    LogName   = 'Security'
    Id        = @(4800, 4801, 4624)
    StartTime = $maxLoginDate 
}
    
$events += Get-WinEvent -ErrorAction SilentlyContinue  -FilterHashtable  @{ 
    LogName   = 'System'
    Id        = @(7001, 7002)
    StartTime = $maxLoginDate
}
    
$type_lu = @{
    7001 = 'Logon'
    7002 = 'Logoff'
    4800 = 'Lock'
    4801 = 'UnLock'
    4624 = 'RdpLogon'
}
    
$loginHistory = ForEach ($event in $events) {
    $xml = $event.ToXml()
    [bool] $skip = 0
    Switch -Regex ($event.Id) {
        '48..' {
            $sid = (Select-Xml -Content $xml -Namespace $ns -XPath $targetsid_xpath).Node.'#text'
            Break            
        }
        '4624' { 
            $logonType = (
                Select-Xml -Content $xml -Namespace $ns -XPath $logontype_xpath
            ).Node.'#text'
    
            if ($logonType -ne '10') { 
                $skip = 1
                continue 
            }
    
            $sid = (Select-Xml -Content $xml -Namespace $ns -XPath $targetsid_xpath).Node.'#text'
            Break            
        }
        '7...' {
            $sid = (Select-Xml -Content $xml -Namespace $ns -XPath $usersid_xpath).Node.'#text'                                                           
            Break
        }
    }
    
    if ($skip -or !$sid) { continue } 
    
    try {
        $user = (New-Object -TypeName 'System.Security.Principal.SecurityIdentifier' -ArgumentList $sid).Translate([System.Security.Principal.NTAccount]).Value
    }
    catch {
        $user = $sid
    }
                
    New-Object -TypeName PSObject -Property @{
        EntryId    = 0
        ServerID   = $machineID
        User       = $user
        Action     = $type_lu[$event.Id]
        LoginDate  = $event.TimeCreated
    
    }

                
}

Write-Output $loginHistory |Sort-Object LoginDate | Format-Table