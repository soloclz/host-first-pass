#requires -Version 5.1
<#
.SYNOPSIS
    Fixed, read-only first pass for a new Windows host.
.DESCRIPTION
    Prints the current token, OS build and QFE records, UAC and Windows Installer
    policy, running process names, PIDs, session numbers and reported accounts,
    logon sessions, current logon session Kerberos tickets, local network
    endpoints and related process and service metadata, plus a few current-user
    credential-source clues. By default, also prints all current-process
    environment variable names and values. No recursive file searches, network
    calls, or files are produced by this script.
.PARAMETER EnvironmentNamesOnly
    Print all current-process environment variable names without their values.
#>

[CmdletBinding()]
param([switch]$EnvironmentNamesOnly)

$ErrorActionPreference = 'Stop'
$ProgressPreference = 'SilentlyContinue'

function Format-SafeText {
    param([AllowNull()][object]$Value)
    if ($null -eq $Value) { return '' }
    return (([string]$Value) -replace '[\x00-\x1f\x7f]', ' ').Trim()
}

function ConvertTo-OneLineJsonString {
    param([AllowNull()][object]$Value)
    $builder = New-Object System.Text.StringBuilder
    [void]$builder.Append('"')
    foreach ($unit in ([string]$Value).ToCharArray()) {
        $code = [int]$unit
        if ($code -eq 0x22) {
            [void]$builder.Append('\"')
        } elseif ($code -eq 0x5c) {
            [void]$builder.Append('\\')
        } elseif ($code -lt 0x20 -or $code -eq 0x7f -or $code -eq 0x85 -or
                  $code -eq 0x2028 -or $code -eq 0x2029 -or
                  ($code -ge 0xd800 -and $code -le 0xdfff)) {
            [void]$builder.Append(('\u{0:x4}' -f $code))
        } else {
            [void]$builder.Append($unit)
        }
    }
    [void]$builder.Append('"')
    return $builder.ToString()
}

function Write-Section {
    param([string]$Title)
    Write-Output ''
    Write-Output ('=== {0} ===' -f $Title)
}

function Write-Result {
    param(
        [ValidateSet('FOUND', 'CANDIDATE', 'NONE', 'QUERY_OK', 'DENIED', 'ERROR', 'UNAVAILABLE', 'NOT_RUN')]
        [string]$Status,
        [string]$Title,
        [string]$Source,
        [string]$Scope,
        [string[]]$Lines = @(),
        [string]$Detail = ''
    )

    $heading = '[{0}] {1} | source: {2} | scope: {3}' -f $Status, $Title, $Source, $Scope
    if ($Detail) { $heading += (' | {0}' -f (Format-SafeText $Detail)) }
    Write-Output $heading
    foreach ($line in $Lines) {
        Write-Output ('  {0}' -f (Format-SafeText $line))
    }
}

function Get-FailureStatus {
    param([System.Management.Automation.ErrorRecord]$Failure)
    if ($Failure.CategoryInfo.Category -eq [System.Management.Automation.ErrorCategory]::PermissionDenied) {
        return 'DENIED'
    }
    $exception = $Failure.Exception
    while ($null -ne $exception) {
        if ($exception -is [System.UnauthorizedAccessException] -or
            $exception -is [System.Security.SecurityException] -or
            $exception.HResult -eq -2147024891 -or
            $exception.HResult -eq -2147217405) {
            return 'DENIED'
        }
        $exception = $exception.InnerException
    }
    return 'ERROR'
}

function Get-FailureDetail {
    param([System.Management.Automation.ErrorRecord]$Failure)
    $exception = $Failure.Exception
    return ('exception: {0}; HRESULT: {1}' -f $exception.GetType().Name, $exception.HResult)
}

function Test-AvailableCommand {
    param([string]$Name)
    return ($null -ne (Get-Command -Name $Name -ErrorAction SilentlyContinue))
}

function Invoke-NativeRead {
    param(
        [string]$Name,
        [string[]]$Arguments = @(),
        [ValidateSet('FOUND', 'QUERY_OK')][string]$SuccessStatus = 'FOUND'
    )
    if (-not (Test-AvailableCommand $Name)) {
        return [pscustomobject]@{ Status = 'UNAVAILABLE'; Lines = @(); Detail = 'command not installed' }
    }

    # Native stderr is captured as text. The exit code, not output text, decides success.
    $ErrorActionPreference = 'Continue'
    # Native commands update the global automatic variable; do not shadow it locally.
    try {
        $lines = @(& $Name @Arguments 2>&1 | ForEach-Object { [string]$_ })
        $exitCode = $global:LASTEXITCODE
    } catch {
        return [pscustomobject]@{
            Status = (Get-FailureStatus $_); Lines = @(); Detail = (Get-FailureDetail $_)
        }
    }

    $lines = @($lines | Where-Object { -not [string]::IsNullOrWhiteSpace($_) })
    if ($null -eq $exitCode) {
        return [pscustomobject]@{ Status = 'ERROR'; Lines = @(); Detail = 'command did not return an exit code' }
    }
    if ($exitCode -ne 0) {
        $nativeError = [string]::Join(' ', $lines)
        $denied = ($exitCode -eq 5 -or
            $nativeError -match '(?i)access (is )?denied|0x0*5\b|拒絕存取|访问被拒绝')
        $status = if ($denied) { 'DENIED' } else { 'ERROR' }
        $detail = "exit code: $exitCode"
        if ($lines.Count -gt 0) {
            $message = Format-SafeText $lines[-1]
            if ($message.Length -gt 160) { $message = $message.Substring(0, 160) + '...' }
            if ($message) { $detail += "; message: $message" }
        }
        return [pscustomobject]@{ Status = $status; Lines = @(); Detail = $detail }
    }
    $status = if ($SuccessStatus -eq 'QUERY_OK') {
        'QUERY_OK'
    } elseif ($lines.Count -gt 0) {
        'FOUND'
    } else {
        'NONE'
    }
    return [pscustomobject]@{ Status = $status; Lines = $lines; Detail = ('lines: {0}' -f $lines.Count) }
}

function Format-Endpoint {
    param([object]$Endpoint, [string]$Protocol, [hashtable]$Processes, [hashtable]$Services,
        [string]$ProcessStatus, [string]$ServiceStatus)

    $address = [string]$Endpoint.LocalAddress
    if ($address.Contains(':')) { $address = '[{0}]' -f $address }
    $endpointProcessId = [int]$Endpoint.OwningProcess
    $processText = if ($ProcessStatus -notin @('FOUND', 'NONE')) {
        '(metadata unavailable)'
    } elseif ($Processes.ContainsKey($endpointProcessId)) {
        $process = $Processes[$endpointProcessId]
        $path = if ($process.ExecutablePath) { [string]$process.ExecutablePath } else { '(not reported)' }
        '{0}; path={1}' -f $process.Name, $path
    } else {
        '(no matching process at query time)'
    }

    $serviceText = if ($ServiceStatus -notin @('FOUND', 'NONE')) {
        '(metadata unavailable)'
    } elseif ($Services.ContainsKey($endpointProcessId)) {
        [string]::Join(', ', [string[]]@($Services[$endpointProcessId] | Sort-Object -Unique))
    } else {
        '(no matching service)'
    }
    $endpointText = '{0} {1}:{2}' -f $Protocol, $address, $Endpoint.LocalPort
    if ($Protocol -eq 'TCP Established') {
        $remoteAddress = [string]$Endpoint.RemoteAddress
        if ($remoteAddress.Contains(':')) { $remoteAddress = '[{0}]' -f $remoteAddress }
        $endpointText += (' -> {0}:{1}' -f $remoteAddress, $Endpoint.RemotePort)
    }
    return ('{0} PID={1} process={2} service={3}' -f $endpointText,
        $endpointProcessId, $processText, $serviceText)
}

$runTime = Get-Date -Format 'yyyy-MM-ddTHH:mm:sszzz'
$hostName = [Environment]::MachineName
$identityName = '(unavailable)'
try { $identityName = [Security.Principal.WindowsIdentity]::GetCurrent().Name } catch { }
Write-Output 'Windows first pass'
Write-Output ('Time: {0} | Host: {1} | Identity: {2}' -f $runTime, $hostName, $identityName)
Write-Output 'Scope: local host, current token, logon session and user profile; TCP Listen/Established and bound UDP endpoints.'
if ($EnvironmentNamesOnly) {
    Write-Output 'Environment mode: all current PowerShell process names, no values.'
} else {
    Write-Output 'Environment mode: all current PowerShell process names and values (JSON-escaped).'
}

Write-Section 'Identity and token'
$whoami = Invoke-NativeRead -Name 'whoami.exe' -Arguments @('/all')
Write-Result -Status $whoami.Status -Title 'Current token' -Source 'whoami /all' -Scope 'current process token' -Lines $whoami.Lines -Detail $whoami.Detail
if ($whoami.Status -eq 'FOUND') {
    $eventLogReadersRows = @($whoami.Lines | Where-Object {
        $_ -match '(?<![0-9-])S-1-5-32-573(?![0-9-])'
    })
    if ($eventLogReadersRows.Count -gt 0) {
        Write-Result -Status 'FOUND' -Title 'Event Log Readers SID in token' -Source 'whoami /all' -Scope 'current process token' -Lines $eventLogReadersRows -Detail 'inspect group attributes; check Security log access separately'
    }
}

Write-Section 'Operating system'
if (-not (Test-AvailableCommand 'Get-CimInstance')) {
    Write-Result -Status 'UNAVAILABLE' -Title 'OS version and build' -Source 'Win32_OperatingSystem' -Scope 'local host' -Detail 'Get-CimInstance not installed'
} else {
    try {
        $os = Get-CimInstance -ClassName Win32_OperatingSystem -ErrorAction Stop
        if ($null -eq $os) {
            Write-Result -Status 'NONE' -Title 'OS version and build' -Source 'Win32_OperatingSystem' -Scope 'local host'
        } else {
            $osLines = @(
                ('Name={0}' -f $os.Caption)
                ('Version={0}; build={1}; architecture={2}' -f $os.Version, $os.BuildNumber, $os.OSArchitecture)
            )
            Write-Result -Status 'FOUND' -Title 'OS version and build' -Source 'Win32_OperatingSystem' -Scope 'local host' -Lines $osLines
        }
    } catch {
        Write-Result -Status (Get-FailureStatus $_) -Title 'OS version and build' -Source 'Win32_OperatingSystem' -Scope 'local host' -Detail (Get-FailureDetail $_)
    }
}

$buildKeyPath = 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion'
try {
    $buildKey = Get-Item -LiteralPath $buildKeyPath -ErrorAction Stop
    $currentBuild = [string]$buildKey.GetValue('CurrentBuild')
    $ubr = $buildKey.GetValue('UBR')
    if ([string]::IsNullOrWhiteSpace($currentBuild) -or $null -eq $ubr) {
        Write-Result -Status 'NONE' -Title 'Full OS build' -Source $buildKeyPath -Scope 'local host' -Detail 'CurrentBuild or UBR value absent'
    } else {
        Write-Result -Status 'FOUND' -Title 'Full OS build' -Source $buildKeyPath -Scope 'local host' -Lines @(('CurrentBuild={0}; UBR={1}; full={0}.{1}' -f $currentBuild, $ubr))
    }
} catch {
    Write-Result -Status (Get-FailureStatus $_) -Title 'Full OS build' -Source $buildKeyPath -Scope 'local host' -Detail (Get-FailureDetail $_)
}

Write-Section 'Installed OS updates'
if (-not (Test-AvailableCommand 'Get-CimInstance')) {
    Write-Result -Status 'UNAVAILABLE' -Title 'QFE records' -Source 'Win32_QuickFixEngineering' -Scope 'local host; CBS-reported updates' -Detail 'Get-CimInstance not installed'
} else {
    try {
        $qfeRecords = @(Get-CimInstance -ClassName Win32_QuickFixEngineering -Property HotFixID, InstalledOn -ErrorAction Stop)
        $qfeLines = @($qfeRecords | Sort-Object HotFixID | ForEach-Object {
            $id = if ($_.HotFixID) { [string]$_.HotFixID } else { '(not reported)' }
            $installedOn = if ($_.InstalledOn) { [string]$_.InstalledOn } else { '(not reported)' }
            'HotFixID={0}; InstalledOn={1}' -f $id, $installedOn
        })
        $qfeStatus = if ($qfeRecords.Count -gt 0) { 'FOUND' } else { 'NONE' }
        Write-Result -Status $qfeStatus -Title 'QFE records' -Source 'Win32_QuickFixEngineering' -Scope 'local host; CBS-reported updates' -Lines $qfeLines -Detail ('records: {0}' -f $qfeRecords.Count)
    } catch {
        Write-Result -Status (Get-FailureStatus $_) -Title 'QFE records' -Source 'Win32_QuickFixEngineering' -Scope 'local host; CBS-reported updates' -Detail (Get-FailureDetail $_)
    }
}

Write-Section 'UAC policy'
$uacPolicyPath = 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System'
foreach ($name in @('EnableLUA', 'ConsentPromptBehaviorAdmin')) {
    try {
        $policyKey = Get-Item -LiteralPath $uacPolicyPath -ErrorAction Stop
        if ($policyKey.GetValueNames() -notcontains $name) {
            Write-Result -Status 'NONE' -Title $name -Source $uacPolicyPath -Scope 'local host' -Detail 'value absent'
            continue
        }

        $value = $policyKey.GetValue($name)
        $kind = $policyKey.GetValueKind($name)
        $meaning = if ($kind -ne [Microsoft.Win32.RegistryValueKind]::DWord) {
            "unexpected registry type: $kind"
        } elseif ($name -eq 'EnableLUA') {
            switch ([string]$value) {
                '0' { 'Admin Approval Mode disabled' }
                '1' { 'Admin Approval Mode enabled (default)' }
                default { 'unrecognized value' }
            }
        } else {
            switch ([string]$value) {
                '0' { 'elevate without prompting' }
                '1' { 'prompt for credentials on secure desktop' }
                '2' { 'prompt for consent on secure desktop' }
                '3' { 'prompt for credentials' }
                '4' { 'prompt for consent' }
                '5' { 'prompt for consent for non-Windows binaries (default)' }
                default { 'unrecognized value' }
            }
        }
        Write-Result -Status 'FOUND' -Title $name -Source $uacPolicyPath -Scope 'local host' -Lines @("$name=$value") -Detail $meaning
    } catch {
        Write-Result -Status (Get-FailureStatus $_) -Title $name -Source $uacPolicyPath -Scope 'local host' -Detail (Get-FailureDetail $_)
    }
}

Write-Section 'Windows Installer policy'
$installerPolicy = @{}
foreach ($hive in @('HKCU', 'HKLM')) {
    $path = '{0}:\SOFTWARE\Policies\Microsoft\Windows\Installer' -f $hive
    $scope = if ($hive -eq 'HKCU') { 'current user' } else { 'local machine' }
    try {
        $key = Get-Item -LiteralPath $path -ErrorAction Stop
        if ($key.GetValueNames() -notcontains 'AlwaysInstallElevated') {
            $installerPolicy[$hive] = 'absent'
            Write-Result -Status 'NONE' -Title 'AlwaysInstallElevated' -Source $path -Scope $scope -Detail 'value absent'
            continue
        }

        $kind = $key.GetValueKind('AlwaysInstallElevated')
        $value = $key.GetValue('AlwaysInstallElevated', $null, [Microsoft.Win32.RegistryValueOptions]::DoNotExpandEnvironmentNames)
        $isEnabled = ($kind -eq [Microsoft.Win32.RegistryValueKind]::DWord -and $value -eq 1)
        $installerPolicy[$hive] = if ($isEnabled) { 'REG_DWORD 1' } else { '{0} {1}' -f $kind, $value }
        Write-Result -Status 'FOUND' -Title 'AlwaysInstallElevated' -Source $path -Scope $scope -Lines @(('type={0}; value={1}' -f $kind, $value))
    } catch {
        if ($_.CategoryInfo.Category -eq [System.Management.Automation.ErrorCategory]::ObjectNotFound) {
            $installerPolicy[$hive] = 'absent'
            Write-Result -Status 'NONE' -Title 'AlwaysInstallElevated' -Source $path -Scope $scope -Detail 'key absent'
        } else {
            $status = Get-FailureStatus $_
            $installerPolicy[$hive] = $status
            Write-Result -Status $status -Title 'AlwaysInstallElevated' -Source $path -Scope $scope -Detail (Get-FailureDetail $_)
        }
    }
}

$installerSummary = 'HKCU={0}; HKLM={1}' -f $installerPolicy['HKCU'], $installerPolicy['HKLM']
if ($installerPolicy['HKCU'] -eq 'REG_DWORD 1' -and $installerPolicy['HKLM'] -eq 'REG_DWORD 1') {
    $installerStatus = 'FOUND'
    $installerDetail = 'both policy values are enabled; verify the token of any process launched by the MSI'
} elseif ($installerPolicy['HKLM'] -eq 'REG_DWORD 1' -and $installerPolicy['HKCU'] -notin @('DENIED', 'ERROR')) {
    $installerStatus = 'CANDIDATE'
    $installerDetail = 'HKLM is enabled; set the current-user HKCU value to REG_DWORD 1 and recheck'
} elseif ($installerPolicy['HKLM'] -notin @('REG_DWORD 1', 'DENIED', 'ERROR')) {
    $installerStatus = 'NONE'
    $installerDetail = 'HKLM is not REG_DWORD 1; changing HKCU alone cannot enable this policy'
} elseif ($installerPolicy.Values -contains 'DENIED') {
    $installerStatus = 'DENIED'
    $installerDetail = 'a registry read was denied; policy condition is uncertain'
} else {
    $installerStatus = 'ERROR'
    $installerDetail = 'a registry read failed; policy condition is uncertain'
}
Write-Result -Status $installerStatus -Title 'Elevated MSI policy condition' -Source 'AlwaysInstallElevated' -Scope 'current user on local host' -Lines @($installerSummary) -Detail $installerDetail

Write-Section 'Running processes'
$tasklistSource = 'tasklist /v /fo csv /nh'
$tasklist = Invoke-NativeRead -Name 'tasklist.exe' -Arguments @('/v', '/fo', 'csv', '/nh')
if ($tasklist.Status -notin @('FOUND', 'NONE')) {
    Write-Result -Status $tasklist.Status -Title 'Process names, PIDs and accounts' -Source $tasklistSource -Scope 'local host' -Detail $tasklist.Detail
} elseif ($tasklist.Status -eq 'NONE') {
    Write-Result -Status 'NONE' -Title 'Process names, PIDs and accounts' -Source $tasklistSource -Scope 'local host' -Detail 'no rows returned'
} else {
    try {
        $taskRows = @($tasklist.Lines | ConvertFrom-Csv -Header @('ImageName', 'PID', 'SessionName', 'SessionNumber', 'MemoryUsage', 'Status', 'UserName', 'CPUTime', 'WindowTitle') -ErrorAction Stop)
        if ($taskRows.Count -ne $tasklist.Lines.Count) { throw 'Unexpected tasklist CSV row count.' }
        $runningProcessLines = @($taskRows | ForEach-Object {
            $pidText = ([string]$_.PID).Trim()
            if ([string]::IsNullOrWhiteSpace($_.ImageName) -or $pidText -notmatch '^\d+$') {
                throw 'Unexpected tasklist CSV fields.'
            }
            $account = if ([string]::IsNullOrWhiteSpace($_.UserName) -or $_.UserName -eq 'N/A') { '(not reported)' } else { [string]$_.UserName }
            $session = if ([string]::IsNullOrWhiteSpace($_.SessionNumber)) { '(not reported)' } else { [string]$_.SessionNumber }
            'PID={0} name={1} session={2} account={3}' -f $pidText, $_.ImageName, $session, $account
        })
        $accountsReported = @($taskRows | Where-Object {
            -not [string]::IsNullOrWhiteSpace($_.UserName) -and $_.UserName -ne 'N/A'
        }).Count
        Write-Result -Status 'FOUND' -Title 'Process names, PIDs and accounts' -Source $tasklistSource -Scope 'local host' -Lines $runningProcessLines -Detail ('processes: {0}; accounts reported: {1}' -f $runningProcessLines.Count, $accountsReported)
    } catch {
        Write-Result -Status 'ERROR' -Title 'Process names, PIDs and accounts' -Source $tasklistSource -Scope 'local host' -Detail 'unexpected tasklist CSV; no process rows shown'
    }
}

Write-Section 'Logon sessions'
$sessions = Invoke-NativeRead -Name 'quser.exe'
Write-Result -Status $sessions.Status -Title 'User sessions' -Source 'quser' -Scope 'local host' -Lines $sessions.Lines -Detail $sessions.Detail

Write-Section 'Kerberos tickets'
$tickets = Invoke-NativeRead -Name 'klist.exe' -SuccessStatus 'QUERY_OK'
Write-Result -Status $tickets.Status -Title 'Cached tickets' -Source 'klist' -Scope 'current logon session' -Lines $tickets.Lines -Detail $tickets.Detail

Write-Section 'Network endpoints and PID mappings'
$tcpEndpoints = @()
$tcpEstablishedEndpoints = @()
$udpEndpoints = @()
$tcpStatus = 'NOT_RUN'
$tcpEstablishedStatus = 'NOT_RUN'
$udpStatus = 'NOT_RUN'
$tcpDetail = ''
$tcpEstablishedDetail = ''
$udpDetail = ''

if (Test-AvailableCommand 'Get-NetTCPConnection') {
    try {
        $tcpConnections = @(Get-NetTCPConnection -ErrorAction Stop)
        $tcpEndpoints = @($tcpConnections | Where-Object { $_.State -eq 'Listen' })
        $tcpEstablishedEndpoints = @($tcpConnections | Where-Object { $_.State -eq 'Established' })
        $tcpStatus = if ($tcpEndpoints.Count -gt 0) { 'FOUND' } else { 'NONE' }
        $tcpEstablishedStatus = if ($tcpEstablishedEndpoints.Count -gt 0) { 'FOUND' } else { 'NONE' }
    } catch {
        $tcpEndpoints = @()
        $tcpEstablishedEndpoints = @()
        $tcpStatus = Get-FailureStatus $_
        $tcpEstablishedStatus = $tcpStatus
        $tcpDetail = Get-FailureDetail $_
        $tcpEstablishedDetail = $tcpDetail
    }
} else {
    $tcpStatus = 'UNAVAILABLE'
    $tcpEstablishedStatus = 'UNAVAILABLE'
    $tcpDetail = 'Get-NetTCPConnection not installed'
    $tcpEstablishedDetail = $tcpDetail
}

if (Test-AvailableCommand 'Get-NetUDPEndpoint') {
    try {
        $udpEndpoints = @(Get-NetUDPEndpoint -ErrorAction Stop)
        $udpStatus = if ($udpEndpoints.Count -gt 0) { 'FOUND' } else { 'NONE' }
    } catch {
        $udpStatus = Get-FailureStatus $_
        $udpDetail = Get-FailureDetail $_
    }
} else {
    $udpStatus = 'UNAVAILABLE'
    $udpDetail = 'Get-NetUDPEndpoint not installed'
}

$processes = @{}
$services = @{}
$processStatus = 'NOT_RUN'
$serviceStatus = 'NOT_RUN'
$processDetail = 'no endpoint PID available from completed queries'
$serviceDetail = 'no endpoint PID available from completed queries'
$tcpEstablishedShown = @($tcpEstablishedEndpoints | Sort-Object LocalPort, LocalAddress, RemotePort, RemoteAddress, OwningProcess | Select-Object -First 100)
$endpointIds = @{}
foreach ($endpoint in @($tcpEndpoints) + @($tcpEstablishedShown) + @($udpEndpoints)) {
    $endpointIds[[int]$endpoint.OwningProcess] = $true
}

if ($endpointIds.Count -gt 0) {
    if (-not (Test-AvailableCommand 'Get-CimInstance')) {
        $processStatus = 'UNAVAILABLE'
        $serviceStatus = 'UNAVAILABLE'
        $processDetail = 'Get-CimInstance not installed'
        $serviceDetail = 'Get-CimInstance not installed'
    } else {
        try {
            $processRows = @(Get-CimInstance -ClassName Win32_Process -Property ProcessId, Name, ExecutablePath -ErrorAction Stop |
                Where-Object { $endpointIds.ContainsKey([int]$_.ProcessId) })
            foreach ($process in $processRows) { $processes[[int]$process.ProcessId] = $process }
            $processStatus = if ($processes.Count -gt 0) { 'FOUND' } else { 'NONE' }
            $processDetail = 'linked process records: {0}; paths reported: {1}' -f $processes.Count, @($processes.Values | Where-Object { $_.ExecutablePath }).Count
        } catch {
            $processStatus = Get-FailureStatus $_
            $processDetail = Get-FailureDetail $_
        }
        try {
            $serviceRows = @(Get-CimInstance -ClassName Win32_Service -Property ProcessId, Name -ErrorAction Stop |
                Where-Object { $endpointIds.ContainsKey([int]$_.ProcessId) })
            foreach ($service in $serviceRows) {
                $serviceProcessId = [int]$service.ProcessId
                if (-not $services.ContainsKey($serviceProcessId)) { $services[$serviceProcessId] = @() }
                $services[$serviceProcessId] += [string]$service.Name
            }
            $serviceStatus = if ($serviceRows.Count -gt 0) { 'FOUND' } else { 'NONE' }
            $serviceDetail = 'linked service records: {0}' -f $serviceRows.Count
        } catch {
            $serviceStatus = Get-FailureStatus $_
            $serviceDetail = Get-FailureDetail $_
        }
    }
}

$tcpLines = @($tcpEndpoints | Sort-Object LocalPort, LocalAddress, OwningProcess | ForEach-Object {
    Format-Endpoint -Endpoint $_ -Protocol 'TCP' -Processes $processes -Services $services -ProcessStatus $processStatus -ServiceStatus $serviceStatus
})
$tcpEstablishedLines = @($tcpEstablishedShown | ForEach-Object {
    Format-Endpoint -Endpoint $_ -Protocol 'TCP Established' -Processes $processes -Services $services -ProcessStatus $processStatus -ServiceStatus $serviceStatus
})
$udpLines = @($udpEndpoints | Sort-Object LocalPort, LocalAddress, OwningProcess | ForEach-Object {
    Format-Endpoint -Endpoint $_ -Protocol 'UDP' -Processes $processes -Services $services -ProcessStatus $processStatus -ServiceStatus $serviceStatus
})
$tcpReportDetail = if ($tcpStatus -in @('FOUND', 'NONE')) { 'count: {0}' -f $tcpEndpoints.Count } else { $tcpDetail }
$tcpEstablishedNotShown = $tcpEstablishedEndpoints.Count - $tcpEstablishedLines.Count
$tcpEstablishedDisplay = if ($tcpEstablishedNotShown -gt 0) { 'TRUNCATED' } else { 'COMPLETE' }
$tcpEstablishedReportDetail = if ($tcpEstablishedStatus -in @('FOUND', 'NONE')) {
    'connections: {0}; shown: {1}; not shown: {2}; display: {3}' -f $tcpEstablishedEndpoints.Count, $tcpEstablishedLines.Count, $tcpEstablishedNotShown, $tcpEstablishedDisplay
} else { $tcpEstablishedDetail }
$udpReportDetail = if ($udpStatus -in @('FOUND', 'NONE')) { 'count: {0}' -f $udpEndpoints.Count } else { $udpDetail }
Write-Result -Status $tcpStatus -Title 'TCP listeners' -Source 'Get-NetTCPConnection (State=Listen)' -Scope 'all local addresses' -Lines $tcpLines -Detail $tcpReportDetail
Write-Result -Status $tcpEstablishedStatus -Title 'TCP established connections' -Source 'Get-NetTCPConnection (State=Established)' -Scope 'local host, all remote addresses' -Lines $tcpEstablishedLines -Detail $tcpEstablishedReportDetail
Write-Result -Status $udpStatus -Title 'UDP bindings' -Source 'Get-NetUDPEndpoint' -Scope 'all local addresses' -Lines $udpLines -Detail $udpReportDetail
Write-Result -Status $processStatus -Title 'Endpoint process metadata' -Source 'Win32_Process' -Scope 'endpoint PIDs only' -Detail $processDetail
Write-Result -Status $serviceStatus -Title 'Endpoint service mapping' -Source 'Win32_Service' -Scope 'endpoint PIDs only' -Detail $serviceDetail

Write-Section 'Current-user credential-source clues'
$profilePath = ''
$profileError = $null
try { $profilePath = [Environment]::GetFolderPath([Environment+SpecialFolder]::UserProfile) } catch { $profileError = $_ }
if ($null -ne $profileError) {
    Write-Result -Status (Get-FailureStatus $profileError) -Title 'User profile' -Source 'Environment.SpecialFolder.UserProfile' -Scope 'current user' -Detail (Get-FailureDetail $profileError)
    Write-Result -Status 'NOT_RUN' -Title 'Profile top-level names' -Source 'Get-ChildItem' -Scope 'current user profile, top level' -Detail 'profile path unavailable'
    Write-Result -Status 'NOT_RUN' -Title '.ssh names and metadata' -Source 'Get-ChildItem' -Scope 'current user .ssh, top level' -Detail 'profile path unavailable'
} elseif ([string]::IsNullOrWhiteSpace($profilePath)) {
    Write-Result -Status 'NONE' -Title 'User profile' -Source 'Environment.SpecialFolder.UserProfile' -Scope 'current user' -Detail 'GetFolderPath returned no profile path'
    Write-Result -Status 'NOT_RUN' -Title 'Profile top-level names' -Source 'Get-ChildItem' -Scope 'current user profile, top level' -Detail 'profile path unavailable'
    Write-Result -Status 'NOT_RUN' -Title '.ssh names and metadata' -Source 'Get-ChildItem' -Scope 'current user .ssh, top level' -Detail 'profile path unavailable'
} else {
    Write-Result -Status 'FOUND' -Title 'User profile' -Source 'Environment.SpecialFolder.UserProfile' -Scope 'current user' -Lines @($profilePath)
    try {
        $profileItems = @(Get-ChildItem -LiteralPath $profilePath -Force -ErrorAction Stop | Sort-Object Name)
        $profileNames = @($profileItems | Select-Object -First 100 | ForEach-Object {
            if ($_.PSIsContainer) { '[dir] {0}' -f $_.Name } else { '[file] {0}' -f $_.Name }
        })
        $profileStatus = if ($profileItems.Count -gt 0) { 'FOUND' } else { 'NONE' }
        $profileNotShown = $profileItems.Count - $profileNames.Count
        $profileDisplay = if ($profileNotShown -gt 0) { 'TRUNCATED' } else { 'COMPLETE' }
        Write-Result -Status $profileStatus -Title 'Profile top-level names' -Source 'Get-ChildItem' -Scope 'current user profile, top level' -Lines $profileNames -Detail ('entries: {0}; shown: {1}; not shown: {2}; display: {3}' -f $profileItems.Count, $profileNames.Count, $profileNotShown, $profileDisplay)
    } catch {
        Write-Result -Status (Get-FailureStatus $_) -Title 'Profile top-level names' -Source 'Get-ChildItem' -Scope 'current user profile, top level' -Detail (Get-FailureDetail $_)
    }
    $sshPath = Join-Path -Path $profilePath -ChildPath '.ssh'
    try {
        if (-not (Test-Path -LiteralPath $sshPath -PathType Container -ErrorAction Stop)) {
            Write-Result -Status 'NONE' -Title '.ssh names and metadata' -Source 'Get-ChildItem' -Scope 'current user .ssh, top level' -Detail '.ssh directory absent'
        } else {
            $sshItems = @(Get-ChildItem -LiteralPath $sshPath -Force -ErrorAction Stop | Sort-Object Name)
            $sshNames = @($sshItems | Select-Object -First 100 | ForEach-Object {
                if ($_.PSIsContainer) {
                    '[dir] {0}; modified={1}' -f $_.Name, $_.LastWriteTime.ToString('o')
                } else {
                    '[file] {0}; bytes={1}; modified={2}' -f $_.Name, $_.Length, $_.LastWriteTime.ToString('o')
                }
            })
            $sshNotShown = $sshItems.Count - $sshNames.Count
            $sshDisplay = if ($sshNotShown -gt 0) { 'TRUNCATED' } else { 'COMPLETE' }
            Write-Result -Status 'FOUND' -Title '.ssh names and metadata' -Source 'Get-ChildItem' -Scope 'current user .ssh, top level' -Lines $sshNames -Detail ('directory exists; entries: {0}; shown: {1}; not shown: {2}; display: {3}' -f $sshItems.Count, $sshNames.Count, $sshNotShown, $sshDisplay)
        }
    } catch {
        Write-Result -Status (Get-FailureStatus $_) -Title '.ssh names and metadata' -Source 'Get-ChildItem' -Scope 'current user .ssh, top level' -Detail (Get-FailureDetail $_)
    }
}

$localAppDataPath = ''
$localAppDataError = $null
try { $localAppDataPath = [Environment]::GetFolderPath([Environment+SpecialFolder]::LocalApplicationData) } catch { $localAppDataError = $_ }
if ($null -ne $localAppDataError) {
    Write-Result -Status (Get-FailureStatus $localAppDataError) -Title 'Sticky Notes database path' -Source 'Environment.SpecialFolder.LocalApplicationData' -Scope 'current user' -Detail (Get-FailureDetail $localAppDataError)
} elseif ([string]::IsNullOrWhiteSpace($localAppDataPath)) {
    Write-Result -Status 'NOT_RUN' -Title 'Sticky Notes database path' -Source 'Test-Path' -Scope 'current user, fixed package path' -Detail 'LocalApplicationData path unavailable'
} else {
    $stickyNotesPath = Join-Path -Path $localAppDataPath -ChildPath 'Packages\Microsoft.MicrosoftStickyNotes_8wekyb3d8bbwe\LocalState\plum.sqlite'
    try {
        if (Test-Path -LiteralPath $stickyNotesPath -PathType Leaf -ErrorAction Stop) {
            Write-Result -Status 'FOUND' -Title 'Sticky Notes database path' -Source 'Test-Path' -Scope 'current user, fixed package path' -Lines @($stickyNotesPath)
        } else {
            Write-Result -Status 'NONE' -Title 'Sticky Notes database path' -Source 'Test-Path' -Scope 'current user, fixed package path' -Detail 'plum.sqlite absent at this path'
        }
    } catch {
        Write-Result -Status (Get-FailureStatus $_) -Title 'Sticky Notes database path' -Source 'Test-Path' -Scope 'current user, fixed package path' -Detail (Get-FailureDetail $_)
    }
}

$cmdkey = Invoke-NativeRead -Name 'cmdkey.exe' -Arguments @('/list') -SuccessStatus 'QUERY_OK'
Write-Result -Status $cmdkey.Status -Title 'Credential Manager metadata' -Source 'cmdkey /list' -Scope 'current user store; targets and account names' -Lines $cmdkey.Lines -Detail $cmdkey.Detail

try {
    $environment = [Environment]::GetEnvironmentVariables('Process')
    $environmentLines = @($environment.Keys | Sort-Object | ForEach-Object {
        $name = [string]$_
        $encodedName = ConvertTo-OneLineJsonString -Value $name
        if ($EnvironmentNamesOnly) {
            $encodedName
        } else {
            $encodedValue = ConvertTo-OneLineJsonString -Value ([string]$environment[$name])
            '{0}={1}' -f $encodedName, $encodedValue
        }
    })
    $envStatus = if ($environmentLines.Count -gt 0) { 'FOUND' } else { 'NONE' }
    $envScope = if ($EnvironmentNamesOnly) { 'current PowerShell process; all names only' } else { 'current PowerShell process; all names and values' }
    Write-Result -Status $envStatus -Title 'Environment variables' -Source "Environment.GetEnvironmentVariables('Process')" -Scope $envScope -Lines $environmentLines -Detail ('variables: {0}' -f $environmentLines.Count)
} catch {
    Write-Result -Status (Get-FailureStatus $_) -Title 'Environment variables' -Source "Environment.GetEnvironmentVariables('Process')" -Scope 'current PowerShell process' -Detail (Get-FailureDetail $_)
}
