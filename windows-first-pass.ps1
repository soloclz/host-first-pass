#requires -Version 5.1
<#
.SYNOPSIS
    Fixed, read-only first pass for a new Windows host.
.DESCRIPTION
    Prints the current token, OS and UAC policy, running process names and PIDs, logon
    sessions, current logon session Kerberos tickets, local network endpoints
    and their process/service owners, plus a few current-user credential-source
    clues. By default, also prints all current-process environment variable
    names and values. No recursive file searches, network calls, or files are
    produced by this script.
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
        [ValidateSet('FOUND', 'NONE', 'QUERY_OK', 'DENIED', 'ERROR', 'UNAVAILABLE', 'NOT_RUN')]
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
    $LASTEXITCODE = $null
    try {
        $lines = @(& $Name @Arguments 2>&1 | ForEach-Object { [string]$_ })
        $exitCode = $LASTEXITCODE
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
            $message = Format-SafeText $lines[0]
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
        $path = if ($process.ExecutablePath) { [string]$process.ExecutablePath } else { '(path unavailable)' }
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
    return ('{0} {1}:{2} PID={3} process={4} service={5}' -f $Protocol, $address,
        $Endpoint.LocalPort, $endpointProcessId, $processText, $serviceText)
}

$runTime = Get-Date -Format 'yyyy-MM-ddTHH:mm:sszzz'
$hostName = [Environment]::MachineName
$identityName = '(unavailable)'
try { $identityName = [Security.Principal.WindowsIdentity]::GetCurrent().Name } catch { }
Write-Output 'Windows first pass'
Write-Output ('Time: {0} | Host: {1} | Identity: {2}' -f $runTime, $hostName, $identityName)
Write-Output 'Scope: local host, current token, logon session and user profile; TCP Listen and bound UDP endpoints.'
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

Write-Section 'Running processes'
$tasklist = Invoke-NativeRead -Name 'tasklist.exe' -Arguments @('/fo', 'csv', '/nh')
if ($tasklist.Status -notin @('FOUND', 'NONE')) {
    Write-Result -Status $tasklist.Status -Title 'Process names and PIDs' -Source 'tasklist /fo csv /nh' -Scope 'local host' -Detail $tasklist.Detail
} elseif ($tasklist.Status -eq 'NONE') {
    Write-Result -Status 'NONE' -Title 'Process names and PIDs' -Source 'tasklist /fo csv /nh' -Scope 'local host' -Detail 'no rows returned'
} else {
    try {
        $taskRows = @($tasklist.Lines | ConvertFrom-Csv -Header @('ImageName', 'PID', 'SessionName', 'SessionNumber', 'MemoryUsage') -ErrorAction Stop)
        if ($taskRows.Count -ne $tasklist.Lines.Count) { throw 'Unexpected tasklist CSV row count.' }
        $runningProcessLines = @($taskRows | ForEach-Object {
            $pidText = ([string]$_.PID).Trim()
            if ([string]::IsNullOrWhiteSpace($_.ImageName) -or $pidText -notmatch '^\d+$') {
                throw 'Unexpected tasklist CSV fields.'
            }
            'PID={0} name={1}' -f $pidText, $_.ImageName
        })
        Write-Result -Status 'FOUND' -Title 'Process names and PIDs' -Source 'tasklist /fo csv /nh' -Scope 'local host' -Lines $runningProcessLines -Detail ('processes: {0}' -f $runningProcessLines.Count)
    } catch {
        Write-Result -Status 'ERROR' -Title 'Process names and PIDs' -Source 'tasklist /fo csv /nh' -Scope 'local host' -Detail 'unexpected tasklist CSV; no process rows shown'
    }
}

Write-Section 'Logon sessions'
$sessions = Invoke-NativeRead -Name 'quser.exe'
Write-Result -Status $sessions.Status -Title 'User sessions' -Source 'quser' -Scope 'local host' -Lines $sessions.Lines -Detail $sessions.Detail

Write-Section 'Kerberos tickets'
$tickets = Invoke-NativeRead -Name 'klist.exe' -SuccessStatus 'QUERY_OK'
Write-Result -Status $tickets.Status -Title 'Cached tickets' -Source 'klist' -Scope 'current logon session' -Lines $tickets.Lines -Detail $tickets.Detail

Write-Section 'Network endpoints and owners'
$tcpEndpoints = @()
$udpEndpoints = @()
$tcpStatus = 'NOT_RUN'
$udpStatus = 'NOT_RUN'
$tcpDetail = ''
$udpDetail = ''

if (Test-AvailableCommand 'Get-NetTCPConnection') {
    try {
        $tcpEndpoints = @(Get-NetTCPConnection -ErrorAction Stop | Where-Object { $_.State -eq 'Listen' })
        $tcpStatus = if ($tcpEndpoints.Count -gt 0) { 'FOUND' } else { 'NONE' }
    } catch {
        $tcpStatus = Get-FailureStatus $_
        $tcpDetail = Get-FailureDetail $_
    }
} else {
    $tcpStatus = 'UNAVAILABLE'
    $tcpDetail = 'Get-NetTCPConnection not installed'
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
$endpointIds = @{}
foreach ($endpoint in @($tcpEndpoints) + @($udpEndpoints)) {
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
            $processDetail = 'linked process records: {0}' -f $processes.Count
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
$udpLines = @($udpEndpoints | Sort-Object LocalPort, LocalAddress, OwningProcess | ForEach-Object {
    Format-Endpoint -Endpoint $_ -Protocol 'UDP' -Processes $processes -Services $services -ProcessStatus $processStatus -ServiceStatus $serviceStatus
})
$tcpReportDetail = if ($tcpStatus -in @('FOUND', 'NONE')) { 'count: {0}' -f $tcpEndpoints.Count } else { $tcpDetail }
$udpReportDetail = if ($udpStatus -in @('FOUND', 'NONE')) { 'count: {0}' -f $udpEndpoints.Count } else { $udpDetail }
Write-Result -Status $tcpStatus -Title 'TCP listeners' -Source 'Get-NetTCPConnection (State=Listen)' -Scope 'all local addresses' -Lines $tcpLines -Detail $tcpReportDetail
Write-Result -Status $udpStatus -Title 'UDP bindings' -Source 'Get-NetUDPEndpoint' -Scope 'all local addresses' -Lines $udpLines -Detail $udpReportDetail
Write-Result -Status $processStatus -Title 'Process owner lookup' -Source 'Win32_Process' -Scope 'endpoint PIDs only' -Detail $processDetail
Write-Result -Status $serviceStatus -Title 'Service owner lookup' -Source 'Win32_Service' -Scope 'endpoint PIDs only' -Detail $serviceDetail

Write-Section 'Current-user credential-source clues'
$profilePath = ''
$profileError = $null
try { $profilePath = [Environment]::GetFolderPath([Environment+SpecialFolder]::UserProfile) } catch { $profileError = $_ }
if ($null -ne $profileError) {
    Write-Result -Status (Get-FailureStatus $profileError) -Title 'User profile' -Source 'Environment.SpecialFolder.UserProfile' -Scope 'current user' -Detail (Get-FailureDetail $profileError)
    Write-Result -Status 'NOT_RUN' -Title 'Profile top-level names' -Source 'Get-ChildItem' -Scope 'current user profile, top level' -Detail 'profile path unavailable'
    Write-Result -Status 'NOT_RUN' -Title '.ssh names and metadata' -Source 'Get-ChildItem' -Scope 'current user .ssh, top level' -Detail 'profile path unavailable'
} elseif ([string]::IsNullOrWhiteSpace($profilePath)) {
    Write-Result -Status 'ERROR' -Title 'User profile' -Source 'Environment.SpecialFolder.UserProfile' -Scope 'current user' -Detail 'profile path unavailable'
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
        Write-Result -Status $profileStatus -Title 'Profile top-level names' -Source 'Get-ChildItem' -Scope 'current user profile, top level' -Lines $profileNames -Detail ('entries: {0}; shown: {1}' -f $profileItems.Count, $profileNames.Count)
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
            Write-Result -Status 'FOUND' -Title '.ssh names and metadata' -Source 'Get-ChildItem' -Scope 'current user .ssh, top level' -Lines $sshNames -Detail ('directory exists; entries: {0}; shown: {1}' -f $sshItems.Count, $sshNames.Count)
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
