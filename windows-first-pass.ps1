#requires -Version 5.1
<#
.SYNOPSIS
    Read-only host snapshot and selected local file searches for Windows PowerShell 5.1.
.DESCRIPTION
    Prints the current token, host role, local accounts, services, scheduled tasks,
    network and drive inventory, OS build and QFE records, UAC and Windows Installer
    policy, running processes, logon sessions, Kerberos tickets, and current-user
    credential-source clues. By default, also prints all current-process
    environment variable names and values. File search categories run only
    when selected. No remote network calls or output files are produced.
.PARAMETER SearchPath
    Limit a selected file search to this absolute local directory (-p).
.PARAMETER FullOutput
    Print every observed file search match instead of the capped display.
.PARAMETER SearchSeconds
    Cooperative file search time limit, 90 seconds by default.
#>

[CmdletBinding()]
param(
    [Alias('n')][switch]$CredentialNames,
    [Alias('c')][switch]$ConfigNames,
    [Alias('s')][switch]$ScriptNames,
    [Alias('a')][switch]$ArchiveNames,
    [Alias('k')][switch]$CredentialContent,
    [Alias('p')][string]$SearchPath,
    [switch]$FullOutput,
    [ValidateRange(1, 3600)][int]$SearchSeconds = 90
)

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

# The five selected categories share one local file traversal. -FullOutput
# removes the display cap, not the time limit.

function New-SearchCategory {
    param([string]$Flag, [string]$Title)
    return [pscustomobject]@{
        Flag = $Flag
        Title = $Title
        Matched = 0
        Shown = 0
        BytesShown = 0
        DisplayClosed = $false
        Lines = (New-Object 'System.Collections.Generic.List[string]')
    }
}

function Add-SearchHit {
    param([psobject]$Category, [string]$Path, [bool]$Uncapped)
    $Category.Matched++
    $line = Format-SafeText $Path
    if ($Uncapped) {
        $Category.Shown++
        Write-Output ('  [{0}] {1}' -f $Category.Flag, $line)
        return
    }
    if ($Category.DisplayClosed) { return }
    $byteCount = [Text.Encoding]::UTF8.GetByteCount($line + "`n")
    if ($Category.Shown -ge 500 -or ($Category.BytesShown + $byteCount) -gt 131072) {
        $Category.DisplayClosed = $true
        return
    }
    [void]$Category.Lines.Add($line)
    $Category.Shown++
    $Category.BytesShown += $byteCount
}

function Invoke-OptionalFileSearch {
    [CmdletBinding()]
    param(
        [Alias('n')][switch]$CredentialNames,
        [Alias('c')][switch]$ConfigNames,
        [Alias('s')][switch]$ScriptNames,
        [Alias('a')][switch]$ArchiveNames,
        [Alias('k')][switch]$CredentialContent,
        [Alias('p')][string]$SearchPath,
        [switch]$FullOutput,
        [ValidateRange(1, 3600)][int]$SearchSeconds = 90
    )

    if (-not ($CredentialNames -or $ConfigNames -or $ScriptNames -or
              $ArchiveNames -or $CredentialContent)) {
        throw 'Choose at least one file search category: -n, -c, -s, -a, or -k.'
    }

    $categories = New-Object 'System.Collections.Generic.List[object]'
    if ($CredentialNames) { [void]$categories.Add((New-SearchCategory 'n' 'Credential-related filenames')) }
    if ($ConfigNames) { [void]$categories.Add((New-SearchCategory 'c' 'Configuration filenames')) }
    if ($ScriptNames) { [void]$categories.Add((New-SearchCategory 's' 'Script and source filenames')) }
    if ($ArchiveNames) { [void]$categories.Add((New-SearchCategory 'a' 'History, backup, log and database filenames')) }
    if ($CredentialContent) { [void]$categories.Add((New-SearchCategory 'k' 'Credential-like text in small files')) }
    $byFlag = @{}
    foreach ($category in $categories) { $byFlag[$category.Flag] = $category }

    $roots = New-Object 'System.Collections.Generic.List[string]'
    if ($PSBoundParameters.ContainsKey('SearchPath')) {
        if ($SearchPath -notmatch '^[A-Za-z]:[\\/]') {
            throw '-p requires an absolute local drive path, for example C:\inetpub\wwwroot.'
        }
        $fullPath = [IO.Path]::GetFullPath($SearchPath)
        if (-not [IO.Directory]::Exists($fullPath)) {
            throw ('-p is not an existing directory: {0}' -f (Format-SafeText $fullPath))
        }
        $drive = New-Object IO.DriveInfo ([IO.Path]::GetPathRoot($fullPath))
        if ($drive.DriveType -notin @([IO.DriveType]::Fixed, [IO.DriveType]::Removable)) {
            throw '-p must be on a local fixed or removable drive; network and UNC paths are excluded.'
        }
        # A selected path behind a junction could silently leave the local drive.
        $ancestor = New-Object IO.DirectoryInfo $fullPath
        while ($null -ne $ancestor) {
            if (($ancestor.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0) {
                throw ('-p resolves through a reparse point: {0}' -f (Format-SafeText $ancestor.FullName))
            }
            $ancestor = $ancestor.Parent
        }
        [void]$roots.Add($fullPath)
    } else {
        foreach ($drive in [IO.DriveInfo]::GetDrives()) {
            try {
                if ($drive.DriveType -eq [IO.DriveType]::Fixed -and $drive.IsReady) {
                    [void]$roots.Add($drive.RootDirectory.FullName)
                }
            } catch {
                # A drive that cannot report readiness is not a ready root.
                # A selected -p path can be used to inspect it explicitly.
            }
        }
        if ($roots.Count -eq 0) { throw 'No ready fixed local drive root is available for file search.' }
    }

    $regexOptions = [Text.RegularExpressions.RegexOptions]::IgnoreCase -bor [Text.RegularExpressions.RegexOptions]::CultureInvariant
    $namePatterns = @{}
    if ($CredentialNames) {
        $namePatterns['n'] = [regex]::new(
            'password|passwd|passphrase|secret|credential|token|note|unattend|sysprep|^\.env(?:\..*)?$|^\.netrc$|^\.git-credentials$|^\.pgpass$|^\.my\.cnf$|^id_(?:rsa|dsa|ecdsa|ed25519)$|^(?:sam|security|system)$|^(?:groups|services|scheduledtasks|datasources|drives|printers)\.xml$|\.(?:kdbx|pfx|p12|pem|ppk|keytab|ccache)$', $regexOptions)
    }
    if ($ConfigNames) {
        $namePatterns['c'] = [regex]::new(
            '\.(?:conf|config|ini|yaml|yml|json|xml|toml|properties)$|^config$|^\.env(?:\..*)?$', $regexOptions)
    }
    if ($ScriptNames) {
        $namePatterns['s'] = [regex]::new(
            '\.(?:ps1|psm1|psd1|bat|cmd|vbs|vbe|js|jse|wsf|wsh|hta|py|pl|rb|php|asp|aspx|cshtml|vbhtml|jsp|cfm|cs|vb|go|java|ts|jsx|tsx|sh|bash)$', $regexOptions)
    }
    if ($ArchiveNames) {
        $namePatterns['a'] = [regex]::new(
            '(?:^|[._-])(?:history|hist)(?:[._-]|$)|backup|\.(?:bak|backup|old|orig|save|log|evtx|sql|sqlite|sqlite3|db|mdb|accdb|edb|zip|7z|rar|tar|gz)$', $regexOptions)
    }
    if ($CredentialContent) {
        $contentPattern = [regex]::new(
            'password|passwd|passphrase|secret|token|credential|api[ _-]*key|private[ _-]*key|connection[ _-]*string|(?<![A-Za-z0-9])(?:pass|pwd)\s*[''"]?\s*[:=]',
            $regexOptions, [TimeSpan]::FromMilliseconds(100))
    }

    $scope = [string]::Join(', ', [string[]]$roots.ToArray())
    Write-Output ''
    Write-Output '=== Optional file search ==='
    Write-Output ('Scope: {0}; one traversal; no nested reparse points; {1}s cooperative time limit; content files <131072 bytes.' -f
        (Format-SafeText $scope), $SearchSeconds)
    if ($FullOutput) {
        Write-Output 'Full output: each observed match is printed with its category flag as it is found.'
    }

    $pending = New-Object 'System.Collections.Generic.Stack[string]'
    foreach ($root in $roots) { $pending.Push($root) }
    $clock = [Diagnostics.Stopwatch]::StartNew()
    $directories = 0
    $files = 0
    $reparseSkipped = 0
    $denied = 0
    $errors = 0
    $contentDenied = 0
    $contentErrors = 0
    $contentTooLarge = 0
    $contentBinary = 0
    $timedOut = $false
    $failureSamples = New-Object 'System.Collections.Generic.List[string]'

    while ($pending.Count -gt 0) {
        if ($clock.Elapsed.TotalSeconds -ge $SearchSeconds) { $timedOut = $true; break }
        $directoryPath = $pending.Pop()
        $directories++
        try {
            $entries = (New-Object IO.DirectoryInfo $directoryPath).GetFileSystemInfos()
        } catch {
            $kind = Get-FailureStatus $_
            if ($kind -eq 'DENIED') { $denied++ } else { $errors++ }
            if ($failureSamples.Count -lt 5) {
                [void]$failureSamples.Add(('{0}: {1}' -f $kind, (Format-SafeText $directoryPath)))
            }
            continue
        }
        foreach ($entry in $entries) {
            if ($clock.Elapsed.TotalSeconds -ge $SearchSeconds) { $timedOut = $true; break }
            try {
                $attributes = $entry.Attributes
                if (($attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0) {
                    $reparseSkipped++
                    continue
                }
                if ($entry -is [IO.DirectoryInfo]) {
                    $pending.Push($entry.FullName)
                    continue
                }
                if ($entry -isnot [IO.FileInfo]) { continue }
                $files++
                $filename = $entry.Name
                $filenamePath = $entry.FullName
                foreach ($flag in @('n', 'c', 's', 'a')) {
                    if ($byFlag.ContainsKey($flag) -and $namePatterns[$flag].IsMatch($filename)) {
                        Add-SearchHit -Category $byFlag[$flag] -Path $filenamePath -Uncapped ([bool]$FullOutput)
                    }
                }
                if (-not $CredentialContent) { continue }
                # Recheck size on the opened handle because a file can grow after listing.
                if ($entry.Length -ge 131072) { $contentTooLarge++; continue }
                $stream = $null
                try {
                    $share = [IO.FileShare]::ReadWrite -bor [IO.FileShare]::Delete
                    $stream = [IO.File]::Open($filenamePath, [IO.FileMode]::Open, [IO.FileAccess]::Read, $share)
                    if ($stream.Length -ge 131072) { $contentTooLarge++; continue }
                    if ($stream.Length -eq 0) { continue }
                    $bytes = New-Object byte[] ([int]$stream.Length)
                    $read = 0
                    while ($read -lt $bytes.Length) {
                        $count = $stream.Read($bytes, $read, $bytes.Length - $read)
                        if ($count -eq 0) { break }
                        $read += $count
                    }
                    if ($read -ge 2 -and $bytes[0] -eq 255 -and $bytes[1] -eq 254) {
                        $body = [Text.Encoding]::Unicode.GetString($bytes, 2, $read - 2)
                    } elseif ($read -ge 2 -and $bytes[0] -eq 254 -and $bytes[1] -eq 255) {
                        $body = [Text.Encoding]::BigEndianUnicode.GetString($bytes, 2, $read - 2)
                    } else {
                        $body = [Text.Encoding]::UTF8.GetString($bytes, 0, $read)
                    }
                    if ($body.IndexOf([char]0) -ge 0) { $contentBinary++; continue }
                    if ($contentPattern.IsMatch($body)) {
                        Add-SearchHit -Category $byFlag['k'] -Path $filenamePath -Uncapped ([bool]$FullOutput)
                    }
                } catch {
                    $kind = Get-FailureStatus $_
                    if ($kind -eq 'DENIED') { $contentDenied++ } else { $contentErrors++ }
                    if ($failureSamples.Count -lt 5) {
                        [void]$failureSamples.Add(('{0} reading: {1}' -f $kind, (Format-SafeText $filenamePath)))
                    }
                } finally {
                    if ($null -ne $stream) { $stream.Dispose() }
                }
            } catch {
                $kind = Get-FailureStatus $_
                if ($kind -eq 'DENIED') { $denied++ } else { $errors++ }
                if ($failureSamples.Count -lt 5) {
                    [void]$failureSamples.Add(('{0}: {1}' -f $kind, (Format-SafeText $entry.FullName)))
                }
            }
        }
        if ($timedOut) { break }
    }
    $clock.Stop()

    foreach ($category in $categories) {
        $categoryDenied = $denied
        $categoryErrors = $errors
        if ($category.Flag -eq 'k') {
            $categoryDenied += $contentDenied
            $categoryErrors += $contentErrors
        }
        $categoryIncomplete = ($timedOut -or $categoryDenied -gt 0 -or $categoryErrors -gt 0)
        $status = if ($categoryIncomplete) { 'INCOMPLETE' } elseif ($category.Matched -gt 0) { 'FOUND' } else { 'NONE' }
        $undisplayed = $category.Matched - $category.Shown
        Write-Output ('[{0}] {1} | source: local file traversal (-{2}) | scope: {3}; matched={4}; shown={5}; undisplayed-observed={6}; unscanned={7}; denied={8}; errors={9}; display={10}' -f
            $status, $category.Title, $category.Flag, (Format-SafeText $scope),
            $category.Matched, $category.Shown, $undisplayed,
            $(if ($categoryIncomplete) { 'unknown' } else { '0' }),
            $categoryDenied, $categoryErrors,
            $(if ($undisplayed -gt 0) { 'TRUNCATED' } else { 'COMPLETE' }))
        if (-not $FullOutput) {
            foreach ($line in $category.Lines) { Write-Output ('  {0}' -f $line) }
        }
        if ($undisplayed -gt 0) {
            $scriptName = if ($PSCommandPath) { $PSCommandPath } else { '.\windows-first-pass.ps1' }
            $rerun = 'powershell.exe -NoProfile -File "{0}" -{1} -FullOutput' -f $scriptName, $category.Flag
            if ($PSBoundParameters.ContainsKey('SearchPath')) {
                $rerun += (' -p "{0}"' -f $SearchPath)
            }
            if ($SearchSeconds -ne 90) { $rerun += " -SearchSeconds $SearchSeconds" }
            Write-Output ('  full-output command: {0}' -f $rerun)
        }
    }
    if ($denied -gt 0 -or $contentDenied -gt 0) {
        Write-Output ('[DENIED] File search access | directories/metadata={0}; content reads={1}' -f $denied, $contentDenied)
    }
    if ($errors -gt 0 -or $contentErrors -gt 0) {
        Write-Output ('[ERROR] File search operations | directories/metadata={0}; content reads={1}' -f $errors, $contentErrors)
    }
    foreach ($sample in $failureSamples) { Write-Output ('  sample: {0}' -f $sample) }
    if ($timedOut) {
        Write-Output ('[INCOMPLETE] File search time limit | {0}s elapsed; unvisited directories and files were not counted' -f $SearchSeconds)
        $retrySeconds = [Math]::Min(3600, [Math]::Max(90, $SearchSeconds * 2))
        if ($retrySeconds -gt $SearchSeconds) {
            $scriptName = if ($PSCommandPath) { $PSCommandPath } else { '.\windows-first-pass.ps1' }
            $retry = 'powershell.exe -NoProfile -File "{0}"' -f $scriptName
            foreach ($category in $categories) { $retry += " -$($category.Flag)" }
            if ($PSBoundParameters.ContainsKey('SearchPath')) {
                $retry += (' -p "{0}"' -f $SearchPath)
            }
            $retry += " -SearchSeconds $retrySeconds"
            Write-Output ('  retry with a longer time limit: {0}' -f $retry)
        }
    }
    Write-Output ('Search totals: directories={0}; files={1}; reparse-points-skipped={2}; content-too-large={3}; binary-content-skipped={4}; elapsed={5:N1}s' -f
        $directories, $files, $reparseSkipped, $contentTooLarge, $contentBinary, $clock.Elapsed.TotalSeconds)
}

$runTime = Get-Date -Format 'yyyy-MM-ddTHH:mm:sszzz'
$hostName = [Environment]::MachineName
$identityName = '(unavailable)'
try { $identityName = [Security.Principal.WindowsIdentity]::GetCurrent().Name } catch { }
$selectedFileSearch = ($CredentialNames -or $ConfigNames -or $ScriptNames -or
    $ArchiveNames -or $CredentialContent)
if (-not $selectedFileSearch -and
    ($PSBoundParameters.ContainsKey('SearchPath') -or $FullOutput -or
     $PSBoundParameters.ContainsKey('SearchSeconds'))) {
    throw '-p, -FullOutput and -SearchSeconds require at least one category: -n, -c, -s, -a or -k.'
}
if ($selectedFileSearch) {
    Write-Output 'Windows first pass: selected file searches'
    Write-Output ('Time: {0} | Host: {1} | Identity: {2}' -f $runTime, $hostName, $identityName)
    $searchArguments = @{
        CredentialNames = $CredentialNames
        ConfigNames = $ConfigNames
        ScriptNames = $ScriptNames
        ArchiveNames = $ArchiveNames
        CredentialContent = $CredentialContent
        FullOutput = $FullOutput
        SearchSeconds = $SearchSeconds
    }
    if ($PSBoundParameters.ContainsKey('SearchPath')) { $searchArguments.SearchPath = $SearchPath }
    Invoke-OptionalFileSearch @searchArguments
    return
}
Write-Output 'Windows first pass'
Write-Output ('Time: {0} | Host: {1} | Identity: {2}' -f $runTime, $hostName, $identityName)
Write-Output 'Scope: local host, current token, logon session and user profile; local network and drive inventory.'
Write-Output 'Environment mode: all current PowerShell process names and values (JSON-escaped).'

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

Write-Section 'Host role, local accounts and shares'
$domainRole = $null
if (-not (Test-AvailableCommand 'Get-CimInstance')) {
    Write-Result -Status 'UNAVAILABLE' -Title 'Host role' -Source 'Win32_ComputerSystem' -Scope 'local host' -Detail 'Get-CimInstance not installed'
} else {
    try {
        $computer = Get-CimInstance -ClassName Win32_ComputerSystem -Property Name, DomainRole, PartOfDomain, Domain -ErrorAction Stop
        if ($null -eq $computer) {
            Write-Result -Status 'NONE' -Title 'Host role' -Source 'Win32_ComputerSystem' -Scope 'local host'
        } else {
            $domainRole = [int]$computer.DomainRole
            $roleName = switch ($domainRole) {
                0 { 'standalone workstation' }
                1 { 'member workstation' }
                2 { 'standalone server' }
                3 { 'member server' }
                4 { 'backup domain controller' }
                5 { 'primary domain controller' }
                default { 'unrecognized' }
            }
            Write-Result -Status 'FOUND' -Title 'Host role' -Source 'Win32_ComputerSystem' -Scope 'local host' -Lines @(
                ('name={0}; domain={1}; joined={2}; DomainRole={3} ({4})' -f $computer.Name, $computer.Domain, $computer.PartOfDomain, $domainRole, $roleName)
            )
        }
    } catch {
        Write-Result -Status (Get-FailureStatus $_) -Title 'Host role' -Source 'Win32_ComputerSystem' -Scope 'local host' -Detail (Get-FailureDetail $_)
    }
}

foreach ($accountClass in @('Win32_UserAccount', 'Win32_Group')) {
    $title = if ($accountClass -eq 'Win32_UserAccount') { 'Local user accounts' } else { 'Local groups' }
    if ($domainRole -in @(4, 5)) {
        Write-Result -Status 'NOT_RUN' -Title $title -Source $accountClass -Scope 'local SAM' -Detail 'domain controller; no local SAM account inventory'
    } elseif (-not (Test-AvailableCommand 'Get-CimInstance')) {
        Write-Result -Status 'UNAVAILABLE' -Title $title -Source $accountClass -Scope 'local SAM' -Detail 'Get-CimInstance not installed'
    } else {
        try {
            $accounts = @(Get-CimInstance -ClassName $accountClass -Filter 'LocalAccount = TRUE' -ErrorAction Stop)
            $accountLines = @($accounts | Sort-Object Name | ForEach-Object {
                if ($accountClass -eq 'Win32_UserAccount') {
                    'name={0}; SID={1}; disabled={2}; lockout={3}' -f $_.Name, $_.SID, $_.Disabled, $_.Lockout
                } else {
                    'name={0}; SID={1}; description={2}' -f $_.Name, $_.SID, $_.Description
                }
            })
            $accountStatus = if ($accounts.Count -gt 0) { 'FOUND' } else { 'NONE' }
            Write-Result -Status $accountStatus -Title $title -Source $accountClass -Scope 'local SAM only' -Lines $accountLines -Detail ('records: {0}' -f $accounts.Count)
        } catch {
            Write-Result -Status (Get-FailureStatus $_) -Title $title -Source $accountClass -Scope 'local SAM only' -Detail (Get-FailureDetail $_)
        }
    }
}

if (-not (Test-AvailableCommand 'Get-CimInstance')) {
    Write-Result -Status 'UNAVAILABLE' -Title 'Local shares' -Source 'Win32_Share' -Scope 'local host' -Detail 'Get-CimInstance not installed'
} else {
    try {
        $shareRows = @(Get-CimInstance -ClassName Win32_Share -ErrorAction Stop)
        $shareLines = @($shareRows | Sort-Object Name | ForEach-Object {
            'name={0}; path={1}; type={2}; description={3}' -f $_.Name, $_.Path, $_.Type, $_.Description
        })
        $shareStatus = if ($shareRows.Count -gt 0) { 'FOUND' } else { 'NONE' }
        Write-Result -Status $shareStatus -Title 'Local shares' -Source 'Win32_Share' -Scope 'local host; definitions, not access test' -Lines $shareLines -Detail ('records: {0}' -f $shareRows.Count)
    } catch {
        Write-Result -Status (Get-FailureStatus $_) -Title 'Local shares' -Source 'Win32_Share' -Scope 'local host' -Detail (Get-FailureDetail $_)
    }
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

Write-Section 'Services and scheduled tasks'
$allServiceRows = @()
$allServiceStatus = 'NOT_RUN'
$allServiceDetail = ''
if (-not (Test-AvailableCommand 'Get-CimInstance')) {
    $allServiceStatus = 'UNAVAILABLE'
    $allServiceDetail = 'Get-CimInstance not installed'
} else {
    try {
        $allServiceRows = @(Get-CimInstance -ClassName Win32_Service -Property Name, DisplayName, State, StartMode, StartName, PathName, ProcessId -ErrorAction Stop)
        $allServiceStatus = if ($allServiceRows.Count -gt 0) { 'FOUND' } else { 'NONE' }
        $allServiceDetail = 'records: {0}' -f $allServiceRows.Count
    } catch {
        $allServiceStatus = Get-FailureStatus $_
        $allServiceDetail = Get-FailureDetail $_
    }
}
$allServiceLines = @($allServiceRows | Sort-Object Name | ForEach-Object {
    'name={0}; display={1}; state={2}; start={3}; account={4}; PID={5}; command={6}' -f
        $_.Name, $_.DisplayName, $_.State, $_.StartMode, $_.StartName, $_.ProcessId, $_.PathName
})
Write-Result -Status $allServiceStatus -Title 'Service inventory' -Source 'Win32_Service' -Scope 'local host; all returned services' -Lines $allServiceLines -Detail $allServiceDetail

if (-not (Test-AvailableCommand 'Get-ScheduledTask')) {
    Write-Result -Status 'UNAVAILABLE' -Title 'Scheduled task inventory' -Source 'Get-ScheduledTask' -Scope 'local host' -Detail 'cmdlet not installed'
} else {
    try {
        $allTaskRows = @(Get-ScheduledTask -ErrorAction Stop)
        $allTaskLines = @($allTaskRows | Sort-Object TaskPath, TaskName | ForEach-Object {
            $taskName = '{0}{1}' -f $_.TaskPath, $_.TaskName
            $actions = @($_.Actions | Where-Object { $null -ne $_ })
            $triggers = @($_.Triggers | Where-Object { $null -ne $_ })
            'task={0}; state={1}; user={2}; group={3}; run_level={4}; logon_type={5}; actions={6}; triggers={7}' -f
                $taskName, $_.State, $_.Principal.UserId, $_.Principal.GroupId,
                $_.Principal.RunLevel, $_.Principal.LogonType, $actions.Count, $triggers.Count
            $index = 0
            foreach ($action in $actions) {
                $index++
                '  action[{0}] task={1}; type={2}; execute={3}; arguments={4}; working_directory={5}; class_id={6}' -f
                    $index, $taskName, $action.CimClass.CimClassName, $action.Execute,
                    $action.Arguments, $action.WorkingDirectory, $action.ClassId
            }
            $index = 0
            foreach ($trigger in $triggers) {
                $index++
                '  trigger[{0}] task={1}; type={2}; enabled={3}; start={4}; end={5}' -f
                    $index, $taskName, $trigger.CimClass.CimClassName, $trigger.Enabled,
                    $trigger.StartBoundary, $trigger.EndBoundary
            }
        })
        $taskStatus = if ($allTaskRows.Count -gt 0) { 'FOUND' } else { 'NONE' }
        Write-Result -Status $taskStatus -Title 'Scheduled task inventory' -Source 'Get-ScheduledTask' -Scope 'local host; all returned tasks; action and trigger summaries' -Lines $allTaskLines -Detail ('tasks: {0}; output lines: {1}; inspect a selected task for full trigger settings' -f $allTaskRows.Count, $allTaskLines.Count)
    } catch {
        Write-Result -Status (Get-FailureStatus $_) -Title 'Scheduled task inventory' -Source 'Get-ScheduledTask' -Scope 'local host' -Detail (Get-FailureDetail $_)
    }
}

Write-Section 'Logon sessions'
$sessions = Invoke-NativeRead -Name 'quser.exe'
Write-Result -Status $sessions.Status -Title 'User sessions' -Source 'quser' -Scope 'local host' -Lines $sessions.Lines -Detail $sessions.Detail

Write-Section 'Kerberos tickets'
$tickets = Invoke-NativeRead -Name 'klist.exe' -SuccessStatus 'QUERY_OK'
Write-Result -Status $tickets.Status -Title 'Cached tickets' -Source 'klist' -Scope 'current logon session' -Lines $tickets.Lines -Detail $tickets.Detail

Write-Section 'Network configuration'
$interfaces = Invoke-NativeRead -Name 'ipconfig.exe' -Arguments @('/all')
Write-Result -Status $interfaces.Status -Title 'Interface addresses and DNS' -Source 'ipconfig /all' -Scope 'local host; all reported adapters' -Lines $interfaces.Lines -Detail $interfaces.Detail
$routes = Invoke-NativeRead -Name 'route.exe' -Arguments @('print')
Write-Result -Status $routes.Status -Title 'IPv4 and IPv6 routes' -Source 'route print' -Scope 'local host; active and persistent routes' -Lines $routes.Lines -Detail $routes.Detail
if (Test-AvailableCommand 'Get-NetNeighbor') {
    try {
        $neighborRows = @(Get-NetNeighbor -ErrorAction Stop | Sort-Object InterfaceIndex, IPAddress)
        $neighborShown = @($neighborRows | Select-Object -First 100 | ForEach-Object {
            'interface={0}; IP={1}; link_layer={2}; state={3}' -f $_.InterfaceIndex, $_.IPAddress, $_.LinkLayerAddress, $_.State
        })
        $neighborStatus = if ($neighborRows.Count -gt 0) { 'FOUND' } else { 'NONE' }
        $neighborNotShown = $neighborRows.Count - $neighborShown.Count
        $neighborDisplay = if ($neighborNotShown -gt 0) { 'TRUNCATED' } else { 'COMPLETE' }
        Write-Result -Status $neighborStatus -Title 'Neighbor cache' -Source 'Get-NetNeighbor' -Scope 'local host; IPv4 and IPv6' -Lines $neighborShown -Detail ('entries: {0}; shown: {1}; not shown: {2}; display: {3}; full query: Get-NetNeighbor' -f $neighborRows.Count, $neighborShown.Count, $neighborNotShown, $neighborDisplay)
    } catch {
        Write-Result -Status (Get-FailureStatus $_) -Title 'Neighbor cache' -Source 'Get-NetNeighbor' -Scope 'local host; IPv4 and IPv6' -Detail (Get-FailureDetail $_)
    }
} else {
    $arp = Invoke-NativeRead -Name 'arp.exe' -Arguments @('-a')
    Write-Result -Status $arp.Status -Title 'Neighbor cache' -Source 'arp -a' -Scope 'local host; IPv4 ARP only' -Lines $arp.Lines -Detail $arp.Detail
}

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
        $processDetail = 'Get-CimInstance not installed'
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
    }
    if ($allServiceStatus -in @('FOUND', 'NONE')) {
        $serviceRows = @($allServiceRows | Where-Object { $endpointIds.ContainsKey([int]$_.ProcessId) })
        foreach ($service in $serviceRows) {
            $serviceProcessId = [int]$service.ProcessId
            if (-not $services.ContainsKey($serviceProcessId)) { $services[$serviceProcessId] = @() }
            $services[$serviceProcessId] += [string]$service.Name
        }
        $serviceStatus = if ($serviceRows.Count -gt 0) { 'FOUND' } else { 'NONE' }
        $serviceDetail = 'linked service records: {0}; reused all-services query' -f $serviceRows.Count
    } else {
        $serviceStatus = $allServiceStatus
        $serviceDetail = $allServiceDetail
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

Write-Section 'Logical drives and top-level names'
if (-not (Test-AvailableCommand 'Get-CimInstance')) {
    Write-Result -Status 'UNAVAILABLE' -Title 'Logical drives' -Source 'Win32_LogicalDisk' -Scope 'local host' -Detail 'Get-CimInstance not installed'
    Write-Result -Status 'NOT_RUN' -Title 'Fixed drive top-level names' -Source 'Get-ChildItem' -Scope 'local fixed drives only' -Detail 'drive inventory unavailable'
} else {
    try {
        $driveRows = @(Get-CimInstance -ClassName Win32_LogicalDisk -Property DeviceID, DriveType, FileSystem, VolumeName, Size, FreeSpace, ProviderName -ErrorAction Stop)
        $driveLines = @($driveRows | Sort-Object DeviceID | ForEach-Object {
            $typeName = switch ([int]$_.DriveType) {
                2 { 'removable' }
                3 { 'fixed' }
                4 { 'network' }
                5 { 'optical' }
                6 { 'RAM disk' }
                default { 'other' }
            }
            'drive={0}; type={1} ({2}); filesystem={3}; label={4}; size={5}; free={6}; provider={7}' -f
                $_.DeviceID, $_.DriveType, $typeName, $_.FileSystem, $_.VolumeName,
                $_.Size, $_.FreeSpace, $_.ProviderName
        })
        $driveStatus = if ($driveRows.Count -gt 0) { 'FOUND' } else { 'NONE' }
        Write-Result -Status $driveStatus -Title 'Logical drives' -Source 'Win32_LogicalDisk' -Scope 'local host; fixed, removable, optical and mapped drives' -Lines $driveLines -Detail ('records: {0}' -f $driveRows.Count)
        foreach ($drive in @($driveRows | Where-Object { $_.DriveType -eq 3 } | Sort-Object DeviceID)) {
            $driveRoot = '{0}\' -f $drive.DeviceID
            try {
                $topItems = @(Get-ChildItem -LiteralPath $driveRoot -Force -ErrorAction Stop | Sort-Object Name)
                $topShown = @($topItems | Select-Object -First 100 | ForEach-Object {
                    if ($_.PSIsContainer) { '[dir] {0}' -f $_.Name } else { '[file] {0}; bytes={1}' -f $_.Name, $_.Length }
                })
                $topStatus = if ($topItems.Count -gt 0) { 'FOUND' } else { 'NONE' }
                $topNotShown = $topItems.Count - $topShown.Count
                $topDisplay = if ($topNotShown -gt 0) { 'TRUNCATED' } else { 'COMPLETE' }
                Write-Result -Status $topStatus -Title 'Fixed drive top-level names' -Source 'Get-ChildItem -Force' -Scope $driveRoot -Lines $topShown -Detail ('entries: {0}; shown: {1}; not shown: {2}; display: {3}; full query: Get-ChildItem -LiteralPath ''{4}'' -Force' -f $topItems.Count, $topShown.Count, $topNotShown, $topDisplay, $driveRoot)
            } catch {
                Write-Result -Status (Get-FailureStatus $_) -Title 'Fixed drive top-level names' -Source 'Get-ChildItem -Force' -Scope $driveRoot -Detail (Get-FailureDetail $_)
            }
        }
    } catch {
        Write-Result -Status (Get-FailureStatus $_) -Title 'Logical drives' -Source 'Win32_LogicalDisk' -Scope 'local host' -Detail (Get-FailureDetail $_)
        Write-Result -Status 'NOT_RUN' -Title 'Fixed drive top-level names' -Source 'Get-ChildItem' -Scope 'local fixed drives only' -Detail 'drive inventory failed'
    }
}

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

if (-not (Test-AvailableCommand 'Get-PSReadLineOption')) {
    Write-Result -Status 'UNAVAILABLE' -Title 'PSReadLine history path and metadata' -Source 'Get-PSReadLineOption' -Scope 'current PowerShell user' -Detail 'cmdlet not installed or not available in this host'
} else {
    try {
        $readLineOptions = Get-PSReadLineOption -ErrorAction Stop
        $historyPath = [string]$readLineOptions.HistorySavePath
        if ([string]::IsNullOrWhiteSpace($historyPath)) {
            Write-Result -Status 'NONE' -Title 'PSReadLine history path and metadata' -Source 'Get-PSReadLineOption' -Scope 'current PowerShell user' -Detail ('no HistorySavePath reported; save_style={0}' -f $readLineOptions.HistorySaveStyle)
        } elseif (Test-Path -LiteralPath $historyPath -PathType Leaf -ErrorAction Stop) {
            $historyFile = Get-Item -LiteralPath $historyPath -ErrorAction Stop
            Write-Result -Status 'FOUND' -Title 'PSReadLine history path and metadata' -Source 'Get-PSReadLineOption; Get-Item' -Scope 'current PowerShell user; metadata only' -Lines @(
                ('path={0}; bytes={1}; modified={2}; save_style={3}' -f $historyFile.FullName, $historyFile.Length, $historyFile.LastWriteTime.ToString('o'), $readLineOptions.HistorySaveStyle)
            )
        } else {
            Write-Result -Status 'NONE' -Title 'PSReadLine history path and metadata' -Source 'Get-PSReadLineOption; Test-Path' -Scope 'current PowerShell user' -Lines @($historyPath) -Detail ('history file absent; save_style={0}' -f $readLineOptions.HistorySaveStyle)
        }
    } catch {
        Write-Result -Status (Get-FailureStatus $_) -Title 'PSReadLine history path and metadata' -Source 'Get-PSReadLineOption; Get-Item' -Scope 'current PowerShell user' -Detail (Get-FailureDetail $_)
    }
}

$cmdkey = Invoke-NativeRead -Name 'cmdkey.exe' -Arguments @('/list') -SuccessStatus 'QUERY_OK'
Write-Result -Status $cmdkey.Status -Title 'Credential Manager metadata' -Source 'cmdkey /list' -Scope 'current user store; targets and account names' -Lines $cmdkey.Lines -Detail $cmdkey.Detail

try {
    $environment = [Environment]::GetEnvironmentVariables('Process')
    $environmentLines = @($environment.Keys | Sort-Object | ForEach-Object {
        $name = [string]$_
        $encodedName = ConvertTo-OneLineJsonString -Value $name
        $encodedValue = ConvertTo-OneLineJsonString -Value ([string]$environment[$name])
        '{0}={1}' -f $encodedName, $encodedValue
    })
    $envStatus = if ($environmentLines.Count -gt 0) { 'FOUND' } else { 'NONE' }
    Write-Result -Status $envStatus -Title 'Environment variables' -Source "Environment.GetEnvironmentVariables('Process')" -Scope 'current PowerShell process; all names and values' -Lines $environmentLines -Detail ('variables: {0}' -f $environmentLines.Count)
} catch {
    Write-Result -Status (Get-FailureStatus $_) -Title 'Environment variables' -Source "Environment.GetEnvironmentVariables('Process')" -Scope 'current PowerShell process' -Detail (Get-FailureDetail $_)
}
