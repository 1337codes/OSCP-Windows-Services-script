param([switch]$NoColor)

# --- Output coloring ------------------------------------------------------
# Colors use Write-Host which does not emit to the pipeline. If you need to
# capture to a file, run:  .\services.ps1 -NoColor > out.txt
$script:UseColor = -not $NoColor

function Write-Colored {
    param([string]$Text, [string]$Color = 'Gray')
    if ($script:UseColor) { Write-Host $Text -ForegroundColor $Color }
    else                  { Write-Output $Text }
}
function Write-Blank    { if ($script:UseColor) { Write-Host '' } else { Write-Output '' } }
function Write-Header   { param([string]$t) Write-Colored $t 'Cyan' }
function Write-Rule     { param([string]$t) Write-Colored $t 'DarkGray' }
function Write-Info     { param([string]$t) Write-Colored $t 'Gray' }
function Write-Plain    { param([string]$t) Write-Colored $t 'White' }
function Write-Good     { param([string]$t) Write-Colored $t 'Green' }
function Write-Warn     { param([string]$t) Write-Colored $t 'Yellow' }
function Write-Miss     { param([string]$t) Write-Colored $t 'DarkGray' }
function Write-Bad      { param([string]$t) Write-Colored $t 'Red' }

# Echoes the actual PowerShell command(s) that produced the next section,
# so the operator can copy/paste and replicate manually. Same style as loot.ps1.
function Write-CMD {
    param([string]$Cmd)
    Write-Blank
    Write-Colored '  >> COMMAND EXECUTED' 'Cyan'
    $lines = @($Cmd -split "`r?`n") | Where-Object { $_ -ne '' }
    if (-not $lines -or $lines.Count -eq 0) { $lines = @([string]$Cmd) }
    $first = $true
    foreach ($line in $lines) {
        if ($first) { Write-Colored ('     PS> {0}' -f $line) 'DarkGray' }
        else        { Write-Colored ('         {0}' -f $line) 'DarkGray' }
        $first = $false
    }
}

function Write-Status {
    param([string]$t)
    if     ($t -match '^\[\+\]') { Write-Good $t }
    elseif ($t -match '^\[\-\]') { Write-Miss $t }
    elseif ($t -match '^\[\!\]') { Write-Warn $t }
    else                         { Write-Plain $t }
}

function Write-ColoredTable {
    param([string]$Text, [scriptblock]$Colorizer)
    foreach ($line in ($Text -split "`r?`n")) {
        if ($line.Length -eq 0) { Write-Blank; continue }
        $color = & $Colorizer $line
        Write-Colored $line $color
    }
}

# Regex fragment matching ACL identities that typically indicate a
# low-privileged user can modify the target (exploit-path indicator).
$script:WritableAclRegex = '(Authenticated Users|\bEveryone\b|BUILTIN\\Users(?!\s*\(RX\))|\bINTERACTIVE\b)'

# =====================================================================
# COMPAT SHIM - dynamic system paths + cmdlet availability detection
# Goal: run on Win7/Server 2008 R2 (PS 2.0) up to Win11/Server 2022 (PS 5.1+)
# =====================================================================

# Dynamic system paths - never assume C:\ as system drive
$script:SystemDriveRoot = if ($env:SystemDrive) { $env:SystemDrive.TrimEnd('\') + '\' } else { 'C:\' }
$script:SystemRootDir   = if ($env:SystemRoot)  { $env:SystemRoot }
                          elseif ($env:windir)  { $env:windir }
                          else                  { Join-Path $script:SystemDriveRoot 'Windows' }
$script:ProgFiles64     = $env:ProgramFiles
$script:ProgFiles86     = ${env:ProgramFiles(x86)}    # may be $null on 32-bit Windows
$script:ProgFilesW6432  = $env:ProgramW6432           # set when running under WOW64
$script:ProgramDataDir  = if ($env:ProgramData)        { $env:ProgramData }
                          elseif ($env:ALLUSERSPROFILE) { $env:ALLUSERSPROFILE }
                          else                          { Join-Path $script:SystemDriveRoot 'ProgramData' }
$script:UserProfilesDir = if ($env:USERPROFILE) { Split-Path $env:USERPROFILE -Parent }
                          else                  { Join-Path $script:SystemDriveRoot 'Users' }

# Standard root folder names - derived from environment, not hardcoded.
# Used to identify "non-standard" top-level folders worth scanning.
$_stdNames = New-Object System.Collections.Generic.List[string]
foreach ($p in @($script:SystemRootDir, $script:UserProfilesDir, $script:ProgramDataDir, $script:ProgFiles64, $script:ProgFiles86, $script:ProgFilesW6432)) {
    if ($p) {
        try { $leaf = Split-Path $p -Leaf } catch { $leaf = $null }
        if ($leaf -and -not $_stdNames.Contains($leaf)) { $null = $_stdNames.Add($leaf) }
    }
}
foreach ($extra in @('PerfLogs','Recovery','System Volume Information','$Recycle.Bin','Documents and Settings','Config.Msi','MSOCache','Boot','Intel','AMD','NVIDIA','OneDriveTemp','EFI')) {
    if (-not $_stdNames.Contains($extra)) { $null = $_stdNames.Add($extra) }
}
$script:StandardRootFolderNames = @($_stdNames)

# Cmdlet availability - guards against older PowerShell / stripped Server Core
$script:HasCim          = [bool](Get-Command Get-CimInstance      -ErrorAction SilentlyContinue)
$script:HasWmi          = [bool](Get-Command Get-WmiObject        -ErrorAction SilentlyContinue)
$script:HasNetTcp       = [bool](Get-Command Get-NetTCPConnection -ErrorAction SilentlyContinue)
$script:HasNetUdp       = [bool](Get-Command Get-NetUDPEndpoint   -ErrorAction SilentlyContinue)
$script:HasScheduledTask= [bool](Get-Command Get-ScheduledTask    -ErrorAction SilentlyContinue)
$script:HasMpPreference = [bool](Get-Command Get-MpPreference     -ErrorAction SilentlyContinue)
$script:HasWinEvent     = [bool](Get-Command Get-WinEvent         -ErrorAction SilentlyContinue)
$script:HasGetHotFix    = [bool](Get-Command Get-HotFix           -ErrorAction SilentlyContinue)
$script:HasGetService   = [bool](Get-Command Get-Service          -ErrorAction SilentlyContinue)

# CIM/WMI dispatcher - prefers Get-CimInstance (PS 3+), falls back to Get-WmiObject (PS 2.0)
function Get-WmiOrCim {
    param([string]$ClassName, [string]$Filter)
    if ($script:HasCim) {
        if ($Filter) { return @(Get-CimInstance -ClassName $ClassName -Filter $Filter -ErrorAction SilentlyContinue) }
        else         { return @(Get-CimInstance -ClassName $ClassName -ErrorAction SilentlyContinue) }
    } elseif ($script:HasWmi) {
        if ($Filter) { return @(Get-WmiObject -Class $ClassName -Filter $Filter -ErrorAction SilentlyContinue) }
        else         { return @(Get-WmiObject -Class $ClassName -ErrorAction SilentlyContinue) }
    }
    return @()
}

# Test if a top-level dir name is a standard Windows folder
function Test-IsStandardRootName {
    param([string]$Name)
    if ([string]::IsNullOrEmpty($Name)) { return $false }
    foreach ($std in $script:StandardRootFolderNames) {
        if ($std -ieq $Name) { return $true }
    }
    if ($Name -match '^\$') { return $true }   # $Recycle.Bin, $Windows.~BT, etc.
    return $false
}

# ---- Task Scheduler registry blob parser ----------------------------
# Task definitions are stored in two places:
#   File:     %SystemRoot%\System32\Tasks\<TaskPath>\<TaskName>
#   Registry: HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Schedule\TaskCache\
#               Tree\<TaskPath>\<TaskName>          (-> Id = task GUID)
#               Tasks\{GUID}\Actions               (-> binary blob of actions)
# The file ACL is often locked but the registry ACL on TaskCache\Tasks\{GUID}
# is typically readable by Authenticated Users. This function extracts the Execute
# path and Arguments without touching the file.
#
# Actions blob format (TaskScheduler 2.0):
#   WORD  version       = 0x0003
#   DWORD contextLen    (bytes)
#   WCHAR context[]
#   For each action:
#     WORD actionMagic  = 0x6666 (Exec) | 0x7777 (COM) | 0x5555 (Email) | 0x4444 (Message)
#     DWORD idLen   ; WCHAR id[]
#     [Exec only:]
#     DWORD cmdLen  ; WCHAR command[]
#     DWORD argsLen ; WCHAR arguments[]
#     DWORD wdLen   ; WCHAR workingDirectory[]
function Read-TaskActionsBlob {
    param([byte[]]$Blob)
    if (-not $Blob -or $Blob.Length -lt 6) { return $null }
    $ms = New-Object System.IO.MemoryStream(,[byte[]]$Blob)
    $br = New-Object System.IO.BinaryReader($ms)
    $actions  = New-Object System.Collections.ArrayList
    $context  = $null
    $version  = 0
    try {
        $version = $br.ReadUInt16()
        $ctxLen  = [int]$br.ReadUInt32()
        if ($ctxLen -gt 0 -and $ctxLen -lt $Blob.Length) {
            $ctxBytes = $br.ReadBytes($ctxLen)
            $context  = [System.Text.Encoding]::Unicode.GetString($ctxBytes)
        }
        while ($ms.Position -le $ms.Length - 2) {
            $magic = $br.ReadUInt16()
            if ($magic -eq 0x6666) {
                $idLen = [int]$br.ReadUInt32()
                $id    = if ($idLen -gt 0 -and $idLen -le ($Blob.Length - $ms.Position)) {
                             [System.Text.Encoding]::Unicode.GetString($br.ReadBytes($idLen))
                         } else { '' }
                $cmdLen = [int]$br.ReadUInt32()
                $cmd    = if ($cmdLen -gt 0 -and $cmdLen -le ($Blob.Length - $ms.Position)) {
                              [System.Text.Encoding]::Unicode.GetString($br.ReadBytes($cmdLen))
                          } else { '' }
                $argsLen = [int]$br.ReadUInt32()
                $args    = if ($argsLen -gt 0 -and $argsLen -le ($Blob.Length - $ms.Position)) {
                               [System.Text.Encoding]::Unicode.GetString($br.ReadBytes($argsLen))
                           } else { '' }
                $wdLen = [int]$br.ReadUInt32()
                $wd    = if ($wdLen -gt 0 -and $wdLen -le ($Blob.Length - $ms.Position)) {
                             [System.Text.Encoding]::Unicode.GetString($br.ReadBytes($wdLen))
                         } else { '' }
                [void]$actions.Add([PSCustomObject]@{
                    Type             = 'Exec'
                    Id               = $id
                    Execute          = $cmd
                    Arguments        = $args
                    WorkingDirectory = $wd
                })
            } else {
                # Unknown / unsupported action type - bail out
                break
            }
        }
    } catch {
        # Truncated or malformed - return what we have
    } finally {
        $br.Close()
    }
    return [PSCustomObject]@{
        Version = $version
        Context = $context
        Actions = @($actions)
    }
}

# Look up a task definition via registry only (works when filesystem and Get-ScheduledTask both fail).
# Input is a task path like "\backup runner" or "\Microsoft\Windows\WindowsUpdate\Foo".
function Get-TaskDefFromRegistry {
    param([string]$TaskPath)
    if (-not $TaskPath) { return $null }
    $treeBase  = 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Schedule\TaskCache\Tree'
    $tasksBase = 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Schedule\TaskCache\Tasks'
    $rel = $TaskPath.TrimStart('\')
    $treeKey = if ($rel) { Join-Path $treeBase $rel } else { $treeBase }
    $tree = $null
    try { $tree = Get-ItemProperty -Path $treeKey -ErrorAction Stop } catch { return $null }
    if (-not $tree -or -not $tree.Id) { return $null }
    $guid = [string]$tree.Id
    $taskKey = Join-Path $tasksBase $guid
    $task = $null
    try { $task = Get-ItemProperty -Path $taskKey -ErrorAction Stop } catch { return $null }
    if (-not $task) { return $null }
    $parsed = $null
    if ($task.Actions) {
        try { $parsed = Read-TaskActionsBlob -Blob ([byte[]]$task.Actions) } catch {}
    }
    return [PSCustomObject]@{
        Guid     = $guid
        TaskPath = $TaskPath
        Path     = $task.Path
        URI      = $task.URI
        Hash     = if ($task.Hash) { ([System.BitConverter]::ToString([byte[]]$task.Hash)).Replace('-','') } else { $null }
        Parsed   = $parsed
    }
}

function Get-SystemRootPath {
    if ($env:SystemRoot) { return $env:SystemRoot }
    if ($env:windir) { return $env:windir }
    return 'C:\Windows'
}

function Get-ProgramRoots {
    $roots = @(
        $env:ProgramFiles,
        ${env:ProgramFiles(x86)},
        $env:ProgramW6432
    ) | Where-Object { -not [string]::IsNullOrWhiteSpace($_) }

    $seen = @{}
    $out = [System.Collections.Generic.List[string]]::new()
    foreach ($root in $roots) {
        $expanded = [Environment]::ExpandEnvironmentVariables($root).TrimEnd('\\')
        if ([string]::IsNullOrWhiteSpace($expanded)) { continue }
        $key = $expanded.ToLowerInvariant()
        if ($seen.ContainsKey($key)) { continue }
        $seen[$key] = $true
        try {
            if (Test-Path -LiteralPath $expanded -ErrorAction SilentlyContinue) {
                $out.Add($expanded)
            }
        } catch {}
    }
    return @($out)
}

function Test-PathUnder {
    param(
        [string]$Path,
        [string]$BasePath
    )

    if ([string]::IsNullOrWhiteSpace($Path) -or [string]::IsNullOrWhiteSpace($BasePath)) { return $false }

    $p = $Path.TrimEnd('\\').ToLowerInvariant()
    $b = $BasePath.TrimEnd('\\').ToLowerInvariant()

    if ($p -eq $b) { return $true }
    return $p.StartsWith(($b + '\\'))
}

function Normalize-WindowsBinaryPath {
    param([string]$Path)

    if ([string]::IsNullOrWhiteSpace($Path)) { return $Path }

    $systemRoot = Get-SystemRootPath
    $p = [Environment]::ExpandEnvironmentVariables($Path.Trim())

    $p = $p -replace '^(?i)\\\\\?\\', ''
    $p = $p -replace '^(?i)\\\?\?\\', ''

    if ($p -match '^(?i)\\SystemRoot\\') {
        return (Join-Path $systemRoot ($p -replace '^(?i)\\SystemRoot\\', ''))
    }
    if ($p -match '^(?i)System32\\') {
        return (Join-Path $systemRoot $p)
    }
    if ($p -match '^(?i)SysWOW64\\') {
        return (Join-Path $systemRoot $p)
    }

    return $p
}

function Resolve-BinaryPath {
    param([string]$CommandLine)

    if ([string]::IsNullOrWhiteSpace($CommandLine)) { return $null }

    $clean = [Environment]::ExpandEnvironmentVariables($CommandLine.Trim())

    $quotedMatch = [regex]::Match($clean, '^"([^"]+)"')
    if ($quotedMatch.Success) {
        return (Normalize-WindowsBinaryPath $quotedMatch.Groups[1].Value.Trim())
    }

    $exeMatch = [regex]::Match($clean, '^(.*?\.(?:exe|com|bat|cmd|ps1|vbs|js|sys))(?=\s|$)', 'IgnoreCase')
    if ($exeMatch.Success) {
        return (Normalize-WindowsBinaryPath $exeMatch.Groups[1].Value.Trim())
    }

    return (Normalize-WindowsBinaryPath $clean)
}

function Resolve-ExistingPath {
    param([string]$Path)

    if ([string]::IsNullOrWhiteSpace($Path)) { return $null }

    $systemRoot = Get-SystemRootPath

    try {
        if ([System.IO.File]::Exists($Path) -or [System.IO.Directory]::Exists($Path)) {
            return $Path
        }
    } catch {}

    try {
        if (Test-Path -LiteralPath $Path -ErrorAction SilentlyContinue) {
            return $Path
        }
    } catch {}

    $system32Base = Join-Path $systemRoot 'System32'
    if ($env:PROCESSOR_ARCHITEW6432 -and (Test-PathUnder -Path $Path -BasePath $system32Base)) {
        $relative = $Path.Substring($system32Base.TrimEnd('\\').Length).TrimStart('\\')
        $alt = Join-Path (Join-Path $systemRoot 'Sysnative') $relative
        try {
            if ([System.IO.File]::Exists($alt) -or [System.IO.Directory]::Exists($alt)) {
                return $alt
            }
        } catch {}
        try {
            if (Test-Path -LiteralPath $alt -ErrorAction SilentlyContinue) {
                return $alt
            }
        } catch {}
    }

    return $null
}

function Get-CurrentTokenPrincipals {
    $id = [System.Security.Principal.WindowsIdentity]::GetCurrent()
    $out = [System.Collections.Generic.List[object]]::new()

    $out.Add([PSCustomObject]@{
        Name       = $id.Name
        Sid        = $id.User.Value
        Kind       = 'User'
        Preference = 0
    })

    foreach ($groupSid in $id.Groups) {
        $translatedName = $null
        try {
            $translatedName = $groupSid.Translate([System.Security.Principal.NTAccount]).Value
        } catch {
            $translatedName = $null
        }

        $out.Add([PSCustomObject]@{
            Name       = $translatedName
            Sid        = $groupSid.Value
            Kind       = 'Group'
            Preference = 1
        })
    }

    $seen = @{}
    foreach ($entry in $out) {
        if (-not $seen.ContainsKey($entry.Sid)) {
            $seen[$entry.Sid] = $true
            $entry
        }
    }
}

function Get-PermissionRank {
    param([string]$Right)

    switch ($Right) {
        'F' { return 3 }
        'M' { return 2 }
        'W' { return 1 }
        default { return 0 }
    }
}

function Get-StrongestWmfRight {
    param([string]$Text)

    if ($Text -match '\(F\)') { return 'F' }
    if ($Text -match '\(M\)') { return 'M' }
    if ($Text -match '\(W\)') { return 'W' }
    return $null
}

function Get-EffectivePathAccess {
    param(
        [string]$TargetPath,
        [object[]]$TokenPrincipals,
        [string]$CurrentUserSid
    )

    $result = [PSCustomObject]@{
        CheckedPath = if ($TargetPath) { $TargetPath } else { 'False' }
        PathExists  = $false
        Detail      = 'False'
        Right       = 'False'
        CanChange   = $false
    }

    if ([string]::IsNullOrWhiteSpace($TargetPath)) { return $result }

    $resolvedPath = Resolve-ExistingPath $TargetPath
    if (-not $resolvedPath) {
        $result.Detail = '[not found]'
        return $result
    }

    $result.CheckedPath = $resolvedPath
    $result.PathExists = $true

    $aclLines = @(icacls $resolvedPath 2>$null)
    if (-not $aclLines -or $aclLines.Count -eq 0) { return $result }

    $matchedAces = [System.Collections.Generic.List[object]]::new()

    foreach ($line in $aclLines) {
        foreach ($principal in $TokenPrincipals) {
            $patterns = @()
            if ($principal.Name) { $patterns += [regex]::Escape($principal.Name) }
            if ($principal.Sid)  { $patterns += [regex]::Escape($principal.Sid) }
            if ($patterns.Count -eq 0) { continue }

            $principalPattern = ($patterns -join '|')
            $aceMatch = [regex]::Match($line, "(?i)(^|\s)(?<principal>$principalPattern)\s*:")
            if (-not $aceMatch.Success) { continue }

            $strongest = Get-StrongestWmfRight $line
            if (-not $strongest) { continue }

            $principalDisplay = if ($principal.Name) { $principal.Name } else { $principal.Sid }
            $inherited = if ($line -match '\(I\)') { '(I)' } else { '' }
            $detail = ('{0}:{1}{2}' -f $principalDisplay, $inherited, "($strongest)")

            $matchedAces.Add([PSCustomObject]@{
                Principal    = $principalDisplay
                Right        = $strongest
                Rank         = (Get-PermissionRank -Right $strongest)
                IsDirectUser = ($principal.Sid -eq $CurrentUserSid)
                Preference   = $principal.Preference
                Detail       = $detail
            })
        }
    }

    if ($matchedAces.Count -eq 0) { return $result }

    $chosen = $matchedAces |
        Sort-Object @{ Expression = { if ($_.IsDirectUser) { 0 } else { 1 } } },
                    @{ Expression = { -1 * $_.Rank } },
                    @{ Expression = { $_.Preference } } |
        Select-Object -First 1

    if ($null -ne $chosen) {
        $result.Detail = $chosen.Detail
        $result.Right = $chosen.Right
        $result.CanChange = $true
    }

    return $result
}

function Get-BinaryMetadata {
    param([string]$Path)

    $result = [PSCustomObject]@{
        Company     = 'False'
        Product     = 'False'
        Description = 'False'
    }

    if ([string]::IsNullOrWhiteSpace($Path)) { return $result }

    $existingPath = Resolve-ExistingPath $Path
    if (-not $existingPath) { return $result }

    try {
        $item = Get-Item -LiteralPath $existingPath -ErrorAction Stop
        $info = $item.VersionInfo

        if ($info.CompanyName)     { $result.Company = $info.CompanyName.Trim() }
        if ($info.ProductName)     { $result.Product = $info.ProductName.Trim() }
        if ($info.FileDescription) { $result.Description = $info.FileDescription.Trim() }
    } catch {}

    return $result
}

function Test-IsMicrosoftLike {
    param(
        [string]$Company,
        [string]$Path
    )

    $systemRoot = Get-SystemRootPath
    $programRoots = Get-ProgramRoots

    if ($Company -and $Company -ne 'False' -and $Company -match '(?i)microsoft') { return $true }
    if (Test-PathUnder -Path $Path -BasePath $systemRoot) { return $true }
    if ($env:ProgramData -and (Test-PathUnder -Path $Path -BasePath (Join-Path $env:ProgramData 'Microsoft'))) { return $true }

    foreach ($root in $programRoots) {
        if (Test-PathUnder -Path $Path -BasePath (Join-Path $root 'Microsoft')) { return $true }
        if (Test-PathUnder -Path $Path -BasePath (Join-Path $root 'Windows')) { return $true }
    }

    return $false
}

function Get-InterestingServiceRights {
    param([string]$SecurityDescriptor)

    $sidMap = @{
        'BU' = 'BUILTIN\Users'
        'WD' = 'Everyone'
        'AU' = 'Authenticated Users'
        'IU' = 'INTERACTIVE'
    }

    $trackedCodes = @('RP','WP','DC','WD','WO')
    $byPrincipal = @{}

    foreach ($m in [regex]::Matches([string]$SecurityDescriptor, '\(A;;([^;]*?);;;(BU|WD|AU|IU)\)')) {
        $rights = $m.Groups[1].Value
        $sidCode = $m.Groups[2].Value

        if (-not $byPrincipal.ContainsKey($sidCode)) {
            $byPrincipal[$sidCode] = @()
        }

        foreach ($code in $trackedCodes) {
            if ($rights -match $code -and $byPrincipal[$sidCode] -notcontains $code) {
                $byPrincipal[$sidCode] += $code
            }
        }
    }

    $summaryParts = @()
    $canRestart = $false
    $serviceDaclRisk = $false

    foreach ($sidCode in @('BU','AU','IU','WD')) {
        if (-not $byPrincipal.ContainsKey($sidCode)) { continue }

        $rights = @($byPrincipal[$sidCode])
        if ($rights.Count -eq 0) { continue }

        $interesting = @()
        if ($rights -contains 'RP' -and $rights -contains 'WP') {
            $canRestart = $true
            $interesting += 'RP'
            $interesting += 'WP'
        } elseif ($rights -contains 'WP') {
            $interesting += 'WP'
        }

        foreach ($code in @('DC','WD','WO')) {
            if ($rights -contains $code) {
                $interesting += $code
                $serviceDaclRisk = $true
            }
        }

        $interesting = @($interesting | Select-Object -Unique)
        if ($interesting.Count -gt 0) {
            $summaryParts += ('{0}:{1}' -f $sidMap[$sidCode], ($interesting -join '/'))
        }
    }

    [PSCustomObject]@{
        Summary         = if ($summaryParts.Count -gt 0) { $summaryParts -join '; ' } else { 'False' }
        CanRestart      = $canRestart
        ServiceDaclRisk = $serviceDaclRisk
    }
}

function Get-UnquotedCandidateExecutables {
    param([string]$BinaryPath)

    $candidates = [System.Collections.Generic.List[string]]::new()
    if ([string]::IsNullOrWhiteSpace($BinaryPath)) { return @() }
    if ($BinaryPath -notmatch '\s') { return @() }

    $segments = $BinaryPath -split ' '
    if ($segments.Count -lt 2) { return @() }

    $current = $segments[0]
    for ($i = 0; $i -lt ($segments.Count - 1); $i++) {
        if ($i -gt 0) {
            $current = ('{0} {1}' -f $current, $segments[$i])
        }

        $candidate = if ($current -match '\.exe$') { $current } else { ('{0}.exe' -f $current) }
        if ($candidate -ne $BinaryPath -and -not $candidates.Contains($candidate)) {
            $candidates.Add($candidate)
        }
    }

    return @($candidates)
}

function Test-IsLikelyDriverServiceEntry {
    param(
        [string]$Path,
        [string]$RawPath
    )

    $candidate = if ($Path) { $Path } else { $RawPath }
    if ([string]::IsNullOrWhiteSpace($candidate)) { return $true }

    $systemRoot = Get-SystemRootPath
    $systemDrivers = Join-Path $systemRoot 'System32\drivers'

    if ($candidate -match '(?i)\.sys($|\s)') { return $true }
    if ($candidate -match '^(?i)\\SystemRoot\\.*\\drivers\\') { return $true }
    if (Test-PathUnder -Path $candidate -BasePath $systemDrivers) { return $true }
    if ($candidate -match '^(?i)System32\\drivers\\') { return $true }
    if ($candidate -match '^(?i)\\Driver\\') { return $true }

    return $false
}

function Test-IsUserlandServiceRecord {
    param([object]$ServiceRecord)

    if ($null -ne $ServiceRecord.RegistryType) {
        try {
            $typeValue = [int]$ServiceRecord.RegistryType
            if (($typeValue -band 16) -or ($typeValue -band 32)) {
                return $true
            }
            if (($typeValue -band 1) -or ($typeValue -band 2)) {
                return $false
            }
        } catch {}
    }

    if ($ServiceRecord.ServiceType -and $ServiceRecord.ServiceType -ne 'False') {
        if ([string]$ServiceRecord.ServiceType -match '(?i)(own process|share process|interactive process|win32)') {
            return $true
        }
    }

    return -not (Test-IsLikelyDriverServiceEntry -Path $ServiceRecord.ResolvedPath -RawPath $ServiceRecord.PathName)
}

function Get-ServiceInventory {
    $serviceMap = @{}

    try {
        $cimServices = @(Get-CimInstance Win32_Service -ErrorAction Stop)
    } catch {
        $cimServices = @()
    }

    if (-not $cimServices -or $cimServices.Count -eq 0) {
        try {
            $cimServices = @(Get-WmiObject Win32_Service -ErrorAction Stop)
        } catch {
            $cimServices = @()
        }
    }

    foreach ($svc in $cimServices) {
        if (-not $svc.Name) { continue }

        $serviceMap[$svc.Name] = [ordered]@{
            Name         = $svc.Name
            DisplayName  = if ($svc.DisplayName) { $svc.DisplayName } else { $svc.Name }
            PathName     = $svc.PathName
            StartName    = if ($svc.StartName) { $svc.StartName } else { 'False' }
            StartMode    = if ($svc.StartMode) { $svc.StartMode } else { 'False' }
            State        = if ($svc.State) { $svc.State } else { 'False' }
            ServiceType  = if ($svc.ServiceType) { [string]$svc.ServiceType } else { 'False' }
            RegistryType = $null
            Source       = 'WMI'
            ResolvedPath = Resolve-BinaryPath $svc.PathName
        }
    }

    try {
        $regServices = @(Get-ItemProperty 'Registry::HKLM\System\CurrentControlSet\Services\*' -ErrorAction Stop)
    } catch {
        $regServices = @()
    }

    foreach ($svc in $regServices) {
        $name = $svc.PSChildName
        if (-not $name) { continue }

        $displayName = $svc.DisplayName
        $imagePath = $svc.ImagePath
        $objectName = if ($svc.ObjectName) { $svc.ObjectName } else { 'False' }
        $registryType = $null
        try { $registryType = [int]$svc.Type } catch { $registryType = $null }

        if ($serviceMap.ContainsKey($name)) {
            if (-not $serviceMap[$name].PathName -and $imagePath) {
                $serviceMap[$name].PathName = $imagePath
                $serviceMap[$name].ResolvedPath = Resolve-BinaryPath $imagePath
            }
            if (($serviceMap[$name].StartName -eq 'False' -or -not $serviceMap[$name].StartName) -and $objectName) {
                $serviceMap[$name].StartName = $objectName
            }
            if (($serviceMap[$name].DisplayName -eq $name -or -not $serviceMap[$name].DisplayName) -and $displayName) {
                $serviceMap[$name].DisplayName = $displayName
            }
            if ($null -eq $serviceMap[$name].RegistryType -and $null -ne $registryType) {
                $serviceMap[$name].RegistryType = $registryType
            }
            if (-not $serviceMap[$name].Source -or $serviceMap[$name].Source -eq 'WMI') {
                $serviceMap[$name].Source = 'WMI+Registry'
            }
        } else {
            $serviceMap[$name] = [ordered]@{
                Name         = $name
                DisplayName  = if ($displayName) { $displayName } else { $name }
                PathName     = $imagePath
                StartName    = $objectName
                StartMode    = 'False'
                State        = 'False'
                ServiceType  = 'False'
                RegistryType = $registryType
                Source       = 'Registry'
                ResolvedPath = Resolve-BinaryPath $imagePath
            }
        }
    }

    $out = [System.Collections.Generic.List[object]]::new()
    foreach ($entry in ($serviceMap.GetEnumerator() | Sort-Object Name)) {
        $record = [PSCustomObject]$entry.Value
        Add-Member -InputObject $record -NotePropertyName IsUserland -NotePropertyValue (Test-IsUserlandServiceRecord -ServiceRecord $record) -Force
        $out.Add($record)
    }

    return @($out)
}

function Test-IsInterestingSoftwareService {
    param(
        [string]$Company,
        [string]$Product,
        [string]$Path,
        [string]$DisplayName,
        [string]$ServiceName,
        [string]$RawPath,
        [bool]$IsUserland = $true
    )

    if (-not $IsUserland) { return $false }
    if (Test-IsLikelyDriverServiceEntry -Path $Path -RawPath $RawPath) { return $false }
    if ([string]::IsNullOrWhiteSpace($Path)) { return $false }

    $systemRoot = Get-SystemRootPath
    $isUnderWindows = Test-PathUnder -Path $Path -BasePath $systemRoot
    $isUnderProgramRoots = $false
    foreach ($root in (Get-ProgramRoots)) {
        if (Test-PathUnder -Path $Path -BasePath $root) {
            $isUnderProgramRoots = $true
            break
        }
    }

    $isUnderProgramData = $false
    if ($env:ProgramData) {
        $isUnderProgramData = Test-PathUnder -Path $Path -BasePath $env:ProgramData
    }

    $isUnderUsers = $false
    if ($env:PUBLIC -and (Test-PathUnder -Path $Path -BasePath $env:PUBLIC)) {
        $isUnderUsers = $true
    } elseif ($env:USERPROFILE) {
        try {
            $usersRoot = Split-Path -Path $env:USERPROFILE -Parent
        } catch {
            $usersRoot = $null
        }
        if ($usersRoot -and (Test-PathUnder -Path $Path -BasePath $usersRoot)) {
            $isUnderUsers = $true
        }
    }

    $hasNonMicrosoftMetadata = $false
    if ($Company -and $Company -ne 'False' -and $Company -notmatch '(?i)microsoft') {
        $hasNonMicrosoftMetadata = $true
    }
    if (-not $hasNonMicrosoftMetadata -and $Product -and $Product -ne 'False' -and $Product -notmatch '^(?i)(Windows|Microsoft)') {
        $hasNonMicrosoftMetadata = $true
    }

    if ($hasNonMicrosoftMetadata) { return $true }

    if (Test-IsMicrosoftLike -Company $Company -Path $Path) { return $false }

    if ($isUnderProgramRoots -or $isUnderProgramData -or $isUnderUsers) {
        return $true
    }

    if ($isUnderWindows) {
        return $false
    }

    return $false
}

function Test-IsLikelyBoringProgramFolder {
    param(
        [string]$Name,
        [string]$Dir
    )

    $candidateName = if ($Name) { $Name.Trim() } elseif ($Dir) { Split-Path -Path $Dir -Leaf } else { '' }
    if ([string]::IsNullOrWhiteSpace($candidateName) -and [string]::IsNullOrWhiteSpace($Dir)) { return $true }

    if ($candidateName -match '^(?i)(Common Files|Internet Explorer|Microsoft($| )|Microsoft\.NET|MSBuild|Reference Assemblies|Windows($| )|WindowsPowerShell|ModifiableWindowsApps)$') {
        return $true
    }

    foreach ($root in (Get-ProgramRoots)) {
        foreach ($leaf in @('Common Files','Internet Explorer','Microsoft','Microsoft.NET','MSBuild','Reference Assemblies','Windows','WindowsPowerShell','ModifiableWindowsApps')) {
            if (Test-PathUnder -Path $Dir -BasePath (Join-Path $root $leaf)) { return $true }
        }
    }

    return $false
}

function Test-IsInterestingInstalledSoftware {
    param(
        [string]$Name,
        [string]$Publisher,
        [string]$InstallDir
    )

    if ([string]::IsNullOrWhiteSpace($Name) -and [string]::IsNullOrWhiteSpace($InstallDir)) { return $false }
    if (Test-IsLikelyBoringProgramFolder -Name $Name -Dir $InstallDir) { return $false }

    if ($Publisher -and $Publisher -ne 'False' -and $Publisher -match '(?i)microsoft') { return $false }
    if ($Name -and $Name -match '^(?i)(Microsoft($| )|Windows($| ))') { return $false }

    foreach ($root in (Get-ProgramRoots)) {
        if (Test-PathUnder -Path $InstallDir -BasePath (Join-Path $root 'Microsoft')) { return $false }
        if (Test-PathUnder -Path $InstallDir -BasePath (Join-Path $root 'Windows')) { return $false }
    }

    if ($env:ProgramData -and (Test-PathUnder -Path $InstallDir -BasePath (Join-Path $env:ProgramData 'Microsoft'))) { return $false }

    return $true
}

function Get-InstalledSoftwareInventory {
    param(
        [object[]]$TokenPrincipals,
        [string]$CurrentUserSid
    )

    $rows = [System.Collections.Generic.List[object]]::new()

    $uninstallRoots = @(
        'Registry::HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\*',
        'Registry::HKLM\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall\*',
        'Registry::HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\*',
        'Registry::HKCU\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall\*'
    )

    foreach ($root in $uninstallRoots) {
        try {
            $items = @(Get-ItemProperty $root -ErrorAction Stop)
        } catch {
            $items = @()
        }

        foreach ($item in $items) {
            $name = if ($item.DisplayName) { [string]$item.DisplayName } else { $null }
            if ([string]::IsNullOrWhiteSpace($name)) { continue }

            $installDir = $null
            if ($item.InstallLocation) {
                $installDir = [Environment]::ExpandEnvironmentVariables([string]$item.InstallLocation).Trim()
            }

            if ([string]::IsNullOrWhiteSpace($installDir) -and $item.DisplayIcon) {
                $parsed = Resolve-BinaryPath ([string]$item.DisplayIcon)
                if ($parsed) {
                    try { $installDir = Split-Path -Path $parsed -Parent } catch { $installDir = $null }
                }
            }

            if ([string]::IsNullOrWhiteSpace($installDir)) { $installDir = 'False' }

            $publisher = if ($item.Publisher) { [string]$item.Publisher } else { 'False' }
            $version = if ($item.DisplayVersion) { [string]$item.DisplayVersion } else { 'False' }

            if (-not (Test-IsInterestingInstalledSoftware -Name $name -Publisher $publisher -InstallDir $installDir)) { continue }

            $dirAccess = if ($installDir -ne 'False') {
                (Get-EffectivePathAccess -TargetPath $installDir -TokenPrincipals $TokenPrincipals -CurrentUserSid $CurrentUserSid).Detail
            } else {
                'False'
            }

            $rows.Add([PSCustomObject]@{
                Name       = $name
                Publisher  = $publisher
                Version    = $version
                InstallDir = $installDir
                DirAccess  = $dirAccess
                Source     = 'Registry'
            })
        }
    }

    foreach ($root in (Get-ProgramRoots)) {
        try {
            $dirs = @(Get-ChildItem -LiteralPath $root -Directory -ErrorAction Stop)
        } catch {
            $dirs = @()
        }

        foreach ($dir in $dirs) {
            $name = $dir.Name
            $installDir = $dir.FullName
            if (-not (Test-IsInterestingInstalledSoftware -Name $name -Publisher 'False' -InstallDir $installDir)) { continue }

            $dirAccess = (Get-EffectivePathAccess -TargetPath $installDir -TokenPrincipals $TokenPrincipals -CurrentUserSid $CurrentUserSid).Detail

            $rows.Add([PSCustomObject]@{
                Name       = $name
                Publisher  = 'False'
                Version    = 'False'
                InstallDir = $installDir
                DirAccess  = $dirAccess
                Source     = 'Folder'
            })
        }
    }

    $bestByKey = @{}
    foreach ($row in $rows) {
        $nameKey = if ($row.Name -and $row.Name -ne 'False') { $row.Name.Trim().ToLowerInvariant() } else { '' }
        $dirKey = if ($row.InstallDir -and $row.InstallDir -ne 'False') { $row.InstallDir.TrimEnd('\\').ToLowerInvariant() } else { '' }
        $key = '{0}|{1}' -f $nameKey, $dirKey

        $score = 0
        if ($row.Source -eq 'Registry') { $score += 10 }
        if ($row.Publisher -and $row.Publisher -ne 'False') { $score += 4 }
        if ($row.Version -and $row.Version -ne 'False') { $score += 2 }
        if ($row.DirAccess -and $row.DirAccess -ne 'False') { $score += 1 }

        if (-not $bestByKey.ContainsKey($key) -or $score -gt $bestByKey[$key].Score) {
            $bestByKey[$key] = [PSCustomObject]@{
                Score = $score
                Row   = $row
            }
        }
    }

    return @($bestByKey.GetEnumerator() | ForEach-Object { $_.Value.Row } | Sort-Object Name, InstallDir)
}

function Test-IsCurrentUserTaskContext {
    param(
        [string]$TaskUser,
        [string]$CurrentUser
    )

    if ([string]::IsNullOrWhiteSpace($TaskUser) -or $TaskUser -eq 'False') { return $false }

    $currentShort = $CurrentUser -replace '^.*\\', ''
    if ($TaskUser -ieq $CurrentUser) { return $true }
    if ($TaskUser -ieq $currentShort) { return $true }

    return $false
}

function Test-IsBoringWindowsTask {
    param(
        [string]$TaskPath,
        [string]$ResolvedBinary
    )

    $systemRoot = Get-SystemRootPath
    if ($TaskPath -match '^\\Microsoft\\Windows\\' -and (Test-PathUnder -Path $ResolvedBinary -BasePath $systemRoot)) {
        return $true
    }
    return $false
}

$currentIdentity = [System.Security.Principal.WindowsIdentity]::GetCurrent()
$currentUser = $currentIdentity.Name
$currentUserSid = $currentIdentity.User.Value
$tokenPrincipals = @(Get-CurrentTokenPrincipals)
$allServices = @(Get-ServiceInventory)

Write-Header 'Combined local pentest triage'
Write-Rule   '-----------------------------'
Write-Plain  ("Current user: {0}" -f $currentUser)
Write-Info   'Sections included:'
Write-Info   '- Services / software'
Write-Info   '- Installed software'
Write-Info   '- Unquoted service paths'
Write-Info   '- DLL hijack candidates'
Write-Info   '- Scheduled tasks'
Write-Info   '- Active network connections'
Write-Blank

# ---- Compat fingerprint - what features/paths this run will use ----
Write-Header 'Runtime compatibility fingerprint'
Write-Rule   '---------------------------------'
$psVer = $PSVersionTable.PSVersion
Write-Info ("PowerShell version : {0}.{1}" -f $psVer.Major, $psVer.Minor)
Write-Info ("System drive       : {0}" -f $script:SystemDriveRoot)
Write-Info ("Windows dir        : {0}" -f $script:SystemRootDir)
$pf64Display = if ($script:ProgFiles64) { $script:ProgFiles64 } else { '<unset>' }
$pf86Display = if ($script:ProgFiles86) { $script:ProgFiles86 } else { '<unset - 32-bit OS?>' }
Write-Info ("Program Files      : {0}" -f $pf64Display)
Write-Info ("Program Files x86  : {0}" -f $pf86Display)
Write-Info ("ProgramData        : {0}" -f $script:ProgramDataDir)
Write-Info ("User profiles dir  : {0}" -f $script:UserProfilesDir)
Write-Info ("Standard roots     : {0}" -f ($script:StandardRootFolderNames -join ', '))

$cmdAvail = @(
    "Get-CimInstance=$($script:HasCim)",
    "Get-WmiObject=$($script:HasWmi)",
    "Get-NetTCPConnection=$($script:HasNetTcp)",
    "Get-NetUDPEndpoint=$($script:HasNetUdp)",
    "Get-ScheduledTask=$($script:HasScheduledTask)",
    "Get-MpPreference=$($script:HasMpPreference)",
    "Get-WinEvent=$($script:HasWinEvent)",
    "Get-HotFix=$($script:HasGetHotFix)"
) -join ', '
Write-Info ("Cmdlets available  : {0}" -f $cmdAvail)
if (-not $script:HasCim -and -not $script:HasWmi) {
    Write-Bad '[!] Neither Get-CimInstance nor Get-WmiObject is available - many checks will be limited.'
}
if ($psVer.Major -lt 3) {
    Write-Warn '[!] PowerShell 2.0 detected - PS3+ cmdlets unavailable, falling back to WMI/netstat where possible.'
}
Write-Blank

# =====================================================================
# QUICK WINS - Token privileges, sensitive groups, OS/CVE, AV exclusions
# =====================================================================

# ---- Token privileges (juicy ones flagged) ----
Write-CMD @'
whoami /priv
# Or in PowerShell:
[System.Security.Principal.WindowsIdentity]::GetCurrent() |
    Select-Object -ExpandProperty UserClaims
# Juicy privs to look for in Enabled state:
#   SeImpersonatePrivilege          -> PrintSpoofer / RoguePotato / GodPotato / SweetPotato
#   SeAssignPrimaryTokenPrivilege   -> token impersonation
#   SeBackupPrivilege               -> read SAM/SYSTEM/SECURITY hives -> hashes
#   SeRestorePrivilege              -> write to protected areas
#   SeLoadDriverPrivilege           -> drop a vulnerable driver and exploit
#   SeDebugPrivilege                -> open any process incl LSASS
#   SeTcbPrivilege                  -> "act as part of OS"
#   SeManageVolumePrivilege         -> arbitrary file write via volume APIs
#   SeTakeOwnershipPrivilege        -> chown anything
#   SeCreateTokenPrivilege          -> mint tokens
'@
Write-Header 'Token privileges (current user)'
Write-Rule   '-------------------------------'

$juicyMap = @{
    'SeImpersonatePrivilege'         = 'PrintSpoofer / RoguePotato / GodPotato / SweetPotato'
    'SeAssignPrimaryTokenPrivilege'  = 'token impersonation -> SYSTEM'
    'SeBackupPrivilege'              = 'shadow-copy + reg save SAM/SYSTEM -> dump hashes'
    'SeRestorePrivilege'             = 'write to protected dirs incl service binaries'
    'SeLoadDriverPrivilege'          = 'drop vulnerable signed driver (BYOVD)'
    'SeDebugPrivilege'               = 'OpenProcess on any PID incl LSASS'
    'SeTcbPrivilege'                 = 'act as part of OS - effectively SYSTEM'
    'SeManageVolumePrivilege'        = 'arbitrary file write via volume APIs'
    'SeTakeOwnershipPrivilege'       = 'change owner on any object'
    'SeCreateTokenPrivilege'         = 'mint new tokens - extremely rare'
    'SeSecurityPrivilege'            = 'manage audit logs / clear traces'
    'SeShutdownPrivilege'            = 'shutdown - useful for service triggers'
}

$privLines = whoami /priv 2>$null
$privTable = [System.Collections.Generic.List[object]]::new()
$enabledJuicy = [System.Collections.Generic.List[string]]::new()
foreach ($line in $privLines) {
    if ($line -match '^(Se\w+)\s{2,}.+\s{2,}(Enabled|Disabled)') {
        $privName = $matches[1]
        $state    = $matches[2]
        $note     = if ($juicyMap.ContainsKey($privName)) { $juicyMap[$privName] } else { '' }
        $privTable.Add([PSCustomObject]@{
            Privilege = $privName
            State     = $state
            Note      = $note
        })
        if ($note -and $state -eq 'Enabled') { $null = $enabledJuicy.Add($privName) }
    }
}
if ($privTable.Count -eq 0) {
    Write-Status '[-] Could not parse whoami /priv output.'
} else {
    $tableText = ($privTable | Format-Table Privilege, State, Note -AutoSize | Out-String -Width 4096)
    Write-ColoredTable -Text $tableText -Colorizer {
        param($line)
        if ($line -match '^Privilege\s+State')     { return 'Cyan' }
        if ($line -match '^-+\s+-+')               { return 'DarkGray' }
        if ($line -match 'Enabled' -and $line -match '(Impersonate|AssignPrimary|Backup|Restore|LoadDriver|Debug|Tcb|ManageVolume|TakeOwnership|CreateToken)') {
            return 'Red'
        }
        if ($line -match 'Enabled')                { return 'Yellow' }
        if ($line -match 'Disabled')               { return 'DarkGray' }
        return 'White'
    }
    if ($enabledJuicy.Count -gt 0) {
        Write-Bad ("[!] {0} JUICY priv(s) ENABLED: {1}" -f $enabledJuicy.Count, ($enabledJuicy -join ', '))
        Write-Info '    Tools: PrintSpoofer.exe, RoguePotato.exe, GodPotato.exe, JuicyPotatoNG.exe'
        Write-Info '    SeBackup hash dump: reg save HKLM\SAM C:\Temp\sam ; reg save HKLM\SYSTEM C:\Temp\system'
    } else {
        Write-Status '[-] No juicy privileges enabled on current token.'
    }
}
Write-Blank

# ---- Sensitive group membership ----
Write-CMD @'
whoami /groups
# Or:
[System.Security.Principal.WindowsIdentity]::GetCurrent().Groups |
    ForEach-Object { $_.Translate([System.Security.Principal.NTAccount]).Value }
# Sensitive groups (each has known privesc paths):
#   Backup Operators                -> SeBackup -> dump SAM/SYSTEM hives
#   Server Operators                -> reconfigure services that run as SYSTEM
#   Print Operators                 -> SeLoadDriver -> BYOVD
#   Hyper-V Administrators          -> SYSTEM via VHD mount
#   DnsAdmins                       -> AD: ServerLevelPluginDll RCE on DC
#   Account Operators               -> AD: edit user accounts (not Admins)
#   Storage Replica Administrators  -> SeBackup
#   Schema Admins / Enterprise Admins / Domain Admins -> tier-0 (you are root in domain)
'@
Write-Header 'Sensitive group membership (current user)'
Write-Rule   '-----------------------------------------'

$sensitiveGroups = @{
    'BUILTIN\Administrators'                  = 'Local Admin - own the box'
    'BUILTIN\Backup Operators'                = 'SeBackup -> reg save SAM/SYSTEM -> hashes'
    'BUILTIN\Server Operators'                = 'reconfigure services running as SYSTEM'
    'BUILTIN\Print Operators'                 = 'SeLoadDriver -> BYOVD'
    'BUILTIN\Hyper-V Administrators'          = 'SYSTEM via VHD mount on system drive'
    'BUILTIN\DnsAdmins'                       = 'AD: ServerLevelPluginDll -> DC RCE'
    'BUILTIN\Account Operators'               = 'AD: edit non-Admin accounts'
    'BUILTIN\Storage Replica Administrators'  = 'SeBackup-equivalent'
    'BUILTIN\Network Configuration Operators' = 'change network config'
    'BUILTIN\Performance Log Users'           = 'limited but check anyway'
    'BUILTIN\Event Log Readers'               = 'read security log -> creds in scripts'
    'Domain Admins'                           = 'AD tier-0'
    'Enterprise Admins'                       = 'AD tier-0 forest-wide'
    'Schema Admins'                           = 'AD: alter schema'
    'Group Policy Creator Owners'             = 'create/edit GPOs'
}

$groupLines = whoami /groups 2>$null
$myGroups   = New-Object System.Collections.Generic.List[string]
foreach ($l in $groupLines) {
    foreach ($k in $sensitiveGroups.Keys) {
        if ($l -match [regex]::Escape($k)) {
            $null = $myGroups.Add($k)
        }
    }
}
$myGroups = $myGroups | Sort-Object -Unique
if (@($myGroups).Count -eq 0) {
    Write-Status '[-] Current user is not in any sensitive groups (besides Users).'
} else {
    foreach ($g in $myGroups) {
        Write-Bad ("[!] MEMBER OF: {0}    -> {1}" -f $g, $sensitiveGroups[$g])
    }
}
Write-Blank

# ---- OS build & known privesc CVEs (heuristic) ----
Write-CMD @'
Get-CimInstance Win32_OperatingSystem | Select Caption, Version, BuildNumber, OSArchitecture, InstallDate
# PS 2.0 fallback:
Get-WmiObject Win32_OperatingSystem | Select Caption, Version, BuildNumber, OSArchitecture, InstallDate
Get-HotFix | Sort-Object InstalledOn -Descending | Select-Object -First 10
# PS 2.0 fallback:
Get-WmiObject Win32_QuickFixEngineering | Sort-Object InstalledOn -Descending
# Compare against known privesc CVEs:
#   PrintNightmare       CVE-2021-34527  spooler running -> RCE/LPE
#   HiveNightmare/SeriousSAM CVE-2021-36934  ACL on %SystemRoot%\System32\config\SAM readable
#   PetitPotam           CVE-2022-26925  NTLM relay
#   nopac                CVE-2021-42278/42287  AD: SAMAccountName spoof
#   CertiFried           CVE-2022-26923  AD CS templates
#   Fancy Bear UAC       CVE-2022-21882  win32k LPE
#   Spoolfool            CVE-2022-22718  spooler LPE (post Aug 2021 patch)
'@
Write-Header 'OS build & known privesc CVEs'
Write-Rule   '-----------------------------'

$os = @(Get-WmiOrCim -ClassName Win32_OperatingSystem) | Select-Object -First 1
if ($os) {
    Write-Plain ("Caption     : {0}" -f $os.Caption)
    Write-Plain ("Version     : {0}" -f $os.Version)
    Write-Plain ("BuildNumber : {0}" -f $os.BuildNumber)
    Write-Plain ("Architecture: {0}" -f $os.OSArchitecture)
    Write-Plain ("InstallDate : {0}" -f $os.InstallDate)
    Write-Blank

    $hotfixes = $null
    if ($script:HasGetHotFix) {
        $hotfixes = Get-HotFix -EA 0 | Sort-Object InstalledOn -Descending
    } elseif ($script:HasCim -or $script:HasWmi) {
        # Fallback for older PS / Server Core: Win32_QuickFixEngineering provides the same data
        $hotfixes = @(Get-WmiOrCim -ClassName Win32_QuickFixEngineering) |
            Where-Object { $_.HotFixID -and $_.HotFixID -ne 'File 1' } |
            ForEach-Object {
                $instOn = $null
                if ($_.InstalledOn) { try { $instOn = [datetime]$_.InstalledOn } catch {} }
                [PSCustomObject]@{
                    HotFixID    = $_.HotFixID
                    Description = $_.Description
                    InstalledOn = $instOn
                }
            } | Sort-Object InstalledOn -Descending
    }
    if ($hotfixes) {
        $latest = $hotfixes | Select-Object -First 1
        $latestDate = $latest.InstalledOn
        Write-Plain ("Latest hotfix: {0} (installed {1:yyyy-MM-dd})" -f $latest.HotFixID, $latestDate)
        $kbList = ($hotfixes | Select-Object -First 10).HotFixID -join ', '
        Write-Info ("Last 10 KBs: {0}" -f $kbList)
        Write-Blank

        # Heuristic CVE checks based on OS build + last patch date
        $build = [int]$os.BuildNumber
        $cveHits = [System.Collections.Generic.List[string]]::new()

        # PrintNightmare: spooler must be running. Patches: KB5004945+ (Jul 2021), KB5005010+ (Aug 2021)
        $spooler = Get-Service -Name Spooler -EA 0
        if ($spooler -and $spooler.Status -eq 'Running') {
            $cveHits.Add('CVE-2021-34527 PrintNightmare candidate (spooler RUNNING). Test: PrintSpoofer / Invoke-Nightmare')
        } else {
            Write-Status '[-] Spooler not running - PrintNightmare path closed.'
        }

        # HiveNightmare CVE-2021-36934 - SAM hive readable by users
        # Affects build 17763 (1809 / Server 2019) and later
        if ($build -ge 17763) {
            try {
                # Try to read a few bytes from SAM - if it works as low-priv, vulnerable
                $samPath = Join-Path $script:SystemRootDir 'System32\config\SAM'
                $null = [System.IO.File]::OpenRead($samPath)
                $cveHits.Add('CVE-2021-36934 HiveNightmare/SeriousSAM - SAM is READABLE by current user! Use shadowcopy + reg save to dump.')
            } catch {
                # Default behavior - SAM should NOT be readable
            }
        }

        # PetitPotam CVE-2022-26925 - applies to all unpatched, May 2022 fix
        if ($latestDate -lt (Get-Date '2022-05-15')) {
            $cveHits.Add('CVE-2022-26925 PetitPotam likely unpatched (last hotfix older than May 2022). Coerce auth via EFSRPC.')
        }

        # CertiFried CVE-2022-26923 - May 2022 patch
        if ($latestDate -lt (Get-Date '2022-05-15')) {
            $cveHits.Add('CVE-2022-26923 CertiFried (AD CS template abuse) likely unpatched.')
        }

        # nopac CVE-2021-42278/42287 - Nov 2021 patch
        if ($latestDate -lt (Get-Date '2021-12-01')) {
            $cveHits.Add('CVE-2021-42278/42287 noPac (sAMAccountName spoof) likely unpatched.')
        }

        # SpoolFool CVE-2022-21999 - Feb 2022
        if ($spooler -and $spooler.Status -eq 'Running' -and $latestDate -lt (Get-Date '2022-02-15')) {
            $cveHits.Add('CVE-2022-21999 SpoolFool likely viable (spooler running + last hotfix < Feb 2022).')
        }

        # Win32k Fancy Bear CVE-2022-21882 - Feb 2022
        if ($build -ge 14393 -and $latestDate -lt (Get-Date '2022-02-15')) {
            $cveHits.Add('CVE-2022-21882 win32k LPE likely viable (last hotfix < Feb 2022).')
        }

        # Server 2022 specific: CVE-2024-26230 Telephony service EoP - Apr 2024
        if ($build -ge 20348 -and $latestDate -lt (Get-Date '2024-04-15')) {
            $cveHits.Add('CVE-2024-26230 Telephony service EoP likely unpatched.')
        }

        if ($cveHits.Count -eq 0) {
            Write-Status '[-] No obvious CVE hits from heuristic check.'
        } else {
            Write-Bad ("[!] {0} likely-applicable privesc CVE(s):" -f $cveHits.Count)
            foreach ($c in $cveHits) { Write-Bad ("    {0}" -f $c) }
        }
    } else {
        Write-Status '[-] Get-HotFix returned nothing (insufficient permissions or no patches).'
    }
}
Write-Blank

# ---- Defender exclusions ----
Write-CMD @'
Get-MpPreference | Select-Object ExclusionPath, ExclusionExtension, ExclusionProcess, ExclusionIpAddress
# Or via registry (works if cmdlet missing):
Get-ChildItem 'HKLM:\SOFTWARE\Microsoft\Windows Defender\Exclusions' -EA 0 -Recurse |
    ForEach-Object { Get-ItemProperty $_.PSPath -EA 0 }
'@
Write-Header 'Defender exclusions'
Write-Rule   '-------------------'

$mp = $null
try { $mp = Get-MpPreference -EA Stop } catch {}
if (-not $mp) {
    # Fallback: registry
    Write-Info '(Get-MpPreference unavailable, falling back to registry)'
    $exclRegRoots = @(
        'HKLM:\SOFTWARE\Microsoft\Windows Defender\Exclusions\Paths',
        'HKLM:\SOFTWARE\Microsoft\Windows Defender\Exclusions\Extensions',
        'HKLM:\SOFTWARE\Microsoft\Windows Defender\Exclusions\Processes',
        'HKLM:\SOFTWARE\Microsoft\Windows Defender\Exclusions\IpAddresses'
    )
    $anyFound = $false
    foreach ($r in $exclRegRoots) {
        if (-not (Test-Path $r -EA 0)) { continue }
        $props = Get-ItemProperty -Path $r -EA 0
        if (-not $props) { continue }
        foreach ($p in $props.PSObject.Properties) {
            if ($p.Name -match '^PS') { continue }
            $anyFound = $true
            $kind = ($r -split '\\' | Select-Object -Last 1)
            Write-Bad ("[!] Exclusion {0} : {1}" -f $kind, $p.Name)
        }
    }
    if (-not $anyFound) { Write-Status '[-] No Defender exclusions found in registry.' }
} else {
    # Get-MpPreference on non-admin returns a placeholder string for each exclusion list:
    # "N/A: Must be and administrator to view exclusions" (sic, MS typo). Detect & skip.
    $isAdminPlaceholder = {
        param($v)
        if (-not $v) { return $true }
        if ($v -is [string]) { return ($v -match '^N/A: Must be (and|an) administrator') }
        if ($v.Count -eq 1 -and $v[0] -is [string]) { return ($v[0] -match '^N/A: Must be (and|an) administrator') }
        return $false
    }

    $cantRead = (& $isAdminPlaceholder $mp.ExclusionPath) -and
                (& $isAdminPlaceholder $mp.ExclusionExtension) -and
                (& $isAdminPlaceholder $mp.ExclusionProcess) -and
                (& $isAdminPlaceholder $mp.ExclusionIpAddress)
    if ($cantRead) {
        Write-Status '[-] Cannot read Defender exclusions (admin required).'
        Write-Info   '    Try via registry as a workaround:'
        Write-Plain  '      reg query "HKLM\SOFTWARE\Microsoft\Windows Defender\Exclusions" /s'
    } else {
        $hadAny = $false
        if ($mp.ExclusionPath -and $mp.ExclusionPath.Count -gt 0 -and -not (& $isAdminPlaceholder $mp.ExclusionPath)) {
            $hadAny = $true
            foreach ($pth in $mp.ExclusionPath) {
                $writable = $false
                try {
                    $acl = (Get-EffectivePathAccess -TargetPath $pth -TokenPrincipals $tokenPrincipals -CurrentUserSid $currentUserSid)
                    if ($acl.CanChange) { $writable = $true }
                } catch {}
                if ($writable) {
                    Write-Bad  ("[!] Path WRITABLE BY YOU : {0}    -> drop your tooling here" -f $pth)
                } else {
                    Write-Warn ("[!] Path exclusion        : {0}" -f $pth)
                }
            }
        }
        if ($mp.ExclusionExtension -and $mp.ExclusionExtension.Count -gt 0 -and -not (& $isAdminPlaceholder $mp.ExclusionExtension)) {
            $hadAny = $true
            foreach ($ext in $mp.ExclusionExtension) {
                Write-Warn ("[!] Extension exclusion   : {0}" -f $ext)
            }
        }
        if ($mp.ExclusionProcess -and $mp.ExclusionProcess.Count -gt 0 -and -not (& $isAdminPlaceholder $mp.ExclusionProcess)) {
            $hadAny = $true
            foreach ($proc in $mp.ExclusionProcess) {
                Write-Warn ("[!] Process exclusion     : {0}" -f $proc)
            }
        }
        if ($mp.ExclusionIpAddress -and $mp.ExclusionIpAddress.Count -gt 0 -and -not (& $isAdminPlaceholder $mp.ExclusionIpAddress)) {
            $hadAny = $true
            foreach ($ip in $mp.ExclusionIpAddress) {
                Write-Warn ("[!] IP exclusion          : {0}" -f $ip)
            }
        }
        if (-not $hadAny) {
            Write-Status '[-] No Defender exclusions configured.'
        }
    }

    # Also surface AV state - if Defender is fully off, that's huge
    Write-Blank
    $stateRT  = if ($mp.DisableRealtimeMonitoring) { 'DISABLED (!)' } else { 'enabled' }
    $stateBM  = if ($mp.DisableBehaviorMonitoring) { 'DISABLED (!)' } else { 'enabled' }
    $stateIO  = if ($mp.DisableIOAVProtection)     { 'DISABLED (!)' } else { 'enabled' }
    $stateSS  = if ($mp.DisableScriptScanning)     { 'DISABLED (!)' } else { 'enabled' }
    Write-Info ("Real-time monitoring  : {0}" -f $stateRT)
    Write-Info ("Behavior monitoring   : {0}" -f $stateBM)
    Write-Info ("IOAV protection       : {0}" -f $stateIO)
    Write-Info ("Script scanning       : {0}" -f $stateSS)
}
Write-Blank

# ---- Service SDDL (writable service config even when binary is read-only) ----
Write-CMD @'
# Parse sc sdshow for each service - look for AU/BU/IU principals with WP (start), WD (DACL), DC (config) rights.
# WP = SERVICE_START          - restart the service
# DC = SERVICE_CHANGE_CONFIG  - change ImagePath via sc config X binPath= "..."
# WD = WRITE_DAC              - set arbitrary new ACL (turn yourself into owner)
# WO = WRITE_OWNER            - take ownership
Get-Service | ForEach-Object {
    $sd = sc.exe sdshow $_.Name 2>$null
    [PSCustomObject]@{ Name=$_.Name; SDDL=($sd | Out-String).Trim() }
} | Where-Object { $_.SDDL -match '\(A;;[^;]*?(WP|DC|WD|WO)[^;]*?;;;(BU|AU|IU|WD)\)' }
'@
Write-Header 'Services with weak SDDL (config writable / restartable by low-priv)'
Write-Rule   '-------------------------------------------------------------------'
Write-Info   'Catches services where the BINARY is locked down but `sc config` is open to you.'
Write-Info   'Exploit: sc config <Name> binPath= "C:\Path\evil.exe" && sc start <Name>'
Write-Blank

$weakSddlRows = [System.Collections.Generic.List[object]]::new()
$noisyUserSvcCount = 0
foreach ($svc in $allServices) {
    if (-not $svc.Name) { continue }
    $sdRaw = (sc.exe sdshow $svc.Name 2>$null | Where-Object { $_ -match '^D:' }) -join ''
    if (-not $sdRaw) { continue }
    $rights = Get-InterestingServiceRights $sdRaw
    if (-not $rights.CanRestart -and -not $rights.ServiceDaclRisk) { continue }

    # Filter out per-user-service template noise:
    # Names like "WpnUserService_358fc9", "PimIndexMaintenanceSvc_4a654" are user-session
    # service variants. They expose RP/WP to AU/IU because each user instance starts on logon -
    # that is by design and not exploitable cross-user.
    # Keep them ONLY if they have actual DaclRisk (DC/WD/WO), not just RP/WP start rights.
    $isUserSvcTemplate = ($svc.Name -match '_[0-9a-f]{4,8}$') -or
                         ($svc.Name -match '(UserSvc|UserService)$') -or
                         ($svc.Name -match '(UserSvc|UserService)_[0-9a-f]+$')
    if ($isUserSvcTemplate -and -not $rights.ServiceDaclRisk) {
        $noisyUserSvcCount++
        continue
    }

    $weakSddlRows.Add([PSCustomObject]@{
        Service    = $svc.Name
        RunAs      = if ($svc.StartName) { $svc.StartName } else { '?' }
        State      = if ($svc.State)     { $svc.State }     else { '?' }
        Rights     = $rights.Summary
        CanRestart = $rights.CanRestart
        DaclRisk   = $rights.ServiceDaclRisk
        SDDL       = $sdRaw
    })
}
if ($noisyUserSvcCount -gt 0) {
    Write-Info ("(filtered {0} per-user-service template entries with only RP/WP rights - those are by design)" -f $noisyUserSvcCount)
}
if ($weakSddlRows.Count -eq 0) {
    Write-Status '[-] No services with weak SDDL granting low-priv users restart/reconfig.'
} else {
    $flatSDDL = [System.Collections.Generic.List[object]]::new()
    foreach ($w in ($weakSddlRows | Sort-Object @{Expression='DaclRisk';Descending=$true},@{Expression='CanRestart';Descending=$true}, Service)) {
        $tag = if ($w.DaclRisk -and $w.RunAs -match 'LocalSystem|SYSTEM') { '*** PRIVESC' }
               elseif ($w.DaclRisk)        { 'DACL-RISK' }
               elseif ($w.CanRestart -and $w.RunAs -match 'LocalSystem|SYSTEM') { 'RESTART-SYS' }
               elseif ($w.CanRestart)      { 'RESTART' }
               else                        { '-' }
        # Row A
        $flatSDDL.Add([PSCustomObject]@{
            Tag      = $tag
            'Service / SDDL' = $w.Service
            'RunAs / Rights' = $w.RunAs
            'State / -'      = $w.State
        })
        # Row B
        $sddlSnip = if ($w.SDDL.Length -gt 120) { $w.SDDL.Substring(0,117) + '...' } else { $w.SDDL }
        $flatSDDL.Add([PSCustomObject]@{
            Tag      = ''
            'Service / SDDL' = $sddlSnip
            'RunAs / Rights' = $w.Rights
            'State / -'      = '-'
        })
    }
    $tableText = ($flatSDDL | Format-Table -AutoSize | Out-String -Width 4096)
    Write-ColoredTable -Text $tableText -Colorizer {
        param($line)
        if ($line -match '^Tag\s+Service / SDDL')          { return 'Cyan' }
        if ($line -match '^-+\s+-+')                       { return 'DarkGray' }
        if ($line -match '^\*\*\* PRIVESC')                { return 'Red' }
        if ($line -match '^DACL-RISK')                     { return 'Red' }
        if ($line -match '^RESTART-SYS')                   { return 'Magenta' }
        if ($line -match '^RESTART')                       { return 'Yellow' }
        if ($line -match '^\s') {
            if ($line -match $script:WritableAclRegex)     { return 'Red' }
            if ($line -match 'LocalSystem|SYSTEM')         { return 'Magenta' }
            return 'DarkGray'
        }
        return 'White'
    }
    Write-Status ("[+] {0} service(s) with weak SDDL" -f $weakSddlRows.Count)
}
Write-Blank

# =====================================================================
# END QUICK WINS - back to original sections
# =====================================================================

# Services / software
$serviceRows = [System.Collections.Generic.List[object]]::new()
foreach ($svc in $allServices) {
    if (-not $svc.PathName) { continue }
    if (-not $svc.IsUserland) { continue }

    $rawImagePath = [string]$svc.PathName
    $bin = Resolve-BinaryPath $rawImagePath
    if (-not $bin) { continue }

    $unquotedPath = $false
    if ($rawImagePath -and $bin -and $bin -match '\s' -and $rawImagePath.Trim() -notmatch '^"') {
        $unquotedPath = $true
    }

    $sd = (sc.exe sdshow $svc.Name 2>$null | Where-Object { $_ -match '^D:' }) -join ''
    $svcRights = Get-InterestingServiceRights $sd
    $binAccess = Get-EffectivePathAccess -TargetPath $bin -TokenPrincipals $tokenPrincipals -CurrentUserSid $currentUserSid

    $parentDir = $null
    try { $parentDir = Split-Path -Path $bin -Parent } catch { $parentDir = $null }

    $dirAccess = Get-EffectivePathAccess -TargetPath $parentDir -TokenPrincipals $tokenPrincipals -CurrentUserSid $currentUserSid
    $meta = Get-BinaryMetadata $bin
    $isInterestingSoftware = Test-IsInterestingSoftwareService -Company $meta.Company -Product $meta.Product -Path $bin -DisplayName $svc.DisplayName -ServiceName $svc.Name -RawPath $rawImagePath -IsUserland $svc.IsUserland

    $findingParts = @()
    if ($isInterestingSoftware)     { $findingParts += 'software:interesting' }
    if ($svcRights.CanRestart)      { $findingParts += 'svc:restart' }
    if ($svcRights.ServiceDaclRisk) { $findingParts += 'svc:dacl' }
    if ($binAccess.CanChange)       { $findingParts += ('bin:{0}' -f $binAccess.Right) }
    if ($dirAccess.CanChange)       { $findingParts += ('dir:{0}' -f $dirAccess.Right) }
    if ($unquotedPath)              { $findingParts += 'unquoted' }

    $isActionable = ($svcRights.CanRestart -and ($binAccess.CanChange -or $dirAccess.CanChange -or $unquotedPath -or $svcRights.ServiceDaclRisk)) -or
                    $svcRights.ServiceDaclRisk -or $binAccess.CanChange -or $dirAccess.CanChange -or $unquotedPath

    if (-not ($isActionable -or $isInterestingSoftware)) { continue }

    $serviceRows.Add([PSCustomObject]@{
        Service     = $svc.Name
        DisplayName = if ($svc.DisplayName) { $svc.DisplayName } else { 'False' }
        RunAs       = if ($svc.StartName) { $svc.StartName } else { 'False' }
        Company     = $meta.Company
        Product     = $meta.Product
        Path        = $bin
        CanRestart  = $svcRights.CanRestart
        SvcRights   = $svcRights.Summary
        BinAccess   = $binAccess.Detail
        DirAccess   = $dirAccess.Detail
        Findings    = if ($findingParts.Count -gt 0) { $findingParts -join '; ' } else { 'False' }
    })
}
$serviceOut = @($serviceRows | Sort-Object @{ Expression = { if ($_.Findings -match 'bin:|dir:|svc:dacl|unquoted') { 0 } else { 1 } } }, @{ Expression = { if ($_.Findings -match 'software:interesting') { 1 } else { 0 } } }, Company, Service)
$serviceActionable = @($serviceOut | Where-Object { $_.Findings -match 'bin:|dir:|svc:dacl|unquoted' -or ($_.Findings -match 'svc:restart' -and $_.Findings -match 'bin:|dir:|svc:dacl|unquoted') })

Write-CMD @'
Get-CimInstance Win32_Service | ForEach-Object {
    $bin = $_.PathName -replace '^"([^"]+)".*','$1'
    $bin = ($bin -split ' ')[0]
    $sd  = sc.exe sdshow $_.Name 2>$null
    [PSCustomObject]@{ Name=$_.Name; RunAs=$_.StartName; Bin=$bin; SDDL=$sd }
}
icacls "<bin>"  ;  icacls "<parent dir>"
'@
Write-Header 'Services / software'
Write-Rule   '-------------------'
Write-Info   'Service filter: userland services/software only (driver rows are suppressed)'
Write-Blank
if ($serviceOut.Count -eq 0) {
    Write-Status '[-] No interesting service/software rows were found.'
} else {
    $flatSvc = [System.Collections.Generic.List[object]]::new()
    foreach ($row in $serviceOut) {
        $dispName = if ($row.DisplayName -and $row.DisplayName -ne 'False') { [string]$row.DisplayName } else { '-' }
        if ($dispName.Length -gt 50) { $dispName = $dispName.Substring(0, 47) + '...' }
        $runAs = if ($row.RunAs -and $row.RunAs -ne 'False') { $row.RunAs } else { '-' }
        $path  = if ($row.Path  -and $row.Path  -ne 'False') { $row.Path  } else { '-' }
        $bin   = if ($row.BinAccess -and $row.BinAccess -ne 'False') { $row.BinAccess } else { '-' }
        $dir   = if ($row.DirAccess -and $row.DirAccess -ne 'False') { $row.DirAccess } else { '-' }
        $state = 'CanRestart:{0} SvcRights:{1}' -f $row.CanRestart, $row.SvcRights

        # Row A: identity
        $flatSvc.Add([PSCustomObject]@{
            Service          = $row.Service
            'Name / BinACL'  = $dispName
            'RunAs / DirACL' = $runAs
            'Path / State'   = $path
        })
        # Row B: access
        $flatSvc.Add([PSCustomObject]@{
            Service          = ''
            'Name / BinACL'  = $bin
            'RunAs / DirACL' = $dir
            'Path / State'   = $state
        })
    }
    $tableText = ($flatSvc | Format-Table -AutoSize | Out-String -Width 4096)
    Write-ColoredTable -Text $tableText -Colorizer {
        param($line)
        if ($line -match '^Service\s+Name / BinACL')   { return 'Cyan' }
        if ($line -match '^-+\s+-+')                   { return 'DarkGray' }
        # Row B (access row) starts with leading whitespace
        if ($line -match '^\s') {
            if ($line -match $script:WritableAclRegex) { return 'Red' }
            return 'DarkGray'
        }
        return 'White'
    }
}
Write-Status ("[+] {0} interesting service row(s)" -f $serviceOut.Count)
Write-Status ("[+] {0} actionable service row(s)" -f $serviceActionable.Count)
Write-Blank

# Installed software
$installedSoftware = @(Get-InstalledSoftwareInventory -TokenPrincipals $tokenPrincipals -CurrentUserSid $currentUserSid)
Write-CMD @'
Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\*' |
    Select-Object DisplayName,Publisher,DisplayVersion,InstallLocation
Get-ItemProperty 'HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall\*' |
    Select-Object DisplayName,Publisher,DisplayVersion,InstallLocation
Get-ChildItem $env:ProgramFiles -Directory; Get-ChildItem ${env:ProgramFiles(x86)} -Directory
'@
Write-Header 'Installed software'
Write-Rule   '------------------'
Write-Info   'Software filter: uncommon/non-Microsoft software from uninstall data plus top-level Program Files folders'
Write-Blank
if ($installedSoftware.Count -eq 0) {
    Write-Status '[-] No uncommon installed software rows were found.'
} else {
    $tableText = ($installedSoftware |
        Format-Table Name, Publisher, Version, InstallDir, DirAccess, Source -AutoSize |
        Out-String -Width 4096)
    Write-ColoredTable -Text $tableText -Colorizer {
        param($line)
        if ($line -match '^Name\s+Publisher')          { return 'Cyan' }
        if ($line -match '^-+\s+-+')                   { return 'DarkGray' }
        if ($line -match $script:WritableAclRegex)     { return 'Red' }
        return 'White'
    }
    Write-Status ("[+] {0} uncommon installed software row(s)" -f $installedSoftware.Count)
}
Write-Blank

# Unquoted service paths
$unquotedRows = [System.Collections.Generic.List[object]]::new()
foreach ($svc in $allServices) {
    if (-not $svc.PathName) { continue }
    if (-not $svc.IsUserland) { continue }

    $rawImagePath = [string]$svc.PathName
    $bin = Resolve-BinaryPath $rawImagePath
    if (-not $bin) { continue }
    if ($bin -notmatch '\s') { continue }
    if ($rawImagePath.Trim() -match '^"') { continue }

    $candidateDetails = [System.Collections.Generic.List[string]]::new()
    foreach ($candidate in (Get-UnquotedCandidateExecutables -BinaryPath $bin)) {
        $parentDir = $null
        try { $parentDir = Split-Path -Path $candidate -Parent } catch { $parentDir = $null }
        $candDirAccess = Get-EffectivePathAccess -TargetPath $parentDir -TokenPrincipals $tokenPrincipals -CurrentUserSid $currentUserSid
        $accessText = if ($candDirAccess.CanChange) { $candDirAccess.Detail } else { 'False' }
        $candidateDetails.Add(('{0} [{1}]' -f $candidate, $accessText))
    }

    $unquotedRows.Add([PSCustomObject]@{
        Service              = $svc.Name
        DisplayName          = if ($svc.DisplayName) { $svc.DisplayName } else { 'False' }
        RawPath              = $rawImagePath
        ResolvedBinary       = $bin
        CandidateExecutables = if ($candidateDetails.Count -gt 0) { $candidateDetails -join ' | ' } else { 'False' }
    })
}
Write-CMD @'
Get-CimInstance Win32_Service |
    Where-Object { $_.PathName -and $_.PathName.Trim() -notmatch '^"' -and $_.PathName -match ' ' -and $_.PathName -match '\.exe' } |
    Select-Object Name, PathName, StartName
# Then for each path with spaces, walk every prefix and icacls the parent dir.
'@
Write-Header 'Unquoted service paths'
Write-Rule   '----------------------'
if ($unquotedRows.Count -eq 0) {
    Write-Status '[-] No unquoted service paths with spaces were found.'
} else {
    $tableText = ($unquotedRows |
        Format-Table Service, DisplayName, RawPath, ResolvedBinary, CandidateExecutables -AutoSize |
        Out-String -Width 4096)
    Write-ColoredTable -Text $tableText -Colorizer {
        param($line)
        if ($line -match '^Service\s+DisplayName')     { return 'Cyan' }
        if ($line -match '^-+\s+-+')                   { return 'DarkGray' }
        # Any unquoted path that matched is itself an exploit candidate
        return 'Yellow'
    }
    Write-Status ("[+] {0} unquoted service path row(s)" -f $unquotedRows.Count)
}
Write-Blank

# DLL hijack candidates
$dllServiceRows = [System.Collections.Generic.List[object]]::new()
foreach ($svc in $allServices) {
    if (-not $svc.PathName) { continue }
    if (-not $svc.IsUserland) { continue }

    $bin = Resolve-BinaryPath $svc.PathName
    if (-not $bin) { continue }
    $parentDir = $null
    try { $parentDir = Split-Path -Path $bin -Parent } catch { $parentDir = $null }

    $dirAccess = Get-EffectivePathAccess -TargetPath $parentDir -TokenPrincipals $tokenPrincipals -CurrentUserSid $currentUserSid
    if (-not $dirAccess.CanChange) { continue }

    $meta = Get-BinaryMetadata $bin
    if (-not (Test-IsInterestingSoftwareService -Company $meta.Company -Product $meta.Product -Path $bin -DisplayName $svc.DisplayName -ServiceName $svc.Name -RawPath $svc.PathName -IsUserland $svc.IsUserland)) { continue }

    $rightLabel = switch ($dirAccess.Right) {
        'F'     { 'Full' }
        'M'     { 'Modify' }
        'W'     { 'Write' }
        default { if ($dirAccess.Right) { [string]$dirAccess.Right } else { 'False' } }
    }

    $dllServiceRows.Add([PSCustomObject]@{
        Service     = $svc.Name
        DisplayName = if ($svc.DisplayName) { $svc.DisplayName } else { 'False' }
        RunAs       = if ($svc.StartName) { $svc.StartName } else { 'False' }
        Binary      = $bin
        BinaryDir   = if ($parentDir) { $parentDir } else { 'False' }
        DirAccess   = $dirAccess.Detail
        Rights      = $rightLabel
    })
}

$pathRows = [System.Collections.Generic.List[object]]::new()
$machinePath = [Environment]::GetEnvironmentVariable('Path', 'Machine')
foreach ($dir in (@($machinePath -split ';' | Where-Object { $_ } | Select-Object -Unique))) {
    $expandedDir = [Environment]::ExpandEnvironmentVariables($dir)
    $dirAccess = Get-EffectivePathAccess -TargetPath $expandedDir -TokenPrincipals $tokenPrincipals -CurrentUserSid $currentUserSid
    if (-not $dirAccess.CanChange) { continue }
    $pathRightLabel = switch ($dirAccess.Right) {
        'F'     { 'Full' }
        'M'     { 'Modify' }
        'W'     { 'Write' }
        default { if ($dirAccess.Right) { [string]$dirAccess.Right } else { 'False' } }
    }
    $pathRows.Add([PSCustomObject]@{
        PathDir   = $expandedDir
        DirAccess = $dirAccess.Detail
        Rights    = $pathRightLabel
    })
}

Write-CMD @'
# Service binary parent dirs that low-priv users can write to:
Get-CimInstance Win32_Service | ForEach-Object { Split-Path ($_.PathName -replace '^"([^"]+)".*','$1') -Parent } |
    Sort-Object -Unique | ForEach-Object { icacls $_ 2>$null }
# Writable directories on machine PATH:
[Environment]::GetEnvironmentVariable('Path','Machine') -split ';' |
    ForEach-Object { icacls $_ 2>$null }
'@
Write-Header 'DLL hijack candidates'
Write-Rule   '---------------------'
if ($dllServiceRows.Count -eq 0) {
    Write-Status '[-] No service-backed software with writable binary directories were found.'
} else {
    $tableText = ($dllServiceRows |
        Format-Table Service, DisplayName, RunAs, Binary, BinaryDir, DirAccess, Rights -AutoSize |
        Out-String -Width 4096)
    Write-ColoredTable -Text $tableText -Colorizer {
        param($line)
        if ($line -match '^Service\s+DisplayName')     { return 'Cyan' }
        if ($line -match '^-+\s+-+')                   { return 'DarkGray' }
        # Every row here is already a finding (it passed the writable filter)
        return 'Red'
    }
    Write-Status ("[+] {0} service row(s) with writable binary directories" -f $dllServiceRows.Count)
}
if ($pathRows.Count -eq 0) {
    Write-Status '[-] No writable machine PATH directories were found.'
} else {
    $tableText = ($pathRows |
        Format-Table PathDir, DirAccess, Rights -AutoSize |
        Out-String -Width 4096)
    Write-ColoredTable -Text $tableText -Colorizer {
        param($line)
        if ($line -match '^PathDir\s+DirAccess')       { return 'Cyan' }
        if ($line -match '^-+\s+-+')                   { return 'DarkGray' }
        return 'Red'
    }
    Write-Status ("[+] {0} writable machine PATH directorie(s)" -f $pathRows.Count)
}
Write-Blank

# Scheduled tasks
$taskRows = [System.Collections.Generic.List[object]]::new()
$scheduledTaskSupported = [bool](Get-Command Get-ScheduledTask -ErrorAction SilentlyContinue)
if ($scheduledTaskSupported) {
    foreach ($task in @(Get-ScheduledTask -ErrorAction SilentlyContinue)) {
        $actions = @($task.Actions | Where-Object { $_.Execute })
        if ($actions.Count -eq 0) { continue }

        foreach ($action in $actions) {
            $resolvedBinary = Resolve-BinaryPath $action.Execute
            if (-not $resolvedBinary) { continue }

            $parentDir = $null
            try { $parentDir = Split-Path -Path $resolvedBinary -Parent } catch { $parentDir = $null }

            $binAccess = Get-EffectivePathAccess -TargetPath $resolvedBinary -TokenPrincipals $tokenPrincipals -CurrentUserSid $currentUserSid
            $dirAccess = Get-EffectivePathAccess -TargetPath $parentDir -TokenPrincipals $tokenPrincipals -CurrentUserSid $currentUserSid

            $taskPathFull = ('{0}{1}' -f $task.TaskPath, $task.TaskName)
            $taskUserId = if ($task.Principal.UserId) { [string]$task.Principal.UserId } else { 'False' }
            $taskRunsAsCurrentUser = Test-IsCurrentUserTaskContext -TaskUser $taskUserId -CurrentUser $currentUser
            $isBoringWindowsTask = Test-IsBoringWindowsTask -TaskPath $task.TaskPath -ResolvedBinary $resolvedBinary
            $isInteresting = ($binAccess.CanChange -or $dirAccess.CanChange) -and -not $isBoringWindowsTask -and -not $taskRunsAsCurrentUser
            if (-not $isInteresting) { continue }

            $findingParts = @()
            if ($binAccess.CanChange) { $findingParts += ('bin:{0}' -f $binAccess.Right) }
            if ($dirAccess.CanChange) { $findingParts += ('dir:{0}' -f $dirAccess.Right) }

            $taskRows.Add([PSCustomObject]@{
                TaskPath       = $taskPathFull
                UserId         = $taskUserId
                State          = if ($task.State) { $task.State } else { 'False' }
                Execute        = $action.Execute
                Arguments      = if ($action.Arguments) { $action.Arguments } else { 'False' }
                ResolvedBinary = $resolvedBinary
                BinAccess      = $binAccess.Detail
                DirAccess      = $dirAccess.Detail
                Findings       = if ($findingParts.Count -gt 0) { $findingParts -join '; ' } else { 'False' }
            })
        }
    }
}

$taskOut = @($taskRows | Sort-Object TaskPath)
Write-CMD @'
Get-ScheduledTask | ForEach-Object {
    foreach ($a in $_.Actions) {
        [PSCustomObject]@{
            TaskPath=$_.TaskPath+$_.TaskName
            RunAs=$_.Principal.UserId
            Execute=$a.Execute
            Args=$a.Arguments
        }
    }
} | Format-Table -AutoSize
'@
Write-Header 'Scheduled tasks'
Write-Rule   '---------------'
if (-not $scheduledTaskSupported) {
    Write-Status '[!] Scheduled task enumeration is not available via Get-ScheduledTask on this host.'
} elseif ($taskOut.Count -eq 0) {
    Write-Status '[-] No writable/interesting scheduled-task actions were found.'
} else {
    $tableText = ($taskOut |
        Format-Table TaskPath, UserId, State, Execute, Arguments, ResolvedBinary, BinAccess, DirAccess, Findings -AutoSize |
        Out-String -Width 4096)
    Write-ColoredTable -Text $tableText -Colorizer {
        param($line)
        if ($line -match '^TaskPath\s+UserId')         { return 'Cyan' }
        if ($line -match '^-+\s+-+')                   { return 'DarkGray' }
        if ($line -match $script:WritableAclRegex)     { return 'Red' }
        return 'White'
    }
    Write-Status ("[+] {0} interesting writable task action row(s)" -f $taskOut.Count)
}
Write-Blank

# Active network connections
# Non-standard C:\ folders + binaries + cross-reference
Write-CMD @'
$std = 'Windows','Program Files','Program Files (x86)','Users','PerfLogs','Recovery',
       'System Volume Information','$Recycle.Bin','ProgramData','Boot','Intel','AMD','NVIDIA'
Get-ChildItem 'C:\' -Directory -Force | Where-Object { $std -notcontains $_.Name -and $_.Name -notmatch '^\$' }
# For each non-standard folder, list binaries:
Get-ChildItem <folder> -File -Recurse -Force | Where-Object { $_.Extension -in '.exe','.dll','.bat','.cmd','.vbs','.ps1','.com' }
icacls "<binary>"
'@
Write-Header ('Non-standard {0} folders & their binaries' -f $script:SystemDriveRoot)
Write-Rule   '-----------------------------------------'
Write-Info   'Walks every top-level folder under C:\ that is NOT a standard Windows folder.'
Write-Info   'Lists every binary (.exe/.dll/.bat/.cmd/.vbs/.ps1/.com) and cross-references each'
Write-Info   'against scheduled tasks, services, and run keys. A writable binary referenced by a'
Write-Info   'SYSTEM-level task or service is direct privesc.'
Write-Info   'Two-row format: Row A = path/size/mtime, Row B = refs / BinACL / DirACL.'
Write-Blank

# Find non-standard top-level folders (catches C:\TEMP, C:\backup, etc.) - drive resolved dynamically
$nonStdFolders = Get-ChildItem $script:SystemDriveRoot -Directory -Force -EA 0 |
    Where-Object { -not (Test-IsStandardRootName $_.Name) }

if (@($nonStdFolders).Count -eq 0) {
    Write-Status ('[-] No non-standard {0} folders found.' -f $script:SystemDriveRoot)
} else {
    foreach ($f in $nonStdFolders) {
        $folderAccess = (Get-EffectivePathAccess -TargetPath $f.FullName -TokenPrincipals $tokenPrincipals -CurrentUserSid $currentUserSid)
        if ($folderAccess.CanChange) {
            Write-Bad ("[!] Non-standard folder WRITABLE : {0}  ({1})" -f $f.FullName, $folderAccess.Detail)
        } else {
            Write-Good ("[+] Non-standard folder         : {0}" -f $f.FullName)
        }
    }
    Write-Blank

    # ---- Build cross-reference lookup tables ----

    # All scheduled task action paths + arguments (PathName references via wrappers)
    $taskRefMap = @{}
    $allTasksForXref = if ($script:HasScheduledTask) { @(Get-ScheduledTask -EA 0) } else { @() }
    foreach ($task in $allTasksForXref) {
        foreach ($a in @($task.Actions)) {
            if (-not $a.Execute) { continue }
            $exe = Resolve-BinaryPath ([string]$a.Execute)
            if ($exe) {
                $key = $exe.ToLowerInvariant()
                if (-not $taskRefMap.ContainsKey($key)) { $taskRefMap[$key] = New-Object System.Collections.ArrayList }
                $null = $taskRefMap[$key].Add([PSCustomObject]@{
                    TaskPath = ('{0}{1}' -f $task.TaskPath, $task.TaskName)
                    RunAs    = if ($task.Principal.UserId) { $task.Principal.UserId } else { '?' }
                    State    = [string]$task.State
                    Args     = [string]$a.Arguments
                    Source   = 'Execute'
                })
            }
            # Also extract paths from wrapper arguments (cmd /c X.bat, powershell -file X.ps1, rundll32 X.dll,Y)
            if ($a.Arguments) {
                foreach ($am in [regex]::Matches([string]$a.Arguments, '([A-Za-z]:\\[^\s",;]+\.(?:exe|dll|bat|cmd|vbs|ps1|com))', 'IgnoreCase')) {
                    $argExe = Resolve-BinaryPath $am.Value
                    if (-not $argExe) { continue }
                    $argKey = $argExe.ToLowerInvariant()
                    if (-not $taskRefMap.ContainsKey($argKey)) { $taskRefMap[$argKey] = New-Object System.Collections.ArrayList }
                    $null = $taskRefMap[$argKey].Add([PSCustomObject]@{
                        TaskPath = ('{0}{1} [via args]' -f $task.TaskPath, $task.TaskName)
                        RunAs    = if ($task.Principal.UserId) { $task.Principal.UserId } else { '?' }
                        State    = [string]$task.State
                        Args     = [string]$a.Arguments
                        Source   = 'Args'
                    })
                }
            }
        }
    }

    # All service ImagePaths (also catches arguments of cmd-wrapped services)
    $svcRefMap = @{}
    foreach ($svc in $allServices) {
        if (-not $svc.PathName) { continue }
        $bin = Resolve-BinaryPath ([string]$svc.PathName)
        if ($bin) {
            $svcKey = $bin.ToLowerInvariant()
            if (-not $svcRefMap.ContainsKey($svcKey)) { $svcRefMap[$svcKey] = New-Object System.Collections.ArrayList }
            $null = $svcRefMap[$svcKey].Add([PSCustomObject]@{
                Service  = $svc.Name
                Display  = $svc.DisplayName
                RunAs    = $svc.StartName
                State    = $svc.State
            })
        }
        # Also extract from PathName arguments
        foreach ($sm in [regex]::Matches([string]$svc.PathName, '([A-Za-z]:\\[^\s",;]+\.(?:exe|dll|bat|cmd|vbs|ps1|com))', 'IgnoreCase')) {
            $argBin = Resolve-BinaryPath $sm.Value
            if (-not $argBin) { continue }
            $argKey = $argBin.ToLowerInvariant()
            if ($argKey -eq ($bin -as [string]).ToLowerInvariant()) { continue }
            if (-not $svcRefMap.ContainsKey($argKey)) { $svcRefMap[$argKey] = New-Object System.Collections.ArrayList }
            $null = $svcRefMap[$argKey].Add([PSCustomObject]@{
                Service  = ('{0} [via args]' -f $svc.Name)
                Display  = $svc.DisplayName
                RunAs    = $svc.StartName
                State    = $svc.State
            })
        }
    }

    # All run keys
    $runRefMap = @{}
    $runKeyPaths = @(
        'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run',
        'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce',
        'HKLM:\SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Run',
        'HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run',
        'HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce'
    )
    foreach ($rk in $runKeyPaths) {
        if (-not (Test-Path $rk -EA 0)) { continue }
        $props = Get-ItemProperty -Path $rk -EA 0
        if (-not $props) { continue }
        foreach ($p in $props.PSObject.Properties) {
            if ($p.Name -match '^PS' -or -not $p.Value) { continue }
            $exe = Resolve-BinaryPath ([string]$p.Value)
            if (-not $exe) { continue }
            $rkKey = $exe.ToLowerInvariant()
            if (-not $runRefMap.ContainsKey($rkKey)) { $runRefMap[$rkKey] = New-Object System.Collections.ArrayList }
            $null = $runRefMap[$rkKey].Add([PSCustomObject]@{
                RunKey = ('{0}\{1}' -f ($rk -replace '.*\\',''), $p.Name)
                Hive   = if ($rk -match '^HKLM') { 'HKLM' } else { 'HKCU' }
                Value  = [string]$p.Value
            })
        }
    }

    # ---- Walk each non-standard folder, list binaries, cross-reference ----

    $binExts = @('.exe','.dll','.bat','.cmd','.vbs','.ps1','.com')
    $binRows = [System.Collections.Generic.List[object]]::new()

    foreach ($folder in $nonStdFolders) {
        $files = @()
        try {
            $files = @(Get-ChildItem -LiteralPath $folder.FullName -File -Recurse -Force -EA SilentlyContinue |
                Where-Object { $binExts -contains $_.Extension.ToLower() })
        } catch {}

        foreach ($bin in $files) {
            $binPath = $bin.FullName
            $binKey  = $binPath.ToLowerInvariant()

            $binAccess = Get-EffectivePathAccess -TargetPath $binPath -TokenPrincipals $tokenPrincipals -CurrentUserSid $currentUserSid
            $dirPath   = Split-Path -Path $binPath -Parent
            $dirAccess = Get-EffectivePathAccess -TargetPath $dirPath -TokenPrincipals $tokenPrincipals -CurrentUserSid $currentUserSid

            $taskHits = @()
            $svcHits  = @()
            $runHits  = @()
            $hasPrivRef = $false

            if ($taskRefMap.ContainsKey($binKey)) {
                foreach ($t in $taskRefMap[$binKey]) {
                    $taskHits += ('TASK[{0}]:{1} ({2})' -f $t.RunAs, $t.TaskPath, $t.State)
                    if ($t.RunAs -match 'SYSTEM|Administrator|NETWORK SERVICE|LOCAL SERVICE|HighestAvailable') { $hasPrivRef = $true }
                }
            }
            if ($svcRefMap.ContainsKey($binKey)) {
                foreach ($s in $svcRefMap[$binKey]) {
                    $svcHits += ('SVC[{0}]:{1} ({2})' -f $s.RunAs, $s.Service, $s.State)
                    if ($s.RunAs -match 'LocalSystem|NT AUTHORITY\\SYSTEM|NetworkService|LocalService|Administrator') { $hasPrivRef = $true }
                }
            }
            if ($runRefMap.ContainsKey($binKey)) {
                foreach ($r in $runRefMap[$binKey]) {
                    $runHits += ('RUN[{0}]:{1}' -f $r.Hive, $r.RunKey)
                    if ($r.Hive -eq 'HKLM') { $hasPrivRef = $true }
                }
            }

            $allRefs = @($taskHits + $svcHits + $runHits)
            $hasWrite = ($binAccess.CanChange -or $dirAccess.CanChange)
            $isPrivesc = ($hasWrite -and $hasPrivRef)

            $binRows.Add([PSCustomObject]@{
                Path       = $binPath
                Size       = $bin.Length
                Modified   = $bin.LastWriteTime
                BinAccess  = if ($binAccess.CanChange) { $binAccess.Detail } else { '-' }
                DirAccess  = if ($dirAccess.CanChange) { $dirAccess.Detail } else { '-' }
                Refs       = if ($allRefs.Count -gt 0) { $allRefs -join ' | ' } else { '-' }
                RefCount   = $allRefs.Count
                HasWrite   = $hasWrite
                HasPrivRef = $hasPrivRef
                IsPrivesc  = $isPrivesc
            })
        }
    }

    if ($binRows.Count -eq 0) {
        Write-Status '[-] No binaries found in non-standard folders.'
    } else {
        # Sort: privesc first, then referenced-by-priv, then writable, then referenced, then rest
        $sortedBins = $binRows | Sort-Object `
            @{ Expression = { if ($_.IsPrivesc)  { 0 } else { 1 } } },
            @{ Expression = { if ($_.HasPrivRef) { 0 } else { 1 } } },
            @{ Expression = { if ($_.HasWrite)   { 0 } else { 1 } } },
            @{ Expression = { if ($_.RefCount -gt 0) { 0 } else { 1 } } },
            Path

        $flatBins = [System.Collections.Generic.List[object]]::new()
        foreach ($b in $sortedBins) {
            $tag = if     ($b.IsPrivesc)         { '*** PRIVESC' }
                   elseif ($b.HasPrivRef)        { 'PRIV-REF' }
                   elseif ($b.HasWrite)          { 'WRITABLE' }
                   elseif ($b.RefCount -gt 0)    { 'REFERENCED' }
                   else                          { '-' }

            $sizeStr = '{0:N0} B' -f $b.Size
            $mtimeStr = $b.Modified.ToString('yyyy-MM-dd HH:mm')

            # Row A: path / size / mtime
            $flatBins.Add([PSCustomObject]@{
                Tag     = $tag
                'Path / Refs'   = $b.Path
                'Size / BinACL' = $sizeStr
                'Mtime / DirACL'= $mtimeStr
            })
            # Row B: refs / BinACL / DirACL
            $flatBins.Add([PSCustomObject]@{
                Tag     = ''
                'Path / Refs'   = $b.Refs
                'Size / BinACL' = $b.BinAccess
                'Mtime / DirACL'= $b.DirAccess
            })
        }

        $tableText = ($flatBins | Format-Table -AutoSize | Out-String -Width 4096)
        Write-ColoredTable -Text $tableText -Colorizer {
            param($line)
            if ($line -match '^Tag\s+Path / Refs')              { return 'Cyan' }
            if ($line -match '^-+\s+-+')                        { return 'DarkGray' }
            if ($line -match '^\*\*\* PRIVESC')                 { return 'Red' }
            if ($line -match '^PRIV-REF')                       { return 'Magenta' }
            if ($line -match '^WRITABLE')                       { return 'Yellow' }
            if ($line -match '^REFERENCED')                     { return 'White' }
            # Row B (starts with whitespace)
            if ($line -match '^\s') {
                if ($line -match $script:WritableAclRegex)      { return 'Red' }
                if ($line -match 'TASK\[(SYSTEM|Administrator|NETWORK SERVICE|LOCAL SERVICE)\]|SVC\[(LocalSystem|NT AUTHORITY)') { return 'Magenta' }
                if ($line -match 'TASK\[|SVC\[|RUN\[')          { return 'Yellow' }
                return 'DarkGray'
            }
            return 'White'
        }

        $cnt_privesc = @($binRows | Where-Object { $_.IsPrivesc }).Count
        $cnt_privref = @($binRows | Where-Object { $_.HasPrivRef }).Count
        $cnt_writ    = @($binRows | Where-Object { $_.HasWrite   }).Count
        $cnt_refd    = @($binRows | Where-Object { $_.RefCount -gt 0 }).Count
        Write-Status ("[+] {0} binaries scanned" -f $binRows.Count)
        Write-Status ("[+] {0} writable, {1} referenced, {2} priv-referenced, {3} *** PRIVESC ***" -f $cnt_writ, $cnt_refd, $cnt_privref, $cnt_privesc)
    }

    # Bonus: scheduled tasks pointing OUTSIDE Windows/Program Files - red flag even without binary
    Write-Blank
    # ---- Local helper that fixes the buggy original Test-PathUnder ----
    # The original uses TrimEnd('\\') + "$b + '\\'" which appends LITERAL two
    # backslashes, so paths almost never match. This helper does it right.
    function Test-PathInside {
        param([string]$Path, [string]$Base)
        if ([string]::IsNullOrWhiteSpace($Path) -or [string]::IsNullOrWhiteSpace($Base)) { return $false }
        $p = $Path.TrimEnd('\').ToLowerInvariant()
        $b = $Base.TrimEnd('\').ToLowerInvariant()
        if ($p -eq $b) { return $true }
        return $p.StartsWith($b + '\')
    }
    function Test-IsStandardLocation {
        param([string]$ExePath)
        if (-not $ExePath) { return $false }
        $sysRoot = Get-SystemRootPath
        if (Test-PathInside -Path $ExePath -Base $sysRoot) { return $true }
        foreach ($pr in (Get-ProgramRoots)) {
            if (Test-PathInside -Path $ExePath -Base $pr) { return $true }
        }
        return $false
    }
    function Get-NonStandardArgPaths {
        param([string]$Args)
        $hits = [System.Collections.Generic.List[string]]::new()
        if ([string]::IsNullOrWhiteSpace($Args)) { return @() }
        foreach ($am in [regex]::Matches([string]$Args, '([A-Za-z]:\\[^\s",;\)]+\.(?:exe|dll|bat|cmd|vbs|ps1|com|js|wsf|py|jar))', 'IgnoreCase')) {
            $argExe = Resolve-BinaryPath $am.Value
            if (-not $argExe) { continue }
            if (-not (Test-IsStandardLocation $argExe)) { $null = $hits.Add($argExe) }
        }
        return ,$hits.ToArray()
    }

    Write-CMD @'
Get-ScheduledTask | Where-Object { $_.TaskPath -notmatch '^\\Microsoft\\' } |
    ForEach-Object {
        foreach ($a in $_.Actions) {
            [PSCustomObject]@{
                Task    = $_.TaskPath + $_.TaskName
                RunAs   = $_.Principal.UserId
                State   = $_.State
                Execute = $a.Execute
                Args    = $a.Arguments
            }
        }
    } | Format-Table -AutoSize
# Then for any path inside Args, icacls each one.
'@
    Write-Header 'Custom (non-Microsoft) scheduled tasks'
    Write-Rule   '---------------------------------------'
    Write-Info   'Filter: TaskPath does NOT start with \Microsoft\  (drops the Windows overload).'
    Write-Info   'Two-row format: Row A = task identity, Row B = action + args + ACL of action target.'
    Write-Info   'Args column is also scanned for paths in non-standard locations (catches cmd /c X).'
    Write-Blank

    $customTaskRows = [System.Collections.Generic.List[object]]::new()
    if (-not $script:HasScheduledTask) {
        Write-Status '[!] Get-ScheduledTask not available on this PowerShell version.'
        Write-Info   '    Manual fallback: schtasks /query /fo LIST /v | findstr /v "\\Microsoft\\"'
    } else {
    foreach ($task in @(Get-ScheduledTask -EA 0)) {
        # Skip Microsoft built-ins
        if ([string]$task.TaskPath -match '^\\Microsoft\\') { continue }
        foreach ($a in @($task.Actions)) {
            $exeRaw = [string]$a.Execute
            $exe    = Resolve-BinaryPath $exeRaw
            $args   = if ($a.Arguments) { [string]$a.Arguments } else { '' }
            $exists = $false
            if ($exe) { $exists = Test-Path -LiteralPath $exe -EA 0 }
            $binACL = if ($exists) { (Get-EffectivePathAccess -TargetPath $exe -TokenPrincipals $tokenPrincipals -CurrentUserSid $currentUserSid).Detail } else { '[not found]' }
            $dirACL = '-'
            if ($exists) {
                $dirACL = (Get-EffectivePathAccess -TargetPath (Split-Path $exe -Parent) -TokenPrincipals $tokenPrincipals -CurrentUserSid $currentUserSid).Detail
            }
            $argHits = Get-NonStandardArgPaths -Args $args
            # ACLs of arg-referenced binaries
            $argAclLines = @()
            foreach ($ah in $argHits) {
                $exists2 = Test-Path -LiteralPath $ah -EA 0
                $acl     = if ($exists2) { (Get-EffectivePathAccess -TargetPath $ah -TokenPrincipals $tokenPrincipals -CurrentUserSid $currentUserSid).Detail } else { '[not found]' }
                $argAclLines += ('{0} -> {1}' -f $ah, $acl)
            }
            $customTaskRows.Add([PSCustomObject]@{
                Task    = ('{0}{1}' -f $task.TaskPath, $task.TaskName)
                RunAs   = if ($task.Principal.UserId) { $task.Principal.UserId } else { '?' }
                State   = [string]$task.State
                ExeRaw  = $exeRaw
                Exe     = if ($exe) { $exe } else { $exeRaw }
                Args    = if ($args) { $args } else { '-' }
                BinACL  = $binACL
                DirACL  = $dirACL
                ArgHits = $argAclLines
                Exists  = $exists
                ExeIsStandard = if ($exe) { Test-IsStandardLocation $exe } else { $false }
            })
        }
    }

    if ($customTaskRows.Count -eq 0) {
        Write-Status '[-] No custom (non-Microsoft) scheduled tasks found.'
    } else {
        $flatCT = [System.Collections.Generic.List[object]]::new()
        $sortedCT = $customTaskRows | Sort-Object `
            @{ Expression = { ($_.BinACL -ne 'False' -and $_.BinACL -ne '[not found]' -and $_.RunAs -match 'SYSTEM|Administrator|HighestAvailable') }; Descending = $true },
            @{ Expression = { ($_.ArgHits | Where-Object { $_ -notmatch 'False$' }).Count -gt 0 }; Descending = $true },
            @{ Expression = { -not $_.ExeIsStandard }; Descending = $true },
            Task

        foreach ($w in $sortedCT) {
            $argActionable = ($w.ArgHits | Where-Object { $_ -notmatch '\sFalse$|\[not found\]$' }).Count -gt 0
            $tag = if     ($w.BinACL -ne 'False' -and $w.BinACL -ne '[not found]' -and $w.RunAs -match 'SYSTEM|Administrator|HighestAvailable') { '*** PRIVESC' }
                   elseif ($argActionable -and $w.RunAs -match 'SYSTEM|Administrator|HighestAvailable')                                          { '*** PRIVESC' }
                   elseif ($w.BinACL -ne 'False' -and $w.BinACL -ne '[not found]')                                                               { 'WRITABLE' }
                   elseif ($w.RunAs -match 'SYSTEM|Administrator|HighestAvailable' -and -not $w.ExeIsStandard)                                  { 'PRIV-NONSTD' }
                   elseif ($w.RunAs -match 'SYSTEM|Administrator|HighestAvailable')                                                              { 'PRIV-CUSTOM' }
                   elseif (-not $w.Exists)                                                                                                       { 'MISSING' }
                   else                                                                                                                          { 'CUSTOM' }
            # Row A: Task / RunAs / Exec
            $flatCT.Add([PSCustomObject]@{
                Tag       = $tag
                'Task / Args'    = $w.Task
                'RunAs / BinACL' = $w.RunAs
                'Exec / DirACL'  = $w.Exe
            })
            # Row B: Args / BinACL / DirACL
            $argDisplay = $w.Args
            if ($w.ArgHits.Count -gt 0) {
                $argDisplay = $w.Args + ' || NON-STD: ' + ($w.ArgHits -join ' ; ')
            }
            $flatCT.Add([PSCustomObject]@{
                Tag       = ''
                'Task / Args'    = $argDisplay
                'RunAs / BinACL' = $w.BinACL
                'Exec / DirACL'  = $w.DirACL
            })
        }

        $tableText = ($flatCT | Format-Table -AutoSize | Out-String -Width 4096)
        Write-ColoredTable -Text $tableText -Colorizer {
            param($line)
            if ($line -match '^Tag\s+Task / Args')             { return 'Cyan' }
            if ($line -match '^-+\s+-+')                       { return 'DarkGray' }
            if ($line -match '^\*\*\* PRIVESC')                { return 'Red' }
            if ($line -match '^WRITABLE')                      { return 'Yellow' }
            if ($line -match '^PRIV-(NONSTD|CUSTOM)')          { return 'Magenta' }
            if ($line -match '^CUSTOM')                        { return 'White' }
            if ($line -match '^MISSING')                       { return 'DarkYellow' }
            if ($line -match '^\s') {
                if ($line -match 'NON-STD:')                   { return 'Red' }
                if ($line -match $script:WritableAclRegex)     { return 'Red' }
                if ($line -match 'SYSTEM|Administrator')       { return 'Magenta' }
                return 'DarkGray'
            }
            return 'White'
        }
        Write-Status ("[+] {0} custom (non-Microsoft) scheduled task action(s)" -f $customTaskRows.Count)
    }
    }  # end if HasScheduledTask

    # ---- Recent task launches from event log (catches \backup runner etc.) ----
    Write-Blank
    Write-CMD @'
Get-WinEvent -FilterHashtable @{
    LogName='Microsoft-Windows-TaskScheduler/Operational'
    Id=100,107,129,200,201
} -MaxEvents 200 |
    Where-Object { $_.Message -notmatch '\\Microsoft\\Windows\\' } |
    Select-Object TimeCreated, Id, Message
# If the log is disabled:  wevtutil sl Microsoft-Windows-TaskScheduler/Operational /e:true
'@
    Write-Header 'Recent custom task launches (event log, last 200, non-Microsoft only)'
    Write-Rule   '---------------------------------------------------------------------'
    Write-Info   'Source: Microsoft-Windows-TaskScheduler/Operational - events 100/107/129/200/201.'
    Write-Info   'Filtered: only tasks NOT under \Microsoft\Windows\.  This shows what actually ran.'
    Write-Blank

    $tsEvents = $null
    if (-not $script:HasWinEvent) {
        Write-Status '[!] Get-WinEvent not available on this PowerShell version - skipping event log section.'
        Write-Info   '    Manual fallback: wevtutil qe Microsoft-Windows-TaskScheduler/Operational /c:200 /f:text'
    } else {
        try {
            $tsEvents = Get-WinEvent -FilterHashtable @{
                LogName = 'Microsoft-Windows-TaskScheduler/Operational'
                Id      = 100,107,129,200,201
            } -MaxEvents 200 -ErrorAction Stop
        } catch {
            Write-Status ("[!] Unable to read TaskScheduler/Operational log: {0}" -f $_.Exception.Message)
            Write-Info   'Tip: it may be disabled. Enable with:'
            Write-Plain  '  wevtutil sl Microsoft-Windows-TaskScheduler/Operational /e:true'
        }
    }

    if ($tsEvents) {
        $eventRows = [System.Collections.Generic.List[object]]::new()
        foreach ($ev in $tsEvents) {
            $taskName = $null
            $actionName = $null
            $userCtx = $null
            $procId = $null
            $rc = $null
            try {
                $props = $ev.Properties
                # NOTE: TaskScheduler/Operational property order on Server 2022:
                #   100: TaskName(0), UserContext(1), InstanceId(2)
                #   107: TaskName(0), InstanceId(1)
                #   129: TaskName(0), Path/ActionName(1), ProcessID(2), InstanceId(3), UserContext(4)
                #   200: TaskName(0), ActionName(1), InstanceId(2), EnginePID(3)
                #   201: TaskName(0), InstanceId(1), ActionName(2), ResultCode(3), EnginePID(4)
                switch ($ev.Id) {
                    100 {
                        $taskName = $props[0].Value
                        if ($props.Count -gt 1) { $userCtx = $props[1].Value }
                    }
                    107 {
                        $taskName = $props[0].Value
                    }
                    129 {
                        $taskName = $props[0].Value
                        if ($props.Count -gt 1) { $actionName = $props[1].Value }
                        if ($props.Count -gt 2) { $procId = $props[2].Value }
                    }
                    200 {
                        $taskName   = $props[0].Value
                        if ($props.Count -gt 1) { $actionName = $props[1].Value }
                    }
                    201 {
                        $taskName = $props[0].Value
                        if ($props.Count -gt 2) { $actionName = $props[2].Value }
                        if ($props.Count -gt 3) { $rc = $props[3].Value }
                    }
                }
            } catch {}

            if (-not $taskName) { continue }
            # Skip Microsoft built-ins
            if ([string]$taskName -match '^\\Microsoft\\') { continue }

            $detail = switch ($ev.Id) {
                100 { 'STARTED  user={0}' -f $userCtx }
                107 { 'TRIGGER  time-based fire' }
                129 { 'LAUNCH   action={0} pid={1}' -f $actionName, $procId }
                200 { 'ACTION   action={0}' -f $actionName }
                201 { 'COMPLETE action={0} rc={1}' -f $actionName, $rc }
            }

            $eventRows.Add([PSCustomObject]@{
                Time   = $ev.TimeCreated
                EvtId  = $ev.Id
                Task   = $taskName
                Detail = $detail
            })
        }

        if ($eventRows.Count -eq 0) {
            Write-Status '[-] No recent non-Microsoft task activity in event log.'
        } else {
            # Pre-resolve task -> {Execute, Arguments} via registry blob (works even when
            # Get-ScheduledTask / schtasks / file are all locked). Then enrich the Detail
            # column of each event row so the user sees the FULL command line, not just
            # 'action=cmd.exe'.
            $regArgsMap = @{}
            $distinctNames = @($eventRows | ForEach-Object { $_.Task } | Sort-Object -Unique)
            foreach ($tn in $distinctNames) {
                try {
                    $regDef = Get-TaskDefFromRegistry -TaskPath $tn
                    if ($regDef -and $regDef.Parsed -and $regDef.Parsed.Actions.Count -gt 0) {
                        $a0 = $regDef.Parsed.Actions[0]
                        $regArgsMap[$tn.ToLowerInvariant()] = [PSCustomObject]@{
                            Execute   = $a0.Execute
                            Arguments = $a0.Arguments
                            WorkDir   = $a0.WorkingDirectory
                        }
                    }
                } catch {}
            }
            # Mutate Detail in-place for the event types that show "action=" (200, 129, 201)
            foreach ($r in $eventRows) {
                $key = $r.Task.ToLowerInvariant()
                if (-not $regArgsMap.ContainsKey($key)) { continue }
                $info = $regArgsMap[$key]
                if (-not $info.Arguments) { continue }
                if ($r.EvtId -eq 200 -or $r.EvtId -eq 129 -or $r.EvtId -eq 201) {
                    $r.Detail = ('{0} args=[{1}]' -f $r.Detail, $info.Arguments)
                }
            }

            # Build a one-shot map of every scheduled task by full path (TaskPath + TaskName)
            # so we can look up details fast without per-task Get-ScheduledTask calls.
            $taskMap = @{}
            if ($script:HasScheduledTask) {
                foreach ($t in @(Get-ScheduledTask -EA 0)) {
                    $fullPath = ('{0}{1}' -f $t.TaskPath, $t.TaskName)
                    $taskMap[$fullPath.ToLowerInvariant()] = $t
                }
            }
            # If empty (older PS or DACL-restricted), the schtasks /xml + file + registry
            # fallbacks inside the foreach below will still pull task definitions on demand.

            # Show all rows newest first; collapse adjacent rows for the same task into a header + indented details
            $sortedEv = $eventRows | Sort-Object Time -Descending
            $tableText = ($sortedEv |
                Format-Table @{N='Time';E={$_.Time.ToString('yyyy-MM-dd HH:mm:ss')};W=20},
                             @{N='Evt';E={$_.EvtId};W=4},
                             @{N='Task';E={$_.Task};W=40},
                             @{N='Detail';E={$_.Detail}} -AutoSize |
                Out-String -Width 4096)
            Write-ColoredTable -Text $tableText -Colorizer {
                param($line)
                if ($line -match '^Time\s+Evt')                    { return 'Cyan' }
                if ($line -match '^-+\s+-+')                       { return 'DarkGray' }
                if ($line -match 'SYSTEM|Administrator')           { return 'Red' }
                if ($line -match 'rc=0\b')                         { return 'Green' }
                if ($line -match 'LAUNCH|ACTION')                  { return 'Yellow' }
                return 'White'
            }

            # Distinct tasks - show binary path, args, ACL details
            Write-Blank
            Write-Header 'Distinct non-Microsoft tasks seen in event log (with binary detail)'
            Write-Rule   '--------------------------------------------------------------------'
            $distinct = $eventRows | Group-Object Task | Sort-Object Count -Descending
            foreach ($g in $distinct) {
                $key = $g.Name.ToLowerInvariant()
                $t = $taskMap[$key]

                # Fallback 1: schtasks /query /xml works on tasks that Get-ScheduledTask can't enumerate
                # (low-priv user vs task DACL). Build a shim object with the same shape.
                $tFromXml = $null
                if (-not $t) {
                    try {
                        $rawXml = & schtasks.exe /query /tn $g.Name /xml ALL 2>$null | Out-String
                        if ($rawXml -and $rawXml -match '<Task') {
                            # schtasks may emit a leading hostname banner before the XML - trim to the first '<'
                            $idx = $rawXml.IndexOf('<')
                            if ($idx -gt 0) { $rawXml = $rawXml.Substring($idx) }
                            $doc = [xml]$rawXml
                            $execActions = @()
                            if ($doc.Task.Actions.Exec) {
                                foreach ($exNode in @($doc.Task.Actions.Exec)) {
                                    $execActions += [PSCustomObject]@{
                                        Execute          = $exNode.Command
                                        Arguments        = $exNode.Arguments
                                        WorkingDirectory = $exNode.WorkingDirectory
                                    }
                                }
                            }
                            $trigList = @()
                            if ($doc.Task.Triggers) {
                                foreach ($tNode in $doc.Task.Triggers.ChildNodes) {
                                    $trigShim = [PSCustomObject]@{
                                        CimClass     = [PSCustomObject]@{ CimClassName = $tNode.LocalName }
                                        Repetition   = $null
                                        StartBoundary = $tNode.StartBoundary
                                    }
                                    if ($tNode.Repetition -and $tNode.Repetition.Interval) {
                                        $trigShim.Repetition = [PSCustomObject]@{ Interval = $tNode.Repetition.Interval }
                                    }
                                    $trigList += $trigShim
                                }
                            }
                            $userIdNode = $null
                            if ($doc.Task.Principals.Principal.UserId) { $userIdNode = $doc.Task.Principals.Principal.UserId }
                            elseif ($doc.Task.Principals.Principal.GroupId) { $userIdNode = $doc.Task.Principals.Principal.GroupId }
                            $tFromXml = [PSCustomObject]@{
                                Principal = [PSCustomObject]@{ UserId = $userIdNode }
                                Actions   = $execActions
                                Triggers  = $trigList
                                State     = '(via schtasks)'
                                _Source   = 'schtasks-xml'
                            }
                            $t = $tFromXml
                        }
                    } catch {}
                }

                # Fallback 2: read task XML directly from %SystemRoot%\System32\Tasks\<path>\<name>
                # The Tasks dir has Authenticated Users:(RX) by default - bypasses Schedule service entirely.
                # Files are UTF-16 LE with a BOM - PowerShell handles it via Get-Content -Raw.
                if (-not $t) {
                    try {
                        $relPath  = $g.Name.TrimStart('\')
                        $taskFile = Join-Path (Join-Path $script:SystemRootDir 'System32\Tasks') $relPath
                        $fileExists = $false
                        # Test-Path raises a non-terminating "Access denied" error on locked tasks
                        # (like \backup runner). Wrap in try/catch with -EA Stop to capture it cleanly.
                        try { $fileExists = Test-Path -LiteralPath $taskFile -PathType Leaf -ErrorAction Stop } catch { $fileExists = $false }
                        if ($fileExists) {
                            $rawXml = Get-Content -LiteralPath $taskFile -Raw -ErrorAction Stop
                            # Strip any BOM
                            $rawXml = $rawXml.TrimStart([char]0xFEFF, [char]0xFFFE)
                            if ($rawXml -match '<Task') {
                                $idx = $rawXml.IndexOf('<')
                                if ($idx -gt 0) { $rawXml = $rawXml.Substring($idx) }
                                $doc = [xml]$rawXml
                                $execActions = @()
                                if ($doc.Task.Actions.Exec) {
                                    foreach ($exNode in @($doc.Task.Actions.Exec)) {
                                        $execActions += [PSCustomObject]@{
                                            Execute          = $exNode.Command
                                            Arguments        = $exNode.Arguments
                                            WorkingDirectory = $exNode.WorkingDirectory
                                        }
                                    }
                                }
                                $trigList = @()
                                if ($doc.Task.Triggers) {
                                    foreach ($tNode in $doc.Task.Triggers.ChildNodes) {
                                        $trigShim = [PSCustomObject]@{
                                            CimClass      = [PSCustomObject]@{ CimClassName = $tNode.LocalName }
                                            Repetition    = $null
                                            StartBoundary = $tNode.StartBoundary
                                        }
                                        if ($tNode.Repetition -and $tNode.Repetition.Interval) {
                                            $trigShim.Repetition = [PSCustomObject]@{ Interval = $tNode.Repetition.Interval }
                                        }
                                        $trigList += $trigShim
                                    }
                                }
                                $userIdNode = $null
                                if ($doc.Task.Principals.Principal.UserId)        { $userIdNode = $doc.Task.Principals.Principal.UserId }
                                elseif ($doc.Task.Principals.Principal.GroupId)   { $userIdNode = $doc.Task.Principals.Principal.GroupId }
                                $t = [PSCustomObject]@{
                                    Principal = [PSCustomObject]@{ UserId = $userIdNode }
                                    Actions   = $execActions
                                    Triggers  = $trigList
                                    State     = ('(via filesystem: {0})' -f $taskFile)
                                    _Source   = 'taskfile-xml'
                                    _FilePath = $taskFile
                                }
                            }
                        }
                    } catch {}
                }

                # Fallback 3: parse the registry binary blob at TaskCache\Tasks\{GUID}\Actions.
                # Different ACL than the file - usually readable by Authenticated Users even when
                # the task XML in System32\Tasks is locked. Recovers Execute + Arguments + WorkDir.
                if (-not $t) {
                    try {
                        $regDef = Get-TaskDefFromRegistry -TaskPath $g.Name
                        if ($regDef -and $regDef.Parsed -and $regDef.Parsed.Actions.Count -gt 0) {
                            $execActions = @()
                            foreach ($a in $regDef.Parsed.Actions) {
                                $execActions += [PSCustomObject]@{
                                    Execute          = $a.Execute
                                    Arguments        = $a.Arguments
                                    WorkingDirectory = $a.WorkingDirectory
                                }
                            }
                            $t = [PSCustomObject]@{
                                Principal = [PSCustomObject]@{ UserId = $regDef.Parsed.Context }
                                Actions   = $execActions
                                Triggers  = @()
                                State     = ('(via registry blob: {0})' -f $regDef.Guid)
                                _Source   = 'registry-blob'
                                _Guid     = $regDef.Guid
                            }
                        }
                    } catch {}
                }

                $runAs = if ($t) { $t.Principal.UserId } else { '?' }
                $state = if ($t) { [string]$t.State } else { '?' }

                Write-Bad ("[!] {0}    runs={1}  RunAs={2}  State={3}" -f $g.Name, $g.Count, $runAs, $state)
                if (-not $t) {
                    Write-Info '    (task definition not found via Get-ScheduledTask, schtasks /xml, filesystem, OR registry - all paths blocked)'
                    Write-Info ('    Manual: schtasks /query /tn "{0}" /xml ALL' -f $g.Name)
                    Write-Info ('    Manual: type "{0}\System32\Tasks{1}"' -f $script:SystemRootDir, $g.Name)
                    Write-Info ('    Manual: reg query "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Schedule\TaskCache\Tree{0}"' -f $g.Name)
                    Write-Blank
                    continue
                }
                if ($t._Source -eq 'schtasks-xml') {
                    Write-Info '    (definition pulled via schtasks /xml fallback - Get-ScheduledTask did not see it)'
                }
                if ($t._Source -eq 'taskfile-xml') {
                    Write-Info ('    (definition pulled from filesystem: {0})' -f $t._FilePath)
                }
                if ($t._Source -eq 'registry-blob') {
                    Write-Info ('    (definition recovered from registry blob - GUID {0})' -f $t._Guid)
                }

                # Iterate ALL actions, not just first - some tasks chain multiple
                $actionIdx = 0
                foreach ($a in @($t.Actions)) {
                    $actionIdx++
                    $exeRaw = [string]$a.Execute
                    $args   = if ($a.Arguments) { [string]$a.Arguments } else { '' }
                    $exe    = Resolve-BinaryPath $exeRaw
                    Write-Info ("    Action #{0}" -f $actionIdx)
                    Write-Info ("      Execute   : {0}" -f $exeRaw)
                    if ($exe -and $exe -ne $exeRaw) {
                        Write-Info ("      Resolved  : {0}" -f $exe)
                    }
                    if ($args) {
                        Write-Info ("      Arguments : {0}" -f $args)
                    }
                    if ($a.WorkingDirectory) {
                        Write-Info ("      WorkingDir: {0}" -f $a.WorkingDirectory)
                    }

                    # ACL of the Execute binary
                    if ($exe -and (Test-Path -LiteralPath $exe -EA 0)) {
                        $binAcl = (Get-EffectivePathAccess -TargetPath $exe -TokenPrincipals $tokenPrincipals -CurrentUserSid $currentUserSid).Detail
                        $dirAcl = (Get-EffectivePathAccess -TargetPath (Split-Path $exe -Parent) -TokenPrincipals $tokenPrincipals -CurrentUserSid $currentUserSid).Detail
                        if ($binAcl -ne 'False') {
                            Write-Bad  ("      *** BinACL    WRITABLE: {0}" -f $binAcl)
                        } else {
                            Write-Info ("      BinACL    : -")
                        }
                        if ($dirAcl -ne 'False') {
                            Write-Bad  ("      *** DirACL    WRITABLE: {0}" -f $dirAcl)
                        } else {
                            Write-Info ("      DirACL    : -")
                        }
                    } elseif ($exe) {
                        Write-Info ("      BinACL    : [not found - resolves to {0}]" -f $exe)
                    }

                    # Walk arguments for inline binary paths (cmd /c X.exe, powershell -file X.ps1, rundll32 X.dll)
                    if ($args) {
                        foreach ($am in [regex]::Matches($args, '([A-Za-z]:\\[^\s",;\)]+\.(?:exe|dll|bat|cmd|vbs|ps1|com|js|wsf|py|jar))', 'IgnoreCase')) {
                            $argExe = Resolve-BinaryPath $am.Value
                            if (-not $argExe) { continue }
                            $exists2 = Test-Path -LiteralPath $argExe -EA 0
                            if ($exists2) {
                                $acl = (Get-EffectivePathAccess -TargetPath $argExe -TokenPrincipals $tokenPrincipals -CurrentUserSid $currentUserSid).Detail
                                $isStandard = Test-IsStandardLocation $argExe
                                if ($acl -ne 'False') {
                                    if ($runAs -match 'SYSTEM|Administrator|HighestAvailable') {
                                        Write-Bad  ("      *** ARG TARGET *** PRIVESC ***: {0}  ({1})  RunAs={2}" -f $argExe, $acl, $runAs)
                                    } else {
                                        Write-Bad  ("      *** ARG TARGET writable: {0}  ({1})" -f $argExe, $acl)
                                    }
                                } elseif (-not $isStandard) {
                                    Write-Warn ("      arg target (non-std): {0}  ACL={1}" -f $argExe, $acl)
                                } else {
                                    Write-Info ("      arg target: {0}  ACL=-" -f $argExe)
                                }
                            } else {
                                Write-Warn ("      arg target [missing]: {0}" -f $argExe)
                            }
                        }
                    }

                    # Triggers: when does it actually fire?
                    $trigStrs = @()
                    foreach ($trig in @($t.Triggers)) {
                        $tType = $trig.CimClass.CimClassName
                        $tDesc = $tType
                        if ($trig.Repetition -and $trig.Repetition.Interval) {
                            $tDesc += (' [repeat={0}]' -f $trig.Repetition.Interval)
                        }
                        if ($trig.StartBoundary) { $tDesc += (' [start={0}]' -f $trig.StartBoundary) }
                        $trigStrs += $tDesc
                    }
                    if ($trigStrs.Count -gt 0) {
                        Write-Info ("      Triggers  : {0}" -f ($trigStrs -join '; '))
                    }
                }
                Write-Blank
            }
        }
    }

    # ---- Services pointing OUTSIDE Windows/Program Files (corrected path check) ----
    Write-Blank
    Write-CMD @'
Get-CimInstance Win32_Service | ForEach-Object {
    $bin = $_.PathName -replace '^"([^"]+)".*','$1'
    $bin = ($bin -split ' ')[0]
    if ($bin -notmatch '^C:\\Windows' -and $bin -notmatch '^C:\\Program Files') {
        [PSCustomObject]@{ Name=$_.Name; RunAs=$_.StartName; State=$_.State; Bin=$bin }
    }
} | Format-Table -AutoSize
'@
    Write-Header 'Services pointing into non-standard locations'
    Write-Rule   '---------------------------------------------'
    Write-Info   'Filter: ImagePath resolves outside C:\Windows and Program Files - true outliers only.'
    Write-Blank

    $weirdSvcRows = [System.Collections.Generic.List[object]]::new()
    foreach ($svc in $allServices) {
        if (-not $svc.PathName) { continue }
        if (-not $svc.IsUserland) { continue }
        $exe = Resolve-BinaryPath ([string]$svc.PathName)
        if (-not $exe) { continue }
        if (Test-IsStandardLocation $exe) { continue }
        $exists = Test-Path -LiteralPath $exe -EA 0
        $binACL = if ($exists) { (Get-EffectivePathAccess -TargetPath $exe -TokenPrincipals $tokenPrincipals -CurrentUserSid $currentUserSid).Detail } else { '[not found]' }
        $dirACL = if ($exists) { (Get-EffectivePathAccess -TargetPath (Split-Path $exe -Parent) -TokenPrincipals $tokenPrincipals -CurrentUserSid $currentUserSid).Detail } else { '[not found]' }
        $weirdSvcRows.Add([PSCustomObject]@{
            Service  = $svc.Name
            Display  = $svc.DisplayName
            RunAs    = $svc.StartName
            State    = $svc.State
            Path     = $exe
            BinACL   = $binACL
            DirACL   = $dirACL
        })
    }
    if ($weirdSvcRows.Count -eq 0) {
        Write-Status '[-] No userland services point outside standard folders.'
    } else {
        $flatWS = [System.Collections.Generic.List[object]]::new()
        foreach ($w in ($weirdSvcRows | Sort-Object @{Expression={$_.BinACL -ne 'False' -and $_.BinACL -ne '[not found]'};Descending=$true}, Service)) {
            $tag = if ($w.BinACL -ne 'False' -and $w.BinACL -ne '[not found]' -and $w.RunAs -match 'LocalSystem|SYSTEM') { '*** PRIVESC' }
                   elseif ($w.BinACL -ne 'False' -and $w.BinACL -ne '[not found]') { 'WRITABLE' }
                   else { 'NON-STD' }
            $flatWS.Add([PSCustomObject]@{
                Tag      = $tag
                'Service / BinACL' = $w.Service
                'RunAs / DirACL'   = $w.RunAs
                'Path / State'     = $w.Path
            })
            $flatWS.Add([PSCustomObject]@{
                Tag      = ''
                'Service / BinACL' = $w.BinACL
                'RunAs / DirACL'   = $w.DirACL
                'Path / State'     = $w.State
            })
        }
        $tableText = ($flatWS | Format-Table -AutoSize | Out-String -Width 4096)
        Write-ColoredTable -Text $tableText -Colorizer {
            param($line)
            if ($line -match '^Tag\s+Service / BinACL')        { return 'Cyan' }
            if ($line -match '^-+\s+-+')                       { return 'DarkGray' }
            if ($line -match '^\*\*\* PRIVESC')                { return 'Red' }
            if ($line -match '^WRITABLE')                      { return 'Yellow' }
            if ($line -match '^NON-STD')                       { return 'Magenta' }
            if ($line -match '^\s') {
                if ($line -match $script:WritableAclRegex)     { return 'Red' }
                if ($line -match 'LocalSystem|SYSTEM')         { return 'Magenta' }
                return 'DarkGray'
            }
            return 'White'
        }
        Write-Status ("[+] {0} userland service(s) point outside standard folders" -f $weirdSvcRows.Count)
    }
}
Write-Blank

Write-CMD @'
Get-NetTCPConnection | Sort-Object State, LocalPort
Get-NetUDPEndpoint  | Sort-Object LocalPort
netstat -ano                # works in restricted shells; resolve PID via Get-Process -Id <pid>
netstat -anob               # admin only - resolves binary names
'@
Write-Header 'Active network connections'
Write-Rule   '--------------------------'

$netRows = [System.Collections.Generic.List[object]]::new()

$procCache = @{}
foreach ($p in (Get-Process -ErrorAction SilentlyContinue)) {
    $procCache[[int]$p.Id] = $p.ProcessName
}

# Probe Get-NetTCPConnection — the cmdlet can exist but still throw at runtime
# (e.g., CIM/WinRM broken, restricted token). Try once; on any failure, fall
# back to netstat -ano which uses direct WinAPI and works in limited contexts.
$tcpData = $null
$udpData = $null
if ($script:HasNetTcp) {
    try {
        $tcpData = @(Get-NetTCPConnection -ErrorAction Stop 2>$null)
    } catch {
        $tcpData = $null
    }
}
if ($null -ne $tcpData -and $script:HasNetUdp) {
    try {
        $udpData = @(Get-NetUDPEndpoint -ErrorAction Stop 2>$null)
    } catch {
        $udpData = @()
    }
}

if ($null -ne $tcpData) {
    foreach ($c in $tcpData) {
        $pidNum = [int]$c.OwningProcess
        $procName = if ($procCache.ContainsKey($pidNum)) { $procCache[$pidNum] } else { '?' }
        $netRows.Add([PSCustomObject]@{
            Proto   = 'TCP'
            Local   = ('{0}:{1}' -f $c.LocalAddress, $c.LocalPort)
            Remote  = ('{0}:{1}' -f $c.RemoteAddress, $c.RemotePort)
            State   = [string]$c.State
            PID     = $pidNum
            Process = $procName
        })
    }
    foreach ($u in $udpData) {
        $pidNum = [int]$u.OwningProcess
        $procName = if ($procCache.ContainsKey($pidNum)) { $procCache[$pidNum] } else { '?' }
        $netRows.Add([PSCustomObject]@{
            Proto   = 'UDP'
            Local   = ('{0}:{1}' -f $u.LocalAddress, $u.LocalPort)
            Remote  = '*:*'
            State   = 'Listen'
            PID     = $pidNum
            Process = $procName
        })
    }
} else {
    # Fallback: parse netstat -ano (no CIM dependency)
    foreach ($line in @(netstat -ano 2>$null)) {
        $t = $line.Trim()
        if ($t -match '^TCP\s+(\S+)\s+(\S+)\s+(\S+)\s+(\d+)$') {
            $pidNum = [int]$Matches[4]
            $procName = if ($procCache.ContainsKey($pidNum)) { $procCache[$pidNum] } else { '?' }
            $netRows.Add([PSCustomObject]@{
                Proto   = 'TCP'
                Local   = $Matches[1]
                Remote  = $Matches[2]
                State   = $Matches[3]
                PID     = $pidNum
                Process = $procName
            })
        } elseif ($t -match '^UDP\s+(\S+)\s+(\S+)\s+(\d+)$') {
            $pidNum = [int]$Matches[3]
            $procName = if ($procCache.ContainsKey($pidNum)) { $procCache[$pidNum] } else { '?' }
            $netRows.Add([PSCustomObject]@{
                Proto   = 'UDP'
                Local   = $Matches[1]
                Remote  = '*:*'
                State   = 'Listen'
                PID     = $pidNum
                Process = $procName
            })
        }
    }
}

$netOut = @($netRows | Sort-Object Proto, State, Local)
if ($netOut.Count -eq 0) {
    Write-Status '[-] No active network connections were found.'
} else {
    $tableText = ($netOut |
        Format-Table Proto, Local, Remote, State, PID, Process -AutoSize |
        Out-String -Width 4096)
    Write-ColoredTable -Text $tableText -Colorizer {
        param($line)
        if ($line -match '^Proto\s+Local')             { return 'Cyan' }
        if ($line -match '^-+\s+-+')                   { return 'DarkGray' }
        if ($line -match '\b(TIME_WAIT|CLOSE_WAIT)\b') { return 'DarkGray' }
        if ($line -match '\b(Established|ESTABLISHED)\b') { return 'Green' }
        if ($line -match '\b(Listen|LISTENING|Bound)\b') {
            # Loopback-only listens are low-value
            if ($line -match '(^|\s)(127\.0\.0\.1|\[::1\]):') { return 'DarkGray' }
            return 'Yellow'
        }
        return 'White'
    }
    $listenCount = @($netOut | Where-Object { $_.State -match '^(Listen|LISTENING)$' }).Count
    $estCount    = @($netOut | Where-Object { $_.State -match '^(Established|ESTABLISHED)$' }).Count
    Write-Status ("[+] {0} endpoint(s); {1} listening, {2} established" -f $netOut.Count, $listenCount, $estCount)
}
Write-Blank

Write-CMD @'
$tcp = Get-NetTCPConnection -State Listen
$tcp | Where-Object { $_.LocalAddress -in '127.0.0.1','::1' }     # local-only - prime targets
$tcp | Where-Object { $_.LocalAddress -in '0.0.0.0','::' }        # wildcard - also network
# Resolve owner with cmdline:
$pid = (Get-NetTCPConnection -LocalPort <PORT>).OwningProcess
Get-CimInstance Win32_Process -Filter "ProcessId=$pid" | Select Name, ExecutablePath, CommandLine
'@
Write-Header 'Localhost listeners (127.0.0.1 / ::1)'
Write-Rule   '-------------------------------------'
Write-Info   'Focus: ports only reachable from this box - prime privesc / pivot targets.'
Write-Info   'Two-row format: Row A = identity/path, Row B = command line / executable path.'
Write-Blank

# Build a process info cache once (Name + CommandLine + ExecutablePath)
$procDetailCache = @{}
foreach ($pp in (Get-CimInstance Win32_Process -ErrorAction SilentlyContinue)) {
    $procDetailCache[[int]$pp.ProcessId] = $pp
}

# Categorize all listeners
$allTcpListeners = @()
if ($null -ne $tcpData) {
    $allTcpListeners = $tcpData | Where-Object { $_.State -match '^(Listen|Bound)$' } | ForEach-Object {
        [PSCustomObject]@{
            LocalAddress  = [string]$_.LocalAddress
            LocalPort     = [int]$_.LocalPort
            Pid           = [int]$_.OwningProcess
        }
    }
} else {
    $allTcpListeners = $netRows | Where-Object { $_.Proto -eq 'TCP' -and $_.State -match 'LISTENING|Listen' } | ForEach-Object {
        $local = [string]$_.Local
        $portText = ($local -split ':')[-1]
        $address  = ($local -replace ":$portText$",'') -replace '^\[','' -replace '\]$',''
        try {
            [PSCustomObject]@{
                LocalAddress = $address
                LocalPort    = [int]$portText
                Pid          = [int]$_.PID
            }
        } catch {}
    }
}

$loBound      = @($allTcpListeners | Where-Object { $_.LocalAddress -in '127.0.0.1','::1' }    | Sort-Object LocalPort)
$wildBound    = @($allTcpListeners | Where-Object { $_.LocalAddress -in '0.0.0.0','::' }       | Sort-Object LocalPort)
$ifaceBound   = @($allTcpListeners | Where-Object { $_.LocalAddress -notin '127.0.0.1','::1','0.0.0.0','::' } | Sort-Object LocalPort)

Write-Status ("[+] Total TCP listeners : {0}" -f $allTcpListeners.Count)
Write-Status ("[+] Local-only          : {0}" -f $loBound.Count)
Write-Status ("[+] Wildcard            : {0}" -f $wildBound.Count)
Write-Status ("[+] Interface-bound     : {0}" -f $ifaceBound.Count)
Write-Blank

function Build-LocalhostFlatRows {
    param($Listeners, [string]$Tag)
    $flat = [System.Collections.Generic.List[object]]::new()
    foreach ($conn in $Listeners) {
        $p     = $procDetailCache[[int]$conn.Pid]
        $pname = if ($p) { $p.Name } else { '?' }
        $cmd   = if ($p -and $p.CommandLine) { [string]$p.CommandLine } else { '-' }
        $path  = if ($p -and $p.ExecutablePath) { [string]$p.ExecutablePath } else { '-' }
        if ($cmd.Length  -gt 110) { $cmd  = $cmd.Substring(0, 107) + '...' }
        if ($path.Length -gt 80)  { $path = $path.Substring(0, 77) + '...' }
        $endpoint = ('{0}:{1}' -f $conn.LocalAddress, $conn.LocalPort)
        # Row A: endpoint identity
        $flat.Add([PSCustomObject]@{
            Bind        = $Tag
            'Endpoint / Path'    = $endpoint
            'Process / Cmdline'  = $pname
            'PID / Detail'       = ('PID={0}' -f $conn.Pid)
        })
        # Row B: path + cmdline
        $flat.Add([PSCustomObject]@{
            Bind        = ''
            'Endpoint / Path'    = $path
            'Process / Cmdline'  = $cmd
            'PID / Detail'       = '-'
        })
    }
    return $flat
}

# LOCAL-ONLY (the gold)
Write-Header '127.0.0.1 / ::1 ONLY (privesc / pivot targets)'
Write-Rule   '----------------------------------------------'
if ($loBound.Count -eq 0) {
    Write-Status '[-] No local-only listeners found.'
} else {
    $flatLocal = Build-LocalhostFlatRows -Listeners $loBound -Tag 'LOCAL'
    $tableText = ($flatLocal | Format-Table -AutoSize | Out-String -Width 4096)
    Write-ColoredTable -Text $tableText -Colorizer {
        param($line)
        if ($line -match '^Bind\s+Endpoint')           { return 'Cyan' }
        if ($line -match '^-+\s+-+')                   { return 'DarkGray' }
        # Row A starts with LOCAL - highlight in red (high-value)
        if ($line -match '^LOCAL\b')                   { return 'Red' }
        # Row B (cmdline / path) - yellow so weird binaries pop out
        if ($line -match '^\s')                        { return 'Yellow' }
        return 'White'
    }
}
Write-Blank

# WILDCARD listeners
Write-Header '0.0.0.0 / :: WILDCARD (also reachable over network)'
Write-Rule   '----------------------------------------------------'
if ($wildBound.Count -eq 0) {
    Write-Status '[-] No wildcard listeners found.'
} else {
    $flatWild = Build-LocalhostFlatRows -Listeners $wildBound -Tag 'WILD'
    $tableText = ($flatWild | Format-Table -AutoSize | Out-String -Width 4096)
    Write-ColoredTable -Text $tableText -Colorizer {
        param($line)
        if ($line -match '^Bind\s+Endpoint')           { return 'Cyan' }
        if ($line -match '^-+\s+-+')                   { return 'DarkGray' }
        if ($line -match '^WILD\b')                    { return 'Green' }
        if ($line -match '^\s')                        { return 'White' }
        return 'White'
    }
}
Write-Blank

# Interface-bound listeners
Write-Header 'Interface-bound listeners'
Write-Rule   '-------------------------'
if ($ifaceBound.Count -eq 0) {
    Write-Status '[-] No interface-bound listeners found.'
} else {
    $flatIface = Build-LocalhostFlatRows -Listeners $ifaceBound -Tag 'IFACE'
    $tableText = ($flatIface | Format-Table -AutoSize | Out-String -Width 4096)
    Write-ColoredTable -Text $tableText -Colorizer {
        param($line)
        if ($line -match '^Bind\s+Endpoint')           { return 'Cyan' }
        if ($line -match '^-+\s+-+')                   { return 'DarkGray' }
        if ($line -match '^IFACE\b')                   { return 'White' }
        if ($line -match '^\s')                        { return 'DarkGray' }
        return 'White'
    }
}
Write-Blank

# UDP local endpoints (often missed)
Write-Header 'UDP local endpoints (127.0.0.1 / ::1)'
Write-Rule   '-------------------------------------'
$udpLocalRows = $netRows | Where-Object { $_.Proto -eq 'UDP' -and ($_.Local -match '^(127\.0\.0\.1|::1|\[::1\]):') }
if (@($udpLocalRows).Count -eq 0) {
    Write-Status '[-] No 127.0.0.1 UDP endpoints found.'
} else {
    $flatUdp = [System.Collections.Generic.List[object]]::new()
    foreach ($u in $udpLocalRows) {
        $p     = $procDetailCache[[int]$u.PID]
        $pname = if ($p) { $p.Name } else { $u.Process }
        $path  = if ($p -and $p.ExecutablePath) { [string]$p.ExecutablePath } else { '-' }
        $cmd   = if ($p -and $p.CommandLine)    { [string]$p.CommandLine }    else { '-' }
        if ($path.Length -gt 80)  { $path = $path.Substring(0, 77) + '...' }
        if ($cmd.Length  -gt 110) { $cmd  = $cmd.Substring(0, 107) + '...' }
        $flatUdp.Add([PSCustomObject]@{
            Bind                = 'UDP-LOCAL'
            'Endpoint / Path'   = [string]$u.Local
            'Process / Cmdline' = $pname
            'PID / Detail'      = ('PID={0}' -f $u.PID)
        })
        $flatUdp.Add([PSCustomObject]@{
            Bind                = ''
            'Endpoint / Path'   = $path
            'Process / Cmdline' = $cmd
            'PID / Detail'      = '-'
        })
    }
    $tableText = ($flatUdp | Format-Table -AutoSize | Out-String -Width 4096)
    Write-ColoredTable -Text $tableText -Colorizer {
        param($line)
        if ($line -match '^Bind\s+Endpoint')           { return 'Cyan' }
        if ($line -match '^-+\s+-+')                   { return 'DarkGray' }
        if ($line -match '^UDP-LOCAL\b')               { return 'Red' }
        if ($line -match '^\s')                        { return 'Yellow' }
        return 'White'
    }
}
Write-Blank

# Established outbound (something calling home?)
Write-Header 'Established outbound connections (excl loopback)'
Write-Rule   '------------------------------------------------'
$outboundRows = $netRows | Where-Object {
    $_.Proto -eq 'TCP' -and $_.State -match '^(Established|ESTABLISHED)$' -and
    $_.Remote -notmatch '^(127\.0\.0\.1|::1|\[::1\]|0\.0\.0\.0):'
}
if (@($outboundRows).Count -eq 0) {
    Write-Status '[-] No external established connections.'
} else {
    $flatOut = [System.Collections.Generic.List[object]]::new()
    foreach ($r in $outboundRows) {
        $p     = $procDetailCache[[int]$r.PID]
        $pname = if ($p) { $p.Name } else { $r.Process }
        $cmd   = if ($p -and $p.CommandLine) { [string]$p.CommandLine } else { '-' }
        if ($cmd.Length -gt 110) { $cmd = $cmd.Substring(0, 107) + '...' }
        $flatOut.Add([PSCustomObject]@{
            Bind              = 'OUT'
            Local             = [string]$r.Local
            Remote            = [string]$r.Remote
            Process           = $pname
            'PID / Cmdline'   = ('PID={0}' -f $r.PID)
        })
        $flatOut.Add([PSCustomObject]@{
            Bind              = ''
            Local             = '-'
            Remote            = '-'
            Process           = '-'
            'PID / Cmdline'   = $cmd
        })
    }
    $tableText = ($flatOut | Format-Table -AutoSize | Out-String -Width 4096)
    Write-ColoredTable -Text $tableText -Colorizer {
        param($line)
        if ($line -match '^Bind\s+Local')              { return 'Cyan' }
        if ($line -match '^-+\s+-+')                   { return 'DarkGray' }
        if ($line -match '^OUT\b')                     { return 'Green' }
        if ($line -match '^\s')                        { return 'DarkGray' }
        return 'White'
    }
}
Write-Blank

Write-Header 'Manual verification'
Write-Rule   '-------------------'
Write-Info   'Services:'
Write-Plain  '  sc.exe qc <serviceName>'
Write-Plain  '  sc.exe sdshow <serviceName>'
Write-Plain  '  reg query "HKLM\SYSTEM\CurrentControlSet\Services\<serviceName>" /v ImagePath'
Write-Plain  '  icacls "<full-binary-path>"'
Write-Plain  '  icacls "<parent-folder>"'
Write-Info   'Installed software:'
Write-Plain  '  dir "%ProgramFiles%"'
Write-Plain  '  dir "%ProgramFiles(x86)%"'
Write-Plain  '  reg query "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall" /s'
Write-Plain  '  reg query "HKLM\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall" /s'
Write-Plain  '  reg query "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall" /s'
Write-Info   'Unquoted paths:'
Write-Plain  '  icacls "<candidate-parent-dir>"'
Write-Info   'DLL hijack checks:'
Write-Plain  '  icacls "<binary-dir>"'
Write-Plain  '  $env:Path'
Write-Info   'Scheduled tasks:'
Write-Plain  '  schtasks /query /tn "<task-name>" /xml'
Write-Plain  '  schtasks /query /tn "<task-name>" /v /fo list'
Write-Info   'Network connections:'
Write-Plain  '  netstat -ano'
Write-Plain  '  netstat -anob    # requires admin; resolves binaries'
Write-Plain  '  Get-NetTCPConnection | Sort-Object LocalPort'
Write-Plain  '  Get-NetUDPEndpoint  | Sort-Object LocalPort'
Write-Info   'Identity context:'
Write-Plain  '  whoami'
Write-Plain  '  whoami /groups'
