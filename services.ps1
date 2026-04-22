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

Write-Output 'Combined local pentest triage'
Write-Output '-----------------------------'
Write-Output ("Current user: {0}" -f $currentUser)
Write-Output 'Sections included:'
Write-Output '- Services / software'
Write-Output '- Installed software'
Write-Output '- Unquoted service paths'
Write-Output '- DLL hijack candidates'
Write-Output '- Scheduled tasks'
Write-Output ''

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

Write-Output 'Services / software'
Write-Output '-------------------'
Write-Output 'Service filter: userland services/software only (driver rows are suppressed)'
Write-Output ''
if ($serviceOut.Count -eq 0) {
    Write-Output '[-] No interesting service/software rows were found.'
} else {
    $serviceOut |
    Format-Table Service, DisplayName, RunAs, Company, Product, Path, CanRestart, SvcRights, BinAccess, DirAccess, Findings -AutoSize |
    Out-String -Width 4096
}
Write-Output ("[+] {0} interesting service row(s)" -f $serviceOut.Count)
Write-Output ("[+] {0} actionable service row(s)" -f $serviceActionable.Count)
Write-Output ''

# Installed software
$installedSoftware = @(Get-InstalledSoftwareInventory -TokenPrincipals $tokenPrincipals -CurrentUserSid $currentUserSid)
Write-Output 'Installed software'
Write-Output '------------------'
Write-Output 'Software filter: uncommon/non-Microsoft software from uninstall data plus top-level Program Files folders'
Write-Output ''
if ($installedSoftware.Count -eq 0) {
    Write-Output '[-] No uncommon installed software rows were found.'
} else {
    $installedSoftware |
    Format-Table Name, Publisher, Version, InstallDir, DirAccess, Source -AutoSize |
    Out-String -Width 4096
    Write-Output ("[+] {0} uncommon installed software row(s)" -f $installedSoftware.Count)
}
Write-Output ''

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
Write-Output 'Unquoted service paths'
Write-Output '----------------------'
if ($unquotedRows.Count -eq 0) {
    Write-Output '[-] No unquoted service paths with spaces were found.'
} else {
    $unquotedRows |
    Format-Table Service, DisplayName, RawPath, ResolvedBinary, CandidateExecutables -AutoSize |
    Out-String -Width 4096
    Write-Output ("[+] {0} unquoted service path row(s)" -f $unquotedRows.Count)
}
Write-Output ''

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

    $dllServiceRows.Add([PSCustomObject]@{
        Service        = $svc.Name
        DisplayName    = if ($svc.DisplayName) { $svc.DisplayName } else { 'False' }
        RunAs          = if ($svc.StartName) { $svc.StartName } else { 'False' }
        Binary         = $bin
        BinaryDir      = if ($parentDir) { $parentDir } else { 'False' }
        DirAccess      = $dirAccess.Detail
        WhyInteresting = 'Writable binary directory; common DLL planting / hijack prerequisite'
    })
}

$pathRows = [System.Collections.Generic.List[object]]::new()
$machinePath = [Environment]::GetEnvironmentVariable('Path', 'Machine')
foreach ($dir in (@($machinePath -split ';' | Where-Object { $_ } | Select-Object -Unique))) {
    $expandedDir = [Environment]::ExpandEnvironmentVariables($dir)
    $dirAccess = Get-EffectivePathAccess -TargetPath $expandedDir -TokenPrincipals $tokenPrincipals -CurrentUserSid $currentUserSid
    if (-not $dirAccess.CanChange) { continue }
    $pathRows.Add([PSCustomObject]@{
        PathDir        = $expandedDir
        DirAccess      = $dirAccess.Detail
        WhyInteresting = 'Writable machine PATH directory'
    })
}

Write-Output 'DLL hijack candidates'
Write-Output '---------------------'
if ($dllServiceRows.Count -eq 0) {
    Write-Output '[-] No service-backed software with writable binary directories were found.'
} else {
    $dllServiceRows |
    Format-Table Service, DisplayName, RunAs, Binary, BinaryDir, DirAccess, WhyInteresting -AutoSize |
    Out-String -Width 4096
    Write-Output ("[+] {0} service row(s) with writable binary directories" -f $dllServiceRows.Count)
}
if ($pathRows.Count -eq 0) {
    Write-Output '[-] No writable machine PATH directories were found.'
} else {
    $pathRows |
    Format-Table PathDir, DirAccess, WhyInteresting -AutoSize |
    Out-String -Width 4096
    Write-Output ("[+] {0} writable machine PATH directorie(s)" -f $pathRows.Count)
}
Write-Output ''

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
Write-Output 'Scheduled tasks'
Write-Output '---------------'
if (-not $scheduledTaskSupported) {
    Write-Output '[!] Scheduled task enumeration is not available via Get-ScheduledTask on this host.'
} elseif ($taskOut.Count -eq 0) {
    Write-Output '[-] No writable/interesting scheduled-task actions were found.'
} else {
    $taskOut |
    Format-Table TaskPath, UserId, State, Execute, Arguments, ResolvedBinary, BinAccess, DirAccess, Findings -AutoSize |
    Out-String -Width 4096
    Write-Output ("[+] {0} interesting writable task action row(s)" -f $taskOut.Count)
}
Write-Output ''

Write-Output 'Manual verification'
Write-Output '-------------------'
Write-Output 'Services:'
Write-Output '  sc.exe qc <serviceName>'
Write-Output '  sc.exe sdshow <serviceName>'
Write-Output '  reg query "HKLM\SYSTEM\CurrentControlSet\Services\<serviceName>" /v ImagePath'
Write-Output '  icacls "<full-binary-path>"'
Write-Output '  icacls "<parent-folder>"'
Write-Output 'Installed software:'
Write-Output '  dir "%ProgramFiles%"'
Write-Output '  dir "%ProgramFiles(x86)%"'
Write-Output '  reg query "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall" /s'
Write-Output '  reg query "HKLM\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall" /s'
Write-Output '  reg query "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall" /s'
Write-Output 'Unquoted paths:'
Write-Output '  icacls "<candidate-parent-dir>"'
Write-Output 'DLL hijack checks:'
Write-Output '  icacls "<binary-dir>"'
Write-Output '  $env:Path'
Write-Output 'Scheduled tasks:'
Write-Output '  schtasks /query /tn "<task-name>" /xml'
Write-Output '  schtasks /query /tn "<task-name>" /v /fo list'
Write-Output 'Identity context:'
Write-Output '  whoami'
Write-Output '  whoami /groups'
