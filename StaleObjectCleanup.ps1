#Requires -Modules ActiveDirectory

<#
.SYNOPSIS
    Manages the lifecycle of stale computer and user objects in Active Directory.

.DESCRIPTION
    This script automates the disabling and deletion of stale computer and user
    objects in Active Directory. It operates in four phases:

    PHASE 1 -- COMPUTER TARGET OU SCAN
    Queries defined target OUs for inactive computer objects.
      - Inactive < DisableThresholdDays   : No action, not reported
      - Inactive >= DisableThresholdDays  : Account disabled, moved to
                                            DisabledComputersOU.
                                            extensionAttribute1 set to YYYY-MM-DD.
                                            Description appended (human-readable).
    Server OS devices and Domain Controllers are never acted on -- reported only.
    Inactivity baseline: lastLogonTimestamp. Falls back to whenCreated for
    accounts that have never logged in.

    PHASE 2 -- USER SCOPE GROUP SCAN
    Queries membership of UserScopeGroup (recursively) for stale enabled users.
      - Already disabled     : Skipped -- handled by Phase 4
      - Protected account    : Reported to manual review, no action taken
      - Inactive < threshold : No action, not reported
      - Inactive >= threshold: Account disabled, moved to DisabledUsersOU.
                               Same extensionAttribute1 / Description logic as Phase 1.
    Protected accounts (built-in objects, privileged adminCount=1, service accounts
    with SPNs, PasswordNeverExpires accounts) are never acted on. They are only
    reported if they would have crossed the disable threshold. 
	
    Inactivity baseline for users: most recent of lastLogonTimestamp and pwdLastSet.
    This reduces false positives on accounts that authenticate non-interactively
    (e.g. scheduled tasks, services that update pwdLastSet but not lastLogonTimestamp).
    Leave UserScopeGroup empty ("") to skip Phase 2 and Phase 4 entirely.

    PHASE 3 -- DISABLED COMPUTERS OU SCAN (deletion)
    Queries the Disabled Computers OU for objects ready for permanent deletion.
    Date logic uses extensionAttribute1 exclusively.
      - extensionAttribute1 date found, < DeleteThresholdMonths  : No action
      - extensionAttribute1 date found, >= DeleteThresholdMonths : Permanently deleted
      - extensionAttribute1 empty : Today's date written to extensionAttribute1.
        Human-readable note appended to Description. No deletion this run.
    Server OS devices and Domain Controllers are never deleted -- skipped.
    Objects are not re-checked for Enabled state or recent activity: any object
    in this OU whose date has passed is eligible for deletion.

    PHASE 4 -- DISABLED USERS OU SCAN (deletion)
    Same logic as Phase 3, applied to user objects in DisabledUsersOU.

    DISABLE GUARDRAIL
    Before Phases 1 and 2 execute any disables, a pre-scan counts all
    disable-eligible candidates across the target OUs and the user scope group
    (computers + users combined). If the count exceeds MaxDisablesPerRun while
    in live mode, the disable phases record every candidate in the report as
    "WOULD DISABLE (Guardrail)" but make NO changes to AD (no disable, no
    move, no extensionAttribute1 stamp, no Description note). This protects
    against mass-disable events caused by bad data (e.g. a domain controller
    with stale lastLogonTimestamp replication).

    DELETION GUARDRAIL
    Before Phases 3 and 4 execute any deletions, a pre-scan counts all eligible
    deletion candidates across both disabled OUs. If the combined count exceeds
    MaxDeletionsPerRun while in live mode, the deletion phases are skipped for
    that run, the anomaly is flagged in the report, and the email subject is
    tagged [GUARDRAIL]. Phases 1 and 2 (disabling and moving) are not affected.
    The run completes and the report is always sent regardless of guardrail state.

    TOTAL LIFECYCLE (with default thresholds, both object types):
      Month 0  - Account becomes inactive
      Month 6  - Account disabled, moved to Disabled OU,
                 extensionAttribute1 set to disable date
      Month 12 - Account permanently deleted

    EXTENSIONATTRIBUTE1 NOTE:
    extensionAttribute1 is used for date tracking on both computer and user objects.
    On user objects this attribute maps to Exchange CustomAttribute1. Verify it is
    not already populated in your environment before running in live mode.

    DESCRIPTION FIELD BEHAVIOR:
    The script always APPENDS to the existing Description field. It never overwrites.

    REPORT ONLY MODE:
    When ReportOnly is $true, no AD changes are made and the report email is
    still sent. The default is $false (live mode). Run with -ReportOnly:$true
    first, review the report, then run live.

    LOGGING & AUDIT TRAIL:
    Each run writes a console transcript and the report CSV to ReportArchivePath
    (default C:\Temp on the machine running the script). These files are the
    last-resort audit trail in case the report email fails to send. 
	Only the most recent run is retained; files from the previous run are removed at the start of each run. 
	If ReportArchivePath is unreachable, the run falls back to %TEMP% and the fallback is flagged in the report.

    CONFIGURATION:
    Default values for TargetOUs, DisabledComputersOU, DisabledUsersOU,
    UserScopeGroup, SmtpServer, EmailFrom and EmailTo are placeholders
    (<...>). Replace them in the param block or pass them as parameters.
    With placeholder values the script fails startup validation and exits
    before making any changes.

.PARAMETER ReportOnly
    When $true, no AD changes are made. Default: $false (live mode).

.PARAMETER TargetOUs
    Array of OU distinguished names to scan for stale computers in Phase 1.
    Must not overlap with or be a parent of DisabledComputersOU.

.PARAMETER DisabledComputersOU
    DN of the OU where disabled computers are moved and queried for deletion.
    Subtree search -- sub-OUs are included automatically.

.PARAMETER DisableThresholdDays
    Days of inactivity before a computer is disabled. Default: 180 (~6 months).

.PARAMETER DeleteThresholdMonths
    Months a disabled object must remain before permanent deletion. Default: 6.
    Applied to both computer and user objects.

.PARAMETER UserScopeGroup
    DN or name of the AD group whose members are scanned for stale users in Phase 2.
    Nested group membership is resolved automatically (-Recursive).
    Leave empty ("") to skip Phase 2 and Phase 4 entirely.

.PARAMETER DisabledUsersOU
    DN of the OU where disabled users are moved and queried for deletion.

.PARAMETER UserDisableThresholdDays
    Days of inactivity before a user account is disabled. Default: 180 (~6 months).

.PARAMETER MaxDisablesPerRun
    Disable safety limit. If the pre-scan finds more combined disable-eligible
    objects (computers + users) than this value while in live mode, the disable
    phases report all candidates but make no AD changes. Protects against
    mass-disable events caused by bad replication data. Default: 50.

.PARAMETER MaxDeletionsPerRun
    Deletion safety limit. If the pre-scan finds more combined deletion-eligible
    objects (computers + users) than this value while in live mode, deletion
    phases are skipped and the anomaly is flagged in the report. Default: 200.

.PARAMETER ReportArchivePath
    Directory where the run transcript and report CSV are written as a
    last-resort audit trail. Only the latest run is retained -- previous run
    files are deleted at the start of each run. Falls back to %TEMP% if
    unreachable. Default: C:\Temp.

.PARAMETER SmtpServer
    SMTP server address for the report email.

.PARAMETER EmailFrom
    From address for the report email.

.PARAMETER EmailTo
    Recipient address(es) for the report email.

.EXAMPLE
    # Test run -- no changes made
    .\Invoke-StaleObjectCleanup.ps1 -ReportOnly:$true

.EXAMPLE
    # Live mode -- changes applied (default)
    .\Invoke-StaleObjectCleanup.ps1

.EXAMPLE
    # Live mode with a user scope group specified
    .\Invoke-StaleObjectCleanup.ps1 `
        -UserScopeGroup "CN=<USER-SCOPE-GROUP>,OU=<GROUPS-OU>,DC=<DOMAIN>,DC=<TLD>" `
        -ReportOnly:$false

.EXAMPLE
    # Computers only (user phases skipped), report-only, with all settings passed in
    .\Invoke-StaleObjectCleanup.ps1 `
        -TargetOUs "OU=<WORKSTATIONS-OU>,DC=<DOMAIN>,DC=<TLD>" `
        -DisabledComputersOU "OU=<DISABLED-COMPUTERS-OU>,DC=<DOMAIN>,DC=<TLD>" `
        -UserScopeGroup "" `
        -SmtpServer "<SMTP-SERVER>" -EmailFrom "<SENDER@DOMAIN>" -EmailTo "<RECIPIENT@DOMAIN>" `
        -ReportOnly:$true
#>

[CmdletBinding(SupportsShouldProcess)]
param (
    # When $true, no AD changes are made (test mode). Default is $false (live)
    [bool]$ReportOnly = $false,

    #region Computer parameters
    # OUs to scan for stale computers in Phase 1. Sub-OUs included via Subtree.
    # Must not overlap with DisabledComputersOU.
    [string[]]$TargetOUs = @(
        "OU=<WORKSTATIONS-OU>,DC=<DOMAIN>,DC=<TLD>"
        # Add additional target OUs here, one per line
    ),

    [string]$DisabledComputersOU = "OU=<DISABLED-COMPUTERS-OU>,DC=<DOMAIN>,DC=<TLD>",
    [int]$DisableThresholdDays   = 180,
    [int]$DeleteThresholdMonths  = 6,
    #endregion

    #region User parameters
    # DN or name of the AD group whose members are checked for staleness in Phase 2.
    # Nested group members are included automatically (-Recursive).
    # Leave empty ("") to disable all user phases.
    #
    # IMPORTANT: extensionAttribute1 maps to Exchange CustomAttribute1 on user
    # objects. Confirm this attribute is not already in use before running live.
    [string]$UserScopeGroup = "CN=<USER-SCOPE-GROUP>,OU=<GROUPS-OU>,DC=<DOMAIN>,DC=<TLD>",

    [string]$DisabledUsersOU        = "OU=<DISABLED-USERS-OU>,DC=<DOMAIN>,DC=<TLD>",
    [int]$UserDisableThresholdDays  = 180,
    #endregion

    #region Guardrails
    # Combined (computer + user) DISABLE candidate limit per run.
    # If the disable pre-scan finds more eligible candidates than this value
    # while in live mode, Phases 1 and 2 report all candidates as
    # "WOULD DISABLE (Guardrail)" but make NO changes to AD. Protects against
    # mass-disable events caused by bad data (e.g. stale DC replication).
    [int]$MaxDisablesPerRun = 50,

    # Combined (computer + user) DELETION candidate limit per run.
    # If the deletion pre-scan finds more eligible deletions than this value
    # while in live mode, deletion phases are skipped and the anomaly is
    # flagged in the report. Disabling phases are never affected by this limit.
    [int]$MaxDeletionsPerRun = 200,
    #endregion

    #region Logging
    # Directory for the run transcript and report CSV (last-resort audit trail
    # in case the report email fails). Only the latest run is retained.
    # Falls back to %TEMP% if this path is unreachable.
    [string]$ReportArchivePath = "C:\Temp",
    #endregion

    #region SMTP
    [string]$SmtpServer  = "<SMTPSERVER>",
    [string]$EmailFrom   = "<SENDER@DOMAIN>",
    [string[]]$EmailTo   = @("<RECIPIENT@DOMAIN>")
    #endregion
)

#region -- INITIALIZATION --

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

$RunDate      = Get-Date
$RunDateStr   = $RunDate.ToString("yyyy-MM-dd")
$RunTimestamp = $RunDate.ToString("yyyy-MM-dd HH:mm:ss")

# -- ARCHIVE DIRECTORY RESOLUTION --
# The transcript and report CSV are written here and retained after the run
# as the last-resort audit trail if the report email fails. If the path is
# unreachable, fall back to %TEMP% -- the run continues and the fallback is
# flagged in the report.
$ArchiveFallback = $false
$ArchiveDir      = $ReportArchivePath
try {
    if (-not (Test-Path -LiteralPath $ArchiveDir)) {
        New-Item -Path $ArchiveDir -ItemType Directory -Force -ErrorAction Stop | Out-Null
    }
    # Verify the directory is writable before committing to it
    $ProbePath = Join-Path $ArchiveDir ".writeprobe_$PID"
    New-Item -Path $ProbePath -ItemType File -Force -ErrorAction Stop | Out-Null
    Remove-Item -LiteralPath $ProbePath -Force -ErrorAction SilentlyContinue
} catch {
    Write-Warning "Report archive path '$ReportArchivePath' is unreachable or not writable: $_"
    Write-Warning "Falling back to '$env:TEMP' for this run. This will be flagged in the report."
    $ArchiveFallback = $true
    $ArchiveDir      = $env:TEMP
}

# -- PREVIOUS RUN CLEANUP --
# Only the latest run's files are retained. The report is emailed every run;
# these on-disk copies exist purely as a fallback, so prior copies are removed.
foreach ($Pattern in @("StaleObjectCleanup_*.log", "StaleObjectReport_*.csv")) {
    try {
        Get-ChildItem -Path $ArchiveDir -Filter $Pattern -File -ErrorAction SilentlyContinue |
            Remove-Item -Force -ErrorAction Stop
    } catch {
        Write-Warning "Could not remove previous run file(s) matching '$Pattern' in '$ArchiveDir': $_"
    }
}

# -- TRANSCRIPT LOGGING --
# A failure to start logging warns but does not stop the run.
$LogPath = Join-Path $ArchiveDir "StaleObjectCleanup_$($RunDate.ToString('yyyy-MM-dd_HHmmss')).log"
try {
    Start-Transcript -Path $LogPath -ErrorAction Stop | Out-Null
} catch {
    Write-Warning "Could not start transcript logging to '$LogPath': $_"
}

# Whether user phases (2 and 4) are active for this run
$UserPhasesEnabled = -not [string]::IsNullOrWhiteSpace($UserScopeGroup)

# -- AD PROPERTY SETS --

# Properties retrieved for every computer object
$ADProperties = @(
    "Name", "DistinguishedName", "Description", "Enabled",
    "OperatingSystem", "lastLogonTimestamp", "whenCreated",
    "primaryGroupID", "extensionAttribute1"
)

# Properties retrieved for every user object.
# Includes fields required by Test-IsProtectedUser and the pwdLastSet-based
# activity baseline used to reduce false positives on service-style accounts.
$UserADProperties = @(
    "Name", "DistinguishedName", "Description", "Enabled",
    "lastLogonTimestamp", "whenCreated", "pwdLastSet",
    "extensionAttribute1", "isCriticalSystemObject",
    "adminCount", "ServicePrincipalName", "PasswordNeverExpires"
)

# -- REPORT BUCKETS --
$Report = @{
    Disabled            = [System.Collections.Generic.List[PSObject]]::new()
    Deleted             = [System.Collections.Generic.List[PSObject]]::new()
    ServersManualReview = [System.Collections.Generic.List[PSObject]]::new()
    UsersManualReview   = [System.Collections.Generic.List[PSObject]]::new()
    Errors              = [System.Collections.Generic.List[PSObject]]::new()
}

# -- GUARDRAIL STATE --
# Disable guardrail: set in the disable pre-scan if candidate count exceeds
# MaxDisablesPerRun in live mode. When tripped, Phases 1 and 2 record all
# candidates in the report but make NO changes to AD.
$DisableGuardrailTripped = $false
$DisableCandidateCount   = 0

# Deletion guardrail: set in the deletion pre-scan if candidate count exceeds
# MaxDeletionsPerRun in live mode. When tripped, Phases 3 and 4 record
# candidates in the report but do not delete.
$DeletionGuardrailTripped = $false
$DeletionCandidateCount   = 0

# Record the archive fallback in the report so it is visible in the email CSV
if ($ArchiveFallback) {
    $Report.Errors.Add([PSCustomObject]@{
        ObjectType          = "N/A"
        AccountName         = "AUDIT TRAIL"
        OUPath              = "N/A"
        OperatingSystem     = "N/A"
        LastLogonDate       = "N/A"
        DaysInactive        = "N/A"
        ActionTaken         = "WARNING -- Archive path fallback"
        ActionDate          = $RunDateStr
        Description         = "Report archive path '$ReportArchivePath' was unreachable. Transcript and CSV for this run were written to '$env:TEMP' instead."
        ExtensionAttribute1 = "N/A"
        ReportOnlyMode      = $ReportOnly
    })
}

Write-Host ""
Write-Host "======================================================"
Write-Host " Invoke-StaleObjectCleanup"
Write-Host " Run Date : $RunTimestamp"
Write-Host " Mode     : $(if ($ReportOnly) { 'REPORT ONLY -- no changes will be made to AD' } else { 'LIVE MODE -- changes will be applied to AD' })"
Write-Host " Users    : $(if ($UserPhasesEnabled) { "Enabled  --  Group: $UserScopeGroup" } else { 'Disabled -- UserScopeGroup not configured' })"
Write-Host " Logs     : $ArchiveDir$(if ($ArchiveFallback) { '  (FALLBACK -- configured archive path unreachable)' })"
Write-Host "======================================================"
Write-Host ""

#endregion

#region -- STARTUP VALIDATION --

Write-Host "--- Startup Validation ---"

$ValidationPassed = $true

# Computer OU overlap check -- TargetOU must not be a parent of DisabledComputersOU
foreach ($OUPath in $TargetOUs) {
    if ($DisabledComputersOU -like "*,$OUPath" -or $DisabledComputersOU -eq $OUPath) {
        Write-Warning "  VALIDATION ERROR: TargetOU '$OUPath' is a parent of or equal to DisabledComputersOU."
        Write-Warning "  Phase 1 would scan objects already in the Disabled Computers OU."
        Write-Warning "  Correct your TargetOUs configuration. Script will not run."
        $ValidationPassed = $false
    }
}

# User scope group existence check
if ($UserPhasesEnabled) {
    try {
        $null = Get-ADGroup -Identity $UserScopeGroup -ErrorAction Stop
        Write-Host "  User scope group resolved: $UserScopeGroup"
    } catch {
        Write-Warning "  VALIDATION ERROR: Cannot resolve UserScopeGroup '$UserScopeGroup': $_"
        Write-Warning "  Correct the UserScopeGroup parameter and re-run. Script will not run."
        $ValidationPassed = $false
    }
}

if (-not $ValidationPassed) { exit 1 }

Write-Host "  Validation passed."
Write-Host ""

#endregion

#region -- HELPER FUNCTIONS --

function Get-LastLogonInfo {
    <#
    .SYNOPSIS
        Returns inactivity information for an AD account (user or computer).

        For computers: baseline is lastLogonTimestamp.
        For users: baseline is the most recent of lastLogonTimestamp and
        pwdLastSet (use -IncludePwdLastSet). This reduces false positives
        on accounts that update their password but don't produce logon events.

        Falls back to whenCreated for accounts with no logon or password history.
    #>
    param (
        [Microsoft.ActiveDirectory.Management.ADAccount]$Account,
        [switch]$IncludePwdLastSet
    )

    $Candidates = [System.Collections.Generic.List[datetime]]::new()

    if ($Account.lastLogonTimestamp -and $Account.lastLogonTimestamp -ne 0) {
        $Candidates.Add([datetime]::FromFileTime($Account.lastLogonTimestamp))
    }

    if ($IncludePwdLastSet -and
        $Account.PSObject.Properties['pwdLastSet'] -and
        $Account.pwdLastSet -and
        $Account.pwdLastSet -ne 0) {
        $Candidates.Add([datetime]::FromFileTime($Account.pwdLastSet))
    }

    if ($Candidates.Count -gt 0) {
        $Baseline     = ($Candidates | Sort-Object -Descending | Select-Object -First 1)
        $LastLogonStr = $Baseline.ToString("yyyy-MM-dd")
    } else {
        $Baseline     = $Account.whenCreated
        $LastLogonStr = "Never (Created: $($Account.whenCreated.ToString('yyyy-MM-dd')))"
    }

    return @{
        Baseline     = $Baseline
        DaysInactive = ($RunDate - $Baseline).Days
        LastLogonStr = $LastLogonStr
    }
}

function Get-ExtensionAttributeDate {
    <#
    .SYNOPSIS
        Reads extensionAttribute1 and returns the stored date as a [datetime].
        Returns $null if the attribute is empty or the value cannot be parsed.
        Works on both user and computer objects. This is the sole source of
        truth for all deletion lifecycle date logic.
    #>
    param (
        [Microsoft.ActiveDirectory.Management.ADAccount]$Account
    )

    $Value = $Account.extensionAttribute1

    if ([string]::IsNullOrWhiteSpace($Value)) { return $null }

    try {
        return [datetime]::ParseExact($Value.Trim(), "yyyy-MM-dd", $null)
    } catch {
        return $null
    }
}

function Set-ExtensionAttributeDate {
    <#
    .SYNOPSIS
        Writes a YYYY-MM-DD string to extensionAttribute1.
        Uses Set-ADObject so it works on both user and computer objects.
        Respects ReportOnly mode -- no AD write is performed if ReportOnly is true.
    #>
    param (
        [Microsoft.ActiveDirectory.Management.ADAccount]$Account,
        [string]$DateString,
        [bool]$ReportOnly
    )

    if (-not $ReportOnly) {
        Set-ADObject -Identity $Account.DistinguishedName `
                     -Replace @{ extensionAttribute1 = $DateString }
    }
}

function Add-DescriptionText {
    <#
    .SYNOPSIS
        Appends a human-readable note to the AD Description field.
        Never overwrites -- existing content is always preserved.
        Uses Set-ADObject so it works on both user and computer objects.
        Respects ReportOnly mode -- no AD write is performed if ReportOnly is true.
        NOTE: Description is purely informational. It is never parsed for logic.
    #>
    param (
        [Microsoft.ActiveDirectory.Management.ADAccount]$Account,
        [string]$TextToAppend,
        [bool]$ReportOnly
    )

    $Existing = if ([string]::IsNullOrWhiteSpace($Account.Description)) {
        ""
    } else {
        $Account.Description.TrimEnd()
    }

    $NewValue = if ($Existing -eq "") { $TextToAppend } else { "$Existing | $TextToAppend" }

    if (-not $ReportOnly) {
        Set-ADObject -Identity $Account.DistinguishedName `
                     -Replace @{ description = $NewValue }
    }

    return $NewValue
}

function Build-ReportRow {
    <#
    .SYNOPSIS
        Builds a standardized PSObject row for the CSV report.
        Accepts both user and computer objects via the ADAccount base type.
    #>
    param (
        [Microsoft.ActiveDirectory.Management.ADAccount]$Account,
        [string]$ObjectType,
        [string]$LastLogonDate,
        [string]$DaysInactive,
        [string]$Action,
        [string]$Description,
        [string]$ExtensionAttribute1
    )

    [PSCustomObject]@{
        ObjectType          = $ObjectType
        AccountName         = $Account.Name
        OUPath              = ($Account.DistinguishedName -replace '^CN=[^,]+,', '')
        OperatingSystem     = if ($Account.PSObject.Properties['OperatingSystem'] -and
                                  $Account.OperatingSystem) { $Account.OperatingSystem } `
                              elseif ($ObjectType -eq 'User') { 'N/A' } `
                              else { 'Unknown' }
        LastLogonDate       = $LastLogonDate
        DaysInactive        = $DaysInactive
        ActionTaken         = $Action
        ActionDate          = $RunDateStr
        Description         = $Description
        ExtensionAttribute1 = $ExtensionAttribute1
        ReportOnlyMode      = $ReportOnly
    }
}

function Build-ErrorRow {
    <#
    .SYNOPSIS
        Builds a standardized error row for the CSV report.
        A failed operation is logged and skipped -- it does not abort the run.
    #>
    param (
        [string]$ObjectType,
        [string]$AccountName,
        [string]$AttemptedAction,
        [string]$ErrorMessage
    )

    [PSCustomObject]@{
        ObjectType          = $ObjectType
        AccountName         = $AccountName
        OUPath              = "N/A"
        OperatingSystem     = "N/A"
        LastLogonDate       = "N/A"
        DaysInactive        = "N/A"
        ActionTaken         = "ERROR -- $AttemptedAction"
        ActionDate          = $RunDateStr
        Description         = $ErrorMessage
        ExtensionAttribute1 = "N/A"
        ReportOnlyMode      = $ReportOnly
    }
}

function Test-IsServerOrDC {
    <#
    .SYNOPSIS
        Returns $true if the computer object is a Server OS or Domain Controller.
        primaryGroupID 516 = Domain Controllers, 521 = Read-Only Domain Controllers.
    #>
    param (
        [Microsoft.ActiveDirectory.Management.ADComputer]$Computer
    )

    return ($Computer.OperatingSystem -like "*Server*" -or
            $Computer.primaryGroupID -eq 516 -or
            $Computer.primaryGroupID -eq 521)
}

function Test-IsProtectedUser {
    <#
    .SYNOPSIS
        Returns $true if the user account should never be acted on automatically.
        Protected accounts are reported to the manual review bucket only.
    .DESCRIPTION
        Excludes:
          - Built-in / critical system objects   (isCriticalSystemObject = $true)
          - Privileged / protected accounts      (adminCount = 1, set by AdminSDHolder)
          - Service accounts with SPNs           (ServicePrincipalName populated)
          - Likely service accounts              (PasswordNeverExpires = $true)
    #>
    param (
        [Microsoft.ActiveDirectory.Management.ADUser]$User
    )

    if ($User.isCriticalSystemObject) { return $true }
    if ($User.adminCount -eq 1)       { return $true }
    if ($User.ServicePrincipalName)   { return $true }
    if ($User.PasswordNeverExpires)   { return $true }

    return $false
}

#endregion

#region -- DISABLE PRE-SCAN & GUARDRAIL --

# Query all target OUs and resolve the user scope group ONCE, storing the
# results for use in Phases 1 and 2. The pre-scan counts disable-eligible
# candidates (computers + users combined) to evaluate the disable guardrail
# BEFORE any account is disabled, moved, or written to.
#
# Eligibility mirrors the phase logic exactly:
#   Computers : not Server/DC, inactive >= DisableThresholdDays
#   Users     : enabled, not protected, inactive >= UserDisableThresholdDays
#               (baseline includes pwdLastSet)
# Servers/DCs and protected users are still routed to manual-review reporting
# by the phases regardless of guardrail state -- reporting makes no AD changes.

Write-Host "--- Disable Pre-Scan and Guardrail ---"

$TargetComputerObjects = [System.Collections.Generic.List[PSObject]]::new()
foreach ($OUPath in $TargetOUs) {
    Write-Host "  Scanning: $OUPath"
    try {
        $Found = @(Get-ADComputer -SearchBase $OUPath -SearchScope Subtree `
                      -Filter * -Properties $ADProperties)
        foreach ($C in $Found) { $TargetComputerObjects.Add($C) }
        Write-Host "    $($Found.Count) computer object(s) found"
    } catch {
        Write-Warning "  Could not query OU '$OUPath': $_"
    }
}

$ScopeUserObjects = [System.Collections.Generic.List[PSObject]]::new()
if ($UserPhasesEnabled) {
    Write-Host "  Resolving group: $UserScopeGroup (recursive)"
    $GroupMembers = @()
    try {
        $GroupMembers = @(Get-ADGroupMember -Identity $UserScopeGroup -Recursive -ErrorAction Stop |
                          Where-Object { $_.objectClass -eq 'user' })
        Write-Host "    $($GroupMembers.Count) user member(s) resolved"
    } catch {
        Write-Warning "  Could not retrieve members of '$UserScopeGroup': $_"
    }

    foreach ($Member in $GroupMembers) {
        try {
            $ScopeUserObjects.Add((Get-ADUser -Identity $Member.DistinguishedName `
                                              -Properties $UserADProperties `
                                              -ErrorAction Stop))
        } catch {
            Write-Warning "    [ERROR] Could not retrieve user '$($Member.SamAccountName)': $_"
            $Report.Errors.Add((Build-ErrorRow `
                -ObjectType      "User" `
                -AccountName     $Member.SamAccountName `
                -AttemptedAction "Get-ADUser (property retrieval)" `
                -ErrorMessage    $_.ToString()))
        }
    }
}

# Count disable-eligible candidates
foreach ($Obj in $TargetComputerObjects) {
    if (Test-IsServerOrDC -Computer $Obj) { continue }
    $Logon = Get-LastLogonInfo -Account $Obj
    if ($Logon.DaysInactive -ge $DisableThresholdDays) { $DisableCandidateCount++ }
}

foreach ($Obj in $ScopeUserObjects) {
    if (-not $Obj.Enabled) { continue }
    if (Test-IsProtectedUser -User $Obj) { continue }
    $Logon = Get-LastLogonInfo -Account $Obj -IncludePwdLastSet
    if ($Logon.DaysInactive -ge $UserDisableThresholdDays) { $DisableCandidateCount++ }
}

Write-Host "  Disable candidates    : $DisableCandidateCount  (limit: $MaxDisablesPerRun)"

if ($DisableCandidateCount -gt $MaxDisablesPerRun -and -not $ReportOnly) {
    Write-Warning "  GUARDRAIL TRIPPED: $DisableCandidateCount disable candidates exceed MaxDisablesPerRun ($MaxDisablesPerRun)."
    Write-Warning "  Phases 1 and 2 will REPORT all candidates but make NO changes to AD this run."
    Write-Warning "  A spike this large may indicate bad data (e.g. stale DC replication). Review before re-running."
    $DisableGuardrailTripped = $true
    $Report.Errors.Add((Build-ErrorRow `
        -ObjectType      "N/A" `
        -AccountName     "DISABLE GUARDRAIL" `
        -AttemptedAction "Disable actions skipped" `
        -ErrorMessage    "Combined disable candidates ($DisableCandidateCount) exceeded MaxDisablesPerRun ($MaxDisablesPerRun). No accounts were disabled, moved, or written to this run."))
} else {
    Write-Host "  Guardrail OK -- proceeding with disable phases."
}
Write-Host ""

#endregion

#region -- PHASE 1: COMPUTER TARGET OU SCAN --

Write-Host "--- Phase 1: Processing Computer Target OUs ---"

foreach ($Computer in $TargetComputerObjects) {

    # -- SERVER / DC CHECK --
    # Never act on servers or DCs. Only report them if they would have
    # crossed the disable threshold -- active servers are skipped silently.
    if (Test-IsServerOrDC -Computer $Computer) {
        $Logon = Get-LastLogonInfo -Account $Computer
        if ($Logon.DaysInactive -ge $DisableThresholdDays) {
            $Report.ServersManualReview.Add((Build-ReportRow `
                -Account             $Computer `
                -ObjectType          "Computer" `
                -LastLogonDate       $Logon.LastLogonStr `
                -DaysInactive        $Logon.DaysInactive `
                -Action              "$(if ($Computer.primaryGroupID -eq 516 -or $Computer.primaryGroupID -eq 521) { 'Domain Controller' } else { 'Server OS' }) -- No Action (Manual Review Required)" `
                -Description         $Computer.Description `
                -ExtensionAttribute1 $Computer.extensionAttribute1))
            Write-Host "    [PROTECTED] $($Computer.Name) -- Server/DC, inactive $($Logon.DaysInactive) days, manual review required"
        }
        continue
    }

    # -- INACTIVITY CHECK --
    $Logon = Get-LastLogonInfo -Account $Computer

    if ($Logon.DaysInactive -lt $DisableThresholdDays) { continue }

    # -- DISABLE GUARDRAIL CHECK --
    # When tripped, record the candidate and make NO changes to AD:
    # no extensionAttribute1 stamp, no Description note, no disable, no move.
    if ($DisableGuardrailTripped) {
        $Report.Disabled.Add((Build-ReportRow `
            -Account             $Computer `
            -ObjectType          "Computer" `
            -LastLogonDate       $Logon.LastLogonStr `
            -DaysInactive        $Logon.DaysInactive `
            -Action              "WOULD DISABLE (Guardrail -- disable skipped this run) -- Inactive $($Logon.DaysInactive) days" `
            -Description         $Computer.Description `
            -ExtensionAttribute1 $Computer.extensionAttribute1))
        Write-Host "    [GUARDRAIL] $($Computer.Name) -- Inactive $($Logon.DaysInactive) days -- WOULD DISABLE (skipped)"
        continue
    }

    # -- DISABLE AND MOVE --
    # Device has been inactive >= DisableThresholdDays.
    # 1. Write disable date to extensionAttribute1 (used for all future logic)
    # 2. Append human-readable note to Description (informational only)
    # 3. Disable the AD account
    # 4. Move object to Disabled Computers OU
    # Each operation has its own error handler -- a failure logs and skips,
    # it does not abort the run.

    # Step 1: Write date to extensionAttribute1
    try {
        Set-ExtensionAttributeDate -Account $Computer -DateString $RunDateStr -ReportOnly $ReportOnly
    } catch {
        Write-Warning "    [ERROR] Failed to set extensionAttribute1 for $($Computer.Name): $_"
        $Report.Errors.Add((Build-ErrorRow `
            -ObjectType      "Computer" `
            -AccountName     $Computer.Name `
            -AttemptedAction "Set extensionAttribute1 (disable date)" `
            -ErrorMessage    $_.ToString()))
        continue
    }

    # Step 2: Append note to Description
    $NewDesc = $Computer.Description
    try {
        $NewDesc = Add-DescriptionText `
            -Account      $Computer `
            -TextToAppend "Disabled by automation on $RunDateStr" `
            -ReportOnly   $ReportOnly
    } catch {
        Write-Warning "    [ERROR] Failed to write Description for $($Computer.Name): $_"
        $Report.Errors.Add((Build-ErrorRow `
            -ObjectType      "Computer" `
            -AccountName     $Computer.Name `
            -AttemptedAction "Append disable note to Description" `
            -ErrorMessage    $_.ToString()))
        continue
    }

    # Steps 3 and 4: Disable and move -- live mode only
    if (-not $ReportOnly) {

        try {
            Disable-ADAccount -Identity $Computer.DistinguishedName
        } catch {
            Write-Warning "    [ERROR] Failed to disable $($Computer.Name): $_"
            $Report.Errors.Add((Build-ErrorRow `
                -ObjectType      "Computer" `
                -AccountName     $Computer.Name `
                -AttemptedAction "Disable-ADAccount" `
                -ErrorMessage    $_.ToString()))
            continue
        }

        try {
            Move-ADObject -Identity $Computer.DistinguishedName -TargetPath $DisabledComputersOU
        } catch {
            Write-Warning "    [ERROR] Failed to move $($Computer.Name) to Disabled Computers OU: $_"
            $Report.Errors.Add((Build-ErrorRow `
                -ObjectType      "Computer" `
                -AccountName     $Computer.Name `
                -AttemptedAction "Move-ADObject to Disabled Computers OU" `
                -ErrorMessage    $_.ToString()))
            continue
        }

    }

    $Report.Disabled.Add((Build-ReportRow `
        -Account             $Computer `
        -ObjectType          "Computer" `
        -LastLogonDate       $Logon.LastLogonStr `
        -DaysInactive        $Logon.DaysInactive `
        -Action              "$(if ($ReportOnly) { 'WOULD DISABLE' } else { 'Disabled' }) -- Inactive $($Logon.DaysInactive) days -- Moved to Disabled Computers OU" `
        -Description         $NewDesc `
        -ExtensionAttribute1 $RunDateStr))

    Write-Host "    [DISABLED] $($Computer.Name) -- Inactive $($Logon.DaysInactive) days -- $(if ($ReportOnly) { 'WOULD DISABLE (ReportOnly ON)' } else { 'DISABLED' })"
}

#endregion

#region -- PHASE 2: USER SCOPE GROUP SCAN --

if ($UserPhasesEnabled) {

    Write-Host ""
    Write-Host "--- Phase 2: Processing User Scope Group ---"
    Write-Host "  Group: $UserScopeGroup ($($ScopeUserObjects.Count) member(s) resolved in pre-scan)"

    foreach ($User in $ScopeUserObjects) {

        # -- SKIP ALREADY-DISABLED ACCOUNTS --
        # Disabled users in this group were previously processed by Phase 2 and
        # moved to DisabledUsersOU. They are handled by Phase 4 (deletion tracking).
        if (-not $User.Enabled) {
            Write-Host "    [SKIP]     $($User.Name) -- already disabled, handled by Phase 4"
            continue
        }

        # -- PROTECTED USER CHECK --
        # Only report protected accounts that would have crossed the disable
        # threshold -- active protected accounts are skipped silently.
        if (Test-IsProtectedUser -User $User) {
            $Logon = Get-LastLogonInfo -Account $User -IncludePwdLastSet
            if ($Logon.DaysInactive -ge $UserDisableThresholdDays) {
                $ProtectWhy = if ($User.isCriticalSystemObject) { 'Critical system object' } `
                         elseif ($User.adminCount -eq 1)        { 'Privileged account (adminCount=1)' } `
                         elseif ($User.ServicePrincipalName)    { 'Service account (SPN present)' } `
                         else                                   { 'PasswordNeverExpires set' }

                $Report.UsersManualReview.Add((Build-ReportRow `
                    -Account             $User `
                    -ObjectType          "User" `
                    -LastLogonDate       $Logon.LastLogonStr `
                    -DaysInactive        $Logon.DaysInactive `
                    -Action              "Protected -- No Action ($ProtectWhy)" `
                    -Description         $User.Description `
                    -ExtensionAttribute1 $User.extensionAttribute1))
                Write-Host "    [PROTECTED] $($User.Name) -- $ProtectWhy, inactive $($Logon.DaysInactive) days, manual review required"
            }
            continue
        }

        # -- INACTIVITY CHECK --
        # Baseline is the most recent of lastLogonTimestamp and pwdLastSet.
        $Logon = Get-LastLogonInfo -Account $User -IncludePwdLastSet

        if ($Logon.DaysInactive -lt $UserDisableThresholdDays) { continue }

        # -- DISABLE GUARDRAIL CHECK --
        # When tripped, record the candidate and make NO changes to AD.
        if ($DisableGuardrailTripped) {
            $Report.Disabled.Add((Build-ReportRow `
                -Account             $User `
                -ObjectType          "User" `
                -LastLogonDate       $Logon.LastLogonStr `
                -DaysInactive        $Logon.DaysInactive `
                -Action              "WOULD DISABLE (Guardrail -- disable skipped this run) -- Inactive $($Logon.DaysInactive) days" `
                -Description         $User.Description `
                -ExtensionAttribute1 $User.extensionAttribute1))
            Write-Host "    [GUARDRAIL] $($User.Name) -- Inactive $($Logon.DaysInactive) days -- WOULD DISABLE (skipped)"
            continue
        }

        # -- DISABLE AND MOVE --
        # Same four-step process as Phase 1.

        # Step 1: Write date to extensionAttribute1
        try {
            Set-ExtensionAttributeDate -Account $User -DateString $RunDateStr -ReportOnly $ReportOnly
        } catch {
            Write-Warning "    [ERROR] Failed to set extensionAttribute1 for $($User.Name): $_"
            $Report.Errors.Add((Build-ErrorRow `
                -ObjectType      "User" `
                -AccountName     $User.Name `
                -AttemptedAction "Set extensionAttribute1 (disable date)" `
                -ErrorMessage    $_.ToString()))
            continue
        }

        # Step 2: Append note to Description
        $NewDesc = $User.Description
        try {
            $NewDesc = Add-DescriptionText `
                -Account      $User `
                -TextToAppend "Disabled by automation on $RunDateStr" `
                -ReportOnly   $ReportOnly
        } catch {
            Write-Warning "    [ERROR] Failed to write Description for $($User.Name): $_"
            $Report.Errors.Add((Build-ErrorRow `
                -ObjectType      "User" `
                -AccountName     $User.Name `
                -AttemptedAction "Append disable note to Description" `
                -ErrorMessage    $_.ToString()))
            continue
        }

        # Steps 3 and 4: Disable and move -- live mode only
        if (-not $ReportOnly) {

            try {
                Disable-ADAccount -Identity $User.DistinguishedName
            } catch {
                Write-Warning "    [ERROR] Failed to disable $($User.Name): $_"
                $Report.Errors.Add((Build-ErrorRow `
                    -ObjectType      "User" `
                    -AccountName     $User.Name `
                    -AttemptedAction "Disable-ADAccount" `
                    -ErrorMessage    $_.ToString()))
                continue
            }

            try {
                Move-ADObject -Identity $User.DistinguishedName -TargetPath $DisabledUsersOU
            } catch {
                Write-Warning "    [ERROR] Failed to move $($User.Name) to Disabled Users OU: $_"
                $Report.Errors.Add((Build-ErrorRow `
                    -ObjectType      "User" `
                    -AccountName     $User.Name `
                    -AttemptedAction "Move-ADObject to Disabled Users OU" `
                    -ErrorMessage    $_.ToString()))
                continue
            }

        }

        $Report.Disabled.Add((Build-ReportRow `
            -Account             $User `
            -ObjectType          "User" `
            -LastLogonDate       $Logon.LastLogonStr `
            -DaysInactive        $Logon.DaysInactive `
            -Action              "$(if ($ReportOnly) { 'WOULD DISABLE' } else { 'Disabled' }) -- Inactive $($Logon.DaysInactive) days -- Moved to Disabled Users OU" `
            -Description         $NewDesc `
            -ExtensionAttribute1 $RunDateStr))

        Write-Host "    [DISABLED] $($User.Name) -- Inactive $($Logon.DaysInactive) days -- $(if ($ReportOnly) { 'WOULD DISABLE (ReportOnly ON)' } else { 'DISABLED' })"
    }

} else {
    Write-Host ""
    Write-Host "--- Phase 2: Skipped (UserScopeGroup not configured) ---"
}

#endregion

#region -- DELETION PRE-SCAN & GUARDRAIL --

# Query both disabled OUs once and store results for use in Phases 3 and 4.
# Querying here avoids a second round-trip to AD purely for the guardrail check.
# The pre-scan also counts deletion-eligible candidates to evaluate the guardrail
# before any Remove-ADObject call is made.

Write-Host ""
Write-Host "--- Deletion Pre-Scan and Guardrail ---"

$DisabledComputerObjects = @()
try {
    $DisabledComputerObjects = @(Get-ADComputer -SearchBase $DisabledComputersOU `
                                    -SearchScope Subtree -Filter * -Properties $ADProperties)
    Write-Host "  Disabled Computers OU : $($DisabledComputerObjects.Count) object(s)"
} catch {
    Write-Warning "  Could not query Disabled Computers OU: $_"
}

$DisabledUserObjects = @()
if ($UserPhasesEnabled) {
    try {
        $DisabledUserObjects = @(Get-ADUser -SearchBase $DisabledUsersOU `
                                    -SearchScope Subtree -Filter * -Properties $UserADProperties)
        Write-Host "  Disabled Users OU     : $($DisabledUserObjects.Count) object(s)"
    } catch {
        Write-Warning "  Could not query Disabled Users OU: $_"
    }
}

# Count deletion-eligible objects across both OUs
foreach ($Obj in $DisabledComputerObjects) {
    if (Test-IsServerOrDC -Computer $Obj) { continue }
    $d = Get-ExtensionAttributeDate -Account $Obj
    if ($null -ne $d -and $RunDate -ge $d.AddMonths($DeleteThresholdMonths)) {
        $DeletionCandidateCount++
    }
}

foreach ($Obj in $DisabledUserObjects) {
    if (Test-IsProtectedUser -User $Obj) { continue }
    $d = Get-ExtensionAttributeDate -Account $Obj
    if ($null -ne $d -and $RunDate -ge $d.AddMonths($DeleteThresholdMonths)) {
        $DeletionCandidateCount++
    }
}

Write-Host "  Deletion candidates   : $DeletionCandidateCount  (limit: $MaxDeletionsPerRun)"

if ($DeletionCandidateCount -gt $MaxDeletionsPerRun -and -not $ReportOnly) {
    Write-Warning "  GUARDRAIL TRIPPED: $DeletionCandidateCount candidates exceed MaxDeletionsPerRun ($MaxDeletionsPerRun)."
    Write-Warning "  Phases 3 and 4 (deletion) are skipped this run. Phases 1 and 2 (disabling) were not affected."
    Write-Warning "  Review the report, confirm the scope is expected, then re-run."
    $DeletionGuardrailTripped = $true
    $Report.Errors.Add((Build-ErrorRow `
        -ObjectType      "N/A" `
        -AccountName     "DELETION GUARDRAIL" `
        -AttemptedAction "Deletion phases skipped" `
        -ErrorMessage    "Combined deletion candidates ($DeletionCandidateCount) exceeded MaxDeletionsPerRun ($MaxDeletionsPerRun). No objects were deleted this run."))
} else {
    Write-Host "  Guardrail OK -- proceeding with deletion phases."
}

#endregion

#region -- PHASE 3: DISABLED COMPUTERS OU SCAN (deletion) --

Write-Host ""
Write-Host "--- Phase 3: Scanning Disabled Computers OU ---"
Write-Host "  Source: $DisabledComputersOU (including all sub-OUs)"

foreach ($Computer in $DisabledComputerObjects) {

    # -- SERVER / DC CHECK --
    # Servers and DCs in the Disabled OU are skipped silently.
    # They are already reported when found stale in Phase 1.
    if (Test-IsServerOrDC -Computer $Computer) {
        Write-Host "    [SKIP]     $($Computer.Name) -- Server/DC in Disabled OU, skipping silently"
        continue
    }

    # -- DATE CHECK via extensionAttribute1 --
    # extensionAttribute1 is the sole source of truth for the disable date.
    # Description is never read or parsed for logic decisions.
    $ReferenceDate = Get-ExtensionAttributeDate -Account $Computer

    if ($null -eq $ReferenceDate) {
        # -- NO DATE FOUND --
        # Object was placed in the Disabled OU outside of this script with no
        # extensionAttribute1 value. Write today's date to start the deletion
        # clock. No deletion takes place this run.

        try {
            Set-ExtensionAttributeDate -Account $Computer -DateString $RunDateStr -ReportOnly $ReportOnly
        } catch {
            Write-Warning "    [ERROR] Failed to set extensionAttribute1 for $($Computer.Name): $_"
            $Report.Errors.Add((Build-ErrorRow `
                -ObjectType      "Computer" `
                -AccountName     $Computer.Name `
                -AttemptedAction "Set extensionAttribute1 (tracking date)" `
                -ErrorMessage    $_.ToString()))
            continue
        }

        try {
            $null = Add-DescriptionText `
                -Account      $Computer `
                -TextToAppend "Not disabled by automation -- date added for tracking purposes: $RunDateStr" `
                -ReportOnly   $ReportOnly
        } catch {
            Write-Warning "    [ERROR] Failed to write tracking note to Description for $($Computer.Name): $_"
            $Report.Errors.Add((Build-ErrorRow `
                -ObjectType      "Computer" `
                -AccountName     $Computer.Name `
                -AttemptedAction "Append tracking note to Description" `
                -ErrorMessage    $_.ToString()))
        }

        Write-Host "    [TRACKED]  $($Computer.Name) -- No date in extensionAttribute1, tracking date set$(if ($ReportOnly) { ' (ReportOnly ON)' })"
        continue
    }

    # -- DELETION CHECK --
    # If less than DeleteThresholdMonths have passed since the disable date, skip.
    if ($RunDate -lt $ReferenceDate.AddMonths($DeleteThresholdMonths)) {
        $DaysRemaining = ($ReferenceDate.AddMonths($DeleteThresholdMonths) - $RunDate).Days
        Write-Host "    [WAITING]  $($Computer.Name) -- $DaysRemaining days until eligible for deletion"
        continue
    }

    # -- DELETE --
    # Disable date is >= DeleteThresholdMonths old. This action is irreversible.
    # -Recursive handles any child objects (e.g. BitLocker keys) stored beneath
    # the computer object in AD.
    $Logon     = Get-LastLogonInfo -Account $Computer
    $ActionStr = if ($ReportOnly)                    { 'WOULD DELETE' } `
                 elseif ($DeletionGuardrailTripped)  { 'WOULD DELETE (Guardrail -- deletion skipped this run)' } `
                 else                                { 'Deleted' }

    if (-not $ReportOnly -and -not $DeletionGuardrailTripped) {
        try {
            Remove-ADObject -Identity $Computer.DistinguishedName -Recursive -Confirm:$false
        } catch {
            Write-Warning "    [ERROR] Failed to delete $($Computer.Name): $_"
            $Report.Errors.Add((Build-ErrorRow `
                -ObjectType      "Computer" `
                -AccountName     $Computer.Name `
                -AttemptedAction "Remove-ADObject (permanent deletion)" `
                -ErrorMessage    $_.ToString()))
            continue
        }
    }

    $Report.Deleted.Add((Build-ReportRow `
        -Account             $Computer `
        -ObjectType          "Computer" `
        -LastLogonDate       $Logon.LastLogonStr `
        -DaysInactive        $Logon.DaysInactive `
        -Action              "$ActionStr -- Disable date: $($ReferenceDate.ToString('yyyy-MM-dd'))" `
        -Description         $Computer.Description `
        -ExtensionAttribute1 $Computer.extensionAttribute1))

    Write-Host "    [DELETED]  $($Computer.Name) -- $(if ($ReportOnly) { 'WOULD DELETE (ReportOnly ON)' } elseif ($DeletionGuardrailTripped) { 'WOULD DELETE (Guardrail)' } else { 'DELETED' })"
}

#endregion

#region -- PHASE 4: DISABLED USERS OU SCAN (deletion) --

if ($UserPhasesEnabled) {

    Write-Host ""
    Write-Host "--- Phase 4: Scanning Disabled Users OU ---"
    Write-Host "  Source: $DisabledUsersOU (including all sub-OUs)"

    foreach ($User in $DisabledUserObjects) {

        # -- PROTECTED USER CHECK --
        # Protected users in the Disabled OU are skipped silently. They should
        # not normally be here, but if they are we never auto-delete them.
        if (Test-IsProtectedUser -User $User) {
            Write-Host "    [SKIP]     $($User.Name) -- Protected user in Disabled OU, skipping silently"
            continue
        }

        # -- DATE CHECK via extensionAttribute1 --
        $ReferenceDate = Get-ExtensionAttributeDate -Account $User

        if ($null -eq $ReferenceDate) {
            # -- NO DATE FOUND --
            # User was placed in the Disabled OU outside of this script.
            # Write today's date to start the deletion clock.

            try {
                Set-ExtensionAttributeDate -Account $User -DateString $RunDateStr -ReportOnly $ReportOnly
            } catch {
                Write-Warning "    [ERROR] Failed to set extensionAttribute1 for $($User.Name): $_"
                $Report.Errors.Add((Build-ErrorRow `
                    -ObjectType      "User" `
                    -AccountName     $User.Name `
                    -AttemptedAction "Set extensionAttribute1 (tracking date)" `
                    -ErrorMessage    $_.ToString()))
                continue
            }

            try {
                $null = Add-DescriptionText `
                    -Account      $User `
                    -TextToAppend "Not disabled by automation -- date added for tracking purposes: $RunDateStr" `
                    -ReportOnly   $ReportOnly
            } catch {
                Write-Warning "    [ERROR] Failed to write tracking note to Description for $($User.Name): $_"
                $Report.Errors.Add((Build-ErrorRow `
                    -ObjectType      "User" `
                    -AccountName     $User.Name `
                    -AttemptedAction "Append tracking note to Description" `
                    -ErrorMessage    $_.ToString()))
            }

            Write-Host "    [TRACKED]  $($User.Name) -- No date in extensionAttribute1, tracking date set$(if ($ReportOnly) { ' (ReportOnly ON)' })"
            continue
        }

        # -- DELETION CHECK --
        if ($RunDate -lt $ReferenceDate.AddMonths($DeleteThresholdMonths)) {
            $DaysRemaining = ($ReferenceDate.AddMonths($DeleteThresholdMonths) - $RunDate).Days
            Write-Host "    [WAITING]  $($User.Name) -- $DaysRemaining days until eligible for deletion"
            continue
        }

        # -- DELETE --
        $Logon     = Get-LastLogonInfo -Account $User -IncludePwdLastSet
        $ActionStr = if ($ReportOnly)                    { 'WOULD DELETE' } `
                     elseif ($DeletionGuardrailTripped)  { 'WOULD DELETE (Guardrail -- deletion skipped this run)' } `
                     else                                { 'Deleted' }

        if (-not $ReportOnly -and -not $DeletionGuardrailTripped) {
            try {
                Remove-ADObject -Identity $User.DistinguishedName -Recursive -Confirm:$false
            } catch {
                Write-Warning "    [ERROR] Failed to delete $($User.Name): $_"
                $Report.Errors.Add((Build-ErrorRow `
                    -ObjectType      "User" `
                    -AccountName     $User.Name `
                    -AttemptedAction "Remove-ADObject (permanent deletion)" `
                    -ErrorMessage    $_.ToString()))
                continue
            }
        }

        $Report.Deleted.Add((Build-ReportRow `
            -Account             $User `
            -ObjectType          "User" `
            -LastLogonDate       $Logon.LastLogonStr `
            -DaysInactive        $Logon.DaysInactive `
            -Action              "$ActionStr -- Disable date: $($ReferenceDate.ToString('yyyy-MM-dd'))" `
            -Description         $User.Description `
            -ExtensionAttribute1 $User.extensionAttribute1))

        Write-Host "    [DELETED]  $($User.Name) -- $(if ($ReportOnly) { 'WOULD DELETE (ReportOnly ON)' } elseif ($DeletionGuardrailTripped) { 'WOULD DELETE (Guardrail)' } else { 'DELETED' })"
    }

} else {
    Write-Host ""
    Write-Host "--- Phase 4: Skipped (UserScopeGroup not configured) ---"
}

#endregion

#region -- REPORTING & EMAIL --

Write-Host ""
Write-Host "--- Building Report ---"

$SectionMap = [ordered]@{
    Disabled            = "Disabled"
    Deleted             = "Deleted"
    ServersManualReview = "Servers / DCs -- Manual Review Required"
    UsersManualReview   = "Protected / Service Accounts -- Manual Review Required"
    Errors              = "Errors -- Action Failed"
}

$AllRows = [System.Collections.Generic.List[PSObject]]::new()

foreach ($Bucket in $SectionMap.Keys) {
    foreach ($Row in $Report[$Bucket]) {
        $Row | Add-Member -NotePropertyName "Section" -NotePropertyValue $SectionMap[$Bucket] -Force
        $AllRows.Add($Row)
    }
}

$SummaryCounts = foreach ($Bucket in $SectionMap.Keys) {
    "  {0,-60} : {1}" -f $SectionMap[$Bucket], $Report[$Bucket].Count
}

$ModeLabel = if ($ReportOnly) {
    "REPORT ONLY -- No changes were made to Active Directory."
} else {
    "LIVE MODE -- Changes have been applied to Active Directory."
}

$DisableGuardrailNote = if ($DisableGuardrailTripped) {
    "`nWARNING -- DISABLE GUARDRAIL TRIPPED: $DisableCandidateCount disable candidates exceeded the limit of $MaxDisablesPerRun. NO accounts were disabled, moved, or written to this run. A spike this large may indicate bad data (e.g. stale DC replication). Review the Disabled section in the attached CSV, then re-run after confirming the scope is expected."
} else { "" }

$DeletionGuardrailNote = if ($DeletionGuardrailTripped) {
    "`nWARNING -- DELETION GUARDRAIL TRIPPED: $DeletionCandidateCount deletion candidates exceeded the limit of $MaxDeletionsPerRun. No objects were deleted this run. Review the Deleted section in the attached CSV to see affected objects, then re-run after confirming the scope is expected."
} else { "" }

$ArchiveNote = if ($ArchiveFallback) {
    "`nWARNING -- The report archive path '$ReportArchivePath' was unreachable. The transcript and CSV for this run were written to '%TEMP%' on the host instead."
} else { "" }

$EmailBody = @"
Stale Object Management -- Run Report
======================================
Run Date : $RunTimestamp
Mode     : $ModeLabel

SUMMARY
-------
$($SummaryCounts -join "`n")

Please review the attached CSV for full details.
A copy of this CSV and the run transcript are retained on the host at:
$ArchiveDir  (previous run's files are replaced each run)
$(if ($Report.Errors.Count -gt 0) { "`nWARNING: $($Report.Errors.Count) operation(s) failed this run. Review the Errors section in the attached CSV." })$DisableGuardrailNote$DeletionGuardrailNote$ArchiveNote
--
This is an automated message from the Stale Object Cleanup script.
"@

# The CSV is written to the archive directory and RETAINED after the run.
# It is the last-resort audit trail if the email below fails to send.
# It is replaced (not accumulated) on the next run.
$CsvContent = $AllRows | Select-Object Section, ObjectType, AccountName, OUPath, OperatingSystem,
                                        LastLogonDate, DaysInactive, ActionTaken,
                                        ActionDate, Description, ExtensionAttribute1,
                                        ReportOnlyMode `
                        | ConvertTo-Csv -NoTypeInformation

$CsvPath    = Join-Path $ArchiveDir "StaleObjectReport_$RunDateStr.csv"
$CsvContent | Out-File -FilePath $CsvPath -Encoding UTF8

$Subject = "$(if ($ReportOnly) { '[REPORT ONLY] ' })$(if ($DisableGuardrailTripped -or $DeletionGuardrailTripped) { '[GUARDRAIL] ' })$(if ($Report.Errors.Count -gt 0) { '[ERRORS] ' })Stale Object Report -- $RunDateStr"

Write-Host "  Report CSV written to: $CsvPath"
Write-Host "  Sending report email to: $($EmailTo -join ', ')"

try {
    Send-MailMessage `
        -From        $EmailFrom `
        -To          $EmailTo `
        -Subject     $Subject `
        -Body        $EmailBody `
        -SmtpServer  $SmtpServer `
        -Attachments $CsvPath

    Write-Host "  Email sent successfully."
} catch {
    Write-Warning "  Failed to send report email: $_"
    Write-Warning "  AD operations for this run are complete. Check SMTP configuration."
    Write-Warning "  The report CSV is retained at: $CsvPath"
    Write-Warning "  The run transcript is retained at: $LogPath"
}

#endregion

#region -- FINAL SUMMARY --

Write-Host ""
Write-Host "======================================================"
Write-Host " Run Complete -- $RunTimestamp"
Write-Host " Mode: $(if ($ReportOnly) { 'REPORT ONLY' } else { 'LIVE' })"
if ($DisableGuardrailTripped) {
    Write-Host " *** DISABLE GUARDRAIL TRIPPED -- no accounts disabled, see report ***"
}
if ($DeletionGuardrailTripped) {
    Write-Host " *** DELETION GUARDRAIL TRIPPED -- deletion phases skipped, see report ***"
}
if ($Report.Errors.Count -gt 0) {
    Write-Host " *** $($Report.Errors.Count) ERROR(S) OCCURRED -- review Errors section in report ***"
}
Write-Host "------------------------------------------------------"
foreach ($Bucket in $SectionMap.Keys) {
    Write-Host ("  {0,-60} : {1}" -f $SectionMap[$Bucket], $Report[$Bucket].Count)
}
Write-Host " Report CSV : $CsvPath"
Write-Host " Transcript : $LogPath"
Write-Host "======================================================"
Write-Host ""

#endregion

#region -- STOP LOGGING --

# Close the transcript. Wrapped so a logging hiccup never surfaces as a script
# error. The log file remains in the archive directory for later review.
try {
    Stop-Transcript | Out-Null
} catch {
    # No active transcript (e.g. Start-Transcript failed earlier) -- nothing to do.
}

#endregion
