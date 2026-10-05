<#
.DESCRIPTION
    Removes safe temp files and inactive user profiles (6+ months).
    Writes a log to C:\Windows\Temp\DiskCleanup_Log.txt on every run.
    Can be run interactively or as SYSTEM via a scheduled task or deployment tool.
    Run locally with -Verbose to also see output in the console.

.PARAMETER ReportOnly
    When specified, the script logs everything it WOULD delete but does not
    actually delete any profiles. 

    Example:
        powershell.exe -ExecutionPolicy Bypass -File DiskCleanup.ps1

    Example (safe report-only review):
        powershell.exe -ExecutionPolicy Bypass -File DiskCleanup.ps1 -ReportOnly

.NOTES
    Profile inactivity is determined solely by the profile folder's
    "Date modified" (LastWriteTime). A profile is deleted when that date
    is older than 6 months. No secondary checks are performed.
#>

[CmdletBinding()]
param(
    [switch]$ReportOnly
)

$ErrorActionPreference = 'SilentlyContinue'
$LogPath = "C:\Windows\Temp\DiskCleanup_Log.txt"

#region Configuration
$InactiveThreshold = (Get-Date).AddMonths(-6)
# Excluded user profiles that should never be deleted regardless of check results.
# Replace <LOCAL-ADMIN-ACCOUNT> with any local or break-glass admin accounts.
$ExcludedProfiles = @(
    'Administrator', 'Default', 'Public', 'systemprofile',
    'LocalService', 'NetworkService', 'DefaultAccount', 'WDAGUtilityAccount',
    '<LOCAL-ADMIN-ACCOUNT>'
)

$CleanupPaths = @(
    "$env:SystemRoot\Temp",
    "$env:SystemRoot\SoftwareDistribution\Download",
    "$env:ProgramData\Microsoft\Windows\WER\ReportArchive",
    "$env:ProgramData\Microsoft\Windows\WER\ReportQueue",
    "$env:SystemRoot\Prefetch"
)
#endregion

#region Logging
function Write-Log {
    param([string]$Message)
    $Message | Out-File -FilePath $LogPath -Append -Encoding UTF8
    Write-Verbose $Message
}

"=" * 60 | Out-File -FilePath $LogPath -Encoding UTF8 -Force
Write-Log "DiskCleanup Log"
Write-Log "Run Time   : $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')"
Write-Log "Hostname   : $env:COMPUTERNAME"
Write-Log "Run As     : $([System.Security.Principal.WindowsIdentity]::GetCurrent().Name)"
Write-Log "Mode       : $(if ($ReportOnly) { 'REPORT ONLY (no deletions)' } else { 'LIVE (deletions enabled)' })"
Write-Log ("=" * 60)
#endregion

#region Disk Space Before
Write-Log ""
Write-Log "[DISK SPACE BEFORE]"
try {
    $Drive = (Get-Item $env:SystemRoot).PSDrive.Name
    $FreeSpaceBefore = (Get-PSDrive $Drive).Free
    Write-Log "  Free : $([math]::Round($FreeSpaceBefore / 1GB, 2)) GB"
} catch {
    Write-Log "  ERROR reading disk space: $_"
}
#endregion

#region System File Cleanup
Write-Log ""
Write-Log "[SYSTEM FILE CLEANUP]"
foreach ($Path in $CleanupPaths) {
    if (Test-Path $Path) {
        $Files  = Get-ChildItem -Path $Path -Recurse -Force
        $Count  = ($Files | Where-Object { -not $_.PSIsContainer }).Count
        $SizeMB = [math]::Round(($Files | Measure-Object -Property Length -Sum).Sum / 1MB, 2)
        if (-not $ReportOnly) {
            $Files | Remove-Item -Recurse -Force
        }
        $Prefix = if ($ReportOnly) { 'WOULD CLEAN' } else { 'CLEANED' }
        Write-Log "  $Prefix  $Path ($Count files, $SizeMB MB)"
    } else {
        Write-Log "  MISSING  $Path"
    }
}

if (-not $ReportOnly) { Clear-RecycleBin -Force }
$Prefix = if ($ReportOnly) { 'WOULD CLEAN' } else { 'CLEANED' }
Write-Log "  $Prefix  Recycle Bin"
#endregion

#region Inactive Profile Cleanup
Write-Log ""
Write-Log "[USER PROFILE CLEANUP]"
Write-Log "  Threshold : profiles with Date Modified older than $($InactiveThreshold.ToString('yyyy-MM-dd'))"
Write-Log ""

$CurrentUser = (Get-WmiObject Win32_ComputerSystem).UserName
if ($CurrentUser) { $CurrentUser = $CurrentUser.Split('\')[-1] }

Get-WmiObject -Class Win32_UserProfile |
    Where-Object {
        -not $_.Special -and
        $_.LocalPath -and
        ($_.LocalPath.Split('\')[-1] -notin $ExcludedProfiles) -and
        (-not $CurrentUser -or $_.LocalPath.Split('\')[-1] -ne $CurrentUser)
    } | ForEach-Object {
        $ProfileName = $_.LocalPath.Split('\')[-1]
        $FolderExists = Test-Path $_.LocalPath
        $FolderDate   = $null
        if ($FolderExists) {
            try { $FolderDate = (Get-Item $_.LocalPath).LastWriteTime } catch {}
        }

        # Case 1: Folder does not exist on disk.
        # The profile folder was previously deleted manually without going through
        # the WMI removal process.
        if (-not $FolderExists) {
            if ($ReportOnly) {
                Write-Log "  WOULD CLEAN ORPHAN  $ProfileName - WMI entry exists but folder not found on disk"
            } else {
                try {
                    $_.Delete()
                    Write-Log "  CLEANED ORPHAN      $ProfileName - WMI entry removed (folder was not on disk)"
                } catch {
                    Write-Log "  ERROR               $ProfileName - orphan removal failed: $_"
                }
            }
        }
        # Case 2: Folder exists but Date Modified could not be read — skip.
        elseif ($null -eq $FolderDate) {
            Write-Log "  SKIPPED             $ProfileName - folder exists but Date Modified could not be read"
        }
        elseif ($FolderDate -ge $InactiveThreshold) {
            Write-Log "  SKIPPED       $ProfileName - Date Modified $($FolderDate.ToString('yyyy-MM-dd')) (within 6 months)"
        }
        else {
            if ($ReportOnly) {
                Write-Log "  WOULD DELETE  $ProfileName - Date Modified $($FolderDate.ToString('yyyy-MM-dd')) (older than 6 months)"
            } else {
                try {
                    $_.Delete()
                    Write-Log "  DELETED       $ProfileName - Date Modified $($FolderDate.ToString('yyyy-MM-dd')) (older than 6 months)"
                } catch {
                    Write-Log "  ERROR         $ProfileName - deletion failed: $_"
                }
            }
        }
    }
#endregion

#region Summary
Write-Log ""
Write-Log "[SUMMARY]"
try {
    $FreeSpaceAfter = (Get-PSDrive $Drive).Free
    $Recovered      = $FreeSpaceAfter - $FreeSpaceBefore
    Write-Log "  Free space after : $([math]::Round($FreeSpaceAfter / 1GB, 2)) GB"
    Write-Log "  Space recovered  : $([math]::Round($Recovered / 1MB, 0)) MB"
    if ($ReportOnly) {
        Write-Log "  NOTE             : Script ran in Report Only mode. No files or profiles were deleted."
    }
} catch {
    Write-Log "  ERROR reading final disk space: $_"
}
Write-Log ""
Write-Log ("=" * 60)
Write-Log "End of Log"
#endregion
