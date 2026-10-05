   <#
   .DESCRIPTION
       Reads names from a text file (one per line) and moves each matching AD object
       into the target OU, logging each move or failure. Supports -WhatIf.
   .PARAMETER ObjectType
       'User' or 'Computer'. Every name in the input file is treated as this type.
   .EXAMPLE
       .\Move-Objects.ps1 -ObjectType Computer -WhatIf
   #>
[CmdletBinding(SupportsShouldProcess)]

param(
    [Parameter(Mandatory)]
    [ValidateSet('User','Computer')]
    [string]$ObjectType
)

$TargetOU = "<SPECIFIED-OU>"
$Objects = Get-Content "<TARGET-OBJECTS.TXT>" | ForEach-Object { $_.Trim() } | Where-Object { $_ }

Import-Module ActiveDirectory
foreach ($Name in $Objects) {
    try {
        $obj = if ($ObjectType -eq 'User') {
            Get-ADUser $Name -ErrorAction Stop
        } else {
            Get-ADComputer $Name -ErrorAction Stop
        }

        if ($PSCmdlet.ShouldProcess($obj.DistinguishedName, "Move to $TargetOU")) {
            Move-ADObject -Identity $obj.DistinguishedName -TargetPath $TargetOU -ErrorAction Stop
            Write-Host "Moved: $Name"
        }
    }
    catch {
        Write-Warning "Failed: $Name - $($_.Exception.Message)"
    }
}
