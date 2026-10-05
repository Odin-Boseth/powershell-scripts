# Windows & Active Directory Admin Scripts

PowerShell scripts for routine Windows and Active Directory maintenance. See the comment block at the top of each script for parameters and examples.

> Replace any `<PLACEHOLDER>` values before running, and use the dry-run option where available.

## DiskCleanup.ps1
Clears common temp and cache folders and removes local user profiles inactive for 6+ months.
- **Run as:** Administrator or SYSTEM
- **Dry run:** `-ReportOnly`

## LogOffDisconnectedSessions.ps1
Logs off all disconnected user sessions on the local machine.
- **Run as:** Administrator

## Move-AD-Objects.ps1
Moves a list of AD users or computers (from a text file, one per line) into a specified OU.
- **Requires:** ActiveDirectory module
- **Dry run:** `-WhatIf`

## ResetLocalAdmin.ps1
Sets a new password on a specified local account.
- **Run as:** Administrator or SYSTEM

## StaleObjectCleanup.ps1
Disables inactive AD users and computers, moves them to a Disabled OU, and deletes them after a set period. Emails a CSV report each run.
- **Requires:** ActiveDirectory module, SMTP server
- **Dry run:** `-ReportOnly:$true` (default is live)
