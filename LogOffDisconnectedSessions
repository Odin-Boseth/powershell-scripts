$sessions = query session 2>&1
  
foreach ($line in $sessions) {
    if ($line -match "SESSIONNAME") { continue }
  
    if ($line -match "\s+(\d+)\s+(Disc)") {
        $sessionID = $matches[1]
  
        if ($sessionID -eq "0") { continue }
  
        logoff $sessionID
    }
}
