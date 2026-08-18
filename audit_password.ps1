# Local Password and Credential Audit Script
$Report = @()

# Fetch target system environment details
$HostName = $env:COMPUTERNAME
$UserName = $env:USERNAME
$IpAddress = (Get-NetIPAddress -AddressFamily IPv4 | Where-Object { $_.IPAddress -notlike "127.*" -and $_.InterfaceAlias -notmatch "Loopback" } | Select-Object -First 10).IPAddress
if (-not $IpAddress) { $IpAddress = "N/A" }

function New-AuditEntry {
    param ($Category, $Item, $Detail)
    return [PSCustomObject]@{
        "Category" = $Category
        "Item"     = $Item
        "Detail"   = $Detail
    }
}

# 1. Audit Windows Credential Manager vaults using cmdkey
Write-Host "[*] Auditing Windows Credential Manager via cmdkey..." -ForegroundColor Cyan
$CmdKeyOutput = & cmdkey /list 2>$null

if ($CmdKeyOutput -match "Target:") {
    # Parse the target names out of the cmdkey list response
    foreach ($line in $CmdKeyOutput) {
        if ($line -match "Target:\s*(.*)") {
            $TargetName = $Matches[1].Trim()
            $Report += New-AuditEntry -Category "Credential Manager Stored Key" -Item $TargetName -Detail "Saved application, network, or domain target credential."
        }
    }
} else {
    # Fallback to vaultcmd if cmdkey is empty or disabled by policy
    $Vaults = & vaultcmd /list 2>$null
    foreach ($line in $Vaults) {
        if ($line -match "\w+") {
            $Report += New-AuditEntry -Category "Credential Manager Vault" -Item $line.Trim() -Detail "Active credential storage container."
        }
    }
}

# 2. Check for common plain-text configuration files across ALL local hard drives
Write-Host "[*] Scanning all local hard disks for configuration files (Bypassing cloud files)..." -ForegroundColor Cyan
$Keywords = @("password=", "pwd=", "secret=", "api_key=", "passwd=")
$TargetExtensions = @("*.config", "*.xml", "*.json", "*.ps1", "*.txt", "*.ini", "*.csv", "*.xlsx", "*.docx", "*.doc", "*.xls", "*.conf", "*.cfg", "*.properties", "*.old", "*.save", "*.bat", "*.sh", "*.key", "*.env", "*.pem")

$CloudAttributes = [System.IO.FileAttributes]::SparseFile -bor 
                   [System.IO.FileAttributes]::Offline -bor 
                   [System.IO.FileAttributes]::RecallOnDataAccess

# Get all connected local fixed drives (C:\, D:\, etc.)
$LocalDrives = (Get-Volume | Where-Object { $_.DriveType -eq 'Fixed' -and $_.DriveLetter }).DriveLetter

foreach ($DriveLetter in $LocalDrives) {
    $DriveRoot = "$($DriveLetter):\"
    Write-Host "[*] Processing Drive $DriveRoot ..." -ForegroundColor Yellow
    
    foreach ($ext in $TargetExtensions) {
        $Files = Get-ChildItem -Path $DriveRoot -Filter $ext -Recurse -File -ErrorAction SilentlyContinue | 
            Where-Object { $_.FullName -notlike "C:\Windows*" -and $_.FullName -notlike "C:\Program Files*" -and $_.FullName -notlike "C:\ProgramData*" }
        
        foreach ($File in $Files) {
            if (($File.Attributes -band $CloudAttributes) -eq 0) {
                $MatchesFound = Select-String -Path $File.FullName -Pattern $Keywords -SimpleMatch:$false -ErrorAction SilentlyContinue
                
                foreach ($match in $MatchesFound) {
                    $Report += New-AuditEntry -Category "Potential File Exposure" -Item $match.Path -Detail "Line $($match.LineNumber): $($match.Line.Trim())"
                }
            }
        }
    }
}

# 3. Extract Saved Credentials from Local Browser Databases (Chromium Dynamic Profile & Firefox)
Write-Host "[*] Extracting saved browser accounts..." -ForegroundColor Cyan

$ChromiumRoots = @(
    @{ Name = "Google Chrome"; Root = "$env:LOCALAPPDATA\Google\Chrome\User Data" },
    @{ Name = "Microsoft Edge"; Root = "$env:LOCALAPPDATA\Microsoft\Edge\User Data" },
    @{ Name = "Brave Browser"; Root = "$env:LOCALAPPDATA\BraveSoftware\Brave-Browser\User Data" },
    @{ Name = "Opera Stable"; Root = "$env:APPDATA\Opera Software\Opera Stable" }
)

foreach ($Browser in $ChromiumRoots) {
    if (Test-Path $Browser.Root) {
        $LoginFiles = Get-ChildItem -Path $Browser.Root -Filter "Login Data" -Recurse -File -ErrorAction SilentlyContinue
        
        foreach ($File in $LoginFiles) {
            try {
                $TempDb = [System.IO.Path]::GetTempFileName()
                Copy-Item -Path $File.FullName -Destination $TempDb -Force -ErrorAction SilentlyContinue
                
                $DbContent = Get-Content -Raw -Path $TempDb -ErrorAction SilentlyContinue
                $UrlsFound = [regex]::Matches($DbContent, '(https?://[^\s\x00-\x1F\x7F]+)')
                
                if ($UrlsFound.Count -gt 0) {
                    $UniqueDomains = $UrlsFound.Value | Sort-Object -Unique
                    foreach ($Domain in $UniqueDomains) {
                        if ($Domain.Length -le 100 -and $Domain -notmatch '[\x00-\x08\x0B\x0C\x0E-\x1F]') {
                            $ProfileName = $File.Directory.Name
                            $Report += New-AuditEntry -Category "Saved Browser Account" -Item "$($Browser.Name) ($ProfileName)" -Detail "Credentials stored for: $Domain"
                        }
                    }
                }
                Remove-Item -Path $TempDb -Force -ErrorAction SilentlyContinue
            } catch {}
        }
    }
}

# B. Process Mozilla Firefox Profiles
$FirefoxProfileRoot = "$env:APPDATA\Mozilla\Firefox\Profiles"
if (Test-Path $FirefoxProfileRoot) {
    $LoginsFiles = Get-ChildItem -Path $FirefoxProfileRoot -Filter "logins.json" -Recurse -File -ErrorAction SilentlyContinue
    
    foreach ($File in $LoginsFiles) {
        try {
            $JsonContent = Get-Content -Raw -Path $File.FullName -ErrorAction SilentlyContinue
            $LoginsData = ConvertFrom-Json $JsonContent -ErrorAction SilentlyContinue
            
            if ($LoginsData -and $LoginsData.logins) {
                foreach ($Login in $LoginsData.logins) {
                    if ($Login.hostname) {
                        $Report += New-AuditEntry -Category "Saved Browser Account" -Item "Mozilla Firefox" -Detail "Credentials stored for: $($Login.hostname)"
                    }
                }
            }
        } catch {}
    }
}

# 4. Generate the Clean Output File
$DestinationPath = Join-Path -Path $env:USERPROFILE -ChildPath "Downloads\CredentialAuditReport.csv"

# Write top-level environmental context block 
$MetadataHeader = @"
I hereby acknowledge that the results of this audit are accurate and correct to my knowledge.
I also acknowledge that there is no KBI-related passwords in the result.
Host Name, $HostName
Username, $UserName
IP Address, $IpAddress

"@
Set-Content -Path $DestinationPath -Value $MetadataHeader -Encoding UTF8

# Convert the tabular data to plain-text CSV lines and append them safely
if ($Report.Count -gt 0) {
    $CsvBodyText = $Report | ConvertTo-Csv -NoTypeInformation
    Add-Content -Path $DestinationPath -Value $CsvBodyText -Encoding UTF8
}

# Write to file
Write-Host "[+] Audit complete. Full drive scan report saved perfectly to: $DestinationPath" -ForegroundColor Green
