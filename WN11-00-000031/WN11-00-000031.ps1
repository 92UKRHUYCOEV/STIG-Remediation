<#
.SYNOPSIS
    This PowerShell script ensures BitLocker pre-boot authentication is configured to require a TPM Startup PIN.

.DESCRIPTION
    The script targets HKLM:\SOFTWARE\Policies\Microsoft\FVE to remediate STIG ID WN11-00-000031. 
    It enforces the use of a TPM Startup PIN and disables non-compliant startup options like 
    startup keys (USB) or booting without a compatible TPM.

.NOTES
    Author          : Sallie Chait
    LinkedIn        : https://www.linkedin.com/in/sallie-chait-57a4893
    GitHub          : https://github.com/92UKRHUYCOEV/STIG-Remediation
    Date Created    : 04-22-26
    Last Modified   : 08-22-26
    Version         : 1.1
    STIG-ID         : WN11-00-000031
    Severity        : High (CAT I)
    Documentation   : https://stigaview.com/products/win11/v2r7/WN11-00-000031/
#>

$regPath = "HKLM:\SOFTWARE\Policies\Microsoft\FVE"

# Define the required settings for TPM + PIN authentication
$stigSettings = @{
    "EnableBDEWithNoTPM" = 0  # Disable booting without TPM
    "UseAdvancedStartup" = 1  # Enable advanced startup options
    "UseTPM"             = 2  # Allow TPM
    "UseTPMPIN"          = 1  # Require Startup PIN with TPM
    "UseTPMKey"          = 0  # Do not allow startup key
    "UseTPMKeyPIN"       = 0  # Do not allow key and PIN combo
}

Write-Host "--- STIG Compliance Check: BitLocker Pre-Boot Authentication ---" -ForegroundColor Cyan

foreach ($valName in $stigSettings.Keys) {
    $desired = $stigSettings[$valName]
    $currentValue = Get-ItemProperty -Path $regPath -Name $valName -ErrorAction SilentlyContinue

    if ($null -ne $currentValue -and $currentValue.$valName -eq $desired) {
        Write-Host "[PASS] $valName is already set to $desired." -ForegroundColor Green
    } 
    else {
        Write-Host "[FAIL] $valName is non-compliant. Remediating..." -ForegroundColor Yellow

        try {
            if (-not (Test-Path $regPath)) {
                New-Item -Path $regPath -Force | Out-Null
                Write-Host "Created missing registry path: $regPath" -ForegroundColor Gray
            }

            Set-ItemProperty -Path $regPath -Name $valName -Value $desired -Type DWord
            
            $verify = Get-ItemProperty -Path $regPath -Name $valName
            if ($verify.$valName -eq $desired) {
                Write-Host "[SUCCESS] $valName set to $desired." -ForegroundColor Green
            }
        } 
        catch {
            Write-Host "[ERROR] Failed to remediate $valName : $($_.Exception.Message)" -ForegroundColor Red
        }
    }
}

# Apply changes to Group Policy
Write-Host "Refreshing Group Policy..." -ForegroundColor Gray
gpupdate /force
