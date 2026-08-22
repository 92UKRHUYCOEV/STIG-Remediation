<#
.SYNOPSIS
    This PowerShell script ensures Microsoft consumer experiences are turned off.

.DESCRIPTION
    The script targets HKLM:\SOFTWARE\Policies\Microsoft\Windows\CloudContent to remediate 
    STIG ID WN11-CC-000197. It ensures the 'DisableWindowsConsumerFeatures' DWORD is set 
    to 1, preventing the unwanted installation of suggested applications and notifications.

.NOTES
    Author          : Sallie Chait
    LinkedIn        : https://www.linkedin.com/in/sallie-chait-57a4893
    GitHub          : https://github.com/92UKRHUYCOEV/STIG-Remediation
    Date Created    : 04-22-26
    Last Modified   : 08-22-26
    Version         : 1.1
    CVEs            : N/A
    Plugin IDs      : N/A
    STIG-ID         : WN11-CC-000197
    Severity        : Low (CAT III)
    Reference       : https://stigaview.com/products/win11/v2r7/WN11-CC-000197/
#>

$regPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\CloudContent"
$valName = "DisableWindowsConsumerFeatures"
$desired = 1

Write-Host "--- STIG Compliance Check: Microsoft Consumer Experiences ---" -ForegroundColor Cyan

# 1. THE CHECK: Does the value exist and match the STIG requirement?
$currentValue = Get-ItemProperty -Path $regPath -Name $valName -ErrorAction SilentlyContinue

if ($null -ne $currentValue -and $currentValue.$valName -eq $desired) {
    Write-Host "[PASS] $valName is already set to $desired (Disabled)." -ForegroundColor Green
} 
else {
    Write-Host "[FAIL] $valName is non-compliant or missing. Remediating..." -ForegroundColor Yellow

    # 2. THE FIX: Create path and set DWORD
    try {
        if (-not (Test-Path $regPath)) {
            New-Item -Path $regPath -Force | Out-Null
            Write-Host "Created missing registry path: $regPath" -ForegroundColor Gray
        }

        Set-ItemProperty -Path $regPath -Name $valName -Value $desired -Type DWord
        
        # 3. VERIFICATION: Confirm the change was written
        $verify = Get-ItemProperty -Path $regPath -Name $valName
        if ($verify.$valName -eq $desired) {
            Write-Host "[SUCCESS] $valName applied. Value set to $desired." -ForegroundColor Green
            
            # Force Group Policy to recognize the change
            gpupdate /force
        }
    } 
    catch {
        Write-Host "[ERROR] Failed to remediate $valName : $($_.Exception.Message)" -ForegroundColor Red
    }
}
