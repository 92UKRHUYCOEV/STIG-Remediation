<#
.SYNOPSIS
    This PowerShell script ensures the Kernel DMA Protection enumeration policy is set to 'Block All'.

.DESCRIPTION
    The script targets HKLM:\SOFTWARE\Policies\Microsoft\Windows\Kernel DMA Protection to remediate 
    the STIG requirement for external device enumeration. It ensures the 'DeviceEnumerationPolicy' 
    is set to 0, which blocks external DMA-capable devices that are incompatible with DMA remapping.

.NOTES
    Author          : Sallie Chait
    LinkedIn        : https://www.linkedin.com/in/sallie-chait-57a4893
    GitHub          : https://github.com/92UKRHUYCOEV/STIG-Remediation
    Date Created    : 04-22-26
    Last Modified   : 08-22-26
    Version         : 1.1
    STIG-ID         : WN11-EP-000310
    Severity        : Medium (CAT II)
    Reference       : https://stigaview.com/products/win11/v2r8/WN11-EP-000310/
#>

$regPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Kernel DMA Protection"
$valName = "DeviceEnumerationPolicy"
$desired = 0  # 0 corresponds to "Block All"

Write-Host "--- STIG Compliance Check: Kernel DMA Protection ---" -ForegroundColor Cyan

# 1. THE CHECK: Verify if the registry value exists and is correct
$currentValue = Get-ItemProperty -Path $regPath -Name $valName -ErrorAction SilentlyContinue

if ($null -ne $currentValue -and $currentValue.$valName -eq $desired) {
    Write-Host "[PASS] $valName is already set to $desired (Block All)." -ForegroundColor Green
} 
else {
    Write-Host "[FAIL] $valName is non-compliant or missing. Remediating..." -ForegroundColor Yellow

    # 2. THE FIX: Create path if missing and set the DWORD
    try {
        if (-not (Test-Path $regPath)) {
            # Note: We use -Force to ensure the nested "Kernel DMA Protection" path is created
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
