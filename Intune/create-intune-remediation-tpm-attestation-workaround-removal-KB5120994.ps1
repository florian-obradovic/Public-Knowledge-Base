# Requires Microsoft.Graph.Authentication
# Permission:
# DeviceManagementScripts.ReadWrite.All

#Connect-MgGraph -Scopes "DeviceManagementScripts.ReadWrite.All"
Get-MgContext

$Publisher = "Florian Obradovic"
$DisplayName = "_TEMPORARY: TPM Attestation Workaround Removal (KB5120994)"
$Jira = "TI-19073"

$Description = @"
Removes the temporary TPM Attestation workaround for KB5120994.
Deletes only Feature Management override 3436801679 and its corresponding metadata subkey ($Jira).
"@

# -------------------------------------------------------------------
# Detection Script
# -------------------------------------------------------------------

$DetectionScript = @'
$ErrorActionPreference = 'Stop'

$FeatureId    = '3436801679'
$OverridePath = 'HKLM:\SYSTEM\CurrentControlSet\Policies\Microsoft\FeatureManagement\Overrides'
$MetadataPath = "$OverridePath\Metadata\$FeatureId"

try {
    $OverrideExists = $false
    if (Test-Path -LiteralPath $OverridePath) {
        $OverrideKey = Get-Item -LiteralPath $OverridePath
        $OverrideExists = $OverrideKey.GetValueNames() -contains $FeatureId
    }

    $MetadataExists = Test-Path -LiteralPath $MetadataPath

    if ($OverrideExists -or $MetadataExists) {
        Write-Output "Removal required for feature $FeatureId. Override exists: $OverrideExists; metadata exists: $MetadataExists."
        exit 1
    }

    Write-Output "Compliant: TPM attestation workaround for feature $FeatureId is absent."
    exit 0
}
catch {
    Write-Output "Detection failed: $($_.Exception.Message)"
    exit 2
}
'@
# -------------------------------------------------------------------
# Remediation Script
# -------------------------------------------------------------------

$RemediationScript = @'
$ErrorActionPreference = 'Stop'

$FeatureId    = '3436801679'
$OverridePath = 'HKLM:\SYSTEM\CurrentControlSet\Policies\Microsoft\FeatureManagement\Overrides'
$MetadataPath = "$OverridePath\Metadata\$FeatureId"

try {
    # Remove only this feature's value; preserve the Overrides parent key.
    if (Test-Path -LiteralPath $OverridePath) {
        $OverrideKey = Get-Item -LiteralPath $OverridePath
        if ($OverrideKey.GetValueNames() -contains $FeatureId) {
            Remove-ItemProperty `
                -LiteralPath $OverridePath `
                -Name $FeatureId `
                -Force
        }
    }

    # Remove only this feature's metadata subkey; preserve the Metadata parent key.
    if (Test-Path -LiteralPath $MetadataPath) {
        Remove-Item `
            -LiteralPath $MetadataPath `
            -Recurse `
            -Force
    }

    # Verify removal independently of the original registry value type or data.
    $OverrideExists = $false
    if (Test-Path -LiteralPath $OverridePath) {
        $OverrideKey = Get-Item -LiteralPath $OverridePath
        $OverrideExists = $OverrideKey.GetValueNames() -contains $FeatureId
    }

    $MetadataExists = Test-Path -LiteralPath $MetadataPath

    if ($OverrideExists -or $MetadataExists) {
        throw "Registry verification failed. Override exists: $OverrideExists; metadata exists: $MetadataExists."
    }

    Write-Output "Successfully removed TPM attestation workaround for feature $FeatureId."
    exit 0
}
catch {
    Write-Output "Remediation failed: $($_.Exception.Message)"
    exit 1
}
'@
# -------------------------------------------------------------------
# Build Graph object
# Script contents must be Base64 encoded
# -------------------------------------------------------------------

$Body = @{
    "@odata.type" = "#microsoft.graph.deviceHealthScript"

    displayName = $DisplayName
    description = $Description
    publisher   = $Publisher
    version     = "1.0"

    detectionScriptContent = [Convert]::ToBase64String(
        [Text.Encoding]::UTF8.GetBytes($DetectionScript)
    )

    remediationScriptContent = [Convert]::ToBase64String(
        [Text.Encoding]::UTF8.GetBytes($RemediationScript)
    )

    # SYSTEM context
    runAsAccount = "system"

    # 64-bit PowerShell
    runAs32Bit = $false

    # Change to $true if you sign the scripts
    enforceSignatureCheck = $false

    roleScopeTagIds = @("0")

    deviceHealthScriptType = "deviceHealthScript"
}

$Json = $Body | ConvertTo-Json -Depth 10

$Result = Invoke-MgGraphRequest `
    -Method POST `
    -Uri "https://graph.microsoft.com/beta/deviceManagement/deviceHealthScripts" `
    -Body $Json `
    -ContentType "application/json"

Write-Host ""
Write-Host "Created Intune Remediation:"
Write-Host "Name: $($Result.displayName)"
Write-Host "ID:   $($Result.id)"

$EncodedDisplayName = [Uri]::EscapeDataString($DisplayName)
$IntuneRemediationUrl = "https://intune.microsoft.com/#view/Microsoft_Intune_Enrollment/UXAnalyticsScriptMenu/~/overview/id/$($Result.id)/scriptName/$EncodedDisplayName/isFirstParty~/false"

Write-Host "---" -ForegroundColor Magenta
Write-Host "Use these links and link names in Jira!" -ForegroundColor Green
Write-Host "---" -ForegroundColor Magenta
Write-Host "`nURL:"
Write-Host $IntuneRemediationUrl -ForegroundColor Cyan
Write-Host "Name:"
Write-Host "Intune Remediation - $DisplayName" -ForegroundColor Blue
Write-Host "---" -ForegroundColor Magenta
