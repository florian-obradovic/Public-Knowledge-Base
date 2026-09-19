# Requires Microsoft.Graph.Authentication
# Permission:
# DeviceManagementScripts.ReadWrite.All

#Connect-MgGraph -Scopes "DeviceManagementScripts.ReadWrite.All"
Get-MgContext

$Publisher = "Florian Obradovic"
$DisplayName = "_TEMPORARY: TPM Attestation Workaround (KB5120994)"
$Jira = "TI-19073"

$Description = @"
Temporary workaround for TPM-attested user certificate enrollment failures introduced with KB5120994.
Disables Feature Management override 3436801679. Remove after Microsoft provides a permanent fix ($Jira)
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
    if (-not (Test-Path -LiteralPath $OverridePath)) {
        Write-Output 'TPM attestation workaround missing: Overrides key does not exist.'
        exit 1
    }

    $OverrideKey = Get-Item -LiteralPath $OverridePath

    if ($null -eq $OverrideKey.GetValue($FeatureId, $null)) {
        Write-Output "TPM attestation workaround missing: Feature override $FeatureId does not exist."
        exit 1
    }

    if ($OverrideKey.GetValueKind($FeatureId) -ne [Microsoft.Win32.RegistryValueKind]::DWord) {
        Write-Output "TPM attestation workaround invalid: Feature override $FeatureId is not REG_DWORD."
        exit 1
    }

    if ([uint32]$OverrideKey.GetValue($FeatureId) -ne 0) {
        Write-Output "TPM attestation workaround invalid: Feature override $FeatureId is not 0."
        exit 1
    }

    if (-not (Test-Path -LiteralPath $MetadataPath)) {
        Write-Output 'TPM attestation workaround missing: Metadata key does not exist.'
        exit 1
    }

    $MetadataKey = Get-Item -LiteralPath $MetadataPath

    if ($null -eq $MetadataKey.GetValue('ChangeTime', $null)) {
        Write-Output 'TPM attestation workaround missing: ChangeTime does not exist.'
        exit 1
    }

    if ($MetadataKey.GetValueKind('ChangeTime') -ne [Microsoft.Win32.RegistryValueKind]::DWord) {
        Write-Output 'TPM attestation workaround invalid: ChangeTime is not REG_DWORD.'
        exit 1
    }

    if ([uint32]$MetadataKey.GetValue('ChangeTime') -ne 3) {
        Write-Output 'TPM attestation workaround invalid: ChangeTime is not 3.'
        exit 1
    }

    Write-Output "Compliant: TPM attestation workaround for feature $FeatureId is configured correctly."
    exit 0
}
catch {
    Write-Output "Detection failed: $($_.Exception.Message)"
    exit 1
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
    if (-not (Test-Path -LiteralPath $OverridePath)) {
        New-Item -Path $OverridePath -Force | Out-Null
    }

    if (-not (Test-Path -LiteralPath $MetadataPath)) {
        New-Item -Path $MetadataPath -Force | Out-Null
    }

    New-ItemProperty `
        -Path $OverridePath `
        -Name $FeatureId `
        -PropertyType DWord `
        -Value 0 `
        -Force | Out-Null

    New-ItemProperty `
        -Path $MetadataPath `
        -Name 'ChangeTime' `
        -PropertyType DWord `
        -Value 3 `
        -Force | Out-Null

    $OverrideKey = Get-Item -LiteralPath $OverridePath
    $MetadataKey = Get-Item -LiteralPath $MetadataPath

    $OverrideValue = [uint32]$OverrideKey.GetValue($FeatureId)
    $ChangeTime    = [uint32]$MetadataKey.GetValue('ChangeTime')

    if ($OverrideValue -ne 0 -or $ChangeTime -ne 3) {
        throw "Registry verification failed. Override=$OverrideValue, ChangeTime=$ChangeTime"
    }

    Write-Output "Successfully configured TPM attestation workaround for feature $FeatureId."
    exit 0
}
catch {
    Write-Error "Remediation failed: $($_.Exception.Message)"
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
