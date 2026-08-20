#Requires -Version 7.0
<#
.SYNOPSIS
    Creates a least-privilege Entra ID app registration for entra-secret-monitor.

.DESCRIPTION
    Creates a dedicated app registration in the target tenant, grants exactly one
    Microsoft Graph application permission (Application.Read.All), consents to it,
    and attaches a credential. Prints the environment block the container expects.

    The permission is read-only on metadata. Graph never returns secret values,
    so the resulting credential can enumerate expiry dates and nothing else.

    Requires the Microsoft.Graph.Applications module and an account that can
    create app registrations and grant admin consent (Application Administrator
    plus Privileged Role Administrator, or Global Administrator).

.PARAMETER TenantId
    Directory (tenant) ID of the tenant to monitor.

.PARAMETER TenantKey
    Short key used in the container configuration, for example "contoso".
    Becomes the environment variable prefix (CONTOSO_TENANT_ID and so on).

.PARAMETER DisplayName
    Display name of the app registration.

.PARAMETER CreateCertificate
    Generate a self-signed key pair locally, upload the public certificate and
    write <TenantKey>.crt and <TenantKey>.key as PEM files. This is the
    recommended credential type: unlike a client secret it is not capped at
    24 months, and the private key never travels through Entra.

.PARAMETER CertificateYears
    Validity of the generated certificate in years. Entra does not cap this,
    but a tenant may enforce a limit through an app management policy.
    Three years is a deliberate default: the monitor reports its own expiry
    in time, so a longer life buys convenience at the cost of a credential
    that stays valid for a decade if it ever leaks.

.PARAMETER CertificateOutDir
    Directory the generated .crt and .key are written to. Defaults to the
    current directory.

.PARAMETER CertificatePath
    Path to an existing public certificate (.crt or .cer, PEM or DER) to upload
    instead of generating one. Use this when the key pair already exists, for
    example created with openssl on the monitoring host:

        openssl req -x509 -newkey rsa:2048 -nodes -days 1095 \
          -keyout contoso.key -out contoso.crt -subj "/CN=entra-secret-monitor"

.PARAMETER SecretMonths
    Lifetime of the client secret in months when no certificate is used at all.
    Entra caps this at 24.

.PARAMETER OutFile
    Optional path to write the environment block to, instead of only printing it.

.PARAMETER UseDeviceCode
    Authenticate with a device code instead of opening a browser. Useful over SSH
    or inside a terminal that cannot launch a browser.

.EXAMPLE
    ./New-MonitorAppRegistration.ps1 -TenantId 00000000-1111-2222-3333-444444444444 -TenantKey contoso -CreateCertificate

.EXAMPLE
    ./New-MonitorAppRegistration.ps1 -TenantId ... -TenantKey contoso -CreateCertificate -CertificateYears 10

.EXAMPLE
    ./New-MonitorAppRegistration.ps1 -TenantId ... -TenantKey contoso -CertificatePath ./contoso.crt

.EXAMPLE
    ./New-MonitorAppRegistration.ps1 -TenantId ... -TenantKey contoso -UseDeviceCode

.NOTES
    Part of https://github.com/benjaminmue/entra-secret-monitor
#>

[CmdletBinding(SupportsShouldProcess)]
param(
    [Parameter(Mandatory)][string]$TenantId,
    [Parameter(Mandatory)][string]$TenantKey,
    [string]$DisplayName = 'SVC-Monitoring-SecretExpiry',
    [switch]$CreateCertificate,
    [ValidateRange(1, 30)][int]$CertificateYears = 3,
    [string]$CertificateOutDir = '.',
    [string]$CertificatePath,
    [ValidateRange(1, 24)][int]$SecretMonths = 24,
    [string]$OutFile,
    [switch]$UseDeviceCode,
    [switch]$UseExistingApp
)

$ErrorActionPreference = 'Stop'

$GraphAppId = '00000003-0000-0000-c000-000000000000'
$PermissionName = 'Application.Read.All'

function Invoke-WithRetry {
    <#
    .SYNOPSIS
        Runs a script block until it succeeds, to ride out directory replication.
    .PARAMETER ScriptBlock
        The operation to retry.
    .PARAMETER Attempts
        How many times to try before giving up.
    .PARAMETER DelaySeconds
        Pause between attempts.
    #>
    param(
        [Parameter(Mandatory)][scriptblock]$ScriptBlock,
        [int]$Attempts = 8,
        [int]$DelaySeconds = 5
    )
    for ($i = 1; $i -le $Attempts; $i++) {
        try {
            return & $ScriptBlock
        } catch {
            if ($i -eq $Attempts) { throw }
            Write-Verbose "Attempt $i failed: $($_.Exception.Message)"
            Start-Sleep -Seconds $DelaySeconds
        }
    }
}

function New-MonitorCertificate {
    <#
    .SYNOPSIS
        Creates a self-signed RSA key pair and writes it as PEM files.
    .DESCRIPTION
        Produces exactly what the container expects: an unencrypted PKCS#8
        private key and the matching certificate, both PEM encoded. The private
        key never leaves the machine this runs on.
    .PARAMETER Subject
        Certificate subject, for example "CN=entra-secret-monitor".
    .PARAMETER Years
        Validity in years.
    .PARAMETER OutDir
        Directory to write into.
    .PARAMETER BaseName
        File name without extension; .crt and .key are appended.
    .OUTPUTS
        Hashtable with CertPath, KeyPath, Thumbprint and NotAfter.
    #>
    param(
        [Parameter(Mandatory)][string]$Subject,
        [Parameter(Mandatory)][int]$Years,
        [Parameter(Mandatory)][string]$OutDir,
        [Parameter(Mandatory)][string]$BaseName
    )

    if (-not (Test-Path -LiteralPath $OutDir)) {
        New-Item -ItemType Directory -Path $OutDir -Force | Out-Null
    }
    $dir = (Resolve-Path -LiteralPath $OutDir).Path
    $certPath = Join-Path $dir "$BaseName.crt"
    $keyPath = Join-Path $dir "$BaseName.key"

    foreach ($p in @($certPath, $keyPath)) {
        if (Test-Path -LiteralPath $p) {
            throw "$p already exists. Remove it or choose another -CertificateOutDir."
        }
    }

    $rsa = [System.Security.Cryptography.RSA]::Create(2048)
    try {
        $request = [System.Security.Cryptography.X509Certificates.CertificateRequest]::new(
            $Subject, $rsa, 'SHA256',
            [System.Security.Cryptography.RSASignaturePadding]::Pkcs1)

        # Backdate slightly so clock skew cannot invalidate a fresh certificate.
        $notBefore = [DateTimeOffset]::UtcNow.AddHours(-1)
        $notAfter = [DateTimeOffset]::UtcNow.AddYears($Years)
        $cert = $request.CreateSelfSigned($notBefore, $notAfter)

        $certPem = [System.Security.Cryptography.PemEncoding]::Write(
            'CERTIFICATE', $cert.RawData) -join ''
        $keyPem = [System.Security.Cryptography.PemEncoding]::Write(
            'PRIVATE KEY', $rsa.ExportPkcs8PrivateKey()) -join ''

        Set-Content -LiteralPath $certPath -Value $certPem -Encoding ascii -NoNewline
        Set-Content -LiteralPath $keyPath -Value $keyPem -Encoding ascii -NoNewline

        if ($IsLinux -or $IsMacOS) {
            & chmod 600 $keyPath 2>$null
        }

        return @{
            CertPath   = $certPath
            KeyPath    = $keyPath
            Thumbprint = $cert.Thumbprint
            NotAfter   = $cert.NotAfter
            RawData    = $cert.RawData
        }
    } finally {
        $rsa.Dispose()
    }
}

function Get-CertificateBase64 {
    <#
    .SYNOPSIS
        Reads a PEM or DER certificate and returns its raw DER bytes as base64.
    .PARAMETER Path
        Path to the certificate file.
    #>
    param([Parameter(Mandatory)][string]$Path)

    $resolved = (Resolve-Path -LiteralPath $Path).Path
    $cert = [System.Security.Cryptography.X509Certificates.X509Certificate2]::new($resolved)
    Write-Host ("   Certificate subject : {0}" -f $cert.Subject)
    Write-Host ("   Valid until         : {0:yyyy-MM-dd}" -f $cert.NotAfter)
    if ($cert.NotAfter -lt (Get-Date).AddDays(90)) {
        Write-Warning 'The certificate expires in less than 90 days.'
    }
    return [Convert]::ToBase64String($cert.RawData)
}

# --- Connect ---------------------------------------------------------------

Write-Host "== Connecting to tenant $TenantId ==" -ForegroundColor Cyan
$connectArgs = @{
    TenantId    = $TenantId
    Scopes      = @('Application.ReadWrite.All', 'AppRoleAssignment.ReadWrite.All')
    NoWelcome   = $true
}
if ($UseDeviceCode) { $connectArgs['UseDeviceAuthentication'] = $true }
Connect-MgGraph @connectArgs

$context = Get-MgContext
Write-Host ("   Signed in as {0}" -f $context.Account)

# --- Guard against duplicates ---------------------------------------------

$existing = Get-MgApplication -Filter "displayName eq '$DisplayName'" -ErrorAction SilentlyContinue

if ($existing -and -not $UseExistingApp) {
    throw "An app registration named '$DisplayName' already exists (AppId $($existing[0].AppId)). Re-run with -UseExistingApp to attach a credential to it, or pass -DisplayName to create a separate one."
}

$action = if ($existing) { "Attach credential to existing app '$DisplayName'" }
          else { "Create app registration '$DisplayName' with $PermissionName" }
if (-not $PSCmdlet.ShouldProcess($TenantId, $action)) {
    return
}

# --- Application and service principal ------------------------------------
# Every step below is idempotent, so a run that failed halfway can be repeated.

if ($existing) {
    $app = $existing[0]
    Write-Host '== Reusing existing app registration ==' -ForegroundColor Yellow
} else {
    Write-Host '== Creating app registration ==' -ForegroundColor Cyan
    $app = New-MgApplication -DisplayName $DisplayName -SignInAudience 'AzureADMyOrg' `
        -Notes "Read-only credential expiry monitoring. Created $(Get-Date -Format 'yyyy-MM-dd')."
}
Write-Host ("   AppId    : {0}" -f $app.AppId)
Write-Host ("   ObjectId : {0}" -f $app.Id)

Write-Host '== Service principal ==' -ForegroundColor Cyan
$sp = Get-MgServicePrincipal -Filter "appId eq '$($app.AppId)'" -ErrorAction SilentlyContinue
if ($sp) {
    Write-Host '   Already present'
} else {
    $sp = Invoke-WithRetry { New-MgServicePrincipal -AppId $app.AppId }
}
$sp = @($sp)[0]
Write-Host ("   SP ObjectId : {0}" -f $sp.Id)

# --- Permission and consent -----------------------------------------------

Write-Host "== Granting $PermissionName ==" -ForegroundColor Cyan
$graphSp = Get-MgServicePrincipal -Filter "appId eq '$GraphAppId'"
$role = $graphSp.AppRoles | Where-Object {
    $_.Value -eq $PermissionName -and $_.AllowedMemberTypes -contains 'Application'
}
if (-not $role) { throw "Application permission $PermissionName not found on the Graph service principal." }

$assigned = Get-MgServicePrincipalAppRoleAssignment -ServicePrincipalId $sp.Id -ErrorAction SilentlyContinue |
    Where-Object { $_.AppRoleId -eq $role.Id -and $_.ResourceId -eq $graphSp.Id }

if ($assigned) {
    Write-Host '   Already granted'
} else {
    Invoke-WithRetry {
        New-MgServicePrincipalAppRoleAssignment -ServicePrincipalId $sp.Id `
            -PrincipalId $sp.Id -ResourceId $graphSp.Id -AppRoleId $role.Id | Out-Null
    }
    Write-Host '   Admin consent granted'
}

# --- Credential ------------------------------------------------------------

$prefix = $TenantKey.ToUpper() -replace '[^A-Z0-9]', '_'
$credentialLines = @()
$generated = $null

# Graph does not return the public key material of existing keyCredentials, so
# they cannot be preserved and written back. Refuse to silently drop them.
if (($CreateCertificate -or $CertificatePath) -and $app.KeyCredentials.Count -gt 0) {
    $names = ($app.KeyCredentials | ForEach-Object { $_.DisplayName }) -join ', '
    throw "This app registration already has $($app.KeyCredentials.Count) certificate(s) [$names]. Uploading another one through this script would replace them. Add the certificate in the portal instead, or use a separate -DisplayName."
}

if ($CreateCertificate) {
    Write-Host "== Generating certificate ($CertificateYears years) ==" -ForegroundColor Cyan
    $generated = New-MonitorCertificate -Subject "CN=$DisplayName" -Years $CertificateYears `
        -OutDir $CertificateOutDir -BaseName $TenantKey
    Write-Host ("   Thumbprint  : {0}" -f $generated.Thumbprint)
    Write-Host ("   Valid until : {0:yyyy-MM-dd}" -f $generated.NotAfter)
    Write-Host ("   Certificate : {0}" -f $generated.CertPath)
    Write-Host ("   Private key : {0}" -f $generated.KeyPath)

    Update-MgApplication -ApplicationId $app.Id -KeyCredentials @(
        @{
            Type        = 'AsymmetricX509Cert'
            Usage       = 'Verify'
            DisplayName = 'entra-secret-monitor'
            Key         = $generated.RawData
        }
    )
    $credentialLines = @(
        "${prefix}_CERT_PATH=/config/$TenantKey.crt",
        "${prefix}_KEY_PATH=/config/$TenantKey.key"
    )
} elseif ($CertificatePath) {
    Write-Host '== Attaching existing certificate ==' -ForegroundColor Cyan
    $base64 = Get-CertificateBase64 -Path $CertificatePath
    Update-MgApplication -ApplicationId $app.Id -KeyCredentials @(
        @{
            Type        = 'AsymmetricX509Cert'
            Usage       = 'Verify'
            DisplayName = 'entra-secret-monitor'
            Key         = [Convert]::FromBase64String($base64)
        }
    )
    $credentialLines = @(
        "${prefix}_CERT_PATH=/config/$TenantKey.crt",
        "${prefix}_KEY_PATH=/config/$TenantKey.key"
    )
} else {
    Write-Host "== Creating client secret ($SecretMonths months) ==" -ForegroundColor Cyan
    $pw = Add-MgApplicationPassword -ApplicationId $app.Id -PasswordCredential @{
        displayName = 'entra-secret-monitor'
        endDateTime = (Get-Date).AddMonths($SecretMonths)
    }
    Write-Host ("   Expires on {0:yyyy-MM-dd}" -f $pw.EndDateTime)
    Write-Warning 'The secret value is shown once and cannot be retrieved again.'
    $credentialLines = @("${prefix}_CLIENT_SECRET=$($pw.SecretText)")
}

# --- Output ----------------------------------------------------------------

$block = @(
    "# entra-secret-monitor - $DisplayName",
    "# Tenant $TenantId, created $(Get-Date -Format 'yyyy-MM-dd')",
    "TENANTS=$TenantKey",
    "${prefix}_DISPLAY_NAME=$DisplayName",
    "${prefix}_TENANT_ID=$TenantId",
    "${prefix}_CLIENT_ID=$($app.AppId)"
) + $credentialLines + @(
    "${prefix}_WARN_DAYS=30",
    "${prefix}_ERROR_DAYS=14"
)

Write-Host ''
Write-Host '== Configuration block ==' -ForegroundColor Green
$block | ForEach-Object { Write-Host "   $_" }

if ($OutFile) {
    $block -join "`n" | Set-Content -LiteralPath $OutFile -Encoding utf8NoBOM
    Write-Host ''
    Write-Host "Written to $OutFile" -ForegroundColor Green
    Write-Warning 'This file contains a credential. Restrict its permissions and delete it once deployed.'
}

if ($generated) {
    Write-Host ''
    Write-Host 'Copy both files to the config directory of the monitoring host:' -ForegroundColor Cyan
    Write-Host ("   {0}  ->  /config/{1}.crt" -f $generated.CertPath, $TenantKey)
    Write-Host ("   {0}  ->  /config/{1}.key" -f $generated.KeyPath, $TenantKey)
    Write-Warning 'The private key is not stored anywhere else. Lose it and you create a new one.'
}

Write-Host ''
Write-Host 'Verify from the monitoring host:' -ForegroundColor Cyan
Write-Host "   docker run --rm --env-file <envfile> -v ./config:/config:ro ghcr.io/benjaminmue/entra-secret-monitor:latest /app/cli.py --tenant $TenantKey --format text"
Write-Host ''
Write-Host 'Consent can take a minute to replicate. A 403 on the first try is normal.' -ForegroundColor DarkGray
