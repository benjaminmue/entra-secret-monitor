#Requires -Version 5.1
<#
.SYNOPSIS
    PRTG EXE/Script Advanced sensor: remaining runtime of Entra ID app
    registration secrets and certificates of one tenant.

.DESCRIPTION
    Acquires an app-only Microsoft Graph token, reads the credentials of all
    app registrations (optionally of service principals as well) and returns
    PRTG XML: three summary channels plus one channel per app.

    Channel names, units and limits are identical to the ones the
    entra-secret-monitor container produces, so a sensor can be moved from the
    container to this script and keeps its history.

    Meant to run on the central PRTG instance, not on a probe at the customer
    site: Entra ID and Graph are public endpoints, so the sensor needs outbound
    TCP 443 to login.microsoftonline.com and graph.microsoft.com and nothing
    else. No customer network, no tunnel, no agent. A tenant whose customer has
    no probe server of its own is monitored exactly like every other one.

    Windows PowerShell 5.1, no modules, no dependencies. The probe service is a
    32 bit process on the core server as well and starts the 32 bit PowerShell,
    everything used here works in both bitnesses.

    Graph permission required: Application.Read.All (application permission,
    admin consent). Graph never returns secret values, only metadata.

.PARAMETER TenantId
    Directory (tenant) ID or a verified domain of the tenant.
    Falls back to prtg_scriptplaceholder1, then to prtg_windowsdomain.

.PARAMETER ClientId
    Application (client) ID of the monitoring app registration.
    Falls back to prtg_scriptplaceholder2, then to prtg_windowsuser.

.PARAMETER ClientSecret
    Client secret of the monitoring app registration.
    Falls back to prtg_scriptplaceholder3, then to prtg_windowspassword.

    The three values belong into Credentials for Script Sensors of the device
    (placeholder 1 to 3), which inherit from group and probe and which PRTG
    hides in the settings and in the sensor log. They have to be handed over as
    parameters: measured on PRTG 26.3, "Set placeholders as environment values"
    exports the Windows, Linux and SNMP credentials but not the script
    placeholders.

    Whoever wants the secret out of the command line has two options: a
    certificate, or the Windows credentials of the device, which do arrive in
    the environment.

.PARAMETER ShowEnvironmentNames
    Diagnostic switch: instead of scanning, report the names of the prtg_*
    environment variables the probe actually provides. Values are never
    printed. Use it once to confirm how the placeholders of Credentials for
    Script Sensors are named on this PRTG version.

.PARAMETER CertificateThumbprint
    Thumbprint of a certificate in LocalMachine\My or CurrentUser\My of the PRTG
    instance whose private key is readable by the PRTG service account. Takes
    precedence over ClientSecret and is the recommended way on an instance that
    serves several customers: the sensor parameters then hold no secret at all,
    and unlike a client secret a certificate is not capped at 24 months.

.PARAMETER WarnDays
    Remaining days below which a channel turns yellow. Default 30.

.PARAMETER ErrorDays
    Remaining days below which a channel turns red. Default 14.

.PARAMETER IncludeServicePrincipals
    Also read service principals, which covers enterprise applications and
    SAML signing certificates. Off by default, it multiplies the channel count.

.PARAMETER ShowExpired
    Keep already expired credentials as channels. Off by default, an expired
    credential that nobody removed would keep the sensor red forever.

.PARAMETER Filter
    Only apps whose display name contains this string (case insensitive).

.PARAMETER Exclude
    Comma separated list of substrings; matching apps are dropped.
    Wins over Filter.

.PARAMETER MaxChannels
    Maximum number of app channels. PRTG allows 50 channels per sensor and
    three of them are the summary, so the value is capped at 47. Default 40.

.PARAMETER Proxy
    HTTP proxy for the token endpoint and Graph, for example http://proxy:8080.

.PARAMETER TimeoutSec
    Timeout per HTTP request. Default 60.

.EXAMPLE
    Credentials for Script Sensors on the device, "Set placeholders as
    environment values" enabled. No credential ends up on a command line:

    -WarnDays 45 -ErrorDays 21

.EXAMPLE
    Same credentials, handed over as parameters instead:

    -TenantId "%scriptplaceholder1" -ClientId "%scriptplaceholder2" -ClientSecret "%scriptplaceholder3"

.EXAMPLE
    Certificate instead of a client secret:

    -TenantId "%scriptplaceholder1" -ClientId "%scriptplaceholder2" -CertificateThumbprint "A1B2C3"

.NOTES
    Author : MTF Solutions AG
    Project: https://github.com/benjaminmue/entra-secret-monitor
    Install: copy to the PRTG instance, folder
             C:\Program Files (x86)\PRTG Network Monitor\Custom Sensors\EXEXML\
             See docs/PRTG-SENSOR.md
#>

[CmdletBinding()]
param(
    [string]$TenantId = "",
    [string]$ClientId = "",
    [string]$ClientSecret = "",
    [string]$CertificateThumbprint = "",
    [int]$WarnDays = 30,
    [int]$ErrorDays = 14,
    [switch]$IncludeServicePrincipals,
    [switch]$ShowExpired,
    [string]$Filter = "",
    [string]$Exclude = "",
    [int]$MaxChannels = 40,
    [string]$Proxy = "",
    [int]$TimeoutSec = 60,
    [switch]$ShowEnvironmentNames
)

$ErrorActionPreference = "Stop"

# PRTG reads the raw stdout bytes and the XML declares UTF-8. Without this the
# console encoding of the probe service would decide how umlauts arrive.
try { [Console]::OutputEncoding = New-Object System.Text.UTF8Encoding($false) } catch { }

# Windows PowerShell 5.1 still negotiates TLS 1.0 first on some builds; login
# and Graph refuse anything below 1.2.
try {
    [Net.ServicePointManager]::SecurityProtocol =
        [Net.ServicePointManager]::SecurityProtocol -bor [Net.SecurityProtocolType]::Tls12
} catch { }

$GraphBase   = "https://graph.microsoft.com/v1.0"
$GraphScope  = "https://graph.microsoft.com/.default"
$SelectField = 'id,appId,displayName,passwordCredentials,keyCredentials'

# PRTG allows 50 channels per sensor, three of them are the summary.
$ChannelHardLimit = 47


# --------------------------------------------------------------------------
# Output helpers
# --------------------------------------------------------------------------

function ConvertTo-Base64Url {
    <#
        .SYNOPSIS
        Encode bytes as base64url without padding, the encoding JWT uses.
    #>
    param([byte[]]$Bytes)
    return [Convert]::ToBase64String($Bytes).TrimEnd('=').Replace('+', '-').Replace('/', '_')
}

function Get-XmlText {
    <#
        .SYNOPSIS
        Escape a value for XML and drop characters XML 1.0 cannot represent.

        .DESCRIPTION
        A display name coming from Graph may contain control characters.
        Escaping alone would leave PRTG with a document it cannot parse.
    #>
    param([string]$Value)
    if ($null -eq $Value) { return "" }
    $clean = New-Object System.Text.StringBuilder
    foreach ($ch in $Value.ToCharArray()) {
        $code = [int]$ch
        if (($code -ge 32 -and $code -ne 127) -or $code -eq 9 -or $code -eq 10 -or $code -eq 13) {
            [void]$clean.Append($ch)
        }
    }
    return $clean.ToString().Replace('&', '&amp;').Replace('<', '&lt;').Replace('>', '&gt;').Replace('"', '&quot;')
}

function Write-PrtgError {
    <#
        .SYNOPSIS
        Emit a PRTG error document and end the run.

        .DESCRIPTION
        The sensor has to turn red with a readable reason instead of failing
        silently or returning a document PRTG rejects as invalid XML. The exit
        code stays 0 on purpose: PRTG reads the error element, a non zero exit
        code would replace the message with a generic one.
    #>
    param([string]$Message)
    $text = Get-XmlText ([string]$Message)
    if ($text.Length -gt 2000) { $text = $text.Substring(0, 2000) }
    Write-Output '<?xml version="1.0" encoding="UTF-8" ?>'
    Write-Output '<prtg>'
    Write-Output '  <error>1</error>'
    Write-Output ("  <text>{0}</text>" -f $text)
    Write-Output '</prtg>'
    exit 0
}


# --------------------------------------------------------------------------
# HTTP
# --------------------------------------------------------------------------

function Invoke-Http {
    <#
        .SYNOPSIS
        Wrap Invoke-RestMethod with the proxy settings and a readable error.

        .DESCRIPTION
        Entra answers with a JSON body that names the actual problem
        (AADSTS7000215 wrong secret, AADSTS700027 wrong certificate and so on).
        Invoke-RestMethod throws that body away, so it is read back from the
        response stream here.
    #>
    param(
        [string]$Method,
        [string]$Uri,
        $Body,
        [string]$ContentType,
        [hashtable]$Headers
    )

    $call = @{
        Method      = $Method
        Uri         = $Uri
        TimeoutSec  = $TimeoutSec
        ErrorAction = "Stop"
    }
    if ($Body)        { $call["Body"] = $Body }
    if ($ContentType) { $call["ContentType"] = $ContentType }
    if ($Headers)     { $call["Headers"] = $Headers }
    if ($Proxy) {
        $call["Proxy"] = $Proxy
        $call["ProxyUseDefaultCredentials"] = $true
    }

    try {
        return Invoke-RestMethod @call
    }
    catch {
        # Windows PowerShell hands the response body over in ErrorDetails and has
        # usually consumed the stream already; PowerShell 7 throws a different
        # exception type altogether. Both are covered here, the stream is only
        # the fallback.
        $status = ""
        $detail = ""
        if ($_.ErrorDetails -and $_.ErrorDetails.Message) { $detail = $_.ErrorDetails.Message }

        $response = $null
        try { $response = $_.Exception.Response } catch { }
        if ($response) {
            try { $status = [int]$response.StatusCode } catch { }
            if (-not $detail) {
                try {
                    $stream = $response.GetResponseStream()
                    if ($stream -and $stream.CanRead) {
                        if ($stream.CanSeek) { $stream.Position = 0 }
                        $reader = New-Object System.IO.StreamReader($stream)
                        $detail = $reader.ReadToEnd()
                        $reader.Close()
                    }
                } catch { }
            }
        }

        if (-not $detail) { $detail = $_.Exception.Message }
        # The error body of Entra is JSON across several lines and the sensor
        # message is a single line.
        $detail = ($detail -replace '\s+', ' ').Trim()
        if ($detail.Length -gt 400) { $detail = $detail.Substring(0, 400) }
        throw ("HTTP {0} auf {1}: {2}" -f $status, ($Uri -split '\?')[0], $detail)
    }
}


# --------------------------------------------------------------------------
# Authentication
# --------------------------------------------------------------------------

function Get-SigningCertificate {
    <#
        .SYNOPSIS
        Find the certificate by thumbprint in the machine or user store.

        .DESCRIPTION
        LocalMachine first: the probe runs as a service account and that is
        where a deployed monitoring certificate belongs. CurrentUser is the
        fallback for testing a sensor by hand.
    #>
    param([string]$Thumbprint)

    $clean = ($Thumbprint -replace '[^0-9A-Fa-f]', '').ToUpper()
    if ($clean.Length -ne 40) {
        throw "CertificateThumbprint ist kein SHA1-Fingerabdruck (40 Hex-Zeichen): $Thumbprint"
    }

    foreach ($store in @("Cert:\LocalMachine\My", "Cert:\CurrentUser\My")) {
        $cert = Get-ChildItem -Path $store -ErrorAction SilentlyContinue |
                Where-Object { $_.Thumbprint -eq $clean } | Select-Object -First 1
        if ($cert) {
            if (-not $cert.HasPrivateKey) {
                throw "Zertifikat $clean in $store hat keinen privaten Schluessel"
            }
            return $cert
        }
    }
    throw (("Zertifikat {0} weder in LocalMachine\My noch in CurrentUser\My gefunden. " +
            "Das Dienstkonto von PRTG braucht Leserecht auf den privaten Schluessel.") -f $clean)
}

function New-ClientAssertion {
    <#
        .SYNOPSIS
        Build the signed JWT that replaces the client secret.

        .DESCRIPTION
        RS256 over header and claims, x5t carries the SHA1 hash of the
        certificate so Entra can pick the matching public key of the app
        registration.
    #>
    param(
        [string]$Tenant,
        [string]$Client,
        [System.Security.Cryptography.X509Certificates.X509Certificate2]$Certificate
    )

    $now = [DateTimeOffset]::UtcNow.ToUnixTimeSeconds()
    $header = @{
        alg = "RS256"
        typ = "JWT"
        x5t = ConvertTo-Base64Url $Certificate.GetCertHash()
    }
    $claims = @{
        aud = "https://login.microsoftonline.com/$Tenant/oauth2/v2.0/token"
        iss = $Client
        sub = $Client
        jti = [guid]::NewGuid().ToString()
        nbf = $now - 60
        exp = $now + 600
    }

    $encode = {
        param($obj)
        ConvertTo-Base64Url ([Text.Encoding]::UTF8.GetBytes((ConvertTo-Json $obj -Compress)))
    }
    $signingInput = "{0}.{1}" -f (& $encode $header), (& $encode $claims)

    $rsa = [System.Security.Cryptography.X509Certificates.RSACertificateExtensions]::GetRSAPrivateKey($Certificate)
    if (-not $rsa) {
        throw "Privater Schluessel des Zertifikats ist nicht als RSA nutzbar (CNG-Rechte pruefen)"
    }
    $signature = $rsa.SignData(
        [Text.Encoding]::UTF8.GetBytes($signingInput),
        [System.Security.Cryptography.HashAlgorithmName]::SHA256,
        [System.Security.Cryptography.RSASignaturePadding]::Pkcs1)

    return "{0}.{1}" -f $signingInput, (ConvertTo-Base64Url $signature)
}

function Get-GraphToken {
    <#
        .SYNOPSIS
        Acquire an app-only Graph token, certificate first, secret as fallback.
    #>
    param(
        [string]$Tenant,
        [string]$Client,
        [string]$Secret,
        [string]$Thumbprint
    )

    $url = "https://login.microsoftonline.com/$Tenant/oauth2/v2.0/token"
    if ($Thumbprint) {
        $assertion = New-ClientAssertion -Tenant $Tenant -Client $Client `
                        -Certificate (Get-SigningCertificate -Thumbprint $Thumbprint)
        $body = @{
            client_id             = $Client
            client_assertion_type = "urn:ietf:params:oauth:client-assertion-type:jwt-bearer"
            client_assertion      = $assertion
            scope                 = $GraphScope
            grant_type            = "client_credentials"
        }
    }
    else {
        $body = @{
            client_id     = $Client
            client_secret = $Secret
            scope         = $GraphScope
            grant_type    = "client_credentials"
        }
    }

    $payload = Invoke-Http -Method Post -Uri $url -Body $body `
                   -ContentType "application/x-www-form-urlencoded"
    if (-not $payload.access_token) {
        throw "Token-Antwort ohne access_token"
    }
    return $payload.access_token
}


# --------------------------------------------------------------------------
# Graph
# --------------------------------------------------------------------------

function Get-GraphCollection {
    <#
        .SYNOPSIS
        Follow @odata.nextLink and return all items of a Graph collection.
    #>
    param([string]$Token, [string]$Path)

    $items = @()
    $url = $GraphBase + $Path
    $headers = @{ Authorization = "Bearer $Token"; Accept = "application/json" }
    while ($url) {
        $payload = Invoke-Http -Method Get -Uri $url -Headers $headers
        if ($payload.value) { $items += $payload.value }
        $url = $payload.'@odata.nextLink'
    }
    return $items
}

function Get-CredentialList {
    <#
        .SYNOPSIS
        Flatten app registrations and service principals into single credentials.

        .DESCRIPTION
        One entry per secret and per certificate with the remaining runtime in
        whole days. Credentials without an end date cannot expire and are skipped.
    #>
    param([string]$Token, [bool]$WithServicePrincipals)

    $objects = @()
    foreach ($app in (Get-GraphCollection -Token $Token -Path ('/applications?$select=' + $SelectField + '&$top=999'))) {
        $objects += [pscustomobject]@{ ObjectType = "application"; Object = $app }
    }
    if ($WithServicePrincipals) {
        foreach ($sp in (Get-GraphCollection -Token $Token -Path ('/servicePrincipals?$select=' + $SelectField + '&$top=999'))) {
            $objects += [pscustomobject]@{ ObjectType = "servicePrincipal"; Object = $sp }
        }
    }

    $now = (Get-Date).ToUniversalTime()
    $result = @()
    foreach ($entry in $objects) {
        $obj = $entry.Object
        $name = $obj.displayName
        if (-not $name) { $name = $obj.appId }
        if (-not $name) { $name = "?" }

        foreach ($kind in @(
            @{ Type = "secret"; Field = "passwordCredentials" },
            @{ Type = "cert";   Field = "keyCredentials" })) {

            $list = $obj.($kind.Field)
            if (-not $list) { continue }
            foreach ($cred in $list) {
                if (-not $cred.endDateTime) { continue }
                $end = ([datetime]$cred.endDateTime).ToUniversalTime()
                $credName = $cred.displayName
                if (-not $credName) { $credName = "(ohne Name)" }
                $result += [pscustomobject]@{
                    AppName    = [string]$name
                    AppId      = [string]$obj.appId
                    ObjectType = $entry.ObjectType
                    CredType   = $kind.Type
                    CredName   = [string]$credName
                    EndDate    = $end
                    DaysLeft   = [int][math]::Floor(($end - $now).TotalDays)
                }
            }
        }
    }
    return $result
}


# --------------------------------------------------------------------------
# Aggregation
# --------------------------------------------------------------------------

function Get-AppChannels {
    <#
        .SYNOPSIS
        Group credentials per app and type and keep the longest remaining runtime.

        .DESCRIPTION
        A freshly rolled secret makes the old one irrelevant, so the maximum per
        group is the value that actually describes the risk for that app.
        Filter keeps matching apps, Exclude drops them and wins over Filter.
    #>
    param($Credentials)

    $excludes = @()
    foreach ($part in ($Exclude -split ',')) {
        $trimmed = $part.Trim().ToLower()
        if ($trimmed) { $excludes += $trimmed }
    }
    $needle = $Filter.ToLower()

    $groups = @{}
    foreach ($cred in $Credentials) {
        $lower = $cred.AppName.ToLower()
        if ($needle -and $lower -notlike "*$needle*") { continue }
        $skip = $false
        foreach ($ex in $excludes) { if ($lower -like "*$ex*") { $skip = $true; break } }
        if ($skip) { continue }

        $key = "{0}|{1}" -f $cred.AppName, $cred.CredType
        if (-not $groups.ContainsKey($key)) { $groups[$key] = @() }
        $groups[$key] += $cred
    }

    $channels = @()
    foreach ($key in $groups.Keys) {
        $items = @($groups[$key])
        $best = $items | Sort-Object DaysLeft -Descending | Select-Object -First 1
        if ($best.DaysLeft -lt 0 -and -not $ShowExpired) { continue }
        if ($best.CredType -eq "secret") { $label = "Secret" } else { $label = "Zertifikat" }
        # The property is deliberately not called Count: on a result set with a
        # single channel PowerShell resolves $channels.Count to the property of
        # that object instead of the length of the collection.
        $channels += [pscustomobject]@{
            Name      = "{0} ({1})" -f $best.AppName, $label
            Days      = $best.DaysLeft
            Expires   = $best.EndDate.ToString("yyyy-MM-dd")
            CredName  = $best.CredName
            CredCount = $items.Count
        }
    }
    return @($channels | Sort-Object Days)
}


# --------------------------------------------------------------------------
# Rendering
# --------------------------------------------------------------------------

function Write-PrtgResult {
    <#
        .SYNOPSIS
        Render the PRTG document: three summary channels plus one per app.

        .DESCRIPTION
        Channel names, units and limits match the XML of the
        entra-secret-monitor container so both can feed the same sensor.
    #>
    param($Channels)

    # A pipeline that produced a single channel arrives as a bare object, so the
    # collection is rebuilt before anything asks for its length.
    $list = @($Channels)
    $limit = [math]::Min($MaxChannels, $ChannelHardLimit)
    $shown = @($list | Select-Object -First $limit)
    $truncated = $list.Count - $shown.Count

    $minimum = 9999
    if ($list.Count -gt 0) { $minimum = [int]($list | Measure-Object Days -Minimum).Minimum }
    $critical = @($list | Where-Object { $_.Days -ge 0 -and $_.Days -lt $WarnDays }).Count
    $expired  = @($list | Where-Object { $_.Days -lt 0 }).Count

    $out = New-Object System.Collections.Generic.List[string]
    $out.Add('<?xml version="1.0" encoding="UTF-8" ?>')
    $out.Add('<prtg>')

    $emit = {
        param([string]$Name, [int]$Value, [string]$Unit, $MinWarn, $MinErr, $MaxWarn, $MaxErr)
        $out.Add('  <result>')
        $out.Add(('    <channel>{0}</channel>' -f (Get-XmlText $Name)))
        $out.Add(('    <value>{0}</value>' -f $Value))
        $out.Add('    <unit>Custom</unit>')
        $out.Add(('    <customunit>{0}</customunit>' -f (Get-XmlText $Unit)))
        if ($null -ne $MinWarn -or $null -ne $MinErr -or $null -ne $MaxWarn -or $null -ne $MaxErr) {
            $out.Add('    <limitmode>1</limitmode>')
            if ($null -ne $MinWarn) { $out.Add(('    <limitminwarning>{0}</limitminwarning>' -f $MinWarn)) }
            if ($null -ne $MinErr)  { $out.Add(('    <limitminerror>{0}</limitminerror>' -f $MinErr)) }
            if ($null -ne $MaxWarn) { $out.Add(('    <limitmaxwarning>{0}</limitmaxwarning>' -f $MaxWarn)) }
            if ($null -ne $MaxErr)  { $out.Add(('    <limitmaxerror>{0}</limitmaxerror>' -f $MaxErr)) }
        }
        $out.Add('  </result>')
    }

    & $emit "Minimale Restlaufzeit"     $minimum  "Tage"   $WarnDays $ErrorDays $null $null
    & $emit "Kritisch unter Warngrenze" $critical "Anzahl" $null     $null      0     $null
    & $emit "Abgelaufen"                $expired  "Anzahl" $null     $null      $null 0
    foreach ($channel in $shown) {
        & $emit $channel.Name $channel.Days "Tage" $WarnDays $ErrorDays $null $null
    }

    if ($list.Count -gt 0) {
        $worst = $list[0]
        $text = "Kritischster Eintrag: {0} am {1} ({2} Tage)" -f $worst.Name, $worst.Expires, $worst.Days
    }
    else {
        $text = "Keine Credentials gefunden"
    }
    if ($truncated -gt 0) { $text += " | {0} weitere nicht dargestellt" -f $truncated }
    if ($text.Length -gt 2000) { $text = $text.Substring(0, 2000) }

    $out.Add(('  <text>{0}</text>' -f (Get-XmlText $text)))
    $out.Add('</prtg>')
    Write-Output ($out -join [Environment]::NewLine)
}


# --------------------------------------------------------------------------
# Main
# --------------------------------------------------------------------------

try {
    if ($ShowEnvironmentNames) {
        # Names only. The values are credentials and have no business in a
        # sensor message, which PRTG stores and displays.
        $names = @(Get-ChildItem Env: | Where-Object { $_.Name -like "prtg_*" } |
                   Select-Object -ExpandProperty Name | Sort-Object)
        if ($names.Count -eq 0) {
            Write-PrtgError ("Keine prtg_* Umgebungsvariablen. In den Sensoreinstellungen " +
                             "unter Environment 'Set placeholders as environment values' aktivieren.")
        }
        Write-PrtgError ("Verfuegbare Umgebungsvariablen: " + ($names -join ", "))
    }

    # Parameters win, and for Credentials for Script Sensors they are the only
    # way: verified on PRTG 26.3, the probe exports the Windows, Linux and SNMP
    # credentials into the environment but not the script placeholders. The
    # scriptplaceholder fallback below therefore stays empty today and only
    # starts working if Paessler ever adds them.
    #
    # Fallback two, the Windows credentials, is the option that keeps a secret
    # out of the command line: domain, user and password carry tenant, client
    # and secret, and prtg_windowspassword does arrive in the environment.
    if (-not $TenantId) {
        $TenantId = [string]$env:prtg_scriptplaceholder1
        if (-not $TenantId) { $TenantId = [string]$env:prtg_windowsdomain }
    }
    if (-not $ClientId) {
        $ClientId = [string]$env:prtg_scriptplaceholder2
        if (-not $ClientId) { $ClientId = [string]$env:prtg_windowsuser }
    }
    if (-not $ClientSecret) {
        $ClientSecret = [string]$env:prtg_scriptplaceholder3
        if (-not $ClientSecret) { $ClientSecret = [string]$env:prtg_windowspassword }
    }

    $TenantId = $TenantId.Trim()
    $ClientId = $ClientId.Trim()

    # Ohne literalen Platzhalternamen: PRTG loest Platzhalter auch in der
    # Sensormeldung auf und wuerde den Wert damit sichtbar machen.
    $hint = ("Erwartet werden Tenant ID, Client ID und Client Secret. Im Geraet unter " +
             "Credentials for Script Sensors die Platzhalter 1 bis 3 fuellen und sie im " +
             "Sensor unter Parameters an -TenantId, -ClientId und -ClientSecret " +
             "uebergeben. Script-Platzhalter stellt PRTG nicht als Umgebungsvariablen " +
             "bereit, das tut es nur fuer die Windows- und Linux-Credentials.")

    if (-not $TenantId) { throw "Keine Tenant ID. $hint" }
    if (-not $ClientId) { throw "Keine Client ID. $hint" }
    if (-not $CertificateThumbprint -and -not $ClientSecret) {
        throw "Weder -CertificateThumbprint noch ein Client Secret vorhanden. $hint"
    }
    if ($ErrorDays -gt $WarnDays) {
        throw "ErrorDays ($ErrorDays) muss kleiner oder gleich WarnDays ($WarnDays) sein"
    }

    $token = Get-GraphToken -Tenant $TenantId -Client $ClientId `
                -Secret $ClientSecret -Thumbprint $CertificateThumbprint
    $credentials = Get-CredentialList -Token $token `
                       -WithServicePrincipals ([bool]$IncludeServicePrincipals)
    Write-PrtgResult -Channels (Get-AppChannels -Credentials $credentials)
    exit 0
}
catch {
    Write-PrtgError $_.Exception.Message
}
