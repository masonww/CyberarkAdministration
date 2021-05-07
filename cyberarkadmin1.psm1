function get-caWMToken {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory=$true)]
        [string]$PVWAhostName,
        [Parameter(Mandatory=$true)]
        [Validateset("Cyberark","Windows","LDAP","RADIUS")]
        $AuthMethod,
        [PSCredential]$cred = $(Get-Credential)
    )

    $uri = "$PVWAhostName/PasswordVault/API/auth/$authmethod/Logon"
    <#
    for radius password is RSA token number
    #>
    $authBody = @{username=$Cred.UserName;password=$Cred.GetNetworkCredential().Password} |  ConvertTo-Json | % { [System.Text.RegularExpressions.Regex]::Unescape($_) } 
    Write-Verbose $authBody
    try {
        Write-Verbose "Logging into REST API"
        $logonResult = Invoke-RestMethod -Method Post -Uri $uri -ContentType "application/json" -Body $authBody
        $script:loginparams=@{
            token=$logonResult
            PVWAhostName=$PVWAhostName 
        }
        #write-output $loginparams
    }
    catch {
        Write-Error  $psitem
        }
}


function New-CyberarkConnection{
param(
    [Parameter(Mandatory=$true)]
    [Validateset("Cyberark","LDAP","RADIUS")]
    $AuthMethod,
    [Parameter(Mandatory=$true)]
    [validateset("mdl","prod")]
    $environment
)
    $script:authM=$authmethod
    $script:CAENV=$environment
    if($environment -eq "mdl"){$PVWAHost = "https://mdl.pmvault.newyorklife.com"}
    if($environment -eq "prod"){$PVWAHost = "https://pmvault.newyorklife.com"}
    get-caWMToken -PVWAhostName $PVWAHost -AuthMethod $AuthMethod
}

function Handle-error{
param(
    $errormessage
)
    if($errormessage -like "*The session token is missing*")
    {
        New-CyberarkConnection -AuthMethod $authm -environment $caenv
    }
    else{write-error $errormessage}

}

function get-caAccountsByKeyword{
    [CmdletBinding()]
    param(
    $token="$($loginparams.token)",
    $PVWAhostName="$($loginparams.pvwahostname)",
    $keyword
    )
    begin{
        $header=@{ Authorization = $token }
        try{
        $uri = "$PVWAhostName/PasswordVault/api/ComponentsMonitoringDetails/pvwa"
        $test = Invoke-RestMethod -Method GET -Uri $uri -Headers $header -ContentType "application/json" -Body $body -TimeoutSec 300
        }catch{
            Handle-error $PSItem
        }
        $returnlist=$null
    }
    process{
        $uri = "$PVWAhostName/PasswordVault/api/accounts?search=$keyword&limit=1000"
        try {
        do{
            $details=$null
            $details = Invoke-RestMethod -Method GET -Uri $uri -Headers $header -ContentType "application/json" -TimeoutSec 10000
            $returnlist+=$details.value
            $nextlink=$details.nextlink
            $uri="$PVWAhostName/PasswordVault/$nextlink"
            }until([string]::IsNullOrWhiteSpace($nextlink))
            write-output $returnlist
        }catch {
            Handle-error $PSItem
        }
    }
}

function get-caAccountsBySafe{
param(
$token="$($loginparams.token)",
$PVWAhostName="$($loginparams.pvwahostname)",
$safename
)
    begin{
        $header=@{ Authorization = $token }
        try{
        $uri = "$PVWAhostName/PasswordVault/api/ComponentsMonitoringDetails/pvwa"
        $test = Invoke-RestMethod -Method GET -Uri $uri -Headers $header -ContentType "application/json" -Body $body -TimeoutSec 300
        }catch{
            Handle-error $PSItem
        }
        $returnlist=$null
    }
    Process{
        $uri = "$PVWAhostName/PasswordVault/api/accounts?limit=1000"; $body = @{filter='safeName eq '+$safename}
        $response=$null
        try{
        do{
            $details=$null
            $details = Invoke-RestMethod -Method GET -Uri $uri -Headers $header -Body $body -ContentType "application/json" -TimeoutSec 10000
            $response+=$details.value
            $nextlink=$details.nextlink
            $uri="$PVWAhostName/PasswordVault/$nextlink"
        }until([string]::IsNullOrWhiteSpace($nextlink))
        Write-Output $response
        }catch{
            Handle-error $PSItem
        }
    }
}

