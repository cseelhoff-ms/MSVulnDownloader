# if not logged in, login
if ($null -eq (az account show)) {az login}

$app_name="vulnerability_downloader"
$https_api_securitycenter_microsoft_com="fc780465-2017-40d4-a0c5-307022471b92"
$Machine_Read_All = "ea8291d3-4b9a-44b5-bc3a-6cea3026dc79"
$api_permissions = $Machine_Read_All + "=Scope"
#$defaultSubscriptionID = az account show --query id -o tsv
#$subscriptions = @($defaultSubscriptionID)
$scope = 'https://api.securitycenter.microsoft.com/.default'

# get tenant id
Write-Host "Getting tenant id"
$tenantID = az account show --query tenantId -o tsv

#get app id of the app if it already exists
Write-Host "Getting app id"
$clientId = az ad app list --display-name $app_name --query [].appId -o tsv

#create the app if it doesn't exist
if ($null -eq $clientId) {
    write-host "Creating app"
    $clientId = az ad app create --display-name $app_name --query appId -o tsv
}

# add permission if the app doesn't have https://management.azure.com/ user_impersonation
Write-Host "Getting permission"
$permission_exists = az ad app permission list --id $clientId --query [].resourceAppId -o tsv | Select-String -Pattern $https_api_securitycenter_microsoft_com
if ($null -eq $permission_exists) {
    write-host "Adding permission"
    az ad app permission add --id $clientId --api $https_api_securitycenter_microsoft_com --api-permissions $api_permissions
    az ad app permission grant --id $clientId --api $https_api_securitycenter_microsoft_com --scope $scope
}

#check if isFallbackPublicClient is set to true
Write-Host "Checking if isFallbackPublicClient is set to true"
$isFallbackPublicClient = az ad app list --id $clientId --query [].isFallbackPublicClient -o tsv

#Allow public client flows - Enable the following mobile and desktop flows
if($isFallbackPublicClient -eq "false") {
    Write-Host "Allowing public client flows"
    az ad app update --id $clientId --set isFallbackPublicClient=true
}

# grant admin consent to reduce the need for all users to consent
#az ad app permission admin-consent --id $app_id

function Get-RefreshedAccessToken {
    param(
        [Parameter(Mandatory=$true)]
        [string]$clientId,
        [Parameter(Mandatory=$true)]
        [string]$tenantId,
        [Parameter(Mandatory=$true)]
        [string]$scope,        
        [Parameter(Mandatory=$false)]
        [string]$tokenJson
    )
    if($null -eq $tokenJson -or $tokenJson -eq "") {   
        Write-Host "Getting new token"         
        $bodyDeviceCode = (
            "client_id=$clientId" +
            "&scope=$scope"
        )
        $deviceCodeResponse = Invoke-RestMethod -Method Post -Uri "https://login.microsoftonline.com/$tenantId/oauth2/v2.0/devicecode" -Body $bodyDeviceCode
        Write-Host($deviceCodeResponse.message)
        $bodyToken = (
            "tenant=$tenantId" +
            "&grant_type=urn:ietf:params:oauth:grant-type:device_code" +
            "&client_id=$clientId" +
            "&device_code=$($deviceCodeResponse.device_code)"
        )
        $expires_in = $deviceCodeResponse.expires_in
        while($expires_in -gt 0) {
            Start-Sleep -Seconds $deviceCodeResponse.interval
            $expires_in -= $deviceCodeResponse.interval
            try {
                $tokenJson = Invoke-WebRequest -Method Post -Uri "https://login.microsoftonline.com/$tenantId/oauth2/v2.0/token" -Body $bodyToken
                break
            } catch {
                $errorDetails = $_.ErrorDetails
                $errorMessage = $errorDetails.Message | ConvertFrom-Json | Select-Object -ExpandProperty error
                if($errorMessage -eq "authorization_pending") {
                    Write-Host "authorization_pending"
                    continue
                } else {
                    Write-Error $errorDetails.Message
                    exit
                }
            }
        }
        return $tokenJson
    }
    # if the token is expiring soon, refresh it
    $token = $tokenJson | ConvertFrom-Json
    $accessToken = $token.access_token
    $tokenheader = $accessToken.Split(".")[0].Replace('-', '+').Replace('_', '/')
    $tokenheader = $accessToken.Split(".")[0].Replace('-', '+').Replace('_', '/')
    while ($tokenheader.Length % 4) { Write-Verbose "Invalid length for a Base-64 char array or string, adding ="; $tokenheader += "=" }
    $tokenPayload = $accessToken.Split(".")[1].Replace('-', '+').Replace('_', '/')
    while ($tokenPayload.Length % 4) { Write-Verbose "Invalid length for a Base-64 char array or string, adding ="; $tokenPayload += "=" }
    $tokenByteArray = [System.Convert]::FromBase64String($tokenPayload)
    $tokenArrayJson = [System.Text.Encoding]::ASCII.GetString($tokenByteArray)
    $tokenArrayObject = $tokenArrayJson | ConvertFrom-Json
    if($tokenArrayObject.exp -lt ((New-TimeSpan -Start (Get-Date '1970-01-01 00:00:00') -End ((Get-Date).ToUniversalTime())).TotalSeconds) + 600) {
        Write-Host "Refreshing access token"
        $bodyToken = (
            "tenant=$tenantId" +
            "&grant_type=refresh_token" +
            "&client_id=$clientId" +
            "&refresh_token=$($token.refreshToken)" +
            "&scope=$scope"
        )
        $tokenJson = Invoke-WebRequest -Method Post -Uri "https://login.microsoftonline.com/$tenantId/oauth2/v2.0/token" -Body $bodyToken
    }
    return $tokenJson
}
$tokenJson = Get-RefreshedAccessToken -clientId $clientId -tenantId $tenantId -scope $scope -tokenJson $tokenJson
$token = $tokenJson | ConvertFrom-Json
$headers = @{"Authorization" = "Bearer $($token.access_token)"}

$machines = Invoke-RestMethod -Method Get -Uri 'https://api.securitycenter.microsoft.com/api/machines' -Headers $headers | Select-Object -ExpandProperty value

$machines2 = New-Object System.Collections.ArrayList
$machines2.AddRange($machines)
# all machine vulns (only CVEs)
$machinesVulnerabilities = Invoke-RestMethod -Method Get -Uri 'https://api.securitycenter.microsoft.com/api/vulnerabilities/machinesVulnerabilities' -Headers $headers | Select-Object -ExpandProperty value
$machineIds = $machinesVulnerabilities.machineId | Select-Object -Unique

foreach($machineId in $machineIds) {
    if($machines2.id -contains $machineId) {
        continue
    }
    
    try {
        $machine = Invoke-RestMethod -Method Get -Uri "https://api.securitycenter.microsoft.com/api/machines/$($machineId)" -Headers $headers
    } catch {
        $errorDetails = $_.ErrorDetails
        $errorCode = $errorDetails.Message | ConvertFrom-Json | Select-Object -ExpandProperty error | Select-Object -ExpandProperty code
        if($errorCode -eq "ResourceNotFound") {
            Write-Host ($errorDetails.Message | ConvertFrom-Json | Select-Object -ExpandProperty error | Select-Object -ExpandProperty message) -ForegroundColor Red
            continue
        } else {
            Write-Error $errorDetails.Message
            exit
        }
    }  
    $null = $machines2.Add($machine)
}
$vulndictionaryName = "vulnerabilityDetailsDictionary.json"
if (Test-Path $vulndictionaryName) {
    $vulnerabilityDetailsDictionary = Get-Content $vulndictionaryName | ConvertFrom-Json
} else {
    #CVE Details (and exposed machine count)
    #save the vulnerabilities to a variable for each download links using odata.nextLink
    $uri = 'https://api.securitycenter.microsoft.com/api/vulnerabilities'
    $vulnerabilityDetails = New-Object System.Collections.ArrayList
    while($null -ne $uri) {
        Write-Host $uri
        $vulnerabilityDetailsPage = Invoke-RestMethod -Uri $uri -Method Get -Headers $headers
        $vulnerabilityDetailsList = $vulnerabilityDetailsPage | Select-Object -ExpandProperty value
        $vulnerabilityDetails.AddRange($vulnerabilityDetailsList)
        $uri = $vulnerabilityDetailsPage.'@odata.nextLink'
    }
    #create a dictionary of the vulnerability details for faster lookup
    $vulnerabilityDetailsDictionary = @{}
    foreach($vulnerabilityDetail in $vulnerabilityDetails) {
        $vulnerabilityDetailsDictionary.Add($vulnerabilityDetail.id, $vulnerabilityDetail)
    }
    #export $vulnerabilityDetailsDictionary to a json file for later use
    $vulnerabilityDetailsDictionary | ConvertTo-Json | Out-File $vulndictionaryName
}

#create a blank arraylist for the results
$machineRecommendationList = New-Object System.Collections.ArrayList

#loop through each machine in $machines and output a progress bar. Use measure-object to get the total count of machines
$machinesCount = $machines2.Count
for($i = 0; $i -lt $machinesCount; $i++) {
    $machine = $machines2[$i]
    #format percentcomplete string to always be 3 characters long
    $percentComplete = "{0:N0}" -f ((($i + 1) * 100) / $machinesCount)
    Write-Progress -Activity "Getting machine recommendations" -Status "($($percentComplete)% $($machine.computerDnsName)" -PercentComplete $percentComplete
    $machineRecommendations = Invoke-RestMethod -Method Get -Uri "https://api.securitycenter.microsoft.com/api/machines/$($machine.id)/recommendations" -Headers $headers | Select-Object -ExpandProperty value
    foreach($machineRecommendation in $machineRecommendations) {
        $matchingMachineVulnerabilities = $machinesVulnerabilities | Where-Object {$_.productName -eq $machineRecommendation.productName -and $_.machineId -eq $machine.id}
        
        foreach($member in $machine.PSObject.Properties) {
            if($machineRecommendation.PSObject.Properties.Name -notcontains $member.Name) {
                $machineRecommendation | Add-Member -MemberType NoteProperty -Name $member.Name -Value $member.Value
            }
        }

        #if there are no matching machine vulnerabilities (i.e. this is a ASR/secure configuration recommendation) then add the machine recommendation to the list and continue
        if($matchingMachineVulnerabilities.Count -eq 0) {
            $null = $machineRecommendationList.Add($machineRecommendation)
            continue
        }

        #if there are matching machine vulnerabilities, add the machine recommendation to the list for each matching machine vulnerability
        foreach($machineVulnerability in $matchingMachineVulnerabilities) {
            $cveId = $machineVulnerability.cveId
            if($null -eq $cveId) {
                continue
            }
            if(!$vulnerabilityDetailsDictionary.ContainsKey($cveId)) {
                continue
            }
            $vulnerabilityDetail = $vulnerabilityDetailsDictionary[$cveId]
            $machineRecommendationCopy = $machineRecommendation | Select-Object *
            foreach($member in $vulnerabilityDetail.PSObject.Properties) {
                if($machineRecommendationCopy.PSObject.Properties.Name -notcontains $member.Name) {
                    $machineRecommendationCopy | Add-Member -MemberType NoteProperty -Name $member.Name -Value $member.Value
                }                
            }
            foreach($member in $machineVulnerability.PSObject.Properties) {
                if($machineRecommendationCopy.PSObject.Properties.Name -notcontains $member.Name) {
                    $machineRecommendationCopy | Add-Member -MemberType NoteProperty -Name $member.Name -Value $member.Value
                }
            }
            $null = $machineRecommendationList.Add($machineRecommendationCopy)
        }
    }
}

# create a new empty hashset to store a list of all of the possible column names
$machineRecommendationListHashSet = New-Object System.Collections.Generic.HashSet[string]
#loop through every item in machineRecommendationList and add the column name to the Hashset
foreach($machineRecommendation in $machineRecommendationList) {
    foreach($member in $machineRecommendation.PSObject.Properties) {
        $null = $machineRecommendationListHashSet.Add($member.Name)
    }
}

#loop through every item in in machineRecommendationList and add any missing columns to the object and set them to blank
foreach($machineRecommendation in $machineRecommendationList) {
    foreach($member in $machineRecommendationListHashSet) {
        if($machineRecommendation.PSObject.Properties.Name -notcontains $member) {
            $machineRecommendation | Add-Member -MemberType NoteProperty -Name $member -Value ""
        }
    }
}

# fix the machineRecommendationList so object members with values of System.Object[] display correctly in the csv
foreach($machineRecommendation in $machineRecommendationList) {
    foreach($member in $machineRecommendation.PSObject.Properties) {
        if($member.Value -is [System.Object[]]) {
            $machineRecommendation.$($member.Name) = $member.Value -join ";"
        }
    }
}

$machineRecommendationList | Export-Csv -Path "machineRecommendationList.csv" -NoTypeInformation
