# if not logged in, login
if ($null -eq (az account show)) {az login}

$app_name="vulnerability_downloader"
$https_management_azure_com="797f4846-ba00-4fd7-ba43-dac1f8f63013"
$user_impersonation = "41094075-9dad-400e-a0bd-54e686782033"
$api_permissions = $user_impersonation + "=Scope"
$defaultSubscriptionID = az account show --query id -o tsv
$subscriptions = @($defaultSubscriptionID)
$scope = 'https://management.azure.com/.default offline_access'

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
$permission_exists = az ad app permission list --id $clientId --query [].resourceAppId -o tsv | Select-String -Pattern $https_management_azure_com
if ($null -eq $permission_exists) {
    write-host "Adding permission"
    az ad app permission add --id $clientId --api $https_management_azure_com --api-permissions $api_permissions
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

# if directory './subassessments' doesn't exist, create it
if(!(Test-Path ./subassessments)) {
    New-Item -ItemType Directory -Path ./subassessments
}

$subAssessmentsCSVname = 'defcloud-subassessments.csv'
# check if $subAssessmentsCSVname exists, if not, create it as a blank file
if(!(Test-Path $subAssessmentsCSVname)) {
    '' | Out-File -FilePath $subAssessmentsCSVname
}

$defcloudSubAssessments = Import-Csv -Path $subAssessmentsCSVname -Delimiter "`t" -Header "nextLink", "subassessmentfileindex"
#create a lookup hashtable for the subassessments from the csv
$subassessmentfileindex = 0
$defcloudSubAssessmentsLookup = @{}
foreach($defcloudSubAssessment in $defcloudSubAssessments) {
    $defcloudSubAssessmentsLookup.Add($defcloudSubAssessment.nextLink, $defcloudSubAssessment.subassessmentfileindex)
    if($defcloudSubAssessment.subassessmentfileindex -gt $subassessmentfileindex) {
        $subassessmentfileindex = $defcloudSubAssessment.subassessmentfileindex
    }
}

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

$assessmentsValue = New-Object System.Collections.ArrayList
foreach($subscription in $subscriptions) { 
    $nextLink = "https://management.azure.com/subscriptions/$($subscription)/providers/Microsoft.Security/assessments?api-version=2020-01-01"
    while($nextLink) {
        Write-Host $nextLink
        $assessmentsResponse = Invoke-WebRequest -Method Get -Uri $nextLink -Headers $headers
        $assessments = $assessmentsResponse.Content | ConvertFrom-Json
        foreach($assessment in $assessments.value.properties) {
            $subAssessmentLink = $assessment.additionaldata.subAssessmentsLink
            if($null -ne $subAssessmentLink -and $subAssessmentLink -ne "") {
                $nextSubLink = "https://management.azure.com$($subAssessmentLink)?api-version=2020-01-01"
                while($nextSubLink) {
                    if($defcloudSubAssessmentsLookup.ContainsKey($nextSubLink)) {
                        Write-Host $nextSubLink -ForegroundColor Green
                        $subassessmentfileindex = $defcloudSubAssessmentsLookup[$nextSubLink]
                        $subassessmentOutputPath = "subassessments/$($subassessmentfileindex.ToString()).json"
                        $subAssessments = Get-Content -Path $subassessmentOutputPath | ConvertFrom-Json
                    } else {
                        Write-Host $nextSubLink -ForegroundColor Yellow
                        $token = Get-RefreshedAccessToken -clientId $clientId -tenantId $tenantId -scope $scope -tokenJson $tokenJson
                        $token = $tokenJson | ConvertFrom-Json
                        $headers = @{"Authorization" = "Bearer $($token.access_token)"}                    
                        #convert $subassessmentfileindex to int
                        $subassessmentfileindex = [int]$subassessmentfileindex + 1
                        $subassessmentOutputPath = "subassessments/$($subassessmentfileindex.ToString()).json"

                        try {
                            $subAssessmentsResponse = Invoke-WebRequest -Method Get -Uri $nextSubLink -Headers $headers
                        } catch {
                            $errorDetails = $_.ErrorDetails
                            $errorCode = $errorDetails.Message | ConvertFrom-Json | Select-Object -ExpandProperty error | Select-Object -ExpandProperty code
                            if($errorCode -eq "ResourceNotFound") {
                                Write-Host "ResourceNotFound" -ForegroundColor Red
                                '' | Out-File -FilePath $subassessmentOutputPath
                                ($nextSubLink + "`t" + $subassessmentfileindex) | Out-File -FilePath "defcloud-subassessments.csv" -Append
                                $nextSubLink = $null
                                continue
                            } else {
                                Write-Error $errorDetails.Message
                                exit
                            }
                        }                        
                        $subAssessmentsResponse.Content | Out-File -FilePath $subassessmentOutputPath
                        ($nextSubLink + "`t" + $subassessmentfileindex) | Out-File -FilePath "defcloud-subassessments.csv" -Append
                        $subAssessments = $subAssessmentsResponse.Content | ConvertFrom-Json
                    }
                    $nextSubLink = $subAssessments.nextLink
                }
            }
        }
        $assessmentsValue.AddRange($assessments.value)
        $nextLink = $assessments.nextLink
    }
}

$outputCSV = 'defcloud.csv'
# delete $outputCSV if it exists
if(Test-Path $outputCSV) {
    write-host "Deleting $outputCSV"
    Remove-Item $outputCSV
}

$assessmentsProperties = $assessmentsValue | Select-Object -Property properties
for($i = 0; $i -lt $assessmentsProperties.Count; $i++) {
    $assessmentProperties = $assessmentsProperties[$i]
    # show a progress bar with percent complete
    Write-Progress -Activity "Processing assessments" -Status "Processing assessment $i of $($assessmentsProperties.Count)" -PercentComplete (($i / $assessmentsProperties.Count) * 100)

    # if the object property of additionaldata is null or empty, add the object to the arraylist
    if($null -eq $assessmentProperties.properties.additionaldata -or $assessmentProperties.properties.additionaldata -eq "") {
        # create a new psobject to store the assessment properties values of resourceDetails.Source, resourceDetails.Id, displayName, status.code, status.cause, status.description
        $flatAssessment = [PSCustomObject]@{
            Source = $assessmentProperties.properties.resourceDetails.Source
            Id = $assessmentProperties.properties.resourceDetails.Id
            displayName = $assessmentProperties.properties.displayName
            code = $assessmentProperties.properties.status.code
            cause = $assessmentProperties.properties.status.cause
            description = $assessmentProperties.properties.status.description            
            additionalData = ''
            subAssessmentRemediation = ''
            subAssessmentImpact = ''
            subAssessmentCategory = ''
            subAssessmentDescription = ''
            subAssessmentTimeGenerated = ''
            subAssessmentResourceDetails = ''
            subAssessmentAdditionalData = ''
            cveTitle = ''
            cveCvssScore = ''
            cveCvssVersion = ''
            cveSeverity = ''
            cveDescription = ''
            cveExploitTypes = ''
            cveExploitUris = ''
            cveExploitabilityLevel = ''
            cveHasPublicExploit = ''
            cveIsExploitVerified = ''
            cveIsExploitInKit = ''
            cveLastModifiedDate = ''
            cvePublishedDate = ''
            cveIsZeroDay = ''
            cveCvssVectorString = ''
        }        
        $flatAssessment | Export-Csv -Path $outputCSV -Append
        continue
    }
    $additionalData = $assessmentProperties.properties.additionaldata
    $subAssessments = $additionalData.subAssessments
    # if subAssessments is null or empty or has zero elements, add the object to the arraylist
    if($null -eq $subAssessments -or $subAssessments -eq "" -or $subAssessments.Count -eq 0) {
        # create a new psobject to store the assessment properties values of resourceDetails.Source, resourceDetails.Id, displayName, status.code, status.cause, status.description
        $flatAssessment = [PSCustomObject]@{
            Source = $assessmentProperties.properties.resourceDetails.Source
            Id = $assessmentProperties.properties.resourceDetails.Id
            displayName = $assessmentProperties.properties.displayName
            code = $assessmentProperties.properties.status.code
            cause = $assessmentProperties.properties.status.cause
            description = $assessmentProperties.properties.status.description
            additionalData = $additionalData | ConvertTo-Json -Depth 99
            subAssessmentRemediation = ''
            subAssessmentImpact = ''
            subAssessmentCategory = ''
            subAssessmentDescription = ''
            subAssessmentTimeGenerated = ''
            subAssessmentResourceDetails = ''
            subAssessmentAdditionalData = ''
            cveTitle = ''
            cveCvssScore = ''
            cveCvssVersion = ''
            cveSeverity = ''
            cveDescription = ''
            cveExploitTypes = ''
            cveExploitUris = ''
            cveExploitabilityLevel = ''
            cveHasPublicExploit = ''
            cveIsExploitVerified = ''
            cveIsExploitInKit = ''
            cveLastModifiedDate = ''
            cvePublishedDate = ''
            cveIsZeroDay = ''
            cveCvssVectorString = ''
        }        
        $flatAssessment | Export-Csv -Path $outputCSV -Append
        continue
    }
    
    $subAssessmentLink = $assessment.additionaldata.subAssessmentsLink
    if($null -ne $subAssessmentLink -and $subAssessmentLink -ne "") {
        $nextSubLink = "https://management.azure.com$($subAssessmentLink)?api-version=2020-01-01"
        while($nextSubLink) {
            Write-Host $nextSubLink
            $subassessmentfileindex = $defcloudSubAssessmentsLookup[$nextSubLink]
            $subassessmentOutputPath = "subassessments/$($subassessmentfileindex.ToString()).json"
            $subAssessmentsObj = Get-Content -Path $subassessmentOutputPath | ConvertFrom-Json
            foreach($subAssessment in $subAssessmentsObj.value) {
                $properties = $subAssessment.properties
                $additionalData = $properties.additionaldata
                $cves = $additionalData.cve
                # if cves is null or empty or has zero elements, add the object to the csv
                if($null -eq $cves -or $cves -eq "" -or $cves.Count -eq 0) {
                    # create a new psobject to store the assessment properties values of resourceDetails.Source, resourceDetails.Id, displayName, status.code, status.cause, status.description
                    $cves = @([PSCustomObject]@{
                        Source = $properties.resourceDetails.Source
                        Id = $properties.resourceDetails.Id
                        displayName = $properties.displayName
                        code = $properties.status.code
                        cause = $properties.status.cause
                        description = $properties.status.description
                        additionalData = ''
                        subAssessmentRemediation = $properties.remediation
                        subAssessmentImpact = $properties.impact
                        subAssessmentCategory = $properties.category
                        subAssessmentDescription = $properties.description
                        subAssessmentTimeGenerated = $properties.timeGenerated
                        subAssessmentResourceDetails = $properties.resourceDetails | ConvertTo-Json -Depth 99
                        subAssessmentAdditionalData = $additionalData | ConvertTo-Json -Depth 99
                        cveTitle = ''
                        cveCvssScore = ''
                        cveCvssVersion = ''
                        cveSeverity = ''
                        cveDescription = ''
                        cveExploitTypes = ''
                        cveExploitUris = ''
                        cveExploitabilityLevel = ''
                        cveHasPublicExploit = ''
                        cveIsExploitVerified = ''
                        cveIsExploitInKit = ''
                        cveLastModifiedDate = ''
                        cvePublishedDate = ''
                        cveIsZeroDay = ''
                        cveCvssVectorString = ''
                    })
                }        
                foreach($cve in $cves) {
                    # create a new psobject to store the assessment properties values of resourceDetails.Source, resourceDetails.Id, displayName, status.code, status.cause, status.description, and cve values
                    $flatAssessment = [PSCustomObject]@{
                        Source = $properties.resourceDetails.Source
                        Id = $properties.resourceDetails.Id
                        displayName = $properties.displayName
                        code = $properties.status.code
                        cause = $properties.status.cause
                        description = $properties.status.description
                        additionalData = ''
                        subAssessmentRemediation = $properties.remediation
                        subAssessmentImpact = $properties.impact
                        subAssessmentCategory = $properties.category
                        subAssessmentDescription = $properties.description
                        subAssessmentTimeGenerated = $properties.timeGenerated
                        subAssessmentResourceDetails = $properties.resourceDetails | ConvertTo-Json -Depth 99
                        subAssessmentAdditionalData = ''
                        cveTitle = $cve.title
                        cveCvssScore = $cve.cvssScore
                        cveCvssVersion = $cve.cvssVersion
                        cveSeverity = $cve.severity
                        cveDescription = $cve.description
                        cveExploitTypes = $cve.exploitTypes | ConvertTo-Json -Depth 99
                        cveExploitUris = $cve.exploitUris | ConvertTo-Json -Depth 99
                        cveExploitabilityLevel = $cve.exploitabilityLevel
                        cveHasPublicExploit = $cve.hasPublicExploit
                        cveIsExploitVerified = $cve.isExploitVerified
                        cveIsExploitInKit = $cve.isExploitInKit
                        cveLastModifiedDate = $cve.lastModifiedDate
                        cvePublishedDate = $cve.publishedDate
                        cveIsZeroDay = $cve.isZeroDay
                        cveCvssVectorString = $cve.cvssVectorString
                    }
                    $flatAssessment | Export-Csv -Path $outputCSV -Append
                }
            }
            $nextSubLink = $subAssessmentsObj.nextLink
        }        
    }
}
