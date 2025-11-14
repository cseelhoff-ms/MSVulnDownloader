# if not logged in, login
if ($null -eq (az account show)) {az login}

# Get tenant and subscription info
Write-Host "Getting tenant and subscription info"
$tenantID = az account show --query tenantId -o tsv
$defaultSubscriptionID = az account show --query id -o tsv
$subscriptions = @($defaultSubscriptionID)

# Use Azure CLI's built-in app registration
$clientId = "04b07795-8ddb-461a-bbee-02f9e1bf7b46"
$resourceId = "https://management.azure.com"

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

# Get access token once - Azure CLI handles token caching and refresh internally
Write-Host "Getting access token from Azure CLI"
$accessToken = az account get-access-token --resource $resourceId --query accessToken -o tsv
$headers = @{"Authorization" = "Bearer $accessToken"}

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
                    Write-Host "Getting subassessments from: $nextSubLink"
                    Write-Host "Skipping for now (debug)..."
                    $nextSubLink = $subAssessments.nextLink
                    continue
                    if($defcloudSubAssessmentsLookup.ContainsKey($nextSubLink)) {
                        Write-Host $nextSubLink -ForegroundColor Green
                        $subassessmentfileindex = $defcloudSubAssessmentsLookup[$nextSubLink]
                        $subassessmentOutputPath = "subassessments/$($subassessmentfileindex.ToString()).json"
                        $subAssessments = Get-Content -Path $subassessmentOutputPath | ConvertFrom-Json
                    } else {
                        Write-Host $nextSubLink -ForegroundColor Yellow
                        #convert $subassessmentfileindex to int
                        $subassessmentfileindex = [int]$subassessmentfileindex + 1
                        $subassessmentOutputPath = "subassessments/$($subassessmentfileindex.ToString()).json"

                        # Retry logic with exponential backoff
                        $maxRetries = 10
                        $retryCount = 0
                        $retrySuccessful = $false
                        $subAssessmentsResponse = $null
                        
                        while($retryCount -le $maxRetries -and -not $retrySuccessful) {
                            try {
                                write-Host "Invoking web request for subassessments..."
                                $subAssessmentsResponse = Invoke-WebRequest -Method Get -Uri $nextSubLink -Headers $headers
                                $retrySuccessful = $true
                                
                            } catch {
                                $errorDetails = $_.ErrorDetails
                                $errorMessage = $errorDetails.Message
                                
                                # Check if it's a TooManyRequests error
                                if($errorMessage -match "TooManyRequests") {
                                    $retryCount++
                                    # Calculate wait time: exponential backoff starting at 10 seconds, capped at 10 minutes (600 seconds)
                                    $waitSeconds = [Math]::Min(10 * [Math]::Pow(2, $retryCount - 1), 600)
                                    Write-Host "TooManyRequests error (Attempt $retryCount/$maxRetries). Waiting $waitSeconds seconds before retry..." -ForegroundColor Yellow
                                    Start-Sleep -Seconds $waitSeconds
                                    continue
                                }
                                
                                # Handle other errors
                                try {
                                    $errorCode = $errorMessage | ConvertFrom-Json | Select-Object -ExpandProperty error | Select-Object -ExpandProperty code
                                } catch {
                                    $errorCode = $null
                                }
                                
                                if($errorCode -eq "ResourceNotFound") {
                                    Write-Host "ResourceNotFound" -ForegroundColor Red
                                    '' | Out-File -FilePath $subassessmentOutputPath
                                    ($nextSubLink + "`t" + $subassessmentfileindex) | Out-File -FilePath "defcloud-subassessments.csv" -Append
                                    $nextSubLink = $null
                                    $retrySuccessful = $true  # Exit retry loop
                                    continue
                                } else {
                                    Write-Error $errorDetails.Message
                                    exit
                                }
                            }
                        }
                        
                        # If we exhausted all retries, exit
                        if(-not $retrySuccessful) {
                            Write-Error "Failed after $maxRetries retry attempts due to TooManyRequests"
                            exit
                        }
                        
                        # Skip further processing if ResourceNotFound
                        if($null -eq $nextSubLink) {
                            continue
                        }                        
                        $subAssessmentsResponse.Content | Out-File -FilePath $subassessmentOutputPath
                        ($nextSubLink + "`t" + $subassessmentfileindex) | Out-File -FilePath "defcloud-subassessments.csv" -Append
                        $subAssessments = $subAssessmentsResponse.Content | ConvertFrom-Json
                    }
                    Write-Host "Subassessment complete."
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
