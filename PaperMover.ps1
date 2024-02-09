 Function Initialize-EventLogging {
    param (
        [Parameter(Mandatory=$false)] [string]$logName = "Application",
        [Parameter(Mandatory=$false)] [string]$source
    )
    # Create the source if it does not exist
    if (![System.Diagnostics.EventLog]::SourceExists($source)) {

        $Message = "Initialize-EventLogging @ "+(Get-Date)+": Creating LogSource for EventLog..."
        Write-Verbose $message

        [System.Diagnostics.EventLog]::CreateEventSource($source, $logName)

    }
    else{

        $Message = "Initialize-EventLogging @ "+(Get-Date)+": LogSource exists already."
        Write-Verbose $message
    }

    $Message = "Initialize-EventLogging @ "+(Get-Date)+": Finished initialization of LogSources for EventLog."
    Write-Host $message -ForegroundColor Green
    Log-Event -message $message

}

Function Log-Event {
    param (
        [Parameter(Mandatory=$false)] [string]$logName = "CustomAutomation",
        [Parameter(Mandatory=$false)] [string]$source = "PaperMover",
        [Parameter(Mandatory=$false)] [string]$entryType = "Information",
        [Parameter(Mandatory=$false)] [int]$eventId = 1001,
        [Parameter(Mandatory=$true)] [string]$message
    )

    switch ($entryType) {
        "Information" { $switchColor = "White" }
        "Warning" { $switchColor = "Yellow" }
        "Error" { $switchColor = "Red" }
        Default {$switchColor = "White"}
    }

    Write-EventLog -LogName $logName -Source $source -EntryType $entryType -EventId $eventId -Message $message
    Write-Host $message -ForegroundColor $switchColor
}

function Get-AccessToken {
    param (
        [string]$clientId,
        [string]$clientSecret,
        [string]$tenantId
    )

    $scope = "https://graph.microsoft.com/.default"
    $authority = "https://login.microsoftonline.com/$tenantId/oauth2/v2.0/token"

    $Body = @{
        "grant_type"    = "client_credentials"
        "client_id"     = $clientId
        "client_secret" = $clientSecret
        "scope"         = $scope
    }

    # Get AccessToken
    $result = Invoke-RestMethod -Method Post -Uri $authority -Body $Body
    $AccessToken = $result.access_token
    
    return $AccessToken
}

# Function to send email using Microsoft Graph API
function Send-Email {
    param (
        [string]$accessToken,
        [string]$recipientEmail,
        [string]$subject,
        [string]$body,
        [string]$fromUserIdOrUpn
    )

    $graphApiEndpoint = "https://graph.microsoft.com/v1.0/users/$fromUserIdOrUpn/sendMail"
    $headers = @{
        Authorization = "Bearer $accessToken"
        "Content-Type" = "application/json"
    }

    $emailData = @{
        message = @{
            subject = $subject
            body = @{
                contentType = "Text"
                content = $body
            }
            toRecipients = @(
                @{
                    emailAddress = @{
                        address = $recipientEmail
                    }
                }
            )
            from = @{
                emailAddress = @{
                    address = $fromUserIdOrUpn
                }
            }
        }
    }

    $emailJson = $emailData | ConvertTo-Json -Depth 100
    Invoke-RestMethod -Uri $graphApiEndpoint -Method Post -Headers $headers -Body $emailJson -ContentType "application/json"
}

Function Submit-FileForAzAIDIAnalysis {
    param(
        [string]$FilePathOrUrl
    )
    # Create a temporary file to store the data to send
    $tempFile = [System.IO.Path]::GetTempFileName()

    # Determine if input is a URL or a file path
    if ($FilePathOrUrl -match '^https?://') {
        $dataToSend = @{ urlSource = $FilePathOrUrl } | ConvertTo-Json
    } else {
        # It's a file path, convert file to base64
        $fileContent = [System.IO.File]::ReadAllBytes($FilePathOrUrl)
        $fileBase64 = [System.Convert]::ToBase64String($fileContent)
        $dataToSend = @{ base64Source = $fileBase64 } | ConvertTo-Json
    }

    # Write data to temporary file
    [System.IO.File]::WriteAllText($tempFile, $dataToSend)

    # Send request to Azure AI Form Recognizer API
    $apiUrl = "$env:FR_ENDPOINT/formrecognizer/documentModels/prebuilt-layout:analyze?api-version=2023-07-31"

    $returnPOST = curl.exe -i -X POST $apiUrl -H "Content-Type: application/json" -H "Ocp-Apim-Subscription-Key: $env:FR_KEY" --data-binary "@$tempFile"

    <#
    This is some hacky stuff here. Why? Sometimes the API returns different formed objects. For some files, return looks like this:

    HTTP/1.1 202 Accepted
    Content-Length: 0
    Operation-Location: https://productionpaperocr.cognitiveservices.azure.com/formrecognizer/documentModels/prebuilt-layout/analyzeResults/c9145efa-d259-4cd4-a834-a6e10de02ba3?api-version=2023-07-31
    x-envoy-upstream-service-time: 91
    apim-request-id: c9145efa-d259-4cd4-a834-a6e10de02ba3
    Strict-Transport-Security: max-age=31536000; includeSubDomains; preload
    x-content-type-options: nosniff
    x-ms-region: Switzerland North
    Date: Fri, 09 Feb 2024 11:45:20 GMT


    And for others:

    HTTP/1.1 100 Continue
    HTTP/1.1 202 Accepted
    Content-Length: 0
    Operation-Location: https://productionpaperocr.cognitiveservices.azure.com/formrecognizer/documentModels/prebuilt-layout/analyzeResults/b7058fb8-7273-4eaa-8dcf-519dfe3b1a9c?api-version=2023-07-31
    x-envoy-upstream-service-time: 122
    apim-request-id: b7058fb8-7273-4eaa-8dcf-519dfe3b1a9c
    Strict-Transport-Security: max-age=31536000; includeSubDomains; preload
    x-content-type-options: nosniff
    x-ms-region: Switzerland North
    Date: Fri, 09 Feb 2024 11:48:43 GMT
    

    Therefore I need to check position 2 and 4 in the Array if it contains the ReturnStr we are looking for.
    #>

    $StrReturn = ($returnPOST[2]).ToString()
    $StrReturn4 = ($returnPOST[4]).ToString()

    If ($StrReturn -like "*analyze*")
    {
        $URIforAnalysisResult = ((($StrReturn.Split(':'))[1])+":"+($StrReturn.Split(':'))[2]).TrimStart(' ')
    }

    if ($StrReturn4 -like "*analyze*")
    {
        $URIforAnalysisResult = ((($StrReturn4.Split(':'))[1])+":"+($StrReturn4.Split(':'))[2]).TrimStart(' ')
    }

    Remove-Item $tempFile -Force

    return $URIforAnalysisResult
}

Function Get-ProductionPaperNumberfromAzAIDIAnalysis {
    param(
        [string]$ProductionPaperAnalysisURI
    )

    $headers = @{
    "Ocp-Apim-Subscription-Key" = $env:FR_KEY
    }

    $AnalysisResults = Invoke-RestMethod -Uri $ProductionPaperAnalysisURI -Method Get -Headers $headers 
    $text = $AnalysisResults.analyzeResult.content

    # Regular expression pattern to match and capture only the number part after "PP"
    $pattern = 'PP (\d+)'
    # Find matches in the text
    $matches = [regex]::Matches($text, $pattern)

    #No Match with default pattern? Apply another known one
    If (!($matches))
    {
        $pattern = 'PP_(\d+)'
        $matches = [regex]::Matches($text, $pattern)
    }

    # Extract only the number part from each match
    $ppNumbers = $matches | ForEach-Object { $_.Groups[1].Value }
    if ($ppNumbers.Count -gt 1)
    {
        #We just take the first ocurrence
        $ppNumbers = $ppNumbers[0]
    }
   
    return $ppNumbers

   }

#Graph E-Mail Configuration
$recipientEmail = ""
$fromUserIdOrUpn = ""

#Graph E-Mail Authentication 
$clientId = ""
$clientSecret = ""
$tenantId = ""

$PathToDirectoryToProcess = ""
$RootPathToMoveFilesInto = ""

$EventSource = "PaperMover"

$Message = "Process-ProductionPapers @ "+(Get-Date)+": PaperMover was invoked."
Log-Event -message $message -source $EventSource -entryType "Warning"

$Message = "Process-ProductionPapers @ "+(Get-Date)+": DirectoryToProcess: "+$PathToDirectoryToProcess
Log-Event -message $message -source $EventSource

$Message = "Process-ProductionPapers @ "+(Get-Date)+": DirectoryToMoveProcessedFilesTo: "+$RootPathToMoveFilesInto
Log-Event -message $message -source $EventSource

$FilesToProcess = Get-ChildItem -Path $PathToDirectoryToProcess

$Message = "Process-ProductionPapers @ "+(Get-Date)+": FilesToProcess: "+$FilesToProcess
Log-Event -message $message -source $EventSource


foreach ($File in $FilesToProcess)
{

    $Message = "Process-ProductionPapers @ "+(Get-Date)+": Processing file: "+$File.FullName
    Log-Event -message $message -source $EventSource

    $ProductionPaperAnalysisURI = Submit-FileForAzAIDIAnalysis -FilePathOrUrl $File.FullName

    $Message = "Process-ProductionPapers @ "+(Get-Date)+": Submitted file for Analysis: "+$File.FullName+" received URI for results: "+$ProductionPaperAnalysisURI
    Log-Event -message $message -source $EventSource

    Start-Sleep 15
    $ProductionPaperNumber = Get-ProductionPaperNumberfromAzAIDIAnalysis -ProductionPaperAnalysisURI $ProductionPaperAnalysisURI

    $Message = "Process-ProductionPapers @ "+(Get-Date)+": Extracted ProductionPaperNumber: "+$ProductionPaperNumber
    Log-Event -message $message -source $EventSource

    #Only continue processing file if we could extract ProcutionPaperNumber via Document Intelligence
    if (!($null -eq $ProductionPaperNumber -or $ProductionPaperNumber -eq "" -or $ProductionPaperNumber -eq " "))
    {
        if (Test-Path -Path ($RootPathToMoveFilesInto+"\"+$ProductionPaperNumber))
        {
            try {
                #define newname and rename
                $newName = ("ProductionPaper_"+$ProductionPaperNumber+".pdf")
                Rename-Item -Path $File.FullName -NewName $newName
        
                #grab the file with the new name again and move
                $renamedItem = Get-Item -Path ($PathToDirectoryToProcess+"\"+$NewName)
                $DestinationPath = ($RootPathToMoveFilesInto+"\"+$ProductionPaperNumber+"\")
                Move-Item -Path $RenamedItem.FullName -Destination $DestinationPath
        
                $Message = "Process-ProductionPapers @ "+(Get-Date)+": Moved item: "+$renamedItem.FullName+" to: "+$DestinationPath
                Log-Event -message $message -source $EventSource 
            }
            catch {

                $Message = "Process-ProductionPapers @ "+(Get-Date)+": Could not move item "+$renamedItem.FullName+" to: "+$DestinationPath+ "Error Details: "+$_.Exception.Message
                Log-Event -message $message -source $EventSource -entryType "Error"

                $subject = "PaperMover: ERROR could not process POPaper "+$file.Name
                $body = "PO Paper with name "+$file.name+" could not be renamed or moved due to error: "+$_.Exception.Message

                #Get GraphAPI access token with credentials
                $accessToken = Get-AccessToken -clientId $clientId -clientSecret $clientSecret -tenantId $tenantId

                # Send the email
                Send-Email -accessToken $accessToken -recipientEmail $recipientEmail -subject $subject -body $body -fromUserIdOrUpn $fromUserIdOrUpn
            }
        }      
    }

    #Send E-Mail that ProcutionPaperNumber could not be extracted
    else 
    {
        $Message = "Process-ProductionPapers @ "+(Get-Date)+": Could not extract POPaperNumber from file "+$file.Name+" because it was NULL or empty. Error Deatils: "+$_.Exception.Message
        Log-Event -message $message -source $EventSource -entryType "Error"

        $subject = "PaperMover: ERROR could not extract PO Number from file "+$file.Name
        $body = "Could not extract POPaperNumber from file "+$file.Name+" because it was NULL or empty. Error Deatils: "+$_.Exception.Message
        
        #Get GraphAPI access token with credentials
        $accessToken = Get-AccessToken -clientId $clientId -clientSecret $clientSecret -tenantId $tenantId

        # Send the emailcls
        Send-Email -accessToken $accessToken -recipientEmail $recipientEmail -subject $subject -body $body -fromUserIdOrUpn $fromUserIdOrUpn
    }
}
