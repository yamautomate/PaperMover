Import-Module Yamautomate.Core

#Config Section
$PathToConfig = "C:\Temp\sampleconfig.json"
$config = Get-Content -raw -Path $PathToConfig | ConvertFrom-Json -ErrorAction Stop

#Mapping config to variables
$PathToLog = $config.EventLogging.PathToLogFile
$EventSource = $config.EventLogging.NameOfEventSource
$PathToDirectoryToProcess = $config.ProductionPaperMoverConfig.DirectoryToProcess
$RootPathToMoveFilesInto = $config.ProductionPaperMoverConfig.MoveProcessedFilesInto
$Endpoint = $config.AzureDocumentIntelligenceService.EndpointUrl

#Grabbing files to process
$FilesToProcess = Get-ChildItem -Path $PathToDirectoryToProcess

$AzAIAPIKeySecret = Get-YcSecret -secretName "AzAiDi"

foreach ($file in $FilesToProcess)
{
    $Message = "Processing file for Analysis: "+$File.FullName
    Write-YcLogFile -message $message -logDirectory $PathToLog -source $EventSource
   
    #Analyze document by AzAiDi
    $APIKey = Convert-YCSecureStringToPlainText -secureString $AzAIAPIKeySecret
    $AzAIAnalysisURI = Submit-YcFileForAzAIDIAnalysis -FilePathOrUrl $File.FullName -Endpoint $Endpoint -APIKey $APIKey
    $APIKey = $null

    $Message = "Submitted file for Analysis: "+$File.FullName+" received URI for results: "+$AzAIAnalysisURI
    Write-YcLogFile -message $message -logDirectory $PathToLog -source $EventSource

    Start-Sleep 15

    #Grab results from URL
    $pattern = @("PP (\d+)", "PP_(\d+)")
    $APIKey = Convert-YCSecureStringToPlainText -secureString $AzAIAPIKeySecret
    $PatternResults = Get-YcPatternfromAzAIDIAnalysis -AnalysisURI $AzAIAnalysisURI -APIKey $APIKey -pattern $pattern
    $APIKey = $null
0
    if ($PatternResults.Count -gt 1)
    {
        $PatternResults = $PatternResults[0]
    }

    #Strip "PP " or "PP_"
    $ProductionPaperNumber = ($PatternResults.Value).Substring(3)

    $Message = "Extracted PO Number: "+$ProductionPaperNumber
    Write-YcLogFile -message $message -logDirectory $PathToLog -source $EventSource    

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
        
                $Message = "Moved item: "+$renamedItem.FullName+" to: "+$DestinationPath
                Write-YcLogFile -message $message -logDirectory $PathToLog -source $EventSource
            }
            catch {
                $Message = "Could not move item "+$renamedItem.FullName+" to: "+$DestinationPath+ "Error Details: "+$_.Exception.Message
                Write-YcLogFile -message $message -logDirectory $PathToLog -source $EventSource
            }
        }      
    }

    Write-YcLogFile -message "---------------------------------------------------------------------" -logDirectory $PathToLog -source $EventSource    
}
