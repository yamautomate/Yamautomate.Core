function Read-YcAzAiDiStringResponse {
    <#
   .SYNOPSIS
   The Read-YcAzAiDiStringResponse function processes a raw Azure API response and extracts key information.

   .DESCRIPTION
   The Read-YcAzAiDiStringResponse function takes a raw API response as input and converts it into a consolidated object. The function splits the response into headers and body, parses them into separate dictionaries, and extracts key information such as HTTP status, operation location, request ID, region, date, and content type. If the response body contains JSON data, it is converted into a dictionary.

   .PARAMETER APIResponseRaw
   The APIResponseRaw parameter is a mandatory input that provides the raw API response.

   .INPUTS
   The function does not accept any pipeline input.

   .OUTPUTS
   The function returns a consolidated object containing information extracted from the API response.

   .EXAMPLE
   The following example shows how to process a raw Azure API response:

   PS> Read-YcAzAiDiStringResponse -APIResponseRaw $response
   #>
   param(
       [Parameter(Mandatory=$true, Position = 0)] [ValidateNotNullOrEmpty()] $APIResponseRaw
   )

   # Convert response to string
   $responseString = $APIResponseRaw | Out-String

   # Split into lines
   $responseLines = $responseString.Split("`n")
   $httpAnswer = $responseLines[0].Trim()
   $httpAnswer = $httpAnswer.TrimStart("HTTP/1.1 ")

   # Determine where headers end and body begins
   $headerEndIndex = $responseLines.IndexOf("") # Finding the first empty line
   $headersString = $responseLines[0..($headerEndIndex - 1)] -join "`n"
   $bodyString = $responseLines[($headerEndIndex + 1)..($responseLines.Length - 1)] -join "`n"

   # Parse headers into a dictionary
   $headers = @{}
   foreach ($line in $headersString.Split("`n")) {
       $parts = $line.Split(":")
       if ($parts.Length -ge 2) {
           $key = $parts[0].Trim()
           $value = [string]::Join(":", $parts[1..($parts.Length - 1)]).Trim()
           $headers[$key] = $value
       }
   }

   # Parse the body JSON into a dictionary, if present
   $bodyObject = @{}
   if ($bodyString.Trim() -like "*{*" -and $bodyString.Trim() -like "*}*") {
       try {
           $bodyObject = $bodyString | ConvertFrom-Json
       } catch {
           $bodyObject = @{}
       }
   }
   # Create a consolidated JSON object
   $responseObject = @{
       "HTTPStatus" = $httpAnswer
       "OperationLocation" = $headers["Operation-Location"]
       "RequestId" = $headers["apim-request-id"]
       "Region" = $headers["x-ms-region"]
       "Date" = $headers["Date"]
       "ContentType" = $headers["Content-Type"]
   }
   return $responseObject

}
Function Submit-YcFileForAzAiDiAnalysis {
<#
   .SYNOPSIS
   The Submit-YcFileForAzAiDiAnalysis function submits a file or URL for analysis by Azure AI Form Recognizer.

   .DESCRIPTION
   The Submit-YcFileForAzAiDiAnalysis function takes a file path or URL, an endpoint, and an API key, and submits the specified data for analysis by Azure AI Form Recognizer. 
   It converts the file or URL into an appropriate format, writes the data to a temporary file, and makes a POST request to the API. 
   The function processes the response, checking for errors or a valid operation location, and returns relevant information.

   .PARAMETER FilePathOrUrl
   The FilePathOrUrl parameter is a mandatory string specifying the file path or URL to be analyzed.

   .PARAMETER Endpoint
   The Endpoint parameter is a mandatory string specifying the API endpoint for Azure AI Form Recognizer.

   .PARAMETER APIKey
   The APIKey parameter is a mandatory string specifying the API key to access the Azure AI Form Recognizer API.

   .INPUTS
   The function does not accept any pipeline input.

   .OUTPUTS
   The function returns the operation location URL or an error response object.

   .EXAMPLE
   The following example shows how to submit a file for analysis:

   PS> Submit-YcFileForAzAiDiAnalysis -FilePathOrUrl "C:\Docs\Sample.pdf" -Endpoint "https://yourapiendpoint.cognitiveservices.azure.com" -APIKey "yourapikey"

   #>
   param(
       [Parameter(Mandatory=$true, Position = 0)] [ValidateNotNullOrEmpty()] [string]$FilePathOrUrl,
       [Parameter(Mandatory=$true, Position = 1)] [ValidateNotNullOrEmpty()] [string]$Endpoint,
       [Parameter(Mandatory=$true, Position = 2)] [ValidateNotNullOrEmpty()] [string]$APIKey
   )

   try {
       # Create a temporary file to store the data to send
       $tempFile = [System.IO.Path]::GetTempFileName()

       # Determine if input is a URL or a file path
       if ($FilePathOrUrl -match '^https?://') {
           $dataToSend = @{ urlSource = $FilePathOrUrl } | ConvertTo-Json
       } 
       
       else {
           # It's a file path, convert file to base64
           $fileContent = [System.IO.File]::ReadAllBytes($FilePathOrUrl)
           $fileBase64 = [System.Convert]::ToBase64String($fileContent)
           $dataToSend = @{ base64Source = $fileBase64 } | ConvertTo-Json
       }

       # Write data to temporary file
       [System.IO.File]::WriteAllText($tempFile, $dataToSend)
   }

   catch {
       throw "Could not create temporary file."
   }

   # Send request to Azure AI Form Recognizer API
   $apiUrl = "$Endpoint/formrecognizer/documentModels/prebuilt-layout:analyze?api-version=2023-07-31"

   try {
       $AzAiDiAPIresponse = curl.exe -i -X POST $apiUrl -H "Content-Type: application/json" -H "Ocp-Apim-Subscription-Key: $APIKey" --data-binary "@$tempFile"
       $AzAiDiAPIresponseParsed = Read-YcAzAiDiStringResponse -APIResponseRaw $AzAiDiAPIresponse

       if ($AzAiDiAPIresponseParsed.HTTPStatus -like "*4*")
       {
           $Message = "Submit-YcFileForAzAiDiAnalysis @ "+(Get-Date)+": Error Received from API: "+$AzAiDiAPIresponseParsed.HTTPStatus
           Write-Host $Message -ForegroundColor Red
           return $AzAiDiAPIresponseParsed
       }
   
       else {
           if ($null -eq $AzAiDiAPIresponseParsed.OperationLocation)
           {
               $Message = "Submit-YcFileForAzAiDiAnalysis @ "+(Get-Date)+": Error. Did not receive OperationLocation URL from API"
               return $AzAiDiAPIresponseParsed
           }
           else {
               return $AzAiDiAPIresponseParsed.OperationLocation
           }
       }
   }

   catch {
       $Message = "Submit-YcFileForAzAiDiAnalysis @ "+(Get-Date)+": Error during curl call to API: "+$apiUrl+" Error Details: " +$_.Exception.Message
       Write-Host $Message -ForegroundColor Red
   }

   finally {
       Remove-Item $tempFile -Force
   }
   
}
Function Get-YcPatternFromAzAiDiAnalysis {
<#
   .SYNOPSIS
   The Get-YcPatternFromAzAiDiAnalysis function retrieves and searches text from an Azure AI Form Recognizer analysis.

   .DESCRIPTION
   The Get-YcPatternFromAzAiDiAnalysis function takes an analysis URI, an API key, and a list of patterns. ^
   It sends a GET request to the specified URI to retrieve the analysis results, extracts the content text, and searches for matches to the specified patterns. T
   he function returns an array of matched patterns found in the text.

   .PARAMETER AnalysisURI
   The AnalysisURI parameter is a mandatory string specifying the URI to retrieve the analysis results from.

   .PARAMETER APIKey
   The APIKey parameter is a mandatory string specifying the API key to access the Azure AI Form Recognizer API.

   .PARAMETER pattern
   The pattern parameter is a mandatory input specifying a list of regex patterns to search for in the text content.

   .INPUTS
   The function does not accept any pipeline input.

   .OUTPUTS
   The function returns an array of matched patterns found in the text content.

   .EXAMPLE
   The following example shows how to retrieve analysis results and search for patterns:

   PS> Get-YcPatternFromAzAiDiAnalysis -AnalysisURI "https://yourapiendpoint.com/analysis/1234" -APIKey "yourapikey" -pattern @("invoice", "total")

   #>
   param(
       [Parameter(Mandatory=$true, Position = 0)] [ValidateNotNullOrEmpty()] [string]$AnalysisURI,
       [Parameter(Mandatory=$true, Position = 1)] [ValidateNotNullOrEmpty()] [string]$APIKey,
       [Parameter(Mandatory=$true, Position = 2)] [ValidateNotNullOrEmpty()] $pattern
   )

   $headers = @{
   "Ocp-Apim-Subscription-Key" = $APIKey
   }

   $AnalysisResults = Invoke-RestMethod -Uri $AnalysisURI -Method Get -Headers $headers 
   $text = $AnalysisResults.analyzeResult.content

   $patternMatches = @()

   foreach ($pat in $pattern)
   {
       $patternMatches += [regex]::Matches($text, $pat)
   }

   return $patternMatches
}

function Get-YcOpenAiResponse {
   <#
   .SYNOPSIS
   The Get-YcOpenAiResponse function retrieves a response from the OpenAI API based on a query.

   .DESCRIPTION
   The Get-YcOpenAiResponse function takes a query and optional parameters, including model, stop token, temperature, and token limits, to retrieve a response from the OpenAI API. It also handles file-based queries, saving responses to specified files if needed. The function sets up necessary modules, constructs a conversation prompt, and returns the response content or writes it to a file.

   .PARAMETER query
   The query parameter is a mandatory string specifying the input query for the OpenAI API.

   .PARAMETER model
   The model parameter is an optional string specifying the model to use for generating the response. The default value is "gpt-4".

   .PARAMETER stop
   The stop parameter is an optional string specifying a stop token for the response generation. The default value is "\n".

   .PARAMETER temperature
   The temperature parameter is an optional double specifying the randomness of the response generation. The default value is 0.4.

   .PARAMETER max_tokens
   The max_tokens parameter is an optional integer specifying the maximum number of tokens allowed in the response. The default value is 900.

   .PARAMETER ShowOutput
   The ShowOutput parameter is an optional boolean specifying whether to display the response output. The default value is false.

   .PARAMETER ShowTokenUsage
   The ShowTokenUsage parameter is an optional boolean specifying whether to display token usage details. The default value is false.

   .PARAMETER instructor
   The instructor parameter is an optional string specifying an instruction for the OpenAI API conversation character. The default value is "You are a helpful AI. You answer as concisely as possible."

   .PARAMETER assistantReply
   The assistantReply parameter is an optional string specifying an initial reply from the OpenAI character. The default value is "Hello! I'm a ChatGPT-4 Model. How can I help you?"

   .PARAMETER Character
   The Character parameter is an optional string specifying the character name for the OpenAI API conversation. The default value is "Chat".

   .INPUTS
   The function does not accept any pipeline input.

   .OUTPUTS
   The function returns the response content from the OpenAI API or writes it to a file.

   .EXAMPLE
   The following example shows how to retrieve a response from the OpenAI API:

   PS> Get-YcOpenAiResponse -query "How's the weather today?"

   #>
   param (
       [Parameter(Mandatory=$true, Position = 0)] [ValidateNotNullOrEmpty()]  [string]$query,                 
       [Parameter(Mandatory=$false, Position = 1)] [string]$model = "gpt-4",       
       [Parameter(Mandatory=$false, Position = 2)] [string]$stop = "\n",                    
       [Parameter(Mandatory=$false, Position = 3)] [double]$temperature = 0.4,             
       [Parameter(Mandatory=$false, Position = 4)] [int]$max_tokens = 900,                 
       [Parameter(Mandatory=$false, Position = 5)] [bool]$ShowOutput = $false,                    
       [Parameter(Mandatory=$false, Position = 6)] [bool]$ShowTokenUsage = $false,                 
       [Parameter(Mandatory=$false, Position = 7)] [string]$instructor = "You are a helpful AI. You answer as concisely as possible.",
       [Parameter(Mandatory=$false, Position = 8)] [string]$assistantReply = "Hello! I'm a ChatGPT-4 Model. How can I help you?",
       [Parameter(Mandatory=$false, Position = 9)] [string]$Character = "Chat"
   )

   Get-YcRequiredModules -moduleName ShellGPT

   $APIKey = Get-YCOpenAIAPIKey -KeyLocation WindowsCredentialStore -Name "OpenAI"

   $InitialQuery = $query

   switch -Regex ($InitialQuery) {
       "^file \|.*" {
           Write-Verbose ("ShellGPT @ "+(Get-Date)+" | InitialQuery is File command")

           $filePath = (($InitialQuery.split("|"))[1]).TrimStart(" ")
           $filepath = $filePath.TrimEnd(" ")
           $filePath = $filePath.Replace('"','')
           $FileQuery = (($InitialQuery.split("|"))[2]).TrimStart(" ")

           Write-Verbose ("ShellGPT @ "+(Get-Date)+" | Extracted FilePath from Query is: "+($filePath)) 
           Write-Verbose ("ShellGPT @ "+(Get-Date)+" | Extracted Query is: "+($FileQuery))
           Write-Verbose ("ShellGPT @ "+(Get-Date)+" | Starting Conversation...") 

           [System.Collections.ArrayList]$conversationPrompt = New-OpenAICompletionConversation -Character $Character -query $FileQuery -instructor $instructor -APIKey $APIKey -temperature $temperature -max_tokens $max_tokens -model $model -stop $stop -filePath $filePath -ShowTokenUsage $ShowTokenUsage -ShowOutput $ShowOutput -assistantReply $assistantReply
           if ($InitialQuery.Contains("| out |"))
               {
                   $filePathOut = (($InitialQuery.split("|"))[4]).TrimStart(" ")
                   $filePathOut = $filePathOut.TrimEnd(" ")
                   Write-Host ("ShellGPT @ "+(Get-Date)+" | Writing output to file: "+($filePathOut)) -ForegroundColor Yellow

                   try {
                       ($conversationPrompt[($conversationPrompt.count)-1].content) | Out-File -Encoding utf8 -FilePath $filePathOut
                       Write-Host ("ShellGPT @ "+(Get-Date)+" | Successfully created file with output at: "+($filePathOut)) -ForegroundColor Green

                   }
                   catch {
                       Write-Host ("ShellGPT @ "+(Get-Date)+" | Could not write output to file: "+($filePathOut)) -ForegroundColor Red
                   }
               }
       }

       "^\s*$" {
           Write-Host ("ShellGPT @ "+(Get-Date)+" | You have not provided any input. Will not send this query to the CompletionAPI") -ForegroundColor Yellow
           [System.Collections.ArrayList]$conversationPrompt = Set-OpenAICompletionCharacter $Character
       }
       default {

           if ($InitialQuery.contains("| out |"))
           {
               $filePathOut = (($InitialQuery.split("|"))[2]).TrimStart(" ")
               $filePathOut = $filePathOut.TrimEnd(" ")
               $InitialQuery = (($InitialQuery.split("|"))[0]).TrimStart(" ")
               $InitialQuery = $InitialQuery.TrimEnd(" ")

               [System.Collections.ArrayList]$conversationPrompt = New-OpenAICompletionConversation -Character $Character -query $InitialQuery -instructor $instructor -APIKey $APIKey -temperature $temperature -max_tokens $max_tokens -model $model -stop $stop -ShowTokenUsage $ShowTokenUsage -ShowOutput $ShowOutput -assistantReply $assistantReply
               Write-Host ("ShellGPT @ "+(Get-Date)+" | Writing output to file: "+($filePathOut)) -ForegroundColor Yellow

               try {
                   ($conversationPrompt[($conversationPrompt.count)-1].content) | Out-File -Encoding utf8 -FilePath $filePathOut
                   Write-Host ("ShellGPT @ "+(Get-Date)+" | Successfully created file with output at: "+($filePathOut)) -ForegroundColor Green

               }
               catch {
                   Write-Host ("ShellGPT @ "+(Get-Date)+" | Could not write output to file: "+($filePathOut)) -ForegroundColor Red
               }
           }
           else
           {
               [System.Collections.ArrayList]$conversationPrompt = New-OpenAICompletionConversation -Character $Character -query $InitialQuery -instructor $instructor -APIKey $APIKey -temperature $temperature -max_tokens $max_tokens -model $model -stop $stop -ShowTokenUsage $ShowTokenUsage -ShowOutput $ShowOutput -assistantReply $assistantReply
           }    
           #Write-Host ("CompletionAPI @ "+(Get-Date)+" | "+($conversationPrompt[($conversationPrompt.count)-1].content)) -ForegroundColor Green
       }
   }

   $APIKey = $null
   #Extract Response
   return ($conversationPrompt[($conversationPrompt.count)-1].content)

}