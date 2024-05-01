function Get-YcRequiredModules {
    param (
        [Parameter(Mandatory=$true)] [string]$moduleName
    )

    # Check if the module is installed
    $moduleInstalled = Get-Module -ListAvailable -Name $moduleName

    if (-not $moduleInstalled) 
    {
        Write-Host "The required module '$moduleName' is not installed. Trying to install it." -ForegroundColor Yellow

        try {
            Install-Module -Name $moduleName -Force -Scope CurrentUser
        } 
        
        catch {
            Write-Error "Could not install module '$moduleName' due to error: $_"
            return
        }
    }

    # Check if the module is imported
    $moduleImported = Get-Module -Name $moduleName
    if (-not $moduleImported) 
    {
        Write-Host "The required module '$moduleName' is not imported. Trying to import it." -ForegroundColor Yellow

        try {
            Import-Module -Name $moduleName
        } 
        
        catch {
            Write-Error "Could not import module '$moduleName' due to error: $_"
        }
    }
}

function Initialize-YcEventLogging {
    param (
        [Parameter(Mandatory=$false)] [string]$logName = "Application",
        [Parameter(Mandatory=$false)] [string]$source
    )

    # Create the source if it does not exist
    if (![System.Diagnostics.EventLog]::SourceExists($source)) {
        [System.Diagnostics.EventLog]::CreateEventSource($source, $logName)
    }
}

function New-YcEventLog {
    param (
        [Parameter(Mandatory=$false)] [string]$logName = "Application",
        [Parameter(Mandatory=$false)] [string]$source = "CustomPowerShellScript",
        [Parameter(Mandatory=$false)] [string]$entryType = "Information",
        [Parameter(Mandatory=$false)] [int]$eventId = 1001,
        [Parameter(Mandatory=$true)] [string]$message
    )

    Write-EventLog -LogName $logName -Source $source -EntryType $entryType -EventId $eventId -Message $message
}

function Write-YcLogFile {
    param (
        [Parameter(Mandatory = $true, Position = 0)] [string]$message,
        [Parameter(Mandatory = $true, Position = 1)] [string]$logDirectory,
        [Parameter(Mandatory = $true, Position = 2)] [string]$source
    )

    # Check if the directory exists, if not create it
    if (!(Test-Path $logDirectory)) {
        New-Item -ItemType Directory -Path $logDirectory | Out-Null
    }

    $currentDate = Get-Date -Format "yyyy-MM-dd"
    $LogFilePath = "$LogDirectory\YCLog_$source-$currentDate.txt"
    
    # Get the current timestamp
    $Timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"

    # Format the log message with a timestamp
    $LogMessage = "$Source @ $Timestamp : $Message"

    If (!(Test-Path $LogFilePath))
    {
        New-Item -ItemType File -Path $LogFilePath | Out-Null
    }

    # Append the log message to the specified file
    Add-Content -Path $LogFilePath -Value $LogMessage
}

function New-YcSecret {
    param (
        [Parameter(Mandatory=$false)] [ValidateSet("WindowsCredentialStore", "EnvironmentVariable", "AzureKeyVault")] [string]$SecretLocation = "WindowsCredentialStore" ,
        [Parameter(Mandatory=$false)] [string]$clientId, # For AzureAppRegistration
        [Parameter(Mandatory=$false)] [string]$secretName,
        [Parameter(Mandatory=$false)] [string]$AzKeyVaultClientId,
        [Parameter(Mandatory=$false)] [string]$AzKeyVaultTenantId,
        [Parameter(Mandatory=$false)] [string]$AzKeyVaultName,
        [Parameter(Mandatory=$false)] [ValidateSet("User", "System-Wide")] [string]$scope = "User"
    )

    Get-RequiredModules -moduleName "CredentialManager"

    switch ($SecretLocation) {
        WindowsCredentialStore 
            {
                $credential = Get-Credential -UserName $secretName -Message "Enter the clientSecret for the App Registration."
                # Check if a non-empty password was provided
                if (-not [string]::IsNullOrEmpty($credential.GetNetworkCredential().Password)) {
                    # Get the password (clientSecret)
                    $Secret = $credential.GetNetworkCredential().Password
            
                    # Determine the persistence type based on the scope parameter
                    switch ($scope) {
                        "User" { $persistenceType = "LocalMachine" }
                        "System-Wide" { $persistenceType = "Enterprise" }
                    }
            
                    New-StoredCredential -Target $secretName -UserName $secretName -Password $Secret -Type Generic -Persist $persistenceType | Out-Null
                    return "Credential saved successfully to Windows Credential Store."
                }
                else {
                    Write-Host "ERROR: There was no clientSecret provided! Run the function again and provide a valid clientSecret!" -ForegroundColor Red
                }
            }

        EnvironmentVariable
            {
                $credential = Get-Credential -UserName $secretName -Message "Enter the credentials to store as Environment Variable"
    
                if (-not [string]::IsNullOrEmpty($credential.GetNetworkCredential().Password)) {
                    # Get the password (clientSecret)
                    $Secret = $credential.GetNetworkCredential().Password
                    Write-Host $secret
            
                    # Determine the persistence type based on the scope parameter
                    switch ($scope) {
                        "User" { $persistenceType = "User" }
                        "System-Wide" { $persistenceType = "Machine" }
                    }

                    [Environment]::SetEnvironmentVariable($SecretName, $Secret, $persistenceType)
                    Write-Host "Credential saved to Environment Variable: $SecretName"
                }
            }
        AzureKeyVault
            {
                Get-RequiredModules -moduleName "Az"

                Get-YcSecret -WindowsCredentialStore -secretName $AzKeyVaultClientId
                Connect-AzAccount -ServicePrincipal -ApplicationId $AzKeyVaultClientId -TenantId $AzKeyVaultTenantId -Credential (New-Object -TypeName PSCredential -ArgumentList $clientId, $clientSecret)

                $secret = New-AzKeyVaultSecret -VaultName $AzKeyVaultName -Name $secretName - 
                
                return "Credential saved to Environment AzureKeyVault: $AzKeyVaultName"

            }
        Default {}
    }
}

function Get-YcSecret {
    param (
        [Parameter(Mandatory=$false)] [ValidateSet("WindowsCredentialStore", "EnvironmentVariable", "AzureKeyVault")] [string]$SecretLocation = "WindowsCredentialStore" ,
        [Parameter(Mandatory=$false)] [string]$secretName,
        [Parameter(Mandatory=$false)] [string]$AzKeyVaultClientId,
        [Parameter(Mandatory=$false)] [string]$AzKeyVaultTenantId,
        [Parameter(Mandatory=$false)] [string]$AzKeyVaultName,
        [Parameter(Mandatory=$false)] [bool]$SupressErrors = $false
    )

    Get-RequiredModules -moduleName "CredentialManager"

    switch ($SecretLocation) {
        WindowsCredentialStore 
        { 
            try 
            {
                $storedCredential = Get-StoredCredential -Target $secretName
        
                # Check if a credential was returned
                if ($null -ne $storedCredential) 
                    {
                        return $storedCredential.Password
                    } 
                else 
                    {
                        $ErrorMessage = "Get-LocalSecret @ "+(Get-Date)+": ERROR: No credential found for the given Name "+$secretName+" Check if the credentialName is correct or if the credential exists in the Windows Credential Store."
                        if ($SupressErrors -eq $false)
                        {
                            Write-Host $ErrorMessage -ForegroundColor Red
                        }
                    }
            }
            catch 
            {
                $ErrorMessage = "Get-LocalSecret @ "+(Get-Date)+": ERROR: Could not retrieve locally stored Secret with name: "+$sercetName+" Error Details: "+$_.Exception.Message
                Write-Host $ErrorMessage -ForegroundColor Red
            }
        }
        EnvironmentVariable 
        {
            If (Test-Path "Env:$secretName")
                {
                    $storedCredential = (Get-Item -Path "Env:$secretName").Value
                    If (-not [string]::IsNullOrEmpty($storedCredential))
                    {
                        return $storedCredential
                    }
                    else {
                        Write-Host "ERROR: Environment variable '$secretName' is null or empty." -ForegroundColor Red
                    }
                }
            else 
            {
                Write-Host "ERROR: Environment variable '$Name' not set." -ForegroundColor Red
            }

        }
        AzureKeyVault
        {
            Get-RequiredModules -moduleName "Az"

            Get-YcSecret -WindowsCredentialStore -secretName $AzKeyVaultClientId
            Connect-AzAccount -ServicePrincipal -ApplicationId $AzKeyVaultClientId -TenantId $AzKeyVaultTenantId -Credential (New-Object -TypeName PSCredential -ArgumentList $clientId, $clientSecret)

            $secret = Get-AzKeyVaultSecret -VaultName $AzKeyVaultName -Name $secretName
            
            return $secret

        }
        Default {}
}


}

function Get-YcJsonConfig {
    param (
        [Parameter(Mandatory=$true)] [string]$PathToConfig
    )

    if (Test-Path $PathToConfig)
    {
        try {
            $config = Get-Content -raw -Path $PathToConfig | ConvertFrom-Json -ErrorAction Stop
            return $config
        }
        catch 
        {
            $ErrorMessage = "Get-JsonConfig @ "+(Get-Date)+": Could not retrieve config from path "+$PathToConfig+" Error Details: "+$_.Exception.Message
            Write-Host $ErrorMessage
    
        }
    }

    else
    {
        $ErrorMessage = "Get-YcJsonConfig @ "+(Get-Date)+": Config does not exist at path "+$PathToConfig+" Error Details: "+$_.Exception.Message
        Write-Host $ErrorMessage
    }
}

function New-YcSampleConfig {
    param (
        [Parameter(Mandatory=$true)] [string]$ConfigPath  # Path where the config file will be created
    )

    # Define the sample configuration as a PowerShell hashtable
    $sampleConfig = @{
        "EventLogging" = @(
            @{
                "NameOfEventSource" = "NameOfSolution"
            }
        )

        "AzureGeneral" = @(
            @{
                "tenantId" = "xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxx"
                "AzureAppRegistrationClientId" = "xxxxxxx-xxxxxxx-xxxxxxx-xxxxxxxx"
            }
        )

        "API1" = @(
            @{
                "EndpointURL" = "https://endpointofyourapi.com"
                "APIKeyCredentialName" = "APIKey_AzureDocumentIntelligenceService"
            }
        )

        "SteerYourApporSolution" = @(
            @{
                "DirectoryToProcess" = "\\someunc\there"
                "MoveProcessedFilesInto" = "\\anotherunc\there"
            }
        )

        "Notifications" = @(
            @{
                "SendReportEmailTo" = "some.recipient@hisdomain.com"
                "SendReportEmailFrom" = "some.sender@hisdomain.com"
            }
        )
    }

    # Convert the hashtable to a JSON string
    $jsonConfig = $sampleConfig | ConvertTo-Json -Depth 4

    # Write the JSON string to the specified file path
    Set-Content -Path $ConfigPath -Value $jsonConfig -Force

    $OutputMessage = "Get-New-YcSampleConfig @ "+(Get-Date)+": Sample configuration created successfully at "+$ConfigPath
    Write-Host $OutputMessage -ForegroundColor Green
}

function Convert-YcSecureStringToPlainText {
    param (
        [Parameter(Mandatory=$true)] [Security.SecureString]$secureString
    )

    # Convert the SecureString to a plain text string
    $credential = New-Object System.Net.NetworkCredential("", $secureString)
    $plainTextString = $credential.Password

    return $plainTextString
}

function Get-YcOpenAiAPIKey {
    param (
        [ValidateSet("WindowsCredentialStore", "EnvironmentVariable")] [string]$KeyLocation = "WindowsCredentialStore",
        [Parameter(Mandatory=$false)] [String]$SecretName
    )

    switch ($KeyLocation) {
        WindowsCredentialStore 
            {
                Write-Host "WindowsCredentialStore"
                if ($WCSSecret = Get-YcSecret -SecretName $SecretName)
                {
                    $APIKey = Convert-YCSecureStringToPlainText -secureString $WCSSecret
                    return $APIKey
                }
                else 
                {
                    New-YCSecret -TypeOfCredentials APIKey -APIName OpenAI
                    Get-YCOpenAIAPIKey -KeyLocation $KeyLocation -Name $Name
                }
            }
        EnvironmentVariable     
            {

                Write-Host "Retrieving from Environment Variable"

                If (Test-Path "Env:$Name")
                {
                    $APIKey = (Get-Item -Path "Env:$Name").Value
                    If (-not [string]::IsNullOrEmpty($APIKey))
                    {
                        return $APIKey
                    }
                    else {
                        Write-Host "ERROR: Environment variable '$Name' is null or empty." -ForegroundColor Red
                    }
                }
                else 
                {
                    Write-Host "ERROR: Environment variable '$Name' not set." -ForegroundColor Red
                }
            }
        Default {}
    }
}

function Get-YcOpenAiResponse {
    param (
        [Parameter(Mandatory=$true)]  [string]$query,                 
        [Parameter(Mandatory=$false)] [string]$model = "gpt-4",       
        [Parameter(Mandatory=$false)] [string]$stop = "\n",                    
        [Parameter(Mandatory=$false)] [double]$temperature = 0.4,             
        [Parameter(Mandatory=$false)] [int]$max_tokens = 900,                 
        [Parameter(Mandatory=$false)] [bool]$ShowOutput = $false,                    
        [Parameter(Mandatory=$false)] [bool]$ShowTokenUsage = $false,                 
        [Parameter(Mandatory=$false)] [string]$instructor = "You are a helpful AI. You answer as concisely as possible.",
        [Parameter(Mandatory=$false)] [string]$assistantReply = "Hello! I'm a ChatGPT-4 Model. How can I help you?",
        [Parameter(Mandatory=$false)] [string]$Character = "Chat"
    )

    Get-RequiredModules -moduleName ShellGPT

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

function Read-YcAzAiDiStringResponse {
    param(
        [Parameter(Mandatory=$true)] $APIResponseRaw
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
    param(
        [Parameter(Mandatory=$true)] [string]$FilePathOrUrl,
        [Parameter(Mandatory=$true)] [string]$Endpoint,
        [Parameter(Mandatory=$true)] [string]$APIKey
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
    param(
        [Parameter(Mandatory=$true)] [string]$AnalysisURI,
        [Parameter(Mandatory=$true)] [string]$APIKey,
        [Parameter(Mandatory=$true)] $pattern
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

Function Send-YcMgEmail{
    param(
        [Parameter(Mandatory=$false)] [bool]$useConfig,
        [Parameter(Mandatory=$false)] [string]$pathToConfig,

        [Parameter(Mandatory=$false)] [string]$clientId,
        [Parameter(Mandatory=$false)] [string]$clientSecretName,
        [Parameter(Mandatory=$false)] [string]$tenantId,

        [Parameter(Mandatory=$true)] [string]$message,
        [Parameter(Mandatory=$true)] [string]$subject,
        [Parameter(Mandatory=$true)] [string]$from,
        [Parameter(Mandatory=$true)] [string]$to
    )

    Get-RequiredModules -moduleName "Microsoft.Graph"

    $messageBody = New-YcMgMailMessageBody -message $message -subject $subject -to $to 

    Connect-MgGraph -ClientId $clientId -ClientSecret $clientSecret -TenantId $tenantId
    New-MgUserMessageSend -UserId $from -BodyParameter $messageBody
    Disconnect-MgGraph

    $clientSecret = $null


}
function New-YcMgMailMessageBody {
    param (
        [Parameter(Mandatory=$true)] [string]$message,
        [Parameter(Mandatory=$true)] [string]$subject,
        [Parameter(Mandatory=$true)] [string]$to
    )

    $message = @{
        Message = @{
            Subject = $subject
            Body = @{
                ContentType = "Text"
                Content = $message
            }
            ToRecipients = @(
                @{
                    EmailAddress = @{
                        Address = $to
                    }
                }
            )
        }
    }

    return $message
    
}
