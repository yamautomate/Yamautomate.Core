function Get-YcRequiredModules {
    <#
    .SYNOPSIS
    The Get-YcRequiredModules function checks for the availability and import status of a specified PowerShell module and attempts to import it if necessary.

    .DESCRIPTION
    The Get-YcRequiredModules function takes the name of a PowerShell module as input and verifies its installation and import status.
    If the module is not installed, it alerts the user to install it. 
    If the module is installed but not imported, the function attempts to import it. 
    If importing fails, an error message is displayed.

    .PARAMETER moduleName
    The moduleName parameter is a mandatory string parameter specifying the name of the module to check for.

    .INPUTS
    The function does not accept any pipeline input.

    .OUTPUTS
    The function outputs a message indicating whether the specified module is installed, imported, or if an error occurred during importing.

    .EXAMPLE
    The following example shows how to use the Get-YcRequiredModules function to check and manage the status of a module:

    PS> Get-YcRequiredModules -moduleName "Az.Accounts"
    #>

    param (
        [Parameter(Mandatory=$true, Position = 0)] [ValidateNotNullOrEmpty()] [string]$moduleName
    )

    # Check if the module is installed
    $moduleInstalled = Get-Module -ListAvailable -Name $moduleName

    if (-not $moduleInstalled) 
    {
        Write-Host "The required module '$moduleName' is not installed. Please install it." -ForegroundColor Yellow
        return 
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
    <#
    .SYNOPSIS
    The Initialize-YcEventLogging function sets up event logging by creating a source in the specified log.

    .DESCRIPTION
    The Initialize-YcEventLogging function initializes logging by creating an event source in a specified log. 
    The function accepts an optional log name, defaulting to "Application", and an optional source name to be associated with the log. 
    If the source does not exist, it is created in the specified log.

    .PARAMETER logName
    The logName parameter is an optional string specifying the name of the log to associate the source with. It defaults to "Application".

    .PARAMETER source
    The source parameter is a mandatory string specifying the source name to be associated with the log.

    .INPUTS
    The function does not accept any pipeline input.

    .OUTPUTS
    The function does not output anything directly, but it initializes logging by ensuring a source exists.

    .EXAMPLE
    The following example shows how to initialize event logging by setting up a source in the "Application" log:

    PS> Initialize-YcEventLogging -source "MyAppSource"
    #>

    param (
        [Parameter(Mandatory=$false, Position = 0)] [ValidateNotNullOrEmpty()] [string]$logName = "Application",
        [Parameter(Mandatory=$true, Position = 1)] [string]$source
    )

    # Create the source if it does not exist
    if (![System.Diagnostics.EventLog]::SourceExists($source)) {
        [System.Diagnostics.EventLog]::CreateEventSource($source, $logName)
    }
}

function New-YcEventLog {
        <#
    .SYNOPSIS
    The New-YcEventLog function writes a new event log entry with a specified message and other optional parameters.

    .DESCRIPTION
    The New-YcEventLog function writes a new entry to the specified event log. 
    The function accepts a mandatory message parameter and optional parameters for the log name, source, entry type, and event ID. 
    The message is processed through the `Protect-LogMessage` function before being logged. 
    The default log name is "Application", the default source is "CustomPowerShellScript", and the default entry type is "Information".

    .PARAMETER message
    The message parameter is a mandatory string specifying the content of the event log entry.

    .PARAMETER logName
    The logName parameter is an optional string specifying the name of the log to write to. The default value is "Application".

    .PARAMETER source
    The source parameter is an optional string specifying the source name associated with the log entry. 
    The default value is "CustomPowerShellScript".

    .PARAMETER entryType
    The entryType parameter is an optional string specifying the type of the log entry. 
    The default value is "Information".

    .PARAMETER eventId
    The eventId parameter is an optional integer specifying the ID associated with the log entry. 
    The default value is 1001.

    .INPUTS
    The function does not accept any pipeline input.

    .OUTPUTS
    The function does not return any output but writes an event log entry.

    .EXAMPLE
    The following example shows how to write a new event log entry:

    PS> New-YcEventLog -message "Application started successfully."
    #>
    param (
        [Parameter(Mandatory=$true, Position = 0)] [ValidateNotNullOrEmpty()] [string]$message,
        [Parameter(Mandatory=$false, Position = 1)] [string]$logName = "Application",
        [Parameter(Mandatory=$false, Position = 2)] [string]$source = "CustomPowerShellScript",
        [Parameter(Mandatory=$false, Position = 3)] [ValidateSet("Infromation", "Warning", "Error")] [string]$entryType = "Information",
        [Parameter(Mandatory=$false, Position = 4)] [int]$eventId = 1001

    )

    $message = Protect-LogMessage($message)
    Write-EventLog -LogName $logName -Source $source -EntryType $entryType -EventId $eventId -Message $message
}

function Write-YcLogFile {
    <#
    .SYNOPSIS
    The Write-YcLogFile function writes a message to a specified log file, organizing logs by date and source.

    .DESCRIPTION
    The Write-YcLogFile function writes a log message to a specified directory and file. 
    It accepts mandatory parameters for the log message, log directory, and source. 
    The function checks if the log directory and file exist, creating them if necessary. 
    The message is processed through the `Protect-LogMessage` function, and a timestamped log entry is appended to the file, organizing logs by date and source.
    If the log file exceeds a specified size, it is rotated and archived.

    .PARAMETER message
    The message parameter is a mandatory string specifying the content of the log entry.

    .PARAMETER logDirectory
    The logDirectory parameter is a mandatory string specifying the directory to store log files.

    .PARAMETER source
    The source parameter is a mandatory string specifying the source of the log entry.

    .PARAMETER maxLogSize
    The maxLogSize parameter is an optional integer specifying the maximum log file size in megabytes before rotating. Default is 5MB.

    .PARAMETER archiveDir
    The archiveDir parameter is an optional string specifying the directory to store archived logs. Defaults to "$logDirectory\archive".

    .INPUTS
    The function does not accept any pipeline input.

    .OUTPUTS
    The function writes a log message to a specified file.

    .EXAMPLE
    The following example shows how to write a log message to a specified directory:

    PS> Write-YcLogFile -message "Process completed successfully." -logDirectory "C:\Logs" -source "MyApp"
    #>

    param (
        [Parameter(Mandatory=$true, Position=0)] [ValidateNotNullOrEmpty()] [string]$message,
        [Parameter(Mandatory=$true, Position=1)] [ValidateNotNullOrEmpty()] [string]$logDirectory,
        [Parameter(Mandatory=$true, Position=2)] [ValidateNotNullOrEmpty()] [string]$source,
        [Parameter(Mandatory=$false, Position=3)] [ValidateSet("Infromation", "Warning", "Error")] [ValidateNotNullOrEmpty()] [string]$entryType = "Information",
        [Parameter(Mandatory=$false, Position=4)] [int]$maxLogSize = 5, # Max log file size in MB
        [Parameter(Mandatory=$false, Position=5)] [string]$archiveDir = "$logDirectory\YC_LogArchive"
    )

    # Ensure the log directory exists, create if not
    if (!(Test-Path $logDirectory)) {
        New-Item -ItemType Directory -Path $logDirectory | Out-Null
    }

    $currentDate = Get-Date -Format "yyyy-MM-dd"
    $LogFilePath = "$logDirectory\YCLog_$source-$currentDate.txt"

    # Check if the log file exists
    if (!(Test-Path $LogFilePath)) {
        New-Item -ItemType File -Path $LogFilePath | Out-Null
    }

    # Rotate the log file if it exceeds maxLogSize
    $fileSizeMB = (Get-Item $LogFilePath).Length / 1MB
    if ($fileSizeMB -ge $maxLogSize) {

        if (!(Test-Path $archiveDir)) {
            New-Item -ItemType Directory -Path $archiveDir | Out-Null
        }

        $archiveFilePath = "$archiveDir\YCLog_$source-$currentDate-$(Get-Date -Format 'HHmmss').txt"
        Move-Item $LogFilePath -Destination $archiveFilePath
        New-Item -ItemType File -Path $LogFilePath | Out-Null
    }

    # Sanitize and prepare the log message
    $message = Protect-LogMessage($message)
    $Timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    $LogMessage = $source+" @" +$Timestamp+" "+$entryType+": "+$message

    # Append the log message to the specified file
    Add-Content -Path $LogFilePath -Value $LogMessage
}

function Protect-LogMessage {
    <#
    .SYNOPSIS
    The Protect-LogMessage function masks sensitive information from a log message.

    .DESCRIPTION
    The Protect-LogMessage function takes a log message as input and searches for patterns indicative of sensitive information, including client secrets, API keys, bearer tokens, passwords, URLs with queries, and credit card numbers. 
    These patterns are masked or redacted to protect sensitive information. 
    The function replaces matched patterns with placeholders like "******" or "REDACTED", ensuring the message is safe for logging.

    .PARAMETER message
    The message parameter is a mandatory string representing the log message to be processed.

    .INPUTS
    The function does not accept any pipeline input.

    .OUTPUTS
    The function returns the sanitized log message with sensitive information masked.

    .EXAMPLE
    The following example shows how to use the Protect-LogMessage function:

    PS> Protect-LogMessage -message "Bearer token: Bearer abcdefghijklmnopqrs..."
    #>

    param (
        [Parameter(Mandatory = $true, Position = 0)] [ValidateNotNullOrEmpty()] [string]$message
    )

    $clientSecretPattern = "\b([a-zA-Z0-9~.]{36,40})\b" 
    $bearerPattern = "Bearer \w+"
    $APIKeyPattern = "APIKey_\w+"
    $URLwithQueryPattern = "https?:\/\/[a-zA-Z0-9-]+\.[a-zA-Z0-9.-]+(\/[a-zA-Z0-9-_]+)*\?[\w=&]+"
    $passwordPattern = "\bPassword\s*:\s*\w+\b"
    $creditCardPattern = "\b(?:\d{4}-?){4,5}\b"

    $patternsToMask = @($clientSecretPattern, $bearerPattern, $APIKeyPattern, $passwordPattern, $creditCardPattern, $URLwithQueryPattern)

    # Replace sensitive patterns with 'REDACTED'
    foreach ($pattern in $patternsToMask) {

        switch ($pattern) {
            $bearerPattern {  
                $message = [regex]::Replace($message, $pattern, {param($m) $m.Value.Substring(0, 6) + "******"})
            }
            $APIKeyPattern {
                $message = [regex]::Replace($message, $pattern, {param($m) $m.Value.Substring(0, 6) + "******"})
            }
            $passwordPattern {
                $message = [regex]::Replace($message, $pattern, {param($m) $m.Value.Substring(0, 6) + "******"})
            }
            $creditCardPattern {
                $message = [regex]::Replace($message, $pattern, {param($m) $m.Value.Substring(0, 6) + "******"})
            }
            $clientSecretPattern {
                $message = [regex]::Replace($message, $pattern, {param($m) $m.Value.Substring(0, 6) + "******"})
            }
            $URLwithQueryPattern {
                $message = [regex]::Replace($message, $pattern, {param($m) $m.Value.Substring(0, 20) + "******"})
            }
            Default {
                $message = [regex]::Replace($message, $pattern, "REDACTED")
            }
        }
    }

    return $message
    
}

function New-YcSecret {
      <#
    .SYNOPSIS
    The New-YcSecret function stores a secret securely in a specified location.

    .DESCRIPTION
    The New-YcSecret function securely stores a secret in one of three locations: Windows Credential Store, Environment Variable, or Azure Key Vault. 
    It takes a mandatory secret name and optional parameters to specify the storage location, scope, and Azure Key Vault credentials. Depending on the specified location, the function retrieves necessary modules, gathers credentials, and stores the secret in the chosen manner.

    .PARAMETER secretName
    The secretName parameter is a mandatory string specifying the name of the secret.

    .PARAMETER SecretLocation
    The SecretLocation parameter is an optional string that indicates where to store the secret: "WindowsCredentialStore", "EnvironmentVariable", or "AzureKeyVault". The default value is "WindowsCredentialStore".

    .PARAMETER AzKeyVaultClientId
    The AzKeyVaultClientId parameter is an optional string specifying the client ID for connecting to Azure Key Vault.

    .PARAMETER AzKeyVaultTenantId
    The AzKeyVaultTenantId parameter is an optional string specifying the tenant ID for connecting to Azure Key Vault.

    .PARAMETER AzKeyVaultName
    The AzKeyVaultName parameter is an optional string specifying the name of the Azure Key Vault.

    .PARAMETER scope
    The scope parameter is an optional string that determines the persistence type for Windows Credential Store or Environment Variable. 
    It can be "User" or "System-Wide".

    .INPUTS
    The function does not accept any pipeline input.

    .OUTPUTS
    The function returns a message indicating the success or failure of storing the secret.

    .EXAMPLE
    The following example shows how to store a secret in Windows Credential Store:

    PS> New-YcSecret -secretName "MyAppSecret"

    #>
    param (
        [Parameter(Mandatory=$true, Position = 0)] [ValidateNotNullOrEmpty()] [string]$secretName,   
        [Parameter(Mandatory=$false, Position = 1)] [ValidateSet("WindowsCredentialStore", "EnvironmentVariable", "AzureKeyVault")] [string]$SecretLocation = "WindowsCredentialStore" ,
        [Parameter(Mandatory=$false, Position = 2)] [string]$AzKeyVaultClientId,
        [Parameter(Mandatory=$false, Position = 3)] [string]$AzKeyVaultTenantId,
        [Parameter(Mandatory=$false, Position = 4)] [string]$AzKeyVaultName,
        [Parameter(Mandatory=$false, Position = 5)] [ValidateSet("User", "System-Wide")] [string]$scope = "User"
    )

    Get-YcRequiredModules -moduleName "CredentialManager"

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
                Get-RequiredModules -moduleName "Az.Accounts"

                Get-YcSecret -WindowsCredentialStore -secretName $AzKeyVaultClientId
                Connect-AzAccount -ServicePrincipal -ApplicationId $AzKeyVaultClientId -TenantId $AzKeyVaultTenantId -Credential (New-Object -TypeName PSCredential -ArgumentList $clientId, $clientSecret)

                $secret = New-AzKeyVaultSecret -VaultName $AzKeyVaultName -Name $secretName - 
                
                return "Credential saved to Environment AzureKeyVault: $AzKeyVaultName"

            }
        Default {}
    }
}

function Get-YcSecret {
     <#
    .SYNOPSIS
    The Get-YcSecret function retrieves a stored secret from a specified location.

    .DESCRIPTION
    The Get-YcSecret function retrieves a secret from one of three locations: Windows Credential Store, Environment Variable, or Azure Key Vault. 
    It takes a mandatory secret name and optional parameters for the storage location, Azure Key Vault credentials, and output format. 
    Depending on the specified location, the function retrieves necessary modules, fetches the secret, and returns it, optionally as plain text.

    .PARAMETER secretName
    The secretName parameter is a mandatory string specifying the name of the secret to retrieve.

    .PARAMETER SecretLocation
    The SecretLocation parameter is an optional string that indicates where to retrieve the secret from: "WindowsCredentialStore", "EnvironmentVariable", or "AzureKeyVault". 
    The default value is "WindowsCredentialStore".

    .PARAMETER AzKeyVaultClientId
    The AzKeyVaultClientId parameter is an optional string specifying the client ID for connecting to Azure Key Vault.

    .PARAMETER AzKeyVaultTenantId
    The AzKeyVaultTenantId parameter is an optional string specifying the tenant ID for connecting to Azure Key Vault.

    .PARAMETER AzKeyVaultName
    The AzKeyVaultName parameter is an optional string specifying the name of the Azure Key Vault.

    .PARAMETER AzKeyVaultCertThumbprint
    The AzKeyVaultCertThumbprint parameter is an optional string specifying the certificate thumbprint for Azure Key Vault authentication.

    .PARAMETER AsPlainText
    The AsPlainText parameter is an optional boolean indicating whether to return the secret as plain text. The default value is false.

    .PARAMETER SupressErrors
    The SupressErrors parameter is an optional boolean indicating whether to suppress error messages. The default value is false.

    .INPUTS
    The function does not accept any pipeline input.

    .OUTPUTS
    The function returns the retrieved secret or an error message.

    .EXAMPLE
    The following example shows how to retrieve a secret from the Windows Credential Store:

    PS> Get-YcSecret -secretName "MyAppSecret"

    #>
    param (
        [Parameter(Mandatory=$true, Position = 0)] [ValidateNotNullOrEmpty()] [string]$secretName,    
        [Parameter(Mandatory=$false, Position = 1)] [ValidateSet("WindowsCredentialStore", "EnvironmentVariable", "AzureKeyVault")] [string]$SecretLocation = "WindowsCredentialStore" ,
        [Parameter(Mandatory=$false, Position = 2)] [string]$AzKeyVaultClientId,
        [Parameter(Mandatory=$false, Position = 3)] [string]$AzKeyVaultTenantId,
        [Parameter(Mandatory=$false, Position = 4)] [string]$AzKeyVaultName,
        [Parameter(Mandatory=$false, Position = 5)] [string]$AzKeyVaultCertThumbprint,
        [Parameter(Mandatory=$false, Position = 6)] [bool]$AsPlainText = $false,
        [Parameter(Mandatory=$false, Position = 7)] [bool]$SupressErrors = $false
    )

    Get-YcRequiredModules -moduleName "CredentialManager"

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
            Get-YcRequiredModules -moduleName "Az.Accounts"
            Get-YcRequiredModules -moduleName "Az.KeyVault"

            Connect-AzAccount -ApplicationId $AzKeyVaultClientId -CertificateThumbprint $AzKeyVaultCertThumbprint -TenantId $AzKeyVaultTenantId | Out-Null

            if ($AsPlainText -eq $true)
            {
                $Secret = Get-AzKeyVaultSecret -VaultName $AzKeyVaultName -Name $secretName -AsPlainText
            }
            else
            {
                $Secret = Get-AzKeyVaultSecret -VaultName $AzKeyVaultName -Name $secretName
            }

            return $Secret
        }
        Default {}
    }
}

function Get-YcJsonConfig {
        <#
    .SYNOPSIS
    The Get-YcJsonConfig function retrieves a JSON configuration file from a specified path.

    .DESCRIPTION
    The Get-YcJsonConfig function takes a mandatory path to a JSON configuration file and retrieves its content, converting it into a PowerShell object. 
    It checks if the specified path exists and attempts to read and convert the content. 
    If an error occurs, it logs an error message, indicating the failure and its details.

    .PARAMETER PathToConfig
    The PathToConfig parameter is a mandatory string specifying the path to the JSON configuration file.

    .INPUTS
    The function does not accept any pipeline input.

    .OUTPUTS
    The function returns a PowerShell object containing the configuration data or logs an error message.

    .EXAMPLE
    The following example shows how to retrieve a JSON configuration file:

    PS> Get-YcJsonConfig -PathToConfig "C:\Configs\AppConfig.json"

    #>
    param (
        [Parameter(Mandatory=$true, Position = 0)] [ValidateNotNullOrEmpty()] [string]$PathToConfig
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
    <#
    .SYNOPSIS
    The New-YcSampleConfig function creates a sample configuration file at a specified path.

    .DESCRIPTION
    The New-YcSampleConfig function takes a mandatory path parameter to specify where to create a sample configuration file. 
    It defines a sample configuration as a PowerShell hashtable, converts it to a JSON string, and writes it to the specified path. 
    The configuration includes sections for event logging, Azure Key Vault, Azure General, API settings, solution settings, and notifications.

    .PARAMETER ConfigPath
    The ConfigPath parameter is a mandatory string specifying the path where the configuration file will be created.

    .INPUTS
    The function does not accept any pipeline input.

    .OUTPUTS
    The function writes a sample configuration file to the specified path and logs a success message.

    .EXAMPLE
    The following example shows how to create a sample configuration file:

    PS> New-YcSampleConfig -ConfigPath "C:\Configs\SampleConfig.json"

    #>
    param (
        [Parameter(Mandatory=$true, Position = 0)] [ValidateNotNullOrEmpty()] [string]$ConfigPath  # Path where the config file will be created
    )

    # Define the sample configuration as a PowerShell hashtable
    $sampleConfig = @{
        "EventLogging" = @(
            @{
                "NameOfEventSource" = "NameOfSolution"
            }
        )

        "AzureKeyVault" = @(
            @{
                "tenantId" = "xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxx"
                "AzureAppRegistrationClientId" = "xxxxxxx-xxxxxxx-xxxxxxx-xxxxxxxx"
                "KeyVaultName" = "xxxxxxx-xxxxxxx-xxxxxxx-xxxxxxxx"
                "CertificateThumbprint" = "xxxxxxx-xxxxxxx-xxxxxxx-xxxxxxxx"
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
    <#
    .SYNOPSIS
    The Convert-YcSecureStringToPlainText function converts a SecureString into a plain text string.

    .DESCRIPTION
    The Convert-YcSecureStringToPlainText function takes a mandatory SecureString parameter and converts it into a plain text string. 
    It uses the System.Net.NetworkCredential class to extract the password value from the SecureString and returns it as a plain text string.

    .PARAMETER secureString
    The secureString parameter is a mandatory SecureString that needs to be converted into plain text.

    .INPUTS
    The function does not accept any pipeline input.

    .OUTPUTS
    The function returns a plain text string representation of the SecureString.

    .EXAMPLE
    The following example shows how to convert a SecureString into plain text:
    PS> $secureString = Read-Host "Enter secure text" -AsSecureString
    PS> Convert-YcSecureStringToPlainText -secureString $secureString

    #>
    param (
        [Parameter(Mandatory=$true, Position = 0)] [ValidateNotNullOrEmpty()] [Security.SecureString]$secureString
    )

    # Convert the SecureString to a plain text string
    $credential = New-Object System.Net.NetworkCredential("", $secureString)
    $plainTextString = $credential.Password

    return $plainTextString
}

function New-YcRandomPassword {
    <#
    .SYNOPSIS
    The New-YcRandomPassword function generates a random password with a specified length.

    .DESCRIPTION
    The New-YcRandomPassword function generates a password of a specified length from a character set that includes uppercase and lowercase letters, digits, and special characters. The default length is 32 characters, but it can be modified by passing a different value to the length parameter.

    .PARAMETER length
    The length parameter is an optional integer specifying the desired length of the password. The default value is 32.

    .INPUTS
    The function does not accept any pipeline input.

    .OUTPUTS
    The function returns a randomly generated password.

    .EXAMPLE
    The following example shows how to generate a random password with a default length:

    PS> New-YcRandomPassword
    #>
    param (
        [Parameter(Mandatory=$false, Position = 0)] [ValidateNotNullOrEmpty()] [int]$length = 32 # Default length is 32 characters
    )

    $charset = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789!@#$%^&*()_+-=[]{}|;:',.<>?/"
    $password = -join ((0..($length-1)) | ForEach-Object { $charset[(Get-Random -Maximum $charset.Length)] })
    return $password
}

function New-YcSelfSignedCertForAppReg {
    <#
    .SYNOPSIS
    The New-YcSelfSignedCertForAppReg function creates a self-signed certificate for application registration.

    .DESCRIPTION
    The New-YcSelfSignedCertForAppReg function creates a self-signed certificate with a specified subject and validity period, storing it in the user's certificate store. 
    It generates a random password for exporting the certificate, exports both a .pfx file (including the private key) and a .cer file (containing only the public key), and returns an object with the certificate's details.

    .PARAMETER subject
    The subject parameter is a mandatory string specifying the common name (CN) of the certificate.

    .PARAMETER validForYears
    The validForYears parameter is a mandatory string specifying the number of years the certificate is valid for.

    .INPUTS
    The function does not accept any pipeline input.

    .OUTPUTS
    The function returns an object containing the certificate's thumbprint, file paths, and password.

    .EXAMPLE
    The following example shows how to create a self-signed certificate valid for 3 years:

    PS> New-YcSelfSignedCertForAppReg -subject "MyApp" -validForYears 3
    #>
    param (
        [Parameter(Mandatory=$true, Position = 0)] [ValidateNotNullOrEmpty()] [string]$subject,
        [Parameter(Mandatory=$true, Position = 1)] [ValidateNotNullOrEmpty()] [string]$validForYears
    )

    # Create the certificate
    $cert = New-SelfSignedCertificate -Subject "CN=$Subject" -CertStoreLocation "Cert:\CurrentUser\My" -KeyExportPolicy Exportable -KeySpec Signature -NotAfter (Get-Date).AddYears($validForYears)

    # Extract the thumbprint explicitly
    $thumbprint = $cert.Thumbprint

    # Generate a random password for exporting the certificate
    $password = New-YcRandomPassword
    $securePassword = ConvertTo-SecureString -String $password -AsPlainText -Force

    # Export the certificate to a .pfx file including the private key
    $pfxFilePath = "$env:USERPROFILE\Downloads\AppRegCert.pfx"
    Export-PfxCertificate -Cert "Cert:\CurrentUser\My\$thumbprint" -FilePath $pfxFilePath -Password $securePassword | Out-Null

    # Export the public key only as a .cer file (optional)
    $cerFilePath = "$env:USERPROFILE\Downloads\AppRegCert.cer"
    Get-ChildItem "Cert:\CurrentUser\My\$thumbprint" | Export-Certificate -FilePath $cerFilePath -Force | Out-Null

    # Create a custom object for the output
    $output = New-Object PSObject -Property @{
        "Thumbprint" = $thumbprint
        "PfxFilePath" = $pfxFilePath
        "CerFilePath" = $cerFilePath
        "Password" = $password
    }

    return $output
}

function Import-YcCertToLocalMachine {
    <#
    .SYNOPSIS
    The Import-YcCertToLocalMachine function imports a certificate into the Local Machine store.

    .DESCRIPTION
    The Import-YcCertToLocalMachine function takes a .pfx file path and a secure password, and imports the certificate into the Local Machine store. 
    It uses the provided password to unlock the certificate and then stores it in the "Cert:\LocalMachine\My" directory. 
    Once the import is complete, a success message is output.

    .PARAMETER pfxFilePath
    The pfxFilePath parameter is a mandatory string specifying the path to the .pfx file containing the certificate.

    .PARAMETER securePassword
    The securePassword parameter is a mandatory SecureString that provides the password needed to unlock and import the certificate.

    .INPUTS
    The function does not accept any pipeline input.

    .OUTPUTS
    The function outputs a message indicating the success of the import.

    .EXAMPLE
    The following example shows how to import a certificate into the Local Machine store:

    PS> Import-YcCertToLocalMachine -pfxFilePath "C:\Downloads\AppRegCert.pfx" -securePassword $password

    #>
    param (
        [Parameter(Mandatory=$true, Position = 0)] [ValidateNotNullOrEmpty()] [string]$pfxFilePath,
        [Parameter(Mandatory=$true, Position = 1)] [ValidateNotNullOrEmpty()] [SecureString]$securePassword
    )

    Import-PfxCertificate -FilePath $pfxFilePath -CertStoreLocation "Cert:\LocalMachine\My" -Password $securePassword
    Write-Output "Certificate imported successfully into the Local Machine store."
}

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

Function Send-YcMgEmail{
    <#
    .SYNOPSIS
    The Send-YcMgEmail function sends an email using Microsoft Graph.

    .DESCRIPTION
    The Send-YcMgEmail function uses Microsoft Graph to send an email. 
    It accepts mandatory parameters for the email message, subject, from address, and to address. 
    Further mandatory parameters include a client ID, client secret name, and tenant ID for Microsoft Graph authentication. 
    The function connects to Microsoft Graph, constructs the email message body, sends the message, and then disconnects from Microsoft Graph.

    .PARAMETER clientId
    The clientId parameter is a mandatory string specifying the client ID for Microsoft Graph authentication.

    .PARAMETER clientSecretName
    The clientSecretName parameter is a mandatory  string specifying the name of the client secret for Microsoft Graph authentication.

    .PARAMETER tenantId
    The tenantId parameter is a mandatory  string specifying the tenant ID for Microsoft Graph authentication.

    .PARAMETER message
    The message parameter is a mandatory string specifying the content of the email.

    .PARAMETER subject
    The subject parameter is a mandatory string specifying the subject of the email.

    .PARAMETER from
    The from parameter is a mandatory string specifying the sender's address.

    .PARAMETER to
    The to parameter is a mandatory string specifying the recipient's address.

    .INPUTS
    The function does not accept any pipeline input.

    .OUTPUTS
    The function does not output any return value directly but sends an email via Microsoft Graph.

    .EXAMPLE
    The following example shows how to send an email:

    PS> Send-YcMgEmail -clientId "your-client-id" -clientSecretName "your-client-secret" -tenantId "your-tenant-id" -message "Hello, world!" -subject "Greeting" -from "sender@example.com" -to "recipient@example.com"

    #>
    param(
        [Parameter(Mandatory=$true, Position = 0)] [ValidateNotNullOrEmpty()] [string]$clientId,
        [Parameter(Mandatory=$true, Position = 1)] [ValidateNotNullOrEmpty()] [string]$clientSecretName,
        [Parameter(Mandatory=$true, Position = 2)] [ValidateNotNullOrEmpty()] [string]$tenantId,
        [Parameter(Mandatory=$true, Position = 3)] [ValidateNotNullOrEmpty()] [string]$message,
        [Parameter(Mandatory=$true, Position = 4)] [ValidateNotNullOrEmpty()] [string]$subject,
        [Parameter(Mandatory=$true, Position = 5)] [ValidateNotNullOrEmpty()] [string]$from,
        [Parameter(Mandatory=$true, Position = 6)] [ValidateNotNullOrEmpty()] [string]$to
    )

    Get-YcRequiredModules -moduleName "Microsoft.Graph"

    $messageBody = New-YcMgMailMessageBody -message $message -subject $subject -to $to 

    Connect-MgGraph -ClientId $clientId -ClientSecret $clientSecret -TenantId $tenantId
    New-MgUserMessageSend -UserId $from -BodyParameter $messageBody
    Disconnect-MgGraph

    $clientSecret = $null
}
function New-YcMgMailMessageBody {
    <#
    .SYNOPSIS
    The New-YcMgMailMessageBody function constructs an email message body for Microsoft Graph.

    .DESCRIPTION
    The New-YcMgMailMessageBody function constructs a dictionary that represents an email message body for Microsoft Graph. 
    It accepts mandatory parameters for the message content, subject, and recipient address. 
    The function constructs a dictionary with fields for the subject, content type, content, and recipient details, and returns this dictionary as output.

    .PARAMETER message
    The message parameter is a mandatory string specifying the content of the email.

    .PARAMETER subject
    The subject parameter is a mandatory string specifying the subject of the email.

    .PARAMETER to
    The to parameter is a mandatory string specifying the recipient's email address.

    .INPUTS
    The function does not accept any pipeline input.

    .OUTPUTS
    The function returns a dictionary representing the email message body.

    .EXAMPLE
    The following example shows how to construct an email message body:

    PS> New-YcMgMailMessageBody -message "Hello, world!" -subject "Greeting" -to "recipient@example.com"
    #>

    param (
        [Parameter(Mandatory=$true, Position = 0)] [ValidateNotNullOrEmpty()] [string]$message,
        [Parameter(Mandatory=$true, Position = 1)] [ValidateNotNullOrEmpty()] [string]$subject,
        [Parameter(Mandatory=$true, Position = 2)] [ValidateNotNullOrEmpty()] [string]$to
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
