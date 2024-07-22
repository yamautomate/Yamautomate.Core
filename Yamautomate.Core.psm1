function Get-YcRequiredModules {
    <#
    .SYNOPSIS
    The Get-YcRequiredModules function checks for the availability and import status of a specified PowerShell module and attempts to import it if necessary.

    .DESCRIPTION
    The Get-YcRequiredModules function takes the name of several PowerShell modules as input and verifies its installation and import status.
    If the module is not installed, it alerts the user to install it. 
    If the module is installed but not imported, the function attempts to import it. 
    If importing fails, an error message is displayed.

    .PARAMETER moduleNames
    The moduleName parameter is a mandatory array of string specifying the name of the modules to check for.

    .INPUTS
    The function does not accept any pipeline input.

    .OUTPUTS
    The function outputs a message indicating whether the specified module is installed, imported, or if an error occurred during importing.

    .EXAMPLE
    The following example shows how to use the Get-YcRequiredModules function to check and manage the status of a module:

    PS> Get-YcRequiredModules -moduleName "Az.Accounts"
    #>

    param (
        [Parameter(Mandatory=$true, Position = 0)] [ValidateNotNullOrEmpty()] [string[]]$moduleNames
    )

    Foreach ($Module in $ModuleNames)
    {
        # Check if the module is installed
        $moduleInstalled = Get-Module -ListAvailable -Name $module

        if (-not $moduleInstalled) 
        {
            $message = "The required module '$module' is not installed. Please install it."
            Write-Host $message -ForegroundColor Yellow
            return 
        }

        else {
            $message = "The required module '$module' is already installed. Trying to import it."
        }

        # Check if the module is imported
        $moduleImported = Get-Module -Name $module
        if (-not $moduleImported) 
        {
            Write-Host "The required module '$module' is not imported. Trying to import it." -ForegroundColor Yellow

            try {
                Import-Module -Name $module
            } 
            
            catch {
                Write-Error "Could not import module '$module' due to error: $_"
            }
        }
        else {
            Write-Host "The required module '$module' is already imported. Doing nothing." -ForegroundColor Green
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

    $requiredModules = "CredentialManager"
    Get-YcRequiredModules $requiredModules

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
            $requiredModules = "Az.Accounts", "Az.KeyVault"
            Get-YcRequiredModules $requiredModules

            try {
                    
                Write-Host ("Trying to connect to KeyVault: "+$AzKeyVaultName+" from Tenant: "+$AzKeyVaultTenantId+"") -ForegroundColor Yellow
                Write-Host ("Using AppId: "+$AzKeyVaultClientId+"") -ForegroundColor Yellow

                Connect-AzAccount -ApplicationId $AzKeyVaultClientId -CertificateThumbprint $AzKeyVaultCertThumbprint -TenantId $AzKeyVaultTenantId | Out-Null
                Write-Host ("Connected successfully to AzVaultKeyVault: "+$AzKeyVaultName+"") -ForegroundColor Green


                Write-Host ("Grabbing Secret: "+$secretName+"") -ForegroundColor Yellow

                if ($AsPlainText -eq $true)
                {
                    $Secret = Get-AzKeyVaultSecret -VaultName $AzKeyVaultName -Name $secretName -AsPlainText
                }
                else
                {
                    $Secret = Get-AzKeyVaultSecret -VaultName $AzKeyVaultName -Name $secretName
                }  

                if ($Secret -eq $null)
                {
                    Write-Host ("Secret is NULL: "+$secretName+"") -ForegroundColor Red
                }
                else {
                    Write-Host ("Retreieved Secret: "+$secretName+"") -ForegroundColor Green
                }

            }
            catch {
                Write-Host ("Could not connect to Az Account and or retrieve AzVaultSecret: " +$secretName+ "from Vault: "+$AzKeyVaultName+" Error Details: "+$_.Exception.Message) -ForegroundColor Red
            }
            finally {

                Disconnect-AzAccount | Out-Null
                Write-host ("Successfully disconnected from AzAccount") -ForegroundColor Green
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

    <# Define the sample configuration as a PowerShell hashtable
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
    #>

    $configTemplate = [YcConfigTemplate]::new()

    # Convert the hashtable to a JSON string
    $jsonConfig = $configTemplate.ToJson()

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

function New-YcGUID {
    $newGUID = [guid]::NewGuid()
    return $newGUID.guid
}
 
class YcConfigTemplate {
    [string]$EventSource = "******"
    [string]$LogEvents = "true"
    [string]$PathToLogFile = "C:\\Temp\\"
    [string]$AzureTenantId = "********-****-****-****-************"
    [string]$KeyVaultName = "***************"
    [string]$AzureAppRegistrationClientId = "********-****-****-****-************"
    [string]$KeyVaultThumbprint = "************************"
    [string]$DocIntelligenceEndpoint = "https://*******.cognitiveservices.azure.com"
    [string]$AKVAPIKeyCredentialName = "***********************"
    [string]$DirToProcess = "\\\\server\\shares\\to\\process"
    [string]$MoveFilesTo = "\\\\server\\shares\\processed"
    [string]$EmailTo = "*****@domain.com"
    [string]$EmailFrom = "*****@domain.com"
    [string]$NotificationsClientId = "********-****-****-****-************"
    [string]$NotificationsClientSecretName = "*********************"

    # Constructor
    YcConfigTemplate() {}

    # Method to convert the class to a hashtable
    [hashtable] ToHashtable() {
        return @{
            "EventLogging" = @(
                @{
                    "LogEvents" = $this.LogEvents
                    "NameOfEventSource" = $this.EventSource
                    "PathToLogFile" = $this.PathToLogFile
                }
            )
            "AzureGeneral" = @(
                @{
                    "tenantId" = $this.AzureTenantId
                }
            )
            "AzureKeyVault" = @(
                @{
                    "tenantId" = $this.AzureTenantId
                    "KeyVaultName" = $this.KeyVaultName
                    "AzureAppRegistrationClientId" = $this.AzureAppRegistrationClientId
                    "CertificateThumbprint" = $this.KeyVaultThumbprint
                }
            )
            "AzureDocumentIntelligenceService" = @(
                @{
                    "EndpointURL" = $this.DocIntelligenceEndpoint
                    "AKVAPIKeyCredentialName" = $this.AKVAPIKeyCredentialName
                }
            )
            "ProductionPaperMoverConfig" = @(
                @{
                    "DirectoryToProcess" = $this.DirToProcess
                    "MoveProcessedFilesInto" = $this.MoveFilesTo
                }
            )
            "Notifications" = @(
                @{
                    "SendReportEmailTo" = $this.EmailTo
                    "SendReportEmailFrom" = $this.EmailFrom
                    "AzureAppRegistrationClientId" = $this.NotificationsClientId
                    "AzureAppRegistrationClientSecretCredentialName" = $this.NotificationsClientSecretName
                }
            )
        }
    }

    # Method to convert the class to a JSON string
    [string] ToJson() {
        $config = $this.ToHashtable()
        return $config | ConvertTo-Json -Depth 4
    }
}
