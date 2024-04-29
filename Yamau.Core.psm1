﻿function Get-RequiredModules {
    param (
        [Parameter(Mandatory=$true)]
        [string]$moduleName
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

Function Initialize-EventLogging {
    param (
        [Parameter(Mandatory=$false)] [string]$logName = "Application",
        [Parameter(Mandatory=$false)] [string]$source
    )

    # Create the source if it does not exist
    if (![System.Diagnostics.EventLog]::SourceExists($source)) {
        [System.Diagnostics.EventLog]::CreateEventSource($source, $logName)
    }
}

Function Log-Event {
    param (
        [Parameter(Mandatory=$false)] [string]$logName = "Application",
        [Parameter(Mandatory=$false)] [string]$source = "CustomPowerShellScript",
        [Parameter(Mandatory=$false)] [string]$entryType = "Information",
        [Parameter(Mandatory=$false)] [int]$eventId = 1001,
        [Parameter(Mandatory=$true)] [string]$message
    )

    Write-EventLog -LogName $logName -Source $source -EntryType $entryType -EventId $eventId -Message $message
}

function New-LocalSecret {
    param (
        [Parameter(Mandatory=$true)] 
        [string]$clientId,
        [ValidateSet("User", "System-Wide")]
        [string]$scope = "System-Wide"
    )

    $RequiredModulesInstalled = Get-RequiredModules -moduleName "CredentialManager"
    $credential = Get-Credential -UserName $clientId -Message "Enter the clientSecret for the App Registration."

    # Check if a non-empty password was provided
    if (-not [string]::IsNullOrEmpty($credential.GetNetworkCredential().Password)) {
        # Get the password (clientSecret)
        $clientSecret = $credential.GetNetworkCredential().Password

        # Add a new generic credential to Windows Credential Store
        $credentialName = "AzureAppRegistration_$clientId"
        $userName = $clientId

        # Determine the persistence type based on the scope parameter
        $persistenceType = $null
        switch ($scope) {
            "User" { $persistenceType = "LocalMachine" }
            "System-Wide" { $persistenceType = "Enterprise" }
        }

        
        New-StoredCredential -Target $credentialName -UserName $userName -Password $clientSecret -Type Generic -Persist LocalMachine | Out-Null
        
        return "Credential saved successfully to Windows Credential Store."
    }
    else {
        Write-Host "ERROR: There was no clientSecret provided! Run the function again and provide a valid clientSecret!" -ForegroundColor Red
    }
}

function Get-LocalSecret {
    param (
        [string]$clientId
    )

    $RequiredModulesInstalled = Get-RequiredModules -moduleName "CredentialManager"

    try 
    {
        $credentialName = "AzureAppRegistration_$clientId"
        $storedCredential = Get-StoredCredential -Target $credentialName

        # Check if a credential was returned
        if ($storedCredential -ne $null) 
            {
                return $storedCredential.Password
            } 
        else 
            {
                $ErrorMessage = "Get-LocalSecret @ "+(Get-Date)+": ERROR: No credential found for the given clientId: "+$clientId+"Check if the clientId is correct or if the credential exists in the Windows Credential Store. Error Details: "+$_.Exception.Message
                Write-Host $ErrorMessage -ForegroundColor Red
            }
    }
    catch 
    {
        $ErrorMessage = "Get-LocalSecret @ "+(Get-Date)+": ERROR: Could not retrieve locally stored clientSecret with clientId: "+$clientId+" Error Details: "+$_.Exception.Message
        Write-Host $ErrorMessage -ForegroundColor Red
    }
}

function Get-JsonConfig {
    param (
        [Parameter(Mandatory=$true)] 
        [string]$PathToConfig
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
        $ErrorMessage = "Get-JsonConfig @ "+(Get-Date)+": Config does not exist at path "+$PathToConfig+" Error Details: "+$_.Exception.Message
        Write-Host $ErrorMessage
    }
}
