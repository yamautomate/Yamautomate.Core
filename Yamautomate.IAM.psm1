Function New-YcAdUser {
    param (
        [Parameter(Mandatory=$true)] [string]$firstname,
        [Parameter(Mandatory=$true)] [string]$lastname,
        [Parameter(Mandatory=$true)] [string]$location,
        [Parameter(Mandatory=$true)] [string]$department,
        [Parameter(Mandatory=$true)] [string]$team,
        [Parameter(Mandatory=$true)] [string]$phoneNumber,
        [Parameter(Mandatory=$true)] [string]$jobTitle,
        [Parameter(Mandatory=$true)] [string]$manager,
        [Parameter(Mandatory=$false)][string]$PathToConfig = "$env:USERPROFILE\.yc\NewAdUser-Config.json"
    )

    try {
        Import-Module Yamautomate.Core
        $requiredModules = @("ActiveDirectory")
        Get-YcRequiredModules -moduleNames $requiredModules -ErrorAction Stop
    }
    catch {
        throw ("Could not import needed modules. Aborting. Error Details: "+$_.Exception.Message)
    }
    
    $EventLogSource = "IdGov-NewAdUser"
    Initialize-YcEventLogging -source $EventLogSource

    try {
        $config = Get-Content -raw -Path $PathToConfig | ConvertFrom-Json -ErrorAction Stop
        $locationForLookup = "Location-"+$location
        $Street = $config.$locationForLookup.Street
        $City = $config.$locationForLookup.City
        $ZIPCode = $config.$locationForLookup.ZIPCode
        $Country = $config.$locationForLookup.Country
        $CountryPhone = $config.$locationForLookup.Phone
        $TopLevelDomain = $config.$locationForLookup.TopLevelDomain
        $OU = $config.ADSetup.OU
        $rawDomainName = $config.ADSetup.rawDomainName
        $SwapDomainsForEmailAlias = $config.ADSetup.SecondarySMTPAlias
        $SetOfficeIpPhone = $config.ADSetup.SetOfficeIpPhone

        Write-YcLogMessage ("Successfuly loaded config from path: "+$PathToConfig) -source $EventLogSource -ToOutput -ToEventLog 
    }
    catch {
        throw ("Could not grab contents of ConfigFile. Aborting. Error Details: "+$_.Exception.Message)
    }

    # Construct the user’s full name and username with the location TLD
    $displayName = "$firstname $lastname"
    $samAccountName = "$firstname.$lastname"
    $primaryEmail = "$firstname.$lastname@$rawDomainname$TopLevelDomain"

    Write-YcLogMessage ("Primary E-Mail Address for new User is: "+$primaryEmail) -source $EventLogSource -ToEventLog -ToOutput 

    # Create the Active Directory user
    try {
            #Create Random Password
            $InitialPw = New-YcRandomPassword -length 14

            New-ADUser `
            -GivenName $firstname `
            -Surname $lastname `
            -Name $displayName `
            -SamAccountName $samAccountName `
            -UserPrincipalName $primaryEmail `
            -Path $OU `
            -Division $team `
            -OfficePhone $phoneNumber `
            -Title $jobTitle `
            -Department $department `
            -DisplayName $displayName `
            -StreetAddress $Street `
            -City $City `
            -PostalCode $ZIPCode `
            -Country $Country `
            -Enabled $true `
            -AccountPassword (ConvertTo-SecureString $InitialPw -AsPlainText -Force) `
            -ChangePasswordAtLogon $true `
            -EmailAddress $primaryEmail

            Write-YcLogMessage ("Successfully created new AD User: "+$samAccountName) -source $EventLogSource -ToEventLog -ToOutput 
    }
    catch {
        Write-YcLogMessage ("Could not create AD User. Aborting. Error Details: "+$_.Exception.Message) Error -source $EventLogSource -ToEventLog -ToOutput 
        throw ("Could not create AD User. Aborting. Error Details: "+$_.Exception.Message)
    }

    # Add organization tab information
    try {
        Set-ADUser -Identity $samAccountName -Title $jobTitle -Department $department -Manager $manager
        Write-YcLogMessage ("Successfully set organizational info on new AD User: "+$samAccountName) -source $EventLogSource -ToEventLog -ToOutput 
    }
    catch {
        Write-YcLogMessage ("Could not set organization tab info on AD User. Aborting. Error Details: "+$_.Exception.Message) -source $EventLogSource -ToEventLog -ToOutput 
        throw ("Could not set organization tab info  on AD User. Aborting. Error Details: "+$_.Exception.Message)
    }

    if ($SwapDomainsForEmailAlias -eq "true") {
        Write-YcLogMessage ("SecondarySMTPAlias is enabled. ") -source $EventLogSource -ToEventLog -ToOutput 
        $secondaryEmailTLD = $config.ADSetup.MakeSecondary

        if ($secondaryEmailTLD -eq $TopLevelDomain)
        {
            $secondaryEmailTLD = $config.ADSetup.SwapWith
        }

        $secondaryEmail = "$firstname.$lastname@$rawDomainname$secondaryEmailTLD"
        Write-YcLogMessage ("SecondarySMTPAlias is: "+$secondaryEmail) -source $EventLogSource -ToEventLog -ToOutput 

        $proxyAddresses = @("SMTP:$primaryEmail", "smtp:$secondaryEmail")

        # Add proxy addresses to the user
        try {
            Set-ADUser -Identity $samAccountName -Add @{proxyAddresses=$proxyAddresses}
            Write-YcLogMessage ("Successfully set proxy addresses on new AD User: "+$samAccountName) -source $EventLogSource -ToEventLog -ToOutput 
        }
        catch {
            Write-YcLogMessage ("Could not set proxy address on AD User. Aborting. Error Details: "+$_.Exception.Message) Error -source $EventLogSource -ToEventLog -ToOutput 
            throw ("Could not set proxy address on AD User. Aborting. Error Details: "+$_.Exception.Message)
        }
    }

    #Set country-specific main phone number
    if ($SetOfficeIpPhone -eq "true")
    {
        try {
            Set-ADUser -Identity $samAccountName -Replace @{ipPhone=$CountryPhone}
            Write-YcLogMessage ("Successfully set Ip Phone on: "+$samAccountName) -source $EventLogSource -ToEventLog -ToOutput 
        }
        catch {
            Write-YcLogMessage ("Could not set country-specific main phone number on AD User. Aborting. Error Details: "+$_.Exception.Message) Error -source $EventLogSource -ToEventLog -ToOutput 
            throw ("Could not set country-specific main phone number on AD User. Aborting. Error Details: "+$_.Exception.Message)
        }
    }

    return $InitialPw
}
Function New-YcTeamsPhoneNumberAssignment {
    param (
        [Parameter(Mandatory=$true)] [string]$phoneNumber,
        [Parameter(Mandatory=$true)] [string]$firstname,
        [Parameter(Mandatory=$true)] [string]$lastname,
        [Parameter(Mandatory=$false)][string]$PathToConfig = "C:\Temp\IdGov-NewAdUser-Config.json"
    )

    try {
        Import-Module Yamautomate.Core
        $requiredModules = @("MicrosoftTeams")
        Get-YcRequiredModules -moduleNames $requiredModules -ErrorAction Stop
    }
    catch {
        Write-Output (New-YcLogMessage -CustomText ("Could not import needed modules. Aborting. Error Details: "+$_.Exception.Message))
        Log-Event -message (New-YcLogMessage -CustomText ("Could not import needed modules. Aborting. Error Details: "+$_.Exception.Message))
        throw ("Could not import needed modules. Aborting. Error Details: "+$_.Exception.Message)
    }
    
    Initialize-YcEventLogging -source "IdGov-New-AdUser-Workflow"

    try {
        $config = Get-Content -raw -Path $PathToConfig | ConvertFrom-Json -ErrorAction Stop
        $locationForLookup = "Location-"+$location
        $TopLevelDomain = $config.$locationForLookup.TopLevelDomain
        $CertificateThumbprint = $config.Teams.CertificateThumbprint
        $tenantId = $config.Teams.tenantId
        $appId = $config.Teams.AzureAppRegistrationClientId
        $rawDomainName = $config.ADSetup.rawDomainName
        $policyname = $config.Teams.PolicyName 

        $identity = $firstname+"."+$lastname+"@"+$rawDomainName+$TopLevelDomain 

        Write-Output (New-YcLogMessage -CustomText ("Successfuly loaded config from path: "+$PathToConfig))
        Log-Event -message (New-YcLogMessage -CustomText ("Successfuly loaded config from path: "+$PathToConfig))
    }

    catch {
        Write-Output (New-YcLogMessage -CustomText ("Could not grab contents of ConfigFile. Aborting. Error Details: "+$_.Exception.Message))
        Log-Event -message (New-YcLogMessage -CustomText ("Could not grab contents of ConfigFile. Aborting. Error Details: "+$_.Exception.Message))
        throw ("Could not grab contents of ConfigFile. Aborting. Error Details: "+$_.Exception.Message)
    }

    try {
        Connect-MicrosoftTeams -TenantId $tenantId -Certificate $CertificateThumbprint -ApplicationId $appId
    }
    catch {
        Write-Output (New-YcLogMessage -CustomText ("Could not connect to Teams. Aborting. Error Details: "+$_.Exception.Message))
        Log-Event -message (New-YcLogMessage -CustomText ("Could not connect to Teams.. Aborting. Error Details: "+$_.Exception.Message))
        throw ("Could not connect to Teams. Aborting. Error Details: "+$_.Exception.Message)
    }

    try {
        Set-CsPhoneNumberAssignment -Identity $identity -PhoneNumber $phoneNumber -PhoneNumberType DirectRouting
        Grant-CsOnlineVoiceRoutingPolicy -Identity $identity -PolicyName $policyname 
        Grant-CsTeamsUpgradePolicy -Identity $identity -PolicyName UpgradeToTeams
    }
    catch {
        Write-Output (New-YcLogMessage -CustomText ("Could not connect to assign phoneNumber. Aborting. Error Details: "+$_.Exception.Message))
        Log-Event -message (New-YcLogMessage -CustomText ("Could not connect to assign phoneNumber.. Aborting. Error Details: "+$_.Exception.Message))
        throw ("Could not connect to assign phoneNumber. Aborting. Error Details: "+$_.Exception.Message)
    }
    finally {
        Disconnect-MicrosoftTeams 
    }
}

function New-YcIAMSampleConfig {
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
        [Parameter(Mandatory=$false, Position = 0)] [ValidateNotNullOrEmpty()] [string]$ConfigPath = "$env:USERPROFILE\.yc"  # Path where the config file will be created
    )

    $configTemplate = [YcIAMConfigTemplate]::new()

    # Convert the hashtable to a JSON string
    $jsonConfig = $configTemplate.ToJson()

    # Write the JSON string to the specified file path
    Set-Content -Path ($ConfigPath+"\YcIAMSampleConfig.json") -Value $jsonConfig -Force

    $OutputMessage = "Get-New-YcSampleConfig @ "+(Get-Date)+": Sample configuration created successfully at "+$ConfigPath+"\YcIAMSampleConfig.json"
    Write-Host $OutputMessage -ForegroundColor Green
}
class YcIAMConfigTemplate {
   
    # Constructor
    YcIAMConfigTemplate() {}

    # Method to convert the class to a hashtable
    [hashtable] ToHashtable() {
        return @{
            "EventLogging" = @(
                @{
                    "NameOfEventSource" = "YcIAM"
                    "PathToLogFile" = "C:\Temp\"
                }
            )
            "AzureGeneral" = @(
                @{
                    "tenantId" = "********-****-****-****-************"
                }
            )
            "ActiveDirectory" = @(
                @{
                    "OU" = ""
                    "rawDomainName" = "domainname"
                    "SecondarySMTPAlias" = "true"
                    "MakeSecondary" = ".com"
                    "SwapWith" = ".ch"
                    "SetOfficeIpPhone" = "true"
                }
            )
            "TeamsPhone" = @(
                @{
                    "AzureAppRegistrationClientId" = "********-****-****-****-************"
                    "CertificateThumbprint" = "***************************"
                    "PolicyName" = "********"
                }
            )
            "Location-CH" = @(
                @{
                    "Street" = "******"
                    "City" = "*****"
                    "ZIPCode" = "*****"
                    "Country" = "**"
                    "Phone" = "+**********"
                    "TopLevelDomain" = ".**"
                }
            )
            "Location-DE" = @(
                @{
                    "Street" = "******"
                    "City" = "*****"
                    "ZIPCode" = "*****"
                    "Country" = "**"
                    "Phone" = "+**********"
                    "TopLevelDomain" = ".**"
                }
            )
            "Location-US" = @(
                @{
                    "Street" = "******"
                    "City" = "*****"
                    "ZIPCode" = "*****"
                    "Country" = "**"
                    "Phone" = "+**********"
                    "TopLevelDomain" = ".**"
                }
            )
            "Notifications" = @(
                @{
                    "SendReportEmailTo" = "*****@domain.com"
                    "SendReportEmailFrom" = "*****@domain.com"
                    "AzureAppRegistrationClientId" = "*******-****-****-****-************"
                    "AzureAppRegistrationClientSecretCredentialName" = "********"
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
