@{
    ModuleVersion = '1.0.5.2'
    GUID = 'c0f54af4-42a5-4858-9cd4-b55a81921a40'
    Author = 'Yanik Maurer'
    PowerShellVersion = '5.1'
    RootModule = 'Yamautomate.Core.psm1'
    FunctionsToExport = @('Get-YcRequiredModules', 'Initialize-YcEventLogging', 'YcLog-Event', 'New-YcSecret', 'Get-YcSecret', 'Get-YcJsonConfig', 'Write-YcLogFile', 'New-YcSampleConfig', 'Convert-YcSecureStringToPlainText', 'Send-YcMgEmail', 'New-YcMgMailMessageBody', 'New-YcSelfSignedCertForAppReg', 'New-YcRandomPassword', 'Import-YcCertToLocalMachine', 'Set-YcWindowsDigitalActivation')
    Description = 'A core module for logging, setting up config files, storing and accessing credentials and API Keys safely and more.'
    RequiredModules = @(
        @{
            ModuleName = 'CredentialManager'
            ModuleVersion = '2.0'
        }
        @{
            ModuleName = 'Az.Accounts'
            ModuleVersion = '2.17.0'
        }
        @{
            ModuleName = 'Az.KeyVault'
            ModuleVersion = '5.2.2'
        }
    )
}
