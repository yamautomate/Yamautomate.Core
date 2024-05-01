@{
    ModuleVersion = '1.0.2'
    GUID = 'c0f54af4-42a5-4858-9cd4-b55a81921a40'
    Author = 'Yanik Maurer'
    PowerShellVersion = '5.1'
    RootModule = 'Yamautomate.Core.psm1'
    FunctionsToExport = @('Get-YcRequiredModules', 'Initialize-YcEventLogging', 'YcLog-Event', 'New-YcSecret', 'Get-YcSecret', 'Get-YcJsonConfig', 'Write-YcLogFile', 'New-YcSampleConfig', 'Convert-YcSecureStringToPlainText', 'Get-YcOpenAiAPIKey', 'Get-YcOpenAiResponse', 'Read-YcAzAiDiStringResponse', 'Submit-YcFileForAzAiDiAnalysis', 'Get-YcPatternFromAzAiDiAnalysis', 'Send-YcMgEmail', 'New-YcMgMailMessageBody')
    Description = 'A core module for logging, setting up config files, storing and accessing credentials and API Keys safely and more.'
    RequiredModules = @(
        @{
            ModuleName = 'CredentialManager'
            ModuleVersion = '2.0'
        }
    )
}
