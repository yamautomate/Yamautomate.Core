@{
    ModuleVersion = '1.0'
    GUID = 'aacb51d6-1a55-4580-9d25-faf920943a82'
    Author = 'Yanik Maurer'
    PowerShellVersion = '5.1'
    RootModule = 'Yamau.Core.psm1'
    FunctionsToExport = @('Get-RequiredModules', 'Initialize-EventLogging', 'Log-Event', 'New-LocalSecret', 'Get-LocalSecret', 'Get-JsonConfig')
    Description = 'A core module for logging, setting up config files, storing and accessing credentials and API Keys safely and more.'
}