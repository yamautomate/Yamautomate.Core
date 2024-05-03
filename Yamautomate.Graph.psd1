@{
    ModuleVersion = '0.5'
    GUID = 'cc95e77c-31c8-4f55-abb4-915f70972de2'
    Author = 'Yanik Maurer'
    PowerShellVersion = '5.1'
    RootModule = 'Yamautomate.Graph.psm1'
    FunctionsToExport = @('New-YcMgAppReg', 'Set-YcMgAppRegCertificate', 'Send-YcMgEmail', 'New-YcMgMailMessageBody', 'New-YcSelfSignedCertForAppReg', 'New-YcRandomPassword', 'Import-YcCertToLocalMachine')
    Description = 'A GraphAPI Module that nests some functions together.'
    RequiredModules = @(
        @{
            ModuleName = 'Microsoft.Graph.Authentication'
            ModuleVersion = '2.17.0'
        }
        @{
            ModuleName = 'Microsoft.Graph.Applications'
            ModuleVersion = '2.17.0'
        }
        @{
            ModuleName = 'Microsoft.Graph'
            ModuleVersion = '5.2.2'
        }
    )
}