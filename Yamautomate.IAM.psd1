@{
    ModuleVersion = '1.0.0.2'
    GUID = 'bf93a78b-e608-4ceb-98ea-e96da66ef864'
    Author = 'Yanik Maurer'
    PowerShellVersion = '5.1'
    RootModule = 'Yamautomate.IAM.psm1'
    FunctionsToExport = @('New-YcAdUser', 'New-YcTeamsPhoneNumberAssignment')
    Description = 'Creates AD Users and assign Teams Phone Numbers.'
    RequiredModules = @(
        @{
            ModuleName = 'Yamautomate.Core'
            ModuleVersion = '1.0.6.2'
        }
        @{
            ModuleName = 'ActiveDirectory'
            ModuleVersion = '1.0.1.0'
        }
        @{
            ModuleName = 'MicrosoftTeams'
            ModuleVersion = '6.5.0'
        }
    )
}
