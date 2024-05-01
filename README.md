# Yamautomate.Core

My personal core module for logging, setting up config files, storing and accessing credentials and API Keys safely and more.

## Available Functions
| Function      | Description | Parameters |
| ------------- | ------------- |------------- |
| `Initialize-YcEventLogging`  | 	to follow |   |
| `YcLog-Event` 	 | 	to follow | |
| `Write-YcLogFile` | 	To follow| |
| `New-YcSecret`  | Generates a secure credential prompt to ask for clientSecret and stores it in Windows Credential Manager (default = system-wide)  |  |
| `Get-YcSecret`  | Retrieves a stord clientSecret to use	| |
| `Get-YcRequiredModules`  | Checks if required modules are imported. Does so if not. | |
| `Get-YcJsonConfig`  | Looks up calendar entries that are marked as OOF in a given timeframe (default = next 30 days) for a given user |  |
| `New-YcSampleConfig` | 	To follow | |
| `Convert-YcSecureStringToPlainText` | 	To follow | |
| `New-YcSelfSignedCertForAppReg` | 	To follow | |
| `New-YcRandomPassword` | 	To follow | |
| `Import-YcCertToLocalMachine` | 	To follow | |
| `Submit-YcFileForAzAiDiAnalysis` | 	To follow | |
| `Read-YcAzAiDiStringResponse` | 	To follow | |
| `Get-YcPatternFromAzAiDiAnalysis` | 	To follow | |
