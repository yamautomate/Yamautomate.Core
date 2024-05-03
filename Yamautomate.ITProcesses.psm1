function New-YcUserOnboarding
{
param (
$Firstname
$Lastname
$Role
$Team
$Department
$StartDate
[json]$GroupMapping

- Creates AD User
- Provides needes groups based on Param and mapping from json
- Creates TAP
- Excludes User from InternalUserProtection CA Policies
- Provides LastPass access to shared folders
- If needed, creates a Proffix User
- If needed, creates a Wrike User
- If needed, assigns Teams Number
- If needed, provides Dynamic permissions
- If needed, creates SVN User
- If needed, provides SVN permissions
- If needed, provides GIT permissions
- 


function New-YcActiveDirectoryUser -Fistname Yanik -Lastname Maurer -OU SpeedgoatEmployees -Password -
#Requires Rights in AD to create Users and reset Passwords

function New-YcTemporaryAccessPass -User yanik.maurer -ValidFrom 1.1.2022 -ValidForHours 8 -secretName
#Requires Mg or Az Scope to generate a TAP for all users (except Admins?)

function Set-YcTeamsNumber -User yanik.maurer
#Requires Mg scope to assign Teams Number 

function Set-YcConditionalAccessExclusion -User yanik.maurer -ExcludeFrom InternalUserProtection -secretName
#Requires Mg scope to adjust CA Policies

function New-YcProffixUser -Firstname Yanik -Lastname Maurer -Role -EmailAddress yanik.maurer@speedgoat.ch
function Set-YcProffixUser -User YM -NewPassword -NewRole
function New-YcWrikeUser -EmailAddress -Type Collaborator -Groups
function New-YcSVNUser -Username ymaurer -Password -Groups Employees
function Set-YcD365Permissions -User yanik.maurer -Environment -Permissions
function Set-YcMathlabLicense -EmailAddress -AdminEmail -AdminPassword
function Set-YcEntraIDPassword -User yanik.maurer -NewPassword
function Set-YcExchangeOnlineArchive -User yanik.maurer -EnableOnlineArchive
function New-YcWelcomeLetter -User yanik.maurer 





