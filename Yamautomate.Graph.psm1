Function New-YcMgAppReg
{
    param (
        [Parameter(Mandatory=$true, Position = 0)] [ValidateNotNullOrEmpty()] [string]$ApplicationRegistrationDisplayName
    )

    $requiredModules = "Microsoft.Graph.Authentication", "Microsoft.Graph.Applications"
    Get-YcRequiredModules $requiredModules

    try {
        Connect-MgGraph -Scopes "Application.Read.All","Application.ReadWrite.All","User.Read.All"
        $AzureAppRegistration = New-MgApplication -DisplayName $ApplicationRegistrationDisplayName
    }
    catch {
        $Message = "Could not connect to Graph API and or could not create AppRegstistration: " +$ApplicationRegistrationDisplayName+" Error Details: "+$_.Exception.Message
        Write-Host $Message -ForegroundColor Red
    }
    finally {
        Disconnect-MgGraph
    }

    return $AzureAppRegistration
}

function Set-YcMgAppRegCertificate {
    Param(  
    [Parameter(Mandatory=$true, Position = 0)] [ValidateNotNullOrEmpty()] [string]$ApplicationRegistrationDisplayName,  
    [Parameter(Mandatory=$true, Position = 1)] [ValidateNotNullOrEmpty()][string]$CertificateThumbprint
    )  
  
    $requiredModules = "Microsoft.Graph.Authentication", "Microsoft.Graph.Applications"
    Get-YcRequiredModules $requiredModules

    # Load the certificate from the local store
    $LocalCert = Get-Item -Path Cert:\CurrentUser\My\$CertificateThumbprint

    # Create the credential object using the certificate's raw data
    $CertCredential = @{  
        Type = "AsymmetricX509Cert"  
        Usage = "Verify"  
        Key = $LocalCert.RawData  
    }  
    
    try {
        Connect-MgGraph -Scopes "Application.Read.All","Application.ReadWrite.All","User.Read.All"
        $AzureAppRegistration = Get-MgApplication -Filter "DisplayName eq '$($ApplicationRegistrationDisplayName)'"
    
        # Update the application registration with the new key credentials
        Update-MgApplication -ApplicationId $AzureAppRegistration.Id -KeyCredentials @($CertCredential)
    }
    catch {
        $Message = "Could not connect to Graph API and or could not update AppRegstistration: " +$ApplicationRegistrationDisplayName+ "with Certificate: "+$CertificateThumbprint+" Error Details: "+$_.Exception.Message
        Write-Host $Message -ForegroundColor Red
    }
    finally {
        Disconnect-MgGraph      
    }
}  

Function Send-YcMgEmail{
    <#
    .SYNOPSIS
    The Send-YcMgEmail function sends an email using Microsoft Graph.
 
    .DESCRIPTION
    The Send-YcMgEmail function uses Microsoft Graph to send an email. 
    It accepts mandatory parameters for the email message, subject, from address, and to address. 
    Further mandatory parameters include a client ID, client secret name, and tenant ID for Microsoft Graph authentication. 
    The function connects to Microsoft Graph, constructs the email message body, sends the message, and then disconnects from Microsoft Graph.
 
    .PARAMETER clientId
    The clientId parameter is a mandatory string specifying the client ID for Microsoft Graph authentication.
 
    .PARAMETER clientSecretName
    The clientSecretName parameter is a mandatory  string specifying the name of the client secret for Microsoft Graph authentication.
 
    .PARAMETER tenantId
    The tenantId parameter is a mandatory  string specifying the tenant ID for Microsoft Graph authentication.
 
    .PARAMETER message
    The message parameter is a mandatory string specifying the content of the email.
 
    .PARAMETER subject
    The subject parameter is a mandatory string specifying the subject of the email.
 
    .PARAMETER from
    The from parameter is a mandatory string specifying the sender's address.
 
    .PARAMETER to
    The to parameter is a mandatory string specifying the recipient's address.
 
    .INPUTS
    The function does not accept any pipeline input.
 
    .OUTPUTS
    The function does not output any return value directly but sends an email via Microsoft Graph.
 
    .EXAMPLE
    The following example shows how to send an email:
 
    PS> Send-YcMgEmail -clientId "your-client-id" -clientSecretName "your-client-secret" -tenantId "your-tenant-id" -message "Hello, world!" -subject "Greeting" -from "sender@example.com" -to "recipient@example.com"
 
    #>
    param(
        [Parameter(Mandatory=$true, Position = 0)] [ValidateNotNullOrEmpty()] [string]$clientId,
        [Parameter(Mandatory=$true, Position = 1)] [ValidateNotNullOrEmpty()] [string]$clientSecretName,
        [Parameter(Mandatory=$true, Position = 2)] [ValidateNotNullOrEmpty()] [string]$tenantId,
        [Parameter(Mandatory=$true, Position = 3)] [ValidateNotNullOrEmpty()] [string]$message,
        [Parameter(Mandatory=$true, Position = 4)] [ValidateNotNullOrEmpty()] [string]$subject,
        [Parameter(Mandatory=$true, Position = 5)] [ValidateNotNullOrEmpty()] [string]$from,
        [Parameter(Mandatory=$true, Position = 6)] [ValidateNotNullOrEmpty()] [string]$to
    )
 
    $requiredModules = "Microsoft.Graph"
    Get-YcRequiredModules $requiredModules
 
    $messageBody = New-YcMgMailMessageBody -message $message -subject $subject -to $to 
 
    try {
        Connect-MgGraph -ClientId $clientId -ClientSecret $clientSecret -TenantId $tenantId
        New-MgUserMessageSend -UserId $from -BodyParameter $messageBody
    }
    catch {
        $Message = "Could not connect to Graph API and or send E-Mail. Error Details: "+$_.Exception.Message
        Write-Host $Message -ForegroundColor Red
    }
    finally {
        Disconnect-MgGraph
    }
 }
function New-YcMgMailMessageBody {
    <#
    .SYNOPSIS
    The New-YcMgMailMessageBody function constructs an email message body for Microsoft Graph.
 
    .DESCRIPTION
    The New-YcMgMailMessageBody function constructs a dictionary that represents an email message body for Microsoft Graph. 
    It accepts mandatory parameters for the message content, subject, and recipient address. 
    The function constructs a dictionary with fields for the subject, content type, content, and recipient details, and returns this dictionary as output.
 
    .PARAMETER message
    The message parameter is a mandatory string specifying the content of the email.
 
    .PARAMETER subject
    The subject parameter is a mandatory string specifying the subject of the email.
 
    .PARAMETER to
    The to parameter is a mandatory string specifying the recipient's email address.
 
    .INPUTS
    The function does not accept any pipeline input.
 
    .OUTPUTS
    The function returns a dictionary representing the email message body.
 
    .EXAMPLE
    The following example shows how to construct an email message body:
 
    PS> New-YcMgMailMessageBody -message "Hello, world!" -subject "Greeting" -to "recipient@example.com"
    #>
 
    param (
        [Parameter(Mandatory=$true, Position = 0)] [ValidateNotNullOrEmpty()] [string]$message,
        [Parameter(Mandatory=$true, Position = 1)] [ValidateNotNullOrEmpty()] [string]$subject,
        [Parameter(Mandatory=$true, Position = 2)] [ValidateNotNullOrEmpty()] [string]$to
    )
 
    $message = @{
        Message = @{
            Subject = $subject
            Body = @{
                ContentType = "Text"
                Content = $message
            }
            ToRecipients = @(
                @{
                    EmailAddress = @{
                        Address = $to
                    }
                }
            )
        }
    }
 
    return $message
    
}