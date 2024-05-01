# Yamautomate.Core

My personal core module for logging, setting up configuration files, securely storing and accessing credentials, and managing other utilities.

## Features
Yamautomate.Core provides a comprehensive set of functions for managing various aspects of application logging, configuration, and credential storage. The module offers capabilities such as:

- **Logging:** Functions for event logging to the system or files, including log rotation and archiving.
- **Configuration:** Functions for retrieving JSON configuration files, creating sample configurations, and storing/retrieving settings.
- **Credential Management:** Functions for securely storing, retrieving, and converting secrets across various locations such as Azure Key Vault, Windows Credential Store or if needed Environment Variables
- **Azure Integrations:** Functions for connecting to Azure services, analyzing files with Azure AI Form Recognizer, and extracting key information.

## Available Functions

| Function                         | Description                                                                                                                    |
|----------------------------------|-------------------------------------------------------------------------------------------------------------------------------|
| `Get-YcRequiredModules`          | Checks for required PowerShell modules. If a specified module isn't installed or imported, it notifies the user or attempts to import it. |
| `Initialize-YcEventLogging`      | Sets up event logging by creating a source in a specified log. If the source doesn't exist, it creates it in the "Application" log by default. |
| `Log-Event`                      | Writes a new event log entry with a specified message, log name, source, entry type, and event ID. Processes the message through the `Protect-LogMessage` function before logging. |
| `Write-YcLogFile`                | Logs messages to a specified directory and file. Organizes logs by date and source, rotates the log file when it exceeds a specified size, and archives old logs. |
| `New-YcSecret`                   | Prompts the user to store a secret securely, defaulting to Windows Credential Store, with options for Environment Variables or Azure Key Vault. |
| `Get-YcSecret`                   | Retrieves a stored secret from one of three locations: Windows Credential Store, Environment Variable, or Azure Key Vault. |
| `Get-YcJsonConfig`               | Retrieves a JSON configuration file from a specified path and converts its content into a PowerShell object. Handles and logs errors. |
| `New-YcSampleConfig`             | Creates a sample configuration file at a specified path, including sections for event logging, Azure Key Vault, API settings, solution settings, and notifications. |
| `Convert-YcSecureStringToPlainText` | Converts a `SecureString` into a plain text string, using the System.Net.NetworkCredential class to extract the password value. |
| `New-YcSelfSignedCertForAppReg`  | Creates a self-signed certificate for application registration with a specified subject and validity period. Exports both `.pfx` and `.cer` files and returns the certificate's details. |
| `New-YcRandomPassword`           | Generates a random password of a specified length, defaulting to 32 characters, using a character set that includes uppercase and lowercase letters, digits, and special characters. |
| `Import-YcCertToLocalMachine`    | Imports a `.pfx` certificate into the Local Machine store using a secure password. Outputs a success message upon completion. |
| `Send-YcMgEmail`                 | Uses Microsoft Graph to send an email with specified content, subject, sender, and recipient addresses. |
| `New-YcMgMailMessageBody`        | Constructs an email message body dictionary for Microsoft Graph, including the subject, content type, content, and recipient details. |

# Yamautomate.AI
| Function                         | Description                                                                                                                    |
|----------------------------------|-------------------------------------------------------------------------------------------------------------------------------|
| `Submit-YcFileForAzAiDiAnalysis` | Submits a file or URL for analysis by Azure AI Form Recognizer, converts it into an appropriate format, and sends a POST request to the API. Returns relevant information or error details. |
| `Read-YcAzAiDiStringResponse`    | Processes a raw Azure API response into a consolidated object, extracting key information such as HTTP status, operation location, request ID, and content type. |
| `Get-YcPatternFromAzAiDiAnalysis`| Retrieves text content from an Azure AI Form Recognizer analysis and searches it for specified patterns. Returns an array of matched patterns. |
recipient details. |
| `Get-YcOpenAiResponse`           | Retrieves a response from the OpenAI API based on a specified query, with options for model, stop token, temperature, token limits, and response display preferences. |
