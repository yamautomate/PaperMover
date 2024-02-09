# PaperMover
Extracts a given pattern via OCR (Azure Document Intelligence Services) and moves files to an according folder.

It leverages the following components:
- Windows Powershell (100% written in it)
- Azure AI Document Intelligence Services
- UNCPath for files to process and store
- A printer that can do Scan2Folder
- A Scheduled Task on a VM
- An Entra ID App Registration to send E-Mails via Graph
- A Shared Mailbox: To send E-Mails from
- Mail-enabled Security Group: acts as a securitywrapper to only permit access to shared Mailbox
- Exchange Online Application access policy: To restruct access only to shared mailbox for the App registration

# Prerequisites
- An available Azure AI Document Intelligence Servie Endpoint
- API Key for Azure AI Document Intelligence Service

# Setup
- Define EnvironmentVariable "env:FR_KEY":
```powershell
Set-Item -path env:FR_KEY -Value "YOUR_API_KEY"
```
- Define EnvironmentVariable "env:FR_ENDPOINT":
```Powershell
Set-Item -path env:FR_ENDPOINT -Value "https://Your_URL.cognitiveservices.azure.com"
```
- Create EventLog
```powershell
New-EventLog -LogName "Custom Automation" -Source "PaperMover"
```
