# msgraph-powershell-auth
Lightweight graph authentication, get security tokens (access/refresh) directly from the protocol by authorization code with PKCE, client credentials or refresh_token grant.

## Usage
Install module from PowerShell Gallery or download release. 

## Examples

### Interactive Code flow that will return access_token and refresh_token.
![](https://github.com/alflokken/msgraph-powershell-auth/blob/main/.readme/code_interactive.gif)

### Interactive Code flow using integrated windows authentication. 
![](https://github.com/alflokken/msgraph-powershell-auth/blob/main/.readme/code_iwa.gif)

### client credentials
```
# Using Application Secret
C:\PS>Get-GraphToken -tenantId $tenantId -clientId $clientId -secret "IBJ6X~jddSYYnXok1Ryd4cWmGAf6"

# Using Client Certificate
C:\PS>Get-GraphToken -TenantId $tenantid -ClientId $clientId -Certificate "Cert:\CurrentUser\My\FS1G1267565552F2XA055552DA42F0F555CDD3E2"
```