function Get-GraphToken {
    <#
        .SYNOPSIS
        Get security tokens (access and/or refresh tokens) for Microsoft Graph.
        
        .DESCRIPTION
        Obtain Microsoft Identity Platform security tokens via OAuth 2.0 client credentials grant or authorization code grant flow (supports multi-factor auth).

        .PARAMETER tenantId
        Tenant identifier or a verified domain belonging to the tenant.

        .PARAMETER clientId
        Client/application Identifier.

        .PARAMETER Scopes
        (Optional) String of space-separated scopes for the resource, include 'offline_access' if you want to aquire a refresh_token. 

        .PARAMETER redirectUri
        (Optional) Address to return to upon receiving a response from the authority.

        .PARAMETER integratedWindowsAuth
        (Optional) Non-interactive request to acquire a security token for the signed-in user in Windows, via Integrated Windows Authentication.

        .PARAMETER RefreshToken
        (Optional) Provide refresh_token to obtain a new access_token (include offline_access scope to also renew the refresh_token).
        
        .PARAMETER Secret
        Shared Secret - for client credentials flow

        .PARAMETER Certificate
        location eg. 'Cert:\CurrentUser\My\THUMBPRINT' for Clients Credential Flow - Certificate 

        .EXAMPLE 
        Interactive Code flow that will prompt a user to sign in and return access_token.
        C:\PS>Get-GraphToken -tenantId $tenantId -clientId $clientId

        .EXAMPLE 
        Interactive Code flow that will return access_token and refresh_token.
        C:\PS>Get-GraphToken -tenantId $cspTenant -clientId $clientId -scopes "openid offline_Access"
        
        .EXAMPLE 
        Use refresh_token grant to retreive access_token and a renewed refresh_token.
        C:\PS>Get-GraphToken -tenantId $custTenant -clientId $clientId -refreshtoken $rt
    #>
    [cmdletbinding(DefaultParameterSetName='code')]
    param(
        [parameter(Position = 0, Mandatory = $true, ParameterSetName='code', HelpMessage="Domain or GUID")]
        [parameter(Position = 0, Mandatory = $true, ParameterSetName='secret', HelpMessage="Domain or GUID")]
        [parameter(Position = 0, Mandatory = $true, ParameterSetName='certificate', HelpMessage="Domain or GUID")]
        [string]$tenantId,
        
        [parameter(Position = 1, Mandatory = $false, ParameterSetName='code', HelpMessage="AppID")]
        [parameter(Position = 1, Mandatory = $false, ParameterSetName='secret', HelpMessage="AppID")]
        [parameter(Position = 1, Mandatory = $false, ParameterSetName='certificate', HelpMessage="AppID")]
        [string]$clientId = '1950a258-227b-4e31-a9cf-717495945fc2', # default = Microsoft Azure PowerShell ClientID
        
        [parameter(Mandatory = $false, ParameterSetName='code')]
        [parameter(Mandatory = $false, ParameterSetName='secret')]
        [parameter(Mandatory = $false, ParameterSetName='certificate')]
        [string]$scopes = 'https://graph.microsoft.com/.default',

        [parameter(Mandatory = $false, ParameterSetName='code')]
        [parameter(Mandatory = $false, ParameterSetName='secret')]
        [parameter(Mandatory = $false, ParameterSetName='certificate')]
        [string]$redirectUri = 'https://login.microsoftonline.com/common/oauth2/nativeclient',

        [parameter(Mandatory = $false, ParameterSetName='code')]
        [switch]$integratedWindowsAuth,

        [parameter(Mandatory = $false, ParameterSetName='code')]
        [string]$refreshToken,

        [parameter(Mandatory = $true, ParameterSetName='secret', HelpMessage="Shared secret")]
        [String]$Secret,

        [parameter(Mandatory = $true, ParameterSetName='certificate', HelpMessage="Location Cert:\CurrentUser\My\THUMBPRINT")]
        $Certificate
    )
    begin { 
        # Define requestBody
        $requestBody = @{}
        $requestBody.client_id = $clientId
        $requestBody.scope = $scopes
        
        # Define payload
        $payload = @{}
        $payload.uri     = "https://login.microsoftonline.com/$tenantId/oauth2/v2.0/token"
        $payload.method  = 'Post'    
    }
    process {
        if ( $secret ) {
            write-debug "client_credentials flow - secret: $($ClientId) $($tenantId)"
            $requestBody.grant_type = 'client_credentials'
            $requestBody.client_secret = $Secret
        }
        elseif ( $Certificate ) {
            # https://learn.microsoft.com/en-us/azure/active-directory/develop/v2-oauth2-client-creds-grant-flow
            write-debug "client credentials flow - certificate: $($ClientId) $($tenantId)"
            try { $Certificate = Get-Item $Certificate -ErrorAction Stop }
            catch { throw $_ }

            # Assertion header
            $jwtHeader = @{
                alg = "RS256"
                typ = "JWT"
                x5t = ConvertTo-Base64urlencoding $certificate.GetCertHash() # x.509 cert SHA-1 thumbprint
            } | ConvertTo-Json
            
            # time on or after which the jwt must not be accepted for processing
            $expUnixtime = [math]::Round((New-TimeSpan -Start (Get-Date "1970-01-01T00:00:00Z" ).ToUniversalTime() -End (Get-Date).ToUniversalTime().AddMinutes(5)).TotalSeconds,0)
            
            # Assertion payload
            $jwtClaims = @{
                aud = $payload.uri
                exp = $expUnixtime
                iss = $ClientId
                jti = [guid]::NewGuid() # unique identifier
                nbf = (New-TimeSpan -Start (Get-Date "1970-01-01T00:00:00Z" ).ToUniversalTime() -End ((Get-Date).ToUniversalTime())).TotalSeconds
                sub = $ClientId
            } | ConvertTo-Json

            # unsigned assertion (base64url encoded header and payload)
            $jwtAssertion = (ConvertTo-Base64urlencoding $jwtHeader) + "." + (ConvertTo-Base64urlencoding $jwtClaims)
            
            # System.Security.Cryptography.RSACryptoServiceProvider.SignData - assertion signature in accordance with RFC. 
            $signature = convertTo-Base64urlencoding $Certificate.PrivateKey.SignData([System.Text.Encoding]::UTF8.GetBytes($jwtAssertion),[Security.Cryptography.HashAlgorithmName]::SHA256,[Security.Cryptography.RSASignaturePadding]::Pkcs1) 

            # Finalize jwt and params.
            $requestBody.client_assertion = $jwtAssertion + "." + $Signature
            $requestBody.client_assertion_type = "urn:ietf:params:oauth:client-assertion-type:jwt-bearer"
            $requestBody.grant_type = "client_credentials"
        }
        else {
            Write-Debug "code authorization flow: $($ClientId) $($tenantId)" 

            # refresh_token grant
            if ( $refreshToken ) {
                $payload.headers = @{ 'Content-Type' = 'application/x-www-form-urlencoded' }
                $requestBody.grant_type    = 'refresh_token'
                $requestBody.refresh_token = $refreshToken
                $requestBody.redirect_uri = $redirectUri
            }

            # Code authorization flow (interactive)
            else {
                #https://learn.microsoft.com/en-us/azure/active-directory/develop/v2-oauth2-auth-code-flow
                Write-Debug "interactive flow"

                # Build codeflow payload
                $codeflowPayload = @{}
                # used to avoid cross site request forgery (not required, but recommended)
                $codeflowPayload.state = [guid]::NewGuid()
                # PKCE - code_challenge secret
                $codeflowPayload.Verifier = [guid]::NewGuid()
                # Load System.Security.Cryptograaphy.SHA256 
                $hashAlgorithm = [System.Security.Cryptography.HashAlgorithm]::Create('sha256')
                # Compute hash from secret
                $hashInBytes = $hashAlgorithm.ComputeHash([System.Text.Encoding]::ASCII.GetBytes($codeflowPayload.Verifier))
                # Convert hash to base64url encoding
                $codeflowPayload.CodeChallenge = ConvertTo-Base64urlencoding $hashInBytes

                # Indicates the type of user interaction that is required. Valid values are login, none, consent, and select_account.
                if ( $integratedWindowsAuth ) { $prompt = "none" }
                else { $prompt = "login" }

                # URL Encoding
                Add-Type -AssemblyName System.Web
                $redirectUriEncoded =  [System.Web.HttpUtility]::UrlEncode($redirectUri)
                $scopeEncoded = [System.Web.HttpUtility]::UrlEncode($scopes)
                $url = "https://login.microsoftonline.com/$tenantId/oauth2/v2.0/authorize?response_type=code&client_id=$ClientID&redirect_uri=$redirectUriEncoded&scope=$scopeEncoded&prompt=$prompt&state=$($codeflowPayload.state)&code_challenge=$($codeflowPayload.CodeChallenge)&code_challenge_method=S256"

                <# Auth dialog code (Windows.Forms/Web Interaction) has been lifted from @darrenjrobinson 
                https://gist.github.com/darrenjrobinson/b74211f98c507c4acb3cdd81ce205b4f #>
                [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
                
                Add-Type -AssemblyName System.Windows.Forms
                $form = New-Object -TypeName System.Windows.Forms.Form -Property @{Width = 440; Height = 640 }
                $web = New-Object -TypeName System.Windows.Forms.WebBrowser -Property @{Width = 420; Height = 600; Url = $url }
                
                # Close form on completion (nice!)
                $docCompletedEvent = {
                    $Global:uri = $web.Url.AbsoluteUri
                    if ($Global:uri -match "error=[^&]*|code=[^&]*") { $form.Close() }
                }
                $web.Add_DocumentCompleted($docCompletedEvent)
                
                $web.ScriptErrorsSuppressed = $true
                $form.Controls.Add($web)
                $form.Add_Shown( { $form.Activate() })
                $form.ShowDialog() | Out-Null
                # End of user interaction.

                $codeResponse = @{}
                $codeResponse.code = [System.Web.HttpUtility]::ParseQueryString($web.Url.Query)['code']
                $codeResponse.session_state = [System.Web.HttpUtility]::ParseQueryString($web.Url.Query)['session_state']
                $codeResponse.state = [System.Web.HttpUtility]::ParseQueryString($web.Url.Query)['state']
                if ( $codeResponse.state -ne $codeflowPayload.state ) { throw "state mismatch!"}
                
                $payload.headers = @{ 'Content-Type' = 'application/x-www-form-urlencoded' }
                $requestBody.redirect_uri  = $redirectUri
                $requestBody.grant_type    = "authorization_code"
                $requestBody.code_verifier = $codeflowPayload.Verifier
                $requestBody.code          = $CodeResponse.Code
            }
        }
        # Finalization of payload & delivery
        $payload.body = $requestBody
        $response = Invoke-RestMethod @payload
    }
    end {
        # Append expiry_datetime to response
        if ( $response.expires_in ) { $expDateTime = get-date -Format o (get-date).AddSeconds($response.expires_in) }
        if ( $response.expireson.DateTime ) { $expDateTime = get-date -format o $response.expireson.DateTime }
        $response | Add-Member -NotePropertyName expiry_datetime -TypeName NoteProperty $expDateTime
        return $response
    }
}