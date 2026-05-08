param(
    [Parameter(Mandatory=$true)]
    [ValidateSet("server", "client")]
    $side,
    $expr,
    $chatId,
    [ValidateSet($true, $false)]
    $forever
)

if ($env:dev_script_token_client -And $env:dev_script_token_server) {
	Write-Host "Both dev_script_token_client and dev_script_token_server are present in env! Security Issue!";
	Exit 1;
}

$id_client = $env:dev_script_id_client
$id_server = $env:dev_script_id_server

$me_id = $null
$me_data = $null
$other_id = $null

$devUrlMain = $env:dev_script_url_main;
$devUrlDDownload = $env:dev_script_url_download;

# Define your side token
$myToken = if ($env:dev_script_token_client) { $env:dev_script_token_client } else { $env:dev_script_token_server }
$apiUrl = "${devUrlMain}${myToken}"

# The secret between server and client
$secret_old = $env:dev_script_mutual_secret_old
$secret_new = $env:dev_script_mutual_secret_new

# Used to cipher contents
$password_old = $env:dev_script_cipher_password_old
$password_new = $env:dev_script_cipher_password_new

# Read data from desc, send logs or ...
$dataChatId = $env:dev_script_data_chat_id

# E.g. 'python -m httpie'
$httpie = $env:dev_script_httpie

if (-Not $myToken -Or -Not $id_client -Or -Not $id_server -Or -Not $dataChatId -Or -Not $httpie `
    -Or -Not $devUrlMain -Or -Not $devUrlDDownload `
    -Or (
	-Not ($secret_old -And $password_old) -And 
	-Not ($secret_new -And $password_new)
)) {
	Write-Host @"
Some env vars not set! Check:

dev_script_token_[ client | server ]
dev_script_mutual_secret_[ old | new ]
dev_script_cipher_password_[ old | new ]
dev_script_id_[ client | server ]
dev_script_url_main
dev_script_url_download
dev_script_data_chat_id
dev_script_httpie
"@
	Exit 1
}

$DATE_FORMAT_M = 'yyyy-MM-dd HH-mm-ss.fff'

# - # - # - # - # - # -------------------
# - # - # - # - # - # - HELPER FUNCTIONS
# - # - # - # - # - # -------------------

function Crypto-GetSHA256Hash {
    param(
        [string]$inputString
    )
    $bytes = [System.Text.Encoding]::UTF8.GetBytes($inputString)
    $sha256 = [System.Security.Cryptography.SHA256]::Create()
    $hashBytes = $sha256.ComputeHash($bytes)
    return [System.BitConverter]::ToString($hashBytes).Replace("-", "").ToLower()
}

function Crypto-Encrypt {
    param(
        [string] $plainText,
        [string] $password,
        [byte[]] $salt  # Optional: provide your own salt, otherwise random
    )

    try {
        # Generate random salt if not provided (16 bytes recommended)
        if (-not $salt) {
            $salt = [byte[]]::new(16)
            [System.Security.Cryptography.RandomNumberGenerator]::Create().GetBytes($salt)
        }
        
        # Derive key and IV from password using PBKDF2
        $iterations = 1000  # Adjust for security/performance balance
        $derive = [System.Security.Cryptography.Rfc2898DeriveBytes]::new($password, $salt, $iterations)
        $key = $derive.GetBytes(32)  # 32 bytes for AES-256
        $iv = $derive.GetBytes(16)   # 16 bytes for AES IV
        
        # Encrypt
        $aes = [System.Security.Cryptography.Aes]::Create()
        $aes.Key = $key
        $aes.IV = $iv
        $aes.Padding = [System.Security.Cryptography.PaddingMode]::PKCS7
        
        $encryptor = $aes.CreateEncryptor()
        $ms = New-Object System.IO.MemoryStream
        
        # Prepend salt to ciphertext (needed for decryption)
        $ms.Write($salt, 0, $salt.Length)
        
        $cs = New-Object System.Security.Cryptography.CryptoStream($ms, $encryptor, [System.Security.Cryptography.CryptoStreamMode]::Write)
        $sw = New-Object System.IO.StreamWriter($cs, [System.Text.UTF8Encoding]::new($false))
        
        $sw.Write($plainText)

	Invoke-Close $sw, $cs, $ms

        return [System.Convert]::ToBase64String($ms.ToArray())
    } catch {
	Invoke-Close $sw, $cs, $ms

	throw
    }
}

function Crypto-Decrypt {
    param(
        [string] $cipherText,
        [string] $password
    )

    try {
        # Convert from base64
        $cipherBytes = [System.Convert]::FromBase64String($cipherText)
        
        # Extract salt (first 16 bytes)
        $salt = $cipherBytes[0..15]
        
        # Extract actual ciphertext (remaining bytes)
        $actualCipherBytes = $cipherBytes[16..($cipherBytes.Length - 1)]
    
        # Derive key and IV using same parameters as encryption
        $iterations = 1000
        $derive = [System.Security.Cryptography.Rfc2898DeriveBytes]::new($password, $salt, $iterations)
        $key = $derive.GetBytes(32)
        $iv = $derive.GetBytes(16)
        
        # Decrypt
        $aes = [System.Security.Cryptography.Aes]::Create()
        $aes.Key = $key
        $aes.IV = $iv
        $aes.Padding = [System.Security.Cryptography.PaddingMode]::PKCS7
        
        $decryptor = $aes.CreateDecryptor()
        $ms = [System.IO.MemoryStream]::new($actualCipherBytes)

        $cs = New-Object System.Security.Cryptography.CryptoStream($ms, $decryptor, [System.Security.Cryptography.CryptoStreamMode]::Read)
        $sr = New-Object System.IO.StreamReader($cs, [System.Text.UTF8Encoding]::new($false))
        
        $plainText = $sr.ReadToEnd()
    
	    Invoke-Close $sr, $cs, $ms
    
        return $plainText
    } catch {
	    Invoke-Close $ms, $cs, $sr

        if ("$_" -Contains 'Padding is invalid and cannot be removed') {
            throw 'Maybe wrong password. $_'
        }
	    throw
    }
    
}

# Only adds new vars (current ones stay the same)
Function Var-Reload {
    # Step 1: Save current Process-level variables
    $currentProcessVars = @{}
    [Environment]::GetEnvironmentVariables("Process").GetEnumerator() | ForEach-Object {
        $currentProcessVars[$_.Key] = $_.Value
    }
    
    # Step 2: Apply User and Machine variables
    ForEach ($level in "User", "Machine") {
        [Environment]::GetEnvironmentVariables($level).GetEnumerator() | ForEach-Object { 
            # Only set if not already exists in Process? Or always set?
            # For "add only new vars" - check if exists
            if (-not $currentProcessVars.ContainsKey($_.Key)) {
                [Environment]::SetEnvironmentVariable($_.Key, $_.Value, "Process")
            }
        }
    }
    
    # Step 3: Restore original Process vars (they might have been overwritten)
    # But if you used the check above, they weren't overwritten
    # If you want to ensure original values are preserved:
    $currentProcessVars.GetEnumerator() | ForEach-Object {
        [Environment]::SetEnvironmentVariable($_.Key, $_.Value, "Process")
    }

	Write-Host "Reloaded (new variables only) in current powershell session."
}

Function Var-Set {
	param(
		[Parameter(Mandatory=$true)]
		$key,
		[Parameter(Mandatory=$true)]
		$value,
		$level
	)

	[Environment]::SetEnvironmentVariable($key, $value, $level)
	[Environment]::SetEnvironmentVariable($key, $value, "Process")

	Write-Host "Saved. Updated in current powershell session."
}

Function Var-Get {
	param(
		[Parameter(Mandatory=$true)]
		$key,
		$level

	)

	[Environment]::GetEnvironmentVariable($key, $level)
}

Function Invoke-Close {
    param(
	[Object[]] $closeables
    )

    $closeables | ForEach-Object {
        try {
            if ($_.Close) { $_.Close() }
            if ($_.Dispose) { $_.Dispose() }
        } catch {}
    }
}

# Only env vars are crossed, other things are isolated
Function Invoke-ExpressionWithTimeout {
    param(
        [Parameter(Mandatory=$true)]
        [string] $command,
        [Parameter(Mandatory=$true)]
        [int] $TimeoutSeconds,
        [object] $ParamList = $null,
        $ErrAc = 'Stop'
    )
    
    $psh = [System.Management.Automation.PowerShell]::Create()
    
    try {
        # Add the script to run
        $psh.AddScript({
            param($paramList)

            $paramList.GetEnumerator() | ForEach-Object {
                Set-Variable -Name $_.Key -Value $_.Value
            }

            $ErrorActionPreference = $ErrAc

            return Invoke-Expression -Command $command184262
        }).AddArgument(@{
            command184262 = $command
            ErrAc = $ErrAc 
        } + $(if ($ParamList) { $ParamList } else { @{} } )) | Out-Null
        
        # Start async execution (non-blocking)
        $asyncResult = $psh.BeginInvoke()
        
        # Wait with timeout
        $waitHandle = $asyncResult.AsyncWaitHandle
        if ($waitHandle.WaitOne($TimeoutSeconds * 1000)) {
            # Completed within timeout
            $result = $psh.EndInvoke($asyncResult)
            
            # Capture all output streams and merge them into main stdout
            $psh.Streams.Information | ForEach-Object { Write-Host $_.MessageData }
            $psh.Streams.Warning | ForEach-Object { Write-Warning $_ }
            $psh.Streams.Verbose | ForEach-Object { Write-Verbose $_ }
            $psh.Streams.Debug | ForEach-Object { Write-Debug $_ }
            $psh.Streams.Error | ForEach-Object { Write-Error $_ }

            return $result
        } else {
            # Timed out - kill it
            $psh.Stop()
            Throw "Command timed out after $TimeoutSeconds seconds"
        }
    }
    finally {
        Invoke-Close $psh
    }
}

Function Replace-Tag-Data {
    param(
        $contentString,
        $key,
        $value
    )
    
    # If <>
    if ([regex]::Match($contentString, '^\s*\<[^\>]*\>').Success) {
        # If <... key:value>
        if ([regex]::Match($contentString, $('^\s*\<[^\>]*(?<![0-9a-zA-Z]>)' + $key)).Success) {
            
            return $contentString -Replace $('^(\s*\<[^\>]*(?<![0-9a-zA-Z>])' + $key + ')\s*:\s*([^\s>]+)'), $('$1:' + $value)
        } else {
            return $contentString -Replace '^(\s*\<[^\>]*)', $('$1 ' + $key + ':' + $value)
        }
    } else {
        return "<${key}:${value}>$contentString"
    }
}

# - # - # - # - # - # -----------
# - # - # - # - # - # - MAIN APIS
# - # - # - # - # - # -----------


function Get-Me {
    write-host "$apiUrl/getMe"
    $response = Invoke-RestMethod -Uri "$apiUrl/getMe"
    return $response.result
}

function Get-File {
    param(
        [string]$fileId
    )
    $response = Invoke-RestMethod -Uri "$apiUrl/getFile" -Body @{ file_id = $fileId }
    return $response.result
}

function Download-FileContent {
    param(
        [string]$filePath
    )

    $fileUrl = "${devUrlDDownload}${myToken}/${filePath}"
    $response = Invoke-RestMethod -Uri $fileUrl
    return $response # This returns the raw content of the file
}

function Send-Document {
    param(
        $chatId,
        [string] $filePath,
        [string] $caption = "",
        $ReplyTo
    )
    
    # NEVER USE POWERSHELL'S (INVOKE-REST* | INVOKE-WEB*) FOR MULTIPART

    $addr = "$apiUrl/sendDocument"

    if ($ReplyTo) { $addr += "?reply_to_message_id=$ReplyTo" }

    $cmnd = "$httpie -h --timeout 5 --multipart POST '$addr' 'document@$filePath' 'caption=$caption' 'chat_id=$chatId'"

    $result = Invoke-Expression $cmnd

    if (-Not $result) {
        Throw "Sending $filePath to $chatId failed#"
    }

    $status = [regex]::Match($result, '\b[0-9]{3}\b').Value

    if (-Not ($status -in 200..299) ) {
        Throw "Sending $filePath to $chatId failed ($status)"
    }

    return $status
}


function Get-Updates {
    param(
        [int]$offset,
        [int]$limit
    )

    $response = Invoke-RestMethod -Uri "$apiUrl/getUpdates" -Body (@{ offset = $offset } + $(if ($limit) { @{ limit = $limit } } else { @{} }))
    return $response.result
}

function Get-Chat {
    param(
        $chatId
    )
    $response = Invoke-RestMethod -Uri "$apiUrl/getChat" -Body @{ chat_id = $chatId }
    return $response.result
}

function Send-Message {
    param(
        $chatId,
        [string]$text,
        $ReplyTo
    )

    $body = @{ chat_id = $chatId ; text = $text }

    if ($ReplyTo) {
        $body += @{ reply_to_message_id = $ReplyTo }
    }

    Invoke-RestMethod -Uri "$apiUrl/sendMessage" -Body $body
}

function Process-Message {
    param(
	$update,
        $message
    )

# Write-Host *!*!*! $($message | ConvertTo-Json -depth 10)

    $chatId = $message.chat.id
    $replyTo = $message.message_id

    # $message.from.username -in $id_client, $id_server
    if ($chatId -eq $dataChatId -And $message.text) {

        $mat = [regex]::Match($message.text.trim(), '([^\n]+)\n([\s\S]+)')
        $hash = $mat.groups[1].value
        $expr = $mat.groups[2].value

        $exprLength = $expr.Length

	    if ($expr -And
            (
                ((($password = $password_new) -Or $true) -And ($hash -eq (Crypto-GetSHA256Hash -inputString "${secret_new}-${exprLength}-${other_id}"))) -Or
	            ((($password = $password_old) -Or $true) -And ($hash -eq (Crypto-GetSHA256Hash -inputString "${secret_old}-${exprLength}-${other_id}"))) 
            )
        ) {
            $decryptedExpr = Crypto-Decrypt -cipherText $expr -password $password

            $mat2 = [regex]::Match($decryptedExpr, '^\s*\<\s*([^\>]*)\s*\>\s*([\s\S]+)')

            if (-Not $mat2.Success) { return -1 }

            $sender_id = [regex]::Match($mat2.groups[1].value, '(?<![0-9a-zA-Z])id\s*:\s*(\S+)').groups[1].value

            if (-Not $sender_id) { return -2 }

            if ($sender_id -eq $me_id) { return -3 }

            if ([regex]::Match($mat2.groups[1].value, '^script-run').Success) {

                $timeout = [regex]::Match($mat2.groups[1].value, '(?<![0-9a-zA-Z])t\s*:\s*(\d+)').groups[1].value

                if (-Not $timeout) { $timeout = 10 } else { $timeout = [int] $timeout }

	            $result = Invoke-ExpressionWithTimeout -Command $mat2.groups[2].value -TimeoutSeconds $timeout

	            if ($result) {

                    $result = Replace-Tag-Data -contentString $result -key 'id' -value $me_id

                    $encryptedResult = Crypto-Encrypt -plainText $result -password $password_new

                    Send-Message -chatId $chatId -text ((Crypto-GetSHA256Hash -inputString "${secret_new}-$($encryptedResult.Length)-${me_id}") + "`n" + $encryptedResult) -ReplyTo $replyTo | Out-Null
                }                
            } else {

                Write-Host "<message-show>" "<$(Get-Date -Format $DATE_FORMAT_M)>" $decryptedExpr
            }

	        return;
	    }
    }
    

    # Only process messages with documents
    if (-not $message.document) {
        # Write-Host "Message has no document. Ignoring."
        return 1
    }

    # Only process messages with captions
    if (-not $message.caption) {
        # Write-Host "Message has no caption. Ignoring."
        return 2
    }

    $fileId = $message.document.file_id
    $file_name = $message.document.file_name
    $fileSize = $message.document.file_size
    $caption = $message.caption

    # Validate hash in caption
    if ( 
	((($password = $password_new) -Or $true) -And ($caption -ne (Crypto-GetSHA256Hash -inputString "${secret_new}-${fileSize}-${other_id}"))) -And
	((($password = $password_old) -Or $true) -And ($caption -ne (Crypto-GetSHA256Hash -inputString "${secret_old}-${fileSize}-${other_id}"))) 
    ) {

        # Write-Host "Caption hash '$caption' does not match expected hash '$expectedHash'. Ignoring."
        return 3
    }
    
    Write-Host "Processing file with valid hash ${file_name}|${fileId}|${fileSize} ~($([int]($fileSize / 1KB)) KB)"

    $fileInfo = Get-File -fileId $fileId
    $filePath = $fileInfo.file_path

    # Download file content
    $downloadedContent = Download-FileContent -filePath $filePath

    # Decrypt content
    $decryptedContent = Crypto-Decrypt -cipherText $downloadedContent -password $password

    # Invoke
    $mat3 = [regex]::Match($decryptedContent, '^\s*\<\s*([^\>]*)\s*\>\s*([\s\S]+)')

    if (-Not $mat3.Success) { return 4 }

    $sender_id = [regex]::Match($mat3.groups[1].value, '(?<![0-9a-zA-Z])id\s*:\s*(\S+)').groups[1].value

    if (-Not $sender_id) { return 5 }

    if ($sender_id -eq $me_id) { return 6 }

    if ([regex]::Match($mat3.groups[1].value, '^script-run').Success) {

        $timeout = [regex]::Match($mat3.groups[1].value, '(?<![0-9a-zA-Z])t\s*:\s*(\d+)').groups[1].value

        if (-Not $timeout) { $timeout = 10 } else { $timeout = [int] $timeout }

	    $result = Invoke-ExpressionWithTimeout -Command $mat3.groups[2].value -TimeoutSeconds $timeout
              
    } else {

        Write-Host "<message-show>" "<$(Get-Date -Format $DATE_FORMAT_M)>" $decryptedContent

        $result = $null
    }
    
    # Send result
    if ($result) {
        try {
            # Encrypt result
            $result = Replace-Tag-Data -contentString $result -key 'id' -value $me_id
            $encryptedResult = Crypto-Encrypt -plainText $result -password $password_new

            $tempFilePath = Join-Path $env:TEMP "U$(Get-Date -Format $DATE_FORMAT_M).zip"
            [System.IO.File]::WriteAllText($tempFilePath, $encryptedResult)
    
	        $sizeInBytes = $(Get-Item $tempFilePath).Length

            $newCaptionHash = Crypto-GetSHA256Hash -inputString "${secret_new}-$sizeInBytes-${me_id}"
    
            # Send processed file
            Send-Document -chatId $chatId -filePath $tempFilePath -caption $newCaptionHash -ReplyTo $replyTo | Out-Null
        } catch {
            Write-Host "Error sending document: $_"
        }

	    if ($tempFilePath) { Remove-Item $tempFilePath -ErrorAction SilentlyContinue }
    }
}

# Usage Send-Error-Wrap -ExpBlock { Send-Message -chatId $dataChatId -text "Get-Updates error: $_" | Out-Null }
Function Send-Error-Wrap {
    param($ExpBlock)

    Write-Host Error $_ $_.ScriptStackTrace
    try {
        & $ExpBlock        
    } catch {
        Write-Host Error $_ $_.ScriptStackTrace
    }

}


# - # - # - # - # - # ------------
# - # - # - # - # - # - EXECUTION
# - # - # - # - # - # ------------


Function Exec-Server {
    param(
        $forever = $true
    )

    $lastUpdateId = 0

    try {

        Write-Host "Listening for updates..."    

        while ($true) {

            Start-Sleep -MilliSeconds 500

            try {
                $updates = Get-Updates -offset $lastUpdateId
            } catch {
                Send-Error-Wrap -ExpBlock { Send-Message -chatId $dataChatId -text "Get-Updates error: $_" | Out-Null }

                Start-Sleep -MilliSeconds 500

                Continue;
            }

# $updates | ConvertTo-Json -Depth 10

            if (-Not $updates) {
                if ($forever) {
                    continue;
                } else {
                    Write-Host "Done updates"
                    break;
                }
            }
    
            Write-Host "Processing $(@($updates).Count) updates... $(Get-Date -Format $DATE_FORMAT_M)"
    
            foreach ($update in $updates) {

                $lastUpdateId = $update.update_id + 1
                $message = $update.message
        
                if ($message) {

# $update | ConvertTo-Json -Depth 10;

                    try {
                        $result = Process-Message -update $update -message $message

        		        if ($result) { Write-Host "$(Get-Date -Format $DATE_FORMAT_M) - Error# $result" }
                    } catch {
                        Send-Error-Wrap -ExpBlock {
                            if ($dataChatId) {
                                Send-Message -chatId $dataChatId -text "message: $message , error: $_" -ReplyTo $message.message_id | Out-Null
                            }
                        }
                    }

                }

            }
    
        }

        if ($lastUpdateId) { Get-Updates -offset $lastUpdateId -limit 1 | Out-Null }

    } catch {
        Send-Error-Wrap -ExpBlock {
            if ($dataChatId) {
                Send-Message -chatId $dataChatId -text "$_ $($_.ScriptStackTrace)" | Out-Null
            }
        }
    }
}

Function Exec-Client {
    param(
        [Parameter(Mandatory=$true)]
        $expr,
        [Parameter(Mandatory=$true)]
        $chatId
    )

        try {

            # Encrypt expr
            $expr = Replace-Tag-Data -contentString $expr -key 'id' -value $me_id
            $encryptedExpr = Crypto-Encrypt -plainText $expr -password $password_new

            $tempFilePath = Join-Path $env:TEMP "E$(Get-Date -Format $DATE_FORMAT_M).zip"
            [System.IO.File]::WriteAllText($tempFilePath, $encryptedExpr)
    
	        $sizeInBytes = $(Get-Item $tempFilePath).Length

            $newCaptionHash = Crypto-GetSHA256Hash -inputString "${secret_new}-$sizeInBytes-${me_id}"

            # Send processed file
            Send-Document -chatId $chatId -filePath $tempFilePath -caption $newCaptionHash | Out-Null



            # $expr = Replace-Tag-Data -contentString $expr -key 'id' -value $me_id
            # $encryptedExpr = Crypto-Encrypt -plainText $expr -password $password_new

            # Send-Message -chatId $chatId -text ((Crypto-GetSHA256Hash -inputString "${secret_new}-$($encryptedExpr.Length)-${me_id}") + "`n" + $encryptedExpr) | Out-Null

        } catch {
            Send-Error-Wrap -ExpBlock {
                if ($dataChatId) {
                    Send-Message -chatId $dataChatId -text "$_ $($_.ScriptStackTrace)" | Out-Null
                }
            }
        }

        if ($tempFilePath) { Remove-Item $tempFilePath -ErrorAction SilentlyContinue }

}

$me_data = Get-Me
$me_id = $me_data.username
if (-Not $me_id) { Write-Host 'Who am I?'; Exit 1 }
$other_id = if ($id_client -eq $me_id) { $id_server } else { if ($id_server -eq $me_id) { $id_client } else { Write-Host 'Who is who?'; Exit 1 } }


$m = "Exec-$side"

$argus = @{}
if ($expr -ne $null) { $argus['expr'] = $expr }
if ($chatId -ne $null) { $argus['chatId'] = $chatId }
if ($forever -ne $null) { $argus['forever'] = $forever }

& $m @argus
