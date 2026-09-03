# Minimal LSP probe: spawn rust-analyzer, send didOpen with broken code,
# capture ALL responses to see what diagnostics it actually emits.

$ErrorActionPreference = 'Stop'

$ws = "C:\Users\robin\AppData\Local\Temp\anubis-manual-probe-$([System.Guid]::NewGuid().ToString('N').Substring(0,8))"
New-Item -ItemType Directory -Path "$ws\src" -Force | Out-Null
@"
[package]
name = "manual_probe"
version = "0.0.0"
edition = "2021"
[lib]
path = "src/lib.rs"
"@ | Set-Content -Path "$ws\Cargo.toml" -Encoding utf8
"" | Set-Content -Path "$ws\src\lib.rs" -Encoding utf8

Write-Host "Workspace: $ws"

$psi = New-Object System.Diagnostics.ProcessStartInfo
$psi.FileName = "C:\Users\robin\.cargo\bin\rust-analyzer.exe"
$psi.RedirectStandardInput = $true
$psi.RedirectStandardOutput = $true
$psi.RedirectStandardError = $true
$psi.UseShellExecute = $false
$psi.CreateNoWindow = $true

$proc = [System.Diagnostics.Process]::Start($psi)

function Send-Msg($proc, $obj) {
    $json = $obj | ConvertTo-Json -Compress -Depth 10
    $bytes = [System.Text.Encoding]::UTF8.GetBytes($json)
    $header = "Content-Length: $($bytes.Length)`r`n`r`n"
    $proc.StandardInput.Write($header)
    $proc.StandardInput.BaseStream.Write($bytes, 0, $bytes.Length)
    $proc.StandardInput.Flush()
    Write-Host "[SENT] $json"
}

$rootUri = "file:///" + ($ws -replace '\\', '/')

# 1. initialize
Send-Msg $proc @{
    jsonrpc = "2.0"
    id = 1
    method = "initialize"
    params = @{
        processId = $PID
        rootUri = $rootUri
        capabilities = @{}
    }
}

# 2. initialized
Send-Msg $proc @{
    jsonrpc = "2.0"
    method = "initialized"
    params = @{}
}

Start-Sleep -Seconds 5  # let it index

# 3. write probe code to disk
$probe = "fn probe() { let v = vec![1,2,3]; v.fabricated_method(); }"
Set-Content -Path "$ws\src\lib.rs" -Value $probe -Encoding utf8
Write-Host "Wrote probe to disk: $probe"

Start-Sleep -Seconds 2  # let file watcher detect

# 4. didOpen with the probe code
$libUri = "file:///" + ($ws -replace '\\', '/') + "/src/lib.rs"
Send-Msg $proc @{
    jsonrpc = "2.0"
    method = "textDocument/didOpen"
    params = @{
        textDocument = @{
            uri = $libUri
            languageId = "rust"
            version = 1
            text = $probe
        }
    }
}

Write-Host "Waiting 30s for publishDiagnostics..."
$deadline = (Get-Date).AddSeconds(30)
while ((Get-Date) -lt $deadline) {
    Start-Sleep -Milliseconds 200
    while ($proc.StandardOutput.BaseStream.CanRead -and $proc.StandardOutput.BaseStream.DataAvailable) {
        # Read header
        $headerLine = $proc.StandardOutput.ReadLine()
        if (-not $headerLine) { continue }
        if ($headerLine -match "Content-Length:\s*(\d+)") {
            $len = [int]$Matches[1]
            # Read empty line
            $null = $proc.StandardOutput.ReadLine()
            # Read body
            $buf = New-Object byte[] $len
            $read = 0
            while ($read -lt $len) {
                $r = $proc.StandardOutput.BaseStream.Read($buf, $read, $len - $read)
                if ($r -le 0) { break }
                $read += $r
            }
            $body = [System.Text.Encoding]::UTF8.GetString($buf, 0, $read)
            Write-Host "[RECV] $body"
        }
    }
}

Write-Host "Done. Killing rust-analyzer."
$proc.Kill()
