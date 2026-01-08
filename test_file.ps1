# ============================
# Proxy Test Script (PowerShell)
# ============================

$PROXY   = "http://127.0.0.1:8080"
$TIMEOUT = 10
$COUNT   = 20

function Run-Many {
    param (
        [string]$Label,
        [scriptblock]$Command
    )

    Write-Host "========================================"
    Write-Host $Label
    Write-Host "========================================"

    $jobs = @()

    for ($i = 1; $i -le $COUNT; $i++) {
        $jobs += Start-Job $Command
    }

    Wait-Job $jobs | Out-Null
    Remove-Job $jobs | Out-Null

    Write-Host "Completed: $Label"
    Write-Host "----------------------------------------"
}

# 1. VALID HTTP REQUESTS
Run-Many "VALID HTTP REQUESTS" {
    curl.exe -x $using:PROXY http://httpbin.org/get --max-time $using:TIMEOUT -s -o NUL
}

# 2. DIRECT HTTPS REQUESTS
Run-Many "DIRECT HTTPS REQUESTS (CONNECT)" {
    curl.exe -x $using:PROXY https://httpbin.org/get --max-time $using:TIMEOUT -s -o NUL
}

# 3. HTTP → HTTPS REDIRECTS
Run-Many "HTTP TO HTTPS REDIRECTS" {
    curl.exe -x $using:PROXY -L http://instagram.com `
        --max-time $using:TIMEOUT -s -o NUL
}

# 4. BLOCKED DOMAINS
Run-Many "BLOCKED DOMAINS" {
    curl.exe -x $using:PROXY http://example.com --max-time $using:TIMEOUT -s -o NUL
}

# 5. INVALID / NON-EXISTENT DOMAINS
Run-Many "INVALID DOMAINS" {
    curl.exe -x $using:PROXY http://nonexistentdomain123456789.com `
        --max-time $using:TIMEOUT -s -o NUL
}

# 6. MALFORMED REQUESTS (NO HOST HEADER)
Write-Host "========================================"
Write-Host "MALFORMED REQUESTS (NO HOST HEADER)"
Write-Host "========================================"

$jobs = @()
for ($i = 1; $i -le $COUNT; $i++) {
    $jobs += Start-Job {
        $client = New-Object System.Net.Sockets.TcpClient("127.0.0.1", 8080)
        $stream = $client.GetStream()
        $data   = [Text.Encoding]::ASCII.GetBytes("GET / HTTP/1.1`r`n`r`n")
        $stream.Write($data, 0, $data.Length)
        $client.Close()
    }
}

Wait-Job $jobs | Out-Null
Remove-Job $jobs | Out-Null
Write-Host "Completed: MALFORMED REQUESTS"
Write-Host "----------------------------------------"

# 7. MALFORMED CONNECT REQUESTS
Write-Host "========================================"
Write-Host "MALFORMED CONNECT REQUESTS"
Write-Host "========================================"

$jobs = @()
for ($i = 1; $i -le $COUNT; $i++) {
    $jobs += Start-Job {
        $client = New-Object System.Net.Sockets.TcpClient("127.0.0.1", 8080)
        $stream = $client.GetStream()
        $data   = [Text.Encoding]::ASCII.GetBytes("CONNECT badhost HTTP/1.1`r`n`r`n")
        $stream.Write($data, 0, $data.Length)
        $client.Close()
    }
}

Wait-Job $jobs | Out-Null
Remove-Job $jobs | Out-Null
Write-Host "Completed: MALFORMED CONNECT"
Write-Host "----------------------------------------"

Write-Host "ALL TESTS COMPLETED"
