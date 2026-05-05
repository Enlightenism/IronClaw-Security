[CmdletBinding()]
param(
    [Parameter(Position = 0)]
    [ValidateSet("start", "stop", "restart", "status")]
    [string]$Action = "status",

    [string]$HostAddress = "127.0.0.1",

    [ValidateRange(1, 65535)]
    [int]$Port = 8000,

    [string]$AppImport = "app.main:app",

    [ValidateSet("critical", "error", "warning", "info", "debug", "trace")]
    [string]$LogLevel = "info",

    [switch]$Reload,

    [switch]$Json
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

function Get-ProjectRoot {
    return (Resolve-Path (Join-Path $PSScriptRoot "..")).Path
}

function Get-RunDirectory {
    param(
        [Parameter(Mandatory = $true)]
        [string]$ProjectRoot
    )

    $runDir = Join-Path $ProjectRoot ".ironclaw"
    if (-not (Test-Path -LiteralPath $runDir)) {
        New-Item -ItemType Directory -Path $runDir -Force | Out-Null
    }
    return $runDir
}

function Get-PidFilePath {
    param(
        [Parameter(Mandatory = $true)]
        [string]$RunDirectory
    )

    return (Join-Path $RunDirectory "ironclaw-service.pid")
}

function Get-LogFilePath {
    param(
        [Parameter(Mandatory = $true)]
        [string]$RunDirectory
    )

    return (Join-Path $RunDirectory "ironclaw-service.log")
}

function Get-PythonExecutable {
    param(
        [Parameter(Mandatory = $true)]
        [string]$ProjectRoot
    )

    $venvPython = Join-Path $ProjectRoot ".venv\Scripts\python.exe"
    if (Test-Path -LiteralPath $venvPython) {
        return $venvPython
    }

    $pythonCommand = Get-Command python -ErrorAction SilentlyContinue
    if ($null -ne $pythonCommand) {
        return $pythonCommand.Source
    }

    $pyCommand = Get-Command py -ErrorAction SilentlyContinue
    if ($null -ne $pyCommand) {
        return $pyCommand.Source
    }

    throw "Python executable not found. Create .venv first or make python available on PATH."
}

function Get-PythonArgumentList {
    param(
        [Parameter(Mandatory = $true)]
        [string]$PythonExecutable,

        [Parameter(Mandatory = $true)]
        [string]$AppImport,

        [Parameter(Mandatory = $true)]
        [string]$HostAddress,

        [Parameter(Mandatory = $true)]
        [int]$Port,

        [Parameter(Mandatory = $true)]
        [string]$LogLevel,

        [Parameter(Mandatory = $false)]
        [switch]$Reload
    )

    $argumentList = @(
        "-m", "uvicorn",
        $AppImport,
        "--host", $HostAddress,
        "--port", "$Port",
        "--log-level", $LogLevel
    )

    if ($Reload.IsPresent) {
        $argumentList += "--reload"
    }

    return $argumentList
}

function Read-ServicePid {
    param(
        [Parameter(Mandatory = $true)]
        [string]$PidFile
    )

    if (-not (Test-Path -LiteralPath $PidFile)) {
        return $null
    }

    $raw = (Get-Content -LiteralPath $PidFile -ErrorAction Stop | Select-Object -First 1).Trim()
    if ([string]::IsNullOrWhiteSpace($raw)) {
        return $null
    }

    $pidValue = 0
    if (-not [int]::TryParse($raw, [ref]$pidValue)) {
        return $null
    }

    return $pidValue
}

function Remove-ServicePidFile {
    param(
        [Parameter(Mandatory = $true)]
        [string]$PidFile
    )

    if (Test-Path -LiteralPath $PidFile) {
        Remove-Item -LiteralPath $PidFile -Force
    }
}

function Test-ProcessAlive {
    param(
        [Parameter(Mandatory = $true)]
        [int]$ProcessId
    )

    try {
        $null = Get-Process -Id $ProcessId -ErrorAction Stop
        return $true
    }
    catch {
        return $false
    }
}

function Test-PortOpen {
    param(
        [Parameter(Mandatory = $true)]
        [string]$HostAddress,

        [Parameter(Mandatory = $true)]
        [int]$Port
    )

    try {
        $client = New-Object System.Net.Sockets.TcpClient
        $async = $client.BeginConnect($HostAddress, $Port, $null, $null)
        $connected = $async.AsyncWaitHandle.WaitOne(500)
        if (-not $connected) {
            $client.Close()
            return $false
        }
        $client.EndConnect($async) | Out-Null
        $client.Close()
        return $true
    }
    catch {
        return $false
    }
}

function Get-ServiceState {
    param(
        [Parameter(Mandatory = $true)]
        [string]$PidFile,

        [Parameter(Mandatory = $true)]
        [string]$LogFile,

        [Parameter(Mandatory = $true)]
        [string]$HostAddress,

        [Parameter(Mandatory = $true)]
        [int]$Port
    )

    $servicePid = Read-ServicePid -PidFile $PidFile
    $running = $false

    if ($null -ne $servicePid) {
        $running = Test-ProcessAlive -ProcessId $servicePid
        if ($running) {
            $portOpen = Test-PortOpen -HostAddress $HostAddress -Port $Port
            if (-not $portOpen) {
                $running = $false
            }
        }
    }

    if (-not $running) {
        Remove-ServicePidFile -PidFile $PidFile
        $servicePid = $null
    }

    return [ordered]@{
        running  = $running
        pid      = $servicePid
        host     = $HostAddress
        port     = $Port
        pid_file = $PidFile
        log_file = $LogFile
    }
}

function Start-IronClawService {
    param(
        [Parameter(Mandatory = $true)]
        [string]$ProjectRoot,

        [Parameter(Mandatory = $true)]
        [string]$PidFile,

        [Parameter(Mandatory = $true)]
        [string]$LogFile,

        [Parameter(Mandatory = $true)]
        [string]$PythonExecutable,

        [Parameter(Mandatory = $true)]
        [string[]]$ArgumentList,

        [Parameter(Mandatory = $true)]
        [string]$HostAddress,

        [Parameter(Mandatory = $true)]
        [int]$Port
    )

    $state = Get-ServiceState -PidFile $PidFile -LogFile $LogFile -HostAddress $HostAddress -Port $Port
    if ($state.running) {
        return $state
    }

    $envPrefix = "set PYTHONPATH=$ProjectRoot&& "
    $escapedArgs = ($ArgumentList | ForEach-Object {
        if ($_ -match '\s') { '"' + $_ + '"' } else { $_ }
    }) -join ' '
    $commandLine = $envPrefix + '"' + $PythonExecutable + '" ' + $escapedArgs

    $process = Start-Process -FilePath "cmd.exe" `
        -ArgumentList @("/c", $commandLine) `
        -WorkingDirectory $ProjectRoot `
        -WindowStyle Hidden `
        -RedirectStandardOutput $LogFile `
        -RedirectStandardError $LogFile `
        -PassThru

    Set-Content -LiteralPath $PidFile -Value $process.Id -Encoding utf8

    $deadline = (Get-Date).AddSeconds(20)
    do {
        Start-Sleep -Milliseconds 250

        if (-not (Test-ProcessAlive -ProcessId $process.Id)) {
            Remove-ServicePidFile -PidFile $PidFile
            throw "IronClaw service exited early. Check log file: $LogFile"
        }

        if (Test-PortOpen -HostAddress $HostAddress -Port $Port) {
            return (Get-ServiceState -PidFile $PidFile -LogFile $LogFile -HostAddress $HostAddress -Port $Port)
        }
    } while ((Get-Date) -lt $deadline)

    try {
        Stop-Process -Id $process.Id -Force -ErrorAction SilentlyContinue
    }
    catch {
    }

    Remove-ServicePidFile -PidFile $PidFile
    throw "IronClaw service did not become ready within 20 seconds."
}

function Stop-IronClawService {
    param(
        [Parameter(Mandatory = $true)]
        [string]$PidFile,

        [Parameter(Mandatory = $true)]
        [string]$LogFile,

        [Parameter(Mandatory = $true)]
        [string]$HostAddress,

        [Parameter(Mandatory = $true)]
        [int]$Port
    )

    $servicePid = Read-ServicePid -PidFile $PidFile
    if ($null -eq $servicePid) {
        Remove-ServicePidFile -PidFile $PidFile
        return (Get-ServiceState -PidFile $PidFile -LogFile $LogFile -HostAddress $HostAddress -Port $Port)
    }

    if (Test-ProcessAlive -ProcessId $servicePid) {
        & taskkill /PID $servicePid /T /F | Out-Null
        Start-Sleep -Seconds 1
    }

    Remove-ServicePidFile -PidFile $PidFile
    return (Get-ServiceState -PidFile $PidFile -LogFile $LogFile -HostAddress $HostAddress -Port $Port)
}

function Write-Result {
    param(
        [Parameter(Mandatory = $true)]
        [string]$Action,

        [Parameter(Mandatory = $true)]
        [hashtable]$State,

        [Parameter(Mandatory = $false)]
        [switch]$Json
    )

    $payload = [ordered]@{
        action = $Action
        state  = $State
    }

    if ($Json.IsPresent) {
        $payload | ConvertTo-Json -Depth 5
        return
    }

    Write-Host "[ironclaw-service] action: $Action"
    Write-Host "[ironclaw-service] running: $($State.running)"
    Write-Host "[ironclaw-service] pid: $($State.pid)"
    Write-Host "[ironclaw-service] host: $($State.host)"
    Write-Host "[ironclaw-service] port: $($State.port)"
    Write-Host "[ironclaw-service] pid_file: $($State.pid_file)"
    Write-Host "[ironclaw-service] log_file: $($State.log_file)"
}

$projectRoot = Get-ProjectRoot
$runDir = Get-RunDirectory -ProjectRoot $projectRoot
$pidFile = Get-PidFilePath -RunDirectory $runDir
$logFile = Get-LogFilePath -RunDirectory $runDir
$pythonExecutable = Get-PythonExecutable -ProjectRoot $projectRoot
$argumentList = Get-PythonArgumentList `
    -PythonExecutable $pythonExecutable `
    -AppImport $AppImport `
    -HostAddress $HostAddress `
    -Port $Port `
    -LogLevel $LogLevel `
    -Reload:$Reload

try {
    switch ($Action) {
        "start" {
            $state = Start-IronClawService `
                -ProjectRoot $projectRoot `
                -PidFile $pidFile `
                -LogFile $logFile `
                -PythonExecutable $pythonExecutable `
                -ArgumentList $argumentList `
                -HostAddress $HostAddress `
                -Port $Port
            Write-Result -Action $Action -State $state -Json:$Json
        }

        "stop" {
            $state = Stop-IronClawService `
                -PidFile $pidFile `
                -LogFile $logFile `
                -HostAddress $HostAddress `
                -Port $Port
            Write-Result -Action $Action -State $state -Json:$Json
        }

        "restart" {
            $null = Stop-IronClawService `
                -PidFile $pidFile `
                -LogFile $logFile `
                -HostAddress $HostAddress `
                -Port $Port

            $state = Start-IronClawService `
                -ProjectRoot $projectRoot `
                -PidFile $pidFile `
                -LogFile $logFile `
                -PythonExecutable $pythonExecutable `
                -ArgumentList $argumentList `
                -HostAddress $HostAddress `
                -Port $Port
            Write-Result -Action $Action -State $state -Json:$Json
        }

        "status" {
            $state = Get-ServiceState `
                -PidFile $pidFile `
                -LogFile $logFile `
                -HostAddress $HostAddress `
                -Port $Port
            Write-Result -Action $Action -State $state -Json:$Json
        }

        default {
            throw "Unsupported action: $Action"
        }
    }

    exit 0
}
catch {
    if ($Json.IsPresent) {
        @{
            ok    = $false
            error = $_.Exception.Message
        } | ConvertTo-Json -Depth 4
    }
    else {
        Write-Error "[ironclaw-service] failed: $($_.Exception.Message)"
    }
    exit 1
}