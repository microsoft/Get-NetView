$Global:Version = "2022.8.16.209"

$Script:RunspacePool = $null
$Script:ThreadList = [Collections.ArrayList]@()

$Global:QueueActivity = "Queueing tasks..."
$Global:FinishActivity = "Finishing..."

$Global:ChelsioDeviceDirs = @{}
$Global:MellanoxSystemLogDir = ""

$ExecFunctions = {
    param(
        [parameter(Mandatory=$true)] [Hashtable] $ExecParams
    )

    $columns   = 4096

    # Alias Write-CmdLog to Write-Host for background threads,
    # since console color only applies to the main thread.
    Set-Alias -Name Write-CmdLog -Value Write-Host

    <#
    .SYNOPSIS
        Log control path errors or issues.
    #>
    function ExecControlError {
        [CmdletBinding()]
        Param(
            [parameter(Mandatory=$true)] [String] $OutDir,
            [parameter(Mandatory=$true)] [String] $Message
        )

        $callerName = (Get-PSCallStack)[1].FunctionName

        $file = "_Error.$callerName.txt"
        $out  = Join-Path $OutDir $file
        Write-Output $Message | Out-File -Encoding "default" -Width $columns -Append $out
    } # ExecControlError()

    enum CommandStatus {
        NotRun       # The command was not executed
        Unavailable  # [Part of] the command doesn't exist
        Failed       # An error prevented successful execution
        Success      # No errors or exceptions
    }

    # Powershell cmdlets have inconsistent implementations in command error handling. This function
    # performs a validation of the command prior to formal execution and will log any failures.
    function TestCommand {
        [CmdletBinding()]
        Param(
            [parameter(Mandatory=$true)] [String] $Command
        )

        $status = [CommandStatus]::NotRun
        $duration = [TimeSpan]::Zero
        $commandOut = ""

        # Check timeout
        $delta = (Get-Date) - $ExecParams.StartTime
        if ($delta.TotalMinutes -gt $ExecParams.Timeout) {
            return $status, $duration.TotalMilliseconds, $commandOut
        }

        try {
            $error.Clear()

            # Redirect all command output (expect errors) to stdout.
            # Any errors will still be output to $error variable.
            $silentCmd = '$({0}) 2>$null 3>&1 4>&1 5>&1 6>&1' -f $Command

            $duration = Measure-Command {
                # ErrorAction MUST be Stop for try catch to work.
                $commandOut = (Invoke-Expression $silentCmd -ErrorAction Stop)
            }

            # Sometimes commands output errors even on successful execution.
            # We only should fail commands if an error was their *only* output.
            if (($error -ne $null) -and [String]::IsNullOrWhiteSpace($commandOut)) {
                # Some PS commands are incorrectly implemented in return
                # code and require detecting SilentlyContinue
                if ($Command -notlike "*SilentlyContinue*") {
                    throw $error[0]
                }
            }

            $status = [CommandStatus]::Success
        } catch [Management.Automation.CommandNotFoundException] {
            $status = [CommandStatus]::Unavailable
        } catch {
            $status  = [CommandStatus]::Failed
            $commandOut = ($_ | Out-String)
        } finally {
            # Post-execution cleanup to avoid false positives
            $error.Clear()
        }

        return $status, $duration.TotalMilliseconds, $commandOut
    } # TestCommand()

    function ExecCommand {
        [CmdletBinding()]
        Param(
            [parameter(Mandatory=$true)] [String] $Command
        )

        $status, [Int] $duration, $commandOut = TestCommand -Command $Command

        # Mirror command execution context
        Write-Output "$env:USERNAME @ ${env:COMPUTERNAME}:"

        # Mirror command to execute
        Write-Output "$(prompt)$Command"

        $logPrefix = "({0,6:n0} ms)" -f $duration
        if ($status -ne [CommandStatus]::Success) {
            $logPrefix = "$logPrefix [$status]"
            Write-Output "[$status]"
        }
        Write-Output $commandOut

        Write-CmdLog "$logPrefix $Command"

        if ($ExecParams.DelayFactor -gt 0) {
            Start-Sleep -Milliseconds ($duration * $ExecParams.DelayFactor + 0.50) # round up
        }
    } # ExecCommand()

    function ExecCommands {
        [CmdletBinding()]
        Param(
            [parameter(Mandatory=$true)] [String] $File,
            [parameter(Mandatory=$true)] [String] $OutDir,
            [parameter(Mandatory=$true)] [String[]] $Commands
        )

        $out = (Join-Path -Path $OutDir -ChildPath $File)
        $($Commands | foreach {ExecCommand -Command $_}) | Out-File -Encoding "default" -Width $columns -Append $out

        # With high-concurreny, WMI-based cmdlets sometimes output in an
        # incorrect format or with missing fields. Somehow, this helps
        # reduce the frequency of the problem.
        $null = Get-NetAdapter
    } # ExecCommands()
} # $ExecFunctions

<#
.SYNOPSIS
    Create a shortcut file (.LNK) pointing to $TargetPath.
.NOTES
    Used to avoid duplicate effort in IHV commands, which are
    executed per NIC, but some data is per system/ASIC.
#>
function New-LnkShortcut {
    [CmdletBinding()]
    Param(
        [parameter(Mandatory=$true)] [String] $LnkFile,
        [parameter(Mandatory=$true)] [String] $TargetPath
    )

    if ($LnkFile -notlike "*.lnk") {
        return
    }

    $shell = New-Object -ComObject "WScript.Shell"
    $lnk = $shell.CreateShortcut($LnkFile)
    $lnk.TargetPath = $TargetPath
    $null = $lnk.Save()
    $null = [Runtime.Interopservices.Marshal]::ReleaseComObject($shell)
} # New-LnkShortcut()

<#
.SYNOPSIS
    Replaces invalid characters with a placeholder to make a
    valid directory or filename.
.NOTES
    Do not pass in a path. It will replace '\' and '/'.
#>
function ConvertTo-Filename {
    [CmdletBinding()]
    Param(
        [parameter(Position=0, Mandatory=$true)] [String] $Filename
    )

    $invalidChars = [System.IO.Path]::GetInvalidFileNameChars() -join ""
    return $Filename -replace "[$invalidChars]","_"
}

function TryCmd {
    [CmdletBinding()]
    Param(
        [parameter(Mandatory=$true)] [ScriptBlock] $ScriptBlock
    )

    try {
        $out = &$ScriptBlock
    } catch {
        $out = $null
    }

    # Returning $null will cause foreach to iterate once
    # unless TryCmd call is in parentheses.
    if ($out -eq $null) {
        $out = @()
    }

    return $out
} # TryCmd()

function Write-CmdLog {
    [CmdletBinding()]
    Param(
        [parameter(Mandatory=$true)] [String] $CmdLog
    )

    $logColor = [ConsoleColor]::White
    switch -Wildcard ($CmdLog) {
        "*``[Failed``]*" {
            $logColor = [ConsoleColor]::Yellow
            break
        }
        "*``[Unavailable``]*" {
            $logColor = [ConsoleColor]::DarkGray
            break
        }
        "*``[NotRun``]*" {
            $logColor = [ConsoleColor]::Gray
            break
        }
    }

    Write-Host $CmdLog -ForegroundColor $logColor
} # Write-CmdLog()

function Open-GlobalRunspacePool {
    [CmdletBinding()]
    Param(
        [parameter(Mandatory=$true)] [Int] $BackgroundThreads
    )

    if ($BackgroundThreads -gt 0) {
        $Script:RunspacePool = [RunspaceFactory]::CreateRunspacePool(1, $BackgroundThreads)
        $Script:RunspacePool.Open()
    }

    if ($BackgroundThreads -le 1) {
        Set-Alias ExecCommandsAsync ExecCommands
        $Global:QueueActivity = "Executing commands..."
    }
} # Open-GlobalRunspacePool()

function Close-GlobalRunspacePool {
    [CmdletBinding()]
    Param()

    if ($Script:RunspacePool -ne $null) {
        Write-Progress -Activity $Global:FinishActivity -Status "Cleanup background threads..."

        if ($Script:ThreadList.Count -gt 0) {
            # Kill any DISM child process, which ignores below Stop attempt...
            $dismId = @(Get-CimInstance "Win32_Process" -Filter "Name = 'DismHost.exe' AND ParentProcessId = $PID").ProcessId
            if ($dismId.Count -gt 0) {
                Stop-Process -Id $dismId -Force
            }

            # Asyncronously stop all threads.
            $Script:ThreadList | foreach {
                $_.AsyncStop = $_.PowerShell.BeginStop($null, $_.AsyncInvoke)
            }

            # Wait for stops to complete.
            $Script:ThreadList | foreach {
                Write-CmdLog "(     0 ms) [NotRun] $($_.Command)"
                $_.PowerShell.EndStop($_.AsyncStop)
            }

            $Script:ThreadList.Clear()
        }

        $Script:RunspacePool.Close()
        $Script:RunspacePool.Dispose()
        $Script:RunspacePool = $null
    }
} # Close-GlobalRunspacePool()

function Start-Thread {
    [CmdletBinding()]
    Param(
        [parameter(Mandatory=$true)] [ScriptBlock] $ScriptBlock,
        [parameter(Mandatory=$false)] [Hashtable] $Params = @{}
    )

    if ($null -eq $Script:RunspacePool) {
        # Execute command synchronously instead
        &$ScriptBlock @Params
    } else {
        $ps = [PowerShell]::Create()

        $ps.RunspacePool = $Script:RunspacePool
        $null = $ps.AddScript("Set-Location `"$(Get-Location)`"")
        $null = $ps.AddScript($ExecFunctions).AddParameter("ExecParams", $Global:ExecParams)
        $null = $ps.AddScript($ScriptBlock, $true).AddParameters($Params)

        $async = $ps.BeginInvoke()

        $cmd = if ($ScriptBlock -eq ${function:ExecCommands}) {$Params.Commands} else {$ScriptBlock.Ast.Name}

        $null = $Script:ThreadList.Add(@{AsyncInvoke=$async; Command=$cmd; PowerShell=$ps})
    }
} # Start-Thread()

function Show-Threads {
    [CmdletBinding()]
    Param()

    $totalTasks = $Script:ThreadList.Count

    while ($Script:ThreadList.Count -gt 0) {
        Write-Progress -Activity "Waiting for all tasks to complete..." -Status "$($Script:ThreadList.Count) remaining." -PercentComplete (100 * (1 - $Script:ThreadList.Count / $totalTasks))

        for ($i = 0; $i -lt $Script:ThreadList.Count; $i++) {
            $thread = $Script:ThreadList[$i]

            $thread.Powershell.Streams.Warning | Out-Host
            $thread.Powershell.Streams.Warning.Clear()
            $thread.Powershell.Streams.Information | foreach {Write-CmdLog "$_"}
            $thread.Powershell.Streams.Information.Clear()

            if ($thread.AsyncInvoke.IsCompleted) {
                # Accessing Streams.Error blocks until thread is completed
                $thread.Powershell.Streams.Error | Out-Host
                $thread.Powershell.Streams.Error.Clear()

                $thread.PowerShell.EndInvoke($thread.AsyncInvoke)
                $Script:ThreadList.RemoveAt($i)
                $i--
            }
        }

        $delta = (Get-Date) - $Global:ExecParams.StartTime
        if ($delta.TotalMinutes -gt $Global:ExecParams.Timeout) {
            Write-Warning "Timeout was reached."
            break
        }

        Start-Sleep -Milliseconds 33 # ~30 Hz
    }
} # Show-Threads()

function ExecCommandsAsync {
    [CmdletBinding()]
    Param(
        [parameter(Mandatory=$true)] [String] $OutDir,
        [parameter(Mandatory=$true)] [String] $File,
        [parameter(Mandatory=$true)] [String[]] $Commands
    )

    return Start-Thread -ScriptBlock ${function:ExecCommands} -Params $PSBoundParameters
} # ExecCommandsAsync()

function ExecCopyItemsAsync {
    [CmdletBinding()]
    Param(
        [parameter(Mandatory=$true)] [String] $OutDir,
        [parameter(Mandatory=$true)] [String] $File,
        [parameter(Mandatory=$true)] [String[]] $Paths,
        [parameter(Mandatory=$true)] [String] $Destination
    )

    if (-not (Test-Path $Destination)) {
        $null = New-Item -ItemType "Container" -Path $Destination
    }

    [String[]] $cmds = $Paths | foreach {"Copy-Item -Path ""$_"" -Destination ""$Destination"" -Recurse -Verbose 4>&1"}
    return ExecCommandsAsync -OutDir $OutDir -File $File -Commands $cmds
} # ExecCopyItemsAsync()

#
# Data Collection Functions
#

function NetIpNic {
    [CmdletBinding()]
    Param(
        [parameter(Mandatory=$false)] [String] $NicName,
        [parameter(Mandatory=$true)] [String] $OutDir
    )

    $name = $NicName
    $dir  = (Join-Path -Path $OutDir -ChildPath "NetIp")
    New-Item -ItemType directory -Path $dir | Out-Null

    $file = "Get-NetIpAddress.txt"
    [String []] $cmds = "Get-NetIpAddress -InterfaceAlias ""$name"" | Format-Table -AutoSize",
                        "Get-NetIpAddress -InterfaceAlias ""$name"" | Format-Table -Property * -AutoSize",
                        "Get-NetIpAddress -InterfaceAlias ""$name"" | Format-List",
                        "Get-NetIpAddress -InterfaceAlias ""$name"" | Format-List -Property *"
    ExecCommandsAsync -OutDir $dir -File $file -Commands $cmds

    $file = "Get-NetIPInterface.txt"
    [String []] $cmds = "Get-NetIPInterface -InterfaceAlias ""$name""",
                        "Get-NetIPInterface -InterfaceAlias ""$name"" | Format-Table -AutoSize",
                        "Get-NetIPInterface -InterfaceAlias ""$name"" | Format-Table -Property * -AutoSize"
    ExecCommandsAsync -OutDir $dir -File $file -Commands $cmds

    $file = "Get-NetNeighbor.txt"
    [String []] $cmds = "Get-NetNeighbor -InterfaceAlias ""$name""",
                        "Get-NetNeighbor -InterfaceAlias ""$name"" | Format-Table -AutoSize",
                        "Get-NetNeighbor -InterfaceAlias ""$name"" | Format-Table -Property * -AutoSize"
    ExecCommandsAsync -OutDir $dir -File $file -Commands $cmds

    $file = "Get-NetRoute.txt"
    [String []] $cmds = "Get-NetRoute -InterfaceAlias ""$name"" | Format-Table -AutoSize",
                        "Get-NetRoute -InterfaceAlias ""$name"" | Format-Table -Property * -AutoSize"
    ExecCommandsAsync -OutDir $dir -File $file -Commands $cmds
} # NetIpNic()

function NetIp {
    [CmdletBinding()]
    Param(
        [parameter(Mandatory=$true)] [String] $OutDir
    )

    Write-Progress -Activity $Global:QueueActivity -Status "Processing $($MyInvocation.MyCommand.Name)"

    $dir = (Join-Path -Path $OutDir -ChildPath "NetIp")
    New-Item -ItemType directory -Path $dir | Out-Null

    $file = "Get-NetIpAddress.txt"
    [String []] $cmds = "Get-NetIpAddress | Format-Table -AutoSize",
                        "Get-NetIpAddress | Format-Table -Property * -AutoSize",
                        "Get-NetIpAddress | Format-List",
                        "Get-NetIpAddress | Format-List -Property *"
    ExecCommandsAsync -OutDir $dir -File $file -Commands $cmds

    $file = "Get-NetIPInterface.txt"
    [String []] $cmds = "Get-NetIPInterface",
                        "Get-NetIPInterface | Format-Table -AutoSize",
                        "Get-NetIPInterface | Format-Table -Property * -AutoSize"
    ExecCommandsAsync -OutDir $dir -File $file -Commands $cmds

    $file = "Get-NetNeighbor.txt"
    [String []] $cmds = "Get-NetNeighbor | Format-Table -AutoSize",
                        "Get-NetNeighbor | Format-Table -Property * -AutoSize"
    ExecCommandsAsync -OutDir $dir -File $file -Commands $cmds

    $file = "Get-NetIPv4Protocol.txt"
    [String []] $cmds = "Get-NetIPv4Protocol",
                        "Get-NetIPv4Protocol | Format-List  -Property *",
                        "Get-NetIPv4Protocol | Format-Table -Property * -AutoSize",
                        "Get-NetIPv4Protocol | Format-Table -Property * -AutoSize"
    ExecCommandsAsync -OutDir $dir -File $file -Commands $cmds

    $file = "Get-NetIPv6Protocol.txt"
    [String []] $cmds = "Get-NetIPv6Protocol",
                        "Get-NetIPv6Protocol | Format-List  -Property *",
                        "Get-NetIPv6Protocol | Format-Table -Property * -AutoSize",
                        "Get-NetIPv6Protocol | Format-Table -Property * -AutoSize"
    ExecCommandsAsync -OutDir $dir -File $file -Commands $cmds

    $file = "Get-NetOffloadGlobalSetting.txt"
    [String []] $cmds = "Get-NetOffloadGlobalSetting",
                        "Get-NetOffloadGlobalSetting | Format-List  -Property *",
                        "Get-NetOffloadGlobalSetting | Format-Table -AutoSize",
                        "Get-NetOffloadGlobalSetting | Format-Table -Property * -AutoSize"
    ExecCommandsAsync -OutDir $dir -File $file -Commands $cmds

    $file = "Get-NetPrefixPolicy.txt"
    [String []] $cmds = "Get-NetPrefixPolicy | Format-Table -AutoSize",
                        "Get-NetPrefixPolicy | Format-Table -Property * -AutoSize"
    ExecCommandsAsync -OutDir $dir -File $file -Commands $cmds

    $file = "Get-NetRoute.txt"
    [String []] $cmds = "Get-NetRoute | Format-Table -AutoSize",
                        "Get-NetRoute | Format-Table -Property * -AutoSize"
    ExecCommandsAsync -OutDir $dir -File $file -Commands $cmds

    $file = "Get-NetTCPConnection.txt"
    [String []] $cmds = "Get-NetTCPConnection | Format-Table -AutoSize",
                        "Get-NetTCPConnection | Format-Table -Property * -AutoSize"
    ExecCommandsAsync -OutDir $dir -File $file -Commands $cmds

    $file = "Get-NetTcpSetting.txt"
    [String []] $cmds = "Get-NetTcpSetting | Format-Table -AutoSize",
                        "Get-NetTcpSetting | Format-Table -Property * -AutoSize",
                        "Get-NetTcpSetting | Format-List -Property *"
    ExecCommandsAsync -OutDir $dir -File $file -Commands $cmds

    $file = "Get-NetTransportFilter.txt"
    [String []] $cmds = "Get-NetTransportFilter | Format-Table -AutoSize",
                        "Get-NetTransportFilter | Format-Table -Property * -AutoSize",
                        "Get-NetTransportFilter | Format-List -Property *"
    ExecCommandsAsync -OutDir $dir -File $file -Commands $cmds

    $file = "Get-NetUDPEndpoint.txt"
    [String []] $cmds = "Get-NetUDPEndpoint | Format-Table -AutoSize",
                        "Get-NetUDPEndpoint | Format-Table -Property * -AutoSize"
    ExecCommandsAsync -OutDir $dir -File $file -Commands $cmds

    $file = "Get-NetUDPSetting.txt"
    [String []] $cmds = "Get-NetUDPSetting | Format-Table -AutoSize",
                        "Get-NetUDPSetting | Format-Table -Property * -AutoSize"
    ExecCommandsAsync -OutDir $dir -File $file -Commands $cmds
} # NetIp()

function NetNatDetail {
    [CmdletBinding()]
    Param(
        [parameter(Mandatory=$true)] [String] $OutDir
    )

    Write-Progress -Activity $Global:QueueActivity -Status "Processing $($MyInvocation.MyCommand.Name)"

    $dir = (Join-Path -Path $OutDir -ChildPath "NetNat")
    New-Item -ItemType directory -Path $dir | Out-Null

    $file = "Get-NetNat.txt"
    [String []] $cmds = "Get-NetNat | Format-Table -AutoSize",
                        "Get-NetNat | Format-Table -Property * -AutoSize",
                        "Get-NetNat | Format-List",
                        "Get-NetNat | Format-List -Property *"
    ExecCommandsAsync -OutDir $dir -File $file -Commands $cmds

    $file = "Get-NetNatExternalAddress.txt"
    [String []] $cmds = "Get-NetNatExternalAddress | Format-Table -AutoSize",
                        "Get-NetNatExternalAddress | Format-Table -Property * -AutoSize",
                        "Get-NetNatExternalAddress | Format-List",
                        "Get-NetNatExternalAddress | Format-List -Property *"
    ExecCommandsAsync -OutDir $dir -File $file -Commands $cmds

    $file = "Get-NetNatGlobal.txt"
    [String []] $cmds = "Get-NetNatGlobal | Format-Table -AutoSize",
                        "Get-NetNatGlobal | Format-Table -Property * -AutoSize",
                        "Get-NetNatGlobal | Format-List",
                        "Get-NetNatGlobal | Format-List -Property *"
    ExecCommandsAsync -OutDir $dir -File $file -Commands $cmds

    $file = "Get-NetNatSession.txt"
    [String []] $cmds = "Get-NetNatSession | Format-Table -AutoSize",
                        "Get-NetNatSession | Format-Table -Property * -AutoSize",
                        "Get-NetNatSession | Format-List",
                        "Get-NetNatSession | Format-List -Property *"
    ExecCommandsAsync -OutDir $dir -File $file -Commands $cmds

    $file = "Get-NetNatStaticMapping.txt"
    [String []] $cmds = "Get-NetNatStaticMapping | Format-Table -AutoSize",
                        "Get-NetNatStaticMapping | Format-Table -Property * -AutoSize",
                        "Get-NetNatStaticMapping | Format-List",
                        "Get-NetNatStaticMapping | Format-List -Property *"
    ExecCommandsAsync -OutDir $dir -File $file -Commands $cmds

} # NetNat()

function NetAdapterWorker {
    [CmdletBinding()]
    Param(
        [parameter(Mandatory=$false)] [String] $NicName,
        [parameter(Mandatory=$true)] [String] $OutDir
    )

    $name = $NicName
    $dir  = $OutDir

    $file = "nmbind.txt"
    [String []] $cmds = "nmbind ""$name"" "
    ExecCommandsAsync -OutDir $dir -File $file -Commands $cmds

    $file = "Get-NetAdapter.txt"
    [String []] $cmds = "Get-NetAdapter -Name ""$name"" -IncludeHidden",
                        "Get-NetAdapter -Name ""$name"" -IncludeHidden | Format-List -Property *"
    ExecCommandsAsync -OutDir $dir -File $file -Commands $cmds

    $file = "Get-NetAdapterAdvancedProperty.txt"
    [String []] $cmds = "Get-NetAdapterAdvancedProperty -Name ""$name"" -AllProperties -IncludeHidden | Sort-Object RegistryKeyword | Format-Table -AutoSize",
                        "Get-NetAdapterAdvancedProperty -Name ""$name"" -AllProperties -IncludeHidden | Format-List -Property *",
                        "Get-NetAdapterAdvancedProperty -Name ""$name"" -AllProperties -IncludeHidden | Format-Table -Property *"
    ExecCommandsAsync -OutDir $dir -File $file -Commands $cmds

    $file = "Get-NetAdapterBinding.txt"
    [String []] $cmds = "Get-NetAdapterBinding -Name ""$name"" -AllBindings -IncludeHidden | Sort-Object ComponentID",
                        "Get-NetAdapterBinding -Name ""$name"" -AllBindings -IncludeHidden | Format-List -Property *"
    ExecCommandsAsync -OutDir $dir -File $file -Commands $cmds

    $file = "Get-NetAdapterChecksumOffload.txt"
    [String []] $cmds = "Get-NetAdapterChecksumOffload -Name ""$name"" -IncludeHidden",
                        "Get-NetAdapterChecksumOffload -Name ""$name"" -IncludeHidden | Format-List -Property *"
    ExecCommandsAsync -OutDir $dir -File $file -Commands $cmds

    $file = "Get-NetAdapterLso.txt"
    [String []] $cmds = "Get-NetAdapterLso -Name ""$name"" -IncludeHidden",
                        "Get-NetAdapterLso -Name ""$name"" -IncludeHidden | Format-List -Property *"
    ExecCommandsAsync -OutDir $dir -File $file -Commands $cmds

    $file = "Get-NetAdapterRss.txt"
    [String []] $cmds = "Get-NetAdapterRss -Name ""$name"" -IncludeHidden",
                        "Get-NetAdapterRss -Name ""$name"" -IncludeHidden | Format-List -Property *"
    ExecCommandsAsync -OutDir $dir -File $file -Commands $cmds

    $file = "Get-NetAdapterStatistics.txt"
    [String []] $cmds = "Get-NetAdapterStatistics -Name ""$name"" -IncludeHidden",
                        "Get-NetAdapterStatistics -Name ""$name"" -IncludeHidden | Format-List -Property *"
    ExecCommandsAsync -OutDir $dir -File $file -Commands $cmds

    $file = "Get-NetAdapterEncapsulatedPacketTaskOffload.txt"
    [String []] $cmds = "Get-NetAdapterEncapsulatedPacketTaskOffload -Name ""$name"" -IncludeHidden",
                        "Get-NetAdapterEncapsulatedPacketTaskOffload -Name ""$name"" -IncludeHidden | Format-List -Property *"
    ExecCommandsAsync -OutDir $dir -File $file -Commands $cmds

    $file = "Get-NetAdapterHardwareInfo.txt"
    [String []] $cmds = "Get-NetAdapterHardwareInfo -Name ""$name"" -IncludeHidden",
                        "Get-NetAdapterHardwareInfo -Name ""$name"" -IncludeHidden | Format-List -Property *"
    ExecCommandsAsync -OutDir $dir -File $file -Commands $cmds

    $file = "Get-NetAdapterIPsecOffload.txt"
    [String []] $cmds = "Get-NetAdapterIPsecOffload -Name ""$name"" -IncludeHidden",
                        "Get-NetAdapterIPsecOffload -Name ""$name"" -IncludeHidden | Format-List -Property *"
    ExecCommandsAsync -OutDir $dir -File $file -Commands $cmds

    $file = "Get-NetAdapterPowerManagement.txt"
    [String []] $cmds = "Get-NetAdapterPowerManagement -Name ""$name"" -IncludeHidden",
                        "Get-NetAdapterPowerManagement -Name ""$name"" -IncludeHidden | Format-List -Property *"
    ExecCommandsAsync -OutDir $dir -File $file -Commands $cmds

    $file = "Get-NetAdapterQos.txt"
    [String []] $cmds = "Get-NetAdapterQos -Name ""$name"" -IncludeHidden",
                        "Get-NetAdapterQos -Name ""$name"" -IncludeHidden | Format-List -Property *"
    ExecCommandsAsync -OutDir $dir -File $file -Commands $cmds

    $file = "Get-NetAdapterRdma.txt"
    [String []] $cmds = "Get-NetAdapterRdma -Name ""$name"" -IncludeHidden",
                        "Get-NetAdapterRdma -Name ""$name"" -IncludeHidden | Format-List -Property *",
                        "Get-NetAdapterRdma -Name ""$name"" -IncludeHidden | Select-Object -ExpandProperty RdmaAdapterInfo",
                        "Get-NetAdapterRdma -Name ""$name"" -IncludeHidden | Select-Object -ExpandProperty RdmaMissingCounterInfo"
    ExecCommandsAsync -OutDir $dir -File $file -Commands $cmds

    $file = "Get-NetAdapterPacketDirect.txt"
    [String []] $cmds = "Get-NetAdapterPacketDirect -Name ""$name"" -IncludeHidden",
                        "Get-NetAdapterPacketDirect -Name ""$name"" -IncludeHidden | Format-List -Property *"
    ExecCommandsAsync -OutDir $dir -File $file -Commands $cmds

    $file = "Get-NetAdapterRsc.txt"
    [String []] $cmds = "Get-NetAdapterRsc -Name ""$name"" -IncludeHidden",
                        "Get-NetAdapterRsc -Name ""$name"" -IncludeHidden | Format-List -Property *"
    ExecCommandsAsync -OutDir $dir -File $file -Commands $cmds

    $file = "Get-NetAdapterSriov.txt"
    [String []] $cmds = "Get-NetAdapterSriov -Name ""$name"" -IncludeHidden",
                        "Get-NetAdapterSriov -Name ""$name"" -IncludeHidden | Format-List -Property *"
    ExecCommandsAsync -OutDir $dir -File $file -Commands $cmds

    $file = "Get-NetAdapterSriovVf.txt"
    [String []] $cmds = "Get-NetAdapterSriovVf -Name ""$name"" -IncludeHidden",
                        "Get-NetAdapterSriovVf -Name ""$name"" -IncludeHidden | Format-List -Property *"
    ExecCommandsAsync -OutDir $dir -File $file -Commands $cmds

    $file = "Get-NetAdapterUso.txt"
    [String []] $cmds = "Get-NetAdapterUso -Name ""$name"" -IncludeHidden",
                        "Get-NetAdapterUso -Name ""$name"" -IncludeHidden | Format-List -Property *"
    ExecCommandsAsync -OutDir $dir -File $file -Commands $cmds

    $file = "Get-NetAdapterVmq.txt"
    [String []] $cmds = "Get-NetAdapterVmq -Name ""$name"" -IncludeHidden",
                        "Get-NetAdapterVmq -Name ""$name"" -IncludeHidden | Format-List -Property *"
    ExecCommandsAsync -OutDir $dir -File $file -Commands $cmds

    $file = "Get-NetAdapterVmqQueue.txt"
    [String []] $cmds = "Get-NetAdapterVmqQueue -Name ""$name"" -IncludeHidden",
                        "Get-NetAdapterVmqQueue -Name ""$name"" -IncludeHidden | Format-List -Property *"
    ExecCommandsAsync -OutDir $dir -File $file -Commands $cmds

    $file = "Get-NetAdapterVPort.txt"
    [String []] $cmds = "Get-NetAdapterVPort -Name ""$name"" -IncludeHidden",
                        "Get-NetAdapterVPort -Name ""$name"" -IncludeHidden | Format-List -Property *"
    ExecCommandsAsync -OutDir $dir -File $file -Commands $cmds
} # NetAdapterWorker()

function NetAdapterWorkerPrepare {
    [CmdletBinding()]
    Param(
        [parameter(Mandatory=$false)] [String] $NicName,
        [ValidateSet("pNIC", "hNIC", "NIC")]
        [parameter(Mandatory=$true)] [String] $Type,
        [parameter(Mandatory=$true)] [String] $OutDir
    )

    $name = $NicName
    $dir  = $OutDir

    $script:NetAdapterTracker += $nic.ifIndex

    # Create dir for each NIC
    $nic   = Get-NetAdapter -Name $name -IncludeHidden
    $idx   = $nic.InterfaceIndex
    $desc  = $nic.InterfaceDescription
    $title = "$Type.$idx.$name"

    if ("$desc") {
        $title = "$title.$desc"
    }

    if ($nic.Hidden) {
        $dir = Join-Path $dir "NIC.Hidden"
    }

    $dir = Join-Path $dir $(ConvertTo-Filename $title.Trim())
    New-Item -ItemType directory -Path $dir | Out-Null

    Write-Progress $Global:QueueActivity -Status "Processing $title"
    NetIpNic         -NicName $name -OutDir $dir
    NetAdapterWorker -NicName $name -OutDir $dir

    if ($Type -eq "pNIC") {
        NicVendor   -NicName $name -OutDir $dir
    } elseif ($Type -eq "hNIC") {
        HostVNicWorker -DeviceID $nic.DeviceID -OutDir $dir
    }
} # NetAdapterWorkerPrepare()

function LbfoWorker {
    [CmdletBinding()]
    Param(
        [parameter(Mandatory=$false)] [String] $LbfoName,
        [parameter(Mandatory=$true)] [String] $OutDir
    )

    $name  = $LbfoName
    $title = "LBFO.$name"

    $Global:NetLbfoTracker += $LbfoName

    $dir   = Join-Path $OutDir $(ConvertTo-Filename $title)
    New-Item -ItemType directory -Path $dir | Out-Null

    Write-Progress -Activity $Global:QueueActivity -Status "Processing $title"
    $file = "Get-NetLbfoTeam.txt"
    [String []] $cmds = "Get-NetLbfoTeam -Name ""$name""",
                        "Get-NetLbfoTeam -Name ""$name"" | Format-List  -Property *"
    ExecCommandsAsync -OutDir $dir -File $file -Commands $cmds

    $file = "Get-NetLbfoTeamNic.txt"
    [String []] $cmds = "Get-NetLbfoTeamNic -Team ""$name""",
                        "Get-NetLbfoTeamNic -Team ""$name"" | Format-List  -Property *"
    ExecCommandsAsync -OutDir $dir -File $file -Commands $cmds

    $file = "Get-NetLbfoTeamMember.txt"
    [String []] $cmds = "Get-NetLbfoTeamMember -Team ""$name""",
                        "Get-NetLbfoTeamMember -Team ""$name"" | Format-List  -Property *"
    ExecCommandsAsync -OutDir $dir -File $file -Commands $cmds

    # Report the TNIC(S)
    foreach ($tnic in TryCmd {Get-NetLbfoTeamNic -Team $name}) {
        NetAdapterWorkerPrepare -NicName $tnic.Name -Type "NIC" -OutDir $OutDir
    }

    # Report the NIC Members
    foreach ($mnic in TryCmd {Get-NetLbfoTeamMember -Team $name}) {
        NetAdapterWorkerPrepare -NicName $mnic.Name -Type "NIC" -OutDir $OutDir
    }
} # LbfoWorker()

function LbfoDetail {
    [CmdletBinding()]
    Param(
        [parameter(Mandatory=$true)] [String] $OutDir
    )

    $dir = $OutDir

    # Query remaining LBFO teams (non-Protocol NICs).
    $lbfoTeams = TryCmd {Get-NetLbfoTeam} | where {$_.Name -notin $script:NetLbfoTracker}
    foreach ($lbfo in $lbfoTeams) {
        LbfoWorker -LbfoName $lbfo.Name -OutDir $dir
    }
} # LbfoDetail()

function ProtocolNicDetail {
    [CmdletBinding()]
    Param(
        [parameter(Mandatory=$false)] [String] $VMSwitchId,
        [parameter(Mandatory=$true)] [String] $OutDir
    )

    $id  = $VMSwitchId
    $dir = $OutDir

    $vmsNicDescriptions = TryCmd {(Get-VMSwitch -Id $id).NetAdapterInterfaceDescriptions}
    foreach ($desc in $vmsNicDescriptions) {
        $nic = Get-NetAdapter -InterfaceDescription $desc
        if (-not $nic) {
            $msg = "No NetAdapter found with desciption ""$desc""."
            ExecControlError -OutDir $dir -Message $msg
            continue
        }

        if ($nic.DriverFileName -like "NdisImPlatform.sys") {
            LbfoWorker -LbfoName $nic.Name -OutDir $dir
        } else {
            NetAdapterWorkerPrepare -NicName $nic.Name -Type "pNIC" -OutDir $dir
        }
    }
} # ProtocolNicDetail()

function NativeNicDetail {
    [CmdletBinding()]
    Param(
        [parameter(Mandatory=$true)] [String] $OutDir
    )

    $dir = $OutDir

    # Query all remaining NetAdapters
    $nics = Get-NetAdapter -IncludeHidden | where {$_.ifIndex -notin $script:NetAdapterTracker}
    foreach ($nic in $nics) {
        $type = if (Get-NetAdapterHardwareInfo -Name $nic.Name -IncludeHidden -ErrorAction "SilentlyContinue") {"pNIC"} else {"NIC"}
        NetAdapterWorkerPrepare -NicName $nic.Name -Type $type -OutDir $dir
    }
} # NativeNicDetail()

function NicDetail {
    # Track which NICs or LBFO teams have been queried.
    $script:NetAdapterTracker = @()
    $script:NetLbfoTracker = @()

    # These functions must be called in the correct order.
    VMSwitchDetail    -OutDir $workDir
    LbfoDetail        -OutDir $workDir
    NativeNicDetail   -OutDir $workDir
} # NicDetail()

function ChelsioDetailPerASIC {
    [CmdletBinding()]
    Param(
        [parameter(Mandatory=$false)] [String] $NicName,
        [parameter(Mandatory=$true)] [String] $OutDir
    )

    $hwInfo       = Get-NetAdapterHardwareInfo -Name "$NicName"
    $locationInfo = $hwInfo.LocationInformationString
    $dirBusName   = "BusDev_$($hwInfo.BusNumber)_$($hwInfo.DeviceNumber)_$($hwInfo.FunctionNumber)"
    $dir          = Join-Path $OutDir $dirBusName

    if ($Global:ChelsioDeviceDirs.ContainsKey($locationInfo)) {
        New-LnkShortcut -LnkFile "$dir.lnk" -TargetPath $Global:ChelsioDeviceDirs[$locationInfo]
        return # avoid duplicate work
    } else {
        $Global:ChelsioDeviceDirs[$locationInfo] = $dir
        $null = New-Item -ItemType Directory -Path $dir
    }

    # Enumerate VBD
    $ifNameVbd = ""
    [Array] $PnPDevices = Get-PnpDevice -FriendlyName "*Chelsio*Enumerator*" | where {$_.Status -eq "OK"}
    for ($i = 0; $i -lt $PnPDevices.Count; $i++) {
        $instanceId = $PnPDevices[$i].InstanceId
        $locationInfo = (Get-PnpDeviceProperty -InstanceId "$instanceId" -KeyName "DEVPKEY_Device_LocationInfo").Data
        if ($hwInfo.LocationInformationString -eq $locationInfo) {
            $ifNameVbd = "vbd$i"
            break
        }
    }

    if ([String]::IsNullOrEmpty($ifNameVbd)) {
        $msg = "No bus device found for NIC ""$NicName""."
        ExecControlError -OutDir $dir -Message $msg
        return
    }

    $file = "ChelsioDetail-Firmware-BusDevice$i.txt"
    [String []] $cmds = "cxgbtool.exe $ifNameVbd firmware mbox 1",
                        "cxgbtool.exe $ifNameVbd firmware mbox 2",
                        "cxgbtool.exe $ifNameVbd firmware mbox 3",
                        "cxgbtool.exe $ifNameVbd firmware mbox 4",
                        "cxgbtool.exe $ifNameVbd firmware mbox 5",
                        "cxgbtool.exe $ifNameVbd firmware mbox 6",
                        "cxgbtool.exe $ifNameVbd firmware mbox 7"
    ExecCommands -OutDir $dir -File $file -Commands $cmds

    $file = "ChelsioDetail-Hardware-BusDevice$i.txt"
    [String []] $cmds = "cxgbtool.exe $ifNameVbd hardware sgedbg"
    ExecCommands -OutDir $dir -File $file -Commands $cmds

    $file = "ChelsioDetail-Dumps-BusDevice$i.txt"
    [String []] $cmds = "cxgbtool.exe $ifNameVbd hardware flash ""$dir\Hardware-BusDevice$i-flash.dmp""",
                        "cxgbtool.exe $ifNameVbd cudbg collect all ""$dir\Cudbg-Collect.dmp""",
                        "cxgbtool.exe $ifNameVbd cudbg readflash ""$dir\Cudbg-Readflash.dmp"""
    ExecCommandsAsync -OutDir $dir -File $file -Commands $cmds
} # ChelsioDetailPerASIC()

function ChelsioDetail {
    [CmdletBinding()]
    Param(
        [parameter(Mandatory=$false)] [String] $NicName,
        [parameter(Mandatory=$true)] [String] $OutDir
    )

    $dir = (Join-Path -Path $OutDir -ChildPath "ChelsioDetail")
    New-Item -ItemType Directory -Path $dir | Out-Null

    $file = "ChelsioDetail-Misc.txt"
    [String []] $cmds = "verifier /query",
                        "Get-PnpDevice -FriendlyName ""*Chelsio*Enumerator*"" | Get-PnpDeviceProperty -KeyName DEVPKEY_Device_DriverVersion | Format-Table -Autosize"
    ExecCommandsAsync -OutDir $dir -File $file -Commands $cmds

    $cxgbtoolTest = TryCmd {cxgbtool.exe}
    if (-not $cxgbtoolTest) {
        $msg = "cxgbtool is required to collect Chelsio diagnostics."
        ExecControlError -OutDir $dir -Message $msg
        return
    }

    ChelsioDetailPerASIC -NicName $NicName -OutDir $dir

    $ifIndex    = (Get-NetAdapter $NicName).InterfaceIndex
    $dirNetName = "NetDev_$ifIndex"
    $dirNet     = (Join-Path -Path $dir -ChildPath $dirNetName)
    New-Item -ItemType Directory -Path $dirNet | Out-Null

    # Enumerate NIC
    $netDevices = Get-NetAdapter -InterfaceDescription "*Chelsio*" | where {$_.Status -eq "Up"} | sort -Property MacAddress
    $nicIndex = @($netDevices.Name).IndexOf($NicName)

    if ($nicIndex -eq -1) {
        $msg = "Invalid state for NIC ""$NicName"". Make sure status is ""Up""."
        ExecControlError -OutDir $dir -Message $msg
        return
    }

    $file = "ChelsioDetail-Debug.txt"
    [String []] $cmds = "cxgbtool.exe nic$nicIndex debug filter",
                        "cxgbtool.exe nic$nicIndex debug qsets",
                        "cxgbtool.exe nic$nicIndex debug qstats txeth rxeth txvirt rxvirt txrdma rxrdma txnvgre rxnvgre",
                        "cxgbtool.exe nic$nicIndex debug dumpctx",
                        "cxgbtool.exe nic$nicIndex debug version",
                        "cxgbtool.exe nic$nicIndex debug eps",
                        "cxgbtool.exe nic$nicIndex debug qps",
                        "cxgbtool.exe nic$nicIndex debug rdma_stats",
                        "cxgbtool.exe nic$nicIndex debug stags",
                        "cxgbtool.exe nic$nicIndex debug l2t"
    ExecCommandsAsync -OutDir $dirNet -File $file -Commands $cmds

    $file = "ChelsioDetail-Hardware.txt"
    [String []] $cmds = "cxgbtool.exe nic$nicIndex hardware tid_info",
                        "cxgbtool.exe nic$nicIndex hardware fec",
                        "cxgbtool.exe nic$nicIndex hardware link_cfg",
                        "cxgbtool.exe nic$nicIndex hardware pktfilter",
                        "cxgbtool.exe nic$nicIndex hardware sensor"
    ExecCommandsAsync -OutDir $dirNet -File $file -Commands $cmds
} # ChelsioDetail()

function MellanoxFirmwareInfo {
    [CmdletBinding()]
    Param(
        [parameter(Mandatory=$false)] [String] $NicName,
        [parameter(Mandatory=$true)] [String] $OutDir
    )

    $dir  = $OutDir

    $mstStatus = TryCmd {mst status -v}
    if ((-not $mstStatus) -or ($mstStatus -like "*error*")) {
        $msg = "Mellanox Firmware Tools (MFT) is required to collect firmware diagnostics."
        ExecControlError -OutDir $dir -Message $msg
        return
    }

    #
    # Parse "mst status" output and match to Nic
    #
    [Bool] $found = $false
    $hwInfo = Get-NetAdapterHardwareInfo -Name $NicName

    foreach ($line in ($mstStatus | where {$_ -like "*pciconf*"})) {
        $device, $info = $line.Trim() -split " "
        $busNum, $deviceNum, $functionNum = $info -split "[:.=]" | select -Last 3 | foreach {[Int64]"0x$_"}

        if (($hwInfo.Bus -eq $busNum) -and ($hwInfo.Device -eq $deviceNum) -and ($hwInfo.Function -eq $functionNum)) {
            $found = $true
            $device = $device.Trim()
            break
        }
    }

    if (-not $found) {
        $msg = "No device found in mst status matching NIC ""$NicName""."
        ExecControlError -OutDir $dir -Message $msg
        return
    }

    $deviceDir = Join-Path $dir "mstdump-$device"
    $null = New-Item -ItemType Directory -Path $deviceDir

    $file = "MellanoxFirmwareInfo.txt"
    [String[]] $cmds = "mst status",
                       "flint -d $device query",
                       "flint -d $device dc",
                       "mstdump $device >> ""$deviceDir\1.txt""",
                       "mstdump $device >> ""$deviceDir\2.txt""",
                       "mstdump $device >> ""$deviceDir\3.txt""",
                       "mlxconfig -d $device query",
                       "mlxdump -d $device fsdump --type FT"
    ExecCommandsAsync -OutDir $dir -File $file -Commands $cmds
} # MellanoxFirmwareInfo()

function MellanoxWinOFTool{
    [CmdletBinding()]
    Param(
        [parameter(Mandatory=$false)] [String] $NicName,
        [parameter(Mandatory=$true)] [String] $OutDir
    )

    $dir = $OutDir

    $toolName = "mlxtool.exe"
    $toolPath = "$env:ProgramFiles\Mellanox\MLNX_VPI\Tools\$toolName"
    $mlxTool = "&""$toolPath"""

    $hardwareInfo = Get-NetAdapterHardwareInfo -Name $NicName
    $deviceLocation = "$($hardwareInfo.bus)`_$($hardwareInfo.device)`_$($hardwareInfo.function)"

    $toolCmds = "$mlxTool show ports",
                "$mlxTool show devices",
                "$mlxTool show tc-bw",
                "$mlxTool show vxlan",
                "$mlxTool show ecn config",
                "$mlxTool show packet-filter",
                "$mlxTool show qos",
                "$mlxTool show regkeys all miniport",
                "$mlxTool show regkeys all bus",
                "$mlxTool show nd connections",
                "$mlxTool show ndk connections",
                "$mlxTool show perfstats ""$NicName"" showall",
                "$mlxTool show driverparams",
                "$mlxTool show selfhealing port",
                "$mlxTool dbg oid-stats-ext",
                "$mlxTool dbg cmd-stats-ext",
                "$mlxTool dbg resources",
                "$mlxTool dbg pkeys",
                "$mlxTool dbg ipoib-ep",
                "$mlxTool dbg get-state",
                "$mlxTool dbg rfd-profiling ""$NicName"" dump",
                "$mlxTool dbg pddrinfo",
                "$mlxTool dbg dump-me-now",
                "$mlxTool dbg eq-data ""$deviceLocation""",
                "$mlxTool dbg dma-cached-stats ""$deviceLocation"""

    $file = "mlxtoolOutput.txt"
    ExecCommandsAsync -OutDir $dir -File $file -Commands $toolCmds

} # MellanoxWinOFTool

function MellanoxDetailPerNic {
    [CmdletBinding()]
    Param(
        [parameter(Mandatory=$false)] [String] $NicName,
        [parameter(Mandatory=$true)] [String] $OutDir
    )

    $dir = $OutDir

    $driverFileName = (Get-NetAdapter -name $NicName).DriverFileName
    $driverDir = switch ($driverFileName) {
        "mlx5.sys" {
            "$env:ProgramFiles\Mellanox\MLNX_WinOF2"
            break
        }
        "mlnx5.sys" {
            "$env:ProgramFiles\Mellanox\MLNX_WinOF2_Azure"
            break
        }
        "mlnx5hpc.sys" {
            "$env:ProgramFiles\Mellanox\MLNX_WinOF2_Azure_HPC"
            break
        }
        "ipoib6x.sys" {
            "$env:ProgramFiles\Mellanox\MLNX_VPI"
            break
        }
        "mlx4eth63.sys" {
            "$env:ProgramFiles\Mellanox\MLNX_VPI"
            break
        }
        default {
            $msg = "Unsupported driver $driverFileName."
            ExecControlError -OutDir $dir -Message $msg
            return
        }
    }

    #
    # Execute tool
    #

    $DriverName = $( if ($driverFileName -in @("Mlx5.sys", "Mlnx5.sys", "Mlnx5Hpc.sys")) {"WinOF2"} else {"WinOF"})
    if ($DriverName -eq "WinOF2") {

        $driverVersionString = (Get-NetAdapter -name $NicName).DriverVersionString
        $versionMajor, $_ = $driverVersionString -split "\."

        if ($versionMajor -ge 3) {
            $toolName = $driverFileName -replace ".sys", "Cmd"
            $toolPath = "$driverDir\Management Tools\$toolName.exe"

            $file = "$toolName-Snapshot.txt"
            [String []] $cmds = "&""$toolPath"" -SnapShot -name ""$NicName"""
            $functionIds = (Get-NetAdapterSriovVf -Name "$NicName" -ErrorAction SilentlyContinue).FunctionID
            if ($functionIds -ne $null) {
                foreach ($id in $functionIds) {
                    $cmds += "&""$toolPath"" -SnapShot -VfStats -name ""$NicName"" -vf $id -register"
                }
            }
            ExecCommandsAsync -OutDir $dir -File $file -Commands $cmds
        }
    } else {
        MellanoxWinOFTool -NicName $NicName -OutDir $Dir
    }

    #
    # Enumerate device location string
    #
    if ((Get-NetAdapterHardwareInfo -Name $NicName).LocationInformationString -like "*Virtual*") {
        [String[]] $locationInfoArray = (Get-NetAdapterHardwareInfo -Name $NicName).LocationInformationString -split " "

        $slot   = $locationInfoArray[$locationInfoArray.IndexOf("Slot") + 1]
        $serial = $locationInfoArray[$locationInfoArray.IndexOf("Serial") + 1]

        $deviceLocation = "$slot`_$serial`_0"
    } else {
        $hardwareInfo = Get-NetAdapterHardwareInfo -Name $NicName
        $deviceLocation = "$($hardwareInfo.bus)`_$($hardwareInfo.device)`_$($hardwareInfo.function)"
    }

    #
    # Dump Me Now (DMN)
    #
    $deviceID     = (Get-NetAdapter -name $NicName).PnPDeviceID
    $driverRegKey = (Get-ItemProperty "HKLM:\System\CurrentControlSet\Enum\$deviceID").Driver
    $dumpMeNowDir = (Get-ItemProperty "HKLM:\System\CurrentControlSet\Control\Class\$driverRegKey").DumpMeNowDirectory

    if (($dumpMeNowDir -like "\DosDevice\*") -or ($dumpMeNowDir -like "\??\*")) {
        $dmpPath = $dumpMeNowDir.SubString($dumpMeNowDir.IndexOf("\", 1))
    } else {
        $dmpPath = "$env:windir\Temp\MLX{0}_Dump_Me_Now" -f $(if ($DriverName -eq "WinOF2") {"5"} else {"4"})
    }

    $file = "Copy-MellanoxDMN.txt"
    [String[]] $paths = "$dmpPath{0}" -f $(if ($DriverName -eq "WinOF2") {("-" + $deviceLocation -replace "_","-")})
    ExecCopyItemsAsync -OutDir $dir -File $file -Paths $paths -Destination $dir

    #
    # Device logs
    #

    $file = "Copy-DeviceLogs.txt"
    $destination = Join-Path $dir "DeviceLogs"
    $buildIdPath = "$driverDir\build_id.txt"

    ExecCopyItemsAsync -OutDir $dir -File $file -Paths $buildIdPath -Destination $destination

    if ($DriverName -eq "WinOF2"){
        [String[]] $paths = "$env:windir\Temp\SingleFunc*$deviceLocation*.log",
                            "$env:windir\Temp\SriovMaster*$deviceLocation*.log",
                            "$env:windir\Temp\SriovSlave*$deviceLocation*.log",
                            "$env:windir\Temp\Native*$deviceLocation*.log",
                            "$env:windir\Temp\Master*$deviceLocation*.log",
                            "$env:windir\Temp\ML?X5*$deviceLocation*.log",
                            "$env:windir\Temp\mlx5*$deviceLocation*.log",
                            "$env:windir\Temp\FwTrace"
        ExecCopyItemsAsync -OutDir $dir -File $file -Paths $paths -Destination $destination
    }
} # MellanoxDetailPerNic()

function MellanoxSystemDetail {
    [CmdletBinding()]
    Param(
        [parameter(Mandatory=$false)] [String] $NicName,
        [parameter(Mandatory=$true)] [String] $OutDir
    )

    $dir = Join-Path $OutDir "SystemLogs"

    if ([String]::IsNullOrEmpty($Global:MellanoxSystemLogDir)){
        $Global:MellanoxSystemLogDir = $dir
        $null = New-Item -ItemType Directory -Path $dir
    } else {
        New-LnkShortcut -LnkFile "$dir.lnk" -TargetPath $Global:MellanoxSystemLogDir
        return # avoid duplicate effort
    }

    $file = "MellanoxMiscInfo.txt"
    [String []] $cmds = "netsh advfirewall show allprofiles",
                        "netstat -n",
                        "netstat -nasert",
                        "netstat -an",
                        "netstat -xan | where {`$_ -match ""445""}",
                        "Get-SmbConnection",
                        "Get-SmbServerConfiguration"
    ExecCommands -OutDir $dir -File $file -Commands $cmds

    $driverFileName = (Get-NetAdapter -name $NicName).DriverFileName
    $DriverName = if ($driverFileName -in @("Mlx5.sys", "Mlnx5.sys", "Mlnx5Hpc.sys")) {"WinOF2"} else {"WinOF"}

    $file = "Copy-LogFiles.txt"
    $destination = Join-Path $dir "LogFiles"

    $mlxEtl = "Mellanox{0}.etl*" -f $(if ($DriverName -eq "WinOF2") {"-WinOF2*"} else {"-System*"})
    $mlxLog = "MLNX_WINOF{0}.log"  -f $(if ($DriverName -eq "WinOF2") {"2"})

    [String[]] $paths = "$env:windir\System32\LogFiles\PerformanceTuning.log",
                        "$env:LOCALAPPDATA\$mlxLog",
                        "$env:windir\inf\setupapi.dev",
                        "$env:windir\inf\setupapi.dev.log",
                        "$env:temp\MpKdTraceLog.bin",
                        "$env:windir\System32\LogFiles\Mlnx\$mlxEtl",
                        "$env:windir\debug\$mlxEtl"
    ExecCopyItemsAsync -OutDir $dir -File $file -Paths $paths -Destination $destination
} # MellanoxSystemDetail()

function MellanoxDetail {
    [CmdletBinding()]
    Param(
        [parameter(Mandatory=$false)] [String] $NicName,
        [parameter(Mandatory=$true)] [String] $OutDir
    )

    $dir = (Join-Path -Path $OutDir -ChildPath "MellanoxDetail")
    New-Item -ItemType Directory -Path $dir | Out-Null

    $driverVersionString = (Get-NetAdapter -name $NicName).DriverVersionString
    $versionMajor, $versionMinor, $_ = $driverVersionString -split "\."

    if (($versionMajor -lt 2) -or (($versionMajor -eq 2) -and ($versionMinor -lt 20))) {
        $msg = "Unsupported driver version $versionMajor.$versionMinor, minimum is 2.20."
        ExecControlError -OutDir $dir -Message $msg
        return
    }

    MellanoxSystemDetail -NicName $NicName -OutDir $dir
    MellanoxFirmwareInfo -NicName $NicName -OutDir $dir
    MellanoxDetailPerNic -NicName $NicName -OutDir $dir
} # MellanoxDetail()

function MarvellDetail{
    [CmdletBinding()]
    Param(
        [parameter(Mandatory=$true)] [String] $NicName,
        [parameter(Mandatory=$true)] [String] $OutDir
    )

$MarvellGetDiagDataClass = @"
using System;
using System.IO;
using System.Text;
using System.Runtime.InteropServices;
using Microsoft.Win32.SafeHandles;

public class MarvellGetDiagData
{
    private const uint QEBDRV_DIAG_IOC = 0x80002538;
    private const uint EBDRV_DIAG_IOC = 0x80002130;
    private const uint NIC_DIAG_IOC = 0x00170002;
    private const uint L2ND2_DIAG_IOC = 0xFF010148;
    private const uint QEBDRV_DIAG_MASK = 0xFFFDFF7F;
    private const uint EBDRV_DIAG_MASK = 0xFFFFFFFF;
    private const uint L2ND2_DIAG_MASK = 0xFFFFFFFF;
    private const uint SIGNATURE = 0x4488AACC;
    private const uint QEBDRV_DIAG_REVISION = 0x01;
    private const uint EBDRV_DIAG_REVISION = 0x01;
    private const uint L2ND2_DIAG_REVISION = 0x01;

    private const uint BYTE_SIZE = (9 * 1024 * 1024);

    [StructLayout(LayoutKind.Sequential)]
    public struct DiagInput_t
    {
        public uint revision;
        public uint data_mask;
        public uint signature;
        [MarshalAs(UnmanagedType.ByValArray, SizeConst = 5)]
        public int[] reserved;
    }

    [DllImport("Kernel32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
    private static extern SafeFileHandle CreateFile(
        string lpFileName,
        [MarshalAs(UnmanagedType.U4)] FileAccess dwDesiredAccess,
        [MarshalAs(UnmanagedType.U4)] FileShare dwShareMode,
        IntPtr lpSecurityAttributes,
        [MarshalAs(UnmanagedType.U4)] FileMode dwCreationDisposition,
        [MarshalAs(UnmanagedType.U4)] FileAttributes dwFlagsAndAttributes,
        IntPtr hTemplateFile);

    [DllImport("Kernel32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
    private static extern bool DeviceIoControl(
        SafeFileHandle hDevice,
        uint IoControlCode,
        byte[] InBuffer,
        int nInBufferSize,
        byte[] OutBuffer,
        int nOutBufferSize,
        ref int pBytesReturned,
        IntPtr Overlapped
        );

    public int MarvellGetDiagDataIoctl(string DeviceID, string FilePath, string ServiceName, StringBuilder ErrString)
    {
        bool bResult;
        string FileName;
        uint revision_set;
        uint data_mask_set;
        uint ioctl_value;
        string DevPath;
        int bytesReturned = 0;
        SafeFileHandle shwnd = null;
        FileStream file = null;

        ErrString.Clear();

        if ((DeviceID == null) || (FilePath == null))
        {
            ErrString.Append("MarvellGetDiagDataIoctl: Input parameter to MarvellGetDiagDataIoctl is invalid");
            return 0;
        }

        try
        {
            if (ServiceName.Equals("QEBDRV", StringComparison.OrdinalIgnoreCase))
            {
                DevPath = "\\\\?\\Global\\" + DeviceID.Replace("\\", "#");
                DevPath += "#{5966d73c-bc2c-49b8-9315-c64c9919e976}";

                ioctl_value = QEBDRV_DIAG_IOC;
                revision_set = QEBDRV_DIAG_REVISION;
                data_mask_set = QEBDRV_DIAG_MASK;
            }
            else if (ServiceName.Equals("EBDRV", StringComparison.OrdinalIgnoreCase))
            {
                DevPath = "\\\\?\\Global\\" + DeviceID.Replace("\\", "#");
                DevPath += "#{ea22615e-c443-434f-9e45-c4e32d83e97d}";

                ioctl_value = EBDRV_DIAG_IOC;
                revision_set = EBDRV_DIAG_REVISION;
                data_mask_set = EBDRV_DIAG_MASK;
            }
            else if (ServiceName.Equals("L2ND2", StringComparison.OrdinalIgnoreCase))
            {
                DevPath = "\\\\.\\" + DeviceID.Replace("\\", "#");

                ioctl_value = NIC_DIAG_IOC;
                revision_set = L2ND2_DIAG_REVISION;
                data_mask_set = L2ND2_DIAG_MASK;
            }
            else
            {
                ErrString.Append("MarvellGetDiagDataIoctl: Invalid or unsupported service (" + ServiceName + ")");
                return 0;
            }

            ErrString.Append("MarvellGetDiagDataIoctl: " + DevPath + "\n");
            shwnd = CreateFile(DevPath, FileAccess.Write | FileAccess.Read, FileShare.Read |
                FileShare.Write, IntPtr.Zero, FileMode.Open, FileAttributes.Normal, IntPtr.Zero);
            if (shwnd.IsClosed | shwnd.IsInvalid)
            {
                ErrString.Append("MarvellGetDiagDataIoctl: CreateFile failed with error " + Marshal.GetLastWin32Error());
                return 0;
            }

            DiagInput_t DiagInput = new DiagInput_t
            {
                revision = revision_set,
                data_mask = data_mask_set,
                signature = SIGNATURE
            };

            int InBufLen = Marshal.SizeOf<DiagInput_t>();
            IntPtr ptr = Marshal.AllocHGlobal(InBufLen);
            Marshal.StructureToPtr(DiagInput, ptr, true);

            byte[] InBuffer;
            byte[] OutBuffer = new byte[BYTE_SIZE];
            Array.Clear(OutBuffer, 0, OutBuffer.Length);

            if (ioctl_value == NIC_DIAG_IOC)
            {
                Marshal.Copy(ptr, OutBuffer, 0, InBufLen);
                InBuffer = BitConverter.GetBytes(L2ND2_DIAG_IOC);
            }
            else
            {
                InBuffer = new byte[InBufLen];
                Marshal.Copy(ptr, InBuffer, 0, InBufLen);
            }
            Marshal.FreeHGlobal(ptr);

            bResult = DeviceIoControl(shwnd, ioctl_value, InBuffer, InBuffer.Length,
                OutBuffer, OutBuffer.Length, ref bytesReturned, IntPtr.Zero);
            if (bResult)
            {
                FileName = String.Format("DiagData-{0}.bin", ServiceName);
                FilePath += "\\" + FileName;

                file = File.Create(FilePath);
                file.Write(OutBuffer, 0, bytesReturned);
            }
            else
            {
                ErrString.Append("MarvellGetDiagDataIoctl: DeviceIoControl failed with error " + Marshal.GetLastWin32Error());
                bytesReturned = 0;
            }
        }
        catch (Exception e)
        {
            ErrString.Append("MarvellGetDiagDataIoctl: Exception generated: " + e.Message);
        }
        finally
        {
            if (file != null)
            {
                file.Close();
            }
            if (shwnd != null)
            {
                shwnd.Close();
            }
        }

        return bytesReturned;
    }
}
"@

    try {
        $NDIS_PnPDeviceID = (Get-NetAdapter -Name $NicName).PnPDeviceID
        $NDIS_DeviceID = (Get-NetAdapter -Name $NicName).DeviceID
        $NDIS_Service = (Get-PnpDeviceProperty -InstanceId "$NDIS_PnPDeviceID" -KeyName "DEVPKEY_Device_Service").Data
        $VBD_DeviceID = (Get-PnpDeviceProperty -InstanceId "$NDIS_PnPDeviceID" -KeyName "DEVPKEY_Device_Parent").Data
        $VBD_Service = (Get-PnpDeviceProperty -InstanceId "$VBD_DeviceID" -KeyName "DEVPKEY_Device_Service").Data

        $file = "$NicName-BusVerifierInfo.txt"
        [String []] $cmds = "verifier /query",
                            "Get-PnpDeviceProperty -InstanceId '$VBD_DeviceID' | Select-Object KeyName, Data | Format-Table -AutoSize"
        ExecCommandsAsync -OutDir $dir -File $file -Commands $cmds

        $file = "$NicName-NicVerifierInfo.txt"
        [String []] $cmds = "verifier /query",
                            "Get-PnpDeviceProperty -InstanceId '$NDIS_PnPDeviceID' | Select-Object KeyName, Data | Format-Table -Autosize"
        ExecCommandsAsync -OutDir $dir -File $file -Commands $cmds

        Add-Type -TypeDefinition $MarvellGetDiagDataClass -ErrorAction Stop
        $r = New-Object -TypeName "MarvellGetDiagData"
        $errorString = New-Object -TypeName "System.Text.StringBuilder"

        $output = $r.MarvellGetDiagDataIoctl($VBD_DeviceID, $OutDir, $VBD_Service, $errorString)
        if ($output -le 0) {
            $msg = $errorString.ToString()
            ExecControlError -OutDir $OutDir -Message $msg
        }

        $output = $r.MarvellGetDiagDataIoctl($NDIS_DeviceID, $OutDir, $NDIS_Service, $errorString)
        if ($output -le 0) {
            $msg = $errorString.ToString()
            ExecControlError -OutDir $OutDir -Message $msg
        }
    } catch {
        $msg = $($error[0] | Out-String)
        ExecControlError -OutDir $OutDir -Message $msg
    } finally {
        Remove-Variable MarvellGetDiagDataClass -ErrorAction SilentlyContinue
    }
} # Marvell Detail

<#
.SYNOPSIS
    Function stub for extension by IHVs Copy and rename it,
    add your commands, and call it in NicVendor() below
#>
function MyVendorDetail {
    [CmdletBinding()]
    Param(
        [parameter(Mandatory=$false)] [String] $NicName,
        [parameter(Mandatory=$true)] [String] $OutDir
    )

    $dir = Join-Path -Path $OutDir -ChildPath "MyVendorDetail"

    # Try to keep the layout of this block of code
    # Feel free to copy it or wrap it in other control structures
    # See other functions in this file for examples
    $file = "CommandOutput.txt"
    [String []] $cmds = "Command 1",
                        "Command 2",
                        "Command 3",
                        "etc."
    ExecCommandsAsync -OutDir $dir -File $file -Commands $cmds
} # MyVendorDetail()

function NicVendor {
    [CmdletBinding()]
    Param(
        [parameter(Mandatory=$true)] [String] $NicName,
        [parameter(Mandatory=$true)] [String] $OutDir
    )

    $dir = $OutDir

    $pciId = TryCmd {(Get-NetAdapterAdvancedProperty -Name $NicName -AllProperties -RegistryKeyword "ComponentID").RegistryValue}
    switch -Wildcard($pciId) {
        "CHT*BUS\chnet*" {
            ChelsioDetail  $NicName $dir
            break
        }
        "PCI\VEN_15B3*" {
            MellanoxDetail $NicName $dir
            break
        }
        "*ConnectX-3*" {
            MellanoxDetail $NicName $dir
            break
        }
        "*EBDRV\L2ND*" {
            MarvellDetail  $NicName $dir
            break
        }
        # To extend refer to MyVendorDetail() above.
        default {
        }
    }
} # NicVendor()

function HostVNicWorker {
    [CmdletBinding()]
    Param(
        [parameter(Mandatory=$false)] [String] $DeviceId,
        [parameter(Mandatory=$true)] [String] $OutDir
    )

    $dir  = $OutDir

    $file = "Get-VMNetworkAdapter.txt"
    [String []] $cmds = "Get-VMNetworkAdapter -ManagementOS | where {`$_.DeviceId -eq ""$DeviceId""}",
                        "Get-VMNetworkAdapter -ManagementOS | where {`$_.DeviceId -eq ""$DeviceId""} | Format-List  -Property *"
    ExecCommandsAsync -OutDir $dir -File $file -Commands $cmds

    $file = "Get-VMNetworkAdapterAcl.txt"
    [String []] $cmds = "Get-VMNetworkAdapterAcl -ManagementOS | where {`$_.DeviceId -eq ""$DeviceId""}",
                        "Get-VMNetworkAdapterAcl -ManagementOS | where {`$_.DeviceId -eq ""$DeviceId""} | Format-List  -Property *"
    ExecCommandsAsync -OutDir $dir -File $file -Commands $cmds

    $file = "Get-VMNetworkAdapterExtendedAcl.txt"
    [String []] $cmds = "Get-VMNetworkAdapterExtendedAcl -ManagementOS | where {`$_.DeviceId -eq ""$DeviceId""}",
                        "Get-VMNetworkAdapterExtendedAcl -ManagementOS | where {`$_.DeviceId -eq ""$DeviceId""} | Format-List  -Property *"
    ExecCommandsAsync -OutDir $dir -File $file -Commands $cmds

    $file = "Get-VMNetworkAdapterIsolation.txt"
    [String []] $cmds = "Get-VMNetworkAdapterIsolation -ManagementOS | where {`$_.DeviceId -eq ""$DeviceId""}",
                        "Get-VMNetworkAdapterIsolation -ManagementOS | where {`$_.DeviceId -eq ""$DeviceId""} | Format-List  -Property *"
    ExecCommandsAsync -OutDir $dir -File $file -Commands $cmds

    $file = "Get-VMNetworkAdapterRoutingDomainMapping.txt"
    [String []] $cmds = "Get-VMNetworkAdapterRoutingDomainMapping -ManagementOS | where {`$_.DeviceId -eq ""$DeviceId""}",
                        "Get-VMNetworkAdapterRoutingDomainMapping -ManagementOS | where {`$_.DeviceId -eq ""$DeviceId""} | Format-List -Property *"
    ExecCommandsAsync -OutDir $dir -File $file -Commands $cmds

    $file = "Get-VMNetworkAdapterTeamMapping.txt"
    [String []] $cmds = "Get-VMNetworkAdapterTeamMapping -ManagementOS | where {`$_.DeviceId -eq ""$DeviceId""}",
                        "Get-VMNetworkAdapterTeamMapping -ManagementOS | where {`$_.DeviceId -eq ""$DeviceId""} | Format-List  -Property *"
    ExecCommandsAsync -OutDir $dir -File $file -Commands $cmds

    $file = "Get-VMNetworkAdapterVlan.txt"
    [String []] $cmds = "Get-VMNetworkAdapterVlan -ManagementOS | where {`$_.DeviceId -eq ""$DeviceId""}",
                        "Get-VMNetworkAdapterVlan -ManagementOS | where {`$_.DeviceId -eq ""$DeviceId""} | Format-List  -Property *"
    ExecCommandsAsync -OutDir $dir -File $file -Commands $cmds
} # HostVNicWorker()

function HostVNicDetail {
    [CmdletBinding()]
    Param(
        [parameter(Mandatory=$false)] [String] $VMSwitchId,
        [parameter(Mandatory=$true)] [String] $OutDir
    )

    # Cache output
    $allNetAdapters = Get-NetAdapter -IncludeHidden

    foreach ($hnic in TryCmd {Get-VMNetworkAdapter -ManagementOS} | where {$_.SwitchId -eq $VMSwitchId}) {
        # Use device ID to find corresponding NetAdapter instance
        $nic = $allNetAdapters | where {$_.DeviceID -eq $hnic.DeviceID}

        NetAdapterWorkerPrepare -NicName $nic.Name -Type "hNIC" -OutDir $OutDir
    }
} # HostVNicDetail()

function VMNetworkAdapterDetail {
    [CmdletBinding()]
    Param(
        [parameter(Mandatory=$false)] [String] $VMName,
        [parameter(Mandatory=$false)] [String] $VMNicName,
        [parameter(Mandatory=$false)] [String] $VMNicId,
        [parameter(Mandatory=$true)] [String] $OutDir
    )

    $name  = $VMNicName
    $id    = $VMNicId
    $title = "VMNic.$name.$id"

    $dir  = Join-Path $OutDir $(ConvertTo-Filename $title)
    $null = New-Item -ItemType directory -Path $dir

    # We must use Id to identity VMNics, because different VMNics
    # can have the same MAC (none if VM is off), Name, VMName, and SwitchName.
    [String] $vmNicObject = "`$(Get-VMNetworkAdapter -VMName ""$VMName"" -Name ""$VMNicName"" | where {`$_.Id -like ""*$id""})"

    Write-Progress -Activity $Global:QueueActivity -Status "Processing $title"
    $file = "Get-VMNetworkAdapter.txt"
    [String []] $cmds = "$vmNicObject",
                        "$vmNicObject | Format-List -Property *"
    ExecCommandsAsync -OutDir $dir -File $file -Commands $cmds

    $file = "Get-VMNetworkAdapterAcl.txt"
    [String []] $cmds = "Get-VMNetworkAdapterAcl -VMNetworkAdapter $vmNicObject",
                        "Get-VMNetworkAdapterAcl -VMNetworkAdapter $vmNicObject | Format-List -Property *"
    ExecCommandsAsync -OutDir $dir -File $file -Commands $cmds

    $file = "Get-VMNetworkAdapterExtendedAcl.txt"
    [String []] $cmds = "Get-VMNetworkAdapterExtendedAcl -VMNetworkAdapter $vmNicObject",
                        "Get-VMNetworkAdapterExtendedAcl -VMNetworkAdapter $vmNicObject | Format-List -Property *"
    ExecCommandsAsync -OutDir $dir -File $file -Commands $cmds

    $file = "Get-VMNetworkAdapterFailoverConfiguration.txt"
    [String []] $cmds = "Get-VMNetworkAdapterFailoverConfiguration -VMNetworkAdapter $vmNicObject",
                        "Get-VMNetworkAdapterFailoverConfiguration -VMNetworkAdapter $vmNicObject | Format-List -Property *"
    ExecCommandsAsync -OutDir $dir -File $file -Commands $cmds

    $file = "Get-VMNetworkAdapterIsolation.txt"
    [String []] $cmds = "Get-VMNetworkAdapterIsolation -VMNetworkAdapter $vmNicObject",
                        "Get-VMNetworkAdapterIsolation -VMNetworkAdapter $vmNicObject | Format-List -Property *"
    ExecCommandsAsync -OutDir $dir -File $file -Commands $cmds

    $file = "Get-VMNetworkAdapterRoutingDomainMapping.txt"
    [String []] $cmds = "Get-VMNetworkAdapterRoutingDomainMapping -VMNetworkAdapter $vmNicObject",
                        "Get-VMNetworkAdapterRoutingDomainMapping -VMNetworkAdapter $vmNicObject | Format-List -Property *"
    ExecCommandsAsync -OutDir $dir -File $file -Commands $cmds

    $file = "Get-VMNetworkAdapterTeamMapping.txt"
    [String []] $cmds = "Get-VMNetworkAdapterTeamMapping -VMNetworkAdapter $vmNicObject",
                        "Get-VMNetworkAdapterTeamMapping -VMNetworkAdapter $vmNicObject | Format-List -Property *"
    ExecCommandsAsync -OutDir $dir -File $file -Commands $cmds

    $file = "Get-VMNetworkAdapterVlan.txt"
    [String []] $cmds = "Get-VMNetworkAdapterVlan -VMNetworkAdapter $vmNicObject",
                        "Get-VMNetworkAdapterVlan -VMNetworkAdapter $vmNicObject | Format-List -Property *"
    ExecCommandsAsync -OutDir $dir -File $file -Commands $cmds

    $file = "Get-VMSwitchExtensionPortFeature.txt"
    [String []] $cmds = "Get-VMSwitchExtensionPortFeature -VMNetworkAdapter $vmNicObject | Format-List -Property *"
    ExecCommandsAsync -OutDir $dir -File $file -Commands $cmds

    $file = "Get-VMSwitchExtensionPortData.txt"
    [String []] $cmds = "Get-VMSwitchExtensionPortData -VMNetworkAdapter $vmNicObject | Format-List -Property *"
    ExecCommandsAsync -OutDir $dir -File $file -Commands $cmds
} # VMNetworkAdapterDetail()

function VMWorker {
    [CmdletBinding()]
    Param(
        [parameter(Mandatory=$false)] [String] $VMId,
        [parameter(Mandatory=$true)] [String] $OutDir
    )

    $id  = $VMId
    $dir = $OutDir

    # Different VMs can have the same name
    [String] $vmObject = "`$(Get-VM -Id $id)"

    $file = "Get-VM.txt"
    [String []] $cmds = "$vmObject",
                        "$vmObject | Format-List -Property *"
    ExecCommandsAsync -OutDir $dir -File $file -Commands $cmds

    $file = "Get-VMBios.txt"
    [String []] $cmds = "Get-VMBios -VM $vmObject",
                        "Get-VMBios -VM $vmObject | Format-List -Property *"
    ExecCommandsAsync -OutDir $dir -File $file -Commands $cmds

    $file = "Get-VMFirmware.txt"
    [String []] $cmds = "Get-VMFirmware -VM $vmObject",
                        "Get-VMFirmware -VM $vmObject | Format-List -Property *"
    ExecCommandsAsync -OutDir $dir -File $file -Commands $cmds

    $file = "Get-VMProcessor.txt"
    [String []] $cmds = "Get-VMProcessor -VM $vmObject",
                        "Get-VMProcessor -VM $vmObject | Format-List -Property *"
    ExecCommandsAsync -OutDir $dir -File $file -Commands $cmds

    $file = "Get-VMMemory.txt"
    [String []] $cmds = "Get-VMMemory -VM $vmObject",
                        "Get-VMMemory -VM $vmObject | Format-List -Property *"
    ExecCommandsAsync -OutDir $dir -File $file -Commands $cmds

    $file = "Get-VMVideo.txt"
    [String []] $cmds = "Get-VMVideo -VM $vmObject",
                        "Get-VMVideo -VM $vmObject | Format-List -Property *"
    ExecCommandsAsync -OutDir $dir -File $file -Commands $cmds

    $file = "Get-VMHardDiskDrive.txt"
    [String []] $cmds = "Get-VMHardDiskDrive -VM $vmObject",
                        "Get-VMHardDiskDrive -VM $vmObject | Format-List -Property *"
    ExecCommandsAsync -OutDir $dir -File $file -Commands $cmds

    $file = "Get-VMComPort.txt"
    [String []] $cmds = "Get-VMComPort -VM $vmObject",
                        "Get-VMComPort -VM $vmObject | Format-List -Property *"
    ExecCommandsAsync -OutDir $dir -File $file -Commands $cmds

    $file = "Get-VMSecurity.txt"
    [String []] $cmds = "Get-VMSecurity -VM $vmObject",
                        "Get-VMSecurity -VM $vmObject | Format-List -Property *"
    ExecCommandsAsync -OutDir $dir -File $file -Commands $cmds
} # VMWorker()

function VMNetworkAdapterPerVM {
    [CmdletBinding()]
    Param(
        [parameter(Mandatory=$false)] [String] $VMSwitchId,
        [parameter(Mandatory=$true)]  [String] $OutDir
    )

    if (-not $SkipVm) {
        [Int] $index = 1
        foreach ($vm in TryCmd {Get-VM}) {
            $vmName = $vm.Name
            $vmId   = $vm.VMId
            $title  = "VM.$index.$vmName"
            $dir    = Join-Path $OutDir $(ConvertTo-Filename $title)

            $vmQuery = $false
            foreach ($vmNic in TryCmd {Get-VMNetworkAdapter -VM $vm} | where {$_.SwitchId -eq $VMSwitchId}) {
                $vmNicId = ($vmNic.Id -split "\\")[1] # Same as AdapterId, but works if VM is off
                if (-not $vmQuery)
                {
                    Write-Progress -Activity $Global:QueueActivity -Status "Processing $title"
                    New-Item -ItemType "Directory" -Path $dir | Out-Null
                    VMWorker -VMId $vmId -OutDir $dir
                    $vmQuery = $true
                }
                VMNetworkAdapterDetail -VMName $vmName -VMNicName $vmNic.Name -VMNicId $vmNicId -OutDir $dir
            }
            $index++
        }
    }
} # VMNetworkAdapterPerVM()

function VMSwitchWorker {
    [CmdletBinding()]
    Param(
        [parameter(Mandatory=$false)] [String] $VMSwitchId,
        [parameter(Mandatory=$true)] [String] $OutDir
    )

    $id  = $VMSwitchId
    $dir = $OutDir

    $vmSwitchObject = "`$(Get-VMSwitch -Id $id)"

    $file = "Get-VMSwitch.txt"
    [String []] $cmds = "$vmSwitchObject",
                        "$vmSwitchObject | Format-List -Property *"
    ExecCommandsAsync -OutDir $dir -File $file -Commands $cmds

    $file = "Get-VMSwitchExtension.txt"
    [String []] $cmds = "Get-VMSwitchExtension -VMSwitch $vmSwitchObject | Format-List -Property *"
    ExecCommandsAsync -OutDir $dir -File $file -Commands $cmds

    $file = "Get-VMSwitchExtensionSwitchData.txt"
    [String []] $cmds = "Get-VMSwitchExtensionSwitchData -VMSwitch $vmSwitchObject | Format-List -Property *"
    ExecCommandsAsync -OutDir $dir -File $file -Commands $cmds

    $file = "Get-VMSwitchExtensionSwitchFeature.txt"
    [String []] $cmds = "Get-VMSwitchExtensionSwitchFeature -VMSwitch $vmSwitchObject | Format-List -Property *"
    ExecCommandsAsync -OutDir $dir -File $file -Commands $cmds

    $file = "Get-VMSwitchTeam.txt"
    [String []] $cmds = "Get-VMSwitchTeam -VMSwitch $vmSwitchObject | Format-List -Property *"
    ExecCommandsAsync -OutDir $dir -File $file -Commands $cmds

    $file = "Get-VMNetworkAdapterTeamMapping.txt"
    [String []] $cmds = "Get-VMNetworkAdapterTeamMapping -ManagementOS -SwitchName $vmSwitchObject | Format-List -Property *"
    ExecCommandsAsync -OutDir $dir -File $file -Commands $cmds
} # VMSwitchWorker()

function VfpExtensionDetail {
    [CmdletBinding()]
    Param(
        [parameter(Mandatory=$false)] [String] $VMSwitchId,
        [parameter(Mandatory=$true)] [String] $OutDir
    )

    #FIXME: Find a non-vSwitch CMDLET mechanism to dump the VFP settings
    #       Necessary for HNS scenarios where vSwitch CMDLETs are not available
    $id = $VMSwitchId
    $vfpExtension = TryCmd {Get-VMSwitch -Id $id | Get-VMSwitchExtension} | where {$_.Name -like "Microsoft Azure VFP Switch Extension"}

    if ($vfpExtension.Enabled -ne "True") {
        return
    }

    $dir  = (Join-Path -Path $OutDir -ChildPath "VFP")
    New-Item -ItemType directory -Path $dir | Out-Null

    $file = "VfpCtrl.help.txt"
    [String []] $cmds = "vfpctrl.exe /h"
    ExecCommandsAsync -OutDir $dir -File $file -Commands $cmds

    $file = "Get-CimInstance.CIM_DataFile.vfpext.txt"
    $vfpExtPath = ((Join-Path $env:SystemRoot "System32\drivers\vfpext.sys") -replace "\\","\\")
    [String []] $cmds = "Get-CimInstance -ClassName ""CIM_DataFile"" -Filter ""Name='$vfpExtPath'"""
    ExecCommandsAsync -OutDir $dir -File $file -Commands $cmds

    $currSwitch = Get-CimInstance -Filter "Name='$id'" -ClassName "Msvm_VirtualEthernetSwitch" -Namespace "Root\Virtualization\v2"
    $ports = Get-CimAssociatedInstance -InputObject $currSwitch -ResultClassName "Msvm_EthernetSwitchPort"

    foreach ($portGuid in $ports.Name) {
        $file = "VfpCtrl.PortGuid.$portGuid.txt"
        [String []] $cmds = "vfpctrl.exe /list-vmswitch-port",
                            "vfpctrl.exe /list-space /port $portGuid",
                            "vfpctrl.exe /list-mapping /port $portGuid",
                            "vfpctrl.exe /list-rule /port $portGuid",
                            "vfpctrl.exe /port $portGuid /get-port-state"
        ExecCommandsAsync -OutDir $dir -File $file -Commands $cmds
    }
} # VfpExtensionDetail()

function VMSwitchDetail {
    [CmdletBinding()]
    Param(
        [parameter(Mandatory=$true)] [String] $OutDir
    )

    # Acquire switch properties/settings via CMD tools
    $dir  = (Join-Path -Path $OutDir -ChildPath "VMSwitch.Detail")
    New-Item -ItemType directory -Path $dir | Out-Null

    $file = "VmspRegistry.txt"
    [String []] $cmds = "Get-ChildItem HKLM:\SYSTEM\CurrentControlSet\Services\vmsmp -Recurse"
    ExecCommands -OutDir $dir -File $file -Commands $cmds

    $file = "NvspInfo.txt"
    [String []] $cmds = "nvspinfo -a -i -h -D -p -d -m -q "
    ExecCommandsAsync -OutDir $dir -File $file -Commands $cmds

    $file = "NvspInfo_bindings.txt"
    [String []] $cmds = "nvspinfo -a -i -h -D -p -d -m -q -b "
    ExecCommandsAsync -OutDir $dir -File $file -Commands $cmds

    $file = "NvspInfo_ExecMon.txt"
    [String []] $cmds = "nvspinfo -X --count --sort max ",
                        "nvspinfo -X --count IOCTL --sort max",
                        "nvspinfo -X --count OID --sort max",
                        "nvspinfo -X --count WORKITEM --sort max",
                        "nvspinfo -X --count RNDIS --sort max"
    ExecCommandsAsync -OutDir $dir -File $file -Commands $cmds

    $file = "NmScrub.txt"
    [String []] $cmds = "nmscrub -a -n -t "
    ExecCommandsAsync -OutDir $dir -File $file -Commands $cmds

    # Acquire per vSwitch instance info/mappings
    [Int] $index = 1
    foreach ($vmSwitch in TryCmd {Get-VMSwitch}) {
        $name  = $vmSwitch.Name
        $type  = $vmSwitch.SwitchType
        $id    = $vmSwitch.Id
        $title = "VMSwitch.$index.$type.$name"

        $dir  =  Join-Path $OutDir $(ConvertTo-Filename $title)
        New-Item -ItemType directory -Path $dir | Out-Null

        Write-Progress -Activity $Global:QueueActivity -Status "Processing $title"
        VfpExtensionDetail    -VMSwitchId $id -OutDir $dir
        VMSwitchWorker        -VMSwitchId $id -OutDir $dir
        ProtocolNicDetail     -VMSwitchId $id -OutDir $dir
        HostVNicDetail        -VMSwitchId $id -OutDir $dir
        VMNetworkAdapterPerVM -VMSwitchId $id -OutDir $dir

        $index++
    }
} # VMSwitchDetail()

function NetworkSummary {
    [CmdletBinding()]
    Param(
        [parameter(Mandatory=$true)] [String] $OutDir
    )

    $dir = $OutDir

    $file = "Get-NetOffloadGlobalSetting.txt"
    [String []] $cmds = "Get-NetOffloadGlobalSetting",
                        "Get-NetOffloadGlobalSetting | Format-List -Property *"
    ExecCommandsAsync -OutDir $dir -File $file -Commands $cmds

    $file = "Get-VMSwitch.txt"
    [String []] $cmds = "Get-VMSwitch | Sort-Object Name | Format-Table -AutoSize",
                        "Get-VMSwitch | Sort-Object Name | Format-Table -Property * -AutoSize"
    ExecCommandsAsync -OutDir $dir -File $file -Commands $cmds

    $file = "Get-VMNetworkAdapter.txt"
    [String []] $cmds = "Get-VmNetworkAdapter -All | Sort-Object IsManagementOS | Sort-Object SwitchName | Format-Table -AutoSize",
                        "Get-VmNetworkAdapter -All | Sort-Object IsManagementOS | Sort-Object SwitchName | Format-Table -Property * -AutoSize"
    ExecCommandsAsync -OutDir $dir -File $file -Commands $cmds

    $file = "Get-NetAdapter.txt"
    [String []] $cmds = "Get-NetAdapter -IncludeHidden | Sort-Object InterfaceDescription | Format-Table -AutoSize",
                        "Get-NetAdapter -IncludeHidden | Sort-Object InterfaceDescription | Format-Table -Property * -AutoSize"
    ExecCommandsAsync -OutDir $dir -File $file -Commands $cmds

    $file = "Get-NetAdapterStatistics.txt"
    [String []] $cmds = "Get-NetAdapterStatistics -IncludeHidden | Sort-Object InterfaceDescription | Format-Table -Autosize",
                        "Get-NetAdapterStatistics -IncludeHidden | Sort-Object InterfaceDescription | Format-Table -Property * -Autosize"
    ExecCommandsAsync -OutDir $dir -File $file -Commands $cmds

    $file = "Get-NetLbfoTeam.txt"
    [String []] $cmds = "Get-NetLbfoTeam | Sort-Object InterfaceDescription | Format-Table -Autosize",
                        "Get-NetLbfoTeam | Sort-Object InterfaceDescription | Format-Table -Property * -AutoSize"
    ExecCommandsAsync -OutDir $dir -File $file -Commands $cmds

    $file = "Get-NetIpAddress.txt"
    [String []] $cmds = "Get-NetIpAddress | Format-Table -Autosize",
                        "Get-NetIpAddress | Format-Table -Property * -AutoSize"
    ExecCommandsAsync -OutDir $dir -File $file -Commands $cmds

    $file = "_ipconfig.txt"
    [String []] $cmds = "ipconfig",
                        "ipconfig /allcompartments /all"
    ExecCommandsAsync -OutDir $dir -File $file -Commands $cmds

    $file = "_arp.txt"
    [String []] $cmds = "arp -a"
    ExecCommandsAsync -OutDir $dir -File $file -Commands $cmds

    $file = "_netstat.txt"
    [String []] $cmds = "netstat -nasert",
                        "netstat -an",
                        "netstat -xan | ? {`$_ -match ""445""}"
    ExecCommandsAsync -OutDir $dir -File $file -Commands $cmds

    $file = "_nmbind.txt"
    [String []] $cmds = "nmbind"
    ExecCommandsAsync -OutDir $dir -File $file -Commands $cmds
    $file = "_advfirewall.txt"
    [String []] $cmds = "netsh advfirewall show allprofiles"
    ExecCommandsAsync -OutDir $dir -File $file -Commands $cmds
} # NetworkSummary()

function PktmonDetail {
    [CmdletBinding()]
    Param(
        [parameter(Mandatory=$true)] [String] $OutDir
    )

    Write-Progress -Activity $Global:QueueActivity -Status "Processing $($MyInvocation.MyCommand.Name)"

    $dir = (Join-Path -Path $OutDir -ChildPath "Pktmon")
    New-Item -ItemType directory -Path $dir | Out-Null

    $file = "pktmon.status.txt"
    [String []] $cmds = "pktmon status",
                        "pktmon stop" # End any pre-existing session
    ExecCommands -OutDir $dir -File $file -Commands $cmds

    $file = "pktmon.filter.txt"
    [String []] $cmds = "pktmon filter list"
    ExecCommands -OutDir $dir -File $file -Commands $cmds

    $file = "pktmon.list.txt"
    [String []] $cmds = "pktmon list",
                        "pktmon list --all",
                        "pktmon list --all --include-hidden"
    ExecCommands -OutDir $dir -File $file -Commands $cmds

    # Reset state and collect a small snapshot of traffic counters.
    $null = pktmon unload

    $file = "pktmon.counters.txt"
    [String []] $cmds = "pktmon start --capture --counters-only --comp all",
                        "Start-Sleep 1",
                        "pktmon counters --include-hidden --zero --drop-reason"
    ExecCommands -OutDir $dir -File $file -Commands $cmds

    $null = pktmon unload
} # PktmonDetail()

function SMBDetail {
    [CmdletBinding()]
    Param(
        [parameter(Mandatory=$true)] [String] $OutDir
    )

    Write-Progress -Activity $Global:QueueActivity -Status "Processing $($MyInvocation.MyCommand.Name)"

    $dir = (Join-Path -Path $OutDir -ChildPath "SMB")
    New-Item -ItemType directory -Path $dir | Out-Null

    $file = "Get-SmbConnection.txt"
    [String []] $cmds = "Get-SmbConnection"
    ExecCommandsAsync -OutDir $dir -File $file -Commands $cmds

    $file = "Get-SmbMapping.txt"
    [String []] $cmds = "Get-SmbMapping"
    ExecCommandsAsync -OutDir $dir -File $file -Commands $cmds

    $file = "Get-SmbOpenFile.txt"
    [String []] $cmds = "Get-SmbOpenFile"
    ExecCommandsAsync -OutDir $dir -File $file -Commands $cmds

    $file = "Get-SmbSession.txt"
    [String []] $cmds = "Get-SmbSession"
    ExecCommandsAsync -OutDir $dir -File $file -Commands $cmds

    $file = "Get-SmbShare.txt"
    [String []] $cmds = "Get-SmbShare"
    ExecCommandsAsync -OutDir $dir -File $file -Commands $cmds

    $file = "Get-SmbClientNetworkInterface.txt"
    [String []] $cmds = "Get-SmbClientNetworkInterface | Sort-Object FriendlyName | Format-Table -AutoSize",
                        "Get-SmbClientNetworkInterface | Format-List  -Property *"
    ExecCommandsAsync -OutDir $dir -File $file -Commands $cmds

    $file = "Get-SmbServerNetworkInterface.txt"
    [String []] $cmds = "Get-SmbServerNetworkInterface | Sort-Object FriendlyName | Format-Table -AutoSize",
                        "Get-SmbServerNetworkInterface | Format-List  -Property *"
    ExecCommandsAsync -OutDir $dir -File $file -Commands $cmds

    $file = "Get-SmbClientConfiguration.txt"
    [String []] $cmds = "Get-SmbClientConfiguration"
    ExecCommandsAsync -OutDir $dir -File $file -Commands $cmds

    $file = "Get-SmbServerConfiguration.txt"
    [String []] $cmds = "Get-SmbServerConfiguration"
    ExecCommandsAsync -OutDir $dir -File $file -Commands $cmds

    $file = "Get-SmbMultichannelConnection.txt"
    [String []] $cmds = "Get-SmbMultichannelConnection | Sort-Object Name | Format-Table -AutoSize",
                        "Get-SmbMultichannelConnection -IncludeNotSelected | Format-List -Property *",
                        "Get-SmbMultichannelConnection -SmbInstance CSV -IncludeNotSelected | Format-List -Property *",
                        "Get-SmbMultichannelConnection -SmbInstance SBL -IncludeNotSelected | Format-List -Property *"
    ExecCommandsAsync -OutDir $dir -File $file -Commands $cmds

    $file = "Get-SmbMultichannelConstraint.txt"
    [String []] $cmds = "Get-SmbMultichannelConstraint"
    ExecCommandsAsync -OutDir $dir -File $file -Commands $cmds

    $file = "Get-SmbBandwidthLimit.txt"
    [String []] $cmds = "Get-SmbBandwidthLimit"
    ExecCommandsAsync -OutDir $dir -File $file -Commands $cmds

    $file = "Smb-WindowsEvents.txt"
    [String []] $cmds = "Get-WinEvent -ListLog ""*SMB*"" | Format-List -Property *",
                        "Get-WinEvent -FilterHashtable @{LogName=""Microsoft-Windows-SMB*""; ProviderName=""Microsoft-Windows-SMB*""} | where {`$_.Message -like ""*RDMA*""} | Format-List -Property *"

    ExecCommandsAsync -OutDir $dir -File $file -Commands $cmds
} # SMBDetail()

function NetSetupDetail {
    [CmdletBinding()]
    Param(
        [parameter(Mandatory=$true)] [String] $OutDir
    )

    $dir = (Join-Path -Path $OutDir -ChildPath "NetSetup")
    New-Item -ItemType directory -Path $dir | Out-Null

    $file = "NetSetup.txt"
    [String []] $paths = "$env:SystemRoot\System32\NetSetupMig.log",
                         "$env:SystemRoot\Panther\setupact.log",
                         "$env:SystemRoot\INF\setupapi.*",
                         "$env:SystemRoot\logs\NetSetup"
    ExecCopyItemsAsync -OutDir $dir -File $file -Paths $paths -Destination $dir
} # NetSetupDetail()

function HNSDetail {
    [CmdletBinding()]
    Param(
        [parameter(Mandatory=$true)] [String] $OutDir
    )

    Write-Progress -Activity $Global:QueueActivity -Status "Processing $($MyInvocation.MyCommand.Name)"

    try {
        $null = Get-Service "hns" -ErrorAction Stop
    } catch {
        Write-Host "$($MyInvocation.MyCommand.Name): hns service not found, skipping."
        return
    }

    $dir = (Join-Path -Path $OutDir -ChildPath "HNS")
    New-Item -ItemType Directory -Path $dir | Out-Null

    # Data collected before stop -> start must be collected synchronously

    $file = "HNSRegistry-1.txt"
    [String []] $cmds = "Get-ChildItem HKLM:\SYSTEM\CurrentControlSet\Services\hns -Recurse",
                        "Get-ChildItem HKLM:\SYSTEM\CurrentControlSet\Services\vmsmp -Recurse"
    ExecCommands -OutDir $dir -File $file -Commands $cmds

    $file = "Get-HNSNetwork-1.txt"
    [String []] $cmds = "Get-HNSNetwork | ConvertTo-Json -Depth 10"
    ExecCommands -OutDir $dir -File $file -Commands $cmds

    $file = "Get-HNSEndpoint-1.txt"
    [String []] $cmds = "Get-HNSEndpoint | ConvertTo-Json -Depth 10"
    ExecCommands -OutDir $dir -File $file -Commands $cmds

    # HNS service stop -> start occurs after capturing the current HNS state info.
    $hnsRunning = (Get-Service hns).Status -eq "Running"
    try {
        if ($hnsRunning) {
            # Force stop to avoid command line prompt
            net stop hns /y *> $null
        }

        $file = "HNSData.txt"
        [String []] $cmds = "Copy-Item -Path ""$env:ProgramData\Microsoft\Windows\HNS\HNS.data"" -Destination $dir -Verbose 4>&1"
        ExecCommands -OutDir $dir -File $file -Commands $cmds
    } finally {
        if ($hnsRunning) {
            net start hns *> $null
        }
    }

    # Acquire all settings again after stop -> start services
    # From now on we can collect data asynchronously.
    $file = "HNSRegistry-2.txt"
    [String []] $cmds = "Get-ChildItem HKLM:\SYSTEM\CurrentControlSet\Services\hns -Recurse",
                        "Get-ChildItem HKLM:\SYSTEM\CurrentControlSet\Services\vmsmp -Recurse"
    ExecCommandsAsync -OutDir $dir -File $file -Commands $cmds

    $file = "Get-HNSNetwork-2.txt"
    [String []] $cmds = "Get-HNSNetwork | ConvertTo-Json -Depth 10"
    ExecCommandsAsync -OutDir $dir -File $file -Commands $cmds

    $file = "Get-HNSEndpoint-2.txt"
    [String []] $cmds = "Get-HNSEndpoint | ConvertTo-Json -Depth 10"
    ExecCommandsAsync -OutDir $dir -File $file -Commands $cmds

    $file = "HNSDiag_all.txt"
    [String []] $cmds = "HNSDiag list all"
    ExecCommandsAsync -OutDir $dir -File $file -Commands $cmds

    $file = "HNSDiag_all_d.txt"
    [String []] $cmds = "HNSDiag list all -d"
    ExecCommandsAsync -OutDir $dir -File $file -Commands $cmds

    $file = "HNSDiag_all_df.txt"
    [String []] $cmds = "HNSDiag list all -df"
    ExecCommandsAsync -OutDir $dir -File $file -Commands $cmds

    $file = "HNSDiag_all_dfl.txt"
    [String []] $cmds = "HNSDiag list all -dfl"
    ExecCommandsAsync -OutDir $dir -File $file -Commands $cmds

    #netsh trace start scenario=Virtualization provider=Microsoft-Windows-tcpip provider=Microsoft-Windows-winnat capture=yes captureMultilayer=yes capturetype=both report=disabled tracefile=$dir\server.etl overwrite=yes
    #Start-Sleep 120
    #netsh trace stop
} # HNSDetail()

function QosDetail {
    [CmdletBinding()]
    Param(
        [parameter(Mandatory=$true)] [String] $OutDir
    )

    Write-Progress -Activity $Global:QueueActivity -Status "Processing $($MyInvocation.MyCommand.Name)"

    $dir = (Join-Path -Path $OutDir -ChildPath "NetQoS")
    New-Item -ItemType directory -Path $dir | Out-Null

    $file = "Get-NetAdapterQos.txt"
    [String []] $cmds = "Get-NetAdapterQos",
                        "Get-NetAdapterQos -IncludeHidden",
                        "Get-NetAdapterQos -IncludeHidden | Format-List -Property *"
    ExecCommands -OutDir $dir -File $file -Commands $cmds # Get-NetAdapterQos has severe concurrency issues

    $file = "Get-NetQosDcbxSetting.txt"
    [String []] $cmds = "Get-NetQosDcbxSetting",
                        "Get-NetQosDcbxSetting | Format-List  -Property *",
                        "Get-NetQosDcbxSetting | Format-Table -Property *  -AutoSize"
    ExecCommandsAsync -OutDir $dir -File $file -Commands $cmds

    $file = "Get-NetQosFlowControl.txt"
    [String []] $cmds = "Get-NetQosFlowControl",
                        "Get-NetQosFlowControl | Format-List  -Property *",
                        "Get-NetQosFlowControl | Format-Table -Property *  -AutoSize"
    ExecCommandsAsync -OutDir $dir -File $file -Commands $cmds

    $file = "Get-NetQosPolicy.txt"
    [String []] $cmds = "Get-NetQosPolicy",
                        "Get-NetQosPolicy | Format-List  -Property *",
                        "Get-NetQosPolicy | Format-Table -Property *  -AutoSize"
    ExecCommandsAsync -OutDir $dir -File $file -Commands $cmds

    $file = "Get-NetQosTrafficClass.txt"
    [String []] $cmds = "Get-NetQosTrafficClass",
                        "Get-NetQosTrafficClass | Format-List  -Property *",
                        "Get-NetQosTrafficClass | Format-Table -Property *  -AutoSize"
    ExecCommandsAsync -OutDir $dir -File $file -Commands $cmds
} # QosDetail()

function ATCDetail {
    [CmdletBinding()]
    param (
        [parameter(Mandatory=$true)] [String] $OutDir
    )

    Write-Progress -Activity $Global:QueueActivity -Status "Processing $($MyInvocation.MyCommand.Name)"

    $intent = Get-Command "Get-NetIntent" -ErrorAction "SilentlyContinue"
    $cluster = Get-Command "Get-Cluster" -ErrorAction "SilentlyContinue"
    if (-not ($intent -or $cluster)) {
        return
    }

    $dir = (Join-Path -Path $OutDir -ChildPath "ATC")
    New-Item -ItemType directory -Path $dir | Out-Null

    # Local Intents
    if ($intent) {
        $file = "Get-NetIntent_Standalone.txt"
        [String []] $cmds = "Get-NetIntent"
        ExecCommands -OutDir $dir -File $file -Commands $cmds

        $file = "Get-NetIntentStatus_Standalone.txt"
        [String []] $cmds = "Get-NetIntentStatus"
        ExecCommands -OutDir $dir -File $file -Commands $cmds

        $file = "Get-NetIntentAllGoalStates_Standalone.txt"
        [String []] $cmds = "Get-NetIntentAllGoalStates | ConvertTo-Json -Depth 10"
        ExecCommands -OutDir $dir -File $file -Commands $cmds
    }

    # Cluster Intents
    if ($cluster) {
        $file = "Get-NetIntent_Cluster.txt"
        [String []] $cmds = "Get-NetIntent -ClusterName $($cluster.Name)"
        ExecCommands -OutDir $dir -File $file -Commands $cmds

        $file = "Get-NetIntentStatus_Cluster.txt"
        [String []] $cmds = "Get-NetIntentStatus -ClusterName $($cluster.Name)"
        ExecCommands -OutDir $dir -File $file -Commands $cmds

        $file = "Get-NetIntentAllGoalStates_Cluster.txt"
        [String []] $cmds = "Get-NetIntentAllGoalStates -ClusterName $($cluster.Name) | ConvertTo-Json -Depth 10"
        ExecCommands -OutDir $dir -File $file -Commands $cmds
    }
} # ATCDetail ()

function ServicesDrivers {
    [CmdletBinding()]
    Param(
        [parameter(Mandatory=$true)] [String] $OutDir
    )

    $dir = (Join-Path -Path $OutDir -ChildPath "ServicesDrivers")
    New-Item -ItemType Directory -Path $dir | Out-Null

    $file = "sc.txt"
    [String []] $cmds = "sc.exe queryex vmsp",
                        "sc.exe queryex vmsproxy",
                        "sc.exe queryex PktMon"
    ExecCommandsAsync -OutDir $dir -File $file -Commands $cmds

    $file = "Get-Service.txt"
    [String []] $cmds = "Get-Service ""*"" | Sort-Object Name | Format-Table -AutoSize",
                        "Get-Service ""*"" | Sort-Object Name | Format-Table -Property * -AutoSize"
    ExecCommands -OutDir $dir -File $file -Commands $cmds # Get-Service has concurrency issues

    $file = "Get-WindowsDriver.txt"
    [String []] $cmds = "Get-WindowsDriver -Online -All"
    ExecCommandsAsync -OutDir $dir -File $file -Commands $cmds

    $file = "Get-WindowsEdition.txt"
    [String []] $cmds = "Get-WindowsEdition -Online"
    ExecCommandsAsync -OutDir $dir -File $file -Commands $cmds

    $file = "Get-HotFix.txt"
    [String []] $cmds = "Get-Hotfix | Sort-Object InstalledOn | Format-Table -AutoSize",
                        "Get-Hotfix | Sort-Object InstalledOn | Format-Table -Property * -AutoSize"
    ExecCommandsAsync -OutDir $dir -File $file -Commands $cmds

    $file = "Get-PnpDevice.txt"
    [String []] $cmds = "Get-PnpDevice | Sort-Object Class, FriendlyName, InstanceId | Format-Table -AutoSize",
                        "Get-PnpDevice | Sort-Object Class, FriendlyName, InstanceId | Format-List -Property *"
    ExecCommandsAsync -OutDir $dir -File $file -Commands $cmds

    $file = "Get-CimInstance.Win32_PnPSignedDriver.txt"
    [String []] $cmds = "Get-CimInstance Win32_PnPSignedDriver | Select-Object DeviceName, DeviceId, DriverVersion | Format-Table -AutoSize",
                        "Get-CimInstance Win32_PnPSignedDriver | Format-List -Property *"
    ExecCommandsAsync -OutDir $dir -File $file -Commands $cmds

    $file = "dism.txt"
    [String []] $cmds = "dism /online /get-features"
    ExecCommandsAsync -OutDir $dir -File $file -Commands $cmds

} # ServicesDrivers()

function VMHostDetail {
    [CmdletBinding()]
    Param(
        [parameter(Mandatory=$true)] [String] $OutDir
    )

    $dir = (Join-Path -Path $OutDir -ChildPath "VMHost")
    New-Item -ItemType Directory -Path $dir | Out-Null

    $file = "Get-VMHostSupportedVersion.txt"
    [String []] $cmds = "Get-VMHostSupportedVersion | Format-Table -AutoSize",
                        "Get-VMHostSupportedVersion | Format-List -Property *"
    ExecCommandsAsync -OutDir $dir -File $file -Commands $cmds

    $file = "Get-VMHostNumaNode.txt"
    [String []] $cmds = "Get-VMHostNumaNode"
    ExecCommandsAsync -OutDir $dir -File $file -Commands $cmds

    $file = "Get-VMHostNumaNodeStatus.txt"
    [String []] $cmds = "Get-VMHostNumaNodeStatus"
    ExecCommandsAsync -OutDir $dir -File $file -Commands $cmds

    $file = "Get-VMSystemSwitchExtension.txt"
    [String []] $cmds = "Get-VMSystemSwitchExtension | Format-List -Property *"
    ExecCommandsAsync -OutDir $dir -File $file -Commands $cmds

    $file = "Get-VMSystemSwitchExtensionSwitchFeature.txt"
    [String []] $cmds = "Get-VMSystemSwitchExtensionSwitchFeature | Format-List -Property *"
    ExecCommandsAsync -OutDir $dir -File $file -Commands $cmds

    $file = "Get-VMSystemSwitchExtensionPortFeature.txt"
    [String []] $cmds = "Get-VMSystemSwitchExtensionPortFeature | Format-List -Property *"
    ExecCommandsAsync -OutDir $dir -File $file -Commands $cmds
} # VMHostDetail()

function NetshDetail {
    [CmdletBinding()]
    Param(
        [parameter(Mandatory=$true)] [String] $OutDir,
        [parameter(Mandatory=$true)] [Bool] $SkipNetshTrace
    )

    $dir = (Join-Path -Path $OutDir -ChildPath "Netsh")
    New-Item -ItemType directory -Path $dir | Out-Null

    $wpp_vswitch  = "{1F387CBC-6818-4530-9DB6-5F1058CD7E86}"
    $wpp_ndis     = "{DD7A21E6-A651-46D4-B7C2-66543067B869}"
    $etw_tcpip    = "{2F07E2EE-15DB-40F1-90EF-9D7BA282188A}"
    $etw_quic     = "{ff15e657-4f26-570e-88ab-0796b258d11c}"

    # The sequence below triggers the ETW providers to dump their
    # internal traces when the session starts. Thus allowing for
    # capturing a snapshot of their logs/traces.
    #
    # NOTE: This does not cover IFR (in-memory) traces.  More work needed to address said traces.
    $file = "NetRundown.txt"
    [String []] $cmds = "New-NetEventSession    NetRundown -CaptureMode SaveToFile -LocalFilePath $dir\NetRundown.etl",
                        "Add-NetEventProvider   ""$wpp_vswitch"" -SessionName NetRundown -Level 1 -MatchAnyKeyword 0x10000",
                        "Add-NetEventProvider   ""$wpp_ndis"" -SessionName NetRundown -Level 1 -MatchAnyKeyword 0x2",
                        "Add-NetEventProvider   ""$etw_tcpip"" -SessionName NetRundown -Level 4",
                        "Add-NetEventProvider   ""$etw_quic"" -SessionName NetRundown -Level 5 -MatchAnyKeyword 0x80000000",
                        "Start-NetEventSession  NetRundown",
                        "Stop-NetEventSession   NetRundown",
                        "Remove-NetEventSession NetRundown"
    ExecCommands -OutDir $dir -File $file -Commands $cmds

    # The ETL file can be converted to text using the following command:
    #    netsh trace convert NetRundown.etl tmfpath=<build>\amd64fre\symbols.pri\TraceFormat

    $file = "NetshDump.txt"
    [String []] $cmds = "netsh dump"
    ExecCommands -OutDir $dir -File $file -Commands $cmds

    $file = "NetshStatistics.txt"
    [String []] $cmds = "netsh interface ipv4 show icmpstats",
                        "netsh interface ipv4 show ipstats",
                        "netsh interface ipv4 show tcpstats",
                        "netsh interface ipv4 show udpstats",
                        "netsh interface ipv6 show ipstats",
                        "netsh interface ipv6 show tcpstats",
                        "netsh interface ipv6 show udpstats"
    ExecCommands -OutDir $dir -File $file -Commands $cmds

    $file = "NetshTrace.txt"
    [String []] $cmds = "netsh -?",
                        "netsh trace show scenarios",
                        "netsh trace show providers"
    if (-not $SkipNetshTrace) {
        $cmds +=        "netsh trace diagnose scenario=NetworkSnapshot mode=Telemetry saveSessionTrace=yes report=yes ReportFile=$dir\Snapshot.cab"
    }
    ExecCommands -OutDir $dir -File $file -Commands $cmds
} # NetshDetail()

function OneX {
    [CmdletBinding()]
    Param(
        [parameter(Mandatory=$true)] [String] $OutDir
    )

    Write-Progress -Activity $Global:QueueActivity -Status "Processing $($MyInvocation.MyCommand.Name)"

    $dir = (Join-Path -Path $OutDir -ChildPath "802.1X")
    New-Item -ItemType directory -Path $dir | Out-Null

    $file = "OneX.txt"
    [String []] $cmds = "netsh lan show interface",
                        "netsh lan show profile"
    ExecCommandsAsync -OutDir $dir -File $file -Commands $cmds
} # OneX

function CounterDetail {
    [CmdletBinding()]
    Param(
        [parameter(Mandatory=$true)] [String] $OutDir,
        [parameter(Mandatory=$true)] [String] $SkipCounters
    )

    $dir = (Join-Path -Path $OutDir -ChildPath "Counters")
    New-Item -ItemType directory -Path $dir | Out-Null

    $file = "CounterSetName.txt"
    [String []] $cmds = "typeperf -q | foreach {(`$_ -split ""\\"")[1]} | Sort-Object -Unique"
    ExecCommands -OutDir $dir -File $file -Commands $cmds

    $file = "CounterSetName.Paths.txt"
    [String []] $cmds = "typeperf -q"
    ExecCommands -OutDir $dir -File $file -Commands $cmds

    $file = "CounterSetName.PathsWithInstances.txt"
    [String []] $cmds = "typeperf -qx"
    ExecCommands -OutDir $dir -File $file -Commands $cmds

    # Get paths for counters of interest
    $file = "CounterDetail.InstancesToQuery.txt"
    $in = Join-Path $dir $file

    $pathFilters = @("\Hyper-V*", "\ICMP*", "*Intel*", "*Cavium*", "\IP*", "*Mellanox*", "\Network*", "\Physical Network*", "\RDMA*", "\SMB*", "\TCP*", "\UDP*","\VFP*", "\WFP*", "*WinNAT*")
    $instancesToQuery = typeperf -qx | where {
        $instance = $_
        $pathFilters | foreach {
            if ($instance -like $_) {
                return $true
            }
        }
        return $false
    }
    $instancesToQuery | Out-File -FilePath $in -Encoding "default" -Width $columns

    if (-not $SkipCounters) {
        $file = "CounterDetail.csv"
        $out  = Join-Path $dir $file
        [String []] $cmds = "typeperf -cf $in -sc 10 -si 5 -f CSV -o $out > `$null"
        ExecCommands -OutDir $dir -File $file -Commands $cmds
    }
} # CounterDetail()

function SystemLogs {
    [CmdletBinding()]
    Param(
        [parameter(Mandatory=$true)] [String] $OutDir
    )

    if (-not $SkipLogs) {
        $dir = $OutDir

        $file = "WinEVT.txt"
        [String []] $paths = "$env:SystemRoot\System32\winevt"
        ExecCopyItemsAsync -OutDir $dir -File $file -Paths $paths -Destination $dir

        $file = "WER.txt"
        [String []] $paths = "$env:ProgramData\Microsoft\Windows\WER"
        ExecCopyItemsAsync -OutDir $dir -File $file -Paths $paths -Destination $dir
    } else {
        $dir = "$OutDir\winevt\Logs"

        $file = "ATCEVT.txt"
        [String []] $paths = "$env:SystemRoot\System32\winevt\logs\Microsoft-Windows-Networking-NetworkAtc%4Operational.evtx",
                             "$env:SystemRoot\System32\winevt\logs\Microsoft-Windows-Networking-NetworkAtc%4Admin.evtx"
        ExecCopyItemsAsync -OutDir $dir -File $file -Paths $paths -Destination $dir
    }
} # SystemLogs()

function Environment {
    [CmdletBinding()]
    Param(
        [parameter(Mandatory=$true)] [String] $OutDir
    )

    $dir = $OutDir

    $file = "Get-ComputerInfo.txt"
    [String []] $cmds = "Get-ComputerInfo"
    ExecCommandsAsync -OutDir $dir -File $file -Commands $cmds

    $file = "Verifier.txt"
    [String []] $cmds = "verifier /querysettings"
    ExecCommandsAsync -OutDir $dir -File $file -Commands $cmds

    $file = "Powercfg.txt"
    [String []] $cmds = "powercfg /List"
    ExecCommandsAsync -OutDir $dir -File $file -Commands $cmds

    $file = "Environment.txt"
    [String []] $cmds = "Get-Variable -Name ""PSVersionTable"" -ValueOnly",
                        "date",
                        "Get-CimInstance ""Win32_OperatingSystem"" | select -ExpandProperty ""LastBootUpTime""",
                        "Get-CimInstance ""Win32_Processor"" | Format-List -Property *",
                        "systeminfo"
    ExecCommandsAsync -OutDir $dir -File $file -Commands $cmds
} # Environment()

function LocalhostDetail {
    [CmdletBinding()]
    Param(
        [parameter(Mandatory=$true)] [String] $OutDir
    )

    $dir = (Join-Path -Path $OutDir -ChildPath "_Localhost") # sort to top
    New-Item -ItemType directory -Path $dir | Out-Null

    SystemLogs        -OutDir $dir
    ServicesDrivers   -OutDir $dir
    VMHostDetail      -OutDir $dir
} # LocalhostDetail()

function CustomModule {
    [CmdletBinding()]
    Param(
        [parameter(Mandatory=$false)] [String[]] $Commands, # Passed in as [ScriptBlock[]]
        [parameter(Mandatory=$true)] [String] $OutDir
    )

    if ($Commands.Count -eq 0) {
        return
    }

    $CustomModule  = (Join-Path $OutDir "CustomModule")
    New-Item -ItemType Directory -Path $CustomModule | Out-Null

    $file = "ExtraCommands.txt"
    ExecCommands -OutDir $CustomModule -File $file -Commands $Commands
} # CustomModule()

function Sanity {
    [CmdletBinding()]
    Param(
        [parameter(Mandatory=$true)] [String] $OutDir,
        [parameter(Mandatory=$true)] [Hashtable] $Params
    )

    $dir = $OutDir

    $file = "Get-ChildItem.txt"
    [String []] $cmds = "Get-ChildItem -Path $OutDir -Exclude Get-NetView.log -File -Recurse | Get-FileHash -Algorithm SHA1 | Format-Table -AutoSize"
    ExecCommands -OutDir $dir -File $file -Commands $cmds

    $file = "Metadata.txt"
    $out = Join-Path $dir $file
    $paramString = if ($Params.Count -eq 0) {"None`n`n"} else {"`n$($Params | Out-String)"}
    Write-Output "Script Version: $($Global:Version)" | Out-File -Encoding "default" -Append $out
    Write-Output "Module Version: $($MyInvocation.MyCommand.Module.Version)" | Out-File -Encoding "default" -Append $out
    Write-Output "Bound Parameters: $paramString" | Out-File -Encoding "default" -Append $out

    [String []] $cmds = "Get-FileHash -Path ""$PSCommandPath"" -Algorithm SHA1 | Format-List -Property *"
    ExecCommands -OutDir $dir -File $file -Commands $cmds
} # Sanity()

function LogPostProcess {
    [CmdletBinding()]
    Param(
        [parameter(Mandatory=$true)] [String] $OutDir
    )

    $dir = $OutDir
    $file = "Command-Time.log"
    $out = Join-Path $dir $file

    $cmdData = Get-Content "$dir\Get-NetView.log" | where {$_ -like "(* ms)*"}
    $table = $cmdData | foreach {
        $time, $cmd = ($_ -replace "^\(\s*","") -split " ms\) "
        [PSCustomObject] @{
            "Time (ms)" = $time -as [Int]
            "Command" = $cmd
        }
    }
    $table = $table | sort -Property "Time (ms)" -Descending

    $stats = $table."Time (ms)" | measure -Average -Sum
    $roundedAvg = [Math]::Round($stats.Average, 2)
    $lazyMedian = $table."Time (ms)"[$table.Count / 2]
    $variance = ($table."Time (ms)" | foreach {[Math]::pow($_ - $stats.Average, 2)} | measure -Average).Average
    $stdDev = [Math]::Round([Math]::Sqrt($variance), 2)
    $timeSec = [Math]::Round($stats.Sum / 1000, 2)

    Write-Output "Average = $roundedAvg ms, Median = $lazyMedian ms, StdDev = $stdDev ms, Sum = $timeSec s, Count = $($stats.Count)" | Out-File -Encoding "default" -Append $out
    Write-Output $table | Out-File -Encoding "default" -Width $columns -Append $out
} # LogPostProcess()

#
# Setup & Validation Functions
#

function CheckAdminPrivileges {
    [CmdletBinding()]
    Param(
        [parameter(Mandatory=$true)] [Bool] $SkipAdminCheck
    )

    if (-not $SkipAdminCheck) {
        # Yep, this is the easiest way to do this.
        $isAdmin = ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole] "Administrator")
        if (-not $isAdmin) {
            throw "Get-NetView : You do not have the required permission to complete this task. Please run this command in an Administrator PowerShell window or specify the -SkipAdminCheck option."
        }
    }
} # CheckAdminPrivileges()

function NormalizeWorkDir {
    [CmdletBinding()]
    Param(
        [parameter(Mandatory=$false)] [String] $OutputDirectory
    )

    # Output dir priority - $OutputDirectory, Desktop, Temp
    $baseDir = if (-not [String]::IsNullOrWhiteSpace($OutputDirectory)) {
                   if (Test-Path $OutputDirectory) {
                       (Resolve-Path $OutputDirectory).Path # full path
                   } else {
                       throw "Get-NetView : The directory ""$OutputDirectory"" does not exist."
                   }
               } elseif (($desktop = [Environment]::GetFolderPath("Desktop"))) {
                   $desktop
               } else {
                   $env:TEMP
               }
    $workDirName = "msdbg.$env:COMPUTERNAME"

    return (Join-Path $baseDir $workDirName).TrimEnd("\")
} # NormalizeWorkDir()

function EnvDestroy {
    [CmdletBinding()]
    Param(
        [parameter(Mandatory=$true)] [String] $OutDir
    )

    If (Test-Path $OutDir) {
        Remove-Item $OutDir -Recurse # Careful - Deletes $OurDir and all its contents
    }
} # EnvDestroy()

function EnvCreate {
    [CmdletBinding()]
    Param(
        [parameter(Mandatory=$true)] [String] $OutDir
    )

    # Attempt to create working directory, stopping on failure.
    New-Item -ItemType directory -Path $OutDir -ErrorAction Stop | Out-Null
} # EnvCreate()

function Initialize {
    [CmdletBinding()]
    Param(
        [parameter(Mandatory=$true)] [Int] $BackgroundThreads,
        [parameter(Mandatory=$true)] [Int] $Timeout,
        [parameter(Mandatory=$true)] [Double] $ExecutionRate,
        [parameter(Mandatory=$true)] [String] $OutDir
    )

    $Global:ExecParams = @{
        StartTime = Get-Date
        Timeout = $Timeout
        DelayFactor = (1 / $ExecutionRate) - 1
    }

    # Remove color codes from output.
    if ($PSVersionTable.PSVersion -ge "7.2") {
        $PSStyle.OutputRendering = [System.Management.Automation.OutputRendering]::Host
    }

    # Setup output folder
    EnvDestroy $OutDir
    EnvCreate $OutDir

    Start-Transcript -Path "$OutDir\Get-NetView.log"

    if ($ExecutionRate -lt 1) {
        Write-Host "Forcing BackgroundThreads=0 because ExecutionRate is less than 1."
        $BackgroundThreads = 0
    }

    Open-GlobalRunspacePool -BackgroundThreads $BackgroundThreads
} # Initialize()

function CreateZip {
    [CmdletBinding()]
    Param(
        [parameter(Mandatory=$true)] [String] $Src,
        [parameter(Mandatory=$true)] [String] $Out
    )

    if (Test-path $Out) {
        Remove-item $Out
    }

    Add-Type -assembly "system.io.compression.filesystem"
    [io.compression.zipfile]::CreateFromDirectory($Src, $Out)
} # CreateZip()

function Completion {
    [CmdletBinding()]
    Param(
        [parameter(Mandatory=$true)] [String] $Src
    )

    $logDir  = (Join-Path -Path $Src -ChildPath "_Logs")
    New-Item -ItemType directory -Path $logDir | Out-Null

    # Override timeout for post-processing.
    $Global:ExecParams.Timeout = [Int]::MaxValue

    Close-GlobalRunspacePool

    Write-Progress -Activity $Global:FinishActivity -Status "Processing output..."
    Sanity -OutDir $logDir -Params $PSBoundParameters

    # Collect statistics
    $timestamp = $Global:ExecParams.StartTime | Get-Date -f yyyy.MM.dd_hh.mm.ss

    $dirs = (Get-ChildItem $Src -Recurse | Measure-Object -Property length -Sum) # out folder size
    $hash = (Get-FileHash -Path $MyInvocation.PSCommandPath -Algorithm "SHA1").Hash # script hash

    # Display version and file save location
    Write-Host ""
    Write-Host "Diagnostics Data:"
    Write-Host "-----------------"
    Write-Host "Get-NetView"
    Write-Host "Version: $($Global:Version)"
    Write-Host "SHA1:  $(if ($hash) {$hash} else {"N/A"})"
    Write-Host ""
    Write-Host $Src
    Write-Host "Size:    $("{0:N2} MB" -f ($dirs.sum / 1MB))"
    Write-Host "Dirs:    $((Get-ChildItem $Src -Directory -Recurse | Measure-Object).Count)"
    Write-Host "Files:   $((Get-ChildItem $Src -File -Recurse | Measure-Object).Count)"
    Write-Host ""
    Write-Host "Execution Time:"
    Write-Host "---------------"
    $delta = (Get-Date) - $Global:ExecParams.StartTime
    Write-Host "$($delta.Minutes) Min $($delta.Seconds) Sec"
    Write-Host ""

    try {
        Stop-Transcript | Out-Null
        Move-Item -Path "$Src\Get-NetView.log" -Destination "$logDir\Get-NetView.log"
        Write-Host "Transcript stopped, output file is $logDir\Get-NetView.log"
        LogPostProcess -OutDir $logDir
    } catch {
        Write-Output "Stop-Transcript failed" | Out-File -Encoding "default" -Append "$logDir\Get-NetView.log"
    }

    Write-Progress -Activity $Global:FinishActivity -Status "Creating zip..."
    $outzip = "$Src-$timestamp.zip"
    CreateZip -Src $Src -Out $outzip
    Write-Host $outzip
    Write-Host "Size:    $("{0:N2} MB" -f ((Get-Item $outzip).Length / 1MB))"

    Write-Progress -Activity $Global:FinishActivity -Completed
} # Completion()

<#
.SYNOPSIS
    Collects data on system and network configuration for diagnosing Microsoft Networking.

.DESCRIPTION
    Collects comprehensive configuration data to aid in troubleshooting Microsoft Network issues.
    Data is collected from the following sources:
        - Get-NetView metadata (path, args, etc.)
        - Environment (OS, hardware, domain, hostname, etc.)
        - Physical, virtual, Container, NICs
        - Network Configuration, IP Addresses, MAC Addresses, Neighbors, Routes
        - Physical Switch configuration, QOS polices
        - Virtual Machine configuration
        - Virtual Switches, Bridges, NATs
        - Device Drivers
        - Performance Counters
        - Logs, Traces, etc.
        - System and Application Events

    The data is collected in a folder on the Desktop (by default), which is zipped on completion.
    Use Feedback hub to submit a new feedback.  Select one of these Categories:
        Network and Internet -> Virtual Networking
        Network and Internet -> Connecting to an Ethernet Network.
    Attach the Zip file to the feedback and submit.

    Do not share the zip file over email or other file sharing tools.  Only submit the file through the feedback hub.

    The output is most easily viewed with Visual Studio Code or similar editor with a navigation panel.

.PARAMETER OutputDirectory
    Optional path to the directory where the output should be saved. Can be either a relative or an absolute path.
    If unspecified, the current user's Desktop will be used by default.

.PARAMETER ExtraCommands
    Optional list of additional commands, given as ScriptBlocks. Their output is saved to the CustomModule directory,
    which can be accessed by using "$CustomModule" as a placeholder. For example, {Copy-Item .\MyFile.txt $CustomModule}
    copies "MyFile.txt" to "CustomModule\MyFile.txt".

.PARAMETER BackgroundThreads
    Maximum number of background tasks, from 0 - 16. Defaults to 5.

.PARAMETER Timeout
    Amount of time, in minutes, to wait for all commands to complete. Note that total runtime may be greater due to
    post-processing. Defaults to 120 minutes.

.PARAMETER ExecutionRate
    Relative rate at which commands are executed, with 1 being normal speed. Reduce to slow down execution and spread
    CPU usage over time. Useful on live or production systems to avoid disruption.

    NOTE: This will force BackgroundThreads = 0.

.PARAMETER SkipAdminCheck
    If present, skip the check for admin privileges before execution. Note that without admin privileges, the scope and
    usefulness of the collected data is limited.

.PARAMETER SkipLogs
    If present, skip the EVT and WER logs gather phases.

.PARAMETER SkipNetshTrace
    If present, skip the Netsh Trace data gather phase.

.PARAMETER SkipCounters
    If present, skip the Windows Performance Counters collection phase.

.PARAMETER SkipVm
    If present, skip the Virtual Machine (VM) data gather phases.

.EXAMPLE
    Get-NetView -OutputDirectory ".\"
    Runs Get-NetView and outputs to the current working directory.

.LINK
    https://github.com/microsoft/Get-NetView
#>
function Get-NetView {
    [CmdletBinding()]
    Param(
        [parameter(Mandatory=$false)]
        [ValidateScript({Test-Path $_ -PathType Container})]
        [String] $OutputDirectory = "",

        [parameter(Mandatory=$false)]
        [ScriptBlock[]] $ExtraCommands = @(),

        [Alias("MaxThreads")]
        [parameter(Mandatory=$false, ParameterSetName="BackgroundThreads")]
        [ValidateRange(0, 16)]
        [Int] $BackgroundThreads = 5,

        [parameter(Mandatory=$false)]
        [ValidateRange(0, [Int]::MaxValue)]
        [Int] $Timeout = 120,

        [parameter(Mandatory=$false)]
        [ValidateRange(0.0001, 1)]
        [Double] $ExecutionRate = 1,

        [parameter(Mandatory=$false)]  [Switch] $SkipAdminCheck = $false,
        [parameter(Mandatory=$false)]  [Switch] $SkipLogs       = $false,
        [parameter(Mandatory=$false)]  [Switch] $SkipNetshTrace = $false,
        [parameter(Mandatory=$false)]  [Switch] $SkipCounters   = $false,
        [parameter(Mandatory=$false)]  [Switch] $SkipVm         = $false
    )

    # Input Validation
    CheckAdminPrivileges $SkipAdminCheck
    $workDir = NormalizeWorkDir -OutputDirectory $OutputDirectory

    Initialize -BackgroundThreads $BackgroundThreads -Timeout $Timeout -ExecutionRate $ExecutionRate -OutDir $workDir

    # Import exec commands into script context
    . $ExecFunctions -ExecParams $Global:ExecParams
    Remove-Item alias:Write-CmdLog -ErrorAction "SilentlyContinue"

    # Start Run
    try {
        CustomModule -OutDir $workDir -Commands $ExtraCommands

        Write-Progress -Activity $Global:QueueActivity

        Start-Thread ${function:NetshDetail}   -Params @{OutDir=$workDir; SkipNetshTrace=$SkipNetshTrace}
        Start-Thread ${function:CounterDetail} -Params @{OutDir=$workDir; SkipCounters=$SkipCounters}

        Environment       -OutDir $workDir
        LocalhostDetail   -OutDir $workDir
        NetworkSummary    -OutDir $workDir
        NetSetupDetail    -OutDir $workDir
        NicDetail         -OutDir $workDir
        OneX              -OutDir $workDir

        QosDetail         -OutDir $workDir
        SMBDetail         -OutDir $workDir
        NetIp             -OutDir $workDir
        NetNatDetail      -OutDir $workDir
        HNSDetail         -OutDir $workDir
        ATCDetail         -OutDir $workDir
        PktmonDetail      -OutDir $workDir

        Show-Threads
    } catch {
        $msg = $($_ | Out-String) + "`nStack Trace:`n" + $_.ScriptStackTrace
        ExecControlError -OutDir $workDir -Message $msg

        throw $_
    } finally {
        Completion -Src $workDir
    }
} # Get-NetView

# For backwards compat, support direct execution as a .ps1 file (no dot sourcing needed).
if (-not [String]::IsNullOrEmpty($MyInvocation.InvocationName)) {
    if (($MyInvocation.InvocationName -eq "&") -or
        ($MyInvocation.MyCommand.Path -eq (Resolve-Path -Path $MyInvocation.InvocationName).ProviderPath)) {
        Get-NetView @args
    }
}
