#
# Common Functions
#

$ExecFunctions = {
    $columns   = 4096
    $Global:ThreadPool = $null

    $Global:ChelsioDeviceDirs = @{}
    $Global:MellanoxSystemLogDir = ""

    # Alias Write-CmdLog to Write-Host for background threads,
    # since console color only applies to the main thread.
    Set-Alias -Name Write-CmdLog -Value Write-Host

    function ExecCommandText {
        [CmdletBinding()]
        Param(
            [parameter(Mandatory=$true)] [ValidateNotNullOrEmpty()] [String] $Command
        )

        # Mirror command execution context
        Write-Output "$env:USERNAME @ ${env:COMPUTERNAME}:"

        # Mirror command to execute
        Write-Output "$(prompt)$Command"
    } # ExecCommandText()

    enum CommandStatus {
        NotTested    # Indicates problem with TestCommand
        Unavailable  # [Part of] the command doesn't exist
        Failed       # An error prevented successful execution
        Succeeded    # No errors or exceptions
    }

    # Powershell cmdlets have inconsistent implementations in command error handling. This function
    # performs a validation of the command prior to formal execution and will log any failures.
    function TestCommand {
        [CmdletBinding()]
        Param(
            [parameter(Mandatory=$true)] [ValidateNotNullOrEmpty()] [String] $Command
        )

        $status = [CommandStatus]::NotTested
        $commandOut = ""

        try {
            $error.Clear()

            # Redirect all command output (expect errors) to stdout.
            # Any errors will still be output to $error variable.
            $silentCmd = '$({0}) 2>$null 3>&1 4>&1 5>&1 6>&1' -f $Command

            # ErrorAction MUST be Stop for try catch to work.
            $commandOut = (Invoke-Expression $silentCmd -ErrorAction Stop)

            # Sometimes commands output errors even on successful execution.
            # We only should fail commands if an error was their *only* output.
            if (($error -ne $null) -and [String]::IsNullOrWhiteSpace($commandOut)) {
                # Some PS commands are incorrectly implemented in return
                # code and require detecting SilentlyContinue
                if ($Command -notlike "*SilentlyContinue*") {
                    throw $error[0]
                }
            }

            $status = [CommandStatus]::Succeeded
        } catch [Management.Automation.CommandNotFoundException] {
            $status = [CommandStatus]::Unavailable
        } catch {
            $status  = [CommandStatus]::Failed
            $commandOut = ($error[0] | Out-String)
        } finally {
            # Post-execution cleanup to avoid false positives
            $error.Clear()
        }

        return $status, $commandOut
    } # TestCommand()

    function ExecCommand {
        [CmdletBinding()]
        Param(
            [parameter(Mandatory=$true)] [ValidateNotNullOrEmpty()] [String] $Command,
            [parameter(Mandatory=$false)] [Switch] $Trusted
        )

        $cmdLog = $Command

        if ($Trusted) {
            # Skip command validation
            ExecCommandText -Command $Command
            Write-Output $(Invoke-Expression $Command)
            $cmdLog = "[Trusted] $Command"
        } else {
            $result, $commandOut = TestCommand -Command $Command

            if ($result -eq [CommandStatus]::Succeeded) {
                ExecCommandText -Command $Command
                Write-Output $commandOut
            } else {
                Write-Output "[$result]"
                Write-Output "$Command"
                Write-Output "$commandOut"
                Write-Output "`n`n"

                $cmdLog = "[$result] $Command"
            }
        }

        Write-CmdLog "$cmdLog"
    } # ExecCommand()

    function ExecCommands {
        [CmdletBinding()]
        Param(
            [parameter(Mandatory=$false)] [Switch] $Trusted,
            [parameter(Mandatory=$true)] [String] $File,
            [parameter(Mandatory=$true)] [String] $OutDir,
            [parameter(Mandatory=$true)] [String[]] $Commands
        )

        $out = (Join-Path -Path $OutDir -ChildPath $File)
        $($Commands | foreach {ExecCommand -Trusted:$Trusted -Command $_}) | Out-File -Encoding ascii -Append $out
    } # ExecCommands()
} # $ExecFunctions

. $ExecFunctions # import into script context

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

    switch -regex ($CmdLog) {
        "\[Trusted\].*" {
            $logColor = [ConsoleColor]::Cyan
            break
        }
        "\[Failed\].*" {
            $logColor = [ConsoleColor]::Yellow
            break
        }
        "\[Unavailable\].*" {
            $logColor = [ConsoleColor]::Gray
            break
        }
    }

    Write-Host $CmdLog -ForegroundColor $logColor
} # Write-CmdLog()

function Open-GlobalThreadPool {
    [CmdletBinding()]
    Param(
        [parameter(Mandatory=$true)] [Int] $MaxThreads
    )

    if ($Global:ThreadPool -eq $null)
    {
        $Global:ThreadPool = [RunspaceFactory]::CreateRunspacePool(1, $MaxThreads)
        $Global:ThreadPool.Open()
    }
} # Open-GlobalThreadPool()

function Close-GlobalThreadPool {
    [CmdletBinding()]
    Param()

    if ($Global:ThreadPool -ne $null)
    {
        Write-Host "Cleanup background threads..."
        $Global:ThreadPool.Close()
        $Global:ThreadPool.Dispose()
        $Global:ThreadPool = $null
    }
} # Close-GlobalThreadPool()

function Start-Thread {
    [CmdletBinding()]
    Param(
        [parameter(Mandatory=$true)] [ScriptBlock] $ScriptBlock,
        [parameter(Mandatory=$false)] [ValidateScript({Test-Path $_ -PathType Container})] [String] $StartPath = ".",
        [parameter(Mandatory=$false)] [Hashtable] $Params = @{}
    )

    $ps = [PowerShell]::Create()

    $ps.RunspacePool = $Global:ThreadPool
    $null = $ps.AddScript("Set-Location ""$(Resolve-Path $StartPath)""")
    $null = $ps.AddScript($ExecFunctions) # import into thread context
    $null = $ps.AddScript($ScriptBlock, $true).AddParameters($Params)

    $async = $ps.BeginInvoke()

    return @{Name=$ScriptBlock.Ast.Name; AsyncResult=$async; PowerShell=$ps}
} # Start-Thread()

function Show-Threads {
    [CmdletBinding()]
    Param(
        [parameter(Mandatory=$true)] [Hashtable[]] $Threads,
        [parameter(Mandatory=$false)] [Switch] $Sequential
    )

    if ($Sequential) {
        $Threads | foreach {
            $_.Powershell.Streams.Error | Out-Host # blocks until thread completion
            $_.Powershell.Streams.Warning | Out-Host
            $_.Powershell.Streams.Information | Out-Host
            $_.PowerShell.Streams.ClearStreams()
            $_.PowerShell.EndInvoke($_.AsyncResult)
        }
    } else {
        $mThreads = [Collections.ArrayList]$Threads

        while ($mThreads.Count -gt 0) {
            for ($i = 0; $i -lt $mThreads.Count; $i++) {
                $thread = $mThreads[$i]

                $thread.Powershell.Streams.Warning | Out-Host
                $thread.Powershell.Streams.Warning.Clear()
                $thread.Powershell.Streams.Information | foreach {Write-CmdLog "$_"}
                $thread.Powershell.Streams.Information.Clear()

                if ($thread.AsyncResult.IsCompleted)
                {
                    # Accessing Streams.Error blocks until thread is completed
                    $thread.Powershell.Streams.Error | Out-Host
                    $thread.Powershell.Streams.Error.Clear()

                    $thread.PowerShell.EndInvoke($thread.AsyncResult)
                    $mThreads.RemoveAt($i)
                    $i--
                }
            }
            Start-Sleep -Milliseconds 15
        }
    }
} # Show-Threads()

function ExecCommandsAsync {
    [CmdletBinding()]
    Param(
        [parameter(Mandatory=$false)] [Switch] $Trusted,
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
        [parameter(Mandatory=$true)] [String] $NicName,
        [parameter(Mandatory=$true)] [String] $OutDir
    )

    $name = $NicName
    $dir  = (Join-Path -Path $OutDir -ChildPath "NetIp")
    New-Item -ItemType directory -Path $dir | Out-Null

    $file = "Get-NetIpAddress.txt"
    [String []] $cmds = "Get-NetIpAddress -InterfaceAlias ""$name"" | Format-Table -AutoSize | Out-String -Width $columns",
                        "Get-NetIpAddress -InterfaceAlias ""$name"" | Format-Table -Property * -AutoSize | Out-String -Width $columns",
                        "Get-NetIpAddress -InterfaceAlias ""$name"" | Format-List",
                        "Get-NetIpAddress -InterfaceAlias ""$name"" | Format-List -Property *"
    ExecCommandsAsync -OutDir $dir -File $file -Commands $cmds

    $file = "Get-NetIPInterface.txt"
    [String []] $cmds = "Get-NetIPInterface -InterfaceAlias ""$name"" | Out-String -Width $columns",
                        "Get-NetIPInterface -InterfaceAlias ""$name"" | Format-Table -AutoSize",
                        "Get-NetIPInterface -InterfaceAlias ""$name"" | Format-Table -Property * -AutoSize | Out-String -Width $columns"
    ExecCommandsAsync -OutDir $dir -File $file -Commands $cmds

    $file = "Get-NetNeighbor.txt"
    [String []] $cmds = "Get-NetNeighbor -InterfaceAlias ""$name"" | Out-String -Width $columns",
                        "Get-NetNeighbor -InterfaceAlias ""$name"" | Format-Table -AutoSize | Out-String -Width $columns",
                        "Get-NetNeighbor -InterfaceAlias ""$name"" | Format-Table -Property * -AutoSize | Out-String -Width $columns"
    ExecCommandsAsync -OutDir $dir -File $file -Commands $cmds

    $file = "Get-NetRoute.txt"
    [String []] $cmds = "Get-NetRoute -InterfaceAlias ""$name"" | Format-Table -AutoSize | Out-String -Width $columns",
                        "Get-NetRoute -InterfaceAlias ""$name"" | Format-Table -Property * -AutoSize | Out-String -Width $columns"
    ExecCommandsAsync -OutDir $dir -File $file -Commands $cmds
} # NetIpNic()

function NetIp {
    [CmdletBinding()]
    Param(
        [parameter(Mandatory=$true)] [String] $OutDir
    )

    $dir = (Join-Path -Path $OutDir -ChildPath "NetIp")
    New-Item -ItemType directory -Path $dir | Out-Null

    $file = "Get-NetIpAddress.txt"
    [String []] $cmds = "Get-NetIpAddress | Format-Table -AutoSize | Out-String -Width $columns",
                        "Get-NetIpAddress | Format-Table -Property * -AutoSize | Out-String -Width $columns",
                        "Get-NetIpAddress | Format-List",
                        "Get-NetIpAddress | Format-List -Property *"
    ExecCommandsAsync -OutDir $dir -File $file -Commands $cmds

    $file = "Get-NetIPInterface.txt"
    [String []] $cmds = "Get-NetIPInterface | Out-String -Width $columns",
                        "Get-NetIPInterface | Format-Table -AutoSize  | Out-String -Width $columns",
                        "Get-NetIPInterface | Format-Table -Property * -AutoSize | Out-String -Width $columns"
    ExecCommandsAsync -OutDir $dir -File $file -Commands $cmds

    $file = "Get-NetNeighbor.txt"
    [String []] $cmds = "Get-NetNeighbor | Format-Table -AutoSize | Out-String -Width $columns",
                        "Get-NetNeighbor | Format-Table -Property * -AutoSize | Out-String -Width $columns"
    ExecCommandsAsync -OutDir $dir -File $file -Commands $cmds

    $file = "Get-NetIPv4Protocol.txt"
    [String []] $cmds = "Get-NetIPv4Protocol | Out-String -Width $columns",
                        "Get-NetIPv4Protocol | Format-List  -Property *",
                        "Get-NetIPv4Protocol | Format-Table -Property * -AutoSize",
                        "Get-NetIPv4Protocol | Format-Table -Property * -AutoSize | Out-String -Width $columns"
    ExecCommandsAsync -OutDir $dir -File $file -Commands $cmds

    $file = "Get-NetIPv6Protocol.txt"
    [String []] $cmds = "Get-NetIPv6Protocol | Out-String -Width $columns",
                        "Get-NetIPv6Protocol | Format-List  -Property *",
                        "Get-NetIPv6Protocol | Format-Table -Property * -AutoSize",
                        "Get-NetIPv6Protocol | Format-Table -Property * -AutoSize | Out-String -Width $columns"
    ExecCommandsAsync -OutDir $dir -File $file -Commands $cmds

    $file = "Get-NetOffloadGlobalSetting.txt"
    [String []] $cmds = "Get-NetOffloadGlobalSetting | Out-String -Width $columns",
                        "Get-NetOffloadGlobalSetting | Format-List  -Property *",
                        "Get-NetOffloadGlobalSetting | Format-Table -AutoSize",
                        "Get-NetOffloadGlobalSetting | Format-Table -Property * -AutoSize | Out-String -Width $columns"
    ExecCommandsAsync -OutDir $dir -File $file -Commands $cmds

    $file = "Get-NetPrefixPolicy.txt"
    [String []] $cmds = "Get-NetPrefixPolicy | Format-Table -AutoSize",
                        "Get-NetPrefixPolicy | Format-Table -Property * -AutoSize | Out-String -Width $columns"
    ExecCommandsAsync -OutDir $dir -File $file -Commands $cmds

    $file = "Get-NetRoute.txt"
    [String []] $cmds = "Get-NetRoute | Format-Table -AutoSize",
                        "Get-NetRoute | Format-Table -Property * -AutoSize | Out-String -Width $columns"
    ExecCommandsAsync -OutDir $dir -File $file -Commands $cmds

    $file = "Get-NetTCPConnection.txt"
    [String []] $cmds = "Get-NetTCPConnection | Format-Table -AutoSize",
                        "Get-NetTCPConnection | Format-Table -Property * -AutoSize | Out-String -Width $columns"
    ExecCommandsAsync -Trusted -OutDir $dir -File $file -Commands $cmds

    $file = "Get-NetTcpSetting.txt"
    [String []] $cmds = "Get-NetTcpSetting  | Format-Table -AutoSize",
                        "Get-NetTcpSetting  | Format-Table -Property * -AutoSize | Out-String -Width $columns"
    ExecCommandsAsync -Trusted -OutDir $dir -File $file -Commands $cmds

    $file = "Get-NetTransportFilter.txt"
    [String []] $cmds = "Get-NetTransportFilter  | Format-Table -AutoSize",
                        "Get-NetTransportFilter  | Format-Table -Property * -AutoSize | Out-String -Width $columns"
    ExecCommandsAsync -OutDir $dir -File $file -Commands $cmds

    $file = "Get-NetUDPEndpoint.txt"
    [String []] $cmds = "Get-NetUDPEndpoint  | Format-Table -AutoSize",
                        "Get-NetUDPEndpoint  | Format-Table -Property * -AutoSize | Out-String -Width $columns"
    ExecCommandsAsync -OutDir $dir -File $file -Commands $cmds

    $file = "Get-NetUDPSetting.txt"
    [String []] $cmds = "Get-NetUDPSetting  | Format-Table -AutoSize",
                        "Get-NetUDPSetting  | Format-Table -Property * -AutoSize | Out-String -Width $columns"
    ExecCommandsAsync -OutDir $dir -File $file -Commands $cmds
} # NetIp()

function NetNat {
    [CmdletBinding()]
    Param(
        [parameter(Mandatory=$true)] [String] $OutDir
    )

    $dir = (Join-Path -Path $OutDir -ChildPath "NetNat")
    New-Item -ItemType directory -Path $dir | Out-Null

    $file = "Get-NetNat.txt"
    [String []] $cmds = "Get-NetNat | Format-Table -AutoSize | Out-String -Width $columns",
                        "Get-NetNat | Format-Table -Property * -AutoSize | Out-String -Width $columns",
                        "Get-NetNat | Format-List",
                        "Get-NetNat | Format-List -Property *"
    ExecCommandsAsync -OutDir $dir -File $file -Commands $cmds

    $file = "Get-NetNatExternalAddress.txt"
    [String []] $cmds = "Get-NetNatExternalAddress | Format-Table -AutoSize | Out-String -Width $columns",
                        "Get-NetNatExternalAddress | Format-Table -Property * -AutoSize | Out-String -Width $columns",
                        "Get-NetNatExternalAddress | Format-List",
                        "Get-NetNatExternalAddress | Format-List -Property *"
    ExecCommandsAsync -OutDir $dir -File $file -Commands $cmds

    $file = "Get-NetNatGlobal.txt"
    [String []] $cmds = "Get-NetNatGlobal | Format-Table -AutoSize | Out-String -Width $columns",
                        "Get-NetNatGlobal | Format-Table -Property * -AutoSize | Out-String -Width $columns",
                        "Get-NetNatGlobal | Format-List",
                        "Get-NetNatGlobal | Format-List -Property *"
    ExecCommandsAsync -OutDir $dir -File $file -Commands $cmds

    $file = "Get-NetNatSession.txt"
    [String []] $cmds = "Get-NetNatSession | Format-Table -AutoSize | Out-String -Width $columns",
                        "Get-NetNatSession | Format-Table -Property * -AutoSize | Out-String -Width $columns",
                        "Get-NetNatSession | Format-List",
                        "Get-NetNatSession | Format-List -Property *"
    ExecCommandsAsync -OutDir $dir -File $file -Commands $cmds

    $file = "Get-NetNatStaticMapping.txt"
    [String []] $cmds = "Get-NetNatStaticMapping | Format-Table -AutoSize | Out-String -Width $columns",
                        "Get-NetNatStaticMapping | Format-Table -Property * -AutoSize | Out-String -Width $columns",
                        "Get-NetNatStaticMapping | Format-List",
                        "Get-NetNatStaticMapping | Format-List -Property *"
    ExecCommandsAsync -OutDir $dir -File $file -Commands $cmds

} # NetNat()

function NetAdapterWorker {
    [CmdletBinding()]
    Param(
        [parameter(Mandatory=$true)] [String] $NicName,
        [parameter(Mandatory=$true)] [String] $OutDir
    )

    $name = $NicName
    $dir  = $OutDir

    $file = "Get-NetAdapter.txt"
    [String []] $cmds = "Get-NetAdapter -Name ""$name"" -IncludeHidden | Out-String -Width $columns",
                        "Get-NetAdapter -Name ""$name"" -IncludeHidden | Format-List  -Property *"
    ExecCommandsAsync -OutDir $dir -File $file -Commands $cmds

    $file = "Get-NetAdapterAdvancedProperty.txt"
    [String []] $cmds = "Get-NetAdapterAdvancedProperty -Name ""$name"" -AllProperties | Sort-Object RegistryKeyword | Format-Table -AutoSize | Out-String -Width $columns",
                        "Get-NetAdapterAdvancedProperty -Name ""$name"" -AllProperties -IncludeHidden | Sort-Object RegistryKeyword | Format-Table -AutoSize | Out-String -Width $columns",
                        "Get-NetAdapterAdvancedProperty -Name ""$name"" -AllProperties -IncludeHidden | Format-List  -Property *",
                        "Get-NetAdapterAdvancedProperty -Name ""$name"" -AllProperties -IncludeHidden | Format-Table  -Property * | Out-String -Width $columns"
    ExecCommandsAsync -OutDir $dir -File $file -Commands $cmds

    $file = "Get-NetAdapterBinding.txt"
    [String []] $cmds = "Get-NetAdapterBinding -Name ""$name"" -AllBindings -IncludeHidden | Sort-Object ComponentID | Out-String -Width $columns",
                        "Get-NetAdapterBinding -Name ""$name"" -AllBindings -IncludeHidden | Format-List  -Property *"
    ExecCommandsAsync -OutDir $dir -File $file -Commands $cmds

    $file = "Get-NetAdapterChecksumOffload.txt"
    [String []] $cmds = "Get-NetAdapterChecksumOffload -Name ""$name"" -IncludeHidden | Out-String -Width $columns",
                        "Get-NetAdapterChecksumOffload -Name ""$name"" -IncludeHidden | Format-List  -Property *"
    ExecCommandsAsync -OutDir $dir -File $file -Commands $cmds

    $file = "Get-NetAdapterLso.txt"
    [String []] $cmds = "Get-NetAdapterLso -Name ""$name"" -IncludeHidden | Out-String -Width $columns",
                        "Get-NetAdapterLso -Name ""$name"" -IncludeHidden | Format-List  -Property *"
    ExecCommandsAsync -OutDir $dir -File $file -Commands $cmds

    $file = "Get-NetAdapterRss.txt"
    [String []] $cmds = "Get-NetAdapterRss -Name ""$name"" -IncludeHidden | Out-String -Width $columns",
                        "Get-NetAdapterRss -Name ""$name"" -IncludeHidden | Format-List  -Property *"
    ExecCommandsAsync -OutDir $dir -File $file -Commands $cmds

    $file = "Get-NetAdapterStatistics.txt"
    [String []] $cmds = "Get-NetAdapterStatistics -Name ""$name"" -IncludeHidden | Out-String -Width $columns",
                        "Get-NetAdapterStatistics -Name ""$name"" -IncludeHidden | Format-List  -Property *"
    ExecCommandsAsync -OutDir $dir -File $file -Commands $cmds

    $file = "Get-NetAdapterEncapsulatedPacketTaskOffload.txt"
    [String []] $cmds = "Get-NetAdapterEncapsulatedPacketTaskOffload -Name ""$name"" -IncludeHidden | Out-String -Width $columns",
                        "Get-NetAdapterEncapsulatedPacketTaskOffload -Name ""$name"" -IncludeHidden | Format-List  -Property *"
    ExecCommandsAsync -OutDir $dir -File $file -Commands $cmds

    $file = "Get-NetAdapterHardwareInfo.txt"
    [String []] $cmds = "Get-NetAdapterHardwareInfo -Name ""$name"" -IncludeHidden | Out-String -Width $columns",
                        "Get-NetAdapterHardwareInfo -Name ""$name"" -IncludeHidden | Format-List  -Property *"
    ExecCommandsAsync -OutDir $dir -File $file -Commands $cmds

    $file = "Get-NetAdapterIPsecOffload.txt"
    [String []] $cmds = "Get-NetAdapterIPsecOffload -Name ""$name"" -IncludeHidden | Out-String -Width $columns",
                        "Get-NetAdapterIPsecOffload -Name ""$name"" -IncludeHidden | Format-List  -Property *"
    ExecCommandsAsync -OutDir $dir -File $file -Commands $cmds

    $file = "Get-NetAdapterPowerManagement.txt"
    [String []] $cmds = "Get-NetAdapterPowerManagement -Name ""$name"" -IncludeHidden | Out-String -Width $columns",
                        "Get-NetAdapterPowerManagement -Name ""$name"" -IncludeHidden | Format-List  -Property *"
    ExecCommandsAsync -OutDir $dir -File $file -Commands $cmds

    $file = "Get-NetAdapterQos.txt"
    [String []] $cmds = "Get-NetAdapterQos -Name ""$name"" -IncludeHidden -ErrorAction SilentlyContinue | Out-String -Width $columns",
                        "Get-NetAdapterQos -Name ""$name"" -IncludeHidden -ErrorAction SilentlyContinue | Format-List  -Property *"
    ExecCommands -OutDir $dir -File $file -Commands $cmds # Get-NetAdapterQos has severe concurrency issues

    $file = "Get-NetAdapterRdma.txt"
    [String []] $cmds = "Get-NetAdapterRdma -Name ""$name"" -IncludeHidden | Out-String -Width $columns",
                        "Get-NetAdapterRdma -Name ""$name"" -IncludeHidden | Format-List  -Property *"
    ExecCommandsAsync -OutDir $dir -File $file -Commands $cmds

    $file = "Get-NetAdapterPacketDirect.txt"
    [String []] $cmds = "Get-NetAdapterPacketDirect -Name ""$name"" -IncludeHidden | Out-String -Width $columns",
                        "Get-NetAdapterPacketDirect -Name ""$name"" -IncludeHidden | Format-List  -Property *"
    ExecCommandsAsync -OutDir $dir -File $file -Commands $cmds

    $file = "Get-NetAdapterRsc.txt"
    [String []] $cmds = "Get-NetAdapterRsc -Name ""$name"" -IncludeHidden | Out-String -Width $columns",
                        "Get-NetAdapterRsc -Name ""$name"" -IncludeHidden | Format-List  -Property *"
    ExecCommandsAsync -OutDir $dir -File $file -Commands $cmds

    $file = "Get-NetAdapterSriov.txt"
    [String []] $cmds = "Get-NetAdapterSriov -Name ""$name"" -IncludeHidden | Out-String -Width $columns",
                        "Get-NetAdapterSriov -Name ""$name"" -IncludeHidden | Format-List  -Property *"
    ExecCommandsAsync -OutDir $dir -File $file -Commands $cmds

    $file = "Get-NetAdapterSriovVf.txt"
    [String []] $cmds = "Get-NetAdapterSriovVf -Name ""$name"" -IncludeHidden | Out-String -Width $columns",
                        "Get-NetAdapterSriovVf -Name ""$name"" -IncludeHidden | Format-List  -Property *"
    ExecCommandsAsync -OutDir $dir -File $file -Commands $cmds

    $file = "Get-NetAdapterVmq.txt"
    [String []] $cmds = "Get-NetAdapterVmq -Name ""$name"" -IncludeHidden | Out-String -Width $columns",
                        "Get-NetAdapterVmq -Name ""$name"" -IncludeHidden | Format-List  -Property *"
    ExecCommandsAsync -OutDir $dir -File $file -Commands $cmds

    $file = "Get-NetAdapterVmqQueue.txt"
    [String []] $cmds = "Get-NetAdapterVmqQueue -Name ""$name"" -IncludeHidden | Out-String -Width $columns",
                        "Get-NetAdapterVmqQueue -Name ""$name"" -IncludeHidden | Format-List  -Property *"
    ExecCommandsAsync -OutDir $dir -File $file -Commands $cmds

    $file = "Get-NetAdapterVPort.txt"
    [String []] $cmds = "Get-NetAdapterVPort -Name ""$name"" -IncludeHidden | Out-String -Width $columns",
                        "Get-NetAdapterVPort -Name ""$name"" -IncludeHidden | Format-List  -Property *"
    ExecCommandsAsync -OutDir $dir -File $file -Commands $cmds
} # NetAdapterWorker()

function NetAdapterWorkerPrepare {
    [CmdletBinding()]
    Param(
        [parameter(Mandatory=$true)] [String] $NicName,
        [parameter(Mandatory=$true)] [String] $OutDir
    )

    $name = $NicName

    # Create dir for each NIC
    $nic     = Get-NetAdapter -Name $name
    $idx     = $nic.InterfaceIndex
    $desc    = $nic.InterfaceDescription
    $title   = "pNic.$idx.$name"
    if ("$desc") {
        $title = "$title.$desc"
    }

    $dir     = (Join-Path -Path $OutDir -ChildPath "$title")
    New-Item -ItemType directory -Path $dir | Out-Null

    Write-Host "Processing: $title"
    NetIpNic         -NicName $name -OutDir $dir
    NetAdapterWorker -NicName $name -OutDir $dir
    NicVendor        -NicName $name -OutDir $dir
} # NetAdapterWorkerPrepare()

function LbfoWorker {
    [CmdletBinding()]
    Param(
        [parameter(Mandatory=$true)] [String] $LbfoName,
        [parameter(Mandatory=$true)] [String] $OutDir
    )

    $name  = $LbfoName
    $title = "LBFO.$name"
    $dir   = (Join-Path -Path $OutDir -ChildPath "$title")
    New-Item -ItemType directory -Path $dir | Out-Null

    Write-Host "Processing: $title"
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
        NetAdapterWorkerPrepare -NicName $tnic.Name -OutDir $OutDir
    }

    # Report the NIC Members
    foreach ($mnic in TryCmd {Get-NetLbfoTeamMember -Team $name}) {
        NetAdapterWorkerPrepare -NicName $mnic.Name -OutDir $OutDir
    }
} # LbfoWorker()

function LbfoDetail {
    [CmdletBinding()]
    Param(
        [parameter(Mandatory=$true)] [String] $OutDir
    )

    $dir = $OutDir

    $vmsNicNames = TryCmd {(Get-NetAdapterBinding -ComponentID "vms_pp" | where {$_.Enabled -eq $true}).Name}

    foreach ($lbfo in TryCmd {Get-NetLbfoTeam}) {
        # Skip all vSwitch Protocol NICs since the LBFO and member
        # reporting will occur as part of vSwitch reporting.
        $match = $false

        if ($lbfo.Name -in $vmsNicNames) {
            $match = $true
        }

        if (-not $match) {
            LbfoWorker -LbfoName $lbfo.Name -OutDir $dir
        }
    }
} # LbfoDetail()

function ProtocolNicDetail {
    [CmdletBinding()]
    Param(
        [parameter(Mandatory=$true)] [String] $VMSwitchId,
        [parameter(Mandatory=$true)] [String] $OutDir
    )

    $id  = $VMSwitchId
    $dir = $OutDir

    $vmsNicDescriptions = TryCmd {(Get-VMSwitch -Id $id).NetAdapterInterfaceDescriptions}

    # Distinguish between LBFO from standard PTNICs and create the hierarchies accordingly
    foreach ($desc in $vmsNicDescriptions) {
        $nic = Get-NetAdapter -InterfaceDescription $desc
        if ($nic.DriverFileName -like "NdisImPlatform.sys") {
            LbfoWorker -LbfoName $nic.Name -OutDir $dir
        } else {
            NetAdapterWorkerPrepare -NicName $nic.Name -OutDir $dir
        }
    }
} # ProtocolNicDetail()

function NativeNicDetail {
    [CmdletBinding()]
    Param(
        [parameter(Mandatory=$true)] [String] $OutDir
    )

    $dir = $OutDir

    # Cache output
    $vmsNicNames = TryCmd {(Get-NetAdapterBinding -ComponentID "vms_pp" | where {$_.Enabled -eq $true}).Name}
    $lbfoNicNames = TryCmd {(Get-NetLbfoTeamMember).Name}

    foreach ($nic in Get-NetAdapter) {
        $native = $true

        # Skip vSwitch Host vNICs by checking the driver
        if ($nic.DriverFileName -in @("vmswitch.sys", "VmsProxyHNic.sys")) {
            continue
        }

        # Skip LBFO TNICs by checking the driver
        if ($nic.DriverFileName -like "NdisImPlatform.sys") {
            continue
        }

        # Skip all vSwitch Protocol NICs
        if ($nic.Name -in $vmsNicNames) {
            $native = $false
        }

        # Skip LBFO Team Member Adapters
        if ($nic.Name -in $lbfoNicNames) {
            $native = $false
        }

        if ($native) {
            NetAdapterWorkerPrepare -NicName $nic.Name -OutDir $dir
        }
    }
} # NativeNicDetail()

function ChelsioDetailPerASIC {
    [CmdletBinding()]
    Param(
        [parameter(Mandatory=$true)] [String] $NicName,
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
        $out = Join-Path $dir "ChelsioDetailPerASIC-Error.txt"
        Write-Output "Couldn't resolve interface name for bus device." | Out-File -Encoding ascii -Append $out
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
    ExecCommandsAsync -Trusted -OutDir $dir -File $file -Commands $cmds
} # ChelsioDetailPerASIC()

function ChelsioDetail {
    [CmdletBinding()]
    Param(
        [parameter(Mandatory=$true)] [String] $NicName,
        [parameter(Mandatory=$true)] [String] $OutDir
    )

    $dir = (Join-Path -Path $OutDir -ChildPath "ChelsioDetail")
    New-Item -ItemType Directory -Path $dir | Out-Null

    # Collect Chelsio related event logs and miscellaneous details
    $file = "ChelsioDetail-WinEvent-BusDevice.txt"
    [String []] $cmds = "Get-WinEvent -LogName System | where {`$_.ProviderName -like ""*chvbd*""} | Format-List",
                        "Get-WinEvent -LogName System | where {`$_.ProviderName -like ""*cht4vbd*""} | Format-List"
    ExecCommandsAsync -OutDir $dir -File $file -Commands $cmds

    $file = "ChelsioDetail-WinEvent-NetDevice.txt"
    [String []] $cmds = "Get-WinEvent -LogName System | where {`$_.ProviderName -like ""*chndis*""} | Format-List",
                        "Get-WinEvent -LogName System | where {`$_.ProviderName -like ""*chnet*""} | Format-List",
                        "Get-WinEvent -LogName System | where {`$_.ProviderName -like ""*cht4ndis*""} | Format-List"
    ExecCommandsAsync -OutDir $dir -File $file -Commands $cmds

    $file = "ChelsioDetail-Misc.txt"
    [String []] $cmds = "verifier /query",
                        "Get-PnpDevice -FriendlyName ""*Chelsio*Enumerator*"" | Get-PnpDeviceProperty -KeyName DEVPKEY_Device_DriverVersion | Format-Table -Autosize"
    ExecCommandsAsync -OutDir $dir -File $file -Commands $cmds

    # Check path for cxgbtool.exe, since it's needed to collect most Chelsio related logs.
    if (-not (Get-Command "cxgbtool.exe" -ErrorAction SilentlyContinue)) {
        $out = Join-Path $dir "ChelsioDetail-Error.txt"
        Write-Output "Unable to collect Chelsio debug logs as cxgbtool is not present." | Out-File -Encoding ascii -Append $out
        return
    }

    ChelsioDetailPerASIC -NicName $NicName -OutDir $dir

    $ifIndex    = (Get-NetAdapter $NicName).InterfaceIndex
    $dirNetName = "NetDev_$ifIndex"
    $dirNet     = (Join-Path -Path $dir -ChildPath $dirNetName)
    New-Item -ItemType Directory -Path $dirNet | Out-Null

    # Enumerate NIC
    [Array] $NetDevices = Get-NetAdapter -InterfaceDescription "*Chelsio*" | where {$_.Status -eq "Up"} | Sort-Object -Property MacAddress
    $ifNameNic = $null
    for ($i = 0; $i -lt $NetDevices.Count; $i++) {
        if ($NicName -eq $NetDevices[$i].Name) {
            $ifNameNic = "nic$i"
            break
        }
    }

    if ([String]::IsNullOrEmpty($ifNameNic)) {
        $out = Join-Path $dir "ChelsioDetail-Error.txt"
        Write-Output "Couldn't resolve interface name for Network device(ifIndex:$ifIndex)" | Out-File -Encoding ascii -Append $out
        return
    }

    $file = "ChelsioDetail-Debug.txt"
    [String []] $cmds = "cxgbtool.exe $ifNameNic debug filter",
                        "cxgbtool.exe $ifNameNic debug qsets",
                        "cxgbtool.exe $ifNameNic debug qstats txeth rxeth txvirt rxvirt txrdma rxrdma txnvgre rxnvgre",
                        "cxgbtool.exe $ifNameNic debug dumpctx",
                        "cxgbtool.exe $ifNameNic debug version",
                        "cxgbtool.exe $ifNameNic debug eps",
                        "cxgbtool.exe $ifNameNic debug qps",
                        "cxgbtool.exe $ifNameNic debug rdma_stats",
                        "cxgbtool.exe $ifNameNic debug stags",
                        "cxgbtool.exe $ifNameNic debug l2t"
    ExecCommandsAsync -OutDir $dirNet -File $file -Commands $cmds

    $file = "ChelsioDetail-Hardware.txt"
    [String []] $cmds = "cxgbtool.exe $ifNameNic hardware tid_info",
                        "cxgbtool.exe $ifNameNic hardware fec",
                        "cxgbtool.exe $ifNameNic hardware link_cfg",
                        "cxgbtool.exe $ifNameNic hardware pktfilter",
                        "cxgbtool.exe $ifNameNic hardware sensor"
    ExecCommandsAsync -OutDir $dirNet -File $file -Commands $cmds
} # ChelsioDetail()

function MellanoxFirmwareInfo {
    [CmdletBinding()]
    Param(
        [parameter(Mandatory=$true)] [String] $NicName,
        [parameter(Mandatory=$true)] [String] $OutDir
    )

    $file = "MellanoxFirmwareInfo-Error.txt"
    $dir  = $OutDir
    $out  = Join-Path $dir $file

    $mstStatus = TryCmd {mst status -v}
    if ((-not $mstStatus) -or ($mstStatus -like "*error*")) {
        Write-Output "$NicName : MFT is not installed on this server" | Out-File -Encoding ascii -Append $out
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
            $found = $true;
            $device = $device.Trim()
            break
        }
    }

    if (-not $found) {
        Write-Output "$NicName : No matching device found in mst status" | Out-File -Encoding ascii -Append $out
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

function MellanoxDetailPerNic {
    [CmdletBinding()]
    Param(
        [parameter(Mandatory=$true)] [String] $NicName,
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
        default {
            $out = Join-Path $dir "MellanoxDetailPerNic-Error.txt"
            Write-Output "Driver $driverFileName isn't supported" | Out-File -Encoding ascii -Append $out
            return
        }
    }

    $toolName = $driverFileName -replace ".sys", "Cmd"
    $toolPath = "$driverDir\Management Tools\$toolName.exe"

    $file = "$toolName-Snapshot.txt"
    [String []] $cmds = "&""$toolPath"" -SnapShot -name ""$NicName"""
    (Get-NetAdapterSriovVf -Name "$NicName" -ErrorAction SilentlyContinue).FunctionID | foreach {
        $cmds += "&""$toolPath"" -SnapShot -VfStats -name ""$NicName"" -vf $_ -register"
    }
    ExecCommandsAsync -OutDir $dir -File $file -Commands $cmds

    #
    # Enumerate device location string
    #
    if ((Get-NetAdapter -Name $NicName).InterfaceDescription -like "*Mellanox*Virtual*Adapter*") {
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
        $dmpPath = "$env:windir\Temp\MLX5_Dump_Me_Now"
    }

    $file = "Copy-MellanoxDMN.txt"
    [String[]] $paths = "$dmpPath-$($deviceLocation -replace "_","-")"
    ExecCopyItemsAsync -OutDir $dir -File $file -Paths $paths -Destination $dir

    #
    # Device logs
    #
    $file = "Copy-DeviceLogs.txt"
    $destination = Join-Path $dir "DeviceLogs"
    [String[]] $paths = "$driverDir\build_id.txt",
                        "$env:windir\Temp\SingleFunc*$deviceLocation*.log",
                        "$env:windir\Temp\SriovMaster*$deviceLocation*.log",
                        "$env:windir\Temp\SriovSlave*$deviceLocation*.log",
                        "$env:windir\Temp\Native*$deviceLocation*.log",
                        "$env:windir\Temp\Master*$deviceLocation*.log",
                        "$env:windir\Temp\ML?X5*$deviceLocation*.log",
                        "$env:windir\Temp\mlx5*$deviceLocation*.log"
    ExecCopyItemsAsync -OutDir $dir -File $file -Paths $paths -Destination $destination
} # MellanoxDetailPerNic()

function MellanoxSystemDetail {
    [CmdletBinding()]
    Param(
        [parameter(Mandatory=$true)] [String] $OutDir
    )

    $dir = Join-Path $OutDir "SystemLogs"

    if ([String]::IsNullOrEmpty($Global:MellanoxSystemLogDir))
    {
        $Global:MellanoxSystemLogDir = $dir
        $null = New-Item -ItemType Directory -Path $dir
    }
    else
    {
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

    $file = "Get-WinEvent-mlx5.txt"
    [String[]] $cmds = "Get-WinEvent -FilterHashTable @{logname=""system"";providername=""mlx5""} | Format-List -Property *"
    ExecCommandsAsync -OutDir $dir -File $file -Commands $cmds

    $file = "Get-WinEvent-mlnx5.txt"
    [String[]] $cmds = "Get-WinEvent -FilterHashTable @{logname=""system"";providername=""mlnx5""} | Format-List -Property *"
    ExecCommandsAsync -OutDir $dir -File $file -Commands $cmds

    $file = "Get-WinEvent-mlnx5hpc.txt"
    [String[]] $cmds = "Get-WinEvent -FilterHashTable @{logname=""system"";providername=""mlnx5hpc""} | Format-List -Property *"
    ExecCommandsAsync -OutDir $dir -File $file -Commands $cmds

    $file = "Get-WinEvent-Application.txt"
    [String[]] $cmds = "Get-WinEvent -FilterHashTable @{logname=""application""} | Format-List -Property *"
    ExecCommandsAsync -OutDir $dir -File $file -Commands $cmds

    $file = "Get-WinEvent-Setup.txt"
    [String[]] $cmds = "Get-WinEvent -FilterHashTable @{logname=""Setup""} | Format-List -Property *"
    ExecCommandsAsync -OutDir $dir -File $file -Commands $cmds

    $file = "Copy-LogFiles.txt"
    $destination = Join-Path $dir "LogFiles"
    [String[]] $paths = "$env:windir\System32\LogFiles\PerformanceTuning.log",
                        "$env:LOCALAPPDATA\MLNX_WINOF2.log",
                        "$env:windir\inf\setupapi.dev",
                        "$env:windir\inf\setupapi.dev.log",
                        "$env:temp\MpKdTraceLog.bin",
                        "$env:windir\System32\LogFiles\Mlnx\Mellanox-*System.etl*",
                        "$env:windir\debug\Mellanox*.etl"
    ExecCopyItemsAsync -OutDir $dir -File $file -Paths $paths -Destination $destination
} # MellanoxSystemDetail()

function MellanoxDetail {
    [CmdletBinding()]
    Param(
        [parameter(Mandatory=$true)] [String] $NicName,
        [parameter(Mandatory=$true)] [String] $OutDir
    )

    $dir = (Join-Path -Path $OutDir -ChildPath "MellanoxDetail")
    New-Item -ItemType Directory -Path $dir | Out-Null

    # Collect Mellanox related event logs and miscellaneous details

    $driverVersionString = (Get-NetAdapter -name $NicName).DriverVersionString
    $versionMajor, $versionMinor, $_ = $driverVersionString -split "\."

    if (($versionMajor -lt 2) -or (($versionMajor -eq 2) -and ($versionMinor -lt 20))) {
        $out  = Join-Path $dir "MellanoxDetail-Error.txt"
        Write-Output "$NicName : Driver version is $versionMajor.$versionMinor, which is less than 2.20" | Out-File -Encoding ascii -Append $out
        return
    }

    MellanoxSystemDetail -OutDir $dir
    MellanoxFirmwareInfo -NicName $NicName -OutDir $dir
    MellanoxDetailPerNic -NicName $NicName -OutDir $dir
} # MellanoxDetail()

# ========================================================================
# function stub for extension by IHV
# Copy and rename it, add your commands, and call it in NicVendor() below
# ========================================================================
function MyVendorDetail {
    [CmdletBinding()]
    Param(
        [parameter(Mandatory=$true)] [String] $NicName,
        [parameter(Mandatory=$true)] [String] $OutDir
    )

    $dir = Join-Path -Path $OutDir -ChildPath "MyVendorDetail"

    # Try to keep the layout of this block of code
    # Feel free to copy it or wrap it in other control structures
    # See other functions in this file for examples
    $file = "$NicName.MyVendor.txt"
    [String []] $cmds = "Command 1",
                        "Command 2",
                        "Command 3",
                        "etc."
    ExecCommandsAsync -OutDir $dir -File $file -Commands $cmds
} # MyVendorDetail()

function NicVendor {
    [CmdletBinding()]
    Param(
        [parameter(Mandatory=$true)] [String] $NicName, # Get-NetAdapter output
        [parameter(Mandatory=$true)] [String] $OutDir
    )

    $dir = $OutDir

    # Call appropriate vendor specific function
    $pciId = (Get-NetAdapterAdvancedProperty -Name $NicName -AllProperties -RegistryKeyword "ComponentID").RegistryValue
    switch -Wildcard($pciId) {
        "CHT*BUS\chnet*" {
            ChelsioDetail  $NicName $dir
            break
        }
        "PCI\VEN_15B3*" {
            MellanoxDetail $NicName $dir
            break
        }
        # Not implemented.  See MyVendorDetail() for examples.
        #
        #"PCI\VEN_8086*" {
        #    IntelDetail $Nic $dir
        #    break
        #}
        default {
            # Not implemented, not native, or N/A
        }
    }
} # NicVendor()

function HostVNicWorker {
    [CmdletBinding()]
    Param(
        [parameter(Mandatory=$true)] [String] $HostVNicName,
        [parameter(Mandatory=$true)] [String] $OutDir
    )

    $name = $HostVNicName
    $dir  = $OutDir

    $file = "Get-VMNetworkAdapter.txt"
    [String []] $cmds = "Get-VMNetworkAdapter -ManagementOS -VMNetworkAdapterName ""$name"" | Out-String -Width $columns",
                        "Get-VMNetworkAdapter -ManagementOS -VMNetworkAdapterName ""$name"" | Format-List  -Property *"
    ExecCommandsAsync -OutDir $dir -File $file -Commands $cmds

    $file = "Get-VMNetworkAdapterAcl.txt"
    [String []] $cmds = "Get-VMNetworkAdapterAcl -ManagementOS -VMNetworkAdapterName ""$name"" | Out-String -Width $columns",
                        "Get-VMNetworkAdapterAcl -ManagementOS -VMNetworkAdapterName ""$name"" | Format-List  -Property *"
    ExecCommandsAsync -OutDir $dir -File $file -Commands $cmds

    $file = "Get-VMNetworkAdapterExtendedAcl.txt"
    [String []] $cmds = "Get-VMNetworkAdapterExtendedAcl -ManagementOS -VMNetworkAdapterName ""$name"" | Out-String -Width $columns",
                        "Get-VMNetworkAdapterExtendedAcl -ManagementOS -VMNetworkAdapterName ""$name"" | Format-List  -Property *"
    ExecCommandsAsync -OutDir $dir -File $file -Commands $cmds

    $file = "Get-VMNetworkAdapterFailoverConfiguration.txt"
    [String []] $cmds = "Get-VMNetworkAdapterFailoverConfiguration -ManagementOS -VMNetworkAdapterName ""$name"" | Out-String -Width $columns",
                        "Get-VMNetworkAdapterFailoverConfiguration -ManagementOS -VMNetworkAdapterName ""$name"" | Format-List  -Property *"
    ExecCommandsAsync -OutDir $dir -File $file -Commands $cmds

    $file = "Get-VMNetworkAdapterIsolation.txt"
    [String []] $cmds = "Get-VMNetworkAdapterIsolation -ManagementOS -VMNetworkAdapterName ""$name"" | Out-String -Width $columns",
                        "Get-VMNetworkAdapterIsolation -ManagementOS -VMNetworkAdapterName ""$name"" | Format-List  -Property *"
    ExecCommandsAsync -OutDir $dir -File $file -Commands $cmds

    $file = "Get-VMNetworkAdapterRoutingDomainMapping.txt"
    [String []] $cmds = "Get-VMNetworkAdapterRoutingDomainMapping -ManagementOS -VMNetworkAdapterName ""$name"" | Out-String -Width $columns",
                        "Get-VMNetworkAdapterRoutingDomainMapping -ManagementOS -VMNetworkAdapterName ""$name"" | Format-List -Property *"
    ExecCommandsAsync -OutDir $dir -File $file -Commands $cmds

    $file = "Get-VMNetworkAdapterTeamMapping.txt"
    [String []] $cmds = "Get-VMNetworkAdapterTeamMapping -ManagementOS -VMNetworkAdapterName ""$name"" | Out-String -Width $columns",
                        "Get-VMNetworkAdapterTeamMapping -ManagementOS -VMNetworkAdapterName ""$name"" | Format-List  -Property *"
    ExecCommandsAsync -OutDir $dir -File $file -Commands $cmds

    $file = "Get-VMNetworkAdapterVlan.txt"
    [String []] $cmds = "Get-VMNetworkAdapterVlan -ManagementOS -VMNetworkAdapterName ""$name"" | Out-String -Width $columns",
                        "Get-VMNetworkAdapterVlan -ManagementOS -VMNetworkAdapterName ""$name"" | Format-List  -Property *"
    ExecCommandsAsync -OutDir $dir -File $file -Commands $cmds
} # HostVNicWorker()

function HostVNicDetail {
    [CmdletBinding()]
    Param(
        [parameter(Mandatory=$true)] [String] $VMSwitchId,
        [parameter(Mandatory=$true)] [String] $OutDir
    )

    # Cache output
    $allNetAdapters = Get-NetAdapter -IncludeHidden

    foreach ($nic in TryCmd {Get-VMNetworkAdapter -ManagementOS} | where {$_.SwitchId -eq $VMSwitchId}) {
        <#
            Correlate to VMNic instance to NetAdapter instance view
            Physical to Virtual Mapping.
            -----------------------------
            Get-NetAdapter uses:
            Name                    : vEthernet (VMS-Ext-Public) 2
            Get-VMNetworkAdapter uses:
            Name                    : VMS-Ext-Public

            Thus we need to match the corresponding devices via DeviceID such that
            we can execute VMNetworkAdapter and NetAdapter information for this hNIC
        #>
        $idx = 0
        foreach($pnic in $allNetAdapters) {
            if ($pnic.DeviceID -eq $nic.DeviceId) {
                $pnicname = $pnic.Name
                $idx      = $pnic.InterfaceIndex
            }
        }

        # Create dir for each NIC
        $name    = $nic.Name
        $title   = "hNic.$idx.$name"
        $dir     = (Join-Path -Path $OutDir -ChildPath "$title")
        New-Item -ItemType directory -Path $dir | Out-Null

        Write-Host "Processing: $title"
        NetIpNic         -NicName      $pnicname -OutDir $dir
        HostVNicWorker   -HostVNicName $name     -OutDir $dir
        NetAdapterWorker -NicName      $pnicname -OutDir $dir
    }
} # HostVNicDetail()

function VMNetworkAdapterDetail {
    [CmdletBinding()]
    Param(
        [parameter(Mandatory=$true)] [String] $VMName,
        [parameter(Mandatory=$true)] [String] $VMNicName,
        [parameter(Mandatory=$true)] [String] $VMNicId,
        [parameter(Mandatory=$true)] [String] $OutDir
    )

    $name  = $VMNicName
    $id    = $VMNicId
    $title = "VMNic.$name.$id"
    $dir   = (Join-Path -Path $OutDir -ChildPath "$title")
    New-Item -ItemType directory -Path $dir | Out-Null

    # We must use Id to identity VMNics, because different VMNics
    # can have the same MAC (if VM is off), Name, VMName, and SwitchName.
    [String] $vmNicObject = "`$(Get-VMNetworkAdapter -VMName ""$VMName"" | where {(`$_.Id -split ""\\"")[1] -eq ""$id""})"

    Write-Host "Processing: $title"
    $file = "Get-VMNetworkAdapter.txt"
    [String []] $cmds = "$vmNicObject | Out-String -Width $columns",
                        "$vmNicObject | Format-List -Property *"
    ExecCommandsAsync -OutDir $dir -File $file -Commands $cmds

    $file = "Get-VMNetworkAdapterAcl.txt"
    [String []] $cmds = "Get-VMNetworkAdapterAcl -VMNetworkAdapter $vmNicObject | Out-String -Width $columns",
                        "Get-VMNetworkAdapterAcl -VMNetworkAdapter $vmNicObject | Format-List -Property *"
    ExecCommandsAsync -OutDir $dir -File $file -Commands $cmds

    $file = "Get-VMNetworkAdapterExtendedAcl.txt"
    [String []] $cmds = "Get-VMNetworkAdapterExtendedAcl -VMNetworkAdapter $vmNicObject | Out-String -Width $columns",
                        "Get-VMNetworkAdapterExtendedAcl -VMNetworkAdapter $vmNicObject | Format-List -Property *"
    ExecCommandsAsync -OutDir $dir -File $file -Commands $cmds

    $file = "Get-VMNetworkAdapterFailoverConfiguration.txt"
    [String []] $cmds = "Get-VMNetworkAdapterFailoverConfiguration -VMNetworkAdapter $vmNicObject | Out-String -Width $columns",
                        "Get-VMNetworkAdapterFailoverConfiguration -VMNetworkAdapter $vmNicObject | Format-List -Property *"
    ExecCommandsAsync -OutDir $dir -File $file -Commands $cmds

    $file = "Get-VMNetworkAdapterIsolation.txt"
    [String []] $cmds = "Get-VMNetworkAdapterIsolation -VMNetworkAdapter $vmNicObject | Out-String -Width $columns",
                        "Get-VMNetworkAdapterIsolation -VMNetworkAdapter $vmNicObject | Format-List -Property *"
    ExecCommandsAsync -OutDir $dir -File $file -Commands $cmds

    $file = "Get-VMNetworkAdapterRoutingDomainMapping.txt"
    [String []] $cmds = "Get-VMNetworkAdapterRoutingDomainMapping -VMNetworkAdapter $vmNicObject | Out-String -Width $columns",
                        "Get-VMNetworkAdapterRoutingDomainMapping -VMNetworkAdapter $vmNicObject | Format-List -Property *"
    ExecCommandsAsync -OutDir $dir -File $file -Commands $cmds

    $file = "Get-VMNetworkAdapterTeamMapping.txt"
    [String []] $cmds = "Get-VMNetworkAdapterTeamMapping -VMNetworkAdapter $vmNicObject | Out-String -Width $columns",
                        "Get-VMNetworkAdapterTeamMapping -VMNetworkAdapter $vmNicObject | Format-List -Property *"
    ExecCommandsAsync -OutDir $dir -File $file -Commands $cmds

    $file = "Get-VMNetworkAdapterVlan.txt"
    [String []] $cmds = "Get-VMNetworkAdapterVlan -VMNetworkAdapter $vmNicObject | Out-String -Width $columns",
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
        [parameter(Mandatory=$true)] [String] $VMId,
        [parameter(Mandatory=$true)] [String] $OutDir
    )

    $id  = $VMId
    $dir = $OutDir

    # Different VMs can have the same name
    [String] $vmObject = "`$(Get-VM -Id $id)"

    $file = "Get-VM.txt"
    [String []] $cmds = "$vmObject | Out-String -Width $columns",
                        "$vmObject | Format-List -Property *"
    ExecCommandsAsync -OutDir $dir -File $file -Commands $cmds

    $file = "Get-VMBios.txt"
    [String []] $cmds = "Get-VMBios -VM $vmObject | Out-String -Width $columns",
                        "Get-VMBios -VM $vmObject | Format-List -Property *"
    ExecCommandsAsync -OutDir $dir -File $file -Commands $cmds

    $file = "Get-VMFirmware.txt"
    [String []] $cmds = "Get-VMFirmware -VM $vmObject | Out-String -Width $columns",
                        "Get-VMFirmware -VM $vmObject | Format-List -Property *"
    ExecCommandsAsync -OutDir $dir -File $file -Commands $cmds

    $file = "Get-VMProcessor.txt"
    [String []] $cmds = "Get-VMProcessor -VM $vmObject | Out-String -Width $columns",
                        "Get-VMProcessor -VM $vmObject | Format-List -Property *"
    ExecCommandsAsync -OutDir $dir -File $file -Commands $cmds

    $file = "Get-VMMemory.txt"
    [String []] $cmds = "Get-VMMemory -VM $vmObject | Out-String -Width $columns",
                        "Get-VMMemory -VM $vmObject | Format-List -Property *"
    ExecCommandsAsync -OutDir $dir -File $file -Commands $cmds

    $file = "Get-VMVideo.txt"
    [String []] $cmds = "Get-VMVideo -VM $vmObject | Out-String -Width $columns",
                        "Get-VMVideo -VM $vmObject | Format-List -Property *"
    ExecCommandsAsync -OutDir $dir -File $file -Commands $cmds

    $file = "Get-VMHardDiskDrive.txt"
    [String []] $cmds = "Get-VMHardDiskDrive -VM $vmObject | Out-String -Width $columns",
                        "Get-VMHardDiskDrive -VM $vmObject | Format-List -Property *"
    ExecCommandsAsync -OutDir $dir -File $file -Commands $cmds

    $file = "Get-VMComPort.txt"
    [String []] $cmds = "Get-VMComPort -VM $vmObject | Out-String -Width $columns",
                        "Get-VMComPort -VM $vmObject | Format-List -Property *"
    ExecCommandsAsync -OutDir $dir -File $file -Commands $cmds

    $file = "Get-VMSecurity.txt"
    [String []] $cmds = "Get-VMSecurity -VM $vmObject | Out-String -Width $columns",
                        "Get-VMSecurity -VM $vmObject | Format-List -Property *"
    ExecCommandsAsync -OutDir $dir -File $file -Commands $cmds
} # VMWorker()

function VMNetworkAdapterPerVM {
    [CmdletBinding()]
    Param(
        [parameter(Mandatory=$true)] [String] $VMSwitchId,
        [parameter(Mandatory=$true)] [String] $OutDir
    )

    [Int] $index = 1
    foreach ($vm in TryCmd {Get-VM}) {
        $vmName = $vm.Name
        $vmId   = $vm.VMId
        $title  = "VM.$index.$vmName"

        $dir    = (Join-Path -Path $OutDir -ChildPath "$title")

        $vmQuery = $false
        foreach ($vmNic in TryCmd {Get-VMNetworkAdapter -VM $vm} | where {$_.SwitchId -eq $VMSwitchId}) {
            $vmNicId = ($vmNic.Id -split "\\")[1] # Same as AdapterId, but works if VM is off

            if (-not $vmQuery)
            {
                Write-Host "Processing: $title"
                New-Item -ItemType "Directory" -Path $dir | Out-Null
                VMWorker -VMId $vmId -OutDir $dir
                $vmQuery = $true
            }

            VMNetworkAdapterDetail -VMName $vmName -VMNicName $vmNic.Name -VMNicId $vmNicId -OutDir $dir
        }

        $index++
    }
} # VMNetworkAdapterPerVM()

function VMSwitchWorker {
    [CmdletBinding()]
    Param(
        [parameter(Mandatory=$true)] [String] $VMSwitchId,
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
} # VMSwitchWorker()

function VfpExtensionDetail {
    [CmdletBinding()]
    Param(
        [parameter(Mandatory=$true)] [String] $VMSwitchId,
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

    $file = "NmScrub.txt"
    [String []] $cmds = "nmscrub -a -n -t "
    ExecCommandsAsync -OutDir $dir -File $file -Commands $cmds

    # FIXME!!!
    # See this command to get VFs on vSwitch
    # Get-NetAdapterSriovVf -SwitchId 2

    # Acquire per vSwitch instance info/mappings
    [Int] $index = 1
    foreach ($vmSwitch in TryCmd {Get-VMSwitch}) {
        $name  = $vmSwitch.Name
        $type  = $vmSwitch.SwitchType
        $id    = $vmSwitch.Id
        $title = "VMSwitch.$index.$type.$name"

        $dir  = (Join-Path -Path $OutDir -ChildPath "$title")
        New-Item -ItemType directory -Path $dir | Out-Null

        Write-Host "Processing: $title"
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
    [String []] $cmds = "Get-VMSwitch | Sort-Object Name | Format-Table -AutoSize | Out-String -Width $columns",
                        "Get-VMSwitch | Sort-Object Name | Format-Table -Property * -AutoSize | Out-String -Width $columns"
    ExecCommandsAsync -OutDir $dir -File $file -Commands $cmds

    $file = "Get-VMNetworkAdapter.txt"
    [String []] $cmds = "Get-VMNetworkAdapter -All | Sort-Object Name | Format-Table -AutoSize | Out-String -Width $columns",
                        "Get-VMNetworkAdapter -All | Sort-Object Name | Format-Table -Property * -AutoSize | Out-String -Width $columns"
    ExecCommandsAsync -OutDir $dir -File $file -Commands $cmds

    $file = "Get-NetAdapter.txt"
    [String []] $cmds = "Get-NetAdapter | Sort-Object InterfaceDescription | Format-Table -AutoSize | Out-String -Width $columns ",
                        "Get-NetAdapter -IncludeHidden | Sort-Object InterfaceDescription | Format-Table -Property * -AutoSize | Out-String -Width $columns"
    ExecCommandsAsync -OutDir $dir -File $file -Commands $cmds

    $file = "Get-NetAdapterStatistics.txt"
    [String []] $cmds = "Get-NetAdapterStatistics -IncludeHidden | Sort-Object InterfaceDescription | Format-Table -Autosize  | Out-String -Width $columns",
                        "Get-NetAdapterStatistics -IncludeHidden | Sort-Object InterfaceDescription | Format-Table -Property * -Autosize | Out-String -Width $columns"
    ExecCommandsAsync -OutDir $dir -File $file -Commands $cmds

    $file = "Get-NetLbfoTeam.txt"
    [String []] $cmds = "Get-NetLbfoTeam | Sort-Object InterfaceDescription | Format-Table -Autosize  | Out-String -Width $columns",
                        "Get-NetLbfoTeam | Sort-Object InterfaceDescription | Format-Table -Property * -AutoSize  | Out-String -Width $columns"
    ExecCommandsAsync -OutDir $dir -File $file -Commands $cmds

    $file = "Get-NetIpAddress.txt"
    [String []] $cmds = "Get-NetIpAddress | Format-Table -Autosize | Format-Table -Autosize  | Out-String -Width $columns",
                        "Get-NetIpAddress | Format-Table -Property * -AutoSize | Out-String -Width $columns"
    ExecCommandsAsync -OutDir $dir -File $file -Commands $cmds

    $file = "_ipconfig.txt"
    [String []] $cmds = "ipconfig",
                        "ipconfig /allcompartments /all"
    ExecCommandsAsync -OutDir $dir -File $file -Commands $cmds

    $file = "_arp.txt"
    [String []] $cmds = "arp -a"
    ExecCommandsAsync -OutDir $dir -File $file -Commands $cmds

    $file = "_netstat.txt"
    [String []] $cmds = "netstat",
                        "netstat -nasert",
                        "netstat -an",
                        "netstat -xan | ? {`$_ -match ""445""}"
    ExecCommandsAsync -OutDir $dir -File $file -Commands $cmds

    $file = "_advfirewall.txt"
    [String []] $cmds = "netsh advfirewall show allprofiles"
    ExecCommandsAsync -OutDir $dir -File $file -Commands $cmds
} # NetworkSummary()

function SMBDetail {
    [CmdletBinding()]
    Param(
        [parameter(Mandatory=$true)] [String] $OutDir
    )

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
    [String []] $cmds = "Get-SmbClientNetworkInterface | Sort-Object FriendlyName | Format-Table -AutoSize | Out-String -Width $columns",
                        "Get-SmbClientNetworkInterface | Format-List  -Property *"
    ExecCommandsAsync -OutDir $dir -File $file -Commands $cmds

    $file = "Get-SmbServerNetworkInterface.txt"
    [String []] $cmds = "Get-SmbServerNetworkInterface | Sort-Object FriendlyName | Format-Table -AutoSize | Out-String -Width $columns",
                        "Get-SmbServerNetworkInterface | Format-List  -Property *"
    ExecCommandsAsync -OutDir $dir -File $file -Commands $cmds

    $file = "Get-SmbClientConfiguration.txt"
    [String []] $cmds = "Get-SmbClientConfiguration"
    ExecCommandsAsync -OutDir $dir -File $file -Commands $cmds

    $file = "Get-SmbServerConfiguration.txt"
    [String []] $cmds = "Get-SmbServerConfiguration"
    ExecCommandsAsync -OutDir $dir -File $file -Commands $cmds

    $file = "Get-SmbMultichannelConnection.txt"
    [String []] $cmds = "Get-SmbMultichannelConnection | Sort-Object Name | Format-Table -AutoSize | Out-String -Width $columns",
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
                        "Get-WinEvent -ListLog ""*SMB*"" | Get-WinEvent | ? Message -like ""*RDMA*"" | Format-List -Property *"
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

    try {
        $null = Get-Service "hns" -ErrorAction Stop
    } catch {
        Write-Host "HNSDetail: hns service not found, skipping."
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
            $null = net stop hns /y
        }

        $file = "HNSData.txt"
        [String []] $cmds = "Copy-Item -Path ""$env:ProgramData\Microsoft\Windows\HNS\HNS.data"" -Destination $dir -Verbose 4>&1"
        ExecCommands -OutDir $dir -File $file -Commands $cmds
    } finally {
        if ($hnsRunning) {
            $null = net start hns
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

    #netsh trace start scenario=Virtualization provider=Microsoft-Windows-tcpip provider=Microsoft-Windows-winnat capture=yes captureMultilayer=yes capturetype=both report=disabled tracefile=$dir\server.etl overwrite=yes
    #Start-Sleep 120
    #netsh trace stop
} # HNSDetail()

function QosDetail {
    [CmdletBinding()]
    Param(
        [parameter(Mandatory=$true)] [String] $OutDir
    )

    $dir = (Join-Path -Path $OutDir -ChildPath "NetQoS")
    New-Item -ItemType directory -Path $dir | Out-Null

    $file = "Get-NetAdapterQos.txt"
    [String []] $cmds = "Get-NetAdapterQos",
                        "Get-NetAdapterQos -IncludeHidden | Out-String -Width $columns",
                        "Get-NetAdapterQos -IncludeHidden | Format-List -Property *"
    ExecCommands -OutDir $dir -File $file -Commands $cmds # Get-NetAdapterQos has severe concurrency issues

    $file = "Get-NetQosDcbxSetting.txt"
    [String []] $cmds = "Get-NetQosDcbxSetting",
                        "Get-NetQosDcbxSetting | Format-List  -Property *",
                        "Get-NetQosDcbxSetting | Format-Table -Property *  -AutoSize | Out-String -Width $columns"
    ExecCommandsAsync -OutDir $dir -File $file -Commands $cmds

    $file = "Get-NetQosFlowControl.txt"
    [String []] $cmds = "Get-NetQosFlowControl",
                        "Get-NetQosFlowControl | Format-List  -Property *",
                        "Get-NetQosFlowControl | Format-Table -Property *  -AutoSize | Out-String -Width $columns"
    ExecCommandsAsync -OutDir $dir -File $file -Commands $cmds

    $file = "Get-NetQosPolicy.txt"
    [String []] $cmds = "Get-NetQosPolicy",
                        "Get-NetQosPolicy | Format-List  -Property *",
                        "Get-NetQosPolicy | Format-Table -Property *  -AutoSize | Out-String -Width $columns"
    ExecCommandsAsync -OutDir $dir -File $file -Commands $cmds

    $file = "Get-NetQosTrafficClass.txt"
    [String []] $cmds = "Get-NetQosTrafficClass",
                        "Get-NetQosTrafficClass | Format-List  -Property *",
                        "Get-NetQosTrafficClass | Format-Table -Property *  -AutoSize | Out-String -Width $columns"
    ExecCommandsAsync -OutDir $dir -File $file -Commands $cmds
} # QosDetail()

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
    [String []] $cmds = "Get-WindowsDriver -Online -All" # very slow, -Trusted to skip validation
    ExecCommandsAsync -Trusted -OutDir $dir -File $file -Commands $cmds

    $file = "Get-WindowsEdition.txt"
    [String []] $cmds = "Get-WindowsEdition -Online"
    ExecCommandsAsync -OutDir $dir -File $file -Commands $cmds

    $file = "Get-HotFix.txt"
    [String []] $cmds = "Get-Hotfix | Sort-Object InstalledOn | Format-Table -AutoSize | Out-String -Width $columns",
                        "Get-Hotfix | Sort-Object InstalledOn | Format-Table -Property * -AutoSize | Out-String -Width $columns"
    ExecCommandsAsync -OutDir $dir -File $file -Commands $cmds

    $file = "Get-PnpDevice.txt"
    [String []] $cmds = "Get-PnpDevice | Sort-Object Class, FriendlyName, InstanceId | Format-Table -AutoSize | Out-String -Width $columns",
                        "Get-PnpDevice | Sort-Object Class, FriendlyName, InstanceId | Format-List -Property * | Out-String -Width $columns"
    ExecCommandsAsync -OutDir $dir -File $file -Commands $cmds

    $file = "Get-CimInstance.Win32_PnPSignedDriver.txt"
    [String []] $cmds = "Get-CimInstance Win32_PnPSignedDriver | Select-Object DeviceName, DeviceId, DriverVersion | Format-Table -AutoSize | Out-String -Width $columns",
                        "Get-CimInstance Win32_PnPSignedDriver | Format-List -Property * | Out-String -Width $columns"
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
    [String []] $cmds = "Get-VMHostSupportedVersion | Format-Table -AutoSize | Out-String -Width $columns",
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

function NetshTrace {
    [CmdletBinding()]
    Param(
        [parameter(Mandatory=$true)] [String] $OutDir
    )

    $dir = (Join-Path -Path $OutDir -ChildPath "Netsh")
    New-Item -ItemType directory -Path $dir | Out-Null

    <# Deprecated / DELETEME
        #Figure out how to get this netsh rundown command executing under Powershell with logging...
        $ndiswpp = "{DD7A21E6-A651-46D4-B7C2-66543067B869}"
        $vmswpp  = "{1F387CBC-6818-4530-9DB6-5F1058CD7E86}"
        netsh trace start provider=$vmswpp level=1 keywords=0x00010000 provider=$ndiswpp level=1 keywords=0x02 correlation=disabled report=disabled overwrite=yes tracefile=$dir\NetRundown.etl
        netsh trace stop
    #>

    #$wpp_vswitch  = "{1F387CBC-6818-4530-9DB6-5F1058CD7E86}"
    #$wpp_ndis     = "{DD7A21E6-A651-46D4-B7C2-66543067B869}"

    # The sequence below triggers the ETW providers to dump their internal traces when the session starts.  Thus allowing for capturing a
    # snapshot of their logs/traces.
    #
    # NOTE: This does not cover IFR (in-memory) traces.  More work needed to address said traces.
    $file = "NetRundown.txt"
    [String []] $cmds = "New-NetEventSession    NetRundown -CaptureMode SaveToFile -LocalFilePath $dir\NetRundown.etl",
                        "Add-NetEventProvider   ""{1F387CBC-6818-4530-9DB6-5F1058CD7E86}"" -SessionName NetRundown -Level 1 -MatchAnyKeyword 0x10000",
                        "Add-NetEventProvider   ""{DD7A21E6-A651-46D4-B7C2-66543067B869}"" -SessionName NetRundown -Level 1 -MatchAnyKeyword 0x2",
                        "Start-NetEventSession  NetRundown",
                        "Stop-NetEventSession   NetRundown",
                        "Remove-NetEventSession NetRundown"
    ExecCommands -Trusted -OutDir $dir -File $file -Commands $cmds

    #
    # The ETL file can be converted to text using the following command:
    #    netsh trace convert NetRundown.etl tmfpath=\\winbuilds\release\RS_ONECORE_STACK_SDN_DEV1\15014.1001.170117-1700\amd64fre\symbols.pri\TraceFormat
    #    Specifying a path to the TMF symbols. Output is attached.

    $file = "NetshDump.txt"
    [String []] $cmds = "netsh dump"
    ExecCommands -Trusted -OutDir $dir -File $file -Commands $cmds

    $file = "NetshStatistics.txt"
    [String []] $cmds = "netsh interface ipv4 show icmpstats",
                        "netsh interface ipv4 show ipstats",
                        "netsh interface ipv4 show tcpstats",
                        "netsh interface ipv4 show udpstats",
                        "netsh interface ipv6 show ipstats",
                        "netsh interface ipv6 show tcpstats",
                        "netsh interface ipv6 show udpstats"
    ExecCommands -Trusted -OutDir $dir -File $file -Commands $cmds

    Write-Host "`n"
    Write-Host "Processing..."
    $file = "NetshTrace.txt"
    [String []] $cmds = "netsh -?",
                        "netsh trace show scenarios",
                        "netsh trace show providers",
                        "netsh trace diagnose scenario=NetworkSnapshot mode=Telemetry saveSessionTrace=yes report=yes ReportFile=$dir\Snapshot.cab"
    ExecCommands -Trusted -OutDir $dir -File $file -Commands $cmds
} # NetshTrace()

function OneX {
    [CmdletBinding()]
    Param(
        [parameter(Mandatory=$true)] [String] $OutDir
    )

    $dir = (Join-Path -Path $OutDir -ChildPath "802.1X")
    New-Item -ItemType directory -Path $dir | Out-Null

    $file = "OneX.txt"
    [String []] $cmds = "netsh lan show interface",
                        "netsh lan show profile"
    ExecCommandsAsync -OutDir $dir -File $file -Commands $cmds
} # OneX

function Counters {
    [CmdletBinding()]
    Param(
        [parameter(Mandatory=$true)] [String] $OutDir
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

    $file = "CounterDetail.blg"
    $out  = (Join-Path -Path $dir -ChildPath $file)

    # Get paths for counters of interest
    $pathFilters = @("Hyper-V*", "ICMP*", "*Intel*", "IP*", "*Mellanox*", "Network*", "Physical Network*", "RDMA*", "SMB*", "TCP*", "UDP*","VFP*", "WFP*", "*WinNAT*")
    $counterSets = $(typeperf -q | foreach {($_ -split "\\")[1]} | Sort-Object -Unique)

    $counterPaths = @()
    foreach ($set in $counterSets) {
        foreach ($filter in $pathFilters) {
            if ($set -like $filter) {
                $counterPaths += "`"\$set\*`""
                break
            }
        }
    }

    Write-Host "Querying perf counters..."
    typeperf -f BIN -o $out -sc 10 -si 5 $counterPaths > $null
} # Counters()

function HwErrorReport {
    [CmdletBinding()]
    Param(
        [parameter(Mandatory=$true)] [String] $OutDir
    )

    $dir = $OutDir

    $file = "WER.txt"
    [String []] $paths = "$env:ProgramData\Microsoft\Windows\WER"
    ExecCopyItemsAsync -OutDir $dir -File $file -Paths $paths -Destination $dir
} # HwErrorReport()

function LogsReport {
    [CmdletBinding()]
    Param(
        [parameter(Mandatory=$true)] [String] $OutDir
    )

    $dir = $OutDir

    $file = "WinEVT.txt"
    [String []] $paths = "$env:SystemRoot\System32\winevt"
    ExecCopyItemsAsync -OutDir $dir -File $file -Paths $paths -Destination $dir
} # LogsReport()

function Environment {
    [CmdletBinding()]
    Param(
        [parameter(Mandatory=$true)] [String] $OutDir
    )

    $dir = $OutDir

    $file = "Environment.txt"
    [String []] $cmds = "Get-Variable -Name ""PSVersionTable"" -ValueOnly",
                        "Get-ItemProperty -Path ""HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion""",
                        "date",
                        #"Get-WinEvent -ProviderName eventlog | Where-Object {$_.Id -eq 6005 -or $_.Id -eq 6006}",
                        "Get-CimInstance ""Win32_OperatingSystem"" | select -ExpandProperty ""LastBootUpTime""",
                        "Get-CimInstance ""Win32_Processor"" | Format-List -Property *",
                        "systeminfo"
    ExecCommandsAsync -OutDir $dir -File $file -Commands $cmds

    $file = "Verifier.txt"
    [String []] $cmds = "verifier /querysettings"
    ExecCommandsAsync -OutDir $dir -File $file -Commands $cmds
} # Environment()

function LocalhostDetail {
    [CmdletBinding()]
    Param(
        [parameter(Mandatory=$true)] [String] $OutDir
    )

    $dir = (Join-Path -Path $OutDir -ChildPath "_Localhost") # sort to top
    New-Item -ItemType directory -Path $dir | Out-Null

    VMHostDetail      -OutDir $dir
    ServicesDrivers   -OutDir $dir
    HwErrorReport     -OutDir $dir
    LogsReport        -OutDir $dir
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

    $dir  = (Join-Path -Path $OutDir -ChildPath "Sanity")
    New-Item -ItemType directory -Path $dir | Out-Null

    $file = "Get-ChildItem.txt"
    [String []] $cmds = "Get-ChildItem -Path $OutDir -Exclude $file -Recurse | Get-FileHash | Format-Table -AutoSize | Out-String -Width $columns"
    ExecCommands -OutDir $dir -File $file -Commands $cmds

    $file = "Metadata.txt"
    $out = Join-Path $dir $file
    $paramString = if ($Params.Count -eq 0) {"None`n`n"} else {"`n$($Params | Out-String)"}
    Write-Output "Version: $($MyInvocation.MyCommand.Module.Version)" | Out-File -Encoding ascii -Append $out
    Write-Output "Parameters: $paramString" | Out-File -Encoding ascii -Append $out

    [String []] $cmds = "Get-FileHash -Path $PSCommandPath -Algorithm ""SHA256"" | Format-List -Property * | Out-String -Width $columns"
    ExecCommands -OutDir $dir -File $file -Commands $cmds
} # Sanity()

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

    # Attempt to create working directory, fail gracefully otherwise
    try {
        New-Item -ItemType directory -Path $OutDir -ErrorAction Stop | Out-Null
    } catch {
        throw "Get-NetView : Failed to create directory ""$OutDir"" because " + $error[0]
    }
} # EnvCreate()

function Initialization {
    [CmdletBinding()]
    Param(
        [parameter(Mandatory=$true)] [String] $OutDir,
        [parameter(Mandatory=$true)] [Bool] $ExecInMain
    )

    # Note: Aliases are higher precedent than functions
    if ($ExecInMain) {
        Set-Alias ExecCommandsAsync ExecCommands
    }

    # Remove alias to Write-Host set in $ExecCommands
    Remove-Item alias:Write-CmdLog

    # Setup output folder
    EnvDestroy $OutDir
    EnvCreate $OutDir

    Clear-Host
} # Initialization()

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

    $timestamp = $start | Get-Date -f yyyy.MM.dd_hh.mm.ss

    # Zip output folder
    $outzip = "$Src-$timestamp.zip"
    CreateZip -Src $Src -Out $outzip

    $dirs = (Get-ChildItem $Src -Recurse | Measure-Object -Property length -Sum) # out folder size
    $hash = (Get-FileHash -Path $MyInvocation.PSCommandPath -Algorithm "SHA256").Hash # script hash

    # Display version and file save location
    Write-Host "`n"
    Write-Host "Diagnostics Data:"
    Write-Host "-----------------"
    Write-Host "Get-NetView"
    Write-Host "Version: $($MyInvocation.MyCommand.Module.Version)"
    Write-Host "SHA256:  $(if ($hash) {$hash} else {"N/A"})"
    Write-Host ""
    Write-Host $outzip
    Write-Host "Size:    $("{0:N2} MB" -f ((Get-Item $outzip).Length / 1MB))"
    Write-Host ""
    Write-Host $Src
    Write-Host "Size:    $("{0:N2} MB" -f ($dirs.sum / 1MB))"
    Write-Host "Dirs:    $((Get-ChildItem $Src -Directory -Recurse | Measure-Object).Count)"
    Write-Host "Files:   $((Get-ChildItem $Src -File -Recurse | Measure-Object).Count)"
    Write-Host ""
    Write-Host "Execution Time:"
    Write-Host "---------------"
    $delta = (Get-Date) - $Start
    Write-Host "$($delta.Minutes) Min $($delta.Seconds) Sec"
    Write-Host "`n"
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

.PARAMETER MaxThreads
    Maximum number of simultaneous background tasks, from 1 to 16. Defaults to 5.

.PARAMETER SkipAdminCheck
    If present, the check for administrator privileges will be skipped. Note that less data
    will be collected and the results may be of limited or no use.

.EXAMPLE
    Get-NetView -OutputDirectory ".\"
    Runs Get-NetView and outputs to the current working directory.

.EXAMPLE
    Get-NetView -SkipAdminCheck
    Runs Get-NetView without verifying administrator privileges and outputs to the Desktop.

.NOTES
    Feature Request List
        - Get-WinEvent and system logs: https://technet.microsoft.com/en-us/library/dd367894.aspx?f=255&MSPPError=-2147217396
        - Convert NetSH to NetEvent PS calls.
        - Perf Profile acqusition
        - Remote powershell support
        - Cluster member execution support via remote powershell
        - See this command to get VFs on vSwitch (see text in below functions)
            > Get-NetAdapterSriovVf -SwitchId 2

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

        [parameter(Mandatory=$false)]
        [ValidateRange(1, 16)]
        [Int] $MaxThreads = 5,

        [parameter(Mandatory=$false)]
        [Switch] $SkipAdminCheck = $false
    )

    $start = Get-Date

    # Input Validation
    CheckAdminPrivileges $SkipAdminCheck
    $workDir = NormalizeWorkDir -OutputDirectory $OutputDirectory

    Initialization -OutDir $workDir -ExecInMain ($MaxThreads -eq 1)

    # Start Run
    try {
        CustomModule -OutDir $workDir -Commands $ExtraCommands

        Open-GlobalThreadPool -MaxThreads $MaxThreads

        $threads = if ($true) {

            Start-Thread ${function:NetshTrace} -Params @{OutDir=$workDir}
            Start-Thread ${function:Counters}   -Params @{OutDir=$workDir}

            Environment       -OutDir $workDir
            NetworkSummary    -OutDir $workDir

            LocalhostDetail   -OutDir $workDir

            NetSetupDetail    -OutDir $workDir
            VMSwitchDetail    -OutDir $workDir
            LbfoDetail        -OutDir $workDir
            NativeNicDetail   -OutDir $workDir
            OneX              -OutDir $workDir

            QosDetail         -OutDir $workDir
            SMBDetail         -OutDir $workDir
            NetIp             -OutDir $workDir
            NetNat            -OutDir $workDir
            HNSDetail         -OutDir $workDir
        }

        # Show thread output, and wait for them all to complete
        Show-Threads -Threads $threads

        # Tamper Detection
        Sanity            -OutDir $workDir -Params $PSBoundParameters
    } catch {
        throw $error[0] # try finally obfuscates error
    } finally {
        Close-GlobalThreadPool
    }

    Completion -Src $workDir
} # Get-NetView
