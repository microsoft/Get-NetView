[![Build status](https://ci.appveyor.com/api/projects/status/rkdclcowkjlh5uu3?svg=true)](https://ci.appveyor.com/project/MSFTCoreNet/get-netview)
[![downloads](https://img.shields.io/powershellgallery/dt/Get-NetView.svg?label=downloads)](https://www.powershellgallery.com/packages/Get-NetView)

# Description

Get-NetView is a tool used to simplify the collection of network configuration information for diagnosis of networking issues on Windows.

## :star: More by the Microsoft Core Networking team

Find more from the Core Networking team using the [MSFTNet](https://github.com/topics/msftnet) topic

# Installation

## MSFT.Network.Diag

This module is part of MSFT.Network.Diag which can be installed using this command:

```Install-Module MSFT.Network.Diag```

## Direct Installation from PowerShell Gallery

Or install this module individually using this command:

```Install-Module Get-NetView```

## Installation on disconnected/air-gapped systems

If your servers are disconnected/air-gapped, use these commands:

```Save-Module Get-NetView C:\SomeFolderPath```

Move the Get-NetView folder (from c:\SomeFolderPath) to C:\Program Files\WindowsPowerShell\Modules on your target server, then run:

```Get-NetView```

## To find more from the Networking Team

To see all modules from the Microsoft Core Networking team, please use:

```Find-Module -Tag MSFTNet```

## Direct Execution
The legacy method of direct execution is still supported:
```PowerShell
Invoke-WebRequest "aka.ms/Get-NetView" -OutFile "Get-NetView.ps1"
.\Get-NetView.ps1 -OutputDir .\
```
If blocked by execution policy:
```PowerShell
Powershell.exe -ExecutionPolicy Bypass -File  .\Get-NetView.ps1 -OutputDir .\
```

## Usage

For help and options when running this command directly, use:
```PowerShell
Get-Help Get-NetView
```

This tool is also run automatically by [Get-SDDCDiagnosticInfo](https://github.com/PowerShell/PrivateCloud.DiagnosticInfo).

# Contributing

This project welcomes contributions and suggestions.  Most contributions require you to agree to a
Contributor License Agreement (CLA) declaring that you have the right to, and actually do, grant us
the rights to use your contribution. For details, visit https://cla.microsoft.com.

When you submit a pull request, a CLA-bot will automatically determine whether you need to provide
a CLA and decorate the PR appropriately (e.g., label, comment). Simply follow the instructions
provided by the bot. You will only need to do this once across all repos using our CLA.

This project has adopted the [Microsoft Open Source Code of Conduct](https://opensource.microsoft.com/codeofconduct/).
For more information see the [Code of Conduct FAQ](https://opensource.microsoft.com/codeofconduct/faq/) or
contact [opencode@microsoft.com](mailto:opencode@microsoft.com) with any additional questions or comments.
