[![Build status](https://ci.appveyor.com/api/projects/status/rkdclcowkjlh5uu3?svg=true)](https://ci.appveyor.com/project/MSFTCoreNet/get-netview)
[![downloads](https://img.shields.io/powershellgallery/dt/Get-NetView.svg?label=downloads)](https://www.powershellgallery.com/packages/Get-NetView)

# Description
Get-NetView is a tool that collects local system and network configuration data, to streamline diagnosis of Windows networking issues.

# Installation
## PowerShell Gallery
To install this module from [PowerShell Gallery](https://www.powershellgallery.com/), run:
```PowerShell
Install-Module Get-NetView -SkipPublisherCheck -Force
```
It is also part of `MSFT.Network.Diag`, which can be installed with:
```PowerShell
Install-Module MSFT.Network.Diag
```

## Disconnected or air-gapped systems
If your servers are disconnected or air-gapped, use:
```PowerShell
Save-Module Get-NetView C:\SomeFolderPath
```
Then move the Get-NetView folder (from `C:\SomeFolderPath`) to `C:\Program Files\WindowsPowerShell\Modules` on your target server.

## Direct Execution
This script also supports direct execution:
```PowerShell
Invoke-WebRequest "aka.ms/Get-NetView" -OutFile "Get-NetView.ps1"
.\Get-NetView.ps1 -OutputDir .\
```
If blocked by execution policy:
```PowerShell
Powershell.exe -ExecutionPolicy Bypass -File  .\Get-NetView.ps1 -OutputDir .\
```

# Usage
To begin data collection, simply run:
```PowerShell
Get-NetView
```
The output is saved to `Desktop\msdbg.<username>`, and can be inspected with any file manager. On completion, a .zip file is created for easy sharing.

For additional help and advanced options, run:
```PowerShell
Get-Help Get-NetView
```

This tool is also run automatically by [Get-SDDCDiagnosticInfo](https://github.com/PowerShell/PrivateCloud.DiagnosticInfo).

# :star: More by the Microsoft Core Networking team
Find more from the Core Networking team using the [MSFTNet](https://github.com/topics/msftnet) topic.

To see all modules from the Microsoft Core Networking team, use:
```PowerShell
Find-Module -Tag MSFTNet
```

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
