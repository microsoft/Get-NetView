$DataFile   = Import-PowerShellDataFile .\$($env:repoName).psd1 -ErrorAction SilentlyContinue
$TestModule = Test-ModuleManifest       .\$($env:repoName).psd1 -ErrorAction SilentlyContinue

Describe "$($env:repoName)-Manifest" {
    Context Validation {
        It "[Import-PowerShellDataFile] - $($env:repoName).psd1 is a valid PowerShell Data File" {
            $DataFile | Should Not BeNullOrEmpty
        }

        It "[Test-ModuleManifest] - $($env:repoName).psd1 should pass the basic test" {
            $TestModule | Should Not BeNullOrEmpty
        }

        It "Should specify 3 modules" {
            ($TestModule).RequiredModules.Count | Should BeGreaterThan 2
        }

        'DataCenterBridging', 'VMNetworkAdapter', 'SoftwareTimestamping' | ForEach-Object {
            It "Should contain the $_ Module" {
                $_ -in ($TestModule).RequiredModules.Name | Should be $true
            }

            Remove-Variable $module -ErrorAction SilentlyContinue
            $module = Find-Module -Name $_ -ErrorAction SilentlyContinue

            It "The $_ module should be available in the PowerShell gallery" {
                $module | Should not BeNullOrEmpty
            }
        }
    }
}
