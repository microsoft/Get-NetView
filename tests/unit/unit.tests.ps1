Describe "$($env:repoName)-Manifest" {
    Context Validation {
        It "[Import-PowerShellDataFile] - $($env:repoName).psd1 is a valid PowerShell Data File" {
            $DataFile = Import-PowerShellDataFile .\$($env:repoName).psd1
            $DataFile | Should -Not -BeNullOrEmpty
        }

        It "[Test-ModuleManifest] - $($env:repoName).psd1 should pass the basic test" {
            $TestModule = Test-ModuleManifest .\$($env:repoName).psd1
            $TestModule | Should -Not -BeNullOrEmpty
        }

        It "Should have the $($env:repoName) function available" {
            Import-Module .\$($env:repoName).psd1
            $command = Get-Command $($env:repoName)
            $command | Should -Not -BeNullOrEmpty
        }
    }
}
