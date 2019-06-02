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

        $command = Get-Command Get-NetView

        It "Should have the Get-NetView function available" {
            $command | Should not BeNullOrEmpty
        }
    }
}
