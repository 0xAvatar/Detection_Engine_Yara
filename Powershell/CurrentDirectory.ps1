# PowerShell script to get the full paths of all directories opened in File Explorer
Write-Host "Starting PowerShell script..."

Add-Type -Namespace Util -Name WinApi -MemberDefinition @'
    [DllImport("user32.dll")]
    public static extern IntPtr FindWindow(string lpClassName, string lpWindowName);
'@

# Function to get the full path of a folder from its HWND
function GetFolderPath($folderHWND) {
    $folderWin = (New-Object -ComObject Shell.Application).Windows() |
        Where-Object { $_.hwnd -eq $folderHWND }

    if ($folderWin) {
        $folderPath = $folderWin.Document.Folder.Self.Path
        Write-Host "Directory Path: $folderPath"
    } else {
        Write-Host "Failed to get directory path."
    }
}

# Get all File Explorer windows
$fileExplorerWindows = (New-Object -ComObject Shell.Application).Windows() | Where-Object { $_.Name -eq "File Explorer" }

# Output the full paths to the console
foreach ($explorerWindow in $fileExplorerWindows) {
    GetFolderPath $explorerWindow.hwnd
}

Write-Host "PowerShell script completed."
