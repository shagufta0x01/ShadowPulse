# Add System.Web for HTML encoding
Add-Type -AssemblyName System.Web

# Define the folders to list with their paths
$userFolders = @(
    @{ Name = "Downloads"; Path = [System.IO.Path]::Combine($env:USERPROFILE, "Downloads") },
    @{ Name = "Documents"; Path = [System.Environment]::GetFolderPath("MyDocuments") },
    @{ Name = "Desktop"; Path = [System.Environment]::GetFolderPath("Desktop") },
    @{ Name = "Pictures"; Path = [System.Environment]::GetFolderPath("MyPictures") },
    @{ Name = "Videos"; Path = [System.Environment]::GetFolderPath("MyVideos") },
    @{ Name = "Music"; Path = [System.Environment]::GetFolderPath("MyMusic") }
)

# Check for OneDrive paths
$oneDrivePath = Join-Path $env:USERPROFILE "OneDrive"
$useOneDrive = Test-Path $oneDrivePath

if ($useOneDrive) {
    # Update paths for common redirected folders
    foreach ($folder in $userFolders) {
        $oneDriveFolder = Join-Path $oneDrivePath $folder.Name
        if (Test-Path $oneDriveFolder) {
            $folder.Path = $oneDriveFolder
        }
    }
}

# Create a simple array to store folder data
$folderData = @()

# Process each folder
foreach ($folder in $userFolders) {
    $folderName = $folder.Name
    $folderPath = $folder.Path
    
    # Create a folder entry
    $folderEntry = @{
        "name" = $folderName
        "path" = $folderPath
        "items" = @()
        "error" = $null
    }
    
    # Get folder contents if the path exists
    if (Test-Path $folderPath) {
        try {
            # Get only the first 50 items to avoid overwhelming the response
            $items = Get-ChildItem -Path $folderPath -ErrorAction Stop | Select-Object -First 50
            
            # Process each item
            foreach ($item in $items) {
                $itemType = if ($item.PSIsContainer) { "Folder" } else { $item.Extension }
                $itemSize = if ($item.PSIsContainer) { 0 } else { $item.Length }
                
                # Add the item to the folder's items array
                $folderEntry.items += @{
                    "name" = $item.Name
                    "type" = $itemType
                    "size" = $itemSize.ToString()
                    "date" = $item.LastWriteTime.ToString("yyyy-MM-dd HH:mm:ss")
                }
            }
        } catch {
            $folderEntry.error = $_.Exception.Message
        }
    } else {
        $folderEntry.error = "Folder not found"
    }
    
    # Add the folder entry to the result
    $folderData += $folderEntry
}

# Convert to JSON
$jsonOutput = ConvertTo-Json -InputObject $folderData -Depth 5 -Compress
Write-Output $jsonOutput
