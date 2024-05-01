function Connect-YcSPOSite
{
    param (
        [Parameter(Mandatory=$false)] [string]$siteURL
    )

    try {
        $message = "Connect-SPOSite @ "+(Get-Date)+": Connecting to SPO Site '"+$siteURL+"' using Connect-PnPOnline cmdlet..."
        Write-Host $message

        $connection = Connect-PnPOnline -Url $siteURL -UseWebLogin

        $message = "Connect-SPOSite @ "+(Get-Date)+": Successfully connected to SPO Site' "+$siteURL+" '"
        Write-Host $message -ForegroundColor Green
    }


    catch {
        $message = "Connect-SPOSite @ "+(Get-Date)+": Could NOT connect to SPO Site '"+$siteURL+"'! Details: "+$_.Exception.Message
        Write-Host $message -ForegroundColor Red
        Log-Event -message $message
    }


}

function Get-YcSPOChildItemsFromURL
{
    param (
        [Parameter(Mandatory=$true)] [string]$srcFolderUrl
    )

    $message = "Get-SPOChildItemsFromURL @ "+(Get-Date)+": srcFolderUrl is: '"+$srcFolderUrl+"'"
    Write-Verbose $message

    # Get all items from the source folder
    $srcItems = Get-PnPFolderItem -FolderSiteRelativeUrl $srcFolderUrl 

    $message = "Get-SPOChildItemsFromURL @ "+(Get-Date)+": Folder '"+$srcFolderUrl+"' has these child items:"
    Write-Host $message

    foreach ($item in $srcItems) {
        $message = "- '"+$item.name+"'"
        Write-Host $message
        }

    Write-Host "--------------------------------------------------------------------------------------------------------------------------------------------------------------"

    $message = "Get-SPOChildItemsFromURL @ "+(Get-Date)+": Total count of child items in this folder: "+$srcItems.Count
    Write-Verbose $message

    return $srcItems

}

function Copy-YcSPOFile
{
   param (
        [Parameter(Mandatory=$true)] $srcItem,
        [Parameter(Mandatory=$true)] [string]$dstFolderUrl,
        [Parameter(Mandatory=$true)] [string]$newFileName
    )

    try {
        Copy-PnPFile -SourceUrl $srcItem.ServerRelativeUrl -TargetUrl "$dstFolderUrl/$newFileName" -Force -OverwriteIfAlreadyExists -ErrorAction Stop
        $global:FileCopiedToDestinationCount++

        $message = "Copy-SPOFile @ "+(Get-Date)+": Successfully copied '"+$srcItem.name+"' to '"+$dstFolderUrl+"/"+$newFileName+"'"
        Log-Event -message $message
        Write-Host $message -ForegroundColor Green
    }
    catch {
        $message = "Copy-SPOFile @ "+(Get-Date)+": Error: "+$_.Exception.Message+" during copying '"+$srcItem.name+"' to '"+$dstFolderUrl+"/"+$newFileName+"'"
        Log-Event -message $message -eventId 1000 -entryType "Error"
        Write-Host $message -ForegroundColor red
    }
}

function Check-YcSPOFileExistsInDestination
{
   param (
        [Parameter(Mandatory=$true)] $srcItem,
        [Parameter(Mandatory=$true)] [string]$dstFolderUrl
    )

   # Get the destination file
    $dstFile = Get-PnPFile -Url "$dstFolderUrl/$($srcItem.Name)" -ErrorAction SilentlyContinue

    # Define new name for the source file
    $newFileName = $srcItem.Name

    # Check if the file exists in the destination
    if($null -ne $dstFile) {

        $message = "Check-SPOFileExistsInDestination @ "+(Get-Date)+": Child item '"+$srcitem.name+"' exists in destination. Appending duplicate ending."
        Log-Event -message $message
        Write-Host $message

        # Append "_duplicate" to the new file name
        $newFileName = $srcItem.Name -replace '\.', '_duplicate.'
    }

    return $newFileName

}

function Check-YcSPOFolderExistsInDestination
{
   param (
        [Parameter(Mandatory=$true)] $srcItem,
        [Parameter(Mandatory=$true)] [string]$dstFolderUrl
    )

    $message = "Check-SPOFolderExistsInDestination @ "+(Get-Date)+": Checking if the folder '"+$srcItem.name+"' already exists in the destination..."
    Write-Verbose $message

    # Check if the folder already exists in the destination
    $dstFolderExists = Get-PnPFolder -Url "$dstFolderUrl/$($srcItem.Name)" -ErrorAction SilentlyContinue


    if($null -ne $dstFolderExists) {
        $message = "Check-SPOFolderExistsInDestination @ "+(Get-Date)+": Folder '"+$srcItem.Name+"' already exists in '"+$dstFolderUrl+"'. No need to create it."
        Log-Event -message $message
        Write-Host $message -ForegroundColor Yellow
                   
        $global:FolderDuplicates++
        $FolderExists = $true
    }

    else {
        $message = "Check-SPOFolderExistsInDestination @ "+(Get-Date)+": Folder '"+$srcItem.Name+"' does NOT exist in "+$dstFolderUrl
        Log-Event -message $message 
        Write-Host $message -ForegroundColor Magenta

        $global:FolderCreatedInDestinationCount++
        $FolderExists = $false
    }

    return $FolderExists

}

function New-YcSPOFolderInDestination
{
   param (
        [Parameter(Mandatory=$true)] $srcItem,
        [Parameter(Mandatory=$true)] [string]$dstFolderUrl
    )
        # Create the destination folder
        $message = "Create-SPOFolderInDestination @ "+(Get-Date)+": Creating folder '"+$srcItem.Name+"' in '"+$dstFolderUrl+"'"
        Log-Event -message $message
        Write-Host $message -ForegroundColor Magenta

        try {

            $dstFolder = Add-PnPFolder -Name $srcItem.Name -Folder $dstFolderUrl -ErrorAction Stop
                        
            $message = "Create-SPOFolderInDestination @ "+(Get-Date)+": Successfully created folder '"+$srcItem.Name+"' in '"+$dstFolderUrl+"'"
            Log-Event -message $message
            Write-Host $message -ForegroundColor Green

        }
        catch {

            $message = "Copy-SPOFile @ "+(Get-Date)+": Error: "+$_.Exception.Message+" during creation of folder '"+$srcItem.name+"' in '"+$dstFolderUrl+"'"
            Log-Event -message $message -eventId 1000 -entryType "Error"
            Write-Host $message -ForegroundColor red
        }
}

Function Check-YcSPOFolderHasNestedItems
{
   param (
        [Parameter(Mandatory=$true)] $srcItem,
        [Parameter(Mandatory=$true)] [string]$srcFolderURL
    )

    $srcFolderUrlForChild = $srcFolderUrl+"/"+$srcItem.Name
    $nestedItems = Get-PnPFolderItem -FolderSiteRelativeUrl $srcFolderUrlForChild


    if ($nestedItems.Count -gt 0) {

        $HasNestedItems = $true

        $message = "Check-SPOFolderHasNestedItems @ "+(Get-Date)+": Folder '"+$srcItem.name+"' has " +$nestedItems.Count+ " nested items."
        Write-Verbose $message
            
    }

    else {

        $message = "Check-SPOFolderHasNestedItems @ "+(Get-Date)+": Folder '"+$srcItem.name+"' has no nested items."
        Write-Verbose $message 

        $HasNestedItems = $false
    }


    return $HasNestedItems

}

function Merge-YcSPOFolders  {

   param (
        [Parameter(Mandatory=$true)] $srcFolderUrl,
        [Parameter(Mandatory=$true)] [string]$dstFolderURL
    )

    $srcItems = Get-SPOChildItemsFromURL -srcFolderUrl $srcFolderUrl

    # Process each item
    foreach($srcItem in $srcItems) {

        $message = "Process-SPOMergeItems @ "+(Get-Date)+": Processing child Item: '"+$srcItem.name+"' from folder '"+$srcFolderUrl+"'"
        Write-Verbose $message


        # Check if the item is a file
        if(($srcItem.GetType()).Name -eq "File") {

            $message = "Process-SPOMergeItems @ "+(Get-Date)+": Child item '"+$srcItem.name+"' is a file."
            Write-Verbose $message

            $newFileName = Check-SPOFileExistsInDestination -srcItem $srcItem -dstFolderUrl $dstFolderUrl

            # Copy the file to the destination folder
            $message =  "Process-SPOMergeItems @ "+(Get-Date)+": Copying child item '"+$srcItem.name+"' from source folder '"+$srcFolderUrl+"' to '"+$dstFolderUrl+"'"
            Write-Verbose $message

            Copy-SPOFile -srcItem $srcItem -dstFolderUrl $dstFolderUrl -newFileName $newFileName
        }
        # Check if the item is a folder
        elseif(($srcItem.GetType()).Name -eq "Folder") {

           $message = "Process-SPOMergeItems @ "+(Get-Date)+": Child item '"+$srcItem.name+"' is a Folder."
           Write-Verbose $message

           $FolderExists = Check-SPOFolderExistsInDestination -srcItem $srcItem -dstFolderUrl $dstFolderUrl

           if ($FolderExists -eq $true){
      
           
           }
           else{
             Create-SPOFolderInDestination -srcItem $srcItem -dstFolderUrl $dstFolderUrl
           }


           $FolderHasNestedItems = Check-SPOFolderHasNestedItems -srcItem $srcItem -srcFolder $srcFolderUrl

           if ($FolderHasNestedItems -eq $true) {
                # Copy the items in the subfolder
                $message = "Process-SPOMergeItems @ "+(Get-Date)+": Folder '"+$srcItem.name+"' has " +$nestedItems.Count+ " nested items. Starting check and if need copy of nested Items of '"+$srcItem.name+"' to '"+$dstFolderUrl+"' ..."
                Write-Verbose $message

                Process-SPOMergeItems "$srcFolderUrl/$($srcItem.Name)" "$dstFolderUrl/$($srcItem.Name)"
                
                $message = "Merge-SPOFolders @ "+(Get-Date)+": Finished copying "+$global:FileCopiedToDestinationCount+" nested files (of which where "+$global:FileDuplicates+" duplicated files) and "+$global:FolderCreatedInDestinationCount+ " folders ("+$global:FolderDuplicates+ " were skipped because they already existed) from folder '"+$srcItem.name+"' from source '"+$srcFolderUrl+"' to destination '"+$dstFolderUrl+"'"
                Write-Verbose $message 
            }
            else {
                $message = "Merge-SPOFolders @ "+(Get-Date)+": Folder '"+$srcItem.name+"' has no nested items."
                Write-Verbose $message
            }
        }
    }
}

function Start-YcSPOFolderMerge
{
    param (
        [Parameter(Mandatory=$true)] [array]$srcFolders,
        [Parameter(Mandatory=$true)][string]$dstFolder
    )

    $message = "Merge-SPOFolders @ "+(Get-Date)+": Defined Sourcefolders to merge from are: '"+$srcFolders+"'"
    Log-Event -message $message
    Write-Host $message


    $message = "Merge-SPOFolders @ "+(Get-Date)+": Defined Destination folders to merge in are: '"+$dstFolder+"'"
    Log-Event -message $message
    Write-Host $message

    # Process each source folder
    foreach($srcFolder in $srcFolders) {

        Write-Host "--------------------------------------------------------------------------------------------------------------------------------------------------------------"

        $message = "Merge-SPOFolders @ "+(Get-Date)+": Going trough folder: '"+$srcFolder+"'"
        Write-Verbose $message

        Merge-SPFolders $srcFolder $dstFolder
    }

}
