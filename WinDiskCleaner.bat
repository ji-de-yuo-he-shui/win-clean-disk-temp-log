@set cbsclear_args=%* & set cbsclear_self=%~f0& powershell -c "(gc \"%~f0\") -replace '@set cbsclear_args.*','#' | Write-Host" | powershell -c - & goto :eof


#把σ https://github.com/justdanpo/JustCleaner/blob/master/JustCleaner.bat
#把σ https://github.com/felipe199903/Win10-Maintenance/blob/master/maintenance.bat
Write-Host "Windows秨﹍睲瞶"

function GetAdminRights {
  $Identity = [System.Security.Principal.WindowsIdentity]::GetCurrent()
  $Principal = New-Object System.Security.Principal.WindowsPrincipal($Identity)
  if (!($Principal.IsInRole([System.Security.Principal.WindowsBuiltInRole]::Administrator)))
  {
    if ((Get-ItemProperty HKLM:\Software\Microsoft\Windows\CurrentVersion\Policies\System).EnableLua -ne 0)
    {
      Start-Process "$env:ComSpec" -verb runas -argumentlist "/c ""$env:cbsclear_self"" $env:cbsclear_args"
    }
    else
    {
      Write-Error "You must be administrator to run this script"
    }
    exit
  }
}

GetAdminRights

# check $VerbosePreference variable, and turns on
{ if ( $VerbosePreference -ne 'SilentlyContinue' )
{ Write-Host " $Message" -ForegroundColor 'Yellow' } }

$VerbosePreference = "Continue"
$DaysToDelete = 0
$LogDate = get-date -format "MM-d-yy-HH"
$objShell = New-Object -ComObject Shell.Application 
$objFolder = $objShell.Namespace(0xA)
$ErrorActionPreference = "silentlycontinue"

## Deletes the contents of windows Logs.
Get-ChildItem "$env:windir\Logs\*" -Recurse -Force -Verbose -ErrorAction SilentlyContinue |
Where-Object { ($_.CreationTime -lt $(Get-Date).AddDays(-$DaysToDelete)) } |
remove-item -force -Verbose -recurse -ErrorAction SilentlyContinue
## The Contents of Windows Logs have been removed successfully!

## Deletes the contents of windows software distribution.
Get-ChildItem "$env:windir\SoftwareDistribution\*" -Recurse -Force -Verbose -ErrorAction SilentlyContinue |
Where-Object { ($_.CreationTime -lt $(Get-Date).AddDays(-$DaysToDelete)) } |
remove-item -force -Verbose -recurse -ErrorAction SilentlyContinue
## The Contents of Windows SoftwareDistribution have been removed successfully!

## Deletes the contents of Installer PatchCache distribution.
Get-ChildItem "$env:windir\Installer\$PatchCache$\*" -Recurse -Force -Verbose -ErrorAction SilentlyContinue |
Where-Object { ($_.CreationTime -lt $(Get-Date).AddDays(-$DaysToDelete)) } |
remove-item -force -Verbose -recurse -ErrorAction SilentlyContinue
## The Contents of Windows Installer PatchCache have been removed successfully!

## Deletes the contents of the Windows Temp folder.
Get-ChildItem "$env:windir\Temp\*" -Recurse -Force -Verbose -ErrorAction SilentlyContinue |
Where-Object { ($_.CreationTime -lt $(Get-Date).AddDays(-$DaysToDelete)) } |
remove-item -force -Verbose -recurse -ErrorAction SilentlyContinue
## The Contents of Windows Temp have been removed successfully!

## Deletes the contents of the Windows Downloaded Installations folder.
Get-ChildItem "$env:windir\Downloaded Installations\*" -Recurse -Force -Verbose -ErrorAction SilentlyContinue |
Where-Object { ($_.CreationTime -lt $(Get-Date).AddDays(-$DaysToDelete)) } |
remove-item -force -Verbose -recurse -ErrorAction SilentlyContinue
## The Contents of Windows Downloaded Installations have been removed successfully!

## Deletes the contents of the Windows Installer folder.
Get-ChildItem "$env:windir\Installer\`$PatchCache`$\Managed\*" -Recurse -Force -Verbose -ErrorAction SilentlyContinue |
Where-Object { ($_.CreationTime -lt $(Get-Date).AddDays(-$DaysToDelete)) } |
remove-item -force -Verbose -recurse -ErrorAction SilentlyContinue
## The Contents of Windows Installer Cache have been removed successfully!
             
## Delets all files and folders in user's Temp folder. 
Get-ChildItem "$env:HOMEDRIVE\users\*\AppData\Local\Temp\*" -Recurse -Force -ErrorAction SilentlyContinue |
Where-Object { ($_.CreationTime -lt $(Get-Date).AddDays(-$DaysToDelete))} |
remove-item -force -Verbose -recurse -ErrorAction SilentlyContinue
## The contents of C:\users\$env:USERNAME\AppData\Local\Temp\ have been removed successfully!
                    
## Remove all files and folders in user's Temporary Internet Files. 
Get-ChildItem "$env:HOMEDRIVE\users\*\AppData\Local\Microsoft\Windows\Temporary Internet Files\*" `
-Recurse -Force -Verbose -ErrorAction SilentlyContinue |
Where-Object {($_.CreationTime -le $(Get-Date).AddDays(-$DaysToDelete))} |
remove-item -force -recurse -ErrorAction SilentlyContinue
## All Temporary Internet Files have been removed successfully!
                    
## Cleans IIS Logs if applicable.
Get-ChildItem "$env:HOMEDRIVE\inetpub\logs\LogFiles\*" -Recurse -Force -ErrorAction SilentlyContinue |
Where-Object { ($_.CreationTime -le $(Get-Date).AddDays(-60)) } |
Remove-Item -Force -Verbose -Recurse -ErrorAction SilentlyContinue
## All IIS Logfiles over x days old have been removed Successfully!

# 合盒睲瞶 --------------------------------------------------------------
cleanmgr.exe /cDrive

# 戈方Μ表睲瞶 --------------------------------------------------------------
$objShell = New-Object -ComObject Shell.Application 
$objFolder = $objShell.Namespace(0xA)
$objFolder.items() | ForEach-Object { Remove-Item $_.path -ErrorAction Ignore -Force -Recurse }

# 陪ボ合盒丁 --------------------------------------------------------------
$After =  Get-WmiObject Win32_LogicalDisk | Where-Object { $_.DriveType -eq "3" } | Select-Object SystemName,
@{ Name = "Drive" ; Expression = { ( $_.DeviceID ) } },
@{ Name = "Size (GB)" ; Expression = {"{0:N1}" -f( $_.Size / 1gb)}},
@{ Name = "FreeSpace (GB)" ; Expression = {"{0:N1}" -f( $_.Freespace / 1gb ) } },
@{ Name = "PercentFree" ; Expression = {"{0:P1}" -f( $_.FreeSpace / $_.Size ) } } |
Format-Table -AutoSize | Out-String
Write-Verbose "After: $After"

Write-Host "Windows睲瞶Ч拨"
Write-Host -NoNewLine "Press any key to continue..."
$null = $Host.UI.RawUI.ReadKey("NoEcho,IncludeKeyDown")
