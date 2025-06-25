#Test if Remediation is applicable
#Region Applicablitity
$CurrentOSInfo = Get-Item -Path 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion'
$Build = $CurrentOSInfo.GetValue('CurrentBuild')
[int]$UBR = $CurrentOSInfo.GetValue('UBR')

#April 2024 UBRs
$AprilPatch = @('19044.4291','19045.4291','22631.3447','22621.3447','22000.2899', '26100.1150')
$MatchedPatch = $AprilPatch | Where-Object {$_ -match $Build}
[int]$MatchedUBR = $MatchedPatch.split(".")[1]

if ($UBR -ge $MatchedUBR){
    $OSSupported = $true
}
else {
    $OSSupported = $false
}
#endregionApplicablitity

if( !$OSSupported ) {
    Write-Output "OS not supported"
    exit 1
}

if( [System.Text.Encoding]::ASCII.GetString((Get-SecureBootUEFI db).bytes) -match 'Windows UEFI CA 2023' ){
    Write-Output "UEFI CA 2023 Certificate is installed"

    #Test: Updating the boot manager
    $Volume = Get-Volume | Where-Object {$_.FileSystemType -eq "FAT32" -and $_.DriveType -eq "Fixed"}
    $SystemDisk = Get-Disk | Where-Object {$_.IsSystem -eq $true}
    $SystemPartition = Get-Partition -DiskNumber $SystemDisk.DiskNumber | Where-Object {$_.IsSystem -eq $true}  
    $SystemVolume = $Volume | Where-Object {$_.UniqueId -match $SystemPartition.Guid}
    $FilePath = "$($SystemVolume.Path)\EFI\Microsoft\Boot\bootmgfw.efi"
    $CertCollection = New-Object System.Security.Cryptography.X509Certificates.X509Certificate2Collection
    $CertCollection.Import($FilePath, $null, 'DefaultKeySet')
    if ($CertCollection.Subject -like "*Windows UEFI CA 2023*") {
        Write-Output "New Bootmanager is installed"

        #Revoke 2011 certificate
        if( [System.Text.Encoding]::ASCII.GetString((Get-SecureBootUEFI dbx).bytes) -match 'Microsoft Windows Production PCA 2011' ){
            Write-Output "Success: PCA 2011 Certificate is already revoked"
        } else {
            Write-Output "PCA 2011 Certificate is not yet revoked"
            reg add HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Secureboot /v AvailableUpdates /t REG_DWORD /d 0x80 /f
            Start-ScheduledTask -TaskName "\Microsoft\Windows\PI\Secure-Boot-Update"
        }    
    } else {
        Write-Output "Old Bootmanager is still installed"
        reg add HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Secureboot /v AvailableUpdates /t REG_DWORD /d 0x100 /f
        Start-ScheduledTask -TaskName "\Microsoft\Windows\PI\Secure-Boot-Update"
    }

} else {
    Write-Output "UEFI CA 2023 Certificate is not installed"
    reg add HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Secureboot /v AvailableUpdates /t REG_DWORD /d 0x40 /f
    Start-ScheduledTask -TaskName "\Microsoft\Windows\PI\Secure-Boot-Update"
}
