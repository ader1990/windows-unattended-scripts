$adminusername = ""                       
$adminpassword = ""                               
$LocalAdminUsername = ""                       
$DatabaseName = ""
$setupPath = ""
$domain = ""
function Generate-Windows-Password($passwordLength=15){
$passwordFound = $False
$maxSteps = 100
$password = ""
$assembly = [Reflection.Assembly]::LoadWithPartialName("System.Web")
while ($passwordFound -ne $True -and $maxSteps -ne 0){
$password =  [System.Web.Security.Membership]::GeneratePassword($passwordLength,0)
$i = 0
$upper = [regex]"[A-Z]"
$lower = [regex]"[a-z]"
$number = [regex]"[0-9]"
$special = [regex]"[^\sa-zA-Z0-9]"
If ($upper.Matches($password).count -ge 1){
$i++
}
If ($lower.Matches($password).count -ge 1){
$i++
}
If ($number.Matches($password).count -ge 1){
$i++
}
If ($special.Matches($password).count -ge 1){
$i++
}
If ($i -ge 3){
$passwordFound = $True
}
$maxSteps = $maxSteps - 1
}
if ($passwordFound){return $password}
else.{throw "Failed to generate password."}
}
$iso = Mount-DiskImage -PassThru $setupPath
$isoSetupPath = $setupPath + ":\setup.exe"
Write-Host "Installing Exchange Server 20123"
if (!($env:userdomain -eq $domain))
{
$hostname = hostname
$localAdminPassword = Generate-Windows-Password
$computer = [ADSI]"WinNT://$env:computername"
$localAdmin = $Computer.Create("User", $localAdminUsername)
$localAdmin.SetPassword($localAdminPassword)
$localAdmin.SetInfo()
([ADSI]"WinNT://$env:computername/Administrators,group").Add("WinNT://$env:computername/$localAdminUsername")
Join the Active Directory Domain
netdom join $env:computername /Domain:$domain /UserD:$adminusername /PasswordD:$adminpassword /UserO:$LocalAdminUsername /PasswordO:$localAdminPassword
if (!$?) {
throw "Failed to join Active Directory Domain."
}
$ThisScript = $MyInvocation.MyCommand.Name
$DestinationScript = "C:\Windows\Temp\Exchange_Unattended.ps1"
Copy-Item -Path $ThisScript -Destination $DestinationScript
Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce"  -Name "ConfigureExchange" -Value ("C:\Windows\System32\WindowsPowerShell\v1.0\Powershell.exe -executionPolicy Unrestricted -File $DestinationScript")
Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon" -Name AutoAdminLogon -Value 1
Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon" -Name DefaultUserName -Value $dcusername
Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon" -Name DefaultPassword -Value $dcpassword
Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon" -Name DefaultDomainName -Value $domain
Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon" -Name AutoLogonCount -Value 1 -Type "DWord"
Install-WindowsFeature RSAT-ADDS, AS-HTTP-Activation, Desktop-Experience, NET-Framework-45-Features, RPC-over-HTTP-proxy, RSAT-Clustering, RSAT-Clustering-CmdInterface, Web-Mgmt-Console, WAS-Process-Model, Web-Asp-Net45, Web-Basic-Auth, Web-Client-Auth, Web-Digest-Auth, Web-Dir-Browsing, Web-Dyn-Compression, Web-Http-Errors, Web-Http-Logging, Web-Http-Redirect, Web-Http-Tracing, Web-ISAPI-Ext, Web-ISAPI-Filter, Web-Lgcy-Mgmt-Console, Web-Metabase, Web-Mgmt-Console, Web-Mgmt-Service, Web-Net-Ext45, Web-Request-Monitor, Web-Server, Web-Stat-Compression, Web-Static-Content, Web-Windows-Auth, Web-WMI, Windows-Identity-Foundation
Restart-Computer
}
else
{
$temp = "c:\Windows\Temp"
(new-object System.Net.WebClient).DownloadFile("http://download.microsoft.com/download/0/A/2/0A28BBFA-CBFA-4C03-A739-30CCA5E21659/FilterPack64bit.exe" , "$temp\FilterPack64bit.exe")
Start-Process -Wait "$temp\FilterPack64bit.exe" -ArgumentList "/quiet"
del "$temp\FilterPack64bit.exe"
(new-object System.Net.WebClient).DownloadFile("http://download.microsoft.com/download/A/A/3/AA345161-18B8-45AE-8DC8-DA6387264CB9/filterpack2010sp1-kb2460041-x64-fullfile-en-us.exe" , "$temp\filterpack2010sp1-kb2460041-x64-fullfile-en-us.exe")
Start-Process -Wait "$temp\filterpack2010sp1-kb2460041-x64-fullfile-en-us.exe" -ArgumentList "/quiet"
del "$temp\filterpack2010sp1-kb2460041-x64-fullfile-en-us.exe"
(new-object System.Net.WebClient).DownloadFile("http://download.microsoft.com/download/2/C/4/2C47A5C1-A1F3-4843-B9FE-84C0032C61EC/UcmaRuntimeSetup.exe" , "$temp\UcmaRuntimeSetup.exe")
Start-Process -Wait "$temp\UcmaRuntimeSetup.exe" -ArgumentList "/quiet"
del "$temp\UcmaRuntimeSetup.exe"
Start-Process  -Wait -FilePath $isoSetupPath -ArgumentList "/IAcceptExchangeServerLicenseTerms /ps"
Start-Process  -Wait -FilePath $isoSetupPath -ArgumentList "/IAcceptExchangeServerLicenseTerms /p /on:$domain"
Start-Process  -Wait -FilePath $isoSetupPath -ArgumentList "/IAcceptExchangeServerLicenseTerms /pd"
Start-Process  -Wait -FilePath $isoSetupPath -ArgumentList "/IAcceptExchangeServerLicenseTerms /mode:install /InstallWindowsComponents /r:mb,ca /MdbName:$DatabaseName"
Remove-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce"  -Name "ConfigureExchange"
ADD-PSSnapin Microsoft.Exchange.Management.PowerShell.SnapIn
New-SendConnector -Internet -Name "Default Send Connector" -AddressSpaces "*"
if (!$?) {
throw "MS Exchange Server 2013 installation failed."
}
}