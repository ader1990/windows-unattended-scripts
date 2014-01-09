
$adminusername = "Administrator"
$adminpassword = "FontoMarco1982!"
$domain = "cloudbase"
$domainsuffix = "local"
$dnsip="10.7.51.202"

$global:RegRunKey ="HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run"
$global:RegVarKey = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Unattended"
$global:powershell = (Join-Path $env:windir "system32\WindowsPowerShell\v1.0\powershell.exe")

$secpasswd = ConvertTo-SecureString $adminpassword -AsPlainText -Force
$creds = New-Object System.Management.Automation.PSCredential ($adminusername , $secpasswd)

$wmi = Get-WmiObject win32_networkadapterconfiguration -filter "ipenabled = 'true'"
$wmi.SetDNSServerSearchOrder($dnsip)

Add-Computer -Credential $creds -DomainName $domain"."$domainsuffix -f


