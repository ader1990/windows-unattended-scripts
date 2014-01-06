param($Step="Join",
$domain = "FONTOHOME",
$domainsuffix ="LOCAL",
$dcusername = "administrator",
$dcpassword = "FontoMarco1982!",
$setupPath = "d:\setup.exe")

$global:started = $FALSE
$global:startingStep = $Step
$global:restartKey = "Restart-And-Resume"
$global:RegRunKey ="HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run"
$global:powershell = (Join-Path $env:windir "system32\WindowsPowerShell\v1.0\powershell.exe")


function Should-Run-Step([string] $prospectStep) 
{
	if ($global:startingStep -eq $prospectStep -or $global:started) {
		$global:started = $TRUE
	}
	return $global:started
}

function Wait-For-Keypress([string] $message, [bool] $shouldExit=$FALSE) 
{
	Write-Host "$message" -foregroundcolor yellow
	$key = $host.UI.RawUI.ReadKey("NoEcho,IncludeKeyDown")
	if ($shouldExit) {
		exit
	}
}

function Test-Key([string] $path, [string] $key)
{
    return ((Test-Path $path) -and ((Get-Key $path $key) -ne $null))   
}

function Remove-Key([string] $path, [string] $key)
{
	Remove-ItemProperty -path $path -name $key
}

function Set-Key([string] $path, [string] $key, [string] $value) 
{
	Set-ItemProperty -path $path -name $key -value $value
}

function Get-Key([string] $path, [string] $key) 
{
	return (Get-ItemProperty $path).$key
}

function Restart-And-Run([string] $key, [string] $run) 
{
	Set-Key $global:RegRunKey $key $run
	Restart-Computer
	exit
} 

function Clear-Any-Restart([string] $key=$global:restartKey) 
{
	if (Test-Key $global:RegRunKey $key) {
		Remove-Key $global:RegRunKey $key
	}
}

function Restart-And-Resume([string] $script, [string] $step) 
{
	Restart-And-Run $global:restartKey "$global:powershell $script -Step $step"
}

function DependencyInstall($url, $filename) {
    Write-Host "Downloading and installing: $filename"
        (new-object System.Net.WebClient).DownloadFile($url, "$pwd\$filename")
        Start-Process -Wait $filename -ArgumentList "/quiet"
        del $filename
}


$script = $myInvocation.MyCommand.Definition
Clear-Any-Restart
if (Should-Run-Step "Join") 
{
    $completeusername = $domain
    $secpasswd = ConvertTo-SecureString $dcpassword -AsPlainText -Force
    $creds = New-Object System.Management.Automation.PSCredential ("administrator" , $secpasswd)
	Write-Host "Joining Active Directory"
	New-ItemProperty -Path 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon' -Name AutoAdminLogon -Value 1 
    New-ItemProperty -Path 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon' -Name DefaultUserName -Value $dcusername
    New-ItemProperty -Path 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon' -Name DefaultPassword -Value $dcpassword
    New-ItemProperty -Path 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon' -Name DefaultDomainName -Value $domain
    Set-ItemProperty -Path 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon' -Name DefaultUserName -Value $dcusername
    Set-ItemProperty -Path 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon' -Name DefaultPassword -Value $dcpassword
    Set-ItemProperty -Path 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon' -Name DefaultDomainName -Value $domain
    add-computer -Credential $creds -DomainName $domain
    Write-Host "System will be rebooting right now"
	Restart-And-Resume $script "Features"
}

if (Should-Run-Step "Features") 
{
	Write-Host "Installing Windows Features"
	Install-WindowsFeature RSAT-ADDS, AS-HTTP-Activation, Desktop-Experience, NET-Framework-45-Features, RPC-over-HTTP-proxy, RSAT-Clustering, RSAT-Clustering-CmdInterface, Web-Mgmt-Console, WAS-Process-Model, Web-Asp-Net45, Web-Basic-Auth, Web-Client-Auth, Web-Digest-Auth, Web-Dir-Browsing, Web-Dyn-Compression, Web-Http-Errors, Web-Http-Logging, Web-Http-Redirect, Web-Http-Tracing, Web-ISAPI-Ext, Web-ISAPI-Filter, Web-Lgcy-Mgmt-Console, Web-Metabase, Web-Mgmt-Console, Web-Mgmt-Service, Web-Net-Ext45, Web-Request-Monitor, Web-Server, Web-Stat-Compression, Web-Static-Content, Web-Windows-Auth, Web-WMI, Windows-Identity-Foundation
	Write-Host "System will be rebooting right now"
	Restart-And-Resume $script "Prerequisites"
}

if (Should-Run-Step "Prerequisites") 
{
	Write-Host "Installing Exchange 2013 Prerequisites"
	DependencyInstall "http://download.microsoft.com/download/0/A/2/0A28BBFA-CBFA-4C03-A739-30CCA5E21659/FilterPack64bit.exe" "FilterPack64bit.exe"	
	DependencyInstall "http://download.microsoft.com/download/A/A/3/AA345161-18B8-45AE-8DC8-DA6387264CB9/filterpack2010sp1-kb2460041-x64-fullfile-en-us.exe" "filterpack2010sp1-kb2460041-x64-fullfile-en-us.exe"
	DependencyInstall "http://download.microsoft.com/download/2/C/4/2C47A5C1-A1F3-4843-B9FE-84C0032C61EC/UcmaRuntimeSetup.exe" "UcmaRuntimeSetup.exe"
	Write-Host "System will be rebooting right now"
	Restart-And-Resume $script "Install"
}

if (Should-Run-Step "Install") 
{
	Write-Host "Installing Exchange 2013"
	Start-Process -Wait -FilePath $setupPath -ArgumentList "/IAcceptExchangeServerLicenseTerms /ps"
	Start-Process -Wait -FilePath $setupPath -ArgumentList "/IAcceptExchangeServerLicenseTerms /p /on:$env:USERDOMAIN"
	Start-Process -Wait -FilePath $setupPath -ArgumentList "/IAcceptExchangeServerLicenseTerms /pd"
	Start-Process -Wait -FilePath $setupPath -ArgumentList "/IAcceptExchangeServerLicenseTerms /mode:install /r:mb,ca /MdbName:exchange_db1"
	Write-Host "System will be rebooting right now"
	Restart-And-Resume $script "Completing"
}

if (Should-Run-Step "Completing") 
{
	Write-Host "Completing Exchange 2013 Installation"
    Set-ItemProperty -Path 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon' -Name AutoAdminLogon -Value 0 
    Set-ItemProperty -Path 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon' -Name DefaultUserName -Value ""
    Set-ItemProperty -Path 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon' -Name DefaultPassword -Value ""
    Set-ItemProperty -Path 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon' -Name DefaultDomainName -Value ""

}

Wait-For-Keypress "Exchange 2013 installation completed, press any key to exit ..."


