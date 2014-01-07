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

function InstallExe($url, $filename, $Arguments) {
    Write-Host "Downloading and installing: $filename"
        (new-object System.Net.WebClient).DownloadFile($url, "$pwd\$filename")
        Start-Process -Wait $filename -ArgumentList $Arguments
        del $filename
}

function InstallMSI($url, $filename) {
    Write-Host "Downloading and installing: $url"
        (new-object System.Net.WebClient).DownloadFile($url, "$pwd\$filename")
        Start-Process -Wait msiexec.exe -ArgumentList "/i $filename /qn"
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
    Set-ItemProperty -Path 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon' -Name AutoAdminLogon -Value 1 
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
    Import-Module ServerManager
    Add-WindowsFeature NET-WCF-HTTP-Activation45,NET-WCF-TCP-Activation45,NET-WCF-Pipe-Activation45
    Add-WindowsFeature Net-Framework-Features,Web-Server,Web-WebServer,Web-Common-Http,Web-Static-Content,Web-Default-Doc,Web-Dir-Browsing,Web-Http-Errors,Web-App-Dev,Web-Asp-Net,Web-Net-Ext,Web-ISAPI-Ext,Web-ISAPI-Filter,Web-Health,Web-Http-Logging,Web-Log-Libraries,Web-Request-Monitor,Web-Http-Tracing,Web-Security,Web-Basic-Auth,Web-Windows-Auth,Web-Filtering,Web-Digest-Auth,Web-Performance,Web-Stat-Compression,Web-Dyn-Compression,Web-Mgmt-Tools,Web-Mgmt-Console,Web-Mgmt-Compat,Web-Metabase,Application-Server,AS-Web-Support,AS-TCP-Port-Sharing,AS-WAS-Support, AS-HTTP-Activation,AS-TCP-Activation,AS-Named-Pipes,AS-Net-Framework,WAS,WAS-Process-Model,WAS-NET-Environment,WAS-Config-APIs,Web-Lgcy-Scripting,Windows-Identity-Foundation,Server-Media-Foundation,Xps-Viewer
    Write-Host "System will be rebooting right now"
	Restart-And-Resume $script "Prerequisites"
}

if (Should-Run-Step "Prerequisites") 
{
	Write-Host "Installing Sharepoint 2013 Prerequisites"
	
    Write-Host "System will be rebooting right now"
	Restart-And-Resume $script "Install"
}

if (Should-Run-Step "Users")
{
    $machinename = hostname
    Import-PSSession -Session (New-PSSession -ComputerName <nome dc> -Credential (Get-Credential)) -CommandName New-ADUser
    $Password = $farmPassword
    $Name = "spFarm"
    $UPN = "spExtranetFarm@$domain.$domainsuffix”
    $Description = "SharePoint Farm Administrator Account"
    $Path = "ou=service,ou=accounts,ou=sharepoint2013,dc=$domain,dc=$domainsuffix"
    New-ADUser -Name $Name -AccountPassword $Password -Description $Description ` -Enabled $true -PasswordNeverExpires $true -Path $Path -SamAccountName $Name ` -UserPrincipalName $UPN
    $Password = $installPassword
    $Name = "spInstall"
    $UPN = "spInstall@$domain.$domainsuffix"
    $Description = "SharePoint Installation Account"
    $Path = "ou=service,ou=accounts,ou=sharepoint2013,dc=$domain,dc=$domainsuffix"
    New-ADUser -Name $Name -AccountPassword $Password -Description $Description ` -Enabled $true -PasswordNeverExpires $true -Path $Path -SamAccountName $Name ` -UserPrincipalName $UPN
    $Password = $appPoolPassword
    $Name = "spAppPool"
    $UPN = "spAppPool@$domain.$domainsuffix"
    $Description = "SharePoint Application Pool Account"
    $Path = "ou=service,ou=accounts,ou=sharepoint2013,dc=$domain,dc=$domainsuffix"
    New-ADUser -Name $Name -AccountPassword $Password -Description $Description ` -Enabled $true -PasswordNeverExpires $true -Path $Path -SamAccountName $Name ` -UserPrincipalName $UPN
    //aggiunta user-groups locali e domain groups
    Invoke-Command -ComputerName $machinename {
    $User = [ADSI]("WinNT://$domain/spFarm")
    $Group = [ADSI]("WinNT://$machinename/Administrators")
    $Group.PSBase.Invoke("Add",$User.PSBase.Path)
    $User = [ADSI]("WinNT://cloudbasesolutions/spInstall")
    $Group = [ADSI]("WinNT://$machinename/Administrators")
    $Group.PSBase.Invoke("Add",$User.PSBase.Path)
    } -Credential (Get-Credential)
    $secpasswd = ConvertTo-SecureString $installPassword -AsPlainText -Force
    $creds = New-Object System.Management.Automation.PSCredential ("spInstall" , $installPassword)
    Set-ItemProperty -Path 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon' -Name AutoAdminLogon -Value 1 
    Set-ItemProperty -Path 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon' -Name DefaultUserName -Value "spInstall"
    Set-ItemProperty -Path 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon' -Name DefaultPassword -Value $installPassword
    Set-ItemProperty -Path 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon' -Name DefaultDomainName -Value $domain
    Restart-And-Resume $script "Users"
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


