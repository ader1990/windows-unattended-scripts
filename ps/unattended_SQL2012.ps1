param($Step="Join")
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

$hostname = hostname
$domain = "FONTOHOME"
$domainsuffix ="LOCAL"
$dcusername = "administrator"
$dcpassword = "FontoMarco1982!"
$svcusername = "sqlserver"
$svcpassword = "Sql!2014!Test"
$script = $myInvocation.MyCommand.Definition
Clear-Any-Restart
if (Should-Run-Step "Join") 
{
    NET USER sqlserver "!Sql2014Server" /ADD
    $secpasswd = ConvertTo-SecureString $dcpassword -AsPlainText -Force
    $creds = New-Object System.Management.Automation.PSCredential ($dcusername , $secpasswd)
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
	Restart-And-Resume $script "Install"
}


if (Should-Run-Step "Install") 
{
	Write-Host "Installing Sql Server 2012"
    $PARAMS="/ACTION=install " #required
    $PARAMS+="/QS "            #quiet mode with process execution lapse
    $PARAMS+="/IACCEPTSQLSERVERLICENSETERMS=1 " #accept end user agreement
    $PARAMS+="/INSTANCENAME=MSSQLSERVER " #instance name
    $PARAMS+="/FEATURES=SQLENGINE,ADV_SSMS " #features enabled. Possible features are stated at http://technet.microsoft.com/en-us/library/ms144259.aspx#Feature
    $PARAMS+="/SQLSYSADMINACCOUNTS=$domain\$dcusername " #provides system admin account
    $PARAMS+="/UpdateEnabled=1 " #enable installing updates from a specified path
    #$PARAMS+="/UpdateSource="" " #folder, UNC path of updates
    #$PARAMS+="/AGTSVCACCOUNT="" " #sql server agent service execution account
    #$PARAMS+="/AGTSVCPASSWORD ="" " #sql server agent service execution account password
    $PARAMS+="/AGTSVCSTARTUPTYPE=Automatic "#sql server agent service startup mode
    $PARAMS+="/BROWSERSVCSTARTUPTYPE=Automatic "#sql server browser startup mode
    #$PARAMS+="/INSTALLSQLDATADIR="" "#sql server data directory location; default %Program Files%\Microsoft SQL Server
    $PARAMS+="/SECURITYMODE=SQL " #enables mixed mode authentication
    $PARAMS+="/SAPWD=SqlSa2014! " #mandatory if you enable mixed mode authentication
    #$PARAMS+="/SQLBACKUPDIR="" "#specifies an alternative backup dir
    #$PARAMS+="/SQLCOLLATION="" "#default is windows' locale
    $PARAMS+="/SQLSVCACCOUNT=$svcusername " #specifies account for sql server instance service
    $PARAMS+="/SQLSVCPASSWORD=$svcpassword " #specifies password for sql server instance service
    $PARAMS+="/SQLSVCSTARTUPTYPE=Automatic " #specifies startup type of sql server instance service
    $PARAMS+="/NPENABLED=1 " #enables named pipes protocol
    $PARAMS+="/TCPENABLED=1 " #enables tcp protocol
    Start-Process -Wait -FilePath "d:\setup.exe" -ArgumentList $PARAMS
	Write-Host "System will be rebooting right now"
	Restart-And-Resume $script "Completing"
}

if (Should-Run-Step "Completing") 
{
	Write-Host "Completing Sql Server 2012 Installation"
}

Wait-For-Keypress "Sql Server 2012 installation completed, press any key to exit ..."

