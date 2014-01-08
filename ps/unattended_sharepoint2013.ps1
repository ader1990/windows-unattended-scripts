param($Step="Prepare",
$domain = "FONTOHOME",
$domainsuffix ="LOCAL",
$dcusername = "administrator",
$dcpassword = "FontoMarco1982!",
$setupPath = "d:\setup.exe",
$sqladmin ="FONTOHOME\administrator",
$sqlpassword = "FontoMarco1982!",
$sqlinstance="MSSQLSERVER",
$dcName ="MARCOFONTAN5E2E",
$farmPassword = "FontoMarco1982!",
$dnsip=""
)

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

function InstallEXE($url, $filename, $arguments) {
    Write-Host "Downloading and installing: $filename"
        (new-object System.Net.WebClient).DownloadFile($url, "$pwd\$filename")
        Start-Process -Wait $filename -ArgumentList $arguments
        del $filename
}

function InstallMSI($url, $filename, $arguments) {
    Write-Host "Downloading and installing: $url"
        (new-object System.Net.WebClient).DownloadFile($url, "$pwd\$filename")
        Start-Process -Wait msiexec.exe -ArgumentList "/i $filename $arguments"
        del $filename
}


$script = $myInvocation.MyCommand.Definition
Clear-Any-Restart
if (Should-Run-Step "Prepare")
{
   #using old local administrator account
   $localadmin = [ADSI]'WinNT://./Administrator'
   $localadmin.SetPassword($dcpassword)
   New-ItemProperty -Path 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon' -Name AutoAdminLogon -Value 1 
   New-ItemProperty -Path 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon' -Name DefaultUserName -Value "Administrator"
   New-ItemProperty -Path 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon' -Name DefaultPassword -Value $dcpassword
   Set-ItemProperty -Path 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon' -Name AutoAdminLogon -Value 1 
   Set-ItemProperty -Path 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon' -Name DefaultUserName -Value "Administrator"
   Set-ItemProperty -Path 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon' -Name DefaultPassword -Value $dcpassword
   Restart-And-Resume $script "Join"
}

if (Should-Run-Step "Join") 
{
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
    $wmi = Get-WmiObject win32_networkadapterconfiguration -filter "ipenabled = 'true'"
    $wmi.SetDNSServerSearchOrder($dnsip)
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
	InstallMSI "http://download.microsoft.com/download/9/1/3/9138773A-505D-43E2-AC08-9A77E1E0490B/1033/x64/sqlncli.msi" "sqlncli.msi" "/quiet IACCEPTSQLNCLILICENSETERMS=YES"
    InstallMSI "http://download.microsoft.com/download/E/0/0/E0060D8F-2354-4871-9596-DC78538799CC/Synchronization.msi" "Synchronization.msi" "/quiet"
    InstallEXE "http://download.microsoft.com/download/A/6/7/A678AB47-496B-4907-B3D4-0A2D280A13C0/WindowsServerAppFabricSetup_x64.exe" "WindowsServerAppFabricSetup_x64.exe" "/quiet"
    InstallEXE "http://download.microsoft.com/download/7/B/5/7B51D8D1-20FD-4BF0-87C7-4714F5A1C313/AppFabric1.1-RTM-KB2671763-x64-ENU.exe" "AppFabric1.1-RTM-KB2671763-x64-ENU.exe" "/quiet"
    InstallMSI "http://download.microsoft.com/download/D/7/2/D72FD747-69B6-40B7-875B-C2B40A6B2BDD/Windows6.1-KB974405-x64.msu" "Windows6.1-KB974405-x64.msu" "/quiet"
    InstallMSI "http://download.microsoft.com/download/0/1/D/01D06854-CA0C-46F1-ADBA-EBF86010DCC6/rtm/MicrosoftIdentityExtensions-64.msi" "MicrosoftIdentityExtensions-64.msi" "/quiet"
    InstallMSI "http://download.microsoft.com/download/9/1/D/91DA8796-BE1D-46AF-8489-663AB7811517/setup_msipc_x64.msi" "setup_msipc_x64.msi" "/quiet"
    InstallEXE "http://download.microsoft.com/download/8/F/9/8F93DBBD-896B-4760-AC81-646F61363A6D/WcfDataServices.exe" "WcfDataServices.exe" "/quiet"
    Write-Host "System will be rebooting right now"
	#Restart-And-Resume $script "Users"
}

if (Should-Run-Step "Users")
{
    #creating AD users
    $machinename = hostname
    Import-PSSession -Session (New-PSSession -ComputerName $dcName) -CommandName New-ADUser
    $Password = ConvertTo-SecureString $farmPassword -AsPlainText -Force
    $Name = "spFarm"
    $Description = "$domain unattended SharePoint 2013 Farm Administrator Account"
    New-ADUser -Name $Name -AccountPassword $Password -Description $Description ` -Enabled $true 
    $Password = ConvertTo-SecureString $installPassword -AsPlainText -Force
    $Name = "spInstall"
    $Description = "$domain unattended SharePoint 2013 Installation Account"
    New-ADUser -Name $Name -AccountPassword $Password -Description $Description ` -Enabled $true 
    $Password = ConvertTo-SecureString $appPoolPassword -AsPlainText -Force
    $Name = "spAppPool"
    $Description = "$domain unattended SharePoint 2013 Application Pool Account"
    New-ADUser -Name $Name -AccountPassword $Password -Description $Description ` -Enabled $true 
    #adding to local and domain user/groups
    Invoke-Command -ComputerName $machinename {
    $User = [ADSI]("WinNT://$domain/spFarm")
    $Group = [ADSI]("WinNT://$machinename/Administrators")
    $Group.PSBase.Invoke("Add",$User.PSBase.Path)
    $User = [ADSI]("WinNT://cloudbasesolutions/spInstall")
    $Group = [ADSI]("WinNT://$machinename/Administrators")
    $Group.PSBase.Invoke("Add",$User.PSBase.Path)
    }
    Get-PSSession | Remove-PSSession
    #SQL Users prep using sql ad-db admin
    $sqlsecpasswd = ConvertTo-SecureString $sqlpassword -AsPlainText -Force
    $sqlcreds = New-Object System.Management.Automation.PSCredential ($sqladmin , $secpasswd)
    Import-PSSession -Session (New-PSSession -ComputerName $sqldatabase -Credential $sqlcreds ) -CommandName Invoke-Sqlcmd
    Invoke-Sqlcmd -ServerInstance  $sqlinstance -Database master –Query `
    "USE [master]
    GO
    CREATE LOGIN [$domain\spInstall] FROM WINDOWS WITH DEFAULT_DATABASE=[master]
    GO
    ALTER SERVER ROLE [dbcreator] ADD MEMBER [$domain\spInstall]
    GO
    ALTER SERVER ROLE [securityadmin] ADD MEMBER [$domain\spInstall]
    GO"

    #set max-degree of parallelism to 1

    Invoke-Sqlcmd -ServerInstance $sqlinstance -Database master –Query `
    "EXEC sys.sp_configure N'max degree of parallelism',N'1'
    GO
    RECONFIGURE WITH OVERRIDE
    GO"
    Get-PSSession | Remove-PSSession
    #Configuring for login supplying spInstall credentials
    Set-ItemProperty -Path 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon' -Name AutoAdminLogon -Value 1 
    Set-ItemProperty -Path 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon' -Name DefaultUserName -Value "spInstall"
    Set-ItemProperty -Path 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon' -Name DefaultPassword -Value $installPassword
    Set-ItemProperty -Path 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon' -Name DefaultDomainName -Value $domain
    Restart-And-Resume $script "Install"
}

if (Should-Run-Step "Install") 
{
	Write-Host "Installing Sharepoint 2013"
	Start-Process -Wait -FilePath $setupPath -ArgumentList "/config $configfile"
	Write-Host "System will be rebooting right now"
	Restart-And-Resume $script "Completing"
}

if (Should-Run-Step "Completing") 
{
	Write-Host "Configuring Sharepoint 2013 Central Administration"


    #configuring managed accounts
    Add-PSSnapin  "Microsoft.SharePoint.PowerShell"
    $UserName = "$domain\spFarm"
    $SecureUserPassword = ConvertTo-SecureString $farmPassword -AsPlainText -Force
    $Credential = New-Object System.Management.Automation.PSCredential $UserName, $SecureUserPassword
    New-SPManagedAccount -Credential $Credential
    $UserName = "$domain\spAppPool"
    $SecureUserPassword = ConvertTo-SecureString $appPoolPassword -AsPlainText -Force
    $Credential = New-Object System.Management.Automation.PSCredential $UserName, $SecureUserPassword
    New-SPManagedAccount -Credential $Credential

    #disabling auto-logon
    Set-ItemProperty -Path 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon' -Name AutoAdminLogon -Value 0 
    Set-ItemProperty -Path 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon' -Name DefaultUserName -Value ""
    Set-ItemProperty -Path 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon' -Name DefaultPassword -Value ""
    Set-ItemProperty -Path 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon' -Name DefaultDomainName -Value ""

}

Wait-For-Keypress "Exchange 2013 installation completed, press any key to exit ..."


