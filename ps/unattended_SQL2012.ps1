param($Step="Prepare",
$adminusername = "administrator",
$adminpassword = "FontoMarco1982!",
$svcusername = "sqlserver",
$svcpassword = "!Sql2014Server",
$features = "SQLENGINE,ADV_SSMS",
$instancename = "MSSQLSERVER",
$sapassword = "Sql!Server2014",
$setupPath = "E:\setup.exe",
$domain = "",
$domainsuffix = "",
$dnsip="")

$global:started = $FALSE
$global:startingStep = $Step
$global:restartKey = "Restart-And-Resume"
$global:RegRunKey ="HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run"
$global:RegVarKey = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Unattended"
$global:powershell = (Join-Path $env:windir "system32\WindowsPowerShell\v1.0\powershell.exe")
$tempFolder = "c:\Windows\temp\"

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


$logFile = $tempFolder + "install_sql2012_log.txt"
if(!(Test-Path -Path $logFile )){
    New-Item $logFile -type file
}
function log([string] $message){
    Add-Content $logFile $message
}

$script = $myInvocation.MyCommand.Definition
Clear-Any-Restart


if (Should-Run-Step "Prepare")
{
    #using old local administrator account
    $localadmin = [ADSI]'WinNT://./Administrator'
    $localadmin.SetPassword($adminpassword)
    New-ItemProperty -Path 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon' -Name AutoAdminLogon -Value 1
    New-ItemProperty -Path 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon' -Name DefaultUserName -Value "Administrator"
    New-ItemProperty -Path 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon' -Name DefaultPassword -Value $adminpassword
    Set-ItemProperty -Path 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon' -Name AutoAdminLogon -Value 1
    Set-ItemProperty -Path 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon' -Name DefaultUserName -Value "Administrator"
    Set-ItemProperty -Path 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon' -Name DefaultPassword -Value $adminpassword
    New-ItemProperty -Path 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon' -Name adminpassword -Value $adminpassword
    New-ItemProperty -Path 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon' -Name adminusername -Value $adminusername
    New-ItemProperty -Path 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon' -Name svcusername -Value $svcusername
    New-ItemProperty -Path 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon' -Name svcpassword -Value $svcpassword
    New-ItemProperty -Path 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon' -Name features -Value $features
    New-ItemProperty -Path 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon' -Name instancename -Value $instancename
    New-ItemProperty -Path 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon' -Name sapassword -Value $sapassword
    New-ItemProperty -Path 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon' -Name setuppath -Value $setupPath
    New-ItemProperty -Path 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon' -Name domain  -Value $domain
    New-ItemProperty -Path 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon' -Name domainsuffix -Value $domainsuffix
    
    if ($domain -ne "")
    {
        log("Join Domain at next logon")
        log($domain)
        log($domainsuffix)
        Restart-And-Resume $script "Join"
    }
    else
    {
        log("Install sql at next logon")
        Restart-And-Resume $script "Install"
    }
}

if (!Should-Run-Step "Prepare"){
    $adminpassword = (Get-ItemProperty -Path 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon' -Name adminpassword).adminpassword
    $adminusername= (Get-ItemProperty -Path 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon' -Name adminusername).adminusername
    $svcusername= (Get-ItemProperty -Path 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon' -Name svcusername).svcusername 
    $svcpassword=(Get-ItemProperty -Path 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon' -Name svcpassword).svcpassword
    $features=(Get-ItemProperty -Path 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon' -Name feature).feature
    $instancename=(Get-ItemProperty -Path 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon' -Name instancename).instancename
    $sapassword=(Get-ItemProperty -Path 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon' -Name sapassword).sapassword
    $setupPath=(Get-ItemProperty -Path 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon' -Name setuppath).setuppath 
    $domain=(Get-ItemProperty -Path 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon' -Name domain).domain
    $domainsuffix=(Get-ItemProperty -Path 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon' -Name domainsuffix).domainsuffix
}
if (Should-Run-Step "Join")
{
    log "Joining domain"
    log($domain)
    log($domainsuffix)
    $secpasswd = ConvertTo-SecureString $adminpassword -AsPlainText -Force
    $creds = New-Object System.Management.Automation.PSCredential ($adminusername , $secpasswd)
    Write-Host "Joining Active Directory"
    New-ItemProperty -Path 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon' -Name AutoAdminLogon -Value 1
    New-ItemProperty -Path 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon' -Name DefaultUserName -Value $adminusername
    New-ItemProperty -Path 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon' -Name DefaultPassword -Value $adminpassword
    New-ItemProperty -Path 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon' -Name DefaultDomainName -Value $domain
    Set-ItemProperty -Path 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon' -Name AutoAdminLogon -Value 1
    Set-ItemProperty -Path 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon' -Name DefaultUserName -Value $adminusername
    Set-ItemProperty -Path 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon' -Name DefaultPassword -Value $adminpassword
    Set-ItemProperty -Path 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon' -Name DefaultDomainName -Value $domain

    $wmi = Get-WmiObject win32_networkadapterconfiguration -filter "ipenabled = 'true'"
    $wmi.SetDNSServerSearchOrder($dnsip)

    Add-Computer -Credential $creds -DomainName $domain"."$domainsuffix -f
    if (!$?) {
        log($domain)
        log($domainsuffix)
        $errorMessage = ($error[0] | out-string)
        log "Add to domain failed"
        log $errorMessage
        throw "AD Controller failed to install"
    }
    log "Joined domain"

    Write-Host "System will be rebooting right now"
    Restart-And-Resume $script "Install"
}


if (Should-Run-Step "Install")
{
    log "Start sql server 2012 install"
    Write-Host "Installing Sql Server 2012"
    NET USER $svcusername $svcpassword /ADD
    $hostname = hostname
    $PARAMS="/ACTION=install " #required
    $PARAMS+="/QS "            #quiet mode with process execution lapse
    $PARAMS+="/IACCEPTSQLSERVERLICENSETERMS=1 " #accept end user agreement
    $PARAMS+="/INSTANCENAME=$instancename " #instance name
    $PARAMS+="/FEATURES=$features " #features enabled. Possible features are stated at http://technet.microsoft.com/en-us/library/ms144259.aspx#Feature
    if ($domain -eq "")
    {
        $PARAMS+="/SQLSYSADMINACCOUNTS=.\$adminusername " #provides system admin account
    }
    else
    {
        $PARAMS+="/SQLSYSADMINACCOUNTS=$domain\$adminusername " #provides system admin account
    }
    $PARAMS+="/UpdateEnabled=1 " #enable installing updates from a specified path
    #$PARAMS+="/UpdateSource="" " #folder, UNC path of updates
    #$PARAMS+="/AGTSVCACCOUNT="" " #sql server agent service execution account
    #$PARAMS+="/AGTSVCPASSWORD ="" " #sql server agent service execution account password
    $PARAMS+="/AGTSVCSTARTUPTYPE=Automatic "#sql server agent service startup mode
    $PARAMS+="/BROWSERSVCSTARTUPTYPE=Automatic "#sql server browser startup mode
    #$PARAMS+="/INSTALLSQLDATADIR="" "#sql server data directory location; default %Program Files%\Microsoft SQL Server
    $PARAMS+="/SECURITYMODE=SQL " #enables mixed mode authentication
    $PARAMS+="/SAPWD=$sapassword " #mandatory if you enable mixed mode authentication
    #$PARAMS+="/SQLBACKUPDIR="" "#specifies an alternative backup dir
    #$PARAMS+="/SQLCOLLATION="" "#default is windows' locale
    $PARAMS+="/SQLSVCACCOUNT=.\$svcusername " #specifies account for sql server instance service
    $PARAMS+="/SQLSVCPASSWORD=$svcpassword " #specifies password for sql server instance service
    $PARAMS+="/SQLSVCSTARTUPTYPE=Automatic " #specifies startup type of sql server instance service
    $PARAMS+="/NPENABLED=1 " #enables named pipes protocol
    $PARAMS+="/TCPENABLED=1 /ERRORREPORTING=1" #enables tcp protocol
    Start-Process -Wait -FilePath $setupPath -ArgumentList $PARAMS
    if (!$?) {
        $errorMessage = ($error[0] | out-string)
        log "SQL install"
        log $errorMessage
        throw "SQL failed to install"
    }
    log "Stop Sql Server 2012 install"
    Write-Host "System will be rebooting right now"
    Restart-And-Resume $script "Completing"
}

if (Should-Run-Step "Completing")
{
    Write-Host "Completing Sql Server 2012 Installation"
    Set-ItemProperty -Path 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon' -Name AutoAdminLogon -Value 0
    Set-ItemProperty -Path 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon' -Name DefaultUserName -Value ""
    Set-ItemProperty -Path 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon' -Name DefaultPassword -Value ""
    Set-ItemProperty -Path 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon' -Name DefaultDomainName -Value ""
}

Wait-For-Keypress "Sql Server 2012 installation completed, press any key to exit ..."


