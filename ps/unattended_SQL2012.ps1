param($Step="Prepare",
$adminusername = "Administrator",
$adminpassword = "FontoMarco1982!",
$svcusername = "sqlserver",
$svcpassword = "!Sql2014Server",
$features = "SQLENGINE,ADV_SSMS",
$instancename = "MSSQLSERVER",
$sapassword = "Sql!Server2014",
$setupPath = "F:\setup.exe",
$domain = "",
$domainsuffix = "",
$dnsip="")

$global:RegRunKey ="HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run"
$global:RegVarKey = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Unattended"
$global:powershell = (Join-Path $env:windir "system32\WindowsPowerShell\v1.0\powershell.exe")

$tempFolder = "c:\Windows\temp\"
$logFile = $tempFolder + "install_sql2012_log.txt"
if(!(Test-Path -Path $logFile )){
    New-Item $logFile -type file
}
function log([string] $message){
    Add-Content $logFile $message
}

$iso = Mount-DiskImage -PassThru $setupPath
$isoSetupPath = (Get-Volume -DiskImage $iso).DriveLetter + ":\setup.exe"

log "Start sql server 2012 install"
Write-Host "Installing Sql Server 2012"
NET USER $svcusername $svcpassword /ADD
$hostname = hostname
$PARAMS="/ACTION=install " #required
$PARAMS+="/Q "            #quiet mode with process execution lapse
$PARAMS+="/IACCEPTSQLSERVERLICENSETERMS=1 " #accept end user agreement
$PARAMS+="/INSTANCENAME=$instancename " #instance name
$PARAMS+="/FEATURES=$features " #features enabled. Possible features are stated at http://technet.microsoft.com/en-us/library/ms144259.aspx#Feature
if ($domain -ne "")
{
    #using old local administrator account
    $localadmin = [ADSI]'WinNT://./Administrator'
    $localadmin.SetPassword($adminpassword)
    $wmi = Get-WmiObject win32_networkadapterconfiguration -filter "ipenabled = 'true'"
    $wmi.SetDNSServerSearchOrder($dnsip)
    netdom join $env:computername /Domain:cloudbase /UserD:Administrator /PasswordD:$adminpassword /UserO:Administrator /PasswordO:$adminpassword
    if (!$?) {
        log($domain)
        log($domainsuffix)
        $errorMessage = ($error[0] | out-string)
        log "Add to domain failed"
        log $errorMessage
        throw "AD Controller failed to install"
    }
    log "Joined domain"
    $PARAMS+="/SQLSYSADMINACCOUNTS=$domain\$adminusername " #provides system admin account
}
else
{
    $PARAMS+="/SQLSYSADMINACCOUNTS=.\$adminusername " #provides system admin account
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
Start-Process -Wait -FilePath $isoSetupPath -ArgumentList $PARAMS
if (!$?) {
    $errorMessage = ($error[0] | out-string)
    log "SQL install"
    log $errorMessage
    throw "SQL failed to install"
}
log "Stop Sql Server 2012 install"


