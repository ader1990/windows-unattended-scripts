NET USER sqlserver "!Sql2014Server" /ADD
NET USER mssqladministrator "!Sql2014Server" /ADD
$machinename=hostname

$PARAMS="/ACTION=install " #required
$PARAMS+="/QS "            #quiet mode with process execution lapse
$PARAMS+="/IACCEPTSQLSERVERLICENSETERMS=1 " #accept end user agreement
$PARAMS+="/INSTANCENAME=MSSQLSERVER " #instance name
$PARAMS+="/FEATURES=SQLENGINE,ADV_SSMS " #features enabled. Possible features are stated at http://technet.microsoft.com/en-us/library/ms144259.aspx#Feature
$PARAMS+="/SQLSYSADMINACCOUNTS=$machinename\mssqladministrator " #provides system admin account
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
$PARAMS+="/SQLSVCACCOUNT=sqlserver " #specifies account for sql server instance service
$PARAMS+="/SQLSVCPASSWORD=!Sql2014Server " #specifies password for sql server instance service
$PARAMS+="/SQLSVCSTARTUPTYPE=Automatic " #specifies startup type of sql server instance service
$PARAMS+="/NPENABLED=1 " #enables named pipes protocol
$PARAMS+="/TCPENABLED=1 " #enables tcp protocol

d:\setup.exe $PARAMS
#a complate list of parameters can be found at http://technet.microsoft.com/en-us/library/ms144259.aspx#Install