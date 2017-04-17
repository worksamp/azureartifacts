Param([String] $Action, [String] $HeartbeatStatusFile)

# constants 
$HeartbeatTaskName = "update_azureoperationalinsight_agent_heartbeat"
$OpInsightsRegFolder = "HKLM:\SYSTEM\CurrentControlSet\Services\HealthService\Parameters\Service Connector Services\Azure Operational Insights"
$AzureReourceIdRegFolder = "HKLM:\SYSTEM\CurrentControlSet\Services\HealthService\Parameters\"
$AzureReourceIdRegItem = "Azure Resource Id"
$ExtensionRegFolder = "HKLM:\Software\Microsoft\Windows Azure\MicrosoftMonitoingAgent"
$OpInsightsCertProperty = "Authentication Certificate Thumbprint"
$ExtensionCertProperty = "AOI-CertThumbprint"
$ExtensionWorkspaceIdProperty = "VMExtensionWorkspaceId"
$ExtensionWorkspaceIdListProperty = "VMExtensionWorkspaceIdList"
$ExtensionProxyProperty = "VMExtensionProxyUri"
$ExtensionWorkspaceIdListDelimeter = ';'
$MMAComObjectName = "AgentConfigManager.MgmtSvcCfg"
$MMAWindowsServiceName = "HealthService"
$ExtensionConfigurationError="The configuration was not valid. Please validate the workspaceId is in the PublicSetting field, and the workspaceKey is in the PrivateSetting field. Both fields are case-sensitive. (MMAEXTENSION_ERROR_INVALIDCONFIG)"

# variables
$invocation = (Get-Variable MyInvocation -scope 0).value
$scriptPath = $invocation.MyCommand.Path
$scriptFolder = split-path -parent $scriptPath
$logFile = ""

#Load Json.Net, extension communication is based on json.
$JsonNetPath=(Get-Item -Path (Join-Path -Path $scriptFolder -ChildPath ".\Newtonsoft.Json.dll")).FullName
[Reflection.Assembly]::LoadFile($JsonNetPath)

<#
.SYNOPSIS 
Logging, log to $global:logFile if exists, otherwise log to screen.
#>
function Write-Log(){
    Param([string] $Message)

  if($global:logFile){
    Add-Content -Path $global:logFile -Value "`r`n$(Get-Date), $Message"
  }else{
    Write-Host "$(Get-Date), $Message"
  }
}

<#
.SYNOPSIS 
VMExtension are required to search latest setting file in a folder with largest LastWriteTime as file name.
#>
function Get-LatestConfigurationFile{
    Param($ConfigFolder)
  
    $defaultResult = New-Object PSObject -Property @{"SequenceNumber"=0; "FullName"="$ConfigFolder\0.settings"}

    $latestConfig = Get-ChildItem -Path $ConfigFolder -Filter "*.settings" | 
    Select-Object -Property FullName, @{Name="SequenceNumber";Expression={[int]$_.BaseName}}, LastWriteTime |
    Sort-Object -Property "LastWriteTime" -Descending |
    Select-Object -First 1

	if($latestConfig) { return $latestConfig; }
    return $defaultResult;
}

<#
.SYNOPSIS 
Add retry to typical Out-File cmdlet.
Extension status and heartbeat reporting is rely on file based communication, extension write, framework read.
There could be conflict issue between read and write, so we need this retry logic.
#>
function Out-FileWithRetry{
    Param([string] $FilePath, [string] $Content)
  
    $retryCount=3
    do{
        $retryCount--
        try{
            Out-File -FilePath $FilePath -InputObject $Content
            return;
        }catch{
            Write-Log -Message "Failed write to $FilePath, will try $retryCount more times. Error: $($_.Exception.ToString())"
        }
        Start-Sleep -Seconds 5
    }while($retryCount -gt 0)
}

<#
.SYNOPSIS 
Decrypt a string with specified certificate.
#>
function Decrypt-ProtectedSettings{
    Param([string] $Thumbprint, [string] $EncryptedString)
  
    trap{ 
        throw "Error while decrypting protected Settings: $($_.Exception.Message)"
        return
    }
  
    $CertPath="Cert:\LocalMachine\My\$Thumbprint"
    if(!(Test-Path -Path $CertPath)){ throw "$CertPath not found!" }
    $cert = Get-Item -Path $CertPath
    if(!$cert) { throw "Cannot load cert $CertPath!" }
    Write-Log -Message "Certificate $Thumbprint loaded."

    [System.Reflection.Assembly]::LoadWithPartialName("System.Security") | out-Null
    $envelope = New-Object System.Security.Cryptography.Pkcs.EnvelopedCms
    $envelope.Decode([Convert]::FromBase64String($EncryptedString)) | out-Null
    $certCollection = New-Object System.Security.Cryptography.X509Certificates.X509Certificate2Collection
    $certCollection.Add($cert) | out-Null
    $envelope.Decrypt($certCollection) | out-Null
    $decrypedContent = [System.Text.Encoding]::UTF8.GetString($envelope.ContentInfo.Content)
    Write-Log -Message "protected setting decrypted."
    return $decrypedContent
}

<#
.SYNOPSIS 
Write a status json file that VMExtension framework understands.
#>
function Write-ExtensionStatus{
    Param([String] $Operation, [string] $MessageString, [int] $StatusCode, [string] $StatusFile)

    $statusJson=@(
        @{
            "version" = "1.0";
            "timestampUTC" = [DateTime]::UtcNow.ToString('o');
            "status" = @{
                "name" = "Azure Log Analytics (OMS)";
                "operation" = $Operation;
                "status" = if($StatusCode -eq 0){"success"}else{"error"};
                "code" = $statusCode;
                "formattedMessage" = @{"lang" ="en-US"; "message" = $MessageString; };
            }
        }
    )
    Out-FileWithRetry -FilePath $StatusFile -Content ([Newtonsoft.Json.JsonConvert]::SerializeObject($statusJson))
}

<#
.SYNOPSIS 
Write a heartbeat json file that VMExtension framework understands.
#>
function Write-HeartbeatStatus{
    Param([int]$HeartbeatCode, [string]$MessageString, [string] $HeartbeatFile)
 
    $heartbeatJson = @(
        @{
            "version" = "1.0";
            "heartbeat" = @{
                "status" = if($HeartbeatCode -eq 0){"ready"}else{"notready"};
                "code" = $HeartbeatCode;
                "formattedMessage" = @{ "lang" = "en-US"; "message" = "$MessageString" }
            };
            "timestampUTC" = [DateTime]::UtcNow.ToString('o')
        }
    )
    Out-FileWithRetry -FilePath $HeartbeatFile -Content ([Newtonsoft.Json.JsonConvert]::SerializeObject($heartbeatJson))
}

<#
.SYNOPSIS 
Call MMA COM interface to connect MMA to specified Azure Log Analytics (OMS) workspace.
#>
function Set-OMSWorkspace{
    Param($WorkspaceConfiguration, $HandlerConfiguration)

    trap{
        if( $_.FullyQualifiedErrorId -match "CannotLoadComObjectType,Microsoft.PowerShell.Commands.NewObjectCommand" -or #2008
            $_.FullyQualifiedErrorId -match "NoCOMClassIdentified,Microsoft.PowerShell.Commands.NewObjectCommand" -or #2012
            ($_.Exception.GetType().FullName -eq "System.Runtime.InteropServices.COMException" -and $_.Exception.Message.Contains("REGDB_E_CLASSNOTREG")) -or
            ($_.Exception.GetType().FullName -eq "Microsoft.PowerShell.Commands.ServiceCommandException" -and $_.Exception.ServiceName -eq $MMAWindowsServiceName)
        ){
            throw "The Microsoft Monitoring Agent failed to install on this machine. Please try to uninstall and reinstall the extension. If the issue persists, please contact support. (MMAEXTENSION_ERROR_AGENTNOTINSTALLED)"
            return 
        }

        if($_.FullyQualifiedErrorId -match "MethodNotFound"){
            throw "MicrosoftMontoringAgent version is not compatible with this extension, either we failed to upgrade to new version or you have an old version which is not upgradable. (MMAEXTENSION_ERROR_INCOMPATIBLEVERSION)"
            return
        }
        if($_.Message -contains "E_INVALIDARG"){
            throw $ExtensionConfigurationError
            return
        }

        throw "$($_.Exception.Message)"
        return
    }
  
    # default to Azure Commercial (Public) Cloud
    $azureCloudType = 0
    if($HandlerConfiguration -and $HandlerConfiguration.AzureCloudType){
        $azureCloudType = $HandlerConfiguration.AzureCloudType
    }
    Write-Log "Set cloudType to $azureCloudType"

    # Try load COMObject and HealthService first, if we hit any exception, don't bother read settings and decrypt.
    $agentcfg = New-Object -ComObject $MMAComObjectName
    $serviceStatus = Get-Service $MMAWindowsServiceName

    $newWorkspaceIdList = $WorkspaceConfiguration.Workspaces | foreach{ $_.WorkspaceId}
    $ExtensionBackup = Get-ExtensionBackup
    $existingWorkspaceIdList = $ExtensionBackup.WorkspaceIdList

    if($WorkspaceConfiguration.StopOnMultipleConnections){
        # find out workspaces manually onboarded on the box.
        $nonExtensionWorkspaces = $agentcfg.GetCloudWorkspaces() | where { 
            # if this workspace was managed by extension previously.
            ($existingWorkspaceIdList -notcontains $_.workspaceId) -and
            # if this workspace is going to be managed by extension, we turn a manual onboarded to extension managed, no need to return error.
            ($newWorkspaceIdList -notcontains $_.workspaceId)      
        } | foreach { return $_.workspaceId }

        # Ask end-user to use acceptMultipleConnections override, also warn they will get billed for each workspace.
        if($nonExtensionWorkspaces){ throw "This machine is already connected to some other Log Analytics workspace, please set stopOnMultipleConnections to false in public settings or remove this property, so this machine can connect to new workspaces, also it means this machine will get billed multiple times for each workspace it report to. (MMAEXTENSION_ERROR_MULTIPLECONNECTIONS)" }
    }
    
    # remove any workspace was on previous extension configuration and nolonger present.
    $existingWorkspaceIdList | where { $newWorkspaceIdList -notcontains $_} | foreach{
        Write-Log "workspace $_ has been removed from extension configuration"
        $agentcfg.RemoveCloudWorkspace($_)
    }

    # config agent with workspace info
    $WorkspaceConfiguration.Workspaces | foreach{
        $workspaceId = $_.WorkspaceId;
        Write-Log -Message "Configing Azure Log Analytics (OMS) with $workspaceId, $($_.WorkspaceKey.Substring(0, 4))***********************"
        $existingWorkspace = $agentcfg.GetCloudWorkspaces() | where {$_.workspaceId -eq $workspaceId};
        if($existingWorkspace -and $existingWorkspace.AzureCloudType -ne $azureCloudType)
		{
            throw "$workspaceId is currently connected to a different Azure Cloud, and updating the cloud type is not supported. Please login to the machine, disconnect the workspace, and try again. (MMAEXTENSION_ERROR_SWITCHINGCLOUD)"
        }
        $agentcfg.AddCloudWorkspace($workspaceId, $_.WorkspaceKey, $azureCloudType);
    }

    # Apply proxy setting if needed.
    if($WorkspaceConfiguration.ProxyUri){
        $agentcfg.SetProxyInfo($WorkspaceConfiguration.ProxyUri, $WorkspaceConfiguration.ProxyUser, $WorkspaceConfiguration.ProxyPassword)
    }else{
        # if we used to have proxy, now we don't, means customer want to remove proxy config.
        if($ExtensionBackup.ProxyUri){
            $agentcfg.SetProxyInfo("", "", "")
        }
    }
    # Recover AOI Certificate, MMA it self can do this, we do last time recovery.
    # TODO: Remove this on once 1.0.10375.2 version fade away.
    Recover-WorkspaceCert

    # Persist the workspaceId, proxyUri from this VMExtension.
    Backup-ExtensionConfiguration -WorkspaceIdList $newWorkspaceIdList -ProxyUri $WorkspaceConfiguration.ProxyUri

    # Set azureResourceId to help AzureScurityCenter track a VM with it's azure Identity.
    if($WorkspaceConfiguration.AzureResourceId){
        Set-AzureResourceId -AzureResourceId $WorkspaceConfiguration.AzureResourceId
    }
  
    $agentcfg.ReloadConfiguration();
    Write-Log -Message "Successfully applied latest config."

    # ensure healthService is running (healthservice will be restarted during ReloadConfiguration)
    $serviceStatus.Refresh();
    if($serviceStatus.Status -ne "Running"){ throw "HealthService failed to start!" }
}

<#
.SYNOPSIS 
Parse the latest settings file, to get workspaceId and workspaceKey.
#>
function Parse-OMSWorkspaceInfo{
    Param([string] $SettingsFile)
    trap{
        Write-Log -Message "Error while parsing new config, Error: $($_.Exception.Message), SettingsFile: $SettingsFile"
        throw "$($_.Exception.Message)"
        return
    }

    # load file and get Json object
    Write-Log -Message "Loading config file $SettingsFile"
    $content = Get-Content -Path $SettingsFile | Out-String
    try{ $configSettings = [Newtonsoft.Json.Linq.JObject]::Parse($content) }
    catch {throw "SettingFile has invalid json format."}
  

    # Read values
    Write-Log -Message "Get protectedSetting"

    if( $configSettings.Item("runtimeSettings") -eq $null -or 
        $configSettings.Item("runtimeSettings").Count -lt 1)
    { throw "missing runtimeSettings." }
    $runtimeSetting = $configSettings.Item("runtimeSettings")[0]

    if( $runtimeSetting.Item("handlerSettings") -eq $null){ throw "missing handlerSettings." } 

    # Read PrivateConfiguration
    $workspaceKeyException = "workspaceKey isn't provided or it's not in PrivateConfiguration"
    if($runtimeSetting.Item("handlerSettings").Item("protectedSettings") -eq $null) {throw $workspaceKeyException}
    $encryptedValue = $runtimeSetting.Item("handlerSettings").Item("protectedSettings").ToString()
    if(!$encryptedValue){ throw $workspaceKeyException }

    # Read Certificate to decrypt WorkspaceKey
    if($runtimeSetting.Item("handlerSettings").Item("protectedSettingsCertThumbprint") -eq $null) {throw $workspaceKeyException}
    $encryptCert = $runtimeSetting.Item("handlerSettings").Item("protectedSettingsCertThumbprint").ToString()
    if(!$encryptCert){ throw $workspaceKeyException }
  
    # Read WorkspaceId
    if($runtimeSetting.Item("handlerSettings").Item("publicSettings") -eq $null) {throw "missing publicSettings."}
    $workspaceIdJToken = $runtimeSetting.Item("handlerSettings").Item("publicSettings").Item("workspaceId")
  
    # decrypt
    Write-Log -Message "Decrypt protectedSetting"
    $decryptedString = Decrypt-ProtectedSettings -Thumbprint $encryptCert -EncryptedString $encryptedValue
    try{ $decryptedJson = [Newtonsoft.Json.Linq.JObject]::Parse($decryptedString) }
    catch{ throw "protectedSetting has invalid json format" }
    if(!$decryptedJson){
        throw $workspaceKeyException 
    }
    $workspaceKeyJToken = $decryptedJson.Item("workspaceKey");

    # Add first workspace
    Write-Log -Message "Validate and add default workspace."
    $workspaces = @()
    $partialResult = $false
    $firstWorkspace = Test-WorkspaceIdAndKey -WorkspaceIdJToken $workspaceIdJToken -WorkspaceKeyJToken $workspaceKeyJToken
    if($firstWorkspace){
        $workspaces += $firstWorkspace
    }else{
        $partialResult=$true
        Write-Log -Message "default workspace configuration is not valid."
    }

    # Read optional Additional Workspaces
    $additionalWorkspaceIds=$runtimeSetting.Item("handlerSettings").Item("publicSettings").Item("additionalWorkspaceIds")
    $additionalWorkspaceKeys=$decryptedJson.Item("additionalWorkspaceKeys")

    # if there are additional workspace info, add them.
    if($additionalWorkspaceIds -and $additionalWorkspaceKeys){
        # Minimum length would be the additional Workspace count.
        $additionalWorkspaceCount = (@($additionalWorkspaceIds.Count, $additionalWorkspaceKeys.Count) | Measure-Object -Minimum).Minimum
        # workspaceId and Key should in right order.
        for($i=0; $i -lt $additionalWorkspaceCount; $i++){
            $workspace=Test-WorkspaceIdAndKey -WorkspaceIdJToken $additionalWorkspaceIds[$i] -WorkspaceKeyJToken $additionalWorkspaceKeys[$i]
            if($workspace){
                $workspaces += $workspace
            }else{
                $partialResult=$true
                Write-Log -Message "config $i is not a valid workspace configuration."
            }
        }
    }

    if($workspaces.Count -eq 0){
        Write-Log -Message "No workspace configured / or none of them are valid."
        throw $ExtensionConfigurationError 
    }
  
    # Read AzureResourceId if exists, this is for AzureSecurityCenter scenario.
    $azureResourceId = $runtimeSetting.Item("handlerSettings").Item("publicSettings").Item("azureResourceId")
    if($azureResourceId){
        $azureResourceId = $azureResourceId.Value.ToString();
    }
    # Override for co-existing manual connected workspace, avoid double billing shock.
    $stopOnMultipleConnectionJToken = $runtimeSetting.Item("handlerSettings").Item("publicSettings").Item("stopOnMultipleConnections");
    if($stopOnMultipleConnectionJToken -and $stopOnMultipleConnectionJToken.Type -eq [Newtonsoft.Json.Linq.JTokenType]::Boolean){
        $stopOnMultipleConnections = $stopOnMultipleConnectionJToken.Value;
    }else{ $stopOnMultipleConnections = $false; } 

    # Read proxy settings, some customer might disable public internet connection even though VM is running on Cloud.
    $proxyUri = $runtimeSetting.Item("handlerSettings").Item("publicSettings").Item("proxyUri")
    $proxyUser = $runtimeSetting.Item("handlerSettings").Item("publicSettings").Item("proxyUser")
    $proxyPassword = $decryptedJson.Item("proxyPassword");
    if($proxyUri){
        $proxyUri = $proxyUri.Value.ToString()

        if($proxyUser){
            $proxyUser = $proxyUser.Value.ToString()

            if($proxyPassword){
                $proxyPassword = $proxyPassword.Value.ToString()
            }
        }
    }

    return @{
        "ProxyUri" = $proxyUri; 
        "ProxyUser" = $proxyUser; 
        "ProxyPassword" = $proxyPassword; 
        "AzureResourceId" = $azureResourceId;
        "StopOnMultipleConnections" = $stopOnMultipleConnections;
        "Workspaces" = $workspaces; 
        "PartialResult" = $partialResult }
}

<#
.SYNOPSIS 
Get default config for this extension (different azure cloud right now)
#>
function Get-HandlerConfig{
    trap{
        Write-Log "Error while parsing HandlerConfig file:" $_.ToString()
        throw $_
    }  
  
    $handlerConfigFile=".\HandlerConfig.json"
    if(Test-Path $handlerConfigFile){
        $handlerConfigContent = (Get-Content $handlerConfigFile) -join ""
        $jObj = [Newtonsoft.Json.Linq.JObject]::Parse($handlerConfigContent)
        if($jObj.Item("AzureCloudType")){
            return @{ "AzureCloudType" = [int]$jObj.Item("AzureCloudType").ToString() }
        }
    }else{
        return $null
    }
}

<#
.SYNOPSIS 
Validate workspaceId and workspaceKey and return a Object contains both.
#>
function Test-WorkspaceIdAndKey{
    param([Newtonsoft.Json.Linq.JToken] $WorkspaceIdJToken, [Newtonsoft.Json.Linq.JToken] $WorkspaceKeyJToken)

    if(!$WorkspaceIdJToken -or !$WorkspaceKeyJToken){return $false;}

    try{
        $workspaceId = $WorkspaceIdJToken.Value.ToString()
        $workspaceKey = $WorkspaceKeyJToken.Value.ToString()
        Write-Log "Verifying workspace $workspaceId"
        # [Guid]::Parse($workspaceId) doesn't works on .Net 2, while we still supprot Windows 2008.
        New-Object Guid $workspaceId | out-null
        if($workspaceKey.Length -lt 8) {return $false;}
        [Convert]::FromBase64String($workspaceKey)  | out-null
    }catch{
        Write-Log $_.ToString()
        return $false
    } 

    return @{"WorkspaceId"=$workspaceId; "WorkspaceKey"=$workspaceKey;}
}

<#
.SYNOPSIS 
Parse the HandlerEnvironment file, to get SettingFolder, StatusFolder, LogFolder and HeartbeatFile info.
#>
function Parse-HandlerEnvironment{
    Param($HandlerEnvironmentFile)

    trap{
        Write-Log $_
        throw "Error while parsing HandlerEnvironment : $_"
    }

    if(!(Test-Path $HandlerEnvironmentFile)){
        throw "Couldn't find $HandlerEnvironmentFile!"
    }

    $content = Get-Content $HandlerEnvironmentFile | Out-String
    $handlerEnvironment = [Newtonsoft.Json.Linq.JArray]::Parse($content)
    $configFolder=$handlerEnvironment[0].Item("handlerEnvironment").Item("configFolder").ToString()
    $logFolder = $handlerEnvironment[0].Item("handlerEnvironment").Item("logFolder").ToString()
    $statusFolder=$handlerEnvironment[0].Item("handlerEnvironment").Item("statusFolder").ToString()
    $heartbeatFile =$handlerEnvironment[0].Item("handlerEnvironment").Item("heartbeatFile").ToString()

    return @{"ConfigFolder"=$configFolder; "LogFolder"=$logFolder; "StatusFolder"=$statusFolder; "HeartbeatFile"=$heartbeatFile }
}

<#
.SYNOPSIS 
Check VMExtension environment, locate and parse latest config, then connect to Azure Log Analytics (OMS) with the info from latest config.
This function is triggered when
    New Configuration come
	Update to the VM
	Reboot.
#>
function Update-MMAExtension{
    trap{
        Write-Log -Message "$($_.Exception.Message)"
        if($statusFile) 
		{
            Write-ExtensionStatus -StatusFile $statusFile -MessageString "Operation Failed: $($_.Exception.Message)" -Operation $Operation -StatusCode 1
        }
        return 
    }
    $Operation = "Update Configuration"
    $handlerEnvironment = Parse-HandlerEnvironment '.\HandlerEnvironment.json'

    # Get config folder and find the right Config
    Write-Log -Message "Trying to find latest setting file."
    $latestConfigFile = Get-LatestConfigurationFile -ConfigFolder $handlerEnvironment.ConfigFolder

    # Get log file
    $global:logFile = Join-Path -Path $handlerEnvironment.LogFolder -ChildPath "$($latestConfigFile.SequenceNumber).log"

    # Get Status File
    $statusFile = Join-Path -Path $handlerEnvironment.StatusFolder -ChildPath "$($latestConfigFile.SequenceNumber).status"

    if(!(Test-Path $latestConfigFile.FullName)){
        Write-ExtensionStatus -StatusFile $statusFile -MessageString $ExtensionConfigurationError -Operation $Operation -StatusCode 1
        return
    }

    # Update OpsInsight with latest config
    $extensionConfiguration = Parse-OMSWorkspaceInfo -SettingsFile $latestConfigFile.FullName -LogFile $logFile
    $handlerConfiguration = Get-HandlerConfig
    Set-OMSWorkspace -WorkspaceConfiguration $extensionConfiguration -HandlerConfiguration $handlerConfiguration
  
    # Write Status
    $statusMessage = "Configuration applied."
    if($extensionConfiguration.PartialResult){
        $statusMessage="Configuration applied, at least one of workspace configuration is wrong."
    }
    Write-ExtensionStatus -StatusFile $statusFile -MessageString $statusMessage -Operation $Operation -StatusCode 0

    #Create schedule and update the heartbeat file
    Create-HeartbeatUpdater -HeartbeatFilePath $handlerEnvironment.HeartbeatFile
}

<#
.SYNOPSIS
This function set AzureResourceId for AzureSecurityCenter scenarios.
#>
function Set-AzureResourceId {
    Param([string] $AzureResourceId)
    trap{
        Write-Log "Failed to set AzureResourceId, Error: $($_.Exception.ToString())"
    }
  
    Set-ItemProperty -Path $AzureReourceIdRegFolder -Name $AzureReourceIdRegItem -Value $azureResourceId -Force
}

<#
.SYNOPSIS 
This function keep track the workspaceId add by this VMExtension.
#>
function Backup-ExtensionConfiguration{
    Param([string[]] $WorkspaceIdList, [string] $ProxyUri)
    trap{
        Write-Log -Message "Failed to backup Azure Log Analytics workspaceId, Error: $($_.Exception.ToString())"
        return
    }

    Write-Log -Message "Backup Azure Log Analytics workspaceId."
    if(!(Test-Path $ExtensionRegFolder)){
        New-Item -Path $ExtensionRegFolder | Out-Null
    }

    $backupValue = $WorkspaceIdList -join $ExtensionWorkspaceIdListDelimeter
    Set-ItemProperty -Path $ExtensionRegFolder -Name $ExtensionWorkspaceIdListProperty -Value $backupValue -Force
    if($ProxyUri){
        Set-ItemProperty -Path $ExtensionRegFolder -Name $ExtensionProxyProperty -Value $ProxyUri -Force
    }else{
        Remove-ItemProperty -Path $ExtensionRegFolder -Name $ExtensionProxyProperty -ErrorAction SilentlyContinue  
    }
  
    # On success backup, remove old version backup
    Remove-ItemProperty -Path $ExtensionRegFolder -Name $ExtensionWorkspaceIdProperty -ErrorAction SilentlyContinue
}

<#
.SYNOPSIS 
Get workspaces added through VMExtension. 
(vs. MMA COM API will return full list where some of them are added by customer manually, Extension shouldn't touch those ones.)
#>
function Get-ExtensionBackup 
{
    $workspaceIdList = @()
    $proxyUri = $null
    # Get from older version which only support single workspace
    if(Test-Path -Path $ExtensionRegFolder){
        $extensionRegItem = Get-Item -Path $ExtensionRegFolder

        # Old backup location (single workspace), version 1.0.10900.0 and previous
        $singletonWorkspaceId = $extensionRegItem.GetValue($ExtensionWorkspaceIdProperty)
        if($singletonWorkspaceId){
            $workspaceIdList += $singletonWorkspaceId
        }

        # newer backup location (multiple workspaces), after 1.0.10900.0
        ($extensionRegItem.GetValue($ExtensionWorkspaceIdListProperty)) -split $ExtensionWorkspaceIdListDelimeter | foreach{
            $workspaceIdList += "$_"
        }
        # get proxyUri backup
        $proxyUri = $extensionRegItem.GetValue($ExtensionProxyProperty)
    }

    return @{ "WorkspaceIdList"=$workspaceIdList; "ProxyUri" = $proxyUri }
}

<#
.SYNOPSIS 
This function should be removed in next release.
New version of MMA can find the right cert on it's own.
#>
function Recover-WorkspaceCert{
    trap{
        # No need to throw, worst case agent will register as new.
        Write-Log -Message "Failed to recovery Azure Log Analytics (OMS) certificate. Error: $($_.Exception.ToString())"
    }

    # find the backup cert thumbprint and recover.
    if(Test-Path -Path $ExtensionRegFolder){
        $extensionRegItem=Get-Item -Path $ExtensionRegFolder
        $thumbprint=$extensionRegItem.GetValue($ExtensionCertProperty)
        if($thumbprint){
            Write-Log -Message "Certificate backup found, trying to recover $thumbprint."
            Set-ItemProperty -Path $OpInsightsRegFolder -Name $OpInsightsCertProperty -Value $thumbprint -Force
            Remove-ItemProperty -Path $ExtensionRegFolder -Name $ExtensionCertProperty
        }
    }
}

<#
.SYNOPSIS 
Create a scheduled task to heartbeat with VM Extension framework.
#>
function Create-HeartbeatUpdater{
    Param([string] $HeartbeatFilePath)

    trap{
        Write-Log -Message "Error while create heartbeat updater : $($_.Exception.ToString())"
    }

    # Write initial status.
    Write-HeartbeatStatus -HeartbeatFile $HeartbeatFilePath -MessageString "Determining the connection status to Azure Log Analytics(OMS)." -HeartbeatCode 1
  
    # task passed to SCHTASKs cannot be more than 261 characters therefore the intermediate updateHB.cmd 
    Write-Log -Message "Registering scheduled task for heartbeat."
    $time = (Get-Date).AddMinutes(2).ToString("HH:mm")
    $registerResult = SCHTASKS /CREATE /TN $heartbeattaskName /TR "%SystemRoot%\System32\WindowsPowerShell\v1.0\Powershell.exe -NoProfile -ExecutionPolicy Bypass $scriptpath -Action Heartbeat" /SC MINUTE /mo 2 /ST $time /RU SYSTEM /F /RL HIGHEST
    Write-Log -Message "Register Result: $registerResult"
}

<#
.SYNOPSIS 
Check MMA status and log to Heartbeat, this function is called from scheduled task every minute.
#>
function Update-MMAExtensionHeartbeat{
    # Get Heartbeat file and LogFile
    $handlerFile = Join-Path -Path $scriptFolder -ChildPath "..\HandlerEnvironment.json"
    $handlerEnvironment = Parse-HandlerEnvironment $handlerFile
    $HeartbeatStatusFile =$handlerEnvironment.HeartbeatFile
    $global:logFile = Join-Path -Path $handlerEnvironment.LogFolder -ChildPath "Heartbeat.log"
    Write-Log -Message "Azure Log Analytics (OMS) Heartbeat."

    trap{
        Write-Log -Message "Error while heartbeating : $($_.Exception.ToString())"
    }

    # Get workspaceList from backup
    $existingWorkspaceIdList = (Get-ExtensionBackup).WorkspaceIdList
    if(!$existingWorkspaceIdList){
        Write-HeartbeatStatus -HeartbeatFile $HeartbeatStatusFile -MessageString "Found no Azure Log Analytics (OMS) for this extension to report." -HeartbeatCode 1
    }
  
    # Try initial COM API Object
    try{
        $mmasettings = New-Object -ComObject $MMAComObjectName
    }catch{  
        $message = "Could not determine the connection status to Azure Log Analytics (OMS)."
        Write-HeartbeatStatus -HeartbeatFile  $HeartbeatStatusFile -MessageString $message -HeartbeatCode 1
        return
    }
  
    # Get workspace comObject for each workspace we have.
    $omsWorkspaces = $existingWorkspaceIdList | foreach { $mmasettings.GetCloudWorkspace($_); }

  
    # if we only have one, return the raw status we have.
    if($existingWorkspaceIdList.Count -eq 1){
        Write-HeartbeatStatus -HeartbeatFile $HeartbeatStatusFile -MessageString $omsWorkspaces.ConnectionStatusText -HeartbeatCode $omsWorkspaces.ConnectionStatus
        return
    }

    # Filter out the workspaces are not ready, and report status.
    $notReadyWorkspaces = $omsWorkspaces | where {$_.ConnectionStatus -ne 0}
    if($notReadyWorkspaces){
        Write-HeartbeatStatus -HeartbeatFile $HeartbeatStatusFile -MessageString "At least one workspace is not connected." -HeartbeatCode 1
        return
    }
    # it appears all workspaces are connected.
    Write-HeartbeatStatus -HeartbeatFile $HeartbeatStatusFile -MessageString "All workspaces are connected." -HeartbeatCode 0
}

<#
.SYNOPSIS 
To hornor disable command from user, we remove connection to Azure Log Analytics (OMS).
#>
function Disable-MMAExtension{
    Write-Log -Message "Disabling Azure Log Analytics (OMS)."

    $handlerEnvironment = Parse-HandlerEnvironment '.\HandlerEnvironment.json'
    $latestConfigFile = Get-LatestConfigurationFile -ConfigFolder $handlerEnvironment.ConfigFolder
    if($latestConfigFile){
        $global:logFile = Join-Path -Path $handlerEnvironment.LogFolder -ChildPath "$($latestConfigFile.SequenceNumber).log"
    }
  
    # Remove OMS Workspace
    $agentcfg = New-Object -ComObject $MMAComObjectName;
    $ExtensionBackup = Get-ExtensionBackup
    if($ExtensionBackup.WorkspaceIdList){
        $ExtensionBackup.WorkspaceIdList | foreach {
            Write-Log -Message "Removing workspace $_ ."
            $agentcfg.RemoveCloudWorkspace($_)
        }
    }
    if($ExtensionBackup.ProxyUri){
        $agentcfg.SetProxyInfo("", "", "")
    }

    # Remove Backup
    Remove-ItemProperty -Path $ExtensionRegFolder -Name $ExtensionWorkspaceIdListProperty -ErrorAction SilentlyContinue
    Remove-ItemProperty -Path $ExtensionRegFolder -Name $ExtensionProxyProperty -ErrorAction SilentlyContinue

    # remove scheduled heartbeat task 
    Write-Log -Message "Azure Log Analytics (OMS) disabled, now removing scheduled heartbeat task."
    SCHTASKS /Delete /TN $heartbeattaskName  /F
    $agentcfg.ReloadConfiguration();

    # Write status to notify this extension has been disabled
    if($largestSequenceFile){
        $Operation = "Disable Extension"
        $statusFile = Join-Path -Path $handlerEnvironment.StatusFolder -ChildPath "$($largestSequenceFile.SequenceNumber).status"
        Write-ExtensionStatus -StatusFile $statusFile -MessageString "Operation Succeed" -Operation $Operation -StatusCode 0
    }
    Write-HeartbeatStatus -HeartbeatFile $handlerEnvironment.HeartbeatFile -MessageString "Azure Log Analytics (OMS) has been disabled." -HeartbeatCode 1
}


# First time install extension, or any configuration change, or Enable after Disable.
if($Action -eq "Update"){ Update-MMAExtension }

# Disable Extension but keep extension on the box.
if($Action -eq "Disable"){ Disable-MMAExtension }

# report Heartbeat to extension framework.
if($Action -eq "Heartbeat"){ Update-MMAExtensionHeartbeat }
# SIG # Begin signature block
# MIIdnQYJKoZIhvcNAQcCoIIdjjCCHYoCAQExCzAJBgUrDgMCGgUAMGkGCisGAQQB
# gjcCAQSgWzBZMDQGCisGAQQBgjcCAR4wJgIDAQAABBAfzDtgWUsITrck0sYpfvNR
# AgEAAgEAAgEAAgEAAgEAMCEwCQYFKw4DAhoFAAQUQb5LmxjJJalcHOJxHQkdApwv
# n7WgghhlMIIEwzCCA6ugAwIBAgITMwAAAMWWQGBL9N6uLgAAAAAAxTANBgkqhkiG
# 9w0BAQUFADB3MQswCQYDVQQGEwJVUzETMBEGA1UECBMKV2FzaGluZ3RvbjEQMA4G
# A1UEBxMHUmVkbW9uZDEeMBwGA1UEChMVTWljcm9zb2Z0IENvcnBvcmF0aW9uMSEw
# HwYDVQQDExhNaWNyb3NvZnQgVGltZS1TdGFtcCBQQ0EwHhcNMTYwOTA3MTc1ODUy
# WhcNMTgwOTA3MTc1ODUyWjCBszELMAkGA1UEBhMCVVMxEzARBgNVBAgTCldhc2hp
# bmd0b24xEDAOBgNVBAcTB1JlZG1vbmQxHjAcBgNVBAoTFU1pY3Jvc29mdCBDb3Jw
# b3JhdGlvbjENMAsGA1UECxMETU9QUjEnMCUGA1UECxMebkNpcGhlciBEU0UgRVNO
# OkMwRjQtMzA4Ni1ERUY4MSUwIwYDVQQDExxNaWNyb3NvZnQgVGltZS1TdGFtcCBT
# ZXJ2aWNlMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAtrwz4CWOpvnw
# EBVOe1crKElrs3CQl/yun1cdkpugh/MxsuoGn7BL43GRTxRn7sPD7rq1Dxj4smPl
# gVZr/ZhGMA8J3zXOqyIcD4hYFikXuhlGuuSokunCAxUl5N4gjN/M7+NwJPm2JtYK
# ZLBdH5J/y+GIk7rQhpgbstpLOZf4GHgC8Myji7089O1uX2MCKFFU+wt2Y560O4Xc
# 2NVjeuG+nnq5pGyq9111nK3f0DeT7FWjDVQWFghKOhyeBb4iMhmkdA8vWpYmx6TN
# c+d35nSZcLc0EhSIVJkzEBYfwkrzxFaG/pgNJ9C4jm/zHgwWLZwQpU7K2fP15fGk
# BGplwNjr1wIDAQABo4IBCTCCAQUwHQYDVR0OBBYEFA4B9X87yXgCWEZxOwn8mnVX
# hjjEMB8GA1UdIwQYMBaAFCM0+NlSRnAK7UD7dvuzK7DDNbMPMFQGA1UdHwRNMEsw
# SaBHoEWGQ2h0dHA6Ly9jcmwubWljcm9zb2Z0LmNvbS9wa2kvY3JsL3Byb2R1Y3Rz
# L01pY3Jvc29mdFRpbWVTdGFtcFBDQS5jcmwwWAYIKwYBBQUHAQEETDBKMEgGCCsG
# AQUFBzAChjxodHRwOi8vd3d3Lm1pY3Jvc29mdC5jb20vcGtpL2NlcnRzL01pY3Jv
# c29mdFRpbWVTdGFtcFBDQS5jcnQwEwYDVR0lBAwwCgYIKwYBBQUHAwgwDQYJKoZI
# hvcNAQEFBQADggEBAAUS3tgSEzCpyuw21ySUAWvGltQxunyLUCaOf1dffUcG25oa
# OW/WuIFJs0lv8Py6TsOrulsx/4NTkIyXra/MsJvwczMX2s/vx6g63O3osQI85qHD
# dp8IMULGmry+oqPVTuvL7Bac905EqqGXGd9UY7y14FcKWBWJ28vjncTw8CW876pY
# 80nSm8hC/38M4RMGNEp7KGYxx5ZgGX3NpAVeUBio7XccXHEy7CSNmXm2V8ijeuGZ
# J9fIMkhiAWLEfKOgxGZ63s5yGwpMt2QE/6Py03uF+X2DHK76w3FQghqiUNPFC7uU
# o9poSfArmeLDuspkPAJ46db02bqNyRLP00bczzwwggYHMIID76ADAgECAgphFmg0
# AAAAAAAcMA0GCSqGSIb3DQEBBQUAMF8xEzARBgoJkiaJk/IsZAEZFgNjb20xGTAX
# BgoJkiaJk/IsZAEZFgltaWNyb3NvZnQxLTArBgNVBAMTJE1pY3Jvc29mdCBSb290
# IENlcnRpZmljYXRlIEF1dGhvcml0eTAeFw0wNzA0MDMxMjUzMDlaFw0yMTA0MDMx
# MzAzMDlaMHcxCzAJBgNVBAYTAlVTMRMwEQYDVQQIEwpXYXNoaW5ndG9uMRAwDgYD
# VQQHEwdSZWRtb25kMR4wHAYDVQQKExVNaWNyb3NvZnQgQ29ycG9yYXRpb24xITAf
# BgNVBAMTGE1pY3Jvc29mdCBUaW1lLVN0YW1wIFBDQTCCASIwDQYJKoZIhvcNAQEB
# BQADggEPADCCAQoCggEBAJ+hbLHf20iSKnxrLhnhveLjxZlRI1Ctzt0YTiQP7tGn
# 0UytdDAgEesH1VSVFUmUG0KSrphcMCbaAGvoe73siQcP9w4EmPCJzB/LMySHnfL0
# Zxws/HvniB3q506jocEjU8qN+kXPCdBer9CwQgSi+aZsk2fXKNxGU7CG0OUoRi4n
# rIZPVVIM5AMs+2qQkDBuh/NZMJ36ftaXs+ghl3740hPzCLdTbVK0RZCfSABKR2YR
# JylmqJfk0waBSqL5hKcRRxQJgp+E7VV4/gGaHVAIhQAQMEbtt94jRrvELVSfrx54
# QTF3zJvfO4OToWECtR0Nsfz3m7IBziJLVP/5BcPCIAsCAwEAAaOCAaswggGnMA8G
# A1UdEwEB/wQFMAMBAf8wHQYDVR0OBBYEFCM0+NlSRnAK7UD7dvuzK7DDNbMPMAsG
# A1UdDwQEAwIBhjAQBgkrBgEEAYI3FQEEAwIBADCBmAYDVR0jBIGQMIGNgBQOrIJg
# QFYnl+UlE/wq4QpTlVnkpKFjpGEwXzETMBEGCgmSJomT8ixkARkWA2NvbTEZMBcG
# CgmSJomT8ixkARkWCW1pY3Jvc29mdDEtMCsGA1UEAxMkTWljcm9zb2Z0IFJvb3Qg
# Q2VydGlmaWNhdGUgQXV0aG9yaXR5ghB5rRahSqClrUxzWPQHEy5lMFAGA1UdHwRJ
# MEcwRaBDoEGGP2h0dHA6Ly9jcmwubWljcm9zb2Z0LmNvbS9wa2kvY3JsL3Byb2R1
# Y3RzL21pY3Jvc29mdHJvb3RjZXJ0LmNybDBUBggrBgEFBQcBAQRIMEYwRAYIKwYB
# BQUHMAKGOGh0dHA6Ly93d3cubWljcm9zb2Z0LmNvbS9wa2kvY2VydHMvTWljcm9z
# b2Z0Um9vdENlcnQuY3J0MBMGA1UdJQQMMAoGCCsGAQUFBwMIMA0GCSqGSIb3DQEB
# BQUAA4ICAQAQl4rDXANENt3ptK132855UU0BsS50cVttDBOrzr57j7gu1BKijG1i
# uFcCy04gE1CZ3XpA4le7r1iaHOEdAYasu3jyi9DsOwHu4r6PCgXIjUji8FMV3U+r
# kuTnjWrVgMHmlPIGL4UD6ZEqJCJw+/b85HiZLg33B+JwvBhOnY5rCnKVuKE5nGct
# xVEO6mJcPxaYiyA/4gcaMvnMMUp2MT0rcgvI6nA9/4UKE9/CCmGO8Ne4F+tOi3/F
# NSteo7/rvH0LQnvUU3Ih7jDKu3hlXFsBFwoUDtLaFJj1PLlmWLMtL+f5hYbMUVbo
# nXCUbKw5TNT2eb+qGHpiKe+imyk0BncaYsk9Hm0fgvALxyy7z0Oz5fnsfbXjpKh0
# NbhOxXEjEiZ2CzxSjHFaRkMUvLOzsE1nyJ9C/4B5IYCeFTBm6EISXhrIniIh0EPp
# K+m79EjMLNTYMoBMJipIJF9a6lbvpt6Znco6b72BJ3QGEe52Ib+bgsEnVLaxaj2J
# oXZhtG6hE6a/qkfwEm/9ijJssv7fUciMI8lmvZ0dhxJkAj0tr1mPuOQh5bWwymO0
# eFQF1EEuUKyUsKV4q7OglnUa2ZKHE3UiLzKoCG6gW4wlv6DvhMoh1useT8ma7kng
# 9wFlb4kLfchpyOZu6qeXzjEp/w7FW1zYTRuh2Povnj8uVRZryROj/TCCBhEwggP5
# oAMCAQICEzMAAACOh5GkVxpfyj4AAAAAAI4wDQYJKoZIhvcNAQELBQAwfjELMAkG
# A1UEBhMCVVMxEzARBgNVBAgTCldhc2hpbmd0b24xEDAOBgNVBAcTB1JlZG1vbmQx
# HjAcBgNVBAoTFU1pY3Jvc29mdCBDb3Jwb3JhdGlvbjEoMCYGA1UEAxMfTWljcm9z
# b2Z0IENvZGUgU2lnbmluZyBQQ0EgMjAxMTAeFw0xNjExMTcyMjA5MjFaFw0xODAy
# MTcyMjA5MjFaMIGDMQswCQYDVQQGEwJVUzETMBEGA1UECBMKV2FzaGluZ3RvbjEQ
# MA4GA1UEBxMHUmVkbW9uZDEeMBwGA1UEChMVTWljcm9zb2Z0IENvcnBvcmF0aW9u
# MQ0wCwYDVQQLEwRNT1BSMR4wHAYDVQQDExVNaWNyb3NvZnQgQ29ycG9yYXRpb24w
# ggEiMA0GCSqGSIb3DQEBAQUAA4IBDwAwggEKAoIBAQDQh9RCK36d2cZ61KLD4xWS
# 0lOdlRfJUjb6VL+rEK/pyefMJlPDwnO/bdYA5QDc6WpnNDD2Fhe0AaWVfIu5pCzm
# izt59iMMeY/zUt9AARzCxgOd61nPc+nYcTmb8M4lWS3SyVsK737WMg5ddBIE7J4E
# U6ZrAmf4TVmLd+ArIeDvwKRFEs8DewPGOcPUItxVXHdC/5yy5VVnaLotdmp/ZlNH
# 1UcKzDjejXuXGX2C0Cb4pY7lofBeZBDk+esnxvLgCNAN8mfA2PIv+4naFfmuDz4A
# lwfRCz5w1HercnhBmAe4F8yisV/svfNQZ6PXlPDSi1WPU6aVk+ayZs/JN2jkY8fP
# AgMBAAGjggGAMIIBfDAfBgNVHSUEGDAWBgorBgEEAYI3TAgBBggrBgEFBQcDAzAd
# BgNVHQ4EFgQUq8jW7bIV0qqO8cztbDj3RUrQirswUgYDVR0RBEswSaRHMEUxDTAL
# BgNVBAsTBE1PUFIxNDAyBgNVBAUTKzIzMDAxMitiMDUwYzZlNy03NjQxLTQ0MWYt
# YmM0YS00MzQ4MWU0MTVkMDgwHwYDVR0jBBgwFoAUSG5k5VAF04KqFzc3IrVtqMp1
# ApUwVAYDVR0fBE0wSzBJoEegRYZDaHR0cDovL3d3dy5taWNyb3NvZnQuY29tL3Br
# aW9wcy9jcmwvTWljQ29kU2lnUENBMjAxMV8yMDExLTA3LTA4LmNybDBhBggrBgEF
# BQcBAQRVMFMwUQYIKwYBBQUHMAKGRWh0dHA6Ly93d3cubWljcm9zb2Z0LmNvbS9w
# a2lvcHMvY2VydHMvTWljQ29kU2lnUENBMjAxMV8yMDExLTA3LTA4LmNydDAMBgNV
# HRMBAf8EAjAAMA0GCSqGSIb3DQEBCwUAA4ICAQBEiQKsaVPzxLa71IxgU+fKbKhJ
# aWa+pZpBmTrYndJXAlFq+r+bltumJn0JVujc7SV1eqVHUqgeSxZT8+4PmsMElSnB
# goSkVjH8oIqRlbW/Ws6pAR9kRqHmyvHXdHu/kghRXnwzAl5RO5vl2C5fAkwJnBpD
# 2nHt5Nnnotp0LBet5Qy1GPVUCdS+HHPNIHuk+sjb2Ns6rvqQxaO9lWWuRi1XKVjW
# kvBs2mPxjzOifjh2Xt3zNe2smjtigdBOGXxIfLALjzjMLbzVOWWplcED4pLJuavS
# Vwqq3FILLlYno+KYl1eOvKlZbiSSjoLiCXOC2TWDzJ9/0QSOiLjimoNYsNSa5jH6
# lEeOfabiTnnz2NNqMxZQcPFCu5gJ6f/MlVVbCL+SUqgIxPHo8f9A1/maNp39upCF
# 0lU+UK1GH+8lDLieOkgEY+94mKJdAw0C2Nwgq+ZWtd7vFmbD11WCHk+CeMmeVBoQ
# YLcXq0ATka6wGcGaM53uMnLNZcxPRpgtD1FgHnz7/tvoB3kH96EzOP4JmtuPe7Y6
# vYWGuMy8fQEwt3sdqV0bvcxNF/duRzPVQN9qyi5RuLW5z8ME0zvl4+kQjOunut6k
# LjNqKS8USuoewSI4NQWF78IEAA1rwdiWFEgVr35SsLhgxFK1SoK3hSoASSomgyda
# Qd691WZJvAuceHAJvDCCB3owggVioAMCAQICCmEOkNIAAAAAAAMwDQYJKoZIhvcN
# AQELBQAwgYgxCzAJBgNVBAYTAlVTMRMwEQYDVQQIEwpXYXNoaW5ndG9uMRAwDgYD
# VQQHEwdSZWRtb25kMR4wHAYDVQQKExVNaWNyb3NvZnQgQ29ycG9yYXRpb24xMjAw
# BgNVBAMTKU1pY3Jvc29mdCBSb290IENlcnRpZmljYXRlIEF1dGhvcml0eSAyMDEx
# MB4XDTExMDcwODIwNTkwOVoXDTI2MDcwODIxMDkwOVowfjELMAkGA1UEBhMCVVMx
# EzARBgNVBAgTCldhc2hpbmd0b24xEDAOBgNVBAcTB1JlZG1vbmQxHjAcBgNVBAoT
# FU1pY3Jvc29mdCBDb3Jwb3JhdGlvbjEoMCYGA1UEAxMfTWljcm9zb2Z0IENvZGUg
# U2lnbmluZyBQQ0EgMjAxMTCCAiIwDQYJKoZIhvcNAQEBBQADggIPADCCAgoCggIB
# AKvw+nIQHC6t2G6qghBNNLrytlghn0IbKmvpWlCquAY4GgRJun/DDB7dN2vGEtgL
# 8DjCmQawyDnVARQxQtOJDXlkh36UYCRsr55JnOloXtLfm1OyCizDr9mpK656Ca/X
# llnKYBoF6WZ26DJSJhIv56sIUM+zRLdd2MQuA3WraPPLbfM6XKEW9Ea64DhkrG5k
# NXimoGMPLdNAk/jj3gcN1Vx5pUkp5w2+oBN3vpQ97/vjK1oQH01WKKJ6cuASOrdJ
# Xtjt7UORg9l7snuGG9k+sYxd6IlPhBryoS9Z5JA7La4zWMW3Pv4y07MDPbGyr5I4
# ftKdgCz1TlaRITUlwzluZH9TupwPrRkjhMv0ugOGjfdf8NBSv4yUh7zAIXQlXxgo
# tswnKDglmDlKNs98sZKuHCOnqWbsYR9q4ShJnV+I4iVd0yFLPlLEtVc/JAPw0Xpb
# L9Uj43BdD1FGd7P4AOG8rAKCX9vAFbO9G9RVS+c5oQ/pI0m8GLhEfEXkwcNyeuBy
# 5yTfv0aZxe/CHFfbg43sTUkwp6uO3+xbn6/83bBm4sGXgXvt1u1L50kppxMopqd9
# Z4DmimJ4X7IvhNdXnFy/dygo8e1twyiPLI9AN0/B4YVEicQJTMXUpUMvdJX3bvh4
# IFgsE11glZo+TzOE2rCIF96eTvSWsLxGoGyY0uDWiIwLAgMBAAGjggHtMIIB6TAQ
# BgkrBgEEAYI3FQEEAwIBADAdBgNVHQ4EFgQUSG5k5VAF04KqFzc3IrVtqMp1ApUw
# GQYJKwYBBAGCNxQCBAweCgBTAHUAYgBDAEEwCwYDVR0PBAQDAgGGMA8GA1UdEwEB
# /wQFMAMBAf8wHwYDVR0jBBgwFoAUci06AjGQQ7kUBU7h6qfHMdEjiTQwWgYDVR0f
# BFMwUTBPoE2gS4ZJaHR0cDovL2NybC5taWNyb3NvZnQuY29tL3BraS9jcmwvcHJv
# ZHVjdHMvTWljUm9vQ2VyQXV0MjAxMV8yMDExXzAzXzIyLmNybDBeBggrBgEFBQcB
# AQRSMFAwTgYIKwYBBQUHMAKGQmh0dHA6Ly93d3cubWljcm9zb2Z0LmNvbS9wa2kv
# Y2VydHMvTWljUm9vQ2VyQXV0MjAxMV8yMDExXzAzXzIyLmNydDCBnwYDVR0gBIGX
# MIGUMIGRBgkrBgEEAYI3LgMwgYMwPwYIKwYBBQUHAgEWM2h0dHA6Ly93d3cubWlj
# cm9zb2Z0LmNvbS9wa2lvcHMvZG9jcy9wcmltYXJ5Y3BzLmh0bTBABggrBgEFBQcC
# AjA0HjIgHQBMAGUAZwBhAGwAXwBwAG8AbABpAGMAeQBfAHMAdABhAHQAZQBtAGUA
# bgB0AC4gHTANBgkqhkiG9w0BAQsFAAOCAgEAZ/KGpZjgVHkaLtPYdGcimwuWEeFj
# kplCln3SeQyQwWVfLiw++MNy0W2D/r4/6ArKO79HqaPzadtjvyI1pZddZYSQfYtG
# UFXYDJJ80hpLHPM8QotS0LD9a+M+By4pm+Y9G6XUtR13lDni6WTJRD14eiPzE32m
# kHSDjfTLJgJGKsKKELukqQUMm+1o+mgulaAqPyprWEljHwlpblqYluSD9MCP80Yr
# 3vw70L01724lruWvJ+3Q3fMOr5kol5hNDj0L8giJ1h/DMhji8MUtzluetEk5CsYK
# wsatruWy2dsViFFFWDgycScaf7H0J/jeLDogaZiyWYlobm+nt3TDQAUGpgEqKD6C
# PxNNZgvAs0314Y9/HG8VfUWnduVAKmWjw11SYobDHWM2l4bf2vP48hahmifhzaWX
# 0O5dY0HjWwechz4GdwbRBrF1HxS+YWG18NzGGwS+30HHDiju3mUv7Jf2oVyW2ADW
# oUa9WfOXpQlLSBCZgB/QACnFsZulP0V3HjXG0qKin3p6IvpIlR+r+0cjgPWe+L9r
# t0uX4ut1eBrs6jeZeRhL/9azI2h15q/6/IvrC4DqaTuv/DDtBEyO3991bWORPdGd
# Vk5Pv4BXIqF4ETIheu9BCrE/+6jMpF3BoYibV3FWTkhFwELJm3ZbCoBIa/15n8G9
# bW1qyVJzEw16UM0xggSiMIIEngIBATCBlTB+MQswCQYDVQQGEwJVUzETMBEGA1UE
# CBMKV2FzaGluZ3RvbjEQMA4GA1UEBxMHUmVkbW9uZDEeMBwGA1UEChMVTWljcm9z
# b2Z0IENvcnBvcmF0aW9uMSgwJgYDVQQDEx9NaWNyb3NvZnQgQ29kZSBTaWduaW5n
# IFBDQSAyMDExAhMzAAAAjoeRpFcaX8o+AAAAAACOMAkGBSsOAwIaBQCggbYwGQYJ
# KoZIhvcNAQkDMQwGCisGAQQBgjcCAQQwHAYKKwYBBAGCNwIBCzEOMAwGCisGAQQB
# gjcCARUwIwYJKoZIhvcNAQkEMRYEFEPC5yWrgY0FgwXII9ywv27bPM6bMFYGCisG
# AQQBgjcCAQwxSDBGoCSAIgBNAGkAYwByAG8AcwBvAGYAdAAgAFcAaQBuAGQAbwB3
# AHOhHoAcaHR0cHM6Ly9henVyZS5taWNyb3NvZnQuY29tLzANBgkqhkiG9w0BAQEF
# AASCAQBj3iKygtG92XCQ+2U8R8NXwGnSFIp77DPjQxVlHwbZ8HinAaffsuAijx8A
# Ee11AuYtWhcXGOtaU1K21dZYT9RcMRkgdNprBVnRru1rBu8IOCt3F8MvUaHHUKjw
# XrQFqZUI0a0AhA4KP8ZL0+V5dQ7/pLNXzJW4YX//RwXhhLp74O2lMe5tB9ThdmM8
# gbLqehhlvsevUTDrbKUF8r4el8jzU2v+fP/XUAYCoz6lTy4GjxCnAkxWRusq/QNL
# vzsNU0G1LPlOskojRthjHvhvMuAheNtGJYxtS53UAEoEUu3jT1W3GzUO0smLthUf
# mjXlY5telMTK1aSuiTohB1kog8jJoYICKDCCAiQGCSqGSIb3DQEJBjGCAhUwggIR
# AgEBMIGOMHcxCzAJBgNVBAYTAlVTMRMwEQYDVQQIEwpXYXNoaW5ndG9uMRAwDgYD
# VQQHEwdSZWRtb25kMR4wHAYDVQQKExVNaWNyb3NvZnQgQ29ycG9yYXRpb24xITAf
# BgNVBAMTGE1pY3Jvc29mdCBUaW1lLVN0YW1wIFBDQQITMwAAAMWWQGBL9N6uLgAA
# AAAAxTAJBgUrDgMCGgUAoF0wGAYJKoZIhvcNAQkDMQsGCSqGSIb3DQEHATAcBgkq
# hkiG9w0BCQUxDxcNMTcwNDEwMjA0NDAwWjAjBgkqhkiG9w0BCQQxFgQUqrteAg5a
# PaHdvZeOpzfGr7rtrWowDQYJKoZIhvcNAQEFBQAEggEAceBceLmKOgEJROjsRtYo
# Am5XeHNgOqukvB9mL+Ai4qucnudL5JF8xOUaZG2q3WKGSzmqAi+tIKMqqgIlrla8
# W3StMKankg1WNP2ufNg/XcLn06pDSWsrNjFUemu1zWq+2uhCTjhD40pGuj01tdoC
# i+8lpbs/7W/MLfMyq9ggcaB1N5WSbbtY7mDUsbIBG9vJzkD/H08qLsOvywLBELBX
# eu9WLV1MoDXpChZCPDu+uoiJlB7QNC0a6J+3t6gjk2kkak+aUJPH18iKzuFQuXIV
# kTJ87A4XRHRotukY1WIPhkebq236B7kEvmvufTe003sPOi4EFKm29GXkddLtHuoX
# 6Q==
# SIG # End signature block
