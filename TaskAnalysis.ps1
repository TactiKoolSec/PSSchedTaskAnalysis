Import-Module ActiveDirectory
$CompsToCheck = Get-ADComputer -Filter * 
$ToMatchEnvs = @("%ALLUSERSPROFILE%","%APPDATA%","%CommonProgramFiles%","%CommonProgramFiles(x86)%","%CommonProgramW6432%","%ComSpec%","%DriverData%","%HOMEDRIVE%","%HOMEPATH%","%IntelliJ IDEA%","%JAVA_HOME%","%LOCALAPPDATA%","%LOGONSERVER%","%OneDrive%","%ProgramData%","%ProgramFiles%","%ProgramFiles(x86)%","%ProgramW6432%","%PSModulePath%","%PUBLIC%","%SESSIONNAME%","%SystemDrive%","%SystemRoot%","%TEMP%","%TMP%","%USERDOMAIN%","%USERDOMAIN_ROAMINGPROFILE%","%USERNAME%","%USERPROFILE%","%VBOX_MSI_INSTALL_PATH%","%VS140COMNTOOLS%","%windir%")
$AllHashes=@()

#Example 1
<#
foreach($comp in $CompsToCheck)
{
     $tasks = Get-ScheduledTask -CimSession $comp.Name
     foreach ($task in $tasks)
     {
        
        $taskaction = $task.Actions.Execute
        if ($taskaction)
        {
            if($taskaction -match ($ToMatchEnvs -join '|'))
            {
                $convertpath = cmd.exe /c echo $taskaction
                $session = New-PSSession -ComputerName $comp.Name
              
                if($convertpath)
                {
                write-host "converted"
                write-host $convertpath
                $hash = Invoke-Command -Session $session -ScriptBlock {Get-FileHash -path $($args[0]) -Algorithm MD5} -ArgumentList $convertpath
                $HashObject = new-object psobject
                $HashObject | Add-Member -MemberType NoteProperty -Name "ComputerName" -Value $session.ComputerName
                $HashObject | Add-Member -MemberType NoteProperty -Name "Hash" -Value $hash.Hash
                $AllHashes += $HashObject
                }
            }
            else
            {
                $session = New-PSSession -ComputerName $comp.Name
                write-host "not converted"
                write-host $taskaction
                $hash = Invoke-Command -Session $session -ScriptBlock {Get-FileHash -path $($args[0]) -Algorithm MD5} -ArgumentList $taskaction
                $HashObject = new-object psobject
                $HashObject | Add-Member -MemberType NoteProperty -Name "ComputerName" -Value $session.ComputerName
                $HashObject | Add-Member -MemberType NoteProperty -Name "Hash" -Value $hash.Hash
                $AllHashes += $HashObject
            }
        }
     }
}

$AllHashes | Export-csv -NoTypeInformation .\hash.csv
#>
#Example 2
<#
$AllTasks = @()
foreach($comp in $CompsToCheck)
{
     $tasks = Get-ScheduledTask -CimSession $comp.Name
     foreach ($task in $tasks)
     {
        
        $taskaction = $task.Actions.Execute
        $taskargs = $task.Actions.Arguments
        if ($taskaction)
        {
            if($taskaction -match ($ToMatchEnvs -join '|'))
            {
                $convertpath = cmd.exe /c echo $taskaction
                $TaskObject = new-object psobject
                $TaskObject | Add-Member -MemberType NoteProperty -Name "ComputerName" -Value $comp.Name
                $TaskObject | Add-Member -MemberType NoteProperty -Name "Action" -Value $convertpath
                $TaskObject | Add-Member -MemberType NoteProperty -Name "Arguments" -Value $taskargs
                $AllTasks += $TaskObject
            }
            else
            {
                $TaskObject = new-object psobject
                $TaskObject | Add-Member -MemberType NoteProperty -Name "ComputerName" -Value $comp.Name
                $TaskObject | Add-Member -MemberType NoteProperty -Name "Action" -Value $taskaction
                $TaskObject | Add-Member -MemberType NoteProperty -Name "Arguments" -Value $taskargs
                $AllTasks += $TaskObject
            }
        }
     }
}
write-host "Stacking by path of Task Action"
$AllTasks.GetEnumerator() | group Action | Select Count,Name | Sort-Object @{expression = 'Count';descending=$false}, @{expression = 'Name';descending = $true}

#>

#Example 3

$LOLBins = @("AppInstaller.exe","Aspnet_Compiler.exe","At.exe","Atbroker.exe","Bash.exe","Bitsadmin.exe","CertOC.exe","CertReq.exe","Certutil.exe","Cmd.exe","Cmdkey.exe","cmdl32.exe","Cmstp.exe","ConfigSecurityPolicy.exe","Conhost.exe","Control.exe","Csc.exe","Cscript.exe","CustomShellHost.exe","DataSvcUtil.exe","Desktopimgdownldr.exe","DeviceCredentialDeployment.exe","Dfsvc.exe","Diantz.exe","Diskshadow.exe","Dnscmd.exe","Esentutl.exe","Eventvwr.exe","Expand.exe","Explorer.exe","Extexport.exe","Extrac32.exe","Findstr.exe","Finger.exe","fltMC.exe","Forfiles.exe","Ftp.exe","GfxDownloadWrapper.exe","Gpscript.exe","Hh.exe","IMEWDBLD.exe","Ie4uinit.exe","Ieexec.exe","Ilasm.exe","Infdefaultinstall.exe","Installutil.exe","Jsc.exe","Ldifde.exe","Makecab.exe","Mavinject.exe","Microsoft.Workflow.Compiler.exe","Mmc.exe","MpCmdRun.exe","Msbuild.exe","Msconfig.exe","Msdt.exe","Mshta.exe","Msiexec.exe","Netsh.exe","Odbcconf.exe","OfflineScannerShell.exe","OneDriveStandaloneUpdater.exe","Pcalua.exe","Pcwrun.exe","Pktmon.exe","Pnputil.exe","Presentationhost.exe","Print.exe","PrintBrm.exe","Psr.exe","Rasautou.exe","rdrleakdiag.exe","Reg.exe","Regasm.exe","Regedit.exe","Regini.exe","Register-cimprovider.exe","Regsvcs.exe","Regsvr32.exe","Replace.exe","Rpcping.exe","Rundll32.exe","Runonce.exe","Runscripthelper.exe","Sc.exe","Schtasks.exe","Scriptrunner.exe","Setres.exe","SettingSyncHost.exe","ssh.exe","Stordiag.exe","SyncAppvPublishingServer.exe","Ttdinject.exe","Tttracer.exe","Unregmp2.exe","vbc.exe","Verclsid.exe","Wab.exe","winget.exe","Wlrmdr.exe","Wmic.exe","WorkFolders.exe","Wscript.exe","Wsreset.exe","wuauclt.exe","Xwizard.exe","fsutil.exe","wt.exe","Advpack.dll","Desk.cpl","Dfshim.dll","Ieadvpack.dll","Ieframe.dll","Mshtml.dll","Pcwutl.dll","Setupapi.dll","Shdocvw.dll","Shell32.dll","Syssetup.dll","Url.dll","Zipfldr.dll","Comsvcs.dll","AccCheckConsole.exe","adplus.exe","AgentExecutor.exe","Appvlp.exe","Bginfo.exe","Cdb.exe","coregen.exe","Createdump.exe","csi.exe","DefaultPack.EXE","Devtoolslauncher.exe","dnx.exe","Dotnet.exe","Dump64.exe","Dxcap.exe","Excel.exe","Fsi.exe","FsiAnyCpu.exe","Mftrace.exe","Msdeploy.exe","MsoHtmEd.exe","Mspub.exe","msxsl.exe","ntdsutil.exe","OpenConsole.exe","Powerpnt.exe","Procdump.exe","ProtocolHandler.exe","rcsi.exe","Remote.exe","Sqldumper.exe","Sqlps.exe","SQLToolsPS.exe","Squirrel.exe","te.exe","Tracker.exe","Update.exe","VSIISExeLauncher.exe","VisualUiaVerifyNative.exe","vsjitdebugger.exe","Wfc.exe","Winword.exe","Wsl.exe","CL_LoadAssembly.ps1","CL_Mutexverifiers.ps1","CL_Invocation.ps1","Launch-VsDevShell.ps1","Manage-bde.wsf","Pubprn.vbs","Syncappvpublishingserver.vbs","UtilityFunctions.ps1","winrm.vbs","Pester.bat")
$AllLOLBins = @()
foreach($ArgCheck in $AllTasks)
{
    if($ArgCheck.Action -match ($LOLBins -join '|'))
    {
        $yeet = $ArgCheck.Action + ' ' + $ArgCheck.Arguments
        $LOLBinObject = new-object psobject
        $LOLBinObject | Add-Member -MemberType NoteProperty -Name "LOLBin" -Value $yeet
        $AllLOLBins += $LOLBinObject
    }
}
write-host "Stacking by path of Task Arguments"
$AllLOLBins.GetEnumerator() | group LOLBin| Select Count,Name | Sort-Object @{expression = 'Count';descending=$false}, @{expression = 'Name';descending = $true}

#>