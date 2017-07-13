<PROLOGUE>
<![CDATA[

]]>
</PROLOGUE>


<KSID>
  <Type>Regular</Type>
  <Name>AzureAD_DevicesCheck</Name>
  <Desc>Monitors the Devices in Azure Active Directory. The KS monitor the state and health of Devices </Desc>
  <Version>
    <AppManID>7.6.108.0</AppManID>
    <KSVerID>1.2</KSVerID>
  </Version>
  <NeedPWD>0</NeedPWD>
  <AdminOnly>0</AdminOnly>
  <UnixOnly>0</UnixOnly>
  <DataSrcID>0</DataSrcID>
  <Platform>-1</Platform>
  <OptionExplicit>0</OptionExplicit>
</KSID>

<ObjType fullpath="1" dropfolderlist="0" styleversion="4">
  <Type name="AzureAD_Devices"></Type>
</ObjType>

<Schedule>
  <Default type="interval" runmode="sched">
    <Interval>
      <Hour>0</Hour>
      <Minute>5</Minute>
      <Second>0</Second>
    </Interval>
  </Default>
  <Allowed>
    <RunOnce>1</RunOnce>
    <IntervalIter>1</IntervalIter>
    <Daily>1</Daily>
    <Weekly>1</Weekly>
    <Monthly>1</Monthly>
  </Allowed>
</Schedule>

<DataSrc></DataSrc>

<Parameter>
  <Desc>Monitors the Devices in Azure Active Directory. The KS monitor the state and health of devices synced/added in Azure AD Account.</Desc>
  <Param name="FDR_GeneralSettings">
    <Desc>General Settings</Desc>
    <ReqInput>0</ReqInput>
    <Folder>2</Folder>
    <NoQuote>0</NoQuote>
  </Param>
  <Param name="FDR_EventFail">
    <Desc>Job failure event notification</Desc>
    <ReqInput>0</ReqInput>
    <Parent>FDR_GeneralSettings</Parent>
    <Folder>2</Folder>
    <NoQuote>0</NoQuote>
  </Param>
  <Param name="PRM_SeverityFail">
    <Desc>Event severity when job fails</Desc>
    <Type>Integer</Type>
    <Min>1</Min>
    <Max>40</Max>
    <Value>5</Value>
    <Unit>Severity</Unit>
    <ReqInput>1</ReqInput>
    <I_Type>I_SPIN</I_Type>
    <Parent>FDR_EventFail</Parent>
    <Folder>0</Folder>
    <NoQuote>0</NoQuote>
  </Param>
  <Param name="FDR_AzureADDevices">
    <Desc>Azure AD Devices Event Notification</Desc>
    <ReqInput>1</ReqInput>
    <Folder>2</Folder>
    <NoQuote>0</NoQuote>
  </Param>
  <Param name="FDR_DevicesCount">
    <Desc>Devices count event settings</Desc>
    <ReqInput>1</ReqInput>
    <Folder>2</Folder>
    <NoQuote>0</NoQuote>
  </Param>
  <Param name="PRM_Devices_Crossed_TH">
    <Desc>Raise event if number of Devices exceeds threshold?</Desc>
    <Value>y</Value>
    <ReqInput>1</ReqInput>
    <I_Type>I_CHECKBOX("Yes","y","n")</I_Type>
    <Parent>FDR_DevicesCount</Parent>
    <Folder>1</Folder>
    <NoQuote>0</NoQuote>
  </Param>
  <Param name="PRM_Devices_Count_Threshold">
    <Desc>Set threshold for number of Devices</Desc>
    <Type>Integer</Type>
    <Min>0</Min>
    <Max>500</Max>
    <Value>0</Value>
    <Unit>Integer</Unit>
    <ReqInput>1</ReqInput>
    <I_Type>I_SPIN</I_Type>
    <Parent>PRM_Devices_Crossed_TH</Parent>
    <Folder>0</Folder>
    <NoQuote>0</NoQuote>
  </Param>
  <Param name="PRM_Devices_TH_EventSeverity">
    <Desc>Event severity when number of Devices exceeds the threshold</Desc>
    <Type>Integer</Type>
    <Min>1</Min>
    <Max>40</Max>
    <Value>5</Value>
    <Unit>Severity</Unit>
    <ReqInput>1</ReqInput>
    <I_Type>I_SPIN</I_Type>
    <Parent>PRM_Devices_Crossed_TH</Parent>
    <Folder>0</Folder>
    <NoQuote>0</NoQuote>
  </Param>
  <Param name="FDR_DevicesStatus">
    <Desc>System AD Device's Directory Sync state event settings</Desc>
    <ReqInput>1</ReqInput>
    <Folder>2</Folder>
    <NoQuote>0</NoQuote>
  </Param>
  <Param name="PRM_SysAD_Devices_Sync_Status">
    <Desc>Raise event if System AD device's Dir Sync Status is disabled</Desc>
    <Value>y</Value>
    <ReqInput>1</ReqInput>
    <I_Type>I_CHECKBOX("Yes","y","n")</I_Type>
    <Parent>FDR_DevicesStatus</Parent>
    <Folder>1</Folder>
    <NoQuote>0</NoQuote>
  </Param>
  <Param name="PRM_SysAD_Devices_Sync_Status_EventSeverity">
    <Desc>Event severity when System AD device's Dir Sync Status is disabled</Desc>
    <Type>Integer</Type>
    <Min>1</Min>
    <Max>40</Max>
    <Value>5</Value>
    <Unit>Severity</Unit>
    <ReqInput>1</ReqInput>
    <I_Type>I_SPIN</I_Type>
    <Parent>PRM_SysAD_Devices_Sync_Status</Parent>
    <Folder>0</Folder>
    <NoQuote>0</NoQuote>
  </Param>
  <Param name="FDR_NewDevice">
    <Desc>New Devices event settings</Desc>
    <ReqInput>1</ReqInput>
    <Folder>2</Folder>
    <NoQuote>0</NoQuote>
  </Param>
  <Param name="PRM_Devices_New">
    <Desc>Raise event if any new device is added/synced in Azure AD</Desc>
    <Value>y</Value>
    <ReqInput>1</ReqInput>
    <I_Type>I_CHECKBOX("Yes","y","n")</I_Type>
    <Parent>FDR_NewDevice</Parent>
    <Folder>1</Folder>
    <NoQuote>0</NoQuote>
  </Param>
  <Param name="PRM_Devices_New_EventSeverity">
    <Desc>Event severity when any new device is added/synced in Azure AD</Desc>
    <Type>Integer</Type>
    <Min>1</Min>
    <Max>40</Max>
    <Value>15</Value>
    <Unit>Severity</Unit>
    <ReqInput>1</ReqInput>
    <I_Type>I_SPIN</I_Type>
    <Parent>FDR_NewDevice</Parent>
    <Folder>0</Folder>
    <NoQuote>0</NoQuote>
  </Param>
  <Param name="FDR_DeleteDevice">
    <Desc>Deleted Devices event settings</Desc>
    <ReqInput>1</ReqInput>
    <Folder>2</Folder>
    <NoQuote>0</NoQuote>
  </Param>
  <Param name="PRM_Devices_Delete">
    <Desc>Raise event if any device is deleted in Azure AD</Desc>
    <Value>y</Value>
    <ReqInput>1</ReqInput>
    <I_Type>I_CHECKBOX("Yes","y","n")</I_Type>
    <Parent>FDR_DeleteDevice</Parent>
    <Folder>1</Folder>
    <NoQuote>0</NoQuote>
  </Param>
  <Param name="PRM_Devices_Delete_EventSeverity">
    <Desc>Event severity when any  device is deleted in Azure AD</Desc>
    <Type>Integer</Type>
    <Min>1</Min>
    <Max>40</Max>
    <Value>15</Value>
    <Unit>Severity</Unit>
    <ReqInput>1</ReqInput>
    <I_Type>I_SPIN</I_Type>
    <Parent>FDR_DeleteDevice</Parent>
    <Folder>0</Folder>
    <NoQuote>0</NoQuote>
  </Param>
  <Param name="FDR_EnvironmentInfo">
    <Desc>Execution Environment</Desc>
    <ReqInput>1</ReqInput>
    <I_Type>I_HIDDEN(0)</I_Type>
    <Folder>2</Folder>
    <NoQuote>0</NoQuote>
  </Param>
  <Param name="PRM_RequiredBitness">
    <Desc>Required CPU architecture for command execution</Desc>
    <Value>64</Value>
    <ReqInput>1</ReqInput>
    <I_Type>I_HIDDEN(0)</I_Type>
    <Parent>FDR_EnvironmentInfo</Parent>
    <Folder>0</Folder>
    <NoQuote>0</NoQuote>
  </Param>
  <Param name="PRM_HostSharing">
    <Desc>Allow other jobs to execute in the same PowerShell server?</Desc>
    <Value>Yes</Value>
    <ReqInput>1</ReqInput>
    <I_Type>I_HIDDEN(0)</I_Type>
    <Parent>FDR_EnvironmentInfo</Parent>
    <Folder>0</Folder>
    <NoQuote>0</NoQuote>
  </Param>
  <Param name="FDR_Tracing">
    <Desc>Debugging</Desc>
    <ReqInput>0</ReqInput>
    <I_Type>I_HIDDEN(0)</I_Type>
    <Folder>2</Folder>
    <NoQuote>0</NoQuote>
  </Param>
  <Param name="PRM_TraceEventEnabled">
    <Desc>Raise event with job execution log? (y/n)</Desc>
    <Type>String</Type>
    <Size>1</Size>
    <Range>ynYN</Range>
    <Value>n</Value>
    <ReqInput>0</ReqInput>
    <I_Type>I_HIDDEN(0)</I_Type>
    <Parent>FDR_Tracing</Parent>
    <Folder>0</Folder>
    <NoQuote>0</NoQuote>
  </Param>
  <Param name="PRM_TraceLevel">
    <Desc>Logging level (Fatal, Error, Warn, Info, Debug, or Trace)</Desc>
    <Value>Debug</Value>
    <ReqInput>0</ReqInput>
    <I_Type>I_HIDDEN(0)</I_Type>
    <Parent>FDR_Tracing</Parent>
    <Folder>0</Folder>
    <NoQuote>0</NoQuote>
  </Param>
  <Param name="PRM_TraceEventAutoSeverity">
    <Desc>Derive event severity from severity level of messages in execution log? (y/n)</Desc>
    <Type>String</Type>
    <Size>1</Size>
    <Range>ynYN</Range>
    <Value>y</Value>
    <ReqInput>0</ReqInput>
    <I_Type>I_HIDDEN(0)</I_Type>
    <Parent>FDR_Tracing</Parent>
    <Folder>0</Folder>
    <NoQuote>0</NoQuote>
  </Param>
  <Param name="PRM_TraceEventSeverity">
    <Desc>Event severity (if automatic derivation of severity not selected above)</Desc>
    <Type>Integer</Type>
    <Min>1</Min>
    <Max>40</Max>
    <Value>40</Value>
    <Unit>Severity</Unit>
    <ReqInput>1</ReqInput>
    <I_Type>I_HIDDEN(0)</I_Type>
    <Parent>FDR_Tracing</Parent>
    <Folder>0</Folder>
    <NoQuote>0</NoQuote>
  </Param>
  <Param name="PRM_ErrorBehavior">
    <Desc>Action to take when a PowerShell error occurs (Continue or Stop)</Desc>
    <Value>Continue</Value>
    <ReqInput>1</ReqInput>
    <I_Type>I_HIDDEN(0)</I_Type>
    <Parent>FDR_Tracing</Parent>
    <Folder>0</Folder>
    <NoQuote>0</NoQuote>
  </Param>
  <Param name="AKPID">
    <Desc>Action Taken</Desc>
    <Value>AKP_NULL</Value>
    <ReqInput>0</ReqInput>
    <Folder>0</Folder>
    <NoQuote>0</NoQuote>
  </Param>
</Parameter>

<ActionDef></ActionDef>

<AdvanceConfig>
  <EventOp>
    <SupprTime uselast="1">1200</SupprTime>
    <OccurCnt nCount="1" nInterval="1">0</OccurCnt>
  </EventOp>
  <DataOp>
    <CollectIter>1</CollectIter>
    <CollectUponEvt pauseonevtstop="0">0</CollectUponEvt>
    <CollectDetail>0</CollectDetail>
    <NoArchiveDetail>1</NoArchiveDetail>
    <ReportArchive>0</ReportArchive>
  </DataOp>
</AdvanceConfig>

<ScriptDef>
  <Script language="VBScript">
<![CDATA[
'### Please do not remove the following comments.
'### Version string added by setQMLVersion.exe during build process.
'### Copyright (c) 2017 NetIQ Corporation. All rights reserved.
'### VERSION: 7.6.108.0
'###
'###
'### Filename:  ExchangeOnline_MailBoxQuota.qml
'### $Revision: $
'###
'#
'# Include common monitoring variables and functions.
'#
' Include: CommonCode.vbs 
'#
'# The following global variables MUST be defined in any KS template that includes this common code:
'#
'#   gstrScriptName      - The base name (no directory or file extension) of the PowerShell script to execute.
'#   gbExchangeOnlineKS  - This boolean variable indicates whether this KS is for Exchange On-Premises or Exchange Online.
'#                         If this value is set to True, then this KS is for Exchange Online.
'#   garrScriptParams    - An array of script parameter name/value pairs to be passed to the PowerShell script.
'#   garrScriptTargets   - An array containing the names of the resource object types this KS monitors.
'#
'# The following KS parameters are recognized and used by the common code in this file.  If these
'# KS parameters are not defined by a KS including this common code, default values will be used.
'#
'#   PRM_SeverityFail           - The severity for events representing general job execution failures.
'#   PRM_RequiredBitness        - "Bitness" (32, 64, or Any) required for PowerShell script execution.
'#   PRM_HostSharing            - "Yes" if the PowerShell script doesn't require its own host, or "No".
'#   PRM_TraceEventEnabled      - "True" if an execution log event at the specified log level should be raised.
'#   PRM_TraceEventSeverity     - The severity of the execution log event raised by PRM_TraceEventEnabled.
'#   PRM_TraceEventAutoSeverity - "Yes" to base severity on log entries (overrides PRM_TraceEventSeverity).
'#   PRM_TraceLevel             - "Fatal", "Error", "Warn", "Info", "Debug", or "Trace".
'#   PRM_ErrorBehavior          - "Silently Continue" (or "SilentlyContinue"), "Continue" or "Stop".
'#                                NOTE: Currently, "Continue" is treated as "Silently Continue".
'#

'#
'# Constants, Global Variables, Subroutines and Functions
'#

'
' Exchange-specific registry constants
'
Const HKEY_LOCAL_MACHINE = &H80000002
Const cstrExchange2007SetupKey  = "SOFTWARE\Microsoft\Exchange\Setup\"
Const cstrExchange2007BackupKey = "HKLM\SOFTWARE\Microsoft\Exchange\v8.0\"
Const cstrExchange2010SetupKey  = "SOFTWARE\Microsoft\ExchangeServer\v14\Setup\"
Const cstrExchange2010BackupKey = "HKLM\SOFTWARE\Microsoft\ExchangeServer\v14\"
Const cstrExchange2013_or_2016SetupKey  = "SOFTWARE\Microsoft\ExchangeServer\v15\Setup\"
Const cstrExchange2013_or_2016BackupKey = "HKLM\SOFTWARE\Microsoft\ExchangeServer\v15\"
Const cstrProductMajorValue     = "MsiProductMajor"
Const cstrProductMinorValue     = "MsiProductMinor"
Const cstrPSModulePath = "C:\Windows\System32\WindowsPowerShell\v1.0\Modules\MSOnline\Microsoft.Online.Administration.Automation.PSModule.dll"

'
' Tracing/logging level constants
'
Const TRACE_OFF    = 6  ' No tracing whatsoever
Const TRACE_FATAL  = 5  ' Trace fatal errors only
Const TRACE_ERROR  = 4  ' Trace errors of any type
Const TRACE_WARN   = 3  ' Trace warnings and errors
Const TRACE_INFO   = 2  ' Trace warnings, errors, and info
Const TRACE_DEBUG  = 1  ' Trace everything other than line-by-line traces
Const TRACE_TRACE  = 0  ' Trace line-by-line PowerShell script execution

'
' PowerShellHost constants
'
Const cstrPowerShellHostName   = "AppManager PowerShell Host"
Const cstrPowerShellHostProgId = "NetIQAgent.MCPSHost"


'#
'# Global Variables
'#

'
' Variables that will be set based on KS parameters, if those parameters are defined.
'
Private gintFailureSeverity        : gintFailureSeverity        = 5                   ' PRM_SeverityFail
Private gstrRequiredBitness        : gstrRequiredBitness        = "Any"               ' PRM_RequiredBitness
Private gstrHostSharing            : gstrHostSharing            = "Yes"               ' PRM_HostSharing
Private gstrTraceEventEnabled      : gstrTraceEventEnabled      = "No"                ' PRM_TraceEventEnabled
Private gintTraceEventSeverity     : gintTraceEventSeverity     = 40                  ' PRM_TraceEventSeverity
Private gstrTraceEventAutoSeverity : gstrTraceEventAutoSeverity = "Yes"               ' PRM_TraceEventAutoSeverity
Private gstrTraceLevel             : gstrTraceLevel             = "Error"             ' PRM_TraceLevel
Private gstrErrorBehavior          : gstrErrorBehavior          = "SilentlyContinue"  ' PRM_ErrorBehavior

' introduced new parameter runtine for .net runtime (if runtime=2 then clr 2.0,3.0,3.5. If runtime=4 then clr 4.0,4.5). By default 2
Private gstrDotNetRuntime		   : gstrDotNetRuntime          = "2"                 ' PRM_RequiredRuntime

'
' PowerShellHost variables
'
Private gobjPSHost          : Set gobjPSHost      = Nothing
Private gdblPSHostVersion   : gdblPSHostVersion   = 0.0

'
' Event variables (will be set in InitializeGlobalVariables).
'
Private gstrEventTarget     : gstrEventTarget     = ""

'
' Tracing/logging variables
'
Private gbTraceLevelSet     : gbTraceLevelSet     = False
Private gintTraceLevel      : gintTraceLevel      = TRACE_OFF
Private gstrTrace           : gstrTrace           = ""


'#
'# Subroutines and Functions
'#

Function PowerShellHostSupportsTraceOverride()

  If (gdblPSHostVersion = 0.0) Then
      gdblPSHostVersion = GetPowerShellHostVersion()
  End If

  PowerShellHostSupportsTraceOverride = gdblPSHostVersion >= 7.4

End Function

Function PowerShellHostSupportsErrorBehavior()

  If (gdblPSHostVersion = 0.0) Then
      gdblPSHostVersion = GetPowerShellHostVersion()
  End If

  PowerShellHostSupportsErrorBehavior = gdblPSHostVersion >= 7.4

End Function


Function PowerShellHostSupportsExecutionSeverity()

  If (gdblPSHostVersion = 0.0) Then
      gdblPSHostVersion = GetPowerShellHostVersion()
  End If

  PowerShellHostSupportsExecutionSeverity = gdblPSHostVersion >= 7.4

End Function


Function GetPowerShellHostVersion()

Dim strVersion, dblVersion, iIndex1, iIndex2, engLocale

Trace TRACE_INFO, "GetPowerShellHostVersion - Enter"

Nqext.MCVersion "PowerShell\MCPSHostClient.dll", strVersion

' The CDbl function would fail, if the locale setting is Hungarian.
' So, change it to english_us temporarily and change it back to Hungarian before exiting this function.
orgLocale = GetLocale()
NQExt.QTrace "Original locale is: " & orgLocale

If orgLocale = 1038 Then
	engLocale = 1033
	NQExt.QTrace "Setting locale to english_us"
	SetLocale(engLocale)
End If

dblVersion = 0.0
If strVersion <> "" Then
    iIndex1 = InStr(strVersion, ".")
    If (iIndex1 > 0) Then
        iIndex1 = InStr(iIndex1+1, strVersion, ".")
        If (iIndex1 > 0) Then
            dblVersion = CDbl(Left(strVersion, iIndex1 - 1))
        End If
    End If
End If

If orgLocale = 1038 Then
	NQExt.QTrace "Setting locale back to: " & orgLocale
	SetLocale(orgLocale)
End If

GetPowerShellHostVersion = dblVersion

Trace TRACE_INFO, "GetPowerShellHostVersion - Installed PowerShellHost version is " & strVersion
Trace TRACE_INFO, "GetPowerShellHostVersion - Truncated PowerShellHost version is " & CStr(dblVersion)
Trace TRACE_INFO, "GetPowerShellHostVersion - Exit"

End Function


Sub RunPowerShellScript(strScriptName, arrScriptParams)

  On Error Resume Next

  Dim strScriptPath    : strScriptPath = "Scripts\" & strScriptName & ".ps1"
  Dim strPSTraceLevel  : strPSTraceLevel  = "Error"
  Dim strEventMessage  : strEventMessage  = ""
  Dim strDetailMessage : strDetailMessage = ""
  Dim strCommandResult : strCommandResult = ""

  Dim strBitness       : strBitness       = gstrRequiredBitness
  Dim strSharing       : strSharing       = gstrHostSharing
  Dim strDotNetRuntime : strDotNetRuntime = gstrDotNetRuntime
  Dim bEndSession      : bEndSession      = False

  If gbExchangeOnlineKS = True Then
		Dim strFailedPrerequisites : strFailedPrerequisites = ""
		Dim FailedPrerequisites
		'If Not CheckWindowsOSVersion() Then
		'	strFailedPrerequisites = "Windows OS"
		'End If
		'If Not CheckIfAzureADModuleIsInstalled() Then
		'	If strFailedPrerequisites <> "" Then
		'		strFailedPrerequisites = strFailedPrerequisites & ","
		'	End If
		'	strFailedPrerequisites = strFailedPrerequisites  & "Microsoft Azure Active Directory Module"
		'End If
		If strFailedPrerequisites <> "" Then
			strEventMessage  = "One or more pre-requisites required to monitor Azure Active Directory failed."
			strDetailMessage = "The failed pre-requisites are as follows:" & vbCrlf
			FailedPrerequisites = split(strFailedPrerequisites, ",")
			For Each strPrerequisite In FailedPrerequisites
				strDetailMessage = strDetailMessage & strPrerequisite & vbCrlf
			Next
			strDetailMessage = strDetailMessage & vbCrlf & vbCrlf
			strDetailMessage = strDetailMessage & "Pre-requisites required for Monitoring Azure Active Directory:" & vbCrlf
			strDetailMessage = strDetailMessage & "Windows Server 2012/2012 R2" & vbCrlf			
			strDetailMessage = strDetailMessage & "Windows Azure Active Directory Module for Windows Powershell 1.0.9031.1 or later." & vbCrlf
		End If		
	End If

  '
  ' If no serious problem has been encountered, check to see whether the Exchange2007 module is installed.
  '
  If strEventMessage = "" Then
      Set fso = CreateObject("Scripting.FileSystemObject")
      If Not fso Is Nothing Then
          Dim strInstallPath, strFullScriptPath
          strInstallPath = ReadRegStr(HKEY_LOCAL_MACHINE, "Software\NetIQ\AppManager\4.0", "InstallPath", 32)
          strFullScriptPath = strInstallPath & "\bin\PowerShell\" & strScriptPath

		  strFullScriptPath = Trim(strFullScriptPath)
		  strFullScriptPath = "C:\Program Files (x86)\NetIQ\AppManager\bin\PowerShell\Scripts\AzureAD_DevicesCheck.ps1"
		  Trace TRACE_ERROR, "Cloud AD Doamins : Full AM path is  " & strFullScriptPath
		  
          If Not fso.FileExists(strFullScriptPath) Then
              strEventMessage  = "AppManager for Azure Active Directory is not installed"
              strDetailMessage = "AppManager for Azure Active Directory does not appear " _
                               & "to be installed on this agent; the " & strScriptName & ".ps1 PowerShell " _
                               & "script is not present in the path" & strFullScriptPath
          End If
          Set fso = Nothing
      End If
  End If

  '
  ' If no serious problem has been encountered, create the PowerShellHost client (MO) instance.
  '
  If strEventMessage = "" Then
      '
      ' Create MCPSHostClient instance.
      '
      Set gobjPSHost = CreateObject(cstrPowerShellHostProgId)

      If Not gobjPSHost Is Nothing Then
          Trace TRACE_DEBUG, "RunPowerShellCommand: MCPSHostClient instantiation succeeded"
      Else
			strEventMessage  = "Unexpected failure instantiating PowerShell host client"
			strDetailMessage = "Failed to instantiate the PowerShell host client, MCPSHostClient." & vbCrlf & vbCrlf
			If gbExchangeOnlineKS = False Then
				strDetailMessage = strDetailMessage & "AppManager for Azure Active Directory is not installed on this host."
			Else
				strDetailMessage = strDetailMessage & "This error could happen because of the following reasons:"  & vbCrlf
				strDetailMessage = strDetailMessage & "1. AppManager for Azure Active Directory is not installed on this host." & vbCrlf
				strDetailMessage = strDetailMessage & "2. Win-OS 8.0.104 or later is not installed. Please follow the steps mentioned under section x.x.x" & vbCrlf
				strDetailMessage = strDetailMessage & "in the management guide."				 
			End If
			strDetailMessage = BuildFailureMessage(strDetailMessage)
      End If
  End If

  '
  ' If no serious problem has been encountered, and debugging is enabled via the gstrTraceEventEnabled
  ' variable, and the PowerShellHost is sufficiently mature that it supports the TraceOverride property,
  ' then set the TraceOverride property to "ThreadSetting" to ensure that the value of the TraceLevel
  ' property (gstrTraceLevel) overrides the global trace/log level setting in log4cxx.cfg.  Note that
  ' we do this before making other calls into the PowerShellHost, to ensure that only log messages of
  ' appropriate levels are written to the log file and execution event log for this job.
  '
  If strEventMessage = "" And PowerShellHostSupportsTraceOverride() Then
      If IsDebugEnabled() Then
          '
          ' Set the trace override to ensure that logging is done at the specified logging level
          ' rather than the logging level specified in the PowerShellHost configuration files.
          '
          gobjPSHost.SetProperty "TraceOverride", "ThreadSetting"
      Else
          '
          ' Use the default global trace override setting.
          '
          gobjPSHost.SetProperty "TraceOverride", "GlobalSetting"
      End If

      If Err.Number = 0 Then
          Trace TRACE_DEBUG, "RunPowerShellCommand: MCPSHostClient.SetProperty(TraceOverride, ...) succeeded"
      Else
          strEventMessage  = "Unexpected failure initializing PowerShell host client"
          strDetailMessage = BuildFailureMessage("Failed to initialize MCPSHostClient TraceOverride property")
      End If
  End If

  '
  ' If no serious problem has been encountered, enable agent callbacks from the PowerShellHost
  ' client and server, and from PowerShell scripts executed from the server.
  '
  If strEventMessage = "" Then
      '
      ' Pass NQExt to MCPSHostClient so that callbacks can be made from PowerShell.
      '
      gobjPSHost.SetNQExt(NQExt)

      If Err.Number = 0 Then
          Trace TRACE_DEBUG, "RunPowerShellCommand: MCPSHostClient.SetNQExt succeeded"
      Else
          strEventMessage  = "Unexpected failure initializing PowerShell host client"
          strDetailMessage = BuildFailureMessage("Failed to initialize MCPSHostClient callback mechanism")
      End If
  End If

  '
  ' If no serious problem has been encountered, set the TracePrefix property.
  '
  If strEventMessage = "" Then
      '
      ' Set the trace prefix so that the Knowledge Script name is included in trace messages.
      '
      gobjPSHost.SetProperty "TracePrefix", strScriptName

      If Err.Number = 0 Then
          Trace TRACE_DEBUG, "RunPowerShellCommand: MCPSHostClient.SetProperty(TracePrefix, ...) succeeded"
      Else
          strEventMessage  = "Unexpected failure initializing PowerShell host client"
          strDetailMessage = BuildFailureMessage("Failed to initialize MCPSHostClient TracePrefix property")
      End If
  End If

  '
  ' If no serious problem has been encountered, set the trace level to be used when determining
  ' whether to write messages to the trace/log file.
  '
  If strEventMessage = "" Then
      '
      ' Set the trace level so that appropriate traces are written to the log file.
      '
      strPSTraceLevel = ConvertVBSToPSTraceLevel(gintTraceLevel)
      gobjPSHost.SetProperty "TraceLevel", strPSTraceLevel

      If Err.Number = 0 Then
          Trace TRACE_DEBUG, "RunPowerShellCommand: MCPSHostClient.SetProperty(TraceLevel, ...) succeeded"
          gbTraceLevelSet = True
      Else
          strEventMessage  = "Unexpected failure initializing PowerShell host client"
          strDetailMessage = BuildFailureMessage("Failed to initialize MCPSHostClient TraceLevel property")
      End If
  End If

  '
  ' If no serious problem has been encountered, and debugging is enabled via the gstrTraceEventEnabled
  ' variable, and the PowerShellHost is sufficiently mature that it supports the ErrorBehavior property,
  ' then set the ErrorBehavior property to the value specified by the user.
  '
  If strEventMessage = "" And PowerShellHostSupportsErrorBehavior() Then
      '
      ' Set the error handling behavior.
      '
      gobjPSHost.SetProperty "ErrorBehavior", gstrErrorBehavior

      If Err.Number = 0 Then
          Trace TRACE_DEBUG, "RunPowerShellCommand: MCPSHostClient.SetProperty(ErrorBehavior, ...) succeeded"
      Else
          strEventMessage  = "Unexpected failure initializing PowerShell host client"
          strDetailMessage = BuildFailureMessage("Failed to initialize MCPSHostClient ErrorBehavior property")
      End If
  End If

  '
  ' If no serious problem has been encountered, start a new PowerShellHost server session.  Note that this
  ' might (or might not) instantiate a new MCPSHostServer.exe process to manage the PowerShell session.
  '
  If strEventMessage = "" Then
      '
      ' Start a MCPSHostServer session for running the PowerShell command.
      '
      If strBitness = "Any" Then
          strBitness = "OS"
      End If

      If strSharing = "Yes" Then
          strSharing = "True"
      Else
          strSharing = "False"
      End If

      gobjPSHost.StartSession "bitness=" & strBitness & ",runtimes=" & strDotNetRuntime & ",shared=" & strSharing

      If Err.Number = 0 Then
          Trace TRACE_DEBUG, "RunPowerShellCommand: MCPSHostClient.StartSession(...) succeeded"
          bEndSession = True
      Else
          strEventMessage  = "Unexpected failure starting PowerShell"
          strDetailMessage = BuildFailureMessage("Failed to initialize MCPSHostServer PowerShell session")
      End If
  End If

  If strEventMessage = "" Then
      '
      ' Execute the PowerShell command.
      '
      strCommandResult = gobjPSHost.ExecuteFile(strScriptPath, (arrScriptParams))

      If Err.Number = 0 Then
          Trace TRACE_DEBUG, "RunPowerShellCommand: MCPSHostClient.ExecuteFile(...) succeeded"
          If strCommandResult <> "" Then
              Err.Clear()
              strEventMessage  = "Unexpected error encountered during job execution"
              strDetailMessage = "PowerShell script '" & strScriptPath & "' returned an error:" _
                               & vbCrLf & vbCrLf & strCommandResult
          End If
      Else
          strEventMessage  = "Unexpected failure executing PowerShell script"
          strDetailMessage = BuildFailureMessage("Failed to execute the PowerShell script")
      End If
  End If

  If strEventMessage = "" Then
      '
      ' If an execution log event was requested, get the log and raise an event.
      '
      CreateExecutionLogEvent
  End If

  If bEndSession Then
      '
      ' End the MCPSHostServer session.
      '
      Err.Clear()
      gobjPSHost.EndSession

      If Err.Number = 0 Then
          Trace TRACE_DEBUG, "RunPowerShellCommand: MCPSHostClient.EndSession(...) succeeded"
      Else
          strEventMessage  = "Unexpected failure ending PowerShell session"
          strDetailMessage = BuildFailureMessage("Failed to gracefully shut down the PowerShell session")
      End If
  End If

  If Not gobjPSHost Is Nothing Then
      Set gobjPSHost = Nothing
  End If

  If strEventMessage <> "" Then
      Trace TRACE_DEBUG, strEventMessage & " - " & strDetailMessage
      
      If(gstrScriptName = "Discovery_ExchangeDAG" Or gstrScriptName = "Discovery_Exchange2007" Or gstrScriptName = "Discovery_ExchangeOnline") Then 
          If(PRM_EventDiscoveryFailed = "y") Then
              CreateEvent gintFailureSeverity, strEventMessage, strDetailMessage, gstrEventTarget, AKPID
          End If    
      Else
          CreateEvent gintFailureSeverity, strEventMessage, strDetailMessage, gstrEventTarget, AKPID
      End If

  End If

End Sub



'
' CreateEvent - Create an event, with default values for uninteresting properties.
'
Sub CreateEvent(intSeverity, strEventMessage, strDetailMessage, strEventTarget, strAction)

  NQExt.CreateEvent intSeverity, strEventMessage, strAction, strEventTarget, 0.0, strDetailMessage, "", 0, 0

End Sub


'
' AbortScript - Abort execution of the script.
'
Sub AbortScript(intSeverity, strDetailMessage, strEventTarget, bRaiseError)
  NQExt.AbortScript strEventTarget, strDetailMessage, intSeverity, CBool(bRaiseError)
End Sub


'
' GetPSValue - Given a VBScript variable, return a string containing the
'              value of the variable as it would exist in PowerShell.
'
Function GetPSValue(varVariable)

  Dim strPSValue

  Select Case VarType(varVariable)
      Case vbEmpty, vbNull
          ' 0 Empty (uninitialized)
          ' 1 Null  (no valid data)
          strPSValue = "$null"

      Case vbInteger, vbLong, vbSingle, vbDouble
          ' 2 Integer
          ' 3 Long integer
          ' 4 Single-precision floating-point number
          ' 5 Double-precision floating-point number
          strPSValue = CStr(varVariable)

     'Case vbCurrency   ' 6 Currency
     'Case vbDate       ' 7 Date

      Case vbString     ' 8 String
          strPSValue = """" & varVariable & """"

     'Case vbObject     ' 9 Automation object
     'Case vbError      ' 10 Error

      Case vbBoolean    ' 11 Boolean
          If CBool(varVariable) Then
              strPSValue = "$true"
          Else
              strPSValue = "$false"
          End If

     'Case vbVariant    ' 12 Variant (used only with arrays of Variants)
     'Case vbDataObject ' 13 A data-access object
     'Case vbByte       ' 17 Byte

     'Case vbArray      ' 8192 Array
          ' TODO: For each element in the array, convert to "," & PSValue. For example: ,1,("Two",3.0),"Four"

      Case Else
          Stop ' Variant type not supported
          strPSValue = "ERROR: " & TypeName(varVariable) & " variant type not supported as PowerShell variable"
  End Select

  GetPSValue = strPSValue
End Function


'
' SetPSVariable - Return a string representing a PowerShell variable assignment statement,
'                 with the variable having the same name and value as the strVariableName
'                 VBScript variable.
'
'                 If a KS parameter value needs to be modified before this function is
'                 called to create the assignment statement, the KS parameter (a VBScript
'                 constant) should be assigned to a variable of the same name, but suffixed
'                 with "_MODIFIED".  This function will automatically remove the suffix and
'                 use the original name as the name of the PowerShell variable.
'
Function SetPSVariable(strVariableName, Byval vbPSType)

  Dim varValue : varValue = Eval(strVariableName)

  If IsNull(vbPSType) Then
      vbPSType = VarType(varValue)
  End If

  If vbPSType = vbBoolean And VarType(varValue) = vbString Then
      ' Convert y/n script property value to Boolean.
      varValue = (LCase(varValue) = "y" Or LCase(varValue) = "yes")
  End If

  If Right(strVariableName, Len("_MODIFIED")) = "_MODIFIED" Then
      strVariableName = Left(strVariableName, Len(strVariableName) - Len("_MODIFIED"))
  End If

  SetPSVariable = strVariableName & "=" & GetPSValue(varValue)

End Function


'
' BuildFailureMessage - Given an error message, add additional information
'                       based on the Err object.
'
Function BuildFailureMessage(strMessage)

  If Err.Number <> 0 Or Err.Description <> "" Then
      strMessage = strMessage & ":" & vbCrLf & vbCrLf
      If Err.Number <> 0 Then
          strMessage = strMessage & "Error Number: 0x" & CStr(Hex(Err.Number)) & vbCrLf
      End If
      If Err.Description <> "" Then
          strMessage = strMessage & "Description:  " & Err.Description & vbCrLf
      End If
  End If

  BuildFailureMessage = strMessage

End Function


'
' IsDebugEnabled - Return true if debugging is enabled, false otherwise.
'
Function IsDebugEnabled()

  IsDebugEnabled = (LCase(Left(gstrTraceEventEnabled, 1)) = "y")

End Function


'
' GetDefaultTraceLevel - Return the numeric trace level, based on the string value
'                        of the gstrTraceLevel variable.
'
Function GetDefaultTraceLevel()

  GetDefaultTraceLevel = TRACE_WARN

  If IsNumeric(gstrTraceLevel) Then
      GetDefaultTraceLevel = Int(gstrTraceLevel)
  Else
      Select Case UCase(gstrTraceLevel)
          Case "DISABLED"
              GetDefaultTraceLevel = TRACE_OFF
          Case "FATAL"
              GetDefaultTraceLevel = TRACE_FATAL
          Case "ERROR"
              GetDefaultTraceLevel = TRACE_ERROR
          Case "WARN"
              GetDefaultTraceLevel = TRACE_WARN
          Case "INFO"
              GetDefaultTraceLevel = TRACE_INFO
          Case "DEBUG"
              GetDefaultTraceLevel = TRACE_DEBUG
          Case "TRACE"
              GetDefaultTraceLevel = TRACE_TRACE
      End Select
  End If

End Function


'
' ConvertVBSToPSTraceLevel - Convert the VBScript trace level integer to the
'                            corresponding PowerShell trace level string.
'
Function ConvertVBSToPSTraceLevel(traceLevel)

  Select Case traceLevel
      Case TRACE_OFF
          ConvertVBSToPSTraceLevel = "Off"
      Case TRACE_FATAL
          ConvertVBSToPSTraceLevel = "Fatal"
      Case TRACE_ERROR
          ConvertVBSToPSTraceLevel = "Error"
      Case TRACE_WARN
          ConvertVBSToPSTraceLevel = "Warn"
      Case TRACE_INFO
          ConvertVBSToPSTraceLevel = "Info"
      Case TRACE_DEBUG
          ConvertVBSToPSTraceLevel = "Debug"
      Case TRACE_TRACE
          ConvertVBSToPSTraceLevel = "All"
      Case Else
          ConvertVBSToPSTraceLevel = "Warn"
  End Select

End Function


'
' ConvertTraceLevelToSeverity - Convert a PowerShellHost trace level to
'                               an appropriate event severity.
'
Function ConvertTraceLevelToSeverity(traceLevel)

  Select Case traceLevel
      Case "Fatal"
          ConvertTraceLevelToSeverity = 5
      Case "Error"
          ConvertTraceLevelToSeverity = 5
      Case "Warn"
          ConvertTraceLevelToSeverity = 15
      Case "Info"
          ConvertTraceLevelToSeverity = 25
      Case "Debug"
          ConvertTraceLevelToSeverity = 35
      Case "All"
          ConvertTraceLevelToSeverity = 35
      Case Else
          ConvertTraceLevelToSeverity = 40
  End Select

End Function


'
' Trace - Write a message to the log file if the specified trace level
'         is greater than or equal to the current trace level setting.
'
Sub Trace(level, strMessage)

  Dim strTrace
  Dim strTraceLevel

  If IsNull(level) Or IsEmpty(level) Then
      level = TRACE_INFO
  End If

  If level >= gintTraceLevel Then
      strTrace = strMessage
      strTraceLevel = ConvertVBSToPSTraceLevel(level)

      if Not gobjPSHost Is Nothing And gbTraceLevelSet = True Then
          gobjPSHost.Trace strTraceLevel, "[KS] - " & gstrTrace & strTrace
          gstrTrace = ""
      Else
          gstrTrace = gstrTrace & strTrace & VbCrLf
      End If
  End If

End Sub


'
' CreateExecutionLogEvent - Generate an event containing all trace messages produced
'                           by the KS, PowerShellHost client, PowerShellHost server,
'                           and PowerShell script during this job's execution.
'
Sub CreateExecutionLogEvent()

  Dim strLog
  Dim strMessage
  Dim lngSeverity

  If IsDebugEnabled() Then
      lngSeverity = gintTraceEventSeverity
      If LCase(Left(gstrTraceEventAutoSeverity, 1)) = "y" Then
          If PowerShellHostSupportsExecutionSeverity() And Not gobjPSHost Is Nothing Then
              strSeverity = gobjPSHost.GetExecutionSeverity()
              lngSeverity = ConvertTraceLevelToSeverity(strSeverity)
          End If
      End If

      If lngSeverity = 0 Then
          strMessage = """" & gstrTraceLevel & """ is not a valid severity; " _
                     & "the severity must be an integer in the range 1-40, or ""Auto""."
          CreateEvent gintFailureSeverity, "Invalid event severity", strMessage, gstrEventTarget, AKPID
      Else
          If Not gobjPSHost Is Nothing Then
              strLog = gobjPSHost.GetExecutionLog()
          Else
              strLog = gstrTrace
          End If
          CreateEvent lngSeverity, "PowerShell execution log", strLog, gstrEventTarget, AKPID
      End If
  End If

End Sub


'
' IsWow64 - Returns true if the current process is running under WoW64, otherwise returns false.
'
function IsWoW64()

  Dim is64, strProgID, objNT, NTSystem
  NQExt.QTrace "Begin IsWoW64" 
  is64 = False

  progid = NQEXT.GetProgID("NetiQAgent.NT", AppManID)
NQExt.QTrace "after GetProgID" 
  Set objNT = CreateObject(progid)
  Set NTSystem = objNT.System
  On Error Resume Next

  is64 = NTSystem.IsWOW64
  If (Err.Number <> 0)Then
      is64 = False
  End If

  Set objNT = Nothing
  IsWoW64 = is64
NQExt.QTrace "Exit IsWoW64- IsWoW64 =" & IsWoW64 
End Function


'
' GetRegistryValue - Get a value from the registry.
'
Function GetRegistryValue(strKey, strValue)

  Trace TRACE_INFO, "GetRegistryValue - Enter"
Trace TRACE_INFO, "GetRegistryValue - Attempting to read value: " & strKey  & strValue

  Err.Clear
  On Error Resume Next
If IsWoW64() Then
	  GetRegistryValue = ReadRegStr (HKEY_LOCAL_MACHINE, strKey, strValue, 64)
Else
	  GetRegistryValue = ReadRegStr (HKEY_LOCAL_MACHINE, strKey, strValue, 32)
End If

    NQExt.QTrace "GetRegistryValue = " & GetRegistryValue
  If Err.Number <> 0 Then
      GetRegistryValue = vbNull
      Trace TRACE_INFO, "GetRegistryValue - Unable to read registry key or value: " _
                                           & Err.Number & " - " & Err.Description
  End If

Trace TRACE_INFO, "GetRegistryValue - Exit"

End Function

' ReadRegStr -  Reads a REG_SZ value from the local computer's registry using WMI.
' Parameters:
'   RootKey - The registry hive (see http://msdn.microsoft.com/en-us/library/aa390788(VS.85).aspx for a list of possible values).
'   Key - The key that contains the desired value.
'   Value - The value that you want to get.
'   RegType - The registry bitness: 32 or 64.
'
Function ReadRegStr (RootKey, Key, Value, RegType)
  Dim oCtx, oLocator, oReg, oInParams, oOutParams
  Dim arrValueNames, arrTypes

  NQExt.QTrace "Begin ReadRegStr"

  Const REG_SZ        = 1
  Const REG_EXPAND_SZ = 2
  Const REG_BINARY    = 3
  Const REG_DWORD     = 4
  Const REG_MULTI_SZ  = 7
  Const KEY_QUERY_VALUE = &H0001

  Set oCtx = CreateObject("WbemScripting.SWbemNamedValueSet")
  If Err.Number <> 0 Then
	  NQExt.QTrace "CreateObject WbemScripting.SWbemNamedValueSet Failed Error Number: " & Err.Number & vbCrlf
	  NQExt.QTrace "Description:  " & Err.Description & vbCrlf
  End If

  oCtx.Add "__ProviderArchitecture", RegType

  Set oLocator = CreateObject("Wbemscripting.SWbemLocator")
  If Err.Number Then
	 NQExt.QTrace "CreateObject Wbemscripting.SWbemLocator Failed Error Number: " & Err.Number & vbCrlf
	 NQExt.QTrace "Description:  " & Err.Description & vbCrlf
  End If

  Set oReg = oLocator.ConnectServer("", "root\default", "", "", , , , oCtx).Get("StdRegProv")
  If Err.Number <> 0 Then
	 NQExt.QTrace "ConnectServer root\default Failed Error Number: " & Err.Number & vbCrlf
	 NQExt.QTrace "Description:  " & Err.Description & vbCrlf
  End If

  oReg.CheckAccess RootKey, Key, KEY_QUERY_VALUE, bHasAccessRight
  If(bHasAccessRight = True) Then 

     oReg.EnumValues RootKey, Key, arrValueNames, arrTypes
     For i = LBound(arrValueNames) To UBound(arrValueNames)
         strValueName = arrValueNames(i)
         If(arrValueNames(i) = Value) Then
	   Select Case arrTypes(i)

    		' Show a REG_SZ value
    		'
    		Case REG_SZ          
      		oReg.GetStringValue RootKey, Key, strValueName, strValue
      		ReadRegStr = strValue

    		' Show a REG_EXPAND_SZ value
    		'
    		Case REG_EXPAND_SZ
      		oReg.GetExpandedStringValue RootKey, Key, strValueName, strValue
      		ReadRegStr= strValue

    		' Show a REG_BINARY value
    		'          
    		Case REG_BINARY
     			oReg.GetBinaryValue RootKey, Key, strValueName, arrBytes
     			strBytes = ""
      		For Each uByte in arrBytes
        		    strBytes = strBytes & Hex(uByte) & " "
      		Next
      		ReadRegStr = strBytes

    		' Show a REG_DWORD value
    		'
    		Case REG_DWORD
      		oReg.GetDWORDValue RootKey, Key, strValueName, uValue
      		ReadRegStr = CStr(uValue)				  

    		' Show a REG_MULTI_SZ value
    		'
    		Case REG_MULTI_SZ
      		oReg.GetMultiStringValue RootKey, Key, strValueName, arrValues				  				
      		For Each strValue In arrValues
        		    ReadRegStr =  strValue 
    			Next

  	   End Select
 	  End If
  	Next
 Else 
  	NQExt.QTrace "Unable to access the registry key" 
 End If 
 NQExt.QTrace "End ReadRegStr"    
End Function

'
' DoesRegistryKeyExist - Return true if the registry key exists, false otherwise.
'
Function DoesRegistryKeyExist(strName)

  Trace TRACE_INFO, "DoesRegistryKeyExist - Enter"

  Dim objWshShell, value, bValueExists
  Set objWshShell = CreateObject("WScript.Shell")

  bValueExists = False

  Trace TRACE_INFO, "DoesRegistryKeyExist - Attempting to read value: " & strName

  Err.Clear
  On Error Resume Next
  value = objWshShell.RegRead(strName)

  If Err.Number = 0 Then
      bValueExists = True
  End If

  DoesRegistryKeyExist = bValueExists

  Set objWshShell = Nothing
  Trace TRACE_INFO, "DoesRegistryKeyExist - Exit"

End Function


'
' GetFirstEventTarget - Get the path of the resource (in "<object_type>=<object_path" format)
'                       on which events not specific to a particular monitored resource should
'                       be raised.  This will be the first resource of the specified type that
'                       is in the list of monitored resources.
'
Function GetFirstEventTarget(strOrArrResourceTypes)

  Dim arrResourceTypes, strTempResourceType, strResourceType, strResourceNames, strResourceName

  arrResourceTypes = strOrArrResourceTypes

  If Not IsArray(arrResourceTypes) Then
      arrResourceTypes = Array(arrResourceTypes)
  End If

  strResourceName = ""

  On Error Resume Next
  Err.Clear()

  For Each strTempResourceType In arrResourceTypes
      strResourceType = strTempResourceType
      strResourceNames = Eval(strTempResourceType)
      If Err.Number = 0 And strResourceNames <> "" Then
          strResourceName  = ConvertResourceName(NQExt.Item(strResourceNames, 1, ","))
          Exit For
      End If
  Next

  On Error Goto 0

  If strResourceName <> "" Then
      GetFirstEventTarget = strResourceType & "=" & strResourceName
  End If

End Function


'
' ConvertResourceName - Convert a TreeView resource object fullpath to the form required
'                       by KS's that specify fullpath="1".  The returned object name can
'                       be passed to CreateEvent, CreateData, etc.
'
' For example:
'
'   Exchange2007_MailboxServer = MBS:RALQEROW06A15:MBS:RALQEROW06A15:First Storage Group:Mailbox Database:1283
'
' will be converted to:
'
'   Exchange2007_MailboxServer = #1283:MBS:RALQEROW06A15:MBS:RALQEROW06A15:First Storage Group:Mailbox Database
'
Function ConvertResourceName(strResourcePath)

  Dim strOriginalPath, nPathComponents

  strOriginalPath = strResourcePath
  strResourcePath = ""

  nPathComponents = NQExt.ItemCount(strOriginalPath, ":")

  For I = 1 To nPathComponents - 1
      strResourcePath = strResourcePath & ":" & NQExt.Item(strOriginalPath, I, ":")
  Next

  strResourcePath = "#" & NQExt.Item(strOriginalPath, nPathComponents, ":") & strResourcePath

  ConvertResourceName = strResourcePath

End Function



'
' IsExchangeServerInstalled - Return true if Microsoft Exchange Server is installed,
'                             otherwise return false.
'
Function IsExchangeServerInstalled()

  Trace TRACE_INFO, "IsExchangeServerInstalled - Enter"
NQExt.QTrace "Begin IsExchangeServerInstalled"

  Dim bExchangeInstalled

  bExchangeInstalled = False
  NQExt.QTrace "Before IsExchangeServer2007Installed" 
  If IsExchangeServer2007Installed() Then
  NQExt.QTrace "Exchange Server 2007 Installed"
      bExchangeInstalled = True
  End If
  If Not bExchangeInstalled Then
      NQExt.QTrace "Exchange server is not installed in regular mode so checking for backup mode" 
      If IsExchangeServer2010Installed() Then
        NQExt.QTrace "Exchange server is installed in backup mode"
          bExchangeInstalled = True
      End If    
  End If
  If Not bExchangeInstalled Then
      NQExt.QTrace "Exchange server 2010 is not installed checking for Exchange Server 2013/2016" 
      If IsExchangeServer2013or2016Installed() Then
          bExchangeInstalled = True
      End If
  End If

  Err.Clear
  IsExchangeServerInstalled = bExchangeInstalled
  Trace TRACE_INFO, "IsExchangeServerInstalled - Exit "
  NQExt.QTrace "IsExchangeServerInstalled - Exit IsExchangeServerInstalled = " & IsExchangeServerInstalled
End Function


'
' ValidateRequiredScriptVariables - Verify that all required script variables are set, returning true
'                                   if they are, otherwise returning false and raising an error event.
'
Function ValidateRequiredScriptVariables()

  Trace TRACE_INFO, "ValidateRequiredScriptVariables - Enter "

  Dim variablesValidated : variablesValidated = True

  Dim arrScriptVariables, undefinedVariables
  Dim eventMessage, detailMessage

  '
  ' Required global variables:
  '
  '   All of these variables must be set by the KS that includes this common code.
  '
  '   gstrScriptName      - The base name (no directory or file extension) of the PowerShell script to execute.
  '   garrScriptParams    - An array of script parameter name/value pairs to be passed to the PowerShell script.
  '
  ' Require functions:
  '
  '   GetDefaultEventTarget() - Returns the "<object_type>=<object_name>" string to be used for global events.
  '

  undefinedVariables  = ""
  arrScriptVariables  = Array("gstrScriptName",      _
                              "garrScriptParams")

  For Each variableName in arrScriptVariables
      If Eval("IsEmpty(" & variableName & ")") Then
          undefinedVariables = undefinedVariables + ", " + variableName
      End If
  Next

  If Len(undefinedVariables) > 0 Then
      undefinedVariables = Mid(undefinedVariables, 3, Len(undefinedVariables)-2)

      eventMessage  = "One or more required Knowledge Script variables are undefined"
      detailMessage = detailMessage & "The following Knowledge Script variables are undefined:" & vbCrLf & vbCrLf _
                                    & undefinedVariables & vbCrLf & vbCrLf

      CreateEvent gintFailureSeverity, eventMessage, detailMessage, "", ""
      variablesValidated = False
  End If

  ' Log version of KS being used - important for debugging
  Trace TRACE_INFO, "ValidateRequiredScriptVariables - AppManID of KS =  " & AppManID

  ValidateRequiredScriptVariables = variablesValidated

  Trace TRACE_INFO, "ValidateRequiredScriptVariables - Exit "

End Function


'
' ValidateSelectedMonitoringOptions - Raise an event and abort the job if no monitoring options that
'                                     are applicable to the TreeView objects that job was dropped on
'                                     are selected.  (If the job were allowed to run in this case it
'                                     would do nothing useful, so we assume the user made a mistake
'                                     when setting the job parameters.)
'
Function ValidateSelectedMonitoringOptions()

  Dim bValid : bValid = ValidateScriptParameters(gstrEventTarget)

  If Not bValid Then
      Dim strEventMessage, strDetailMessage, strAbortMessage

      strEventMessage  = "Invalid script parameters"
      strDetailMessage = "The job failed either because you did not select anything to monitor, " _
                       & "or because the monitoring options you selected are not applicable to " _
                       & "any of the TreeView resource objects on which the job was dropped."

      CreateEvent gintFailureSeverity, strEventMessage, strDetailMessage, gstrEventTarget, AKPID

      strAbortMessage = "Job failure: " & strEventMessage  & vbNewLine & vbNewLine _
                                        & strDetailMessage & vbNewLine & vbNewLine _
                                        & "This job will now be aborted."

      AbortScript gintFailureSeverity, strAbortMessage, gstrEventTarget, False
  End If

  ValidateSelectedMonitoringOptions = bValid

End Function


'
' InitializeGlobalVariables - Initialize per-iteration global variables.
'
Sub InitializeGlobalVariables()

  '
  ' Initialize per-iteration variables.  Note that global variables, whether public or
  ' private, should be initialized here rather than at the global level if they are
  ' intended to be global on a per-iteration basis rather than a per-job basis.
  '

  '
  ' First we set global variables from the values of certain KS parameters we expect to be defined.
  ' If a KS fails to define one or more of these parameters the associated global variables will be
  ' set to appropriate default values.
  '
  '   Note that these will be assigned default values below if they are not defined in the KS.
  '
  '   PRM_SeverityFail           - The severity for events representing general job execution failures.
  '   PRM_RequiredBitness        - "Bitness" (32, 64, or Any) required for PowerShell script execution.
  '   PRM_HostSharing            - "Yes" if the PowerShell script doesn't require its own host, or "No".
  '   PRM_TraceEventEnabled      - "True" if an execution log event at the specified log level should be raised.
  '   PRM_TraceEventSeverity     - The severity of the execution log event produced by PRM_TraceEventEnabled.
  '   PRM_TraceEventAutoSeverity - "Yes" to base severity on log entries (overrides PRM_TraceEventSeverity).
  '   PRM_TraceLevel             - "Fatal", "Error", "Warn", "Info", "Debug", or "Trace".
  '   PRM_ErrorBehavior          - "Silently Continue" (or "SilentlyContinue"), "Continue" or "Stop".
  '                                NOTE: Currently, "Continue" is treated as "Silently Continue".
  '
  If IsEmpty(PRM_SeverityFail) Then
      gintFailureSeverity = 5
  Else
      gintFailureSeverity = PRM_SeverityFail
  End If
  If IsEmpty(PRM_RequiredBitness) Then
      gstrRequiredBitness = "Any"
  Else
      gstrRequiredBitness = PRM_RequiredBitness
  End If
  If IsEmpty(PRM_HostSharing) Then
      gstrHostSharing = "Yes"
  Else
      gstrHostSharing = PRM_HostSharing
  End If
  If IsEmpty(PRM_TraceEventEnabled) Then
      gstrTraceEventEnabled = "No"
  Else
      gstrTraceEventEnabled = PRM_TraceEventEnabled
  End If
  If IsEmpty(PRM_TraceEventSeverity) Then
      gintTraceEventSeverity = 40
  Else
      gintTraceEventSeverity = PRM_TraceEventSeverity
  End If
  If IsEmpty(PRM_TraceEventAutoSeverity) Then
      gstrTraceEventAutoSeverity = "Yes"
  Else
      gstrTraceEventAutoSeverity = PRM_TraceEventAutoSeverity
  End If
  If IsEmpty(PRM_TraceLevel) Then
      gstrTraceLevel = "Error"
  Else
      gstrTraceLevel = PRM_TraceLevel
  End If
  If IsEmpty(PRM_ErrorBehavior) Then
      gstrErrorBehavior = "Continue"
  Else
      gstrErrorBehavior = PRM_ErrorBehavior
  End If

  '
  ' We treat "Continue" and "Silently Continue" the same as "SilentlyContinue".
  '
  If ((StrComp(gstrErrorBehavior, "Continue",          1) = 0)  _
   Or (StrComp(gstrErrorBehavior, "Silently Continue", 1) = 0)) Then
      gstrErrorBehavior = "SilentlyContinue"
  End If

  '
  ' Set the default resource object target for events.
  '
  gstrEventTarget = GetFirstEventTarget(garrScriptTargets)

  '
  ' Set the default trace level, which is based on gstrTraceLevel.
  '
  gintTraceLevel = GetDefaultTraceLevel()

End Sub

'
'  The method introduced to read 64bit registry from 32bits
'  The method gets the Exchange version from registry. 
'  If found return True o.w. False
'
'

Function GetExchangeVersionFromRegedit(strRegeditKey,strValueName)
Dim objValue
Dim uValue
strComputer = "."
Const HKLM = &h80000002
Set objCtx = CreateObject("WbemScripting.SWbemNamedValueSet")
objCtx.Add "__ProviderArchitecture", 64  
Set objLocator = CreateObject("Wbemscripting.SWbemLocator")
Set objServices = objLocator.ConnectServer("","root\default","","",,,,objCtx)
Set objStdRegProv = objServices.Get("StdRegProv") 

' Use ExecMethod to call the GetDWORDValue method
Set Inparams = objStdRegProv.Methods_("GetDWORDValue").Inparameters
'HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\ExchangeServer\v15\Setup\MsiProductMajor
Inparams.Hdefkey = HKLM
Inparams.Ssubkeyname = strRegeditKey
Inparams.Svaluename = strValueName
set Outparams = objStdRegProv.ExecMethod_("GetDWORDValue", Inparams,,objCtx)
objValue = Outparams.ReturnValue
 
If objValue <> 0 Then
  GetExchangeVersionFromRegedit = False 
Else
  uValue = Outparams.uValue
  If uValue = 15 Then        
	 	GetExchangeVersionFromRegedit = True 
	Else
		GetExchangeVersionFromRegedit = False
End If
End If


End Function

' The method sets the .net runtime based on Exchange installed  
' Exchange 2013 uses .net 4.0 and higher so runtime=4
' o.w. runtime=2
'
Function SetDotNetRuntimeVersionBasedOnExchange()
	Dim strExch2013SetupKey
	Dim strExchVersion
	Dim strValueName
	
	If gbExchangeOnlineKS = True Then
		gstrDotNetRuntime = "4"
		NQExt.QTrace "For Exchange online, setting .Net runtime set to v4"
	Else
		strExch2013SetupKey = "SOFTWARE\Microsoft\ExchangeServer\v15\Setup"
	    strValueName = "MsiProductMajor"    
		'First check is Exchange 2013 installed
		strExchVersion = GetExchangeVersionFromRegedit(strExch2013SetupKey,strValueName)
		If strExchVersion = False Then	    
			'Then check is Exchange 2010 or Exchange 2007 uses .Net runtine v2
			gstrDotNetRuntime = "2"	
			NQExt.QTrace "SetDotNetRuntimeVersionBasedOnExchange : .Net runtime set to v2"		
		Else
			gstrDotNetRuntime = "4"	
			NQExt.QTrace "SetDotNetRuntimeVersionBasedOnExchange : .Net runtime set to v4"		
		End If
	End If
End Function

Function CheckWindowsOSVersion()
	Trace TRACE_INFO, "CheckWindowsOSVersion - Enter"
	Dim strComputer, objWMIService, systemSet, bValidVersion
	
	bValidVersion = False
	
	strComputer = "."
	Set objWMIService = GetObject("winmgmts:{impersonationLevel=impersonate}!\\" & strComputer & "\root\cimv2")
	Set systemSet = objWMIService.ExecQuery ("Select * from Win32_OperatingSystem")
	
	For Each system In systemSet
		arr=system.Version
		tokens=split(arr, ".")
		If system.ProductType <> 1  And (tokens(0)=6 And (tokens(1)=2 Or tokens(1)=3)) Then
			bValidVersion = True
		End If 
	Next
	CheckWindowsOSVersion = bValidVersion
	Set objWMIService = Nothing
	Set colItems = Nothing
	
	Trace TRACE_INFO, "CheckWindowsOSVersion - Exit"
End Function

Function CheckIfAzureADModuleIsInstalled()
	Trace TRACE_INFO, "CheckIfAzureADModuleIsInstalled - Enter"
	
	Dim bInstalled, strVersion
	bInstalled = False
	Set objFSO = CreateObject("Scripting.FileSystemObject")
	If Not objFSO Is Nothing Then
		strVersion = objFSO.GetFileVersion(cstrPSModulePath)
		NQEXT.QTrace "Windows Azure Active Directory Module for Windows Powershell version is: " & strVersion
		If strVersion <> "" Then
			tokenizedVersion = split(strVersion, ".")
			' Supported versions are 1.0.9031.1 and 1.1.xxxx.x
			If (tokenizedVersion(0)=1) Then
				If (tokenizedVersion(1)=1 Or(tokenizedVersion(1)=0 And tokenizedVersion(2)=9031)) Then
					bInstalled = True
				End If
			End If
		End If
	End If

	CheckIfAzureADModuleIsInstalled = bInstalled
	
	Trace TRACE_INFO, "CheckIfAzureADModuleIsInstalled - Exit"
End Function

'
' Main - Script entry point.
'
Sub Main()

  InitializeGlobalVariables()

	' The method used to set the runtime parameter of .net
  SetDotNetRuntimeVersionBasedOnExchange
	
  If ValidateRequiredScriptVariables() And ValidateSelectedMonitoringOptions() Then
      RunPowerShellScript gstrScriptName, garrScriptParams
  End If

  

End Sub

' End: CommonCode.vbs 

'#
'# This global variable MUST be defined!
'# gstrExecuteInAllVersion - This variable is used to specify whether to execute this KS against all Exchange/MCPSHost version or not.
'#                           If it is set to true, the KS will execute against all Exchange/MCPSHost version.
'#                           Only in discovery KS this variable is set to true.
'#
gstrExecuteInAllVersion = False

'#
'# These global variables MUST be defined!
'#
'# gstrScriptName    - The name of this Knowledge Script, without the .qml extension.
'# garrScriptParams  - The name and type of the KS parameters that will be passed to the PowerShell script.
'# garrScriptTargets - An array containing the names of the resource object types this KS monitors.
'# gbExchangeOnlineKS - This boolean variable indicates whether this KS is for Exchange On-Premises or Exchange Online.
'#                      If this value is set to True, then this KS is for Exchange Online.

'#
'# Note that the types specified in the garrScriptParams array should be vbBoolean for Boolean
'# (checkbox or "y/n") parameters, and Null for all other parameters.
'#
gstrScriptName     = "AzureAD_DevicesCheck"
gbExchangeOnlineKS = True
garrScriptParams   = Array(SetPSVariable("AzureAD_Devices",                     Null     ), _
					   SetPSVariable("PRM_Devices_Crossed_TH",                         vbBoolean), _
					   SetPSVariable("PRM_Devices_Count_Threshold",						Null     ), _
					   SetPSVariable("PRM_Devices_TH_EventSeverity",						Null     ), _
					   SetPSVariable("PRM_SysAD_Devices_Sync_Status",                         vbBoolean), _
					   SetPSVariable("PRM_SysAD_Devices_Sync_Status_EventSeverity",						Null     ), _
					   SetPSVariable("PRM_Devices_New",                         vbBoolean), _
					   SetPSVariable("PRM_Devices_New_EventSeverity",           Null     ), _
					   SetPSVariable("PRM_Devices_Delete",                         vbBoolean), _
					   SetPSVariable("PRM_Devices_Delete_EventSeverity",           Null     ), _
					   SetPSVariable("PRM_SeverityFail",                               Null     ), _
                     SetPSVariable("AKPID",                                          Null     ))
garrScriptTargets = Array("AzureAD_Devices")


'#
'# ValidateScriptParameters
'#
'# Returns true if script parameters are valid, false otherwise.  Parameters should be considered
'# valid if at least one event and/or datastream parameter is set to "y", and if the KS has been
'# dropped on a TreeView node for which at least one of those parameters applies.
'#
Function ValidateScriptParameters(strResourceObject)

Trace TRACE_INFO, "ValidateScriptParameters - Enter"

Dim bValid : bValid = False

 If (Not bValid) And (NQExt.ItemCount(AzureAD_Devices, ",") > 0) Then
If PRM_Devices_Crossed_TH                     = "y" Or _
 PRM_SysAD_Devices_Sync_Status              = "y" Or _
 PRM_Devices_New              = "y" Or _
 PRM_Devices_Delete                     = "y" Then
  bValid = True
End If
End If
ValidateScriptParameters = bValid

Trace TRACE_INFO, "ValidateScriptParameters - Exit"

End Function
]]>
</Script>
</ScriptDef>

