#                                    
# Version number of this script.     
#                                    
$global:script_version = '7.6.119.0' 
                                     

$global:security_context = $null


function GetJobID
{
    $nqext.GetJobID()
}


function GetMachName
{
    $nqext.GetMachName()
}


function GetScriptInterval
{
    $nqext.GetScriptInterval()
}


function GetTempFileName
{
    param([System.String] $pathname,
          [System.String] $prefix,
          [System.Int32]    $unique_id)

    $nqext.GetTempFileName($pathname, $prefix, $unique_id)
}


function GetVersion
{
    param([System.String] $filename)

    $nqext.GetVersion($filename)
}


function GetProgID
{
    param([System.String] $prog_id,
          [System.String] $version)

    $nqext.GetProgID($prog_id, $version)
}


function IterationCount
{
    $nqext.IterationCount()
}


function NQSleep
{
    param([System.Int32]  $interval,
          [System.Boolean] $no_abort = $false)

    $nqext.NQSleep($interval, $no_abort)
}


function QTrace
{
    param([System.String] $message)

    $nqext.QTrace($message)
}

#
# If the resource full path length is greater than 156 characters, 
# then converting it into short path in the following format.
# <Resource_name>=#<obj_id>:<object_name>
# If the length short path is still greater than 156 characters, 
# we are considering only the first 156 characters, remaining characters are trimmed.
# The trimming won't be any problem because <Resource_name> and <obj_id> are necessary to distinguish the objects.
# The combined length of <Resource_name> and <obj_id> always less than 50 characters.
#
function TrimResource
{
    param ([System.String] $resource)
    
    if ($resource)
    {
        if ($global:max_resource_length -and ($resource.Length -gt $global:max_resource_length))
        {
            $index = $resource.IndexOf(':')
            if ($index -gt -1)
            {
                $short_path  = $resource.SubString(0, $index)
                $index       = $resource.LastIndexOf(':')
                $short_path += $resource.SubString($index)
                if ($short_path.Length -gt $global:max_resource_length)
                {
                    $short_path = $short_path.SubString(0, $global:max_resource_length)
                }
                $resource = $short_path
            }
        }
    }
    
    $resource
}

#
# Create an AppManager event with default values for those properties of
# the event that don't normally need to have specific values specified.
#
function CreateEvent
{
    param([System.Int32]    $severity,
          [System.String] $event_msg,
          [System.String] $detail_msg,
          [System.String] $resource,
          [System.String] $action       = "AKP_NULL",
          [System.Boolean]   $proxy        = $false,
          [System.String] $kb_id        = $null,
          [System.String] $metadata_xml = $null)

    if (-not $event_msg)
    {
        $stack_trace = GetStackTrace
        Trace "Error" "CreateEvent called with no event message.  Stack trace follows.`n$stack_trace"
    }

    #
    # Replace \r\n by \n so that the message is formatted correctly
    # in the main event dialog as well as the event details dialog.
    #
    $detail_msg = $detail_msg -replace "`r`n", "`n"

    $resource = ConvertResourceObjectPath $resource
    $resource = TrimResource $resource

    $temp_event_msg = $event_msg
    $event_msg      = $global:prefix_server_name + $temp_event_msg

    Trace "Debug" "CreateEvent: Resource:   $resource"
    Trace "Debug" "CreateEvent: Severity:   $severity"
    Trace "Debug" "CreateEvent: EventMsg:   $event_msg"
    Trace "Debug" "CreateEvent: DetailMsg:  $detail_msg"
    Trace "Debug" "CreateEvent: Action:     $action"

    $nqext.CreateEventEx($kb_id, $metadata_xml, $severity, $event_msg, `
                         $action, $resource, 0.0, $detail_msg, `
                         "MCPSHostServer", 0, 0, $proxy, $true)
}


#
# Create an AppManager data point with default values for those properties
# of the data point that don't normally need to have specific values specified.
#
function CreateData
{
    param([System.String] $stream,
          [System.String] $legend,
          [System.String] $dynalegend,
          [System.String] $resource,
          [System.String] $value,
          [System.String] $detail_msg,
          [System.String] $kb_id        = $null,
          [System.String] $metadata_xml = $null)

    #
    # Replace \r\n by \n so that the message is formatted correctly
    # in the main event dialog as well as the event details dialog.
    #
    $detail_msg = $detail_msg -replace "`r`n", "`n"

    $resource = ConvertResourceObjectPath $resource
    $resource = TrimResource $resource
    
    $culture_info   = [Threading.Thread]::CurrentThread.CurrentCulture
    $culture_info   = New-Object Globalization.CultureInfo $culture_info.Name
    [System.Double]$dvalue = [System.Double]::Parse($value, $culture_info)

    Trace "Debug" "CreateData: Stream:     $stream"
    Trace "Debug" "CreateData: Legend:     $legend"
    Trace "Debug" "CreateData: DynaLegend: $dynalegend"
    Trace "Debug" "CreateData: Resource:   $resource"
    Trace "Debug" "CreateData: DetailMsg:  $detail_msg"
    Trace "Debug" "CreateData: Value:      $dvalue"

    $nqext.CreateDataEx($kb_id, $metadata_xml, $stream, $legend, `
                        $dynalegend, $resource, $dvalue, $detail_msg, `
                        0, "NULL", -1, -1.0, -1.0, $true, $true, 0)
}


function AbortScript
{
    param([System.Int32]    $severity,
          [System.String] $resource,
          [System.String] $detail_msg,
          [System.String] $raise_error,
          [System.String] $kb_id        = $null,
          [System.String] $metadata_xml = $null)

    #
    # Replace \r\n by \n so that the message is formatted correctly
    # in the main event dialog as well as the event details dialog.
    #
    $detail_msg = $detail_msg -replace "`r`n", "`n"

    $resource = ConvertResourceObjectPath $resource
    $resource = TrimResource $resource

    Trace "Debug" "AbortScript: Resource:   $resource"
    Trace "Debug" "AbortScript: Severity:   $severity"
    Trace "Debug" "AbortScript: DetailMsg:  $detail_msg"
    Trace "Debug" "AbortScript: RaiseError: $raise_error"

    $nqext.AbortScriptEx($kb_id, $metadata_xml, $resource, $detail_msg, `
                         $severity, $raise_error)
}


#
# Get an array containing the three values associated with the given
# security manager label and sublabel.
#
function GetSecurityContext
{
    param([System.String] $label,
          [System.String] $sublabel,
          [System.Boolean]   $decrypt = $false)

    $result = $null

    if ($global:security_context -eq $null)
    {
        $global:security_context = @{}
    }

    $result = $global:security_context["$label/$sublabel"]

    if (-not $result)
    {
        $value1 = $nqext.GetSecurityContext($label, $sublabel, "Val1", $decrypt)
        $value2 = $nqext.GetSecurityContext($label, $sublabel, "Val2", $decrypt)
        $value3 = $nqext.GetSecurityContext($label, $sublabel, "Val3", $decrypt)

        if ($value1 -or $value2 -or $value3)
        {
            [string[]] $result = $value1, $value2, $value3
        }

        $global:security_context["$label/$sublabel"] = $result
    }

    $result
}


function ExportData
{
    param([System.String] $key,
          [object] $value)

    $nqext.ExportData($key, $value)
}


function ImportData
{
    param([System.String] $key)

    $nqext.ImportData($key)
}


function DictionaryInsertValue
{
    param([System.String] $key,
          [System.String] $value)

    $nqext.DictionaryInsertValue($key, $value)
}


function DictionaryRetrieveValue
{
    param([System.String] $key)

    $nqext.DictionaryRetrieveValue($key)
}


function DictionaryRetrieveAllValues
{
    $result = $nqext.DictionaryRetrieveAllValues()

    if ($result -is [System.Array])
    {
        $hash_result = @{}
        for ($i = 0; $i -lt $result.Length; $i += 2)
        {
            $hash_result[$result[$i]] = $result[$i+1]
        }
        $result = $hash_result
    }

    $result
}


function DictionaryRetrieveByPattern
{
    param([System.String] $pattern)

    $result = $nqext.DictionaryRetrieveByPattern($pattern)

    if ($result -is [System.Array])
    {
        $hash_result = @{}
        for ($i = 0; $i -lt $result.Length; $i += 2)
        {
            $hash_result[$result[$i]] = $result[$i+1]
        }
        $result = $hash_result
    }

    $result
}


function DictionaryRemoveValue
{
    param([System.String] $key)

    $nqext.DictionaryRemoveValue($key)
}


function BuildDynamicLegendXML
{
    param([System.String] $static_desc,
          [System.String] $dynamic_desc,
          [System.String] $original_ks_name,
          [System.String] $application_name,
          [System.String] $obj_and_type_name,
          [System.String] $units,
          [System.String] $fullpath_obj_name  = $null,
          [System.String] $fullpath_delimiter = $null,
          [System.String] $transform_type     = $null)

    $nqutil.BuildDynamicLegendXML($static_desc,
                                  $dynamic_desc,
                                  $original_ks_name,
                                  $application_name,
                                  $obj_and_type_name,
                                  $units,
                                  $fullpath_obj_name,
                                  $fullpath_delimiter,
                                  $transform_type)
}


function BuildDetailTableXML
{
    param([System.Collections.Hashtable] $table_info)

    $nqutil.BuildDetailTableXML($table_info);
}


#
# Write a trace statement to the log or console.
#
function Trace
{
    param([System.String] $tracelevel,
          [System.String] $traceline)

    if ($nqext)
    {
        $nqext.PSTrace($tracelevel, "[PS] - " + $traceline)
    }
    else
    {
        write-output "$traceline"
    }
}


#
# Sets variables based upon command-line arguments.
#
function SetCommandLineVariables
{
    param([string[]] $cmdline_args)

    foreach ($arg in $cmdline_args)
    {

        if ($arg)
        {
            $var_name, $var_val = $arg.Split("=", 2)

            if($var_name.Contains('-')){
            $var_name = $var_name.Substring(1,$var_name.Length-1)}

            switch -regex ($var_val)
            {
                '^\$false$'
                {
                    Set-Variable $var_name $false -Scope global
                    break
                }

                '^\$true$'
                {
                    Set-Variable $var_name $true -Scope global
                    break
                }

                '^\$null$'
                {
                    Set-Variable $var_name $null -Scope global
                    break
                }

                '^\d+$'
                {
                    Set-Variable $var_name ([Int32]::Parse($var_val)) `
                                                        -Scope global
                    break
                }

                '^\d*\.\d*$'
                {
                    Set-Variable $var_name ([System.Double]::Parse($var_val)) `
                                                         -Scope global
                    break
                }

                '^".*"$'
                {
                    $var_val = $var_val.SubString(1, $var_val.Length-2)
                    Set-Variable $var_name $var_val -Scope global
                    break
                }

                '.'
                {
                    Set-Variable $var_name $var_val.ToString() -Scope global
                    break
                }

                default
                {
                    Set-Variable $var_name $false -Scope global
                    break
                }
            }

            #
            # Note: No spaces around the "=" because we want to be able to copy
            #       these lines from the log file and paste them into a file to
            #       be used as a job parameter configuration file, which can be
            #       used when running MCPSHostServer.exe in test mode.  In this
            #       job parameter configuration file spaces are significant, to
            #       support parameter values that begin with a space.
            #
            Trace "Debug" "Script Parameter: $var_name=$var_val"
        }
    }
}


#
# Set the window width to a reasonably large size.  Note that the maximum
# window width depends upon the environment, although it's not clear what
# particular attribute(s) of the environment affect the maximum width.
#
function SetWindowWidth
{
    #
    # Attempt to set the window width to a reasonable size, so that text produced
    # by the Format-Table cmdlet and included in event details includes as many
    # columns as possible, with reasonable column widths.
    #
    $script:window_width = 150
    $script:window_width_set = $false;

    while (($script:window_width -gt 0) -and (-not $script:window_width_set))
    {
        trap
        {
            Trace "Debug" "Failed to set window width to $window_width"
            $script:window_width = $script:window_width - 10
            $error.Clear()
            continue
        }

        [Console]::WindowWidth = $script:window_width
        $script:window_width_set = [Console]::WindowWidth -eq $script:window_width
    }

    Trace "Debug" ("Window width has been set to " + [Console]::WindowWidth)
}


#
# Return the major version of the PowerShell engine on the local host
#     Return type: integer
#
function GetPSMajorVersion
{

    $major_version = 1

    if (test-path variable:PSVersionTable)
    {
        $major_version = $PSVersionTable.PSVersion.Major
    }

    Trace "Debug" "GetPSMajorVersion: PowerShell major version is $major_version"

    return $major_version
}

#
# Return the value of the first function argument that is considered
# a true value (that is, something other than $null, "", 0, etc.).
# If no arguments are considered true, the function returns $null.
#
# Examples:
#
#   FirstOf 5 7)           # returns 5
#   FirstOf "" 0 "thing"   # returns "thing"
#   FirstOf "" 0 $null     # returns $null
#
function FirstOf
{
    $first = $null

    foreach ($arg in $args)
    {
        if ($arg)
        {
            $first = $arg
            break
        }
    }

    return $first
}


function HostName
{
    $hostname = [Environment]::MachineName

    If ((Get-Service | Where {$_.Name -match "ClusSvc"} | Select Status).Status -eq "Running")
    {
        If ((Get-Service | Where {$_.Name -match "MSExchangeIS"} | Select Status).Status -eq "Running")
        {
            trap { $hostname = [Environment]::MachineName; $error.Clear(); continue }
            $hostname = $($(Get-ClusteredMailboxServerStatus).Identity).Name
        }
    }

    return $hostname
}


#
# Get the domain name.
#
function DomainName
{
    $global_properties = [Net.NetworkInformation.IPGlobalProperties]::GetIPGlobalProperties()
    $global_properties.DomainName
}


#
# Get a string containing stack trace information, for debugging purposes.
#
function GetStackTrace
{
    trap { continue }

    $stack_trace  = ""
    $stack_frames = @()

    1..100 |
    %{
        $invocation = &{ Get-Variable -scope $_ MyInvocation } 2>$null

        if ($invocation)
        {
            if ($invocation.Value.PositionMessage)
            {
                $stack_frames += $invocation.Value.PositionMessage.Replace("`n", "")
            }
        }
    }

    foreach ($stack_frame in $stack_frames)
    {
        if ($stack_frame)
        {
            $stack_trace += "$stack_frame`n"
        }
    }

    $error.Clear()
    return $stack_trace
}


#
# Load a library (assembly) by its name, e.g., "System.ServiceProcess".
#
function LoadLibrary
{
    param([System.String] $library_name)

    if ($script:loaded_libraries -eq $null)
    {
        $script:loaded_libraries = @()
    }
    if (-not ($script:loaded_libraries -contains $library_name))
    {
        [Reflection.Assembly]::LoadWithPartialName($library_name) | Out-Null
        $loaded_libraries += $library_name
    }
}


#
# Execute an external program and return the lines written to standard output as an array.
#
# NOTE: This function should be used ONLY FOR UNIT TESTING, because the timeout cannot be
#       enforced (because we must read all data synchronously before calling WaitForExit,
#       which means the timeout will effectively be ignored).  Scripts running "for real"
#       under MCPSHostServer should use the host's ExecuteProgram method instead:
#
#       $pshost = [NetIQ.Common.PSHost.BasicPSHost] $host
#       $lines = $pshost.ExecuteProgram($program_name, $program_arguments, $timeout)
#
function ExecuteProgram
{
    param([System.String] $program,
          [System.String] $arguments,
          [System.Int32]    $timeout)

    $results = $null

    trap
    {
        Trace "Error" "Exception thrown when running command: $program $arguments`n" `
                    + "Exception details: $_"
        break
    }

    $process = New-Object System.Diagnostics.Process
    $process.StartInfo.RedirectStandardOutput = $true
    $process.StartInfo.UseShellExecute        = $false
    $process.StartInfo.FileName               = $program
    $process.StartInfo.Arguments              = $arguments
    $process.Start()

    $start_time = [DateTime]::Now

    $delimiters = [char[]] "`r`n"
    $split_options = [StringSplitOptions]::RemoveEmptyEntries
    $results = $process.StandardOutput.ReadToEnd().Split($delimiters, $split_options)

    if ($process.WaitForExit($timeout * 1000))
    {
        $process.Close()
    }
    else
    {
        $process.Kill()
        $process.Close()
        throw "The $program program failed to complete in $timeout seconds."
    }

    if (([DateTime]::Now - $start_time).Seconds -gt $timeout)
    {
        throw "The $program program failed to complete in $timeout seconds."
    }

    $results
}


#
# Format the results of a test, with summary table at the top, followed
# by details of the results.
#
function FormatTestResults
{
    param([object] $test_results)

    $message1 = $test_results | Format-Table -Autosize -Wrap | Out-String
    $message2 = $test_results | Format-List | Out-String

    $message1 + "Details:`n" + $message2
}


#
# Given a username, look up the password in Security Manager and return a
# PSCredential object with the username and password.
#
# This method assumes that the Security Manager label is "Exchange2007"
# and the sublabel is the username.
#
function GetCredentials
{
    param([System.String] $username)

    $credentials = $null

    if (! $global:credentials)
    {
        $global:credentials = @{}
    }
    else
    {
        $credentials = $global:credentials[$username]
    }

    if (! $credentials)
    {
        $info = GetSecurityContext 'Exchange2007' $username

        if ($info)
        {
            $password = new-object Security.SecureString

            foreach ($char in $credentials[0])
            {
                $password.AppendChar($char)
            }

            $credentials = new-object Management.Automation.PSCredential `
                                                    $username, $password
            $global:credentials[$username] = $credentials
        }
    }

    $credentials
}


#
# Given a hashtable that maps parameter names (without the "-" prefix) to
# values, build a string containing cmdlet arguments for those parameters.
#
function BuildCmdletArgs
{
    param([System.Collections.Hashtable] $function_args = $null)

    $cmdlet_args = ""

    if ($function_args)
    {
        foreach ($key in $function_args.Keys)
        {
            $cmdlet_args += " -" + $key + " " + $function_args[$key]
        }
    }

    $cmdlet_args
}


#
# Invoke a PowerShell command in a nested pipeline in the current runspace.
# This is similar to "eval" in Perl, and allows a command to be constructed
# dynamically and then executed.
#
function InvokeCommand
{
    param([System.String]      $command,
          [System.String]      $target_resources,
          [System.Int32]         $failure_severity,
          [System.String]      $action_to_be_taken,
          [System.Management.Automation.ScriptBlock] $exception_handler = $null)

    $error.Clear()

    trap
    {
        Trace "Error" "Exception thrown while invoking the command; message: $_"
        continue
    }

    Trace "Debug" ("Invoking command: " + $command)

    # Get cmdlet name
    $command_name = ([Text.RegularExpressions.Regex]::Split($command, "\s+"))[0]

    #
    # The Test-OutlookWebServices cmdlet must be run in-process, because the
    # serialized result that would be returned if it runs out of process
    # does not deserialize in a manner that allows access to the messages
    # included in the result.
    #
    $runspace = [Management.Automation.Runspaces.Runspace]::DefaultRunspace
    $pipeline = $runspace.CreateNestedPipeline()
    $pipeline.Commands.AddScript($command, $false)
    $result = $pipeline.Invoke()

    # Remove extraneous error messages
    if ($command_name -match "^Test-")
    {
        RemoveErrorMessage "Microsoft.Exchange.Configuration.Tasks.ThrowTerminatingErrorException"

        if ($command_name -match "^Test-ActiveSyncConnectivity")
        {
            RemoveErrorMessage "The connection cache size can only be set once"
        }
    }

    #
    # Copy any errors that occurred in the pipeline to $error.
    # This must be done before we call CheckForErrors.
    #
    foreach ($error_result in $pipeline.Error.Read())
    {
        $error.Add($error_result) | Out-Null
    }

    if ($exception_handler)
    {
        $no_errors = CheckForErrors $exception_handler
    }
    else
    {
        $no_errors = CheckForErrors $target_resources $null $command_name "health test"
    }

    if ($result)
    {
        Trace "Debug" "Command $command returned results: $result"
    }
    else
    {
        Trace "Error" "Command $command failed to execute."
    }

    $result
}


#
# Return a string value from the Windows registry.
#
function GetRegistryString
{
    param([System.String] $registryKey,
          [System.String] $registryString)

    trap
    {
        Trace "Error" "GetRegistryString: Exception thrown retrieving item for $registryKey; message: $_"
        continue
    }

    $regKey = Get-ItemProperty -Path $registryKey

    if ($nqext)
    {
        Trace "Info" "GetRegistryString: Registry string from `"$registryKey`" is: $regKey.$registryString"
    }

    if ($regKey)
    {
        $regKey.$registryString
    }
    else
    {
        $null
    }
}


#
# Initialize the $global:default_resource variable.  This variable specifies an arbitrary
# AM resource object that the job is running against.  This can be usd in event messages
# raised in cases where we can't load the Exchange snap-in.
#
function InitializeDefaultResource
{
    $resource_name  = $null
    $resource_value = $null

    Trace "Debug" "InitializeDefaultResource: Enter"

    #
    # NOTE: Some of these resource types aren't in use; they'll be ignored because they're not defined.
    #       This list should be pruned to include only those resource types actually used.  (But not at
    #       this point in the current release....)
    #
    $resource_names =
    @(
        "NT_MachineFolder",
        "NT_VIR_MachineFolder",

        "Exchange_Server",
        "Exchange2007_ClientAccessServer",
        "Exchange2007_MailboxServer",
        "Exchange2007_EdgeTransportServer",
        "Exchange2007_UnifiedMessagingServer",
        "Exchange2007_HubTransportServer",
        "Exchange2007_Store_Group",
        "Exchange2007_Store_Database",
        "Exchange2007_Store_PFDatabase",
        "Exchange2007_Queue",
        "Exchange2007_Services",
        "Exchange2007_Service",

        "Exchange2010_ClientAccessServer",
        "Exchange2010_MailboxServer",
        "Exchange2010_EdgeTransportServer",
        "Exchange2010_UnifiedMessagingServer",
        "Exchange2010_HubTransportServer",
        "Exchange2010_Store_Database",
        "Exchange2010_Store_PFDatabase",
        "Exchange2010_Queue",
        "Exchange2010_Services",
        "Exchange2010_Service",

        "Exchange2013_ClientAccessServer",
        "Exchange2013_MailboxServer",
        "Exchange2013_EdgeTransportServer",
        "Exchange2013_UnifiedMessagingServer",
        "Exchange2013_HubTransportServer",
        "Exchange2013_Store_Database",
        "Exchange2013_Store_PublicFolder",
        "Exchange2013_Queue",
        "Exchange2013_Services",
        "Exchange2013_Service"
		
	    "Exchange2016_ClientAccessServer",
        "Exchange2016_MailboxServer",
        "Exchange2016_EdgeTransportServer",
        "Exchange2016_UnifiedMessagingServer",
        "Exchange2016_HubTransportServer",
        "Exchange2016_Store_Database",
        "Exchange2016_Store_PublicFolder",
        "Exchange2016_Queue",
        "Exchange2016_Services",
        "Exchange2016_Service"
		
		"ExchangeOnline_MailBox",
		"ExchangeOnline_Service"
		
		"AzureAD_Connect",
		"AzureAD_Domains",
		"AzureAD_Users_Groups"
    )


    trap
    {
        Trace "Error" "InitializeDefaultResource: Exception thrown while iterating through possible resource names => message: $_"
        continue
    }

    if (-not $global:default_resource)
    {
        foreach ($resource_name in $resource_names)
        {
            $resource_var = Get-Variable $resource_name -ValueOnly -ErrorAction SilentlyContinue

            if ($resource_var)
            {
                Trace "Info" "InitializeDefaultResource: Object type $resource_name exists and its value => *** '$resource_var' *** exists, so setting its value"
                $resource_value = $resource_var
                break;
            }
            else
            {
                Trace "Debug" "InitializeDefaultResource: Object type value not set for type '$resource_name'"
            }
        }

        if ($resource_value)
        {
            Trace "Debug" "InitializeDefaultResource: Setting global:default_resource to '$resource_name = $resource_value'"
            $global:default_resource = Invoke-Expression "'$resource_name = $resource_value'" -ErrorAction Stop
            Trace "Debug" "InitializeDefaultResource: Set default resource: '$global:default_resource'"
        }
        else
        {
            Trace "Error" "InitializeDefaultResource: Error - Failed to find any resources for the job, throwing exception"
            throw "InitializeDefaultResource: Failed to find any resources for the job."
        }

    }
    else
    {
        Trace "Debug" "InitializeDefaultResource: Skipping resource iteration as global:default_resource already set to '$global:default_resource'"
    }


    Trace "Debug" "InitializeDefaultResource: Exit"
}


#
# Get the TreeView resource and fullpath that the KS was dropped on.  For KS's
# that drop on a particular server role node in the TreeView, and General KS's
# that drop on the top-level Exchange2007 node, the resource and fullpath always
# refer to that node.  For KS's that drop on lower level nodes (such as services,
# queues, and mailbox databases), if the KS was dropped on multiple nodes this
# function picks an arbitrary node from that set.
#
function GetDefaultResourceAndFullPath
{
    $node_state = 0
    $event_detail_msg = ""

    Trace "Debug" "GetDefaultResourceAndFullPath: Enter"

    if ($global:b_is_exch2010 -eq $true)
    {
        Trace "Info" "GetDefaultResourceAndFullPath: Exchange 2010 Tree view resource and full path"

        $global:exchange_cas              = $Exchange2010_ClientAccessServer
        $global:cas_resource              = "Exchange2010_ClientAccessServer"

        $global:exchange_mbs              = $Exchange2010_MailboxServer
        $global:mbs_resource              = "Exchange2010_MailboxServer"

        $global:exchange_ets              = $Exchange2010_EdgeTransportServer
        $global:ets_resource              = "Exchange2010_EdgeTransportServer"

        $global:exchange_ums              = $Exchange2010_UnifiedMessagingServer
        $global:ums_resource              = "Exchange2010_UnifiedMessagingServer"

        $global:exchange_hts              = $Exchange2010_HubTransportServer
        $global:hts_resource              = "Exchange2010_HubTransportServer"

        $global:exchange                  = $Exchange_Server
        $global:exchange_resource         = "Exchange_Server"

        $global:exchange_store_database   = $Exchange2010_Store_Database
        $global:store_database_resource   = "Exchange2010_Store_Database"

        $global:exchange_store_pfdatabase = $Exchange2010_Store_PFDatabase
        $global:store_pfdatabase_resource = "Exchange2010_Store_PFDatabase"

        $global:exchange_queue            = $Exchange2010_Queue
        $global:queue_resource            = "Exchange2010_Queue"

        $global:exchange_services         = $Exchange2010_Services
        $global:services_resource         = "Exchange2010_Services"

        $global:exchange_service          = $Exchange2010_Service
        $global:ser_resource              = "Exchange2010_Service"
    }
    elseif ($global:b_is_exch2013 -eq $true)
    {
        Trace "Info" "GetDefaultResourceAndFullPath: Exchange 2013 Tree view resource and full path"

        $global:exchange_cas              = $Exchange2013_ClientAccessServer
        $global:cas_resource              = "Exchange2013_ClientAccessServer"

        $global:exchange_mbs              = $Exchange2013_MailboxServer
        $global:mbs_resource              = "Exchange2013_MailboxServer"

        $global:exchange_ets              = $Exchange2013_EdgeTransportServer
        $global:ets_resource              = "Exchange2013_EdgeTransportServer"

        $global:exchange_ums              = $Exchange2013_UnifiedMessagingServer
        $global:ums_resource              = "Exchange2013_UnifiedMessagingServer"

        $global:exchange_hts              = $Exchange2013_HubTransportServer
        $global:hts_resource              = "Exchange2013_HubTransportServer"

        $global:exchange                  = $Exchange_Server
        $global:exchange_resource         = "Exchange_Server"

        $global:exchange_store_database   = $Exchange2013_Store_Database
        $global:store_database_resource   = "Exchange2013_Store_Database"

        $global:exchange_store_pfdatabase = $Exchange2013_Store_PublicFolder
        $global:store_pfdatabase_resource = "Exchange2013_Store_PublicFolder"

        $global:exchange_queue            = $Exchange2013_Queue
        $global:queue_resource            = "Exchange2013_Queue"

        $global:exchange_services         = $Exchange2013_Services
        $global:services_resource         = "Exchange2013_Services"

        $global:exchange_service          = $Exchange2013_Service
        $global:ser_resource              = "Exchange2013_Service"
    }
    elseif ($global:b_is_exch2016 -eq $true)
    {
        Trace "Info" "GetDefaultResourceAndFullPath: Exchange 2016 Tree view resource and full path"

        $global:exchange_cas              = $Exchange2016_ClientAccessServer
        $global:cas_resource              = "Exchange2016_ClientAccessServer"

        $global:exchange_mbs              = $Exchange2016_MailboxServer
        $global:mbs_resource              = "Exchange2016_MailboxServer"

        $global:exchange_ets              = $Exchange2016_EdgeTransportServer
        $global:ets_resource              = "Exchange2016_EdgeTransportServer"

        $global:exchange_ums              = $Exchange2016_UnifiedMessagingServer
        $global:ums_resource              = "Exchange2016_UnifiedMessagingServer"

        $global:exchange_hts              = $Exchange2016_HubTransportServer
        $global:hts_resource              = "Exchange2016_HubTransportServer"

        $global:exchange                  = $Exchange_Server
        $global:exchange_resource         = "Exchange_Server"

        $global:exchange_store_database   = $Exchange2016_Store_Database
        $global:store_database_resource   = "Exchange2016_Store_Database"

        $global:exchange_store_pfdatabase = $Exchange2016_Store_PublicFolder
        $global:store_pfdatabase_resource = "Exchange2016_Store_PublicFolder"

        $global:exchange_queue            = $Exchange2016_Queue
        $global:queue_resource            = "Exchange2016_Queue"

        $global:exchange_services         = $Exchange2016_Services
        $global:services_resource         = "Exchange2016_Services"

        $global:exchange_service          = $Exchange2016_Service
        $global:ser_resource              = "Exchange2016_Service"
    }
    elseif ($global:b_is_exch2007 -eq $true)
    {
        Trace "Info" "GetDefaultResourceAndFullPath: Exchange 2007 Tree view resource and full path"

        $global:exchange_cas              = $Exchange2007_ClientAccessServer
        $global:cas_resource              = "Exchange2007_ClientAccessServer"

        $global:exchange_mbs              = $Exchange2007_MailboxServer
        $global:mbs_resource              = "Exchange2007_MailboxServer"

        $global:exchange_ets              = $Exchange2007_EdgeTransportServer
        $global:ets_resource              = "Exchange2007_EdgeTransportServer"

        $global:exchange_ums              = $Exchange2007_UnifiedMessagingServer
        $global:ums_resource              = "Exchange2007_UnifiedMessagingServer"
        $global:exchange_hts              = $Exchange2007_HubTransportServer
        $global:hts_resource              = "Exchange2007_HubTransportServer"

        $global:exchange                  = $Exchange_Server
        $global:exchange_resource         = "Exchange_Server"

        $global:exchange_store_group      = $Exchange2007_Store_Group
        $global:store_group_resource      = "Exchange2007_Store_Group"

        $global:exchange_store_database   = $Exchange2007_Store_Database
        $global:store_database_resource   = "Exchange2007_Store_Database"

        $global:exchange_store_pfdatabase = $Exchange2007_Store_PFDatabase
        $global:store_pfdatabase_resource = "Exchange2007_Store_PFDatabase"

        $global:exchange_queue            = $Exchange2007_Queue
        $global:queue_resource            = "Exchange2007_Queue"

        $global:exchange_services         = $Exchange2007_Services
        $global:services_resource         = "Exchange2007_Services"

        $global:exchange_service          = $Exchange2007_Service
        $global:ser_resource              = "Exchange2007_Service"
    }
	else
	{
		$global:exchangeonline_mailboxquota    = $ExchangeOnline_MailBox
		Trace "Debug" "GetDefaultResourceAndFullPath: global:exchangeonline_mailboxquota =$global:exchangeonline_mailboxquota"
        $global:exchangeonline_mailboxquota_resource  = "ExchangeOnline_MailBox"
		Trace "Debug" "GetDefaultResourceAndFullPath: global:exchangeonline_mailboxquota_resource =$global:exchangeonline_mailboxquota_resource"
		$global:ExchangeOnline_ServiceHealth    = $ExchangeOnline_Service
		Trace "Debug" "GetDefaultResourceAndFullPath: global:ExchangeOnline_ServiceHealth =$global:ExchangeOnline_ServiceHealth"
        $global:ExchangeOnline_ServiceHealth_resource  = "ExchangeOnline_Service"
		Trace "Debug" "GetDefaultResourceAndFullPath: global:ExchangeOnline_ServiceHealth_resource =$global:ExchangeOnline_ServiceHealth_resource"
		
		$global:azuread_usersinfo    = $AzureAD_Users_Groups
		Trace "Debug" "GetDefaultResourceAndFullPath: global:azuread_userssinfo =$global:azuread_usersinfo"
        $global:azuread_usersinfo_resource  = "AzureAD_Users_Groups"
		Trace "Debug" "GetDefaultResourceAndFullPath: global:azuread_usersinfo_resource =$global:azuread_usersinfo_resources"
	}

	if ($global:exchangeonline_mailboxquota)
    {
        $target_fullpath = $global:exchangeonline_mailboxquota
        $target_resource = "$global:exchangeonline_mailboxquota_resource = $global:exchangeonline_mailboxquota_resource"
    }
	if ($global:ExchangeOnline_ServiceHealth)
    {
        $target_fullpath = $global:ExchangeOnline_ServiceHealth
        $target_resource = "$global:ExchangeOnline_ServiceHealth_resource = $global:ExchangeOnline_ServiceHealth_resource"
    }
	
	if ($global:azuread_usersinfo)
    {
        $target_fullpath = $global:azuread_usersinfo
        $target_resource = "$global:azuread_usersinfo_resource = $global:azuread_usersinfo_resource"
    }

    if ($global:exchange_cas)
    {
        $target_fullpath = $global:exchange_cas
        $target_resource = "$global:cas_resource = $global:exchange_cas"
    }
    elseif ($global:exchange_mbs)
    {
        $target_fullpath = $global:exchange_mbs
        $target_resource = "$global:mbs_resource = $global:exchange_mbs"
    }
    elseif ($global:exchange_ets)
    {
        $target_fullpath = $global:exchange_ets
        $target_resource = "$global:ets_resource = $global:exchange_ets"
    }
    elseif ($global:exchange_hts)
    {
        $target_fullpath = $global:exchange_hts
        $target_resource = "$global:hts_resource = $global:exchange_hts"
    }
    elseif ($global:exchange_ums)
    {
        $target_fullpath = $global:exchange_ums
        $target_resource = "$global:ums_resource = $global:exchange_ums"
    }
    elseif ($Exchange_Server)
    {
        $target_fullpath = $Exchange_Server
        $target_resource = "Exchange_Server = $Exchange_Server"
    }
    elseif ($Exchange2010_DAG_Databases)
    {
        $target_fullpath = $Exchange2010_DAG_Databases
        $target_resource = "Exchange2010_DAG_Databases = $Exchange2010_DAG_Databases"
    }
    elseif ($Exchange2013_DAG_Databases)
    {
        $target_fullpath = $Exchange2013_DAG_Databases
        $target_resource = "Exchange2013_DAG_Databases = $Exchange2013_DAG_Databases"
    }
    elseif ($Exchange2016_DAG_Databases)
    {
        $target_fullpath = $Exchange2016_DAG_Databases
        $target_resource = "Exchange2016_DAG_Databases = $Exchange2016_DAG_Databases"
    }
    elseif ($Exchange2007_Store_Group)
    {
        $temp_server_name = $Exchange2007_Store_Group.split(":")
        $server_name = $temp_server_name[1]
        $node_state = NodeVirtualServerStatus $server_name

        $store_group_names = GetMonitoredStorageGroupNames
        $store_group_name  = %{ if ($store_group_names -is [System.Array]) { $store_group_names[0] }
                                                               else { $store_group_names    } }
        if (-1 -ne $node_state)
        {
            $store_group = Get-StorageGroup $store_group_name
            $target_fullpath = GetStorageGroupFullPath $store_group
            $target_resource = GetStorageGroupResource $store_group
        }
        if (($target_fullpath -eq $Null) -or ($target_resource -eq $Null))
        {
            $event_detail_msg = "Storage Group " + $store_group_name + " has been removed.  " `
                              + "Run Discovery_Exchange2007 to update the resource objects."
        }
    }
    elseif ($Exchange2007_Store_Database)
    {
        $temp_server_name = $Exchange2007_Store_Database.split(":")
        $server_name = $temp_server_name[1]
        $node_state = NodeVirtualServerStatus $server_name

        $database_names = GetMonitoredMailboxDatabaseNames
        $database_name  = %{ if ($database_names -is [System.Array]) { $database_names[0] }
                                                         else { $database_names    } }
        if (-1 -ne $node_state)
        {
            $database = Get-MailboxDatabase $database_name
            $target_fullpath = GetMailboxDatabaseFullPath $database
            $target_resource = GetMailboxDatabaseResource $database
        }
        if (($target_fullpath -eq $Null) -or ($target_resource -eq $Null))
        {
            $event_detail_msg = "Database " + $database_name + " has been removed.  " `
                              + "Run Discovery_Exchange2007 to update the resource objects."
        }
    }
    elseif ($Exchange2010_Store_Database)
    {
        $database_name = ""

        # if the Exchange 2010 node is part of DAG, then will look similar to the following object.
        # Exchange2010_Store_Database = "BLRDAG01:MBS:Mailbox Database 1604659876:234"
        # if the Exchange 2010 node is a physical node, then will look similar to the following object.
        # Exchange2010_Store_Database = "Exchange2010:BLRDVAM5188:MBS:BLRDVAM5188:Mailbox Database 0708137508:589"
        # We are retrieving first database from it.

        $temp_db_name  = $Exchange2010_Store_Database.split(",")[0]
        if ($temp_db_name)
        {
            $database_name = $temp_db_name.split(":")[-2]
        }

        if ("" -ne $database_name)
        {
            $database = Get-MailboxDatabase $database_name
            $target_fullpath = GetMailboxDatabaseFullPath $database
            $target_resource = GetMailboxDatabaseResource $database
        }

        if (($target_fullpath -eq $Null) -or ($target_resource -eq $Null))
        {
            $event_detail_msg = "Database " + $database_name + " has been removed.  " `
                              + "Run Discovery_Exchange2007 to update the resource objects."
        }
    }
    elseif ($Exchange2013_Store_Database)
    {
        $database_name = ""

        # if the Exchange 2013 node is part of DAG, then will look similar to the following object.
        # Exchange2010_Store_Database = "BLRDAG01:MBS:Mailbox Database 1604659876:234"
        # if the Exchange 2010 node is a physical node, then will look similar to the following object.
        # Exchange2010_Store_Database = "Exchange2013:BLRDVAM5188:MBS:BLRDVAM5188:Mailbox Database 0708137508:589"
        # We are retrieving first database from it.

        $temp_db_name  = $Exchange2013_Store_Database.split(",")[0]
        if ($temp_db_name)
        {
            $database_name = $temp_db_name.split(":")[-2]
        }

        if ("" -ne $database_name)
        {
            $database = Get-MailboxDatabase $database_name
            $target_fullpath = GetMailboxDatabaseFullPath $database
            $target_resource = GetMailboxDatabaseResource $database
        }

        if (($target_fullpath -eq $Null) -or ($target_resource -eq $Null))
        {
            $event_detail_msg = "Database " + $database_name + " has been removed.  " `
                              + "Run Discovery_Exchange2007 to update the resource objects."
        }
    }
	elseif ($Exchange2016_Store_Database)
    {
        $database_name = ""

        # if the Exchange 2016 node is part of DAG, then will look similar to the following object.
        # Exchange2016_Store_Database = "BLRDAG01:MBS:Mailbox Database 1604659876:234"
        # if the Exchange 2016 node is a physical node, then will look similar to the following object.
        # Exchange2016_Store_Database = "Exchange2016:BLRDVAM5188:MBS:BLRDVAM5188:Mailbox Database 0708137508:589"
        # We are retrieving first database from it.

        $temp_db_name  = $Exchange2016_Store_Database.split(",")[0]
        if ($temp_db_name)
        {
            $database_name = $temp_db_name.split(":")[-2]
        }

        if ("" -ne $database_name)
        {
            $database = Get-MailboxDatabase $database_name
            $target_fullpath = GetMailboxDatabaseFullPath $database
            $target_resource = GetMailboxDatabaseResource $database
        }

        if (($target_fullpath -eq $Null) -or ($target_resource -eq $Null))
        {
            $event_detail_msg = "Database " + $database_name + " has been removed.  " `
                              + "Run Discovery_Exchange2007 to update the resource objects."
        }
    }
    elseif ($Exchange2007_Store_PFDatabase)
    {

        $temp_server_name = $Exchange2007_Store_PFDatabase.split(":")
        $server_name = $temp_server_name[1]
        $node_state = NodeVirtualServerStatus $server_name

        $database_names = GetMonitoredPublicFolderDatabaseNames
        $database_name  = %{ if ($database_names -is [System.Array]) { $database_names[0] }
                                                         else { $database_names    } }
        if (-1 -ne $node_state)
        {
            $database = Get-PublicFolderDatabase $database_name
            $target_fullpath = GetPublicFolderDatabaseFullPath $database
            $target_resource = GetPublicFolderDatabaseResource $database
        }
        if (($target_fullpath -eq $Null) -or ($target_resource -eq $Null))
        {
            $event_detail_msg = "Public Folder Database " + $database_name + " has been removed.  "
                              + "Run Discovery_Exchange2007 to update the resource objects."
        }
    }
    elseif ($Exchange2010_Store_PFDatabase)
    {
        $database_name = ""

        $temp_db_name  = $Exchange2010_Store_PFDatabase.split(",")[0]
        if ($temp_db_name)
        {
            $database_name = $temp_db_name.split(":")[-2]
        }
        if ("" -ne $database_name)
        {
            $database = Get-PublicFolderDatabase $database_name
            $target_fullpath = GetPublicFolderDatabaseFullPath $database
            $target_resource = GetPublicFolderDatabaseResource $database
        }
        if (($target_fullpath -eq $Null) -or ($target_resource -eq $Null))
        {
            $event_detail_msg = "Public Folder Database " + $database_name + " has been removed.  " `
                              + "Run Discovery_Exchange2007 to update the resource objects."
        }
    }
    elseif ($Exchange2013_Store_PublicFolder)
    {
        $database_name = ""

        $temp_db_name  = $Exchange2013_Store_PublicFolder.split(",")[0]
        if ($temp_db_name)
        {
            $database_name = $temp_db_name.split(":")[-2]
        }
        if ("" -ne $database_name)
        {
            $pubfoldname = $database_name
            $target_fullpath = GetPublicFolderDatabaseFullPath $pubfoldname
            $target_resource = GetPublicFolderDatabaseResource $pubfoldname
        }
        if (($target_fullpath -eq $Null) -or ($target_resource -eq $Null))
        {
            $event_detail_msg = "Public Folder Database " + $database_name + " has been removed.  " `
                              + "Run Discovery_Exchange2007 to update the resource objects."
        }
    }
	elseif ($Exchange2016_Store_PublicFolder)
    {
        $database_name = ""

        $temp_db_name  = $Exchange2016_Store_PublicFolder.split(",")[0]
        if ($temp_db_name)
        {
            $database_name = $temp_db_name.split(":")[-2]
        }
        if ("" -ne $database_name)
        {
            $pubfoldname = $database_name
            $target_fullpath = GetPublicFolderDatabaseFullPath $pubfoldname
            $target_resource = GetPublicFolderDatabaseResource $pubfoldname
        }
        if (($target_fullpath -eq $Null) -or ($target_resource -eq $Null))
        {
            $event_detail_msg = "Public Folder Database " + $database_name + " has been removed.  " `
                              + "Run Discovery_Exchange2007 to update the resource objects."
        }
    }
    elseif ($global:exchange_queue)
    {

        $temp_server_name = $global:exchange_queue.split(":")
        $server_name = $temp_server_name[1]
        $node_state = NodeVirtualServerStatus $server_name

        $queue_names = GetMonitoredQueueNames
        $queue_name  = %{ if ($queue_names -is [System.Array]) { $queue_names[0] }
                                                   else { $queue_names    } }

        if (-1 -ne $node_state)
        {
            $queue = Get-Queue $queue_name
            $target_fullpath = GetTransportQueueFullPath $queue
            $target_resource = GetTransportQueueResource $queue
        }
    }
    elseif ($global:exchange_services)
    {
        $target_fullpath = $global:exchange_services
        $target_resource = "$global:services_resource = $global:exchange_services"
    }
    elseif ($global:exchange_service)
    {
        $service_names = GetMonitoredServiceNames
        $service_name  = %{ if ($service_names -is [System.Array]) { $service_names[0] }
                                                       else { $service_names    } }

        $target_fullpath = GetServiceFullPath $service_name
        $target_resource = GetServiceResource $service_name
    }
    elseif ($NT_MachineFolder)
    {
        Trace "Debug" "GetDefaultResourceAndFullPath: NT_MachineFolder exists and is set to '$NT_MachineFolder'"
        $target_fullpath = $NT_MachineFolder
        $target_resource = "NT_MachineFolder = $NT_MachineFolder"
    }
    elseif ($NT_VIR_MachineFolder)
    {
        Trace "Debug" "GetDefaultResourceAndFullPath: $NT_VIR_MachineFolder exists and is set to '$NT_VIR_MachineFolder'"
        $target_fullpath = $NT_VIR_MachineFolder
        $target_resource = "NT_VIR_MachineFolder = $NT_VIR_MachineFolder"
    }


    if (-not $target_resource -or -not $target_fullpath)
    {
        if (-1 -ne $node_state)
        {
            $severity   = 5
            $resource   = "NT_MachineFolder = UNKNOWN"
            $event_msg  = "Internal error: No applicable resource object for datastreams/events"
            $detail_msg = "The GetDefaultResourceAndFullPath function failed to find any applicable " `
                        + "resource object for this Knowledge Script.`n`n" `
                        + $event_detail_msg

            CreateEvent $severity $event_msg $detail_msg $resource
        }
    }
    else
    {
        Trace "Debug" "GetDefaultResourceAndFullPath: target_resource => $target_resource"
        Trace "Debug" "GetDefaultResourceAndFullPath: target_fullpath => $target_fullpath"
    }

    Trace "Debug" "GetDefaultResourceAndFullPath: Exit"
    return @($target_resource, $target_fullpath)
}


#
# Get an array containing the names of all monitored storage groups.
#
function GetMonitoredStorageGroupNames
{
    $monitored_storage_group_names = $null

    if ($Exchange2007_Store_Group)
    {
        $monitored_storage_group_names = $Exchange2007_Store_Group.Split(',')
        $monitored_storage_group_names = $monitored_storage_group_names | ForEach-Object { $_.Split(':')[-2] }
    }

    return $monitored_storage_group_names
}


#
# Get an array containing the names of all monitored mailbox databases.
#
function GetMonitoredMailboxDatabaseNames
{
    $monitored_mailbox_database_names = $null
    $active_database_names            = @()
    $monitored_dag_database_names     = @()

    if ($global:exchange_store_database)
    {
        $monitored_mailbox_database_names = $global:exchange_store_database.Split(',')

        if ($global:b_is_exch2010 -eq $true -or $global:b_is_exch2013 -eq $true -or $global:b_is_exch2016 -eq $true)
        {
            # Retrieving active databases on the local host for Exchange 2010/2013/2016 only
            $active_database_names = GetLocalNodeActiveDatabases
        }
        for ($i = 0; $i -lt $monitored_mailbox_database_names.Length; $i += 1)
        {
            if ($global:b_is_exch2010 -eq $true -or $global:b_is_exch2013 -eq $true -or $global:b_is_exch2016 -eq $true)
            {
                $mailbox_database_name = $monitored_mailbox_database_names[$i].Split(':')[-2]

                # If the database in $mailbox_database_name is active, adding into the array.
                if ($active_database_names -contains $mailbox_database_name)
                {
                    $monitored_dag_database_names += "$mailbox_database_name"
                }
            }
            else
            {
                $storage_group_name, $mailbox_database_name = $monitored_mailbox_database_names[$i].Split(':')[-3..-2]
                $monitored_mailbox_database_names[$i] = "$storage_group_name\$mailbox_database_name"
            }
        }
        if ($global:b_is_exch2010 -eq $true -or $global:b_is_exch2013 -eq $true -or $global:b_is_exch2016 -eq $true)
        {
            if ($monitored_dag_database_names.length -gt 0)
            {
                $monitored_mailbox_database_names = $monitored_dag_database_names
            }
            else
            {
                $monitored_mailbox_database_names = $null
            }
        }
    }

    return $monitored_mailbox_database_names
}


#
# Get an array containing the names of all monitored public folder databases.
#
function GetMonitoredPublicFolderDatabaseNames
{
    $monitored_pf_database_names      = $null
    $monitored_2010_pf_database_names = @()

    if ($global:exchange_store_pfdatabase)
    {
        $monitored_pf_database_names = $global:exchange_store_pfdatabase.Split(',')

        for ($i = 0; $i -lt $monitored_pf_database_names.Length; $i += 1)
        {
            if ($global:b_is_exch2010 -eq $true -or $global:b_is_exch2013 -eq $true -or $global:b_is_exch2016 -eq $true)
            {
                $pf_database_name = $monitored_pf_database_names[$i].Split(':')[-2]
                $monitored_2010_pf_database_names += "$pf_database_name"
            }
            else
            {
                $storage_group_name, $pf_database_name = $monitored_pf_database_names[$i].Split(':')[-3..-2]
                $monitored_pf_database_names[$i] = "$storage_group_name\$pf_database_name"
            }
        }
        if ($global:b_is_exch2010 -eq $true -or $global:b_is_exch2013 -eq $true -or $global:b_is_exch2016 -eq $true)
        {
            if ($monitored_2010_pf_database_names.length -gt 0)
            {
                $monitored_pf_database_names = $monitored_2010_pf_database_names
            }
            else
            {
                $monitored_pf_database_names = $null
            }
        }
    }

    return $monitored_pf_database_names
}

function GetMonitoredPublicFolderMailboxNames
{
    $monitored_pf_mailbox_names      = $null
    $monitored_2013_pf_mailbox_names = @()

    if ($global:exchange_store_pfdatabase)
    {
        $monitored_pf_mailbox_names = $global:exchange_store_pfdatabase.Split(',')

                foreach($monitored_pf_mailbox in $monitored_pf_mailbox_names)
                {
                        $pf_mailbox_name = $monitored_pf_mailbox.Split(':')[-2]
                        $monitored_2013_pf_mailbox_names += "$pf_mailbox_name"
                }

                $monitored_pf_mailbox_names = $monitored_2013_pf_mailbox_names
    }

    return $monitored_pf_mailbox_names
}

#
# Get an array containing the names of all monitored queues.
#
function GetMonitoredQueueNames
{
    $monitored_queue_names = $null

    if ($global:exchange_queue)
    {
        $monitored_queue_names = $global:exchange_queue.Split(',')
        $monitored_queue_names = $monitored_queue_names | ForEach-Object { $_.Split(':')[-2] }
    }

    return $monitored_queue_names
}


#
# Get an array containing the names of all monitored services.
#
function GetMonitoredServiceNames
{
    $monitored_service_names = $null

    if ($global:exchange_service)
    {
        $monitored_service_names = $global:exchange_service.Split(',')
        $monitored_service_names = $monitored_service_names | ForEach-Object { $_.Split(':')[-2] }
    }

    return $monitored_service_names
}


#
# Get the full path of the TreeView MBS mailbox database resource for the given mailbox database.
# If the mailbox database is not selected for monitoring this function returns $null.
# The string returned by this function contains only the full path of the resource;
# it does not contain the "resource_type=" prefix.
#
function GetMailboxDatabaseFullPath
{
    param($mailbox_database)

    $mailbox_database_fullpath = $null

    if ($Exchange2007_Store_Database)
    {
        $monitored_mailbox_databases = $Exchange2007_Store_Database.Split(',')

        foreach ($monitored_mailbox_database in $monitored_mailbox_databases)
        {
            $storage_group_name, $mailbox_database_name = $monitored_mailbox_database.Split(':')[-3..-2]

            if ($mailbox_database.StorageGroup.Name -eq $storage_group_name -and
                $mailbox_database.Name              -eq $mailbox_database_name)
            {
                $mailbox_database_fullpath = $monitored_mailbox_database
                break
            }
        }
    }
    elseif ($Exchange2010_Store_Database)
    {
        $monitored_mailbox_databases = $Exchange2010_Store_Database.Split(',')

        foreach ($monitored_mailbox_database in $monitored_mailbox_databases)
        {
            $mailbox_database_name = $monitored_mailbox_database.Split(':')[-2]

            if ($mailbox_database.Name -eq $mailbox_database_name)
            {
                $mailbox_database_fullpath = $monitored_mailbox_database
                break
            }
        }
    }
    elseif ($Exchange2013_Store_Database)
    {
        $monitored_mailbox_databases = $Exchange2013_Store_Database.Split(',')

        foreach ($monitored_mailbox_database in $monitored_mailbox_databases)
        {
            $mailbox_database_name = $monitored_mailbox_database.Split(':')[-2]

            if ($mailbox_database.Name -eq $mailbox_database_name)
            {
                $mailbox_database_fullpath = $monitored_mailbox_database
                break
            }
        }
    }
	elseif ($Exchange2016_Store_Database)
    {
        $monitored_mailbox_databases = $Exchange2016_Store_Database.Split(',')

        foreach ($monitored_mailbox_database in $monitored_mailbox_databases)
        {
            $mailbox_database_name = $monitored_mailbox_database.Split(':')[-2]

            if ($mailbox_database.Name -eq $mailbox_database_name)
            {
                $mailbox_database_fullpath = $monitored_mailbox_database
                break
            }
        }
    }


    return $mailbox_database_fullpath
}


#
# Get the name of the TreeView MBS mailbox database resource for the given mailbox database.
# If the mailbox database is not selected for monitoring this function returns $null.
# The string returned by this function is formatted for use in CreateData and CreateEvent calls.
#
function GetMailboxDatabaseResource
{
    param($mailbox_database)

    if ($script:mailbox_database_resources -eq $null)
    {
        $script:mailbox_database_resources = @{}
    }

    if ($mailbox_database)
    {
        $mailbox_database_resource = $script:mailbox_database_resources[$mailbox_database]

        if (-not $mailbox_database_resource)
        {
            $mailbox_database_fullpath = GetMailboxDatabaseFullPath $mailbox_database

            if ($mailbox_database_fullpath)
            {
                $mailbox_database_resource = ConvertResourceObjectPath $mailbox_database_fullpath
                $mailbox_database_resource = "$global:store_database_resource = $mailbox_database_resource"
                $script:mailbox_database_resources[$mailbox_database] = $mailbox_database_resource
            }
        }
    }
    return $mailbox_database_resource
}


#
# Get the full path of the TreeView MBS public folder database resource for the given public folder database.
# If the public folder database is not selected for monitoring this function returns $null.
# The string returned by this function contains only the full path of the resource;
# it does not contain the "resource_type=" prefix.
#
function GetPublicFolderDatabaseFullPath
{
    param($pf_database)

    $pf_database_fullpath = $null

    if ($Exchange2007_Store_PFDatabase)
    {
        $monitored_pf_databases = $Exchange2007_Store_PFDatabase.Split(',')

        foreach ($monitored_pf_database in $monitored_pf_databases)
        {
            $storage_group_name, $pf_database_name = $monitored_pf_database.Split(':')[-3..-2]

            if ($pf_database.StorageGroup.Name -eq $storage_group_name -and
                $pf_database.Name              -eq $pf_database_name)
            {
                $pf_database_fullpath = $monitored_pf_database
                break
            }
        }
    }
    elseif ($Exchange2010_Store_PFDatabase)
    {
        $monitored_pf_databases = $Exchange2010_Store_PFDatabase.Split(',')

        foreach ($monitored_pf_database in $monitored_pf_databases)
        {

            $pf_database_name = $monitored_pf_database.Split(':')[-2]

            if ($pf_database.Name -eq $pf_database_name)
            {
                $pf_database_fullpath = $monitored_pf_database
                break
            }
        }
    }
    elseif ($Exchange2013_Store_PublicFolder)
    {
        $monitored_pf_mailboxes = $Exchange2013_Store_PublicFolder.Split(',')
        foreach ($monitored_pf_mailbox in $monitored_pf_mailboxes)
        {
            $pf_mailboxes_name = $monitored_pf_mailbox.Split(':')[-2]
            if ($pf_database -eq $pf_mailboxes_name)
            {
                $pf_database_fullpath = $monitored_pf_mailbox
                break
            }
        }
    }
	elseif ($Exchange2016_Store_PublicFolder)
    {
        $monitored_pf_mailboxes = $Exchange2016_Store_PublicFolder.Split(',')
        foreach ($monitored_pf_mailbox in $monitored_pf_mailboxes)
        {
            $pf_mailboxes_name = $monitored_pf_mailbox.Split(':')[-2]
            if ($pf_database -eq $pf_mailboxes_name)
            {
                $pf_database_fullpath = $monitored_pf_mailbox
                break
            }
        }
    }

    return $pf_database_fullpath
}


#
# Get the name of the TreeView MBS public folder database resource for the given public folder database.
# If the public folder database is not selected for monitoring this function returns $null.
# The string returned by this function is formatted for use in CreateData and CreateEvent calls.
#
function GetPublicFolderDatabaseResource
{
    param($pf_database)

    if ($script:pf_database_resources -eq $null)
    {
        $script:pf_database_resources = @{}
    }

    $pf_database_resource = $script:pf_database_resources[$pf_database]

    if (-not $pf_database_resource)
    {
        $pf_database_fullpath = GetPublicFolderDatabaseFullPath $pf_database

        if ($pf_database_fullpath)
        {
            $pf_database_resource = ConvertResourceObjectPath $pf_database_fullpath
            $pf_database_resource = "$global:store_pfdatabase_resource = $pf_database_resource"
            $script:pf_database_resources[$pf_database] = $pf_database_resource
        }
    }

    return $pf_database_resource
}

#
# GetMatchingMountPointDrive
#
# Uses mountvol.exe utility to accept a string path and finds the closest matching
# volume disk on the host, returning it to the caller
#
function GetMatchingMountPointDrive
{
    param([System.String] $file_path)

    # Trim whitespace from input path
    $file_path = $file_path.Trim()
    Trace "Debug" "GetMatchingMountPointDrive: Enter with file_path => $file_path"

    # Return value
    $matching_mountpoint_drive = $null
    $matching_mountpoint_volume = $null

    # Handle errors occurring while executing mountvol.exe
    trap
    {
        Trace "Error" "GetMatchingMountPointDrive: Exception thrown while executing mountvol.exe; message: $_"
        continue
    }

    # Execute mountvol.exe
    $error.Clear()
    Trace "Debug" "GetMatchingMountPointDrive: Executing mountvol.exe to get drives accessible to this host"
    $mountvol_results = mountvol.exe /L

    # Log any errors that occurred when executing mountvol.exe
    if ($error.Count -gt 0)
    {
        for ($i = $error.Count - 1; $i -ge 0; $i -= 1)
        {
            Trace "Warn" "GetMatchingMountPointDrive: Error occurred while executing mountvol.exe => `"$($error[$i])`" at index $i"
        }
    }

    # Iterate through mountvol.exe output and save drive paths for volumes found
    $bReadingVolume = $false
    $drives_found = @{}
    $num_drives_found = 0
    $current_volume_ID = ""

    Trace "Debug" "GetMatchingMountPointDrive: Looking at mountvol.exe output"
    foreach ($mountvol_line in $mountvol_results)
    {
        $mountvol_line = $mountvol_line.Trim()

        if ($bReadingVolume -eq $true)
        {
            if ($mountvol_line -eq "")
            {
                $bReadingVolume = $false
            }
            else
            {
                if ($mountvol_line -match "\*\*\*")
                {
                    Trace "Debug" "GetMatchingMountPointDrive: Skipping disk volume that has no drive letters associated with it"
                }
                else
                {
                    # This is the drive info for the volume just read
                    Trace "Debug" "GetMatchingMountPointDrive: Adding drive path `"$mountvol_line`" to hash with volume ID `"$current_volume_ID`""
                    $drives_found.Add($mountvol_line, $current_volume_ID)
                    $num_drives_found++
                }
            }
        }
        else
        {
            # Looking for line with a disk volume in the output
            if ($mountvol_line -match "\\\?\\")
            {
                $bReadingVolume = $true
                $current_volume_ID = $mountvol_line
            }
        }
    }

    # Find closest path match to input path ($file_path)
    if ($drives_found.Count -gt 0)
    {
        $longest_match = 0

        foreach ($drive_path in $drives_found.Keys)
        {
            Trace "Debug" ("GetMatchingMountPointDrive: Seeking closest drive path to input path => comparing `"" + $file_path.ToLower() + "`" to `"" + $drive_path.ToLower() + "`"")
            if ($file_path.ToLower().StartsWith($drive_path.ToLower()))
            {
                if ($drive_path.Length -gt $longest_match)
                {
                    $longest_match = $drive_path.Length
                    $matching_mountpoint_drive = $drive_path
                    $matching_mountpoint_volume = $drives_found.Get_Item($drive_path)
                    Trace "Debug" "GetMatchingMountPointDrive: ** Matched mount point path: $matching_mountpoint_drive and volume ID $matching_mountpoint_volume **"
                }
            }
        }

        if ($longest_match -eq 0)
        {
            Trace "Warn" "GetMatchingMountPointDrive: No mount points matched the input path of $file_path"
        }
    }
    else
    {
        Trace "Info" "GetMatchingMountPointDrive: No drives found in output from mountvol.exe"
    }

    # Array holds any matching paths with same volume label (eg. matching path is mount point with logical drive)
    $matching_volumeIDs = @()

    if ($matching_mountpoint_drive -ne $null)
    {
        # Now using DriveInfo .NET class, ensure mount point path found is a logical drive connected to the host, so
        # we can ensure we return the actual physical disk to the caller

        # 1) First get the drive letters/paths with identical volume IDs
        Trace "Debug" "GetMatchingMountPointDrive: Collecting all disk drives that match volume ID: $matching_mountpoint_volume"
        foreach ($drive_path in $drives_found.Keys)
        {
            $current_volID = $drives_found.Get_Item($drive_path)
            Trace "Debug" "GetMatchingMountPointDrive: Finding matching volume IDs => comparing volume ID $current_volID to one sought => $matching_mountpoint_volume"
            if ($current_volID -eq $matching_mountpoint_volume)
            {
                # Drive matches volume ID of longest matching mount point/drive for input pathname
                Trace "Debug" "GetMatchingMountPointDrive: Drive $drive_path matches volume ID sought, so adding to list"
                $matching_volumeIDs += $drive_path
            }
        }

        # 2) Now find logical drive matching volume ID sought (given paths that match in (1) above) - this allows us to ensure
        # we are getting free space for actual logical drive where files reside, not a mount point
        if ($matching_volumeIDs.Length -gt 0)
        {
            Trace "Debug" "GetMatchingMountPointDrive: Fetching logical drives from IO.DriveInfo class"
            $DriveInfo_Drives = [System.IO.DriveInfo]::GetDrives()
            for ($j = 0; $j -le $matching_volumeIDs.Length - 1; $j++)
            {
                $current_drive = ($matching_volumeIDs[$j]).ToLower()
                foreach ($io_drive in $DriveInfo_Drives)
                {
                    $root_dir = $io_drive.RootDirectory
                    $root_dir = ($root_dir.FullName).ToLower()
                    Trace "Debug" ("GetMatchingMountPointDrive: Looking for logical drive match between $current_drive and `"" + $root_dir + "`"")
                    if ($current_drive -eq $root_dir)
                    {
                        Trace "Debug" "GetMatchingMountPointDrive: ----- $root_dir is a match ----- "
                        $matching_mountpoint_drive = $root_dir
                    }
                }
            } # end for each matching drive path found
        }
        else
        {
            Trace "Warn" "GetMatchingMountPointDrive: Matching volume ID not found even though we had set earlier - should not reach this point."
        }
    }
    else
    {
        Trace "Info" "GetMatchingMountPointDrive: No paths returned by mountvol.exe matched the input path"
    }

    if ($matching_mountpoint_drive -eq $null)
    {
        Trace "Debug" "GetMatchingMountPointDrive: Exit and returning null matching drive string"
    }
    else
    {
        Trace "Debug" "GetMatchingMountPointDrive: Exit and returning matching drive string => $matching_mountpoint_drive"
    }

    return $matching_mountpoint_drive
}



#
# Get the full path of the TreeView MBS storage group resource for the given storage group.
# If the storage group is not selected for monitoring this function returns $null.
# The string returned by this function contains only the full path of the resource;
# it does not contain the "resource_type=" prefix.
#
function GetStorageGroupFullPath
{
    param($storage_group)

    $storage_group_fullpath = $null

    if ($Exchange2007_Store_Group)
    {
        $monitored_storage_groups = $Exchange2007_Store_Group.Split(',')

        foreach ($monitored_storage_group in $monitored_storage_groups)
        {
            $storage_group_name = $monitored_storage_group.Split(':')[-2]

            if ($storage_group.Name -eq $storage_group_name)
            {
                $storage_group_fullpath = $monitored_storage_group
                break
            }
        }
    }

    return $storage_group_fullpath
}


#
# Get the name of the TreeView MBS storage group resource for the given storage group.
# If the storage group is not selected for monitoring this function returns $null.
# The string returned by this function is formatted for use in CreateData and CreateEvent calls.
#
function GetStorageGroupResource
{
    param($storage_group)

    if ($script:storage_group_resources -eq $null)
    {
        $script:storage_group_resources = @{}
    }

    $storage_group_resource = $script:storage_group_resources[$storage_group]

    if (-not $storage_group_resource)
    {
        $storage_group_fullpath = GetStorageGroupFullPath $storage_group

        if ($storage_group_fullpath)
        {
            $storage_group_resource = ConvertResourceObjectPath $storage_group_fullpath
            $storage_group_resource = "Exchange2007_Store_Group = $storage_group_resource"
            $script:storage_group_resources[$storage_group] = $storage_group_resource
        }
    }

    return $storage_group_resource
}


#
# Get the full path of the TreeView HTS or ETS queue resource for the given queue.
# If the queue is not selected for monitoring this function returns $null.
# The string returned by this function contains only the full path of the resource;
# it does not contain the "resource_type=" prefix.
#
function GetTransportQueueFullPath
{
    param($queue)

    $queue_fullpath = $null

    if ($global:exchange_queue)
    {
        $monitored_queues = $global:exchange_queue.Split(',')

        if ($queue)
        {
            foreach ($monitored_queue in $monitored_queues)
            {
                $queue_name = $monitored_queue.Split(':')[-2]

                if ($queue.Identity.ToString() -eq $queue_name)
                {
                    $queue_fullpath = $monitored_queue
                    break
                }
            }
        }
        else
        {
            $monitored_queue = $monitored_queues[0]
            $queue_fullpath  = $monitored_queue
        }
    }

    return $queue_fullpath
}


#
# Get the name of the TreeView HTS or ETS queue resource for the given queue.
# If the queue is not selected for monitoring this function returns $null.
# The string returned by this function is formatted for use in CreateData and CreateEvent calls.
#
function GetTransportQueueResource
{
    param($queue)

    if ($script:queue_resources -eq $null)
    {
        $script:queue_resources = @{}
    }

    $queue_resource = $script:queue_resources[$queue]

    if (-not $queue_resource)
    {
        $queue_fullpath = GetTransportQueueFullPath $queue

        if ($queue_fullpath)
        {
            $queue_resource = ConvertResourceObjectPath $queue_fullpath
            $queue_resource = "$global:queue_resource = $queue_resource"
            $script:queue_resources[$queue] = $queue_resource
        }
    }

    return $queue_resource
}


#
# Get Mailbox quota Fullpath name for monitored exchange online domain.
#
function GetMailboxQuotaFullPath
{
    param($domain_name)

    $mailbox_quota_fullpath = $null

    if ($ExchangeOnline_MailBox)
    {
        $monitored_mailbox_quotas = $ExchangeOnline_MailBox.Split(',')

        foreach ($monitored_mailbox_quota in $monitored_mailbox_quotas)
        {
            $mailbox_database_name = $monitored_mailbox_quota.Split(':')[-3]

            if ($domain_name              -eq $mailbox_database_name)
            {
                $mailbox_quota_fullpath = $monitored_mailbox_quota
                break
            }
        }
    }
	 return $mailbox_quota_fullpath
}

#
# Get ServiceHealth full path for monitored exchange online domain.
#
function GetServiceHealthFullPath
{
    param($domain_name)

    $service_health_fullpath = $null

    if ($ExchangeOnline_Service)
    {
        $monitored_service_health_objects = $ExchangeOnline_Service.Split(',')

        foreach ($service_health_object in $monitored_service_health_objects)
        {
            $service_health_domain_name = $service_health_object.Split(':')[-3]

            if ($domain_name -eq $service_health_domain_name)
            {
                $service_health_fullpath = $service_health_object
                break
            }
        }
    }
	 return $service_health_fullpath
}

#
# Get Mailbox quota resource name for monitored exchange online domain.
#
function GetMailboxQuotaResource
{
    param($domain_name)

    if ($script:mailbox_quota_resources -eq $null)
    {
        $script:mailbox_quota_resources = @{}
    }

    if ($domain_name)
    {
        $mailbox_quota_resource = $script:mailbox_quota_resources[$domain_name]

        if (-not $mailbox_quota_resource)
        {
            $mailbox_quota_fullpath = GetMailboxQuotaFullPath $domain_name

            if ($mailbox_quota_fullpath)
            {
                $mailbox_quota_resource = ConvertResourceObjectPath $mailbox_quota_fullpath
                $mailbox_quota_resource = "$global:exchangeonline_mailboxquota_resource = $mailbox_quota_resource"
                $script:mailbox_quota_resources[$domain_name] = $mailbox_quota_resource
            }
        }
    }
    return $mailbox_quota_resource
}

#
# Get service health resource name for monitored exchange online domain.
#
function GetServiceHealthResource
{
    param($domain_name)

    if ($script:service_health_resources -eq $null)
    {
        $script:service_health_resources = @{}
    }

    if ($domain_name)
    {
        $service_health_resource = $script:service_health_resources[$domain_name]

        if (-not $service_health_resource)
        {
            $service_health_fullpath = GetServiceHealthFullPath $domain_name

            if ($service_health_fullpath)
            {
                $service_health_resource = ConvertResourceObjectPath $service_health_fullpath
                $service_health_resource = "$global:ExchangeOnline_ServiceHealth_resource = $service_health_resource"
                $script:service_health_resources[$domain_name] = $service_health_resource
            }
        }
    }
    return $service_health_resource
}

#
# Get an array containing the names of all monitored exchange online domain.
#
function GetMonitoredAzureADDomainNames
{
    $monitored_azuread_domainnames = $null

    if ($global:exchangeonline_mailboxquota)
    {
        $monitored_exchangeOnline_domainnames = $global:exchangeonline_mailboxquota.Split(',')
        $monitored_exchangeOnline_domainnames = $monitored_exchangeOnline_domainnames | ForEach-Object { $_.Split(':')[-3] }
    }	
	if ($global:exchangeonline_servicehealth)
    {
        $monitored_exchangeOnline_domainnames = $global:exchangeonline_servicehealth.Split(',')
        $monitored_exchangeOnline_domainnames = $monitored_exchangeOnline_domainnames | ForEach-Object { $_.Split(':')[-3] }
    }
	if ($global:exchangeonline_servicehealth)
    {
        $monitored_exchangeOnline_domainnames = $global:exchangeonline_servicehealth.Split(',')
        $monitored_exchangeOnline_domainnames = $monitored_exchangeOnline_domainnames | ForEach-Object { $_.Split(':')[-3] }
    }
	
	if ($global:azuread_usersinfo)
    {
        $monitored_azuread_domainnames = $global:azuread_usersinfo.Split(',')
        $monitored_azuread_domainnames = $monitored_azuread_domainnames | ForEach-Object { $_.Split(':')[-3] }
		
    }

    return $monitored_azuread_domainnames
}


#
# Get the full path of the TreeView service resource for the given service.
# If the service is not selected for monitoring this function returns $null.
# The string returned by this function contains only the full path of the resource;
# it does not contain the "resource_type=" prefix.
#
# NOTE: The $service_name parameter is a string containing the display name
#       of the service; it must NOT be the short service name, or an instance
#       of a ServiceController object, or anything else.
#
function GetServiceFullPath
{
    param($service_name)

    $service_fullpath = $null

    if ($global:exchange_service)
    {
        $monitored_services = $global:exchange_service.Split(',')

        foreach ($monitored_service in $monitored_services)
        {
            $monitored_service_name = $monitored_service.Split(':')[-2]

            if ($service_name -eq $monitored_service_name)
            {
                $service_fullpath = $monitored_service
                break
            }
        }
    }

    return $service_fullpath
}


#
# Get the name of the TreeView service resource for the given service.
# If the service is not selected for monitoring this function returns $null.
# The string returned by this function is formatted for use in CreateData and CreateEvent calls.
#
# NOTE: The $service_name parameter is a string containing the display name
#       of the service; it must NOT be the short service name, or an instance
#       of a ServiceController object, or anything else.
#
function GetServiceResource
{
    param($service_name)

    if ($script:service_resources -eq $null)
    {
        $script:service_resources = @{}
    }

    $service_resource = $script:service_resources[$service_name]

    if (-not $service_resource)
    {
        $service_fullpath = GetServiceFullPath $service_name

        if ($service_fullpath)
        {
            $service_resource = ConvertResourceObjectPath $service_fullpath
            $service_resource = "$global:ser_resource = $service_resource"
            $script:service_resources[$service_name] = $service_resource
        }
    }

    return $service_resource
}


#
# Convert a TreeView resource object fullpath to the form required by KS's that specify
# fullpath="1".  The returned object name can be passed to CreateEvent, CreateData, etc.
#
# For example:
#
# Exchange2007_MailboxServer = MBS:RALQEROW06A15:MBS:RALQEROW06A15:First Storage Group:Mailbox Database:1283
#
# will be converted to:
#
# Exchange2007_MailboxServer = #1283:MBS:RALQEROW06A15:MBS:RALQEROW06A15:First Storage Group:Mailbox Database
#
# NOTE: This function properly handles cases where a resource path has already been
#       converted (in which case the original path is returned), and also handles
#       cases where the resource name and '=' sign have already been prepended to
#       the object path.
#
function ConvertResourceObjectPath
{
    param([System.String] $object_path)

    $converted_path = $null

    if ($object_path)
    {
        if ($object_path -like "*=*")
        {
            #
            # The resource name prefix has already been prepended to the path we were given,
            # so remove it before munge the path, and then reattach it before returning.
            #
            $resource_name, $object_path = $object_path.Split('=')
            $resource_name = $resource_name.Trim()
            $object_path = $object_path.Trim()
        }

        if ($object_path -match '^\s*#')
        {
            #
            # It appears that the path has already been put through the conversion process,
            # so we'll just return the original resource object path.
            #
            $converted_path = $object_path
        }
        else
        {
            #
            # Move the ":id" from the end to the beginning, then prefix the result with '#'.
            #
            $name_parts = $object_path.Split(':')
            if ($name_parts -ne $object_path)
            {
                $number_part    = $name_parts[-1]
                $object_part    = [System.String]::Join(':', $name_parts[0 .. ($name_parts.Length-2)])
                $converted_path = "#" + $number_part + ":" + $object_part
            }
            else
            {
                $converted_path = $object_path
            }
        }

        if ($resource_name)
        {
            #
            # Reattach the resource name if we detached it earlier.
            #
            $converted_path = "$resource_name=$converted_path"
        }
    }

    return $converted_path
}


#
# Get the domains in the forest.  The return values is an instance
# of [System.DirectoryServices.ActiveDirectory.DomainCollection].
#
function GetDomains
{
    Trace "Debug" "GetDomains - Enter: Calling `[DirectoryServices.ActiveDirectory.Forest`]`:`:GetCurrentForest`(`)"
    $forest = [DirectoryServices.ActiveDirectory.Forest]::GetCurrentForest()
    $domains = $null

    if ($forest)
    {
        Trace "Debug" ("GetDomains: Returning domains for forest " + $forest.Name)
        $domains = $forest.Domains
    }
    else
    {
        Trace "Debug" "GetDomains: GetCurrentForest returned null"
    }

    Trace "Debug" "GetDomains - Exit"
    $domains
}


#
# Get the domain controllers in the forest, or in the named domain.  Returns
# an array of [System.DirectoryServices.ActiveDirectory.DomainControllers].
#
function GetDomainControllers
{
    param([System.String] $domain_name)

    Trace "Debug" "GetDomainControllers - Enter"

    $domains = GetDomains
    $domain_controllers = @()

    if ($domains)
    {
        foreach ($domain in $domains)
        {
            if ((-not $domain_name) -or ($domain.Name -eq $domain_name))
            {
                if (($domain.Name -ne $null) -and ($domain.DomainControllers -eq $null))
                {

                    $event_sev  = $global:job_failure_severity
                    $event_msg  = "Domain controller for domain " + $domain.Name + " cannot be contacted"
                    $detail_msg = "Domain controller for domain " + $domain.Name + " cannot be contacted.`n"`
                                + "Check whether the domain controller is up and running."
                    CreateEvent $event_sev $event_msg $detail_msg `
                                $global:target_resource $action_to_be_taken

                }
                Trace "Info" ("GetDomainControllers: Getting domain controllers for " + $domain.Name)
                foreach ($domain_controller in $domain.DomainControllers)
                {
                    $domain_controllers += $domain_controller
                }
            }
        }
    }
    else
    {
        Trace "Warn" "GetDomainControllers - No domains found from this host"
    }

    Trace "Warn" "GetDomainControllers - Exit"
    $domain_controllers
}


#
# PruneMailboxServerList - Given a collection of mailbox server objects, return an
# array containing the subset of those objects that are members of the current domain.
#
function PruneMailboxServerList
{
    param([object[]] $mailbox_servers)

    $pruned_servers = @()
    $domain_name = (DomainName)

    foreach ($mailbox_server in $mailbox_servers)
    {
        $server = Get-ExchangeServer $mailbox_server.Name
        if ($server.Domain -eq $domain_name)
        {
            $pruned_servers += $mailbox_server
        }
    }

    $pruned_servers
}


#
# Remove from the $error array all errors whose messages match any of those passed
# in to this function.
#
function RemoveFromErrorArray
{
    param([string[]] $messages)

    $index = 0
    $remove_indexes = @()

    foreach ($single_error in $error)
    {
        if ($messages -contains $single_error.Exception.Message)
        {
            $remove_indexes += $index
        }
        $index++
    }

    [Array]::Reverse($remove_indexes)

    foreach ($index in $remove_indexes)
    {
        $error.RemoveAt($index)
    }
}


#
# CheckForErrors - retrieves error information from $error variable and raises
# the appropriate events - returns $true or $false if $error was set, and then
# clears it to go forward
#
function CheckForErrors
{
    if ($args.Length -eq 1 -and $args[0] -is [System.Management.Automation.ScriptBlock])
    {
        $exception_handler = [System.Management.Automation.ScriptBlock] $args[0]
    }
    elseif ($args.Length -ge 4)
    {
        $target_resource = [System.String] $args[0]
        $event_msg       = [System.String] $args[1]
        $cmd_name        = [System.String] $args[2]
        $functional_area = [System.String] $args[3]
        if ($args.Length -eq 5)
        {
            $alternate_severity = [System.Int32] $args[4]
        }
        else
        {
            $alternate_severity = $null
        }
    }
    else
    {
        Trace "Error" "CheckForErrors: Invalid parameters passed to function."
        return $false
    }


    $local_error = $error.Clone()
    $server = HostName

    # Some error messages occur from powershell itself when certain environment conditions are in
    # place; they are not useful to the user, so we're removing them
    $bogus_error = "WriteObject and WriteError methods cannot be called after the pipeline has been closed"
    if ($local_error.Count -gt 0)
    {
        for ($i = $local_error.Count - 1; $i -ge 0; $i -= 1)
        {
            if ($local_error[$i].ToString() -match $bogus_error)
            {
                Trace "Debug" "CheckForErrors: Removing bogus error `"$local_error[$i]`" at index $i"
                $local_error.RemoveAt($i)
            }
        }
    }

    # Some error messages occur from powershell itself when certain environment conditions are in
    # place; they are duplicated, so we're removing them
    if ($local_error.Count -gt 1)
    {
        $NotCompleted = $true
        [System.Int32] $dCount = 1
        While($NotCompleted)
        {
            [System.Int32] $i = $local_error.Count - $dCount
            for ($j = $i - 1; $j -ge 0; $j -= 1)
            {
                if ($local_error[$i].ToString() -match $local_error[$j].ToString())
                {
                    Trace "Debug" "CheckForErrors: Removing duplicate error `"$local_error[$j]`" at index $j"
                    $local_error.RemoveAt($j)
                }
            }
            if ($i -eq 1)
            {
                $NotCompleted = $false
            }
            $dCount += 1
        }
    }

    $num_of_errors = $local_error.Count
    Trace "Info" "CheckForErrors: There are $num_of_errors error(s) set at this time"
    $no_errors = $num_of_errors -eq 0

    if (-not $no_errors)
    {
        if ($exception_handler)
        {
            #
            # Execute the exception handler specified by the user, and use
            # its return value as the return value of this function.
            #
            $no_errors = &$exception_handler
        }
        else
        {
            # Create an event with the appropriate message and error info
            if (-not $event_msg)
            {
                $event_msg = "An error occurred while monitoring $server"
            }

            # Gather error information for event display
            $error_details = ""
            [System.Int32] $err_num = 0 + 1
            foreach ($single_error in $local_error)
            {
                Trace "Error" "CheckForErrors: $cmd_name produced error: $single_error"
                $error_details += "Error " + $err_num + ": `"" + $single_error.ToString() + "`"`n`n"
                [System.Int32] $err_num += 0 + 1
            }

            # Construct the detailed event message, using the additional error info
            # and possible reasons for failure
            $detail_msg = "An error occurred while monitoring $functional_area on `"$server`".`n`n" `
                        + "While running command $cmd_name, the following errors occurred -`n`n" `
                        + $error_details + "`n`n" `
                        + "These errors can occur for the following reasons:`n" `
                        + "- One or more Exchange services was not running`n" `
                        + "- The Active Directory domain controller was not accessible`n" `
                        + "- The account running the AppManager Management agent did not`n" `
                        + "     have the proper permissions for this command to execute`n" `
                        + "- Failover in progress on the cluster environment`n"

            # Custom error additions
            if ($cmd_name -eq "Get-MessageTrackingLog")
            {
                $detail_msg += "- Message tracking is not enabled on this server`n"
            }

            # Ensure a target resource is specified for proper event display
            if (-not $target_resource)
            {
                $target_resource = $global:target_resource
            }

            # Use alternate severity, if provided
            if ($alternate_severity)
            {
                $event_sev = $alternate_severity
            }
            else
            {
                $event_sev = $job_failure_severity
            }

            CreateEvent $event_sev $event_msg $detail_msg `
                        $target_resource $action_to_be_taken
        }
    }

    $error.Clear()
    $local_error.Clear()
    $no_errors
}


#
# RemoveErrorMessage - remove the error message passed in from $error - this
#     serves the purpose of allowing known messages to be skipped from event
#     creation
#
function RemoveErrorMessage
{
    param([System.String] $message)

    if ($message)
    {
        if ($error.Count -gt 0)
        {
            for ($i = $error.Count - 1; $i -ge 0; $i -= 1)
            {
                if ($error[$i].ToString() -match $message)
                {
                    Trace "Debug" "RemoveErrorMessage: removing known error message `"$error[$i]`" at index $i"
                    $error.RemoveAt($i)
                }
            }
        }

    }
}

Function GetOwnerNode($objCluster,[System.String]$strGroup)
{

  trap
  {
      echo "Error occured in the function GetOwnerNode. Exception details: $_"
      $error.clear()
      continue
  }

  $objGroup = $objCluster.ResourceGroups.Item($strGroup).OwnerNode

  [System.String]$strName  = $objGroup.Name

  return $strName

}

Function GetClusterName()
{

    $error.Clear()
    $cluster_name = ""
    $obj_reg = Get-ItemProperty -path "HKLM:\Cluster"  -ea "silentlycontinue"

    if ($obj_reg)
    {
        $cluster_name = $obj_reg.clustername
    }
    if ($error[0])
    {
        Trace "Info" "Error occurred fetching cluster name from registry - error detail: $error[0]"
        $error.Clear()
    }

    $cluster_name

}

#
# This function will find whether the virtual server $sSvrname is online on the current physical node where the job is running is active
# If it is active this function will return 2. If it is a cluster node and if the virtual server is not running, the function will return
# -1, if it is a standalone server this function will return -2
#
Function NodeVirtualServerStatus($sSvrname)
{
    $iStatus = -2

    trap
    {
        Trace "Warn" "Error occured in the function NodeVirtualServerStatus. Exception details: $_"
        $error.clear()
        continue
    }

    $objCluster = new-object -comobject MSCluster.Cluster -strict
    $objCluster.Open("")

    [System.String]$strMe = [Environment]::MachineName

    $ObjResGrp = $objCluster.ResourceGroups

    For($ix =1;$ix -le $ObjResGrp.count;$ix++)
    {
        $iStatus = -1
        $objGroup = $ObjResGrp.item($ix)
        $strGroup = $objGroup.Name
        [System.String]$strOwner = GetOwnerNode $objCluster $strGroup
        $objResources = $objGroup.Resources
        if (0 -eq (($strOwner.toupper()).compareto($strMe.toupper())))
        {
            For($IndexResources = 1; $IndexResources -le $objResources.Count;$IndexResources++)
            {
                $objResource = $objResources.Item($IndexResources)
                $strResourceTypeName = $objResource.TypeName
                if ((0 -eq ([System.String]$strResourceTypeName.toupper()).compareto("NETWORK NAME")))
                {
                    $strResName = $strGroup
                    $strtmep = $objResource.name
                    if (0 -eq ([System.String]$sSvrname.toupper()).compareto([System.String]$strResName.toupper()))
                    {
                        $iStatus = $objResource.State
                        break
                    }
                }
            }
        }
        if ($iStatus -eq 2)
        {
            break
        }
    }
    return $iStatus
}

#
# Silently exit if this machine is a passive node in a cluster.
# When the job is dropped on a physical node, target_resource will contain information about all the virtual servers. We will find which virtual node is
# currently online on that physical node and replace target_resource and target_fullpath with that resource name.If none of the virtual server is online
# on a physical node the iteration will be skipped.
#
function ExitIfItIsPassiveNode($msgString)
{
     $bExit = $true

    if ($global:b_is_exch2010 -or $global:b_is_exch2013 -or $global:b_is_exch2016)
    {
        if ($global:b_is_exch2010)
        {
            if ( ($Exchange2010_DAG_Databases -ne $null) -and ($Exchange2010_DAG_Databases.length -gt 0) )
            {
                $dag_name  = $Exchange2010_DAG_Databases.split(":")
                $dag_name  = $dag_name[-2]
                $temp_dag_name = @()
                $temp_dag_name = $dag_name.split(".")
                if ($temp_dag_name.count -gt 1)
                {
                    $dag_name = $temp_dag_name[0]
                }
                $global:prefix_server_name = "$dag_name : "
            }
        }
        if ($global:b_is_exch2013)
        {
            if ( ($Exchange2013_DAG_Databases -ne $null) -and ($Exchange2013_DAG_Databases.length -gt 0) )
            {
                $dag_name  = $Exchange2013_DAG_Databases.split(":")
                $dag_name  = $dag_name[-2]
                $temp_dag_name = @()
                $temp_dag_name = $dag_name.split(".")
                if ($temp_dag_name.count -gt 1)
                {
                    $dag_name = $temp_dag_name[0]
                }
                $global:prefix_server_name = "$dag_name : "
            }
        }
		if ($global:b_is_exch2016)
        {
            if ( ($Exchange2016_DAG_Databases -ne $null) -and ($Exchange2016_DAG_Databases.length -gt 0) )
            {
                $dag_name  = $Exchange2016_DAG_Databases.split(":")
                $dag_name  = $dag_name[-2]
                $temp_dag_name = @()
                $temp_dag_name = $dag_name.split(".")
                if ($temp_dag_name.count -gt 1)
                {
                    $dag_name = $temp_dag_name[0]
                }
                $global:prefix_server_name = "$dag_name : "
            }
        }
    }
    elseif (-not ($global:b_is_exch2010 -or $global:b_is_exch2013 -or $global:b_is_exch2016  ))
    {
        # The check for Passive node is done for only Exchange 2007 and there is no concept of active/passive node in Exchange 2010.

        if ($global:target_resource)
        {
            $temp_target_resource = ($global:target_resource).split(",")
            $temp_target_fullpath = ($global:target_fullpath).split(",")
        }
        else
        {
            Trace "Error" "ExitIfItIsPassiveNode global:target_resource is empty"
        }

        for($index=0;$index -lt $temp_target_fullpath.count;$index++)
        {
            $target_fullpath   = $temp_target_fullpath[$index]
            $temp_server_name  = $target_fullpath.split(":")
            $server_name       = $temp_server_name[1]
            $node_state = NodeVirtualServerStatus $server_name

            if ($node_state -eq 2)
            {
                $global:target_resource        = $temp_target_resource[$index]
                $global:target_fullpath        = $temp_target_fullpath[$index]
                $global:prefix_server_name     = "$server_name : "

                $bExit = $false
                if ($PRM_EmitClusterStateEvent)
                {
                    $event_sev = 30
                    $event_msg  = "This is cluster active node"
                    $cdate = date
                    $detail_msg = "The Node (" + ([Environment]::MachineName).ToString() + ") is active.  " `
                                + "Current DateTime: " + $cdate.ToString()
                    CreateEvent $event_sev $event_msg $detail_msg `
                    $global:target_resource $action_to_be_taken
                }
                If ((Get-Service | Where {$_.Name -match "ClusSvc"} | Select Status).Status -eq "Running")
                {
                    If ((Get-Service | Where {$_.Name -match "MSExchangeIS"} | Select Status).Status -ne "Running")
                    {
                        Trace "Info" "ExitIfItIsPassiveNode: MSExchangeIS not running"
                        $bExit = $true
                    }
                }
                break
            }
            elseif ($node_state -eq -2)
            {
                $cluster_name = ""
                $cluster_name = GetClusterName

                if ($cluster_name.length -gt 0)
                {
                    $bExit = $true
                    Trace "Error" "ExitIfItIsPassiveNode: Cluster Service is down"
                }
                else
                {
                    $bExit = $false
                    Trace "Info" "ExitIfItIsPassiveNode: Standalone server"
                }
            }

        }

        if ($bExit)
        {
            if ($PRM_EmitClusterStateEvent)
            {
                $event_sev = 15
                $event_msg  = "This is cluster passive node"
                $detail_msg = $msgString
                CreateEvent $event_sev $event_msg $detail_msg $global:target_resource $action_to_be_taken
            }
            Trace "Info" "ExitIfItIsPassiveNode: Clustered System Passive Node"
            exit 0 # for passive node
        }
    }
}



function validateEmailID($id)
{
     [System.String] $patternStrict = "^(([^<>()[\]\\.,;:\s@\""]+"
     $patternStrict += "(\.[^<>()[\]\\.,;:\s@\""]+)*)|(\"".+\""))@"
     $patternStrict += "((\[[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}"
     $patternStrict += "\.[0-9]{1,3}\])|(([a-zA-Z\-0-9]+\.)+"
     $patternStrict += "[a-zA-Z]{2,}))$";
     $reStrict = new-object System.Text.RegularExpressions.Regex($patternStrict);
     $match = $reStrict.Match($id);
     $match.Success
}


#
# Replace all instances of {XXX} (where XXX is an arbitrary sequence of characters)
# in the $text string with the value associated with the "XXX" key in the given
# hashtable.
#
function PerformSubstitutions
{
    param([System.Collections.Hashtable] $key_vals,
          [System.String]    $text)

    $regex = New-Object Text.RegularExpressions.Regex "{(?<1>[^}]*)}"
    $match = $regex.Match($text)

    while ($match.Success)
    {
        $item = $match.Groups[1].ToString()

        if ($key_vals[$item] -ne $null)
        {
            if ($key_vals[$item] -is [System.String] -and $key_vals[$item] -eq "")
            {
                # This special case behavior is to avoid changing "one {two} three"
                # to "one  three" (note the extra space) rather than "one three".
                $text = $text -replace "\s*{$item}\s*", " "
                $text = $text.Trim()
            }
            else
            {
                $text = $text -replace "{$item}", $key_vals[$item]
            }
        }
        else
        {
            #
            # This is not necessarily an error - it may be intentional that only
            # some placeholders have substitutions performed on them.
            #
            Trace "Debug" ("No entry for $item is present in the hashtable passed " +
                          "to PerformSubstitutions, so {$item} in the cannot be " +
                          "replaced with substitution text.")
        }

        $match = $match.NextMatch()
    }

    $text
}


#
# Write a message to the log file indicating that the job is starting to run.
#
function TraceJobStart
{
    param([System.String] $job_name)

    $script:job_start_time = [DateTime]::Now
    Trace "Info" "Starting $job_name job at $script:job_start_time ..."
}


#
# Write a message to the log file indicating that the job has completed.
#
function TraceJobCompletion
{
    if ($script:job_start_time)
    {
        $job_end_time = [DateTime]::Now
        $job_duration = $job_end_time - $script:job_start_time
        $job_duration = [System.String]::Format("{0:D2}:{1:D2}", $job_duration.Minutes, $job_duration.Seconds)
        Trace "Info" "$job_name job completed at $job_end_time (duration $job_duration)"
    }
    else
    {
        Trace "Error" "TraceJobStart must be called before TraceJobCompletion."
    }
}


#
# Format a number, inserting thousands separators and including the specified
# number of decimal places.  Note that in the case of a number that is not an
# integer, the resulting formatted number will be rounded to produce the most
# accurate result.
#
function FormatNumber
{
    param([System.Double] $number,
          [System.Int32]    $decimal_places = 0)

    #
    # Set the number of decimal places for the formatted number.  Note that
    # we need to make a copy of the CultureInfo to avoid having an exception
    # being thrown when we attempt to set the NumberDecimalDigits property,
    # which under certain (unknown) circumstances is a read-only property.
    #
    $culture_info   = [Threading.Thread]::CurrentThread.CurrentCulture
    $culture_info   = New-Object Globalization.CultureInfo $culture_info.Name
    $number_format  = $culture_info.NumberFormat
    $decimal_digits = $number_format.NumberDecimalDigits
    $number_format.NumberDecimalDigits = $decimal_places

    #
    # Format the number with thousands separators and the requested
    # number of decimal places.
    #
    return [System.String]::Format($culture_info, "{0:n}", $number)
}



#
# This function returns true if it is Exchange 2007
#
function IsExchange2007
{
    $bExch2007 = $false

    trap
    {
        $error.clear()
        continue
    }

    $major_version = GetRegistryString "HKLM:\\SOFTWARE\Microsoft\Exchange\v8.0\Setup\" "MsiProductMajor"

    if ($major_version -eq 8)
    {
       $bExch2007 = $true
    }

    $error.clear()
    
	Trace "Debug" "IsExchange2007: $bExch2007"
    $bExch2007
}


#
# This function returns true if it is Exchange 2010
#
function IsExchange2010
{
    $bExch2010 = $false

    trap
    {
        $error.clear()
        continue
    }

    $major_version = GetRegistryString "HKLM:\\SOFTWARE\Microsoft\ExchangeServer\v14\Setup\" "MsiProductMajor"

    if ($major_version -eq 14)
    {
       $bExch2010 = $true
    }

    $error.clear()

	Trace "Debug" "IsExchange2010: $bExch2010"
    $bExch2010
}

#
# This function returns true if it is Exchange 2013
#
function IsExchange2013
{
    $bExch2013 = $false

    trap
    {
        $error.clear()
        continue
    }

    $major_version = GetRegistryString "HKLM:\\SOFTWARE\Microsoft\ExchangeServer\v15\Setup\" "MsiProductMajor"
	$minor_version = GetRegistryString "HKLM:\\SOFTWARE\Microsoft\ExchangeServer\v15\Setup\" "MsiProductMinor"

    if (($major_version -eq 15 ) -and ($minor_version -eq 0))
    {
       $bExch2013 = $true
    }

    $error.clear()
	
	Trace "Debug" "IsExchange2013: $bExch2013"
    $bExch2013
}

#
# This function returns true if it is Exchange 2016
#
function IsExchange2016
{
    $bExch2016 = $false

    trap
    {
        $error.clear()
        continue
    }

    $major_version = GetRegistryString "HKLM:\\SOFTWARE\Microsoft\ExchangeServer\v15\Setup\" "MsiProductMajor"
    $minor_version = GetRegistryString "HKLM:\\SOFTWARE\Microsoft\ExchangeServer\v15\Setup\" "MsiProductMinor"

    if (($major_version -eq 15 ) -and ($minor_version -eq 1))
    {
       $bExch2016 = $true
    }

    $error.clear()
     
	Trace "Debug" "IsExchange2016: $bExch2016"
    $bExch2016
}

#
# This function returns true if it is Exchange 2010 DAG
#
function IsExchangeDAGNode
{
    $bExchDAG = $false

    #
    # Determine whether the Get-DatabaseAvailabilityGroup cmdlet is present before invoking it.
    # We do this because there are valid cases where it won't be present (e.g., Exchange 2007),
    # and if we simply executed it and trapped the exception that would be thrown we'd write an
    # error to the log file even though it's not really an error.  When diagnosing issues it is
    # helpful to be able to know that errors in the log file represent true unexpected errors.
    #
    Get-Command -Name Get-DatabaseAvailabilityGroup -ErrorAction SilentlyContinue

    if ($?)
    {
        trap
        {
            Trace "Error" "IsExchangeDAGNode: Error throwed: $error"
            $error.clear()
            continue
        }

        $host_server = (HostName)

        $dag_details = @(Get-DatabaseAvailabilityGroup )

        if ($dag_details)
        {
            foreach ($dag_detail in $dag_details)
            {
                $dag_servers = $dag_detail.servers
                foreach ($dag_server in $dag_servers)
                {
                    if ($host_server -eq $dag_server.name)
                    {
                        $bExchDAG = $true
                        break
                    }
                }
            }
        }
    }

    Trace "Debug" "IsExchangeDAGNode: $host_server is part of DAG - $bExchDAG"
    $error.clear()

    $bExchDAG
}

#
# This function returns an array containing databases that are active in the local host.
#
function GetLocalNodeActiveDatabases
{
    $active_databases = @()

    trap
    {
        Trace "Error" "GetLocalNodeActiveDatabases: Error throwed: $error"
        $error.clear()
        continue
    }

    $host_server = (HostName)
    $db_details = Get-MailboxDatabase

    if ($db_details)
    {
        foreach ($db_detail in $db_details)
        {
            if ($host_server -eq $db_detail.Server)
            {
                $active_databases += $db_detail.name
            }
        }
    }

    $error.clear()

    $active_databases
}

#
# This function returns true if the given mail box belongs to any of the active databases in local host.
#
function IsMailboxAvailableInActiveDatabases
{
    param ([System.String] $mailbox_to_be_validated)

    trap
    {
        Trace "Error" "IsMailboxAvailableInActiveDatabases: Error throwed: $error"
        $error.clear()
        continue
    }

    $host_server         = (HostName)
    $bMailbox_exist_here = $false
    if ($mailbox_to_be_validated)
    {
        if ($mailbox_to_be_validated -ne "")
        {
            $active_databases = GetLocalNodeActiveDatabases
            if ($active_databases.Length -gt 0)
            {
                #
                # The Get-MailboxStatistics cmdlet returns various "internal" mailboxes in addition to user mailboxes;
                # the Get-Mailbox cmdlet returns only user mailboxes.  These are the mailboxes we care about, so this
                # code ignores internal (archive, remote archive, arbitration, and health/monitoring) databases.
                #
                $mailbox_guids = @(Get-Mailbox -Server $host_server | %{ $_.ExchangeGuid })
                $mailbox_stats = Get-MailboxStatistics -Server $host_server `
                               | Where-Object { $mailbox_guids -contains $_.MailboxGuid }

                if ($mailbox_stats)
                {
                    if (-not ($mailbox_stats -is [System.Array]))
                    {
                        $mailbox_stats = @($mailbox_stats)
                    }

                    foreach ($mailbox_stat in $mailbox_stats)
                    {
                        $temp = $mailbox_stat.DisplayName
                        if ($temp -eq $mailbox_to_be_validated)
                        {
                            $temp = $mailbox_stat.DatabaseName
                            if ($active_database -contains $temp)
                            {
                                $bMailbox_exist_here = $true
                                break
                            }
                        }
                    }
                }
            }
        }
    }
    $error.clear()

    $bMailbox_exist_here
}


# This function skips the iteration of a job running on a DAG node, if the database availability
# group is removed from the Exchange organization or if a server is removed from the DAG .
function ExitIfDAGRemoved
{

    Trace "Debug" "ExitIfDAGRemoved: Enter"

    if ($global:b_is_exch2010 -or $global:b_is_exch2013 -or $global:b_is_exch2016)
    {

        Trace "Debug" "ExitIfDAGRemoved: Checking for existence of Get-DatabaseAvailabilityGroup cmdlet"
        Get-Command -Name Get-DatabaseAvailabilityGroup -ErrorAction SilentlyContinue
        $bDAGRemoved    = $true
        $bServerRemoved = $true
        $dag_name    = ""
        $host_server = ""
        if ($?)
        {
            Trace "Debug" "ExitIfDAGRemoved: Get-DatabaseAvailabilityGroup cmdlet exists on this host."

            trap
            {
                Trace "Error" "ExitIfDAGRemoved: Error message: $error"
                $error.clear()
                continue
            }

            if ($Exchange2010_DAG_Databases -ne $null) {
                Trace "Debug" "ExitIfDAGRemoved: Exchange2010_DAG_Databases = $Exchange2010_DAG_Databases"
            } else {
                Trace "Debug" "ExitIfDAGRemoved: Exchange2010_DAG_Databases = null"
            }
            if ($Exchange2013_DAG_Databases -ne $null) {
                Trace "Debug" "ExitIfDAGRemoved: Exchange2013_DAG_Databases = $Exchange2013_DAG_Databases"
            } else {
                Trace "Debug" "ExitIfDAGRemoved: Exchange2013_DAG_Databases = null"
            }
			if ($Exchange2016_DAG_Databases -ne $null) {
                Trace "Debug" "ExitIfDAGRemoved: Exchange2016_DAG_Databases = $Exchange2016_DAG_Databases"
            } else {
                Trace "Debug" "ExitIfDAGRemoved: Exchange2016_DAG_Databases = null"
            }

            $host_server = (HostName)
            $mailbox_databases = $global:exchange_store_database.Split(',')
            foreach ($mailbox_database in $mailbox_databases)
            {
                Trace "Debug" "ExitIfDAGRemoved: Mailbox database object string for use of finding DAG name = $mailbox_database"

                if ( ($Exchange2010_DAG_Databases -ne $null) -and ($Exchange2010_DAG_Databases -ne "") )
                {
                    Trace "Debug" "ExitIfDAGRemoved: (2010) - Getting DAG name from mailbox $mailbox_database"
                    $dag_name = $mailbox_database.split(":")[-3] #Getting the DAG name
                    $DAG_FQDN = @()
                    $DAG_FQDN = $dag_name.split(".")
                    if ($DAG_FQDN.count -gt 1)
                    {
                        $dag_name = $DAG_FQDN[0]
                    }

                    Trace "Debug" "ExitIfDAGRemoved: (2010) - DAG name = $dag_name"

                    $dag_details = @(Get-DatabaseAvailabilityGroup)

                    if ($dag_details)
                    {
                        foreach ($dag_detail in $dag_details)
                        {
                            if ($dag_detail.name -eq $dag_name)
                            {
                                $dag_servers = $dag_detail.servers
                                $bDAGRemoved = $false
                                foreach ($dag_server in $dag_servers)
                                {
                                    if ($host_server -eq $dag_server.name)
                                    {
                                        $bServerRemoved = $false  #DAG present in the organization, no need to proceed check other items
                                        break
                                    }
                                }
                            }
                        }
                    }
                }
                elseif ( ($Exchange2013_DAG_Databases -ne $null) -and ($Exchange2013_DAG_Databases -ne "") )
                {
                    Trace "Debug" "ExitIfDAGRemoved: (2013) - Getting DAG name from mailbox $mailbox_database"
                    $dag_name = $mailbox_database.split(":")[-3] #Getting the DAG name
                    $DAG_FQDN = @()
                    $DAG_FQDN = $dag_name.split(".")
                    if ($DAG_FQDN.count -gt 1)
                    {
                        $dag_name = $DAG_FQDN[0]
                    }

                    Trace "Debug" "ExitIfDAGRemoved: (2013) - DAG name = $dag_name"

                    $dag_details = @(Get-DatabaseAvailabilityGroup)

                    if ($dag_details)
                    {
                        foreach ($dag_detail in $dag_details)
                        {
                            if ($dag_detail.name -eq $dag_name)
                            {
                                $dag_servers = $dag_detail.servers
                                $bDAGRemoved = $false
                                foreach ($dag_server in $dag_servers)
                                {
                                    if ($host_server -eq $dag_server.name)
                                    {
                                        $bServerRemoved = $false  #DAG present in the organization, no need to proceed check other items
                                        break
                                    }
                                }
                            }
                        }
                    }
                }
				elseif ( ($Exchange2016_DAG_Databases -ne $null) -and ($Exchange2016_DAG_Databases -ne "") )
                {
                    Trace "Debug" "ExitIfDAGRemoved: (2016) - Getting DAG name from mailbox $mailbox_database"
                    $dag_name = $mailbox_database.split(":")[-3] #Getting the DAG name
                    $DAG_FQDN = @()
                    $DAG_FQDN = $dag_name.split(".")
                    if ($DAG_FQDN.count -gt 1)
                    {
                        $dag_name = $DAG_FQDN[0]
                    }

                    Trace "Debug" "ExitIfDAGRemoved: (2016) - DAG name = $dag_name"

                    $dag_details = @(Get-DatabaseAvailabilityGroup)

                    if ($dag_details)
                    {
                        foreach ($dag_detail in $dag_details)
                        {
                            if ($dag_detail.name -eq $dag_name)
                            {
                                $dag_servers = $dag_detail.servers
                                $bDAGRemoved = $false
                                foreach ($dag_server in $dag_servers)
                                {
                                    if ($host_server -eq $dag_server.name)
                                    {
                                        $bServerRemoved = $false  #DAG present in the organization, no need to proceed check other items
                                        break
                                    }
                                }
                            }
                        }
                    }
                }
                else
                {
                    Trace "Debug" "ExitIfDAGRemoved: Job was not dropped on any Exchange 2010 or 2013 DAG Database objects"
                    $bDAGRemoved    = $false
                    $bServerRemoved = $false
                }

                # Breaking the loop as we need to check only for any one mailbox database
                break
            }
        }
        else
        {
            Trace "Debug" "ExitIfDAGRemoved: Get-DatabaseAvailabilityGroup cmdlet not found on this host."
        }

        Trace "Debug" "ExitIfDAGRemoved: DAG name = $dag_name"

        if ( ($bDAGRemoved -eq $true) -and ($dag_name -ne "") )
        {
            Trace "Error" "ExitIfDAGRemoved : DAG $dag_name is not available."
            $event_sev  = $PRM_SeverityFail
            $event_msg  = "$dag_name Database Availability Group is not available."
            $detail_msg = "Database Availability Group $dag_name is not available.  " `
                        + "Run Discovery_ExchangeDAG followed by Discovery_Exchange2007 " `
                        + "to rediscover the DAG."
            CreateEvent $event_sev $event_msg $detail_msg `
                        $global:target_resource $action_to_be_taken
            exit 0
        }
        elseif ($bServerRemoved -eq $true)
        {
            Trace "Error" "ExitIfDAGRemoved : Server $host_server is removed from DAG."
            $event_sev  = $PRM_SeverityFail
            $event_msg  = "$host_server server has been removed from the DAG."
            $detail_msg = "Server $host_server has been removed from Database Availability Group $dag_name.  " `
                        + "Run Discovery_ExchangeDAG followed by Discovery_Exchange2007 to rediscover the DAG."
            CreateEvent $event_sev $event_msg $detail_msg `
                        $global:target_resource $action_to_be_taken
            exit 0

        }

    }

    Trace "Debug" "ExitIfDAGRemoved: Exit"
}


# This function returns the FQDN
Function GetFQDNFromNamingContext
{
    $error.clear()
    trap
    {
        Trace "Error" "Exception thrown in the function GetFQDNFromNamingContext ; message: $_"
        continue
    }
    $Root       = [System.DirectoryServices.DirectoryEntry]"LDAP://RootDSE"
    $strDomain  = $Root.Get("DefaultNamingContext")
    $strFQDN    = $Null
    if ($error[0] -eq $null)
    {
        $result_dcs = ([Text.RegularExpressions.Regex]::Split($strDomain, ","))
        foreach ($result_dc in $result_dcs)
        {
            $result_dc = $result_dc.Trim()
            if ($result_dc -match "DC=(\w+)")
            {
                if ($strFQDN -ne $Null)
                {
                    $strFQDN = $strFQDN + "."
                }
                $strFQDN = $strFQDN + $matches[1]
            }

        }
    }
    else
    {
        Trace "Debug" "Exception thrown while executing cmdlet; message: $error[0]"
        $error.clear()
    }
    $strFQDN
}


# This function taks a hostname or cluster node name and a path (eg. Exchange database file path)
# and returns an array with the matching mount point/volume directory path and its volume/device ID
# that can be then used to find free disk space or perf counter data
function MatchVolumeFromPath
{
    param([System.String]  $node_name,
          [System.String]  $path)

    Trace "Debug" "MatchVolumeFromPath: Enter"

    $volume_matches = @()

    trap
    {
        Trace "Error" "MatchVolumeFromPath: Exception caught while collecting disk volume info from WMI: $_"
        continue;
    }

    $error.Clear()
    $provider_fail_msg = "provider failure"

    #
    # First try using WMI to fetch Win32_MountPoint class objects only
    #
    Trace "Debug" "MatchVolumeFromPath: Getting mount points via WMI for node/host => $node_name"
    $mount_points = Get-WmiObject -namespace root\cimv2 -ComputerName $node_name -class Win32_MountPoint `
                  | select Directory, Volume

    # Log any errors that occurred when using WMI
    if ($error.Count -gt 0)
    {
        for ($i = $error.Count - 1; $i -ge 0; $i -= 1)
        {
            if ($error[$i].ToString() -match $provider_fail_msg)
            {
                # Removing known error message that can occur when WMI stops responding properly to queries
                Trace "Warn" "MatchVolumeFromPath: Error [being removed from global error] occurred while fetching mount points via WMI => `"$($error[$i])`" at index $i"
                $error.RemoveAt($i)
            }
            else
            {
                Trace "Warn" "MatchVolumeFromPath: Error occurred while fetching mount points via WMI => `"$($error[$i])`" at index $i"
            }
        }
    }

    $longest_match     = 0
    $matched_volume    = $null
    $matched_directory = $null

    Trace "Debug" "MatchVolumeFromPath: Looking through mount points for closest match to input path of `"$path`""
    foreach ($mount_point in @($mount_points))
    {
        if (($mount_point.Directory -ne $null) -and ($mount_point.Directory -ne ""))
        {
            $directory = $mount_point.Directory -replace "Win32_Directory.Name=", ""
            $directory = $directory -replace '\\\\', '\'
            $directory = $directory -replace '"', ''
            Trace "Debug" "MatchVolumeFromPath: Working on Directory and Volume identifiers represented by Directory => $directory"
        }
        else
        {
            Trace "Debug" "MatchVolumeFromPath: Directory property for this mount point is null or unpopulated, so continuing to next one"
            continue
        }

        $volume = $mount_point.Volume -replace "Win32_Volume.DeviceID=.*Volume", ""
        $volume = $volume -replace '\\\\"', ''

        Trace "Debug" "MatchVolumeFromPath: Final disk directory for comparison = `"$directory`"; Volume: `"$volume`""
        if ($path.ToLower().StartsWith($directory.ToLower()))
        {
            if ($directory.Length -gt $longest_match)
            {
                $longest_match     = $directory.Length
                $matched_volume    = $volume
                $matched_directory = $directory
                Trace "Debug" "MatchVolumeFromPath: **Matched Volume: $matched_volume; longest matched Directory: $matched_directory **"
            }
        }
    }

    #
    # Second, try using WMI to fetch Win32_Volume class objects - somewhat harder to get information needed as
    # needs the 'Name' property specified
    #
    if ($matched_volume -eq $null) {

        Trace "Debug" "MatchVolumeFromPath: Getting Win32_Volumes via WMI for node/host => $node_name"
        $mount_points = Get-WmiObject -namespace "root\cimv2" -ComputerName "$node_name" -class "Win32_Volume" `
                      | select Caption, DeviceID, Name

        # Log any errors that occurred when using WMI
        if ($error.Count -gt 0)
        {
            for ($i = $error.Count - 1; $i -ge 0; $i -= 1)
            {
                if ($error[$i].ToString() -match $provider_fail_msg)
                {
                    # Removing known error message that can occur when WMI stops responding properly to queries
                    Trace "Warn" "MatchVolumeFromPath: Error [being removed from global error] occurred while fetching mount points via WMI => `"$($error[$i])`" at index $i"
                    $error.RemoveAt($i)
                }
                else
                {
                    Trace "Warn" "MatchVolumeFromPath: Error occurred while fetching mount points via WMI => `"$($error[$i])`" at index $i"
                }
            }
        }

        $longest_match     = 0
        $matched_volume    = $null
        $matched_directory = $null

        Trace "Debug" "MatchVolumeFromPath: Looking through mount points for closest match to input path of `"$path`""
        foreach ($mount_point in @($mount_points))
        {
            if (($mount_point.Name -ne $null) -and ($mount_point.Name -ne ""))
            {
                $directory = $mount_point.Name
                Trace "Debug" "MatchVolumeFromPath: Working on Win32_Volume with Name => $directory"
            }
            else
            {
                Trace "Debug" "MatchVolumeFromPath: Name property for this Win32_Volume is null or unpopulated, so continuing to next one"
                continue
            }

            $volume = $mount_point.DeviceID -replace ".*Volume", ""
            $volume = $volume -replace '\\\\"', ''

            Trace "Debug" "MatchVolumeFromPath: Final disk directory for comparison = `"$directory`"; Volume: `"$volume`""
            if ($path.ToLower().StartsWith($directory.ToLower()))
            {
                if ($directory.Length -gt $longest_match)
                {
                    $longest_match     = $directory.Length
                    $matched_volume    = $volume
                    $matched_directory = $directory
                    Trace "Debug" "MatchVolumeFromPath: **Matched Volume: $matched_volume; longest matched Directory: $matched_directory **"
                }
            }
        }

    } # end if matched_volume eq null



    # Assign matched volume and directory to a custom object identifying the properties, and then
    # place in output array for use by caller
    if ( ($matched_volume -ne $null) -and ($matched_directory -ne $null) ) {

        # Remove any trailing backslash from directory
        if ($matched_directory.Substring($matched_directory.length - 1, 1) -eq "\")
        {
            $matched_directory = $matched_directory.Substring(0, $matched_directory.length - 1)
        }

        Trace "Debug" "MatchVolumeFromPath: Returning best path match with directory [$matched_directory] and volume ID [$matched_volume]"
        $volume_match_object = New-Object PSObject
        Add-Member -in $volume_match_object NoteProperty "Directory" $matched_directory
        Add-Member -in $volume_match_object NoteProperty "Volume" $matched_volume
        $volume_matches += $volume_match_object

    } else {
        Trace "Info" "MatchVolumeFromPath: Warning - No matching drive found for input path requested!!"
    }

    $volume_matches

}

function BuildEventDetailsTable
{
    param($Mailboxes,
	      $Mailboxes_count,
		  $HasSQThreshold,
		  $HasSRQThreshold,
		  $HasRemark)
		  
	Trace "Debug" "BuildEventDetailsTable - Enter"
    $Mailbox_rows = New-Object Collections.Hashtable[] $Mailboxes_count
	
	$index = 0
	
	foreach($Mailbox in $Mailboxes)
	{
	
		$Mailbox_rows[$index] = New-Object Collections.Hashtable

        $Mailbox_rows[$index]['Column1'] = New-Object Collections.Hashtable
        $Mailbox_rows[$index]['Column1']['Text'] = $Mailbox.DisplayName.ToString()
			
        $Mailbox_rows[$index]['Column2'] = New-Object Collections.Hashtable
        $Mailbox_rows[$index]['Column2']['Text'] = $Mailbox.Mailboxfree.ToString()
		
		$Mailbox_rows[$index]['Column3'] = New-Object Collections.Hashtable
        $Mailbox_rows[$index]['Column3']['Text'] = $Mailbox.MailboxUsedPercent.ToString()
		
		$Mailbox_rows[$index]['Column4'] = New-Object Collections.Hashtable
        $Mailbox_rows[$index]['Column4']['Text'] = $Mailbox.MailboxUsed.ToString()
		
		$Mailbox_rows[$index]['Column5'] = New-Object Collections.Hashtable
        $Mailbox_rows[$index]['Column5']['Text'] = $Mailbox.WarningQuota.ToString()
		
		if($HasSQThreshold)
		{
			$Mailbox_rows[$index]['Column6'] = New-Object Collections.Hashtable
			$Mailbox_rows[$index]['Column6']['Text'] = $Mailbox.SendQuotaThreshold.ToString()
			
			$Mailbox_rows[$index]['Column7'] = New-Object Collections.Hashtable
			$Mailbox_rows[$index]['Column7']['Text'] = $Mailbox.SendQuotaThresholdFormula.ToString()
		}
		
		$Mailbox_rows[$index]['Column8'] = New-Object Collections.Hashtable
        $Mailbox_rows[$index]['Column8']['Text'] = $Mailbox.SendQuota.ToString()
		
		if($HasSRQThreshold)
		{
			$Mailbox_rows[$index]['Column9'] = New-Object Collections.Hashtable
			$Mailbox_rows[$index]['Column9']['Text'] = $Mailbox.SendReceiveQuotaThreshold.ToString()
			
			$Mailbox_rows[$index]['Column10'] = New-Object Collections.Hashtable
			$Mailbox_rows[$index]['Column10']['Text'] = $Mailbox.SendReceiveQuotaThresholdFormula.ToString()
		}
		
		$Mailbox_rows[$index]['Column11'] = New-Object Collections.Hashtable
        $Mailbox_rows[$index]['Column11']['Text'] = $Mailbox.SendReceiveQuota.ToString()
		
		$Mailbox_rows[$index]['Column12'] = New-Object Collections.Hashtable
        $Mailbox_rows[$index]['Column12']['Text'] = $Mailbox.UPN.ToString() 
		
		$Mailbox_rows[$index]['Column13'] = New-Object Collections.Hashtable
        $Mailbox_rows[$index]['Column13']['Text'] = $Mailbox.MailBoxType.ToString()
		
		$Mailbox_rows[$index]['Column14'] = New-Object Collections.Hashtable
        $Mailbox_rows[$index]['Column14']['Text'] = $Mailbox.Server.ToString()
		
		$Mailbox_rows[$index]['Column15'] = New-Object Collections.Hashtable
        $Mailbox_rows[$index]['Column15']['Text'] = $Mailbox.Database.ToString()
		
		$Mailbox_rows[$index]['Column16'] = New-Object Collections.Hashtable
        $Mailbox_rows[$index]['Column16']['Text'] = $Mailbox.LastLogonTime.ToString()
		
		if($HasRemark)
		{
		    $Mailbox_rows[$index]['Column17'] = New-Object Collections.Hashtable
			$Mailbox_rows[$index]['Column17']['Text'] = $Mailbox.Remarks.ToString()
		}
		$index += 1
	}			
	
	$detail_message = ""
	
	if ($Mailbox_rows.Count -gt 0)
	{	
		$Columns=@()

		$column1 = New-Object Collections.Hashtable
		$column1['Name']   = "Column1"
		$column1['Title']  = "Display Name "
		$column1['ACType']  = "ACName"
		$Columns += $column1
		remove-variable column1
	   
		$column2 = New-Object Collections.Hashtable
		$column2['Name']   = "Column2"
		$column2['Title']  = "Mailbox Freespace(MB) "
		$column2['ACType']  = "ACName"
		$Columns += $column2
		remove-variable column2
	   
		$column3 = New-Object Collections.Hashtable
		$column3['Name']   = "Column3"
		$column3['Title']  = "Mailbox Used(%) "
		$column3['ACType']  = "ACName"
		$Columns += $column3
		remove-variable column3
	   
		$column4 = New-Object Collections.Hashtable
		$column4['Name']   = "Column4"
		$column4['Title']  = "Mailbox Used(MB) "
		$column4['ACType']  = "ACName"
		$Columns += $column4
		remove-variable column4
	   
		$column5 = New-Object Collections.Hashtable
		$column5['Name']   = "Column5"
		$column5['Title']  = "WQ (Warning Quota in MB) "
		$column5['ACType']  = "ACName"
		$Columns += $column5
		remove-variable column5

		if($HasSQThreshold)
		{				   
			$column6 = New-Object Collections.Hashtable
			$column6['Name']   = "Column6"
			$column6['Title']  = "Send Quota Threshold(MB) "
			$column6['ACType']  = "ACName"
			$Columns += $column6
			remove-variable column6
			
			$column7 = New-Object Collections.Hashtable
			$column7['Name']   = "Column7"
			$column7['Title']  = "Send Quota Threshold Formula "
			$column7['ACType']  = "ACName"
			$Columns += $column7
			remove-variable column7
		} 
	   
		$column8 = New-Object Collections.Hashtable
		$column8['Name']   = "Column8"
		$column8['Title']  = "SQ (Send Quota in MB) "
		$column8['ACType']  = "ACName"
		$Columns += $column8
		remove-variable column8

		if($HasSRQThreshold)
		{
			$column9 = New-Object Collections.Hashtable
			$column9['Name']   = "Column9"
			$column9['Title']  = "Send/Receive Quota Threshold(MB) "
			$column9['ACType']  = "ACName"
			$Columns += $column9
			remove-variable column9
			
			$column10 = New-Object Collections.Hashtable
			$column10['Name']   = "Column10"
			$column10['Title']  = "Send/Receive Quota Threshold Formula "
			$column10['ACType']  = "ACName"
			$Columns += $column10
			remove-variable column10
		}
	   
	   
		$column11 = New-Object Collections.Hashtable
		$column11['Name']   = "Column11"
		$column11['Title']  = "SRQ (Send/Receive Quota in MB)  "
		$column11['ACType']  = "ACName"
		$Columns += $column11
		remove-variable column11

		$column12 = New-Object Collections.Hashtable
		$column12['Name']   = "Column12"
		$column12['Title']  = "User Principal Name "
		$column12['ACType']  = "ACName"
		$Columns += $column12
		remove-variable column12

		$column13 = New-Object Collections.Hashtable
		$column13['Name']   = "Column13"
		$column13['Title']  = "Mailbox Type " 
		$column13['ACType']  = "ACName"
		$Columns += $column13
		remove-variable column13
	   
		$column14 = New-Object Collections.Hashtable
		$column14['Name']   = "Column14"
		$column14['Title']  =  "Server " 
		$column14['ACType']  = "ACName"
		$Columns += $column14
		remove-variable column14
		
		
		$column15 = New-Object Collections.Hashtable
		$column15['Name']   = "Column15"
		$column15['Title']  = "Database "
		$column15['ACType']  = "ACName"
		$Columns += $column15
		remove-variable column15	
	   
		$column16 = New-Object Collections.Hashtable
		$column16['Name']   = "Column16"
		$column16['Title']  = "LastLogonTime "
		$column16['ACType']  = "ACName"
		$Columns += $column16
		remove-variable column16

        if($HasRemark)
		{
			$column17 = New-Object Collections.Hashtable
			$column17['Name']   = "Column17"
			$column17['Title']  = "Remark "
			$column17['ACType']  = "ACName"
			$Columns += $column17
			remove-variable column17
		}
					

		#
        # Building the detail message for events
        #
        $detail_info =
        @{
            Title        = "Mailbox usage report"
            Description  = ""
            TableGUID    = ""
            DetailType   = "Event"

            ColumnDefs = $Columns
            Rows = $Mailbox_rows
        }
        $detail_table = BuildDetailTableXML $detail_info
        $detail_message  = "$detail_table"
	}
	Trace "Debug" "BuildEventDetailsTable - Exit"
	
	return $detail_message
}



function ConnectAzureAD([System.String]$val1, [System.String]$val2, [System.String]$val3)
{
    
	#----------------Azure AD---------------------------
    #
	Trace "Debug" "Initializing Connection to AzureAD... , $val1 , $val2 , $Val3"
	$val 	= ConvertTo-SecureString $val2 -AsPlainText -Force
	$val1= $($val1+"@$val3")
	$cr 	= New-Object System.Management.Automation.PSCredential ($val1, $val)

	$error.clear()
	try
	{
		Connect-AzureAD -Credential $cr
		if ($error.Count -gt 0)
		{
			$err = $error[0].Exception 
			for ($i = $error.Count - 1; $i -ge 0; $i -= 1)
			{
				Trace "Error" "AzureAD: Error occurred => `"$($error[$i])`" at index $i"
			}
			$Object = New-Object PSObject
			$Object | add-member Noteproperty Domain       $($val3 +"  ")      
			$Object | add-member Noteproperty Status       "Failed   "		
			$Object | add-member Noteproperty "Reason For Failure"      $($err.Message +"`n") 
				   
			$global:Domain_Discovery_Details+=$Object			   
			remove-variable Object
			
			$error.clear()
					
			$global:connect_success=0
		}
		else
		{ 
			$global:connect_success=1		
		}
	}
	catch
	{
		Trace "Error" "Exception happened while connecting to AzureAD: $_"
		$global:connect_success=0
		$err = $_.Exception.Message + "`n"
		$Object = New-Object PSObject
		$Object | add-member Noteproperty Domain       $($val3 +"  ")      
		$Object | add-member Noteproperty Status       "Failed   "
		$Object | add-member Noteproperty "Reason For Failure"      $err
			   
		$global:Domain_Discovery_Details+=$Object			   
		remove-variable Object
		$error.clear()		
	}    
}

if ($args.Length -eq 0)
{
    exit 0
}


#
# Set PowerScript variables from values passed on the command line.
#
SetCommandLineVariables $args

#
# Initialize Default resources.
#
InitializeDefaultResource
#
# Set a reasonable window width, so that formatted messages have a reasonable
# column width and can thus contain a reasonable number of table columns.
#
SetWindowWidth


#
# Tell the runtime to format types using our format definition file.
#
# Raju Check this Update-FormatData
#Update-FormatData -PrependPath Exchange2007.Format.ps1xml `
                            #-ErrorAction SilentlyContinue
							

							#
# Initialize various global variables.
$ErrorActionPreference = "Stop"
$global:azuread_usersinfo    = ""
$global:exchangeonline_usersinfo_resource  = ""
$resource_and_fullpath       = GetDefaultResourceAndFullPath
$global:target_resource      = $resource_and_fullpath[0]
$global:target_fullpath      = $resource_and_fullpath[1]
$global:job_failure_severity = FirstOf $PRM_SeverityFail 5
$global:action_to_be_taken   = $AKPID
$Incorrect_SM_msg = "To specify the credentials, create an entry in Security Manager as follows`n" `
                    + "`n" `
                    + "`tLabel     :     AzureAD`n" `
                    + "`tSub-Label :     <Domain>`n" `
                    + "`tValue 1   :     <Username>`n" `
                    + "`tValue 2   :     <Password>`n" `
                    + "`tValue 3   :     [not used - leave this value empty]`n" `
					+ "`n" `
					+ "NOTE: When entering the credentials in Security Manager you must check the`n" `
                    + "`t`"Extended application support`" checkbox to encrypt the information.`n" `
                    + "`tIf the credentials are not encrypted in this manner the Exchange`n" `
                    + "`tmodule will not be able to access them`n`n" 



###########################################################
# Main script execution
###########################################################

TraceJobStart "AzureAD_UsersInfo"



if($global:azuread_usersinfo)
{
    Trace "Debug" "Monitoring Azure AD User's Activities - Enter"
	Trace "Debug" "global:target_resource = $global:target_resource"
	Trace "Debug" "global:target_fullpath = $global:target_fullpath"
		
		
	$monitored_azuread_domains = GetMonitoredAzureADDomainNames
	$total_domains= $monitored_azuread_domains.count
		
	Trace "Debug" "Total domains : $total_domains"
	
	foreach ($domain in $monitored_azuread_domains)
	{
	
		Trace "Debug" "$domain = $domain"	   
		Trace "Debug" "Getting security context for domain $domain"
		#$Event_target = GetMailboxQuotaResource $domain
		$Event_target = $NT_MachineFolder
		# Raju - Check the GetMailboxQuotaResource for Event_target
		
		#$Vals = GetSecurityContext 'AzureAD' $domain $true

		$vals = @()
		$Vals = @("pralay.roy","Control@123"," ")
		Trace "Debug" "Security context for domain $domain is available now"
		if((!$Vals) -or (($Vals[0] -eq "") -or ($Vals[1] -eq "") -or ($Vals[2] -eq "")))
		{
			Trace "Debug" "Missing or Incorrect Security Manager credentials for this domain"
			$event_msg = "Failed to monitor Azure AD for the domain $domain"
			$detail_message = "Missing or Incorrect Security Manager credentials for this domain`n"
			$detail_message += $Incorrect_SM_msg			
			CreateEvent $PRM_SeverityFail $event_msg $detail_message $Event_target $action_to_be_taken				
			Continue
		}
		
		
		$azureAD_users_count_TH=0
		$azureAD_new_users=@()
		$azureAD_deleted_users=@()
		
		$domainName = "novellSMG.onmicrosoft.com"	
		

	    $error.clear()
		try
		{
		
			Trace "Debug" "Attempting to import to Azure AD Module "
			Import-Module AzureAD
			
			Trace "Debug" "Attempting to connect to Azure AD: $domainName "
			ConnectAzureAD $Vals[0] $Vals[1] $domainName
		
			Trace "Debug" "Connected == $global:connect_success "
			if ($global:connect_success)
			{
		  
				Trace "Debug" "Main: Successfully connected to AzureAD for domain $domainName"
				
				if ( $PRM_Users_Crossed_TH -eq $true)
				{
					$usercount = 0
					$usercount = Get-AzureADUser -All 1 | Measure
					$usrcount = $usercount.count
					
					Trace "Debug" "Total group count $gpcount"
					
					if ($usrcount -ge $PRM_Users_Count_Threshold)
					{
						Trace "Debug" "Main: Users Count Crossed the threshold limit"
						$event_msg  = "Users Count on AzureAD:$domain exceeded threshold."
						$detail_message = "Total # of Users = $usrcount ,Threshold Limit = $PRM_Users_Count_Threshold `n`n"
						$detail_message += "Number of Users on AzureAD:$domain crossed the set throughold `n"
						$detail_message += "Either change the limit or block user creation"
						
						CreateEvent $PRM_Users_TH_EventSeverity $event_msg $detail_message $Event_target $action_to_be_taken
						
					}
					else
					{
						Trace "Error" "Main: Users Count not Crossed the threshold limit"
					}
				}
				if ( $PRM_New_User_Creat -eq $true)
				{
					
					Trace "Debug" "Main: New User Created in Azure AD"
					$event_msg  = "New User(s) created in AzureAD:$domain."
					$detail_message = "New User(s) got created in AzureAD:$domain `n"
					$detail_message += "Details"
						
					CreateEvent $PRM_New_User_Creat_EventSeverity $event_msg $detail_message $Event_target $action_to_be_taken
					
				}
				if ( $PRM_User_Deleted -eq $true)
				{
					Trace "Debug" "Main:  User deleted in Azure AD"
					$event_msg  = "Existing User(s) deleted AzureAD:$domain."
					$detail_message = " Existing User(s) got detelted in AzureAD:$domain `n"
					$detail_message += "Details"
						
					CreateEvent $PRM_User_Deleted_EventSeverity $event_msg $detail_message $Event_target $action_to_be_taken
				}
				
				Disconnect-AzureAD
			}
			else
			{	
				Trace "Debug" "Main: Failed to connect AzureAD for domain $domainName"
				
			}
	
			
		}
		catch
		{		    
			Trace "Debug" "Main: Exception raised while attempting to fetch Azure AD group information for the domain $domain"
		 	$error_msg = $_.Exception.Message
			$event_msg = "Failed to retrieve user details for $domain"
			CreateEvent $PRM_SeverityFail $event_msg $error_msg $Event_target $action_to_be_taken
			
			$error.clear()
			if($ExchangeSession)
			{
				Remove-PSSession $ExchangeSession
			}			
		}	
	}
	Trace "Debug" "Monitoring Azure AD Users Info - Exit"
}
TraceJobCompletion "AzureAD_UsersInfo"
# SIG # Begin signature block
# MIIXmwYJKoZIhvcNAQcCoIIXjDCCF4gCAQExCzAJBgUrDgMCGgUAMGkGCisGAQQB
# gjcCAQSgWzBZMDQGCisGAQQBgjcCAR4wJgIDAQAABBAfzDtgWUsITrck0sYpfvNR
# AgEAAgEAAgEAAgEAAgEAMCEwCQYFKw4DAhoFAAQU9E9HhXZc3i62hde5SmRG7+/q
# MqOgghLJMIID7jCCA1egAwIBAgIQfpPr+3zGTlnqS5p31Ab8OzANBgkqhkiG9w0B
# AQUFADCBizELMAkGA1UEBhMCWkExFTATBgNVBAgTDFdlc3Rlcm4gQ2FwZTEUMBIG
# A1UEBxMLRHVyYmFudmlsbGUxDzANBgNVBAoTBlRoYXd0ZTEdMBsGA1UECxMUVGhh
# d3RlIENlcnRpZmljYXRpb24xHzAdBgNVBAMTFlRoYXd0ZSBUaW1lc3RhbXBpbmcg
# Q0EwHhcNMTIxMjIxMDAwMDAwWhcNMjAxMjMwMjM1OTU5WjBeMQswCQYDVQQGEwJV
# UzEdMBsGA1UEChMUU3ltYW50ZWMgQ29ycG9yYXRpb24xMDAuBgNVBAMTJ1N5bWFu
# dGVjIFRpbWUgU3RhbXBpbmcgU2VydmljZXMgQ0EgLSBHMjCCASIwDQYJKoZIhvcN
# AQEBBQADggEPADCCAQoCggEBALGss0lUS5ccEgrYJXmRIlcqb9y4JsRDc2vCvy5Q
# WvsUwnaOQwElQ7Sh4kX06Ld7w3TMIte0lAAC903tv7S3RCRrzV9FO9FEzkMScxeC
# i2m0K8uZHqxyGyZNcR+xMd37UWECU6aq9UksBXhFpS+JzueZ5/6M4lc/PcaS3Er4
# ezPkeQr78HWIQZz/xQNRmarXbJ+TaYdlKYOFwmAUxMjJOxTawIHwHw103pIiq8r3
# +3R8J+b3Sht/p8OeLa6K6qbmqicWfWH3mHERvOJQoUvlXfrlDqcsn6plINPYlujI
# fKVOSET/GeJEB5IL12iEgF1qeGRFzWBGflTBE3zFefHJwXECAwEAAaOB+jCB9zAd
# BgNVHQ4EFgQUX5r1blzMzHSa1N197z/b7EyALt0wMgYIKwYBBQUHAQEEJjAkMCIG
# CCsGAQUFBzABhhZodHRwOi8vb2NzcC50aGF3dGUuY29tMBIGA1UdEwEB/wQIMAYB
# Af8CAQAwPwYDVR0fBDgwNjA0oDKgMIYuaHR0cDovL2NybC50aGF3dGUuY29tL1Ro
# YXd0ZVRpbWVzdGFtcGluZ0NBLmNybDATBgNVHSUEDDAKBggrBgEFBQcDCDAOBgNV
# HQ8BAf8EBAMCAQYwKAYDVR0RBCEwH6QdMBsxGTAXBgNVBAMTEFRpbWVTdGFtcC0y
# MDQ4LTEwDQYJKoZIhvcNAQEFBQADgYEAAwmbj3nvf1kwqu9otfrjCR27T4IGXTdf
# plKfFo3qHJIJRG71betYfDDo+WmNI3MLEm9Hqa45EfgqsZuwGsOO61mWAK3ODE2y
# 0DGmCFwqevzieh1XTKhlGOl5QGIllm7HxzdqgyEIjkHq3dlXPx13SYcqFgZepjhq
# IhKjURmDfrYwggSjMIIDi6ADAgECAhAOz/Q4yP6/NW4E2GqYGxpQMA0GCSqGSIb3
# DQEBBQUAMF4xCzAJBgNVBAYTAlVTMR0wGwYDVQQKExRTeW1hbnRlYyBDb3Jwb3Jh
# dGlvbjEwMC4GA1UEAxMnU3ltYW50ZWMgVGltZSBTdGFtcGluZyBTZXJ2aWNlcyBD
# QSAtIEcyMB4XDTEyMTAxODAwMDAwMFoXDTIwMTIyOTIzNTk1OVowYjELMAkGA1UE
# BhMCVVMxHTAbBgNVBAoTFFN5bWFudGVjIENvcnBvcmF0aW9uMTQwMgYDVQQDEytT
# eW1hbnRlYyBUaW1lIFN0YW1waW5nIFNlcnZpY2VzIFNpZ25lciAtIEc0MIIBIjAN
# BgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAomMLOUS4uyOnREm7Dv+h8GEKU5Ow
# mNutLA9KxW7/hjxTVQ8VzgQ/K/2plpbZvmF5C1vJTIZ25eBDSyKV7sIrQ8Gf2Gi0
# jkBP7oU4uRHFI/JkWPAVMm9OV6GuiKQC1yoezUvh3WPVF4kyW7BemVqonShQDhfu
# ltthO0VRHc8SVguSR/yrrvZmPUescHLnkudfzRC5xINklBm9JYDh6NIipdC6Anqh
# d5NbZcPuF3S8QYYq3AhMjJKMkS2ed0QfaNaodHfbDlsyi1aLM73ZY8hJnTrFxeoz
# C9Lxoxv0i77Zs1eLO94Ep3oisiSuLsdwxb5OgyYI+wu9qU+ZCOEQKHKqzQIDAQAB
# o4IBVzCCAVMwDAYDVR0TAQH/BAIwADAWBgNVHSUBAf8EDDAKBggrBgEFBQcDCDAO
# BgNVHQ8BAf8EBAMCB4AwcwYIKwYBBQUHAQEEZzBlMCoGCCsGAQUFBzABhh5odHRw
# Oi8vdHMtb2NzcC53cy5zeW1hbnRlYy5jb20wNwYIKwYBBQUHMAKGK2h0dHA6Ly90
# cy1haWEud3Muc3ltYW50ZWMuY29tL3Rzcy1jYS1nMi5jZXIwPAYDVR0fBDUwMzAx
# oC+gLYYraHR0cDovL3RzLWNybC53cy5zeW1hbnRlYy5jb20vdHNzLWNhLWcyLmNy
# bDAoBgNVHREEITAfpB0wGzEZMBcGA1UEAxMQVGltZVN0YW1wLTIwNDgtMjAdBgNV
# HQ4EFgQURsZpow5KFB7VTNpSYxc/Xja8DeYwHwYDVR0jBBgwFoAUX5r1blzMzHSa
# 1N197z/b7EyALt0wDQYJKoZIhvcNAQEFBQADggEBAHg7tJEqAEzwj2IwN3ijhCcH
# bxiy3iXcoNSUA6qGTiWfmkADHN3O43nLIWgG2rYytG2/9CwmYzPkSWRtDebDZw73
# BaQ1bHyJFsbpst+y6d0gxnEPzZV03LZc3r03H0N45ni1zSgEIKOq8UvEiCmRDoDR
# EfzdXHZuT14ORUZBbg2w6jiasTraCXEQ/Bx5tIB7rGn0/Zy2DBYr8X9bCT2bW+IW
# yhOBbQAuOA2oKY8s4bL0WqkBrxWcLC9JG9siu8P+eJRRw4axgohd8D20UaF5Mysu
# e7ncIAkTcetqGVvP6KUwVyyJST+5z3/Jvz4iaGNTmr1pdKzFHTx/kuDDvBzYBHUw
# ggTPMIIDt6ADAgECAhBG0NW61AkZ34AozjyvlpSCMA0GCSqGSIb3DQEBCwUAMH8x
# CzAJBgNVBAYTAlVTMR0wGwYDVQQKExRTeW1hbnRlYyBDb3Jwb3JhdGlvbjEfMB0G
# A1UECxMWU3ltYW50ZWMgVHJ1c3QgTmV0d29yazEwMC4GA1UEAxMnU3ltYW50ZWMg
# Q2xhc3MgMyBTSEEyNTYgQ29kZSBTaWduaW5nIENBMB4XDTE2MDkxOTAwMDAwMFoX
# DTE3MTAxOTIzNTk1OVowZzELMAkGA1UEBhMCVVMxDjAMBgNVBAgMBVRleGFzMRAw
# DgYDVQQHDAdIb3VzdG9uMRowGAYDVQQKDBFOZXRJUSBDb3Jwb3JhdGlvbjEaMBgG
# A1UEAwwRTmV0SVEgQ29ycG9yYXRpb24wggEiMA0GCSqGSIb3DQEBAQUAA4IBDwAw
# ggEKAoIBAQC51eA0O/XiktnOh22dQ2a3UoDUXN2m/y0ZWF72MFssgtpAlhDyZwEH
# 3OUfMGeNHW0xGGlhkxrrTWOwFWNBrWMEaN08wdQ1RIwDsOxQ0Hx0wBKXL8P7LoTk
# GbKGcgTO9+/P5T7OK8/JHoRIy+R5WaTEZwOuzJEBYpzsIHbllJvy4hRtYd7HuPVV
# YJPH2NkaaexFhuq6GeU2FEphUiuL+PZvm1V1Q7gHlJVqJIYWUlLl2WHk1U1fqtKO
# WMGT/HhK1kbUTwwWUl9oKqwBRfJRWhh4e7gfNd9iN9gGSzQ+10J9yrLeJaVwvhlK
# yeEhn9sSWX3qmu2Zz/ixCz7y4q5motExAgMBAAGjggFdMIIBWTAJBgNVHRMEAjAA
# MA4GA1UdDwEB/wQEAwIHgDArBgNVHR8EJDAiMCCgHqAchhpodHRwOi8vc3Yuc3lt
# Y2IuY29tL3N2LmNybDBhBgNVHSAEWjBYMFYGBmeBDAEEATBMMCMGCCsGAQUFBwIB
# FhdodHRwczovL2Quc3ltY2IuY29tL2NwczAlBggrBgEFBQcCAjAZDBdodHRwczov
# L2Quc3ltY2IuY29tL3JwYTATBgNVHSUEDDAKBggrBgEFBQcDAzBXBggrBgEFBQcB
# AQRLMEkwHwYIKwYBBQUHMAGGE2h0dHA6Ly9zdi5zeW1jZC5jb20wJgYIKwYBBQUH
# MAKGGmh0dHA6Ly9zdi5zeW1jYi5jb20vc3YuY3J0MB8GA1UdIwQYMBaAFJY7U/B5
# M5evfYPvLivMyreGHnJmMB0GA1UdDgQWBBQuLDgRnJbcnHc651bedpvz2SCCeDAN
# BgkqhkiG9w0BAQsFAAOCAQEAh6s1sptMcewPLSZhmVIy7IEHgbjyFQwoHeG5/WAj
# HDrabY07rRz2vSLgocpDZlBwYfGQM2IG8iaR1k0VXwM5KHQBEFiVHpJZDNzVurzt
# o9DOx/ehDuSALxdhhL6sk/831j7f7UnntCgiQLfgn7UxnID+x1w3wSEQKtcttdMO
# MDLWtSmkmxRSnZ1p64TcnABXke+VsPxAuD67Yor4IYeOAoQV0rVLei72wQfOjZlB
# hrOmgRErhcUkVpiS0d7wrEoaHN+P7SxtNiql8YbLewO19D35Rk39lGjSIOfuOirp
# 75JTG1QJ7z2eUMRls+0DowSm4/YsM+yC6nCVlSaraj61ITCCBVkwggRBoAMCAQIC
# ED141/l2SWCyYX308B7KhiowDQYJKoZIhvcNAQELBQAwgcoxCzAJBgNVBAYTAlVT
# MRcwFQYDVQQKEw5WZXJpU2lnbiwgSW5jLjEfMB0GA1UECxMWVmVyaVNpZ24gVHJ1
# c3QgTmV0d29yazE6MDgGA1UECxMxKGMpIDIwMDYgVmVyaVNpZ24sIEluYy4gLSBG
# b3IgYXV0aG9yaXplZCB1c2Ugb25seTFFMEMGA1UEAxM8VmVyaVNpZ24gQ2xhc3Mg
# MyBQdWJsaWMgUHJpbWFyeSBDZXJ0aWZpY2F0aW9uIEF1dGhvcml0eSAtIEc1MB4X
# DTEzMTIxMDAwMDAwMFoXDTIzMTIwOTIzNTk1OVowfzELMAkGA1UEBhMCVVMxHTAb
# BgNVBAoTFFN5bWFudGVjIENvcnBvcmF0aW9uMR8wHQYDVQQLExZTeW1hbnRlYyBU
# cnVzdCBOZXR3b3JrMTAwLgYDVQQDEydTeW1hbnRlYyBDbGFzcyAzIFNIQTI1NiBD
# b2RlIFNpZ25pbmcgQ0EwggEiMA0GCSqGSIb3DQEBAQUAA4IBDwAwggEKAoIBAQCX
# gx4AFq8ssdIIxNdok1FgHnH24ke021hNI2JqtL9aG1H3ow0Yd2i72DarLyFQ2p7z
# 518nTgvCl8gJcJOp2lwNTqQNkaC07BTOkXJULs6j20TpUhs/QTzKSuSqwOg5q1PM
# IdDMz3+b5sLMWGqCFe49Ns8cxZcHJI7xe74xLT1u3LWZQp9LYZVfHHDuF33bi+Vh
# iXjHaBuvEXgamK7EVUdT2bMy1qEORkDFl5KK0VOnmVuFNVfT6pNiYSAKxzB3JBFN
# YoO2untogjHuZcrf+dWNsjXcjCtvanJcYISc8gyUXsBWUgBIzNP4pX3eL9cT5Dio
# hNVGuBOGwhud6lo43ZvbAgMBAAGjggGDMIIBfzAvBggrBgEFBQcBAQQjMCEwHwYI
# KwYBBQUHMAGGE2h0dHA6Ly9zMi5zeW1jYi5jb20wEgYDVR0TAQH/BAgwBgEB/wIB
# ADBsBgNVHSAEZTBjMGEGC2CGSAGG+EUBBxcDMFIwJgYIKwYBBQUHAgEWGmh0dHA6
# Ly93d3cuc3ltYXV0aC5jb20vY3BzMCgGCCsGAQUFBwICMBwaGmh0dHA6Ly93d3cu
# c3ltYXV0aC5jb20vcnBhMDAGA1UdHwQpMCcwJaAjoCGGH2h0dHA6Ly9zMS5zeW1j
# Yi5jb20vcGNhMy1nNS5jcmwwHQYDVR0lBBYwFAYIKwYBBQUHAwIGCCsGAQUFBwMD
# MA4GA1UdDwEB/wQEAwIBBjApBgNVHREEIjAgpB4wHDEaMBgGA1UEAxMRU3ltYW50
# ZWNQS0ktMS01NjcwHQYDVR0OBBYEFJY7U/B5M5evfYPvLivMyreGHnJmMB8GA1Ud
# IwQYMBaAFH/TZafC3ey78DAJ80M5+gKvMzEzMA0GCSqGSIb3DQEBCwUAA4IBAQAT
# hRoeaak396C9pK9+HWFT/p2MXgymdR54FyPd/ewaA1U5+3GVx2Vap44w0kRaYdtw
# b9ohBcIuc7pJ8dGT/l3JzV4D4ImeP3Qe1/c4i6nWz7s1LzNYqJJW0chNO4LmeYQW
# /CiwsUfzHaI+7ofZpn+kVqU/rYQuKd58vKiqoz0EAeq6k6IOUCIpF0yH5DoRX9ak
# JYmbBWsvtMkBTCd7C6wZBSKgYBU/2sn7TUyP+3Jnd/0nlMe6NQ6ISf6N/SivShK9
# DbOXBd5EDBX6NisD3MFQAfGhEV0U5eK9J0tUviuEXg+mw3QFCu+Xw4kisR93873N
# Q9TxTKk/tYuEr2Ty0BQhMYIEPDCCBDgCAQEwgZMwfzELMAkGA1UEBhMCVVMxHTAb
# BgNVBAoTFFN5bWFudGVjIENvcnBvcmF0aW9uMR8wHQYDVQQLExZTeW1hbnRlYyBU
# cnVzdCBOZXR3b3JrMTAwLgYDVQQDEydTeW1hbnRlYyBDbGFzcyAzIFNIQTI1NiBD
# b2RlIFNpZ25pbmcgQ0ECEEbQ1brUCRnfgCjOPK+WlIIwCQYFKw4DAhoFAKBwMBAG
# CisGAQQBgjcCAQwxAjAAMBkGCSqGSIb3DQEJAzEMBgorBgEEAYI3AgEEMBwGCisG
# AQQBgjcCAQsxDjAMBgorBgEEAYI3AgEVMCMGCSqGSIb3DQEJBDEWBBQFE7miHXUx
# B2JKrv6+tJfRG9IBhDANBgkqhkiG9w0BAQEFAASCAQBaBnMGtebPW1dGGk+UH50q
# uwcZ88Gh2HlgPiVS477bkZ2C4ZOKZqqCLPfA48YlQ31/NKbQKI34pcqzl45/r226
# V9VrjSmxLJfqYwM9mhpgAooySZ0TBbbm9g0dmLS5TJBbMtB0+mrb4Qbp0rJTay2c
# o4VHgsmK3W4BP1a53LDteCG40Z3wQcilx2ZlLkFFQ30SWTAYNZU19iphSSC3/Jnl
# j1mAmbX05FcXz6x+5ad+VRot6kyD51ppiJFR5Qq2v8i2WkK8EDwtcbVXOECsdiRF
# fm5k4GVRTdWF6lu5WI2/R77UCplvE9h2FGpqSto8haG84qug2rvOcPQaIVacdRso
# oYICCzCCAgcGCSqGSIb3DQEJBjGCAfgwggH0AgEBMHIwXjELMAkGA1UEBhMCVVMx
# HTAbBgNVBAoTFFN5bWFudGVjIENvcnBvcmF0aW9uMTAwLgYDVQQDEydTeW1hbnRl
# YyBUaW1lIFN0YW1waW5nIFNlcnZpY2VzIENBIC0gRzICEA7P9DjI/r81bgTYapgb
# GlAwCQYFKw4DAhoFAKBdMBgGCSqGSIb3DQEJAzELBgkqhkiG9w0BBwEwHAYJKoZI
# hvcNAQkFMQ8XDTE3MDYwNzA0NDY0MVowIwYJKoZIhvcNAQkEMRYEFE5aWtSur3qn
# yWPOBVmuOLHVvJY9MA0GCSqGSIb3DQEBAQUABIIBAJVw4uIUxzINUxCnuxbaeeSf
# QnRVaoSGg+6JUE1Lq8FjpXZbhmCX7TbWPJovH786Ut3JsIm4/LgIbTM2zEGjb5Ny
# R7MscCxa/NvEruPf1KUAzg3LS/Dh8YSM94uI0EDal3OwhcZiseNyyHvEfRWZqKSf
# Z28PIvCM5JucblNO9uncFHMMrFXp+tVfsiN7Ngtb7xCs02dEB3V9XTo6FM5lHSIY
# FWglRgUES2driDijKUHROZDyYFggJu1KYLnl7i6cFHIC6rvRivX44rbfx9RDnMUh
# HPlOR88HY87Ow7a5cuGlDJV6z1f/125np2xE6bNz+h4cqE6+TdlWtT7/YzTyDq8=
# SIG # End signature block
