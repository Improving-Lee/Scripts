<#

.SYNOPSIS

    Add neccessary firewall rules for Teams based on user.

.DESCRIPTION

    Teams does not natively allow specific functions through the firewall that apply to user settings.  This mostly impacts users
    when they attempt to use the calling capabilities and a firewall prompt is displayed.  Without administrative permissions, 
    standard users are unable to udpate the firewall with the necessary rules to allow Teams functionality.

    This script adds the necessary firewall rules that will account for the Teams executable in the user
    profile APPDATA (common install) and the system PROGRAMDATA directory if they exist.


.NOTES

    Author:     Christopher Lee
    Compnay:    ProSource IT Consulting, Inc. (dba Improving, Improving-Cleveland)
    Date:       May 8, 2020

    DISCLAIMER:  This script is provided "as-is" and is not supported under any agreement or contract.  This script is provided without warranty
    of any kind.  In no event shall ProSource IT Consulting, Inc., its authors, or anyone else involved in the creation, production, or
    distribution of this script be liable for damages whatsoever arising from the use of or inability to use this script.

    Versions:
    1.0     05-08-20 Initial script development ready for production use.
    1.1     05-11-20 Updated to remove existing firewall rules if present and account for SYSTEM run context.
#>

#========================================================================
#region VARIABLES

#Log file path directory.
$logPath = "C:\IntuneScripts\Logs"

# Script status to return to Intune.
$status = $true

#endregion
#========================================================================

#========================================================================
#region FUNCTIONS

# Logging function to write log to user app data temp directory.
Function Write-Log {
    [CmdletBinding()]
    param(
        [Parameter()]
        [ValidateNotNullOrEmpty()]
        [String]$Message,

        [Parameter()]
        [ValidateNotNullOrEmpty()]
        [ValidateSet('Information','Warning','Error')]
        [String]$Severity = 'Information'
    )

    [PSCustomObject]@{  
        Time  = (Get-Date -f g)
        Message = $Message
        Severity = $Severity    
    } | Export-Csv -Path "$logPath\TeamsFirewallScriptLog.csv" -Append -NoTypeInformation

    Switch ($Severity) {
        'Information'   {Write-Host $Message}
        'Warning'       {Write-Host $Message -ForegroundColor Yellow}
        'Error'         {Write-Host $Message -ForegroundColor Red}
    }
}

#endregion
#========================================================================

#========================================================================
#region MAIN

# Create log directory if it does not exist.
If (!(Test-Path $logPath)) {
    New-Item -Path $logPath -ItemType Directory -Force | Out-Null
    Write-Log -Message "Created log directory path $logPath." -Severity Information
}

# Get username and profile of logged in user.  Because script may run under SYSTEM context, standard $env: variables do not work.
$Error.Clear()
Try {
    $username= ((Get-WmiObject -Class Win32_ComputerSystem | Select Username -ExpandProperty Username) -split "\\")[1]
    Write-Log -Message "Successfully retrieved currently logged in user under SYSTEM context for $username." -Severity Information

    $userProf = Get-ChildItem (Join-Path -Path $env:SystemDrive -ChildPath 'Users') | Where-Object Name -Like "$username*" | Select -First 1
    Write-Log -Message "Successfully found user profile for $username." -Severity Information
} Catch {
    Write-Log -Message "Failed WMI query to get logged in user or user profile." -Severity Error
    Write-Log -Message $Error -Severity Error
    Write-Log -Message "Exiting script..." -Severity Warning
    Exit
}

# Generate Teams executable path for user profile directory.
$profPath = Join-Path -Path $userProf.FullName -ChildPath "\AppData\Local\Microsoft\Teams\Current\Teams.exe"
Write-Log -Message "Teams profile executable path = $profPath." -Severity Information

#Generate Teams executable path for programdata directory.
$progPath = Join-Path -Path $env:ProgramData -ChildPath "$($userProf.Name)\Microsoft\Teams\Current\Teams.exe"
Write-Log -Message "Teams ProgramData executable path = $progPath." -Severity Information

# Generate rule name to use for firewall rules.
$ruleName = "Teams.exe for $($userProf.Name)"
Write-Log = -Message "Teams rule name = $ruleName" -Severity Information

# Update firewall Teams rule with user profile executable.
If (Test-Path $profPath) {
    
    # Remove existing rule for Teams profile path if it exists.
    If (Get-NetFirewallApplicationFilter -Program $profPath -ErrorAction SilentlyContinue) {
        Write-Log -Message "Existing rule(s) found for $profPath." -Severity Information
        Write-Log -Message "Removing existing rule(s)..." -Severity Information
        
        # Remove existing firewall rule.
        $Error.Clear()
        Try {
            Get-NetFirewallApplicationFilter -Program $profPath -ErrorAction SilentlyContinue | Remove-NetFirewallRule -ErrorAction SilentlyContinue
            Write-Log -Message "Existing rule(s) removed for $profPath." -Severity Information
        } Catch {
            Write-Log -Message "Failed to remove existing rule(s) for $profPath." -Severity Error
            Write-Log -Message $Error -Severity Error
            Write-Log -Message "New rules may not apply as expected." -Severity Warning
        }
    } Else {
        Write-Log -Message "No existing rules for $profPath found." -Severity Information
    }

    # Create new rules for profile path Teams.exe.
    $Error.Clear()
    Try {
        "UDP","TCP" | ForEach-Object { New-NetFirewallRule -DisplayName $ruleName -Direction Inbound -Profile Any -Program $profPath -Action Allow -Protocol $_ }
        Write-Log -Message "Created firewall rules for user profile Teams executable." -Severity Information
    } Catch {
        Write-Log -Message "Failed to create new firwall rules for $profPath." -Severity Error
        Write-Log -Message $Error -Severity Error
        $status = $false
    }
} Else {
    Write-Log -Message "Teams executable not found for $progPath." -Severity Warning
}



#Update firewall Teams rule with the programdata executable.
If (Test-Path $progPath) {

    # Remove existing rule for Teams programdata path if it exists.
    If (Get-NetFirewallApplicationFilter -Program $progPath -ErrorAction SilentlyContinue) {
        Write-Log -Message "Existing rule(s) found for $progPath." -Severity Information
        Write-Log -Message "Removing existing rule(s)..." -Severity Information
        
        # Remove existing firewall rule.
        $Error.Clear()
        Try {
            Get-NetFirewallApplicationFilter -Program $progPath -ErrorAction SilentlyContinue | Remove-NetFirewallRule -ErrorAction SilentlyContinue
            Write-Log -Message "Existing rule(s) removed for $progPath." -Severity Information
        } Catch {
            Write-Log -Message "Failed to remove existing rule(s) for $progPath." -Severity Error
            Write-Log -Message "New rules may not apply as expected." -Severity Warning
        }
    } Else {
        Write-Log -Message "No existing rules for $progPath found." -Severity Informtion
    }

    # Create new rules for programdata path Teams.exe.
    $Error.Clear()
    Try {
        "UDP","TCP" | ForEach-Object { New-NetFirewallRule -DisplayName $ruleName -Direction Inbound -Profile Any -Program $progPath -Action Allow -Protocol $_ }
        Write-Log -Message "Created firewall rules for user programdata Teams executable." -Severity Information
    } Catch {
        Write-Log -Message "Failed to create new firwall rules for $progPath." -Severity Error
        Write-Log -Message $Error -Severity Error
        $status = $false
    }
} Else {
    Write-Log -Message "Teams executable not found for $progPath." -Severity Warning
}

If (!($status)) {
    Write-Log -Message "Errors encountered prevented desired end-state." -Severity Warning
    Stop-Transcript
    Throw "Errors encountered prevented desired end-state."
}

Write-Log -Message "Script execution complete." -Severity Information

#endregion
#========================================================================
