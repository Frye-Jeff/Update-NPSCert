<#
 .SYNOPSIS
  Updates NPS Network Policies to use the newest/desired server certificate by:
  Exporting NPS config -> modifying exported XML -> importing back.


.DESCRIPTION
  - Detects a "desired" certificate (newest matching criteria) OR uses a provided thumbprint.
  - Exports current NPS config to a backup XML (Export-NpsConfiguration).
  - Modifies msEAPConfiguration nodes in the exported XML by replacing embedded cert thumbprints.
  - Imports modified XML back into NPS (Import-NpsConfiguration) (overwrites existing config).
  - Restarts IAS service.

.NOTES
  Requires: Windows Server 2012+ for Export-NpsConfiguration/Import-NpsConfiguration cmdlets.
  Run as Administrator.
  The msEAPConfiguration thumbprint position/format can vary by EAP type and policy.
  This script implements the commonly used Substring(72,40) replacement, and includes
  validation and a fallback heuristic.

.PARAMETER CertThumbprint
  If provided, uses this certificate thumbprint as the desired certificate.

.PARAMETER SubjectRegex
  If provided, uses regex to match certificate Subject (CN=...) when auto-selecting desired certificate.

.PARAMETER IssuerRegex
  If provided, uses regex to match certificate Issuer when auto-selecting.

.PARAMETER WorkingFolder
  Optional: Folder to store exports/backups/logs. Default: Running directory of the Script

.PARAMETER LogFile
  Optional: Log file. Default: WorkingFolder\NpsCertUpdate-<timestamp>.log

.PARAMETER ThumbprintIgnorePrivateKey
  Optional : For thumbprint matching only; when specified will not check if the selected certificate has a private key. Useful for testing. 

.PARAMETER RestartIAS
  Optional : When specified together with -ImportConfig, restarts the IAS (NPS) service after a successful import.

.PARAMETER ImportConfig
  Optional : When specified, imports the modified NPS configuration XML back into NPS using Import-NpsConfiguration.

.PARAMETER WhatIf
  Shows what would change without importing/restarting.

.EXAMPLE
  .\Update-NpsPoliciesCertificate-Option2.ps1 -SubjectRegex 'CN=nps(\.|$)'

.EXAMPLE
  .\Update-NpsPoliciesCertificate-Option2.ps1 -CertThumbprint 'A1B2C3D4E5F6...' -WhatIf
#> 

[CmdletBinding(SupportsShouldProcess = $true, ConfirmImpact = 'High')]
param
(
	[Parameter(Mandatory = $false)]
	[ValidatePattern('^[a-fA-F0-9]{40}$')]
	[string]$CertThumbprint,

	[Parameter(Mandatory = $false)]
	[string]$SubjectRegex = '',

	[Parameter(Mandatory = $false)]
	[string]$IssuerRegex = '',

	[Parameter(Mandatory = $false)]
	[string]$WorkingFolder = $PSScriptRoot,

	[Parameter(Mandatory = $false)]
	[string]$LogFile,

	[Parameter(Mandatory = $false)]
	[switch]$ThumbprintIgnorePrivateKey,

	[Parameter(Mandatory = $false)]
	[switch]$RestartIas,

	[Parameter(Mandatory = $false)]
	[switch]$ImportConfig
)



Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
#----------------------------------------------------------------------------------------------------------------------------------------------------------
# Start Region Helper Functions
#----------------------------------------------------------------------------------------------------------------------------------------------------------
Function Confirm-Administrator
{
	#Script needs to run as Administrator, check this before continuing.
	[CmdletBinding()]
	param()

	$CurrentIdentity = [Security.Principal.WindowsIdentity]::GetCurrent()
	$Principal = [Security.Principal.WindowsPrincipal]::new($CurrentIdentity)

	IF (-not $Principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator))
	{
		throw 'This script must be run as Administrator.'
	}
}

Function Write-Log
{
	[CmdletBinding()]
	param
	(
		[Parameter(Mandatory = $true)]
		[string]$Message,

		[Parameter(Mandatory = $false)]
		[ValidateSet('INFO', 'WARN', 'ERROR', 'DEBUG')]
		[string]$Level = 'INFO'
	)

	$TimeStamp = Get-Date -Format 'yyyy-MM-dd HH:mm:ss'
	$Line = "[${TimeStamp}][$Level] $Message"

	Write-Host $Line

	IF ($script:LogFile)
	{
		Add-Content -Path $script:LogFile -Value $Line
	}
}
function Get-DesiredCertificate
{
	[CmdletBinding()]
	param
	(
		[Parameter(Mandatory = $false)]
		[string]$Thumbprint,

		[Parameter(Mandatory = $false)]
		[string]$SubjectRegex,

		[Parameter(Mandatory = $false)]
		[string]$IssuerRegex
	)

	Write-Log -Message 'Searching for candidate certificates in Cert:\LocalMachine\My.' -Level 'DEBUG'

	#Check by Thumbprint first
	IF ($Thumbprint)
	{
		Write-Log -Message "Looking up certificate by thumbprint '$Thumbprint'." -Level 'DEBUG'

		$Certificate = Get-Item -Path "Cert:\LocalMachine\My\$Thumbprint" -ErrorAction Stop

		IF (-not $ThumbprintIgnorePrivateKey)
		{
			IF (-not $Certificate.HasPrivateKey)
			{
				Write-Log -Message "Certificate '$Thumbprint' does not have a private key." -Level 'ERROR'
				throw "Certificate '$Thumbprint' does not have a private key."
			}
		}
		Else 
		{
			Write-Log -Message "Private key was not checked." -Level 'DEBUG'
		}

		return $Certificate
	}

	#Get a list of all possible certificates to use
	$Candidates = Get-ChildItem -Path Cert:\LocalMachine\My |
		Where-Object {
			$_.HasPrivateKey -and
			$_.NotAfter -gt (Get-Date)
		}

	# If the Subject Regex was supplied filter for that
	IF ($SubjectRegex)
	{
		Write-host "SubjectRegex"
		$Candidates = $Candidates | Where-Object { $_.Subject -match $SubjectRegex }
	}
	# If the Issuer Regex was supplied filter for that
	IF ($IssuerRegex)
	{
		$Candidates = $Candidates | Where-Object { $_.Issuer -match $IssuerRegex }
	}

	# Of all possible certs, select our desired one
	$Desired = $Candidates |
		Sort-Object -Property NotBefore -Descending |
		Select-Object -First 1

	IF (-not $Desired)
	{
		Write-Log -Message "No eligible certificate found matching the specified criteria." -Level 'ERROR'
		throw 'No eligible certificate found matching the specified criteria.'
	}

	return $Desired
}
Function Set-MsEapConfigThumbprint
{
	[CmdletBinding()]
	param
	(
		[Parameter(Mandatory = $true)]
		[string]$MsEapText,

		[Parameter(Mandatory = $true)]
		[string]$NewThumbprint
	)

	$OldThumbprint = Get-ThumbprintFromMsEapConfig -Text $MsEapText

	#No old thumbprint found, return an object saying the update failed (false)
	IF (-not $OldThumbprint)
	{
		return [pscustomobject]@{
			Updated       = $false
			OldThumbprint = $null
			NewThumbprint = $null
			Text          = $MsEapText
		}
	}

	$UpdatedText = $MsEapText.Replace($OldThumbprint, $NewThumbprint.ToLower())

	return [pscustomobject]@{
		Updated       = $true
		OldThumbprint = $OldThumbprint
		NewThumbprint = $NewThumbprint.ToLower()
		Text          = $UpdatedText
	}
}

Function Get-ThumbprintFromMsEapConfig
{
	[CmdletBinding()]
	param
	(
		[Parameter(Mandatory = $true)]
		[string]$Text
	)

	IF ($Text.Length -ge 112)
	{
		$Candidate = $Text.Substring(72, 40).ToLower()

		# Check the Candidate for being the old Thumbprint is indeed 40 characters of hex
		IF ($Candidate -match '^[a-f0-9]{40}$')
		{
			return $Candidate
		}
	}

	#No match found, lets try an alternative way
	$Match = [regex]::Match($Text.ToLower(), '\b[a-f0-9]{40}\b')

	if ($Match.Success)
	{
		return $Match.Value
	}
	#No match found, return $null
	return $null
}
#----------------------------------------------------------------------------------------------------------------------------------------------------------
#Endregion Helper Functions
#----------------------------------------------------------------------------------------------------------------------------------------------------------


#----------------------------------------------------------------------------------------------------------------------------------------------------------
#Start Region Initialization
#----------------------------------------------------------------------------------------------------------------------------------------------------------
Confirm-Administrator

#Check mandatory cmdlets exist
IF (-not (Get-Command -Name Export-NpsConfiguration -ErrorAction SilentlyContinue) -or
    -not (Get-Command -Name Import-NpsConfiguration -ErrorAction SilentlyContinue))
{
    throw "Export-NpsConfiguration/Import-NpsConfiguration not found. Ensure NPS is installed on Windows Server 2012 or later."
}


#Check to see if "Working" folder exists, if not; create it
If (-not (Test-Path -Path $WorkingFolder))
{
	New-Item -Path $WorkingFolder -ItemType Directory -Force | Out-Null
}

#Check to see if a Log was specified, if not use a logfile in the "Working" folder
IF (-not $PSBoundParameters.ContainsKey('LogFile'))
{
	$script:LogFile = Join-Path -Path $WorkingFolder -ChildPath 'NpsCertUpdate.log'
}
Else
{
	$script:LogFile = $LogFile
}

Write-Log -Message 'Starting NPS certificate update script.' -Level 'INFO'
#----------------------------------------------------------------------------------------------------------------------------------------------------------
# End Region Initialization
#----------------------------------------------------------------------------------------------------------------------------------------------------------

#----------------------------------------------------------------------------------------------------------------------------------------------------------
# Start Region Certificate Selection
#----------------------------------------------------------------------------------------------------------------------------------------------------------
$DesiredCertificate = Get-DesiredCertificate `
	-Thumbprint $CertThumbprint `
	-SubjectRegex $SubjectRegex `
	-IssuerRegex $IssuerRegex

Write-Log -Message ("Using certificate: Subject='{0}', Thumbprint='{1}'" -f $DesiredCertificate.Subject, $DesiredCertificate.Thumbprint) -Level 'INFO'


#----------------------------------------------------------------------------------------------------------------------------------------------------------
# Endregion Certificate Selection
#----------------------------------------------------------------------------------------------------------------------------------------------------------

#----------------------------------------------------------------------------------------------------------------------------------------------------------
# Start Region Export Current Configuration
#----------------------------------------------------------------------------------------------------------------------------------------------------------
$TimeStamp = Get-Date -Format 'yyyyMMdd-HHmmss'
$OriginalExportPath = Join-Path -Path $WorkingFolder -ChildPath "NpsConfig-Original-$TimeStamp.xml"														
$ModifiedExportPath = Join-Path -Path $WorkingFolder -ChildPath "NpsConfig-Modified-$TimeStamp.xml"

Write-Log -Message "Exporting current NPS configuration to '$OriginalExportPath'." -Level 'INFO'
Export-NpsConfiguration -Path $OriginalExportPath																									

# Use .Load() for stability
$NpsConfig = New-Object System.Xml.XmlDocument
$NpsConfig.Load((Resolve-Path $OriginalExportPath).Path)
#----------------------------------------------------------------------------------------------------------------------------------------------------------
# End  Region Export Current Configuration
#----------------------------------------------------------------------------------------------------------------------------------------------------------

#----------------------------------------------------------------------------------------------------------------------------------------------------------
# Start Region Update msEAPConfiguration Thumbprints
#----------------------------------------------------------------------------------------------------------------------------------------------------------
$MsEapNodes = $NpsConfig.SelectNodes('//msEAPConfiguration')

IF (-not $MsEapNodes -or $MsEapNodes.Count -eq 0)
{
	Write-Log -Message 'No msEAPConfiguration nodes found in exported configuration.' -Level 'WARN'
	return
}

$UpdatedNodeCount = 0
$UniqueOldThumbprints = [System.Collections.Generic.HashSet[string]]::new()

ForEach ($Node in $MsEapNodes)
{
	$RawText = $Node.'#text'

	IF (-not $RawText)
	{
		#No XML Record found
		continue
	}

	$Result = Set-MsEapConfigThumbprint -MsEapText $RawText -NewThumbprint $DesiredCertificate.Thumbprint

	IF ($Result.Updated)
	{
		$Node.'#text' = $Result.Text
		$UpdatedNodeCount++

		IF ($Result.OldThumbprint -and -not $UniqueOldThumbprints.Contains($Result.OldThumbprint))
		{
			$null = $UniqueOldThumbprints.Add($Result.OldThumbprint)
		}
	}
}

IF ($UpdatedNodeCount -eq 0)
{
	Write-Log -Message 'No msEAPConfiguration nodes were updated.' -Level 'WARN'
	return
}

Write-Log -Message "Found $UpdatedNodeCount msEAPConfiguration node(s)." -Level 'INFO'

IF ($UniqueOldThumbprints.Count -gt 0)
{
	Write-Log -Message ("Original thumbprints observed: {0}" -f ($UniqueOldThumbprints -join ', ')) -Level 'DEBUG'
}

$NpsConfig.Save($ModifiedExportPath)
Write-Log -Message "Saved modified configuration to '$ModifiedExportPath'." -Level 'INFO'

#----------------------------------------------------------------------------------------------------------------------------------------------------------
# Start Region Import Modified Configuration
#----------------------------------------------------------------------------------------------------------------------------------------------------------
#Import the new config?
IF ($ImportConfig)
{
	IF ($PSCmdlet.ShouldProcess("NPS configuration (import from '$ModifiedExportPath')", 'Import-NpsConfiguration'))
	{
		Write-Log -Message "Importing modified configuration from '$ModifiedExportPath'." -Level 'INFO'
		Import-NpsConfiguration -Path $ModifiedExportPath
	}
}
Else
{
	Write-Log -Message 'ImportConfig is not specified; modified configuration will not be imported.' -Level 'INFO'
}
#----------------------------------------------------------------------------------------------------------------------------------------------------------
# End region Import Modified Configuration
#----------------------------------------------------------------------------------------------------------------------------------------------------------

#----------------------------------------------------------------------------------------------------------------------------------------------------------
# Start Region Optional IAS Service Restart
#----------------------------------------------------------------------------------------------------------------------------------------------------------
#Restart the Network Policy Service?
IF ($RestartIas -and $ImportConfig)
{
	IF ($PSCmdlet.ShouldProcess("IAS (NPS) service", 'Restart-Service'))
	{
		Write-Log -Message 'Restarting IAS (NPS) service.' -Level 'INFO'
		Restart-Service -Name 'IAS' -Force -ErrorAction Stop
	}
}
Else
{
	Write-Log -Message 'RestartIas or ImportConfig is not specified; IAS service will not be restarted.' -Level 'INFO'
}
#----------------------------------------------------------------------------------------------------------------------------------------------------------
# End Region Optional IAS Service Restart
#----------------------------------------------------------------------------------------------------------------------------------------------------------