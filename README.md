# Update-NPSCert

A PowerShell utility to automate the update of server certificates in Microsoft Network Policy Server (NPS) policies.

## Overview

Updating the certificate used for PEAP or EAP-TLS in NPS normally requires manual clicks through the MMC snap-in for every policy. `Update-NPSCert` automates this by:
1. Exporting the current NPS configuration to XML.
2. Replacing the old certificate thumbprints within the `msEAPConfiguration` blocks.
3. Re-importing the modified configuration.

This is particularly useful for automated certificate renewals (e.g., via Let's Encrypt).

## Features

- **Smart Selection**: Automatically finds the newest valid certificate matching a Subject or Issuer regex.
- **Safety First**: Creates a timestamped backup of your configuration before making changes.
- **Dry Run**: Use `-WhatIf` to see which certificates and policies would be affected without applying changes.
- **Automation Ready**: Fully supports non-interactive execution for scheduled tasks or ACME hooks.

## Prerequisites

- **OS**: Windows Server 2012 or later (requires `Export-NpsConfiguration` and `Import-NpsConfiguration` cmdlets).
- **Permissions**: Must be run from an Elevated (Administrator) PowerShell prompt.
- **Certificates**: The script looks for certificates in the `Cert:\LocalMachine\My` (Personal) store.

## Usage

### 1. Preview changes (Dry Run)
Find the newest certificate matching "nps.domain.com" and show what would happen:
```powershell
.\Update-NPSCert.ps1 -SubjectRegex 'CN=nps\.domain\.com' -WhatIf
```

### 2. Update and Apply
Find the certificate, update the XML, import it back, and restart the NPS service:
```powershell
.\Update-NPSCert.ps1 -SubjectRegex 'CN=nps\.domain\.com' -ImportConfig -RestartIAS
```

### 3. Manual Selection
Target a specific certificate by its thumbprint, import it, but don't restart the NPS service:
```powershell
.\Update-NPSCert.ps1 -CertThumbprint 'A1B2C3D4E5F6G7H8I9J0K1L2M3N4O5P6Q7R8S9T0' -ImportConfig
```

## Automation (Win-ACME / Simple-ACME)

This script is designed to be called as a post-renewal script by ACME clients like **Win-ACME (Simple-ACME)**. When configured as an installation step, you can pass the new certificate's thumbprint directly.

**Example paramater call for Win-ACME (Simple-ACME):**
```powershell
-CertThumbprint {CertThumbprint} -ImportConfig -RestartIAS -Confirm:$false
```

*Note: The `{CertThumbprint}` placeholder is automatically replaced by Win-ACME (Simple-ACME) during execution.*

## Parameters

| Parameter | Description |
| :--- | :--- |
| `-CertThumbprint` | Manually specify the 40-character hex thumbprint of the certificate to use. |
| `-SubjectRegex` | A regex pattern to match the Certificate Subject (e.g., 'CN=server01'). |
| `-IssuerRegex` | A regex pattern to match the Certificate Issuer. |
| `-ImportConfig` | Switch. If present, the script will import the modified XML back into NPS. |
| `-RestartIAS` | Switch. If present, restarts the 'Network Policy Server' (IAS) service after import. |
| `-WorkingFolder` | Directory for logs and XML backups (defaults to script directory). |
| `-Confirm:$false` | Standard PowerShell parameter to suppress confirmation prompts. |

## How it Works

The script targets the `msEAPConfiguration` XML nodes. These nodes contain a hex-encoded configuration blob. The script identifies the 40-character thumbprint within that blob (typically starting at offset 72) and replaces it with the new certificate's thumbprint, ensuring the NPS policy correctly points to the new SSL/TLS certificate.

## Troubleshooting

- **Logs**: Detailed activity is logged to `NpsCertUpdate.log` in the working directory (or specific `-LogFile` path).
- **Permissions**: If the script fails with "Access Denied," ensure you are running PowerShell as Administrator.
- **No nodes found**: If the script reports "No msEAPConfiguration nodes found," verify that your Network Policies are actually configured to use EAP (PEAP or EAP-TLS).

## License

This project is licensed under the [MIT License](LICENSE).
