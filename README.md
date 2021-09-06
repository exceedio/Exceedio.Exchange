# Exceedio Exchange PowerShell Module
 
This module contains cmdlets for standardizing the configuration of Exchange Online and related policies including Microsoft Defender for Office 365.

## Installation

Run the following command in an elevated PowerShell session to install the module:

```powershell
Install-Module -Name Exceedio.Exchange
```

This module runs on Windows PowerShell with [.NET Framework 4.7.2](https://dotnet.microsoft.com/download/dotnet-framework-runtime) or greater,
or [the latest version of PowerShell 7](https://github.com/PowerShell/PowerShell/releases/latest).

If you have an earlier version of the Exceedio Exchange PowerShell module installed from the PowerShell Gallery and would like to update to the latest version, run the following commands in an elevated PowerShell session:

```powershell
Update-Module -Name Exceedio.Exchange
```

`Update-Module` installs the new version side-by-side with previous versions. It does not uninstall the previous versions.

## Usage

### Connect to Exchange Online

To connect to Exchange Online, use the `Connect-ExceedioExchangeOnline` cmdlet:

```powershell
Connect-ExceedioExchangeOnline -UserPrincipalName username@myorganization.com -DelegatedOrganization contoso.com
```

### Listing Microsoft Defender for Office 365 SafeLinks policies

```powershell
Get-ExceedioSafeLinksPolicy
```

### Creating a new Microsoft Defender for Office 365 SafeLinks policy

To create a new policy using the name of 'Default':

```powershell
New-ExceedioSafeLinksPolicy
```

To create a new policy using a custom name:

```powershell
New-ExceedioSafeLinksPolicy -Name MyCustomPolicyName
```
