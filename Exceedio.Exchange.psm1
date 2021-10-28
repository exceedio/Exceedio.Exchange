function Connect-ExceedioExchangeOnline {
    <#
    .SYNOPSIS
    Connects to Exchange Online.
    .PARAMETER UserPrincipalName
    Username in username@contoso.com format.
    .PARAMETER DelegatedOrganization
    Domain name in contoso.com format.
    .EXAMPLE
    Connect-ExceedioExchangeOnline -UserPrincipalName alice@contoso.com -DelegatedOrganization fabrikam.com
    .NOTES
    This is a helper function for Connect-ExchangeOnline which is part of the Exchange Online PowerShell V2
    module. See https://docs.microsoft.com/en-us/powershell/module/exchange/connect-exchangeonline?view=exchange-ps
    for details about that function.
    #>
    [CmdletBinding()]
    param (
        [Parameter()]
        [String]
        $UserPrincipalName,
        [Parameter()]
        [String]
        $DelegatedOrganization
    )
    $module = Get-InstalledModule -Name ExchangeOnlineManagement
    if ($null -eq $module -or $module.Version -lt '2.0.5') {
        Write-Warning "Module ExchangeOnlineManagement doesn't exist or is out of date; Install-Module ExchangeOnlineManagement -AllowClobber -Force"
        return
    }
    Connect-ExchangeOnline -UserPrincipalName $UserPrincipalName -DelegatedOrganization $DelegatedOrganization
}

function Connect-ExceedioIPPSSession {
    <#
    .SYNOPSIS
    Use the Connect-ExceedioIPPSSession cmdlet in the Exchange Online PowerShell V2 module to connect to
    Security & Compliance Center PowerShell or standalone Exchange Online Protection PowerShell using modern
    authentication. The cmdlet works for MFA or non-MFA enabled accounts.
    .PARAMETER UserPrincipalName
    Username in username@contoso.com format.
    .PARAMETER DelegatedOrganization
    Domain name in contoso.com format.
    .EXAMPLE
    Connect-ExceedioIPPSSession -UserPrincipalName alice@contoso.com -DelegatedOrganization fabrikam.com
    .NOTES
    This is a helper function for Connect-IPPSSession which is part of the Exchange Online PowerShell V2
    module. See https://docs.microsoft.com/en-us/powershell/module/exchange/connect-ippssession?view=exchange-ps
    for details about that function.
    #>
    [CmdletBinding()]
    param (
        [Parameter()]
        [String]
        $UserPrincipalName,
        [Parameter()]
        [String]
        $DelegatedOrganization
    )
    $module = Get-InstalledModule -Name ExchangeOnlineManagement
    if ($null -eq $module -or $module.Version -lt '2.0.5') {
        Write-Warning "Module ExchangeOnlineManagement doesn't exist or is out of date; Install-Module ExchangeOnlineManagement -AllowClobber -Force"
        return
    }
    Connect-IPPSSession -UserPrincipalName $UserPrincipalName -DelegatedOrganization $DelegatedOrganization
}

function Get-ExceedioSafeLinksPolicy {
    <#
    .SYNOPSIS
    Retrieves and audits the default Safe Links policy and lists the recipient(s) and/or recipient domain(s)
    that the policy applies to.
    .EXAMPLE
    Get-ExceedioSafeLinksPolicy
    .NOTES
    Use Get-SafeLinksPolicy from the Exchange Online PowerShell V2 module to see all details for a specific
    Safe Links policy.
    #>
    $policy = Get-SafeLinksPolicy -Identity Default
    if (-not $policy) {
        Write-Warning "No Safe Links policy named 'Default' exists"
        return
    }
    $rule = $policy | Get-SafeLinksRule
    Write-Output ("[*] Name is 'Default'             : {0}" -f ($policy.Name -eq 'Default' ? "OK" : "ERR"))
    Write-Output ("[*] Policy enabled                : {0}" -f ($policy.IsEnabled ? "OK" : "ERR"))
    Write-Output ("[*] Email links are scanned       : {0}" -f ($policy.ScanUrls ? "OK" : "ERR"))
    Write-Output ("[*] Email scanned before delivery : {0}" -f ($policy.DeliverMessageAfterScan ? "OK" : "ERR"))
    Write-Output ("[*] Teams links are scanned       : {0}" -f ($policy.EnableSafeLinksForTeams ? "OK" : "ERR"))
    Write-Output ("[*] Click through is disabled     : {0}" -f ($policy.DoNotAllowClickThrough ? "OK" : "ERR"))
    Write-Output ("[*] Clicks are tracked            : {0}" -f (-not $policy.DoNotTrackUserClicks ? "OK" : "ERR"))
    Write-Output ("[*] Internal senders excluded     : {0}" -f (-not $policy.EnableForInternalSenders ? "OK" : "ERR"))
    Write-Output ("[*] No special branding           : {0}" -f (-not $policy.EnableOrganizationBranding ? "OK" : "ERR"))
    Write-Output ("[*] Recipient address(es)         : {0}" -f $rule.SentTo)
    Write-Output ("[*] Recipient domain(s)           : {0}" -f $rule.RecipientDomainIs)
}

function New-ExceedioSafeLinksPolicy {
    <#
    .SYNOPSIS
    Creates a standard Safe Links policy and applies it to recipient(s) or recipient domain(s).
    .PARAMETER Name
    The name of the policy. Defaults to 'Default'
    .PARAMETER Users
    Comma-separated list of recipients that the policy applies to.
    .PARAMETER Users
    Comma-separated list of domain names that the policy applies to.
    .EXAMPLE
    New-ExceedioSafeLinksPolicy -Users pilotuser1@fabrikam.com,pilotuser2@fabrikam.com
    .EXAMPLE
    New-ExceedioSafeLinksPolicy -Domains fabrikam.com
    .NOTES
    Running this after the first time will overwrite the existing policy with the same name. Normally
    you would run this first to set up a list of pilot users and then run it again at the end of the
    pilot to apply to the entire domain.
    #>
    [CmdletBinding()]
    param (
        [Parameter()]
        [String]
        $Name = 'Default',
        [Parameter()]
        [String[]]
        $Users,
        [Parameter()]
        [String[]]
        $Domains
    )
    if (-not $Users -and -not $Domains) {
        Write-Warning "You must specify either -Users or -Domains; both cannot be empty"
        return
    }
    if (Get-SafeLinksPolicy -Identity $Name -ErrorAction SilentlyContinue) {
        Write-Warning "A policy named '$Name' exists"
        Write-Output "Do you want to overwrite the existing policy '$Name' with a new policy?"
        Write-Host '[Y] Yes  [N] No (Default is "N"): ' -NoNewline
        $answer = $Host.UI.RawUI.ReadKey()
        if ($answer.Character -ine 'Y') {
            return
        } else {
            Write-Output ""
            Write-Output "Removing existing policy..."
            Remove-SafeLinksRule -Identity "$Name" -Confirm:$false
            Remove-SafeLinksPolicy -Identity "$Name" -Confirm:$false
        }
    }
    $policy = New-SafeLinksPolicy `
        -Name "$Name" `
        -DeliverMessageAfterScan $true `
        -DoNotAllowClickThrough $true `
        -DoNotTrackUserClicks $false `
        -EnableForInternalSenders $false `
        -EnableOrganizationBranding $false `
        -EnableSafeLinksForTeams $true `
        -IsEnabled $true `
        -ScanUrls $true
    if ($policy -and $Users) {
        New-SafeLinksRule `
            -Name "$Name" `
            -SafeLinksPolicy "$Name" `
            -SentTo $Users `
            | Out-Null
    } elseif ($policy -and $Domains) {
        New-SafeLinksRule `
            -Name "$Name" `
            -SafeLinksPolicy "$Name" `
            -RecipientDomainIs $Domains `
            | Out-Null
    }
    Write-Output "Policy '$Name' successfully created; Use Get-ExceedioSafeLinksPolicy to audit"
}

function Get-ExceedioSafeAttachmentPolicy {
    <#
    .SYNOPSIS
    Retrieves and audits the default Safe Attachment policy and lists the recipient(s) and/or recipient domain(s)
    that the policy applies to.
    .EXAMPLE
    Get-ExceedioSafeAttachmentPolicy
    .NOTES
    Use Get-SafeAttachmentPolicy from the Exchange Online PowerShell V2 module to see all details for a specific
    Safe Attachment policy.
    #>
    $policy = Get-SafeAttachmentPolicy -Identity Default
    if (-not $policy) {
        Write-Warning "No Safe Attachment policy named 'Default' exists"
        return
    }
    $rule = $policy | Get-SafeAttachmentRule
    Write-Output ("[*] Name is 'Default'             : {0}" -f ($policy.Name -eq 'Default' ? "OK" : "ERR"))
    Write-Output ("[*] Policy enabled                : {0}" -f ($policy.Enable ? "OK" : "ERR"))
    Write-Output ("[*] Action is dynamic delivery    : {0}" -f ($policy.Action -eq 'DynamicDelivery' ? "OK" : "ERR"))
    Write-Output ("[*] Scan timeout is 30            : {0}" -f ($policy.ScanTimeout -eq 30 ? "OK" : "ERR"))
    Write-Output ("[*] Operation mode is Delay       : {0}" -f ($policy.OperationMode -eq 'Delay' ? "OK" : "ERR"))
    Write-Output ("[*] Action on error is true       : {0}" -f ($policy.ActionOnError ? "OK" : "ERR"))
    Write-Output ("[*] Redirect is false             : {0}" -f (-not $policy.Redirect ? "OK" : "ERR"))
    Write-Output ("[*] Recipient address(es)         : {0}" -f $rule.SentTo)
    Write-Output ("[*] Recipient domain(s)           : {0}" -f $rule.RecipientDomainIs)
}

function New-ExceedioSafeAttachmentPolicy {
    <#
    .SYNOPSIS
    Creates a standard Safe Attachment policy and applies it to recipient(s) or recipient domain(s).
    .PARAMETER Name
    The name of the policy. Defaults to 'Default'
    .PARAMETER PrimaryDomain
    The primary domain name that the policy applies to (e.g. contoso.com). This is used when determining
    where to redirect mail that was found to contain malicious attachments and is required.
    .PARAMETER Users
    Comma-separated list of recipients that the policy applies to.
    .PARAMETER Domains
    Comma-separated list of domain names that the policy applies to.
    .EXAMPLE
    New-ExceedioSafeAttachmentPolicy -PrimaryDomain fabrikam.com -Users pilotuser1@fabrikam.com,pilotuser2@fabrikam.com
    .EXAMPLE
    New-ExceedioSafeAttachmentPolicy -PrimaryDomain fabrikam.com -Domains fabrikam.com
    .NOTES
    Running this after the first time will overwrite the existing policy with the same name. Normally
    you would run this first to set up a list of pilot users and then run it again at the end of the
    pilot to apply to the entire domain.
    #>
    [CmdletBinding()]
    param (
        [Parameter()]
        [String]
        $Name = 'Default',
        [Parameter(Mandatory=$true)]
        [String]
        $PrimaryDomain,
        [Parameter()]
        [String[]]
        $Users,
        [Parameter()]
        [String[]]
        $Domains
    )
    if (-not $Users -and -not $Domains) {
        Write-Warning "You must specify either -Users or -Domains; both cannot be empty"
        return
    }
    if (Get-SafeAttachmentPolicy -Identity $Name -ErrorAction SilentlyContinue) {
        Write-Warning "A policy named '$Name' exists"
        Write-Output "Do you want to overwrite the existing policy '$Name' with a new policy?"
        Write-Host '[Y] Yes  [N] No (Default is "N"): ' -NoNewline
        $answer = $Host.UI.RawUI.ReadKey()
        if ($answer.Character -ine 'Y') {
            return
        } else {
            Write-Output ""
            Write-Output "Removing existing policy..."
            Remove-SafeAttachmentRule -Identity "$Name" -Confirm:$false
            Remove-SafeAttachmentPolicy -Identity "$Name" -Confirm:$false
        }
    }
    $redirectAddress = "blockedemail@$PrimaryDomain"
    $redirectMailbox = Get-EXOMailbox $redirectAddress -ErrorAction SilentlyContinue
    if (-not $redirectMailbox) {
        Write-Output "Creating shared mailbox $redirectAddress..."
        New-Mailbox -Name "Blocked Email" -DisplayName "Blocked Email" -Alias blockedemail -Shared
    } else {
        Write-Output "Mailbox $redirectAddress already exists; skipping creation of shared mailbox to hold blocked email"
    }
    $policy = New-SafeAttachmentPolicy `
        -Name "$Name" `
        -Enable $true `
        -Action Block `
        -Redirect $true `
        -RedirectAddress $redirectAddress `
        -ActionOnError $true
    if ($policy -and $Users) {
        New-SafeAttachmentRule `
            -Name "$Name" `
            -SafeAttachmentPolicy "$Name" `
            -SentTo $Users `
            | Out-Null
    } elseif ($policy -and $Domains) {
        New-SafeAttachmentRule `
            -Name "$Name" `
            -SafeAttachmentPolicy "$Name" `
            -RecipientDomainIs $Domains `
            | Out-Null
    }
    Write-Output "Policy '$Name' successfully created; Use Get-ExceedioSafeAttachmentPolicy to audit"
}

function New-ExceedioPhishSimOverridePolicy {
    <#
    .SYNOPSIS
    Creates a standard phish sim override policy to override phishing simulations. The parameter
    defaults are appropriate for allowing phishing simulations from KnowBe4.
    .PARAMETER PolicyName
    The name of the policy. Defaults to 'PhishSimOverridePolicy' and should not be changed.
    .PARAMETER RuleName
    The name of the policy. Defaults to 'PhishSimOverrideRule' and should not be changed.
    .PARAMETER SenderDomainIs
    Comma-separated list of domain names that the policy applies to.
    .PARAMETER SenderIpRanges
    Comma-separated list of IP addresses or IP address CIDR blocks that the policy applies to.
    .EXAMPLE
    New-ExceedioPhishSimOverridePolicy
    .EXAMPLE
    New-ExceedioPhishSimOverridePolicy -SenderDomainIs somedomain.com -SenderIpRanges 8.8.8.8,8.8.4.4
    .NOTES
    The documentation for New-PhishSimOverridePolicy and New-PhishSimOverrideRule state that the
    Name parameter for both have no effect and the names will always be PhishSimOverridePolicy and
    PhishSimOverrideRule respectively. The parameters are included for completeness but should not
    be overridden.
    See https://docs.microsoft.com/en-us/microsoft-365/security/office-365-security/configure-advanced-delivery
    for more information.
    #>
    [CmdletBinding()]
    param (
        [Parameter()]
        [String]
        $PolicyName = 'PhishSimOverridePolicy',
        [Parameter()]
        [String]
        $RuleName = 'PhishSimOverrideRule',
        [Parameter()]
        [String[]]
        $SenderDomainIs = 'psm.knowbe4.com',
        [Parameter()]
        [String[]]
        $SenderIpRanges = @('147.160.167.0/26','23.21.109.197','23.21.109.212')
    )

    New-PhishSimOverridePolicy `
        -Name $PolicyName `
        -Enabled $true
    
    New-PhishSimOverrideRule `
        -Name $RuleName `
        -Policy $PolicyName `
        -SenderDomainIs $SenderDomainIs `
        -SenderIpRanges $SenderIpRanges
}