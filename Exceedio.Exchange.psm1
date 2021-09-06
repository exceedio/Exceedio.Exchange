function Connect-ExceedioExchangeOnline {
    [CmdletBinding()]
    param (
        [Parameter()]
        [String]
        $UserPrincipalName,
        [Parameter()]
        [String]
        $DelegatedOrganization
    )
    Connect-ExchangeOnline -UserPrincipalName $UserPrincipalName -DelegatedOrganization $DelegatedOrganization
}

function Get-ExceedioSafeLinksPolicy {
    $policy = Get-SafeLinksPolicy -Identity Default
    if (-not $policy) {
        Write-Warning "No Safe Links named 'Default' exists"
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
    $policy = Get-SafeAttachmentPolicy -Identity Default
    if (-not $policy) {
        Write-Warning "No Safe Links named 'Default' exists"
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
    $policy = New-SafeAttachmentPolicy `
        -Name "$Name" `
        -Enable $true `
        -Redirect $false `
        -Action DynamicDelivery `
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