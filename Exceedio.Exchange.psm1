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
    Write-Output ("[*] Name is 'Default'         : {0}" -f ($policy.Name -eq 'Default' ? "OK" : "ERR"))
    Write-Output ("[*] Policy enabled            : {0}" -f ($policy.IsEnabled ? "OK" : "ERR"))
    Write-Output ("[*] Links are scanned         : {0}" -f ($policy.ScanUrls ? "OK" : "ERR"))
    Write-Output ("[*] Internal senders excluded : {0}" -f (-not $policy.EnableForInternalSenders ? "OK" : "ERR"))
}

function New-ExceedioSafeLinksPolicy {
    [CmdletBinding()]
    param (
        [Parameter()]
        [String]
        $Name = 'Default'
    )
    if (Get-SafeLinksPolicy -Identity $Name) {
        Write-Warning "A Safe Links policy named '$Name' already exists"
        return
    }
    New-SafeLinksPolicy `
        -Name "$Name" `
        -DeliverMessagesAfterScan $true `
        -DoNotAllowClickThrough $false `
        -DoNotTrackUserClicks $false `
        -EnableForInternalSenders $false `
        -EnableOrganizationBranding $false `
        -EnableSafeLinksForTeams $true `
        -IsEnabled $true `
        -ScanUrls $true
}
