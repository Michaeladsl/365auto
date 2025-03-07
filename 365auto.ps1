$transcriptFile = "$PSScriptRoot\script_output.log"
Start-Transcript -Path $transcriptFile -Append

function Authenticate-Once {
    Write-Host "Authenticating to Microsoft 365 services..." -ForegroundColor Cyan

    if ([System.Threading.Thread]::CurrentThread.ApartmentState -ne "STA") {
        Write-Host "Restarting in STA mode..." -ForegroundColor Yellow
        Start-Process -FilePath "powershell.exe" -ArgumentList "-STA", "-File", $MyInvocation.MyCommand.Path -Wait
        exit
    }
    
    try {
        Write-Host "Authenticating to Microsoft Teams..." -ForegroundColor Cyan
        Connect-MicrosoftTeams
        Write-Host "Connected to Microsoft Teams." -ForegroundColor Green
    
        Write-Host "Authenticating to Microsoft Graph..." -ForegroundColor Cyan
        Connect-MgGraph -Scopes 'Policy.Read.All, Directory.Read.All, Sites.Read.All, AuditLog.Read.All, OrgSettings-Forms.Read.All, OrgSettings-AppsAndServices.Read.All, PeopleSettings.Read.All, AuditLogsQuery-SharePoint.Read.All, SecurityEvents.Read.All, SecurityActions.Read.All, SecurityBaseline.Read.All' -NoWelcome
        Write-Host "Connected to Microsoft Graph." -ForegroundColor Green
    
        Write-Host "Authenticating to Exchange Online..." -ForegroundColor Cyan
        Connect-ExchangeOnline
        Write-Host "Connected to Exchange Online." -ForegroundColor Green
    
        Write-Host "Authenticating to Security & Compliance Center (IPPS Session)..." -ForegroundColor Cyan
        Connect-IPPSSession
        Write-Host "Connected to Security & Compliance Center." -ForegroundColor Green
    
    } catch {
        Write-Host "Authentication failed:" -ForegroundColor Red
        Write-Host $_.Exception.Message
    }


    Write-Host "All services authenticated successfully!" -ForegroundColor Green
}
Authenticate-Once


$scripts = @(
    @{
        Name = "1.1.3 Amount of Global Admins"
        Type = "Script"
        Logic = {
            try {
                $globalAdminRole = Get-MgDirectoryRole -Filter "RoleTemplateId eq '62e90394-69f5-4237-9190-012177145e10'"
                
                if (-not $globalAdminRole) {
                    Write-Host "Global Admin Role not found. Skipping check." -ForegroundColor Yellow
                    return
                }
    
                $globalAdmins = Get-MgDirectoryRoleMember -DirectoryRoleId $globalAdminRole.Id
                
                $adminCount = $globalAdmins.AdditionalProperties.Count
                Write-Host "*** There are $adminCount Global Administrators assigned." -ForegroundColor Cyan
                Write-Host ""
                Write-Host ""
    
                if ($adminCount -gt 8) {
                    Write-Host "Fail" -ForegroundColor Red
                } else {
                    Write-Host "Pass" -ForegroundColor Green
                }
            } catch {
                Write-Host "Error checking Global Administrators." -ForegroundColor Red
                Write-Host $_.Exception.Message
            }
        }
    },
    @{
        Name = "1.1.4 Admin Licenses"
        Type = "Script"
        Logic = {
            $DirectoryRoles = Get-MgDirectoryRole
            $PrivilegedRoles = $DirectoryRoles | Where-Object { $_.DisplayName -like "*Administrator*" -or $_.DisplayName -eq "Global Reader" }
            $RoleMembers = $PrivilegedRoles | ForEach-Object { Get-MgDirectoryRoleMember -DirectoryRoleId $_.Id } | Select-Object Id -Unique
            $PrivilegedUsers = $RoleMembers | ForEach-Object { Get-MgUser -UserId $_.Id -Property UserPrincipalName, DisplayName, Id }
            $Report = [System.Collections.Generic.List[Object]]::new()
            foreach ($Admin in $PrivilegedUsers) {
                $License = (Get-MgUserLicenseDetail -UserId $Admin.id).SkuPartNumber -join ", "
                $Object = [pscustomobject][ordered]@{
                    DisplayName = $Admin.DisplayName
                    UserPrincipalName = $Admin.UserPrincipalName
                    License = $License
                }
                $Report.Add($Object)
            }
            $Report | Format-Table -AutoSize
        }
    },
    @{
        Name = "1.2.1 Public Groups"
        Type = "Script"
        Logic = {
            Get-MgGroup | where {$_.Visibility -eq "Public"} | select DisplayName, Visibility | Format-Table -AutoSize
            Write-Host ""
            Write-Host ""
            Write-Host "Review" -ForegroundColor DarkYellow
        }
    },
    @{
        Name = "1.2.2 Sign-in to Shared Mailboxes"
        Type = "Script"
        Logic = {
            try {
                Write-Host "Checking sign-in status for Shared Mailboxes..." -ForegroundColor Cyan
                
                $MBX = Get-EXOMailbox -RecipientTypeDetails SharedMailbox
                $SignInData = $MBX | ForEach-Object { 
                    Get-MgUser -UserId $_.ExternalDirectoryObjectId -Property DisplayName, UserPrincipalName, AccountEnabled 
                }
    
                if ($SignInData) {
                    $SignInData | Format-Table DisplayName, UserPrincipalName, AccountEnabled -AutoSize
                    Write-Host ""
                    Write-Host ""
    
                    if ($SignInData | Where-Object { $_.AccountEnabled -eq $true }) {
                        Write-Host "Fail: AccountEnabled is True for shared mailboxes" -ForegroundColor Red
                    } else {
                        Write-Host "Pass" -ForegroundColor Green
                    }
                } else {
                    Write-Host "No data found for Shared Mailboxes." -ForegroundColor Yellow
                    Write-Host "Pass" -ForegroundColor Green
                }
            } catch {
                Write-Host "Error checking sign-in status for Shared Mailboxes." -ForegroundColor Red
                Write-Host $_.Exception.Message
            }
        }
    }
    
    @{
        Name = "1.3.1 Password Expiration Policy"
        Type = "Script"
        Logic = {
            try {
                
                $domains = Get-MgDomain | Select-Object id, PasswordValidityPeriodInDays
                
                if ($domains) {
                    $domains | Format-Table id, PasswordValidityPeriodInDays -AutoSize
                    Write-Host ""
                    Write-Host ""
    
                    if ($domains | Where-Object { $_.PasswordValidityPeriodInDays -lt 365 }) {
                        Write-Host "Fail: Password expiration set" -ForegroundColor Red
                    } else {
                        Write-Host "Pass" -ForegroundColor Green
                    }
                } else {
                    Write-Host "No domain data found." -ForegroundColor Yellow
                    Write-Host "Pass" -ForegroundColor Green
                }
            } catch {
                Write-Host "Error checking Password Expiration Policy." -ForegroundColor Red
                Write-Host $_.Exception.Message
            }
        }
    }
    ,
    @{
        Name = "1.3.2 Idle Session Timeout"
        Type = "Script"
        Logic = {
            try {
    
                $policies = Get-MgIdentityConditionalAccessPolicy | ForEach-Object {
                    if ($_.SessionControls.IdleSessionSignOut -ne $null) {
                        [PSCustomObject]@{
                            Id                   = $_.Id
                            DisplayName          = $_.DisplayName
                            State                = $_.State
                            IsEnabled            = $_.SessionControls.IdleSessionSignOut.IsEnabled
                            SignOutAfterInSecs   = $_.SessionControls.IdleSessionSignOut.SignOutAfterInSeconds
                            WarnAfterInSecs      = $_.SessionControls.IdleSessionSignOut.WarnAfterInSeconds
                        }
                    }
                }
    
                if ($policies) {
                    $policies | Format-Table -AutoSize
                    Write-Host ""
                    Write-Host ""
    
                    if ($policies | Where-Object { $_.SignOutAfterInSecs -eq $null -or $_.SignOutAfterInSecs -lt 3 }) {
                        Write-Host "Fail" -ForegroundColor Red
                    } else {
                        Write-Host "Pass" -ForegroundColor Green
                    }
                } else {
                    Write-Host "No policies found with Idle Session Timeout configured." -ForegroundColor Yellow
                    Write-Host ""
                    Write-Host ""
                    Write-Host "Fail" -ForegroundColor Red
                }
            } catch {
                Write-Host "Error checking Idle Session Timeout." -ForegroundColor Red
                Write-Host $_.Exception.Message
            }
        }
    }
    ,
    @{
        Name = "1.3.3 External Sharing"
        Type = "Script"
        Logic = {
            try {
    
                $sharingPolicy = Get-SharingPolicy -Identity "Default Sharing Policy"
    
                if ($sharingPolicy) {
                    $sharingPolicy | Format-Table -AutoSize
                    Write-Host ""
                    Write-Host ""
    
                    if ($sharingPolicy.Enabled -eq $false) {
                        Write-Host "Pass" -ForegroundColor Green
                    } else {
                        Write-Host "Fail: External calendar sharing enabled" -ForegroundColor Red
                    }
                } else {
                    Write-Host "No External Sharing Policy found." -ForegroundColor Yellow
                    Write-Host "Fail" -ForegroundColor Red
                }
            } catch {
                Write-Host "Error retrieving External Sharing Policy." -ForegroundColor Red
                Write-Host $_.Exception.Message
            }
        }
    },
    @{
        Name = "1.3.4 Apps and Services Settings Check"
        Type = "Script"
        Logic = {
            try {

                $endpoint = "https://graph.microsoft.com/beta/admin/appsAndServices"

                $response = Invoke-MgGraphRequest -Uri $endpoint -Method GET

                Write-Host "Raw API Response:"
                Write-Host ($response | ConvertTo-Json -Depth 10)
                Write-Host ""

                if (-not $response.PSObject.Properties["settings"]) {
                    Write-Host "Fail: API response does not contain 'settings'." -ForegroundColor Red
                    return
                }

                $settings = $response.settings

                Write-Host "Extracted Settings:"
                Write-Host ($settings | ConvertTo-Json -Depth 10)
                Write-Host ""

                $isOfficeStoreEnabled = $settings.isOfficeStoreEnabled
                $isAppAndServicesTrialEnabled = $settings.isAppAndServicesTrialEnabled

                if ($isOfficeStoreEnabled -eq $true -or $isAppAndServicesTrialEnabled -eq $true) {
                    Write-Host "Fail: One or more settings are enabled." -ForegroundColor Red
                    if ($isOfficeStoreEnabled -eq $true) {
                        Write-Host "Fail: Office Store is enabled." -ForegroundColor Red
                    }
                    if ($isAppAndServicesTrialEnabled -eq $true) {
                        Write-Host "Fail: App and Services Trial is enabled." -ForegroundColor Red
                    }
                } else {
                    Write-Host "Pass: Both Office Store and App & Services Trial are disabled." -ForegroundColor Green
                }
            } catch {
                Write-Host "Error retrieving Apps and Services settings." -ForegroundColor Red
                Write-Host $_.Exception.Message
            }
        }
    },
    @{
        Name = "1.3.5 Internal Phishing Protection"
        Type = "Manual"
        Link = "https://admin.microsoft.com/#/Settings/Services/:/Settings/L1/OfficeForms"
        explanation = {
            Verify that internal phishing protection is enabled.
            Scroll down to and verify that 'Add internal phishing protection' is checked
        }
    },
    @{
        Name = "1.3.6 Customer Lockbox"
        Type = "Script"
        Logic = {
            try {
    
                $lockboxConfig = Get-OrganizationConfig | Select-Object CustomerLockBoxEnabled
                $lockboxConfig | Format-Table -AutoSize
                Write-Host ""
                Write-Host ""
    
                if ($lockboxConfig.CustomerLockBoxEnabled -eq $true) {
                    Write-Host "Pass" -ForegroundColor Green
                } elseif ($lockboxConfig.CustomerLockBoxEnabled -eq $false) {
                    Write-Host "Fail: Customer LockBox disabled" -ForegroundColor Red
                } else {
                    Write-Host "Customer Lockbox status could not be determined." -ForegroundColor Yellow
                    Write-Host "Fail" -ForegroundColor Red
                }
    

            } catch {
                Write-Host "Error retrieving Customer Lockbox configuration." -ForegroundColor Red
                Write-Host $_.Exception.Message
                Write-Host "Fail" -ForegroundColor Red
            }
        }
    },
    @{
        Name = "1.3.7 Third Party Storage"
        Type = "Script"
        Logic = {
            try {

                $appId = "c1f33bc0-bdb4-4248-ba9b-096807ddb43e"
                $endpoint = "https://graph.microsoft.com/v1.0/servicePrincipals?`$filter=appId eq '$appId'"

                $response = Invoke-MgGraphRequest -Uri $endpoint -Method GET

                Write-Host ($response | ConvertTo-Json -Depth 10)
                Write-Host ""

                if ($response.value -and $response.value.Count -gt 0) {
                    Write-Host "Fail: The following service principal(s) exist with App ID `${appId}`:" -ForegroundColor Red
                    foreach ($sp in $response.value) {
                        Write-Host "Display Name: $($sp.displayName)" -ForegroundColor Red
                    }
                } else {
                    Write-Host "Pass: No service principal exists with App ID `${appId}`." -ForegroundColor Green
                }
            } catch {
                Write-Host "Error retrieving service principal." -ForegroundColor Red
                Write-Host $_.Exception.Message
            }
        }
    },
    @{
        Name = "1.3.8 Sway Sharing"
        Type = "Manual"
        Link = "https://admin.microsoft.com/#/Settings/Services/:/Settings/L1/Sway"
        explanation = {
            Verify that sway sharing is not allowed.
            Ensure 'Let people in the organization share their sways' is NOT checked
        }

    },
    @{
        Name = "2.1.1 SafeLinks for Office Apps"
        Type = "Script"
        Logic = {
            try {
                $safeLinksPolicies = Get-SafeLinksPolicy | Select-Object Name
    
                if ($safeLinksPolicies.Count -eq 0) {
                    Write-Host "No SafeLinks policies found." -ForegroundColor Yellow
                    Write-Host "Fail" -ForegroundColor Red
                    return
                }
    
                foreach ($policy in $safeLinksPolicies) {
                    try {
                        $policyDetails = Get-SafeLinksPolicy -Identity $policy.Name
    
                        $expectedSettings = @{
                            EnableSafeLinksForEmail     = $true
                            EnableSafeLinksForTeams     = $true
                            EnableSafeLinksForOffice    = $true
                            TrackClicks                 = $true
                            AllowClickThrough           = $false
                            ScanUrls                    = $true
                            EnableForInternalSenders    = $true
                            DeliverMessageAfterScan     = $true
                            DisableUrlRewrite           = $false
                        }
    
                        $allSettingsCorrect = $true
                        Write-Host "`nSafeLinks Policy: $($policy.Name)`n" -ForegroundColor Cyan
    
                        foreach ($key in $expectedSettings.Keys) {
                            $actualValue = $policyDetails.$key
                            $expectedValue = $expectedSettings[$key]
    
                            if ($actualValue -ne $expectedValue) {
                                Write-Host "{$key}: $actualValue" -ForegroundColor Red -NoNewline
                                Write-Host " > desired: $expectedValue" -ForegroundColor Green
                                $allSettingsCorrect = $false
                            } else {
                                Write-Host "{$key}: $actualValue" -ForegroundColor Green
                            }
                        }
    
                        Write-Host ""
    
                        if ($allSettingsCorrect) {
                            Write-Host "Pass: All settings are correct for policy: $($policy.Name)" -ForegroundColor Green
                        } else {
                            Write-Host "Fail: Policy $($policy.Name) has misconfigurations." -ForegroundColor Red
                        }
    
                    } catch {
                        Write-Host "Failed to retrieve details for policy: $($policy.Name)" -ForegroundColor Red
                        Write-Host $_.Exception.Message
                        Write-Host "$($script.Name) - Fail" -ForegroundColor Red
                    }
                }
            } catch {
                Write-Host "Error retrieving SafeLinks policies." -ForegroundColor Red
                Write-Host $_.Exception.Message
                Write-Host "$($script.Name) - Fail" -ForegroundColor Red
            }
        }
    },
    @{
        Name = "2.1.2 Common Attachment Types Filter"
        Type = "Script"
        Logic = {
            try {
    
                $malwareFilterPolicy = Get-MalwareFilterPolicy -Identity Default | Select-Object EnableFileFilter
                $malwareFilterPolicy | Format-Table -AutoSize
                Write-Host ""
                Write-Host ""
    
                if ($malwareFilterPolicy.EnableFileFilter -eq $true) {
                    Write-Host "Pass" -ForegroundColor Green
                } else {
                    Write-Host "Fail: File filter disabled" -ForegroundColor Red
                }
    

            } catch {
                Write-Host "Error retrieving Common Attachment Types Filter status." -ForegroundColor Red
                Write-Host $_.Exception.Message
                Write-Host "$($script.Name) - Fail" -ForegroundColor Red
            }
        }
    },    
    @{
        Name = "2.1.3 Internal Users Sending Malware"
        Type = "Script"
        Logic = {
            try {
    
                $malwareFilterPolicies = Get-MalwareFilterPolicy | Select-Object Identity, EnableInternalSenderAdminNotifications, InternalSenderAdminAddress
    
                $pass = $false
    
                foreach ($policy in $malwareFilterPolicies) {
                    if ($policy.EnableInternalSenderAdminNotifications -eq $true -and -not [string]::IsNullOrWhiteSpace($policy.InternalSenderAdminAddress)) {
                        $pass = $true
                        Write-Host "Policy '$($policy.Identity)' meets the criteria:" -ForegroundColor Green
                        Write-Host "EnableInternalSenderAdminNotifications: $($policy.EnableInternalSenderAdminNotifications)" -ForegroundColor Green
                        Write-Host "InternalSenderAdminAddress: $($policy.InternalSenderAdminAddress)" -ForegroundColor Green
                    } else {
                        Write-Host "Policy '$($policy.Identity)' does not meet the criteria:" -ForegroundColor Yellow
                        Write-Host "EnableInternalSenderAdminNotifications: $($policy.EnableInternalSenderAdminNotifications)" -ForegroundColor Yellow
                        Write-Host "InternalSenderAdminAddress: $($policy.InternalSenderAdminAddress)" -ForegroundColor Yellow
                    }
                }
                $malwareFilterPolicies | Format-Table -AutoSize
                Write-Host ""
                Write-Host ""
    
                if ($pass) {
                    Write-Host "Pass" -ForegroundColor Green
                } else {
                    Write-Host "Fail: Admin notifications disabled or admin email not configured" -ForegroundColor Red
                }
    
            
            } catch {
                Write-Host "Error retrieving Internal Users Sending Malware settings." -ForegroundColor Red
                Write-Host $_.Exception.Message
                Write-Host "Fail" -ForegroundColor Red
            }
        }
    },
    @{
        Name = "2.1.4 Safe Attachments Policy"
        Type = "Script"
        Logic = {
            try {
    
                $safeAttachmentPolicies = Get-SafeAttachmentPolicy | Select-Object Name, Enable
    
                $enabledPolicies = $safeAttachmentPolicies | Where-Object { $_.Enable -eq $true }
                Write-Host "All Safe Attachment Policies:" -ForegroundColor Yellow
                $safeAttachmentPolicies | Format-Table -AutoSize
                Write-Host ""
                Write-Host ""
    
                if ($enabledPolicies) {
                    

                    Write-Host "Pass" -ForegroundColor Green
                } else {
                    Write-Host "Fail" -ForegroundColor Red
                    Write-Host "No Safe Attachment Policies are enabled." -ForegroundColor Red
                }
    
                
            } catch {
                Write-Host "Error retrieving Safe Attachment Policies." -ForegroundColor Red
                Write-Host $_.Exception.Message
                Write-Host "Fail" -ForegroundColor Red
            }
        }
    },
    @{
        Name = "2.1.5 Safe Attachments for SharePoint, OneDrive, and Teams"
        Type = "Script"
        Logic = {
            try {
    
                $atpPolicies = Get-AtpPolicyForO365 | Select-Object Name, EnableATPForSPOTeamsODB, EnableSafeDocs, AllowSafeDocsOpen
    
                $pass = $true
    
                foreach ($policy in $atpPolicies) {
                    if ($policy.EnableATPForSPOTeamsODB -eq $true -and 
                        $policy.EnableSafeDocs -eq $true -and 
                        $policy.AllowSafeDocsOpen -eq $false) {
                        $policy | Format-List
                        Write-Host ""
                        Write-Host ""
                        Write-Host "Pass" -ForegroundColor Green
                    } else {
                        $pass = $false
        
                        $policy | Format-List
                        Write-Host ""
                        Write-Host ""
                        Write-Host "Fail" -ForegroundColor Red
                        Write-Host "Details:" -ForegroundColor Yellow
                    }
                }
                Write-Host ""
                Write-Host ""
    
        
    
            } catch {
                Write-Host "Error retrieving Safe Attachments for SharePoint, OneDrive, and Teams settings." -ForegroundColor Red
                Write-Host $_.Exception.Message
                Write-Host "Fail: Safe attachments disabled for services" -ForegroundColor Red
            }
        }
    },
    @{
        Name = "2.1.6 Exchange Online Spam Policies"
        Type = "Script"
        Logic = {
            try {
    
                $spamPolicies = Get-HostedOutboundSpamFilterPolicy | Select-Object NotifyOutboundSpamRecipients, NotifyOutboundSpam
    
                if ($spamPolicies.Count -eq 0) {
                    Write-Host "No Hosted Outbound Spam Filter Policies found." -ForegroundColor Yellow
                    Write-Host "Fail" -ForegroundColor Red
                } else {
                    $pass = $true
    
                    foreach ($policy in $spamPolicies) {
                        $notifyRecipients = $policy.NotifyOutboundSpamRecipients
                        $notifyOutboundSpam = $policy.NotifyOutboundSpam
    
                        if ($notifyOutboundSpam -eq $true -and $notifyRecipients -ne $null -and $notifyRecipients.Count -gt 0) {
                            $policy | Format-List
                            Write-Host ""
                            Write-Host ""
                            Write-Host "Pass" -ForegroundColor Green
                        } else {
                            $pass = $false
                            $policy | Format-List
                            Write-Host ""
                            Write-Host ""
                            Write-Host "Fail" -ForegroundColor Red
                            Write-Host "Details:" -ForegroundColor Yellow
                        }
                    }
              
                   
                }
    
            } catch {
                Write-Host "Error retrieving Exchange Online Spam Policies." -ForegroundColor Red
                Write-Host $_.Exception.Message
                Write-Host "2.1.6 Exchange Online Spam Policies - Fail" -ForegroundColor Red
            }
        }
    },
    @{
        Name = "2.1.7 Anti-Phishing Policy"
        Type = "Script"
        Logic = {
            try {
                $expectedValues = @{
                    Enabled                              = $true
                    PhishThresholdLevel                 = 3
                    EnableTargetedUserProtection        = $true
                    EnableOrganizationDomainsProtection = $true
                    EnableMailboxIntelligence           = $true
                    EnableMailboxIntelligenceProtection = $true
                    EnableSpoofIntelligence             = $true
                    TargetedUserProtectionAction        = "Quarantine"
                    TargetedDomainProtectionAction      = "Quarantine"
                    MailboxIntelligenceProtectionAction = "Quarantine"
                    EnableFirstContactSafetyTips        = $true
                    EnableSimilarUsersSafetyTips        = $true
                    EnableSimilarDomainsSafetyTips      = $true
                    EnableUnusualCharactersSafetyTips   = $true
                    HonorDmarcPolicy                    = $true
                }
    
                $antiPhishPolicies = Get-AntiPhishPolicy
                $globalPass = $false  
    
                foreach ($policy in $antiPhishPolicies) {
                    Write-Host "`nName: $($policy.Name)" -ForegroundColor Cyan
                    $policyPass = $true  
    
                    foreach ($key in $expectedValues.Keys) {
                        $currentValue = $policy.$key
                        $desiredValue = $expectedValues[$key]
    
                        if ($currentValue -ne $desiredValue) {
                            Write-Host "$($key): " -NoNewline
                            Write-Host "$($currentValue)" -ForegroundColor Red -NoNewline
                            Write-Host " > Desired: " -NoNewline
                            Write-Host "$($desiredValue)" -ForegroundColor Green
                            $policyPass = $false  
                        } else {
                            Write-Host "$($key): $($currentValue)"
                        }
                    }
    
                    if (-not $policy.TargetedUsersToProtect -or $policy.TargetedUsersToProtect.Count -eq 0) {
                        Write-Host "TargetedUsersToProtect: {}" -ForegroundColor Red -NoNewline
                        Write-Host " > Desired: Non-empty user list" -ForegroundColor Green
                        $policyPass = $false
                    } else {
                        Write-Host "TargetedUsersToProtect: $($policy.TargetedUsersToProtect -join ', ')"
                    }
    
                    if ($policyPass) {
                        $globalPass = $true
                    }
                }
                Write-Host ""
                Write-Host ""
    
                if ($globalPass) {
                    Write-Host "`nPass: At least one policy is correctly configured." -ForegroundColor Green
                } else {
                    Write-Host "`nFail: No policies are correctly configured." -ForegroundColor Red
                }
    
            } catch {
                Write-Host "Error retrieving Anti-Phishing Policy." -ForegroundColor Red
                Write-Host $_.Exception.Message
            }
        }
    },
    @{
        Name = "2.1.8 SPF Records"
        Type = "Script"
        Logic = {
            try {
    
                $dkimConfigs = Get-DkimSigningConfig
    
                if (-not $dkimConfigs) {
                    Write-Host "No DKIM configurations found." -ForegroundColor Yellow
                    Write-Host "Fail" -ForegroundColor Red
                    return
                }
    
                $domains = $dkimConfigs | Select-Object -ExpandProperty Domain
    
                if (-not $domains) {
                    Write-Host "No domains found in DKIM configurations. Skipping SPF check." -ForegroundColor Yellow
                    Write-Host "Fail" -ForegroundColor Red
                    return
                }
    
                $pass = $true
                foreach ($domain in $domains) {
                    try {
                        
                        $spfRecord = Resolve-DnsName -Name $domain -Type TXT -ErrorAction Stop | Where-Object { $_.Strings -like "*v=spf1 include:spf.protection.outlook.com*" }
                        
    
                        if ($spfRecord) {
                            Write-Host ""
                            Write-Host "SPF Record exists for $($domain)." -ForegroundColor Green
                        } else {
                            Write-Host ""
                            Write-Host "SPF Record does not exist for $($domain)." -ForegroundColor Red
                            $pass = $false
                        }
                    } catch {
                        Write-Host "Failed to resolve SPF record for $($domain)" -ForegroundColor Red
                        Write-Host $_.Exception.Message
                        $pass = $false
                    }
                }
                Write-Host ""
                Write-Host ""
    
                if ($pass) {
                    Write-Host "Pass" -ForegroundColor Green
                } else {
                    Write-Host "Fail: SPF records missing" -ForegroundColor Red
                }
            } catch {
                Write-Host "Error retrieving SPF Records." -ForegroundColor Red
                Write-Host $_.Exception.Message
                Write-Host "Fail" -ForegroundColor Red
            }
        }
    },
    @{
        Name = "2.1.9 DKIM Signing"
        Type = "Script"
        Logic = {
            try {
                
                $dkimConfig = Get-DkimSigningConfig
    
                if ($dkimConfig.Count -eq 0) {
                    Write-Host "No DKIM Signing Configurations found." -ForegroundColor Yellow
                    Write-Host "Fail" -ForegroundColor Red
                    return
                }
    
                $filteredConfig = $dkimConfig | Where-Object { $_.Domain -notlike "*.onmicrosoft.com" }
    
                if ($filteredConfig.Count -eq 0) {
                    Write-Host "No relevant domains found (excluding .onmicrosoft.com domains)." -ForegroundColor Yellow
                    Write-Host "Fail" -ForegroundColor Red
                    return
                }
    
                $allEnabled = $true
                foreach ($config in $filteredConfig) {
                    if (-not $config.Enabled) {
                        Write-Host "DKIM Signing is Disabled for domain: $($config.Domain)" -ForegroundColor Red
                        $allEnabled = $false
                    } else {
                        Write-Host "DKIM Signing is Enabled for domain: $($config.Domain)" -ForegroundColor Green
                    }
                }
                Write-Host ""
                Write-Host ""
    
                if ($allEnabled) {
                    Write-Host "Pass" -ForegroundColor Green
                } else {
                    Write-Host "Fail: DKIM signing disabled" -ForegroundColor Red
                }
            } catch {
                Write-Host "Error retrieving DKIM Signing Configurations." -ForegroundColor Red
                Write-Host $_.Exception.Message
                Write-Host "Fail" -ForegroundColor Red
            }
        }
    },
    @{
        Name = "2.1.10 DMARC Records"
        Type = "Script"
        Logic = {
            try {
    
                $dkimConfigs = Get-DkimSigningConfig
    
                if (-not $dkimConfigs) {
                    Write-Host "No DKIM configurations found." -ForegroundColor Yellow
                    Write-Host "Fail: No domains available for DMARC check." -ForegroundColor Red
                    return
                }
    
                $domains = $dkimConfigs | Select-Object -ExpandProperty Domain
    
                if (-not $domains) {
                    Write-Host "No domains found in DKIM configurations." -ForegroundColor Yellow
                    Write-Host "Fail: No domains available for DMARC check." -ForegroundColor Red
                    return
                }
    
                $missingDmarc = @()
                foreach ($domain in $domains) {
                    $dmarcDomain = "_dmarc.$domain"
    
                    try {
                        $dmarcRecord = Resolve-DnsName -Name $dmarcDomain -Type TXT -ErrorAction Stop
                        Write-Host "DMARC Record for $($dmarcDomain) found." -ForegroundColor Green
                    } catch {
                        Write-Host "DMARC Record for $($dmarcDomain) not found." -ForegroundColor Red
                        $missingDmarc += $domain
                    }
                }
                Write-Host ""
                Write-Host ""
    
                if ($missingDmarc.Count -eq 0) {
                    Write-Host "Pass: All domains have DMARC records." -ForegroundColor Green
                } else {
                    Write-Host "Fail: The following domains are missing DMARC records:" -ForegroundColor Red
                    $missingDmarc | ForEach-Object { Write-Host $_ -ForegroundColor Red }
                }
            } catch {
                Write-Host "Error retrieving DMARC Records." -ForegroundColor Red
                Write-Host $_.Exception.Message
            }
        }
    },        
    @{
        Name = "2.1.11 Comprehensive Attachment Filtering"
        Type = "Script"
        Logic = {
            try {
                $L2Extensions = @(
                    "7z", "a3x", "ace", "ade", "adp", "ani", "app", "appinstaller",
                    "applescript", "application", "appref-ms", "appx", "appxbundle", "arj",
                    "asd", "asx", "bas", "bat", "bgi", "bz2", "cab", "chm", "cmd", "com",
                    "cpl", "crt", "cs", "csh", "daa", "dbf", "dcr", "deb", "desktopthemepackfile",
                    "dex", "diagcab", "dif", "dir", "dll", "dmg", "doc", "docm", "dot", "dotm",
                    "elf", "eml", "exe", "fxp", "gadget", "gz", "hlp", "hta", "htc", "htm", "html",
                    "hwpx", "ics", "img", "inf", "ins", "iqy", "iso", "isp", "jar", "jnlp", "js", "jse",
                    "kext", "ksh", "lha", "lib", "library-ms", "lnk", "lzh", "macho", "mam", "mda",
                    "mdb", "mde", "mdt", "mdw", "mdz", "mht", "mhtml", "mof", "msc", "msi", "msix",
                    "msp", "msrcincident", "mst", "ocx", "odt", "ops", "oxps", "pcd", "pif", "plg",
                    "pot", "potm", "ppa", "ppam", "ppkg", "pps", "ppsm", "ppt", "pptm", "prf", "prg",
                    "ps1", "ps11", "ps11xml", "ps1xml", "ps2", "ps2xml", "psc1", "psc2", "pub", "py",
                    "pyc", "pyo", "pyw", "pyz", "pyzw", "rar", "reg", "rev", "rtf", "scf", "scpt", "scr",
                    "sct", "searchConnector-ms", "service", "settingcontent-ms", "sh", "shb", "shs",
                    "shtm", "shtml", "sldm", "slk", "so", "spl", "stm", "svg", "swf", "sys", "tar",
                    "theme", "themepack", "timer", "uif", "url", "uue", "vb", "vbe", "vbs", "vhd",
                    "vhdx", "vxd", "wbk", "website", "wim", "wiz", "ws", "wsc", "wsf", "wsh", "xla",
                    "xlam", "xlc", "xll", "xlm", "xls", "xlsb", "xlsm", "xlt", "xltm", "xlw", "xnk",
                    "xps", "xsl", "xz", "z"
                )
    
                $ExtensionPolicies = Get-MalwareFilterPolicy | Where-Object { $_.FileTypes.Count -gt 50 }
    
                if (!$ExtensionPolicies) {
                    Write-Host "Fail: No malware filter policies with over 50 extensions were found." -ForegroundColor Red
                    return
                }
    
                $missingExtensionsOverall = @()
                foreach ($policy in $ExtensionPolicies) {
                    $MissingExtensions = $L2Extensions | Where-Object { -not $policy.FileTypes.Contains($_) }
    
                    if ($MissingExtensions.Count -gt 0) {
                        Write-Host "Missing extensions for policy '$($policy.Identity)':" -ForegroundColor Yellow
                        Write-Host ($MissingExtensions -join ", ") -ForegroundColor Red
                        $missingExtensionsOverall += $MissingExtensions
                    } else {
                        Write-Host "Policy '$($policy.Identity)' contains all required extensions." -ForegroundColor Green
                    }
                }
                Write-Host ""
                Write-Host ""
    
                if ($missingExtensionsOverall.Count -gt 0) {
                    Write-Host "Fail: The above extensions are missing across policies." -ForegroundColor Red
                } else {
                    Write-Host "Pass: All required extensions are present in all policies." -ForegroundColor Green
                }
            } catch {
                Write-Host "Error processing Comprehensive Attachment Filtering." -ForegroundColor Red
                Write-Host $_.Exception.Message
            }
        }
    },
    @{
        Name = "2.1.12 Connection Filter IP Allow List"
        Type = "Script"
        Logic = {
            try {
    
                $connectionFilter = Get-HostedConnectionFilterPolicy -Identity Default
    
                if ($connectionFilter.IPAllowList -ne $null -and $connectionFilter.IPAllowList.Count -gt 0) {
        
                    Write-Host "IPAllowList contains:" -ForegroundColor Red
                    $connectionFilter.IPAllowList | Format-Table -AutoSize
                    Write-Host ""
                    Write-Host ""
                    Write-Host "Fail: IP Allow List is not empty." -ForegroundColor Red
                } else {
                    Write-Host ""
                    Write-Host ""
                    Write-Host "Pass: IP Allow List is empty." -ForegroundColor Green
                }
            } catch {
                Write-Host "Error checking Connection Filter IP Allow List." -ForegroundColor Red
                Write-Host $_.Exception.Message
            }
        }
    },
    @{
        Name = "2.1.13 Connection Filter Safe List"
        Type = "Script"
        Logic = {
            try {
    
                $connectionFilter = Get-HostedConnectionFilterPolicy -Identity Default
    
                if ($connectionFilter.EnableSafeList -eq $false) {
                    Write-Host "Pass: EnableSafeList is set to False." -ForegroundColor Green
                } else {
                    Write-Host "EnableSafeList: $($connectionFilter.EnableSafeList)" -ForegroundColor Red
                    Write-Host ""
                    Write-Host ""
                    Write-Host "Fail: EnableSafeList is not set to False." -ForegroundColor Red

                }
            } catch {
                Write-Host "Error checking Connection Filter Safe List status." -ForegroundColor Red
                Write-Host $_.Exception.Message
            }
        }
    },    
    @{
        Name = "2.1.14 Inbound Anti-Spam Policies"
        Type = "Script"
        Logic = {
            try {
    
                $contentFilterPolicies = Get-HostedContentFilterPolicy | Select-Object Identity, AllowedSenderDomains
    
                $isPass = $true
    
                foreach ($policy in $contentFilterPolicies) {
                    if ($policy.AllowedSenderDomains -ne $null -and $policy.AllowedSenderDomains.Count -gt 0) {
                        Write-Host ""
                        Write-Host "Policy '$($policy.Identity)'" -ForegroundColor DarkYellow
                        Write-Host "AllowedSenderDomains"
                        Write-Host "$($policy.AllowedSenderDomains)" -ForegroundColor Red
                        $isPass = $false
                    } else {
                        Write-Host "Policy '$($policy.Identity)' has an empty AllowedSenderDomains." -ForegroundColor Green
                    }
                }
                Write-Host ""
                Write-Host ""
    
                if ($isPass) {
                    Write-Host "Pass: All policies have empty AllowedSenderDomains." -ForegroundColor Green
                } else {
                    Write-Host "Fail: One or more policies have non-empty AllowedSenderDomains." -ForegroundColor Red
                }
            } catch {
                Write-Host "Error checking Inbound Anti-Spam Policies." -ForegroundColor Red
                Write-Host $_.Exception.Message
            }
        }
    },
    @{
        Name = "2.4.4 Zero Hour Purge for Teams"
        Type = "Script"
        Logic = {
            try {
    
                $teamsProtectionPolicies = Get-TeamsProtectionPolicy | Select-Object Name, ZapEnabled
    
                $isPass = $true
    
                foreach ($policy in $teamsProtectionPolicies) {
                    if ($policy.ZapEnabled -eq $true) {
                        Write-Host "Policy '$($policy.Name)`n'.`n ZapEnabled: $($policy.ZapEnabled)" -ForegroundColor Green
                    } else {
                        Write-Host "Policy '$($policy.Name)`n'.`n ZapEnabled: $($policy.ZapEnabled)" -ForegroundColor Red
                        $isPass = $false
                    }
                }
                Write-Host ""
                Write-Host ""
    
                if ($isPass) {
                    Write-Host "Pass: All policies have ZapEnabled set to true." -ForegroundColor Green
                } else {
                    Write-Host "Fail: One or more policies have ZapEnabled not set to true." -ForegroundColor Red
                }
    
                Get-TeamsProtectionPolicyRule | Format-List ExceptIf*
    
            } catch {
                Write-Host "Error checking Zero Hour Purge for Teams." -ForegroundColor Red
                Write-Host $_.Exception.Message
            }
        }
    },    
    @{
        Name = "3.1.1 Audit Log Search"
        Type = "Script"
        Logic = {
            try {
    
                $auditLogConfig = Get-AdminAuditLogConfig | Select-Object UnifiedAuditLogIngestionEnabled
                $auditLogConfig | Format-Table -AutoSize
                Write-Host ""
                Write-Host ""
                if ($auditLogConfig.UnifiedAuditLogIngestionEnabled -eq $true) {
                    Write-Host "Pass: Unified Audit Log Ingestion is Enabled." -ForegroundColor Green
                } else {
                    Write-Host "Fail: Unified Audit Log Ingestion is Disabled or not configured correctly." -ForegroundColor Red
                }
    
    
            } catch {
                Write-Host "Error retrieving Unified Audit Log Ingestion status." -ForegroundColor Red
                Write-Host $_.Exception.Message
            }
        }
    },    
    @{
        Name = "3.2.1-3.2.2 DLP Policies for Teams"
        Type = "Script"
        Logic = {
            try {
    
                $dlpPolicy = Get-DlpCompliancePolicy
    
                if ($dlpPolicy.Count -eq 0) {
                    Write-Host "No DLP policies found." -ForegroundColor Yellow
                    return
                }
    
                $teamsDlpPolicies = $dlpPolicy | Where-Object { $_.Workload } | Format-Table Name,Mode,TeamsLocation*
                $teamsDlpPolicies
                Write-Host ""
                Write-Host ""
    
                if ($teamsDlpPolicies.Count -eq 0) {
                    Write-Host "Fail: No DLP policies found for Teams workload." -ForegroundColor Red
                    return
                }
    
                $isCompliant = $true
    
                foreach ($policy in $teamsDlpPolicies) {
    
                    $mode = $policy.Mode
                    $teamsLocation = $policy.TeamsLocation
    
                    if ($mode -ne "Enable" -or -not ($teamsLocation -contains "All")) {
                        $isCompliant = $false
                    } else {
                    }
                }
    
                if ($isCompliant) {
                    Write-Host "Pass: All DLP policies for Teams workload are compliant." -ForegroundColor Green
                } else {
                    Write-Host "Fail: Some DLP policies for Teams workload are not compliant." -ForegroundColor Red
                }
    
            } catch {
                Write-Host "Error retrieving or validating DLP policies." -ForegroundColor Red
                Write-Host $_.Exception.Message
            }
        }
    },    
    @{
        Name = "3.3.1 SharePoint Protection Policies"
        Type = "Manual"
        Link = "https://purview.microsoft.com/informationprotection/purviewmipoverview"
        explanation = {
            Verify that SharePoint Information Protection Policies are configured.
            Scroll down to see if Sensitivity labels have been created.
        }
    },
    @{
        Name = "5.1.1.1 Security Defaults"
        Type = "Script"
        Logic = {
            try {
    
                $securityDefaults = Get-MgPolicyIdentitySecurityDefaultEnforcementPolicy | Select-Object IsEnabled
    
                $securityDefaults | Format-Table -AutoSize
                Write-Host ""
                Write-Host ""
    
                if ($securityDefaults.IsEnabled -eq $false) {
                    Write-Host "Pass: Security Defaults are disabled." -ForegroundColor Green
                } elseif ($securityDefaults.IsEnabled -eq $true) {
                    Write-Host "Fail: Security Defaults are enabled." -ForegroundColor Red
                } else {
                    Write-Host "Fail: Unable to determine Security Defaults status." -ForegroundColor Red
                }
            } catch {
                Write-Host "Error retrieving Security Defaults policy." -ForegroundColor Red
                Write-Host $_.Exception.Message
            }
        }
    },    
    @{
        Name = "5.1.2.1 Per-User MFA State"
        Type = "Script"
        Logic = {
            try {
                $users = Get-MgUser -All:$true | Select-Object Id, DisplayName, UserPrincipalName

                $mfaResults = @()

                foreach ($user in $users) {
                    $mfaState = Invoke-MgGraphRequest -Uri "https://graph.microsoft.com/beta/users/$($user.Id)/authentication/requirements" -Method GET
                    
                    $perUserMfaState = $mfaState.perUserMfaState

                    $mfaResults += [PSCustomObject]@{
                        DisplayName      = $user.DisplayName
                        UserPrincipalName = $user.UserPrincipalName
                        PerUserMfaState  = $perUserMfaState
                    }
                }

                $mfaResults | Format-Table -AutoSize
                Write-Host ""
                Write-Host ""

                if ($mfaResults.PerUserMfaState -contains "disabled") {
                    Write-Host "Fail: Some users do not have MFA enabled." -ForegroundColor Red
                } elseif ($mfaResults.Count -gt 0) {
                    Write-Host "Pass: All users have MFA enabled." -ForegroundColor Green
                } else {
                    Write-Host "Fail: No users found or unable to determine MFA state." -ForegroundColor Red
                }
            } catch {
                Write-Host "Error retrieving MFA state for users." -ForegroundColor Red
                Write-Host $_.Exception.Message
            }
        }
    },

    @{
        Name = "5.1.2.2 Third Party Application"
        Type = "Script"
        Logic = {
            try {
    
                $permissions = (Get-MgPolicyAuthorizationPolicy).DefaultUserRolePermissions | Select-Object AllowedToCreateApps
    
                $permissions | Format-Table -AutoSize
                Write-Host ""
                Write-Host ""
    
                if ($permissions.AllowedToCreateApps -eq $false) {
                    Write-Host "Pass: Third party application creation is not allowed." -ForegroundColor Green
                } else {
                    Write-Host "Fail: Third party application creation is allowed." -ForegroundColor Red
                }
            } catch {
                Write-Host "Error retrieving Third Party Application settings." -ForegroundColor Red
                Write-Host $_.Exception.Message
            }
        }
    },    
    @{
        Name = "5.1.2.3 Tenant Creation"
        Type = "Script"
        Logic = {
            try {
    
                $permissions = (Get-MgPolicyAuthorizationPolicy).DefaultUserRolePermissions | Select-Object AllowedToCreateTenants
    
                $permissions | Format-Table -AutoSize
                Write-Host ""
                Write-Host ""
    
                if ($permissions.AllowedToCreateTenants -eq $false) {
                    Write-Host "Pass: Tenant creation is not allowed." -ForegroundColor Green
                } else {
                    Write-Host "Fail: Tenant creation is allowed." -ForegroundColor Red
                }
            } catch {
                Write-Host "Error retrieving Tenant Creation settings." -ForegroundColor Red
                Write-Host $_.Exception.Message
            }
        }
    },    
    @{
        Name = "5.1.2.4 Access to Entra Admin Center"
        Type = "Manual"
        Link = "https://portal.azure.com/#view/Microsoft_AAD_IAM/ActiveDirectoryMenuBlade/~/UserSettings"
        explanation = {
            Verify access to Entra admin center is restricted
            Ensure 'Restrict access to Microsoft Entra admin center' is toggled to or has a value of 'Yes'.
        }
    },
    @{
        Name = "5.1.2.5 Remain Signed-in Allowed"
        Type = "Manual"
        Link = "https://portal.azure.com/#view/Microsoft_AAD_IAM/ActiveDirectoryMenuBlade/~/UserSettings"
        explanation = {
            Verify that users are not allowed to remain signed-in
            Ensure 'Show keep user signed in' is toggled to or has a value of 'No'.
        }
    },
    @{
        Name = "5.1.2.6 LinkedIn Account Syncronizaton"
        Type = "Manual"
        Link = "https://portal.azure.com/#view/Microsoft_AAD_IAM/ActiveDirectoryMenuBlade/~/UserSettings"
        explanation = {
            Verify that users are not allowed to connect their account to LinkedIn
            Ensure 'Allow users to connect their work or school account with LinkedIn' has a value of 'No'.
        }
    },
    @{
        Name = "5.1.3.1 Dynamic Guest Group"
        Type = "Script"
        Logic = {
            try {
    
                $groups = Get-MgGroup | Where-Object { $_.GroupTypes -contains "DynamicMembership" }
    
                if ($groups) {
                    $groups | Format-Table DisplayName, GroupTypes, MembershipRule -AutoSize
                    Write-Host ""
                    Write-Host ""
                    Write-Host "Pass: Dynamic guest groups found." -ForegroundColor Green
                } else {
                    Write-Host ""
                    Write-Host ""
                    Write-Host "Fail: No dynamic guest groups found." -ForegroundColor Red
                }
            } catch {
                Write-Host "Error retrieving Dynamic Guest Group settings." -ForegroundColor Red
                Write-Host $_.Exception.Message
            }
        }
    },    
    @{
        Name = "5.1.5.1 User App Consent"
        Type = "Script"
        Logic = {
            try {
    
                $consentPolicies = (Get-MgPolicyAuthorizationPolicy).DefaultUserRolePermissions | Select-Object -ExpandProperty PermissionGrantPoliciesAssigned
    
                if ($consentPolicies) {
                    Write-Host "Permission Grant Policies Assigned:" -ForegroundColor Cyan
                    $consentPolicies | Format-Table -AutoSize
                    Write-Host ""
                    Write-Host ""
    
                    if ($consentPolicies -contains "ManagePermissionGrantsForSelf.microsoft-user-default-low") {
                        Write-Host "Fail: ManagePermissionGrantsForSelf.microsoft-user-default-low is present." -ForegroundColor Red
                    } else {
                        Write-Host "Pass: ManagePermissionGrantsForSelf.microsoft-user-default-low is not present." -ForegroundColor Green
                    }
                } else {
                    Write-Host "Pass: No permission grant policies assigned for user app consent." -ForegroundColor Green
                }
            } catch {
                Write-Host "Error retrieving User App Consent settings." -ForegroundColor Red
                Write-Host $_.Exception.Message
            }
        }
    },    
    @{
        Name = "5.1.5.2 Admin Consent Request Policy"
        Type = "Script"
        Logic = {
            try {
                $adminConsentPolicy = Get-MgPolicyAdminConsentRequestPolicy | Select-Object IsEnabled, NotifyReviewers, RemindersEnabled, RequestDurationInDays

                $adminConsentPolicy | Format-Table -AutoSize
                Write-Host ""
                Write-Host ""

                if ($adminConsentPolicy.IsEnabled -eq $true) {
                    Write-Host "Pass: Admin Consent Request Policy is enabled." -ForegroundColor Green
                } else {
                    Write-Host "Fail: Admin Consent Request Policy is disabled." -ForegroundColor Red
                }
            } catch {
                Write-Host "Error retrieving Admin Consent Request Policy." -ForegroundColor Red
                Write-Host $_.Exception.Message
            }
        }
    },
    @{
        Name = "5.1.6.1 Collaboration Invitations"
        Type = "Manual"
        Link = "https://portal.azure.com/#view/Microsoft_AAD_IAM/AllowlistPolicyBlade"
        explanation = {
            Verify collaboration invitations are restricted
            Scroll down to bottom of page to find 'Collaboration restrictions'
            Ensure 'Allow invitations to be sent to any domain' is set NOT selected
        }
    },
    @{
        Name = "5.1.6.2 Guest User Access"
        Type = "Script"
        Logic = {
            try {
    
                $guestUserPolicy = Get-MgPolicyAuthorizationPolicy | Select-Object -ExpandProperty GuestUserRoleId
    
                $mostRestrictiveValues = @(
                    "10dae51f-b6af-4016-8d66-8c2a99b929b3",
                    "2af84b1e-32c8-42b7-82bc-daa82404023b"
                )
    
                Write-Host "Guest User Role ID:" -ForegroundColor Cyan
                Write-Host $guestUserPolicy
                Write-Host ""
                Write-Host ""
    
                if ($mostRestrictiveValues -contains $guestUserPolicy) {
                    Write-Host "Pass: Guest User Role ID is set to a most restrictive value." -ForegroundColor Green
                } else {
                    Write-Host "Fail: Guest User Role ID is not set to a most restrictive value." -ForegroundColor Red
                }
            } catch {
                Write-Host "Error retrieving Guest User Access settings." -ForegroundColor Red
                Write-Host $_.Exception.Message
            }
        }
    },    
    @{
        Name = "5.1.6.3 Guest User Invitations"
        Type = "Script"
        Logic = {
            try {
    
                $invitesPolicy = Get-MgPolicyAuthorizationPolicy | Select-Object -ExpandProperty AllowInvitesFrom
    
                $allowedValues = @(
                    "none",                  
                    "adminsAndGuestInviters", 
                    "admins",                 
                    "everyone"                
                )
    
                Write-Host "AllowInvitesFrom Value:" -ForegroundColor Cyan
                Write-Host $invitesPolicy
                Write-Host ""
                Write-Host ""
    
                $policyIndex = $allowedValues.IndexOf($invitesPolicy)
                $requiredIndex = $allowedValues.IndexOf("adminsAndGuestInviters")
    
                if ($policyIndex -ge 0 -and $policyIndex -le $requiredIndex) {
                    Write-Host "Pass: Guest User Invitations setting is sufficiently restrictive." -ForegroundColor Green
                } else {
                    Write-Host "Fail: Guest User Invitations setting is not restrictive enough." -ForegroundColor Red
                }
            } catch {
                Write-Host "Error retrieving Guest User Invitations settings." -ForegroundColor Red
                Write-Host $_.Exception.Message
            }
        }
    },    
    @{
        Name = "5.1.8.1 Password Hash Sync"
        Type = "Script"
        Logic = {
            try {
    
                $hashSyncStatus = Get-MgOrganization | Select-Object -ExpandProperty OnPremisesSyncEnabled
    
                if ($null -ne $hashSyncStatus) {
                    Write-Host "Password Hash Sync Status:" -ForegroundColor Cyan
                    Write-Host "OnPremisesSyncEnabled: $hashSyncStatus"
                    
    
                    if ($hashSyncStatus -eq $true) {
                        Write-Host ""
                        Write-Host ""
                        Write-Host "Pass: Password Hash Sync is enabled." -ForegroundColor Green
                    } else {
                        Write-Host ""
                        Write-Host ""
                        Write-Host "Fail: Password Hash Sync is disabled." -ForegroundColor Red
                    }
                } else {
                    Write-Host "Fail: No results found for OnPremisesSyncEnabled." -ForegroundColor Red
                }
            } catch {
                Write-Host "Error retrieving Password Hash Sync status." -ForegroundColor Red
                Write-Host $_.Exception.Message
            }
        }
    },    
    @{
        Name = "5.2.2.1 MFA Status for Admin Roles"
        Type = "Script"
        Logic = {
            try {
                $Parameters = @{
                    Method = "GET"
                    URI = "/v1.0/me"
                    OutputType = "HttpResponseMessage"
                }

                $Response = Invoke-GraphRequest @Parameters
                $Headers = $Response.RequestMessage.Headers
                $Token = $Headers.Authorization.Parameter

                if (-not $Token) {
                    Write-Host "Failed to retrieve Graph API token." -ForegroundColor Red
                    return
                }


                Write-Host "Fetching MFA status for admin roles..." -ForegroundColor Cyan
                $headers = @{
                    "Authorization" = "Bearer $Token"
                    "Content-Type"  = "application/json"
                }

                $secureScores = Invoke-RestMethod -Uri "https://graph.microsoft.com/beta/security/secureScores" -Headers $headers -Method Get
                
                if ($secureScores) {
                    Write-Host "MFA Status for Admin Roles:" -ForegroundColor Green
                    $secureScores | Format-Table -AutoSize
                    Write-Host ""
                    Write-Host ""
                } else {
                    Write-Host "No MFA status data found for admin roles." -ForegroundColor Yellow
                }
            } catch {
                Write-Host "Error retrieving MFA status for Admin Roles" -ForegroundColor Red
                Write-Host $_.Exception.Message
            }
        }
    },
    @{
        Name = "5.2.2.2 Conditional Access MFA Policy Check"
        Type = "Script"
        Logic = {
            try {

                $policies = Get-MgIdentityConditionalAccessPolicy | Where-Object {
                    $_.DisplayName -match "MFA" -and $_.State -eq "enabled"
                }

                if ($policies.Count -eq 0) {
                    Write-Host "Fail: No enabled Conditional Access policies contain 'MFA' in their name." -ForegroundColor Red
                    return
                }

                $failFlag = $false

                foreach ($policy in $policies) {
                    $policyId = $policy.Id
                    $endpoint = "https://graph.microsoft.com/v1.0/identity/conditionalAccess/policies('$policyId')`?$select=conditions,createdDateTime"

                    $response = Invoke-MgGraphRequest -Uri $endpoint -Method GET
                    $responseJson = $response | ConvertTo-Json -Depth 10

                    Write-Host "Policy ID: $policyId" -ForegroundColor Cyan
                    Write-Host $responseJson
                    Write-Host ""

                    $users = $response.conditions.users

                    if ($users.includeUsers -eq "All" -and -not $users.excludeUsers -and -not $users.excludeGroups) {
                        Write-Host "Pass: MFA Conditional Access Policy '$($policy.DisplayName)' applies to all users." -ForegroundColor Green
                    } else {
                        Write-Host "Fail: MFA Conditional Access Policy '$($policy.DisplayName)' has exclusions." -ForegroundColor Red
                        $failFlag = $true
                    }
                }

                if ($failFlag) {
                    Write-Host "Fail: One or more MFA Conditional Access policies have exclusions." -ForegroundColor Red
                } else {
                    Write-Host "Pass: All MFA Conditional Access policies apply to all users with no exclusions." -ForegroundColor Green
                }
            } catch {
                Write-Host "Error retrieving Conditional Access policies." -ForegroundColor Red
                Write-Host $_.Exception.Message
            }
        }
    },
    @{
        Name = "5.2.2.4 Conditional Access Session Controls Check"
        Type = "Script"
        Logic = {
            try {

                $policies = Get-MgIdentityConditionalAccessPolicy | Where-Object { $_.State -eq "enabled" }

                if ($policies.Count -eq 0) {
                    Write-Host "Fail: No enabled Conditional Access policies found." -ForegroundColor Red
                    return
                }

                $failFlag = $true

                foreach ($policy in $policies) {
                    $policyId = $policy.Id
                    $endpoint = "https://graph.microsoft.com/v1.0/identity/conditionalAccess/policies('$policyId')`?$select=sessionControls"

                    $response = Invoke-MgGraphRequest -Uri $endpoint -Method GET
                    $sessionControls = $response.sessionControls

                    Write-Host "Policy ID: $policyId" -ForegroundColor Cyan
                    Write-Host ($sessionControls | ConvertTo-Json -Depth 10)
                    Write-Host ""

                    if ($sessionControls -and $sessionControls.PSObject.Properties.Count -gt 0) {
                        Write-Host "Pass: Conditional Access Policy '$($policy.DisplayName)' has session controls configured." -ForegroundColor Green
                        $failFlag = $false
                    }
                }

                if ($failFlag) {
                    Write-Host "Fail: No enabled Conditional Access policies have session controls configured." -ForegroundColor Red
                } else {
                    Write-Host "Pass: At least one enabled Conditional Access policy has session controls configured." -ForegroundColor Green
                }
            } catch {
                Write-Host "Error retrieving Conditional Access policies." -ForegroundColor Red
                Write-Host $_.Exception.Message
            }
        }
    },
    @{
        Name = "5.2.2.5 Conditional Access Grant Controls Check"
        Type = "Script"
        Logic = {
            try {

                $policies = Get-MgIdentityConditionalAccessPolicy | Where-Object { $_.State -eq "enabled" }

                if ($policies.Count -eq 0) {
                    Write-Host "Fail: No enabled Conditional Access policies found." -ForegroundColor Red
                    return
                }

                $failFlag = $true

                foreach ($policy in $policies) {
                    $policyId = $policy.Id
                    $endpoint = "https://graph.microsoft.com/v1.0/identity/conditionalAccess/policies('$policyId')`?$select=grantControls"

                    $response = Invoke-MgGraphRequest -Uri $endpoint -Method GET
                    $grantControls = $response.grantControls

                    Write-Host "Policy ID: $policyId" -ForegroundColor Cyan
                    Write-Host ($grantControls | ConvertTo-Json -Depth 10)
                    Write-Host ""

                    if ($grantControls -and $grantControls.authenticationStrength) {
                        Write-Host "Pass: Conditional Access Policy '$($policy.DisplayName)' has authentication strength configured." -ForegroundColor Green
                        $failFlag = $false
                    }
                }

                if ($failFlag) {
                    Write-Host "Fail: No enabled Conditional Access policies have authentication strength configured in grantControls." -ForegroundColor Red
                } else {
                    Write-Host "Pass: At least one enabled Conditional Access policy has authentication strength configured in grantControls." -ForegroundColor Green
                }
            } catch {
                Write-Host "Error retrieving Conditional Access policies." -ForegroundColor Red
                Write-Host $_.Exception.Message
            }
        }
    },
    @{
        Name = "5.2.2.6 Conditional Access Session Controls Check"
        Type = "Script"
        Logic = {
            try {

                $policies = Get-MgIdentityConditionalAccessPolicy | Where-Object { $_.State -eq "enabled" }

                if ($policies.Count -eq 0) {
                    Write-Host "Fail: No enabled Conditional Access policies found." -ForegroundColor Red
                    return
                }

                $failFlag = $true

                foreach ($policy in $policies) {
                    $policyId = $policy.Id
                    $endpoint = "https://graph.microsoft.com/v1.0/identity/conditionalAccess/policies('$policyId')`?$select=sessionControls"

                    $response = Invoke-MgGraphRequest -Uri $endpoint -Method GET
                    $sessionControls = $response.sessionControls

                    Write-Host "Policy ID: $policyId" -ForegroundColor Cyan
                    Write-Host ($sessionControls | ConvertTo-Json -Depth 10)
                    Write-Host ""

                    if ($sessionControls -and $sessionControls.PSObject.Properties.Count -gt 0) {
                        Write-Host "Pass: Conditional Access Policy '$($policy.DisplayName)' has session controls configured." -ForegroundColor Green
                        $failFlag = $false
                    }
                }

                if ($failFlag) {
                    Write-Host "Fail: No enabled Conditional Access policies have session controls configured." -ForegroundColor Red
                } else {
                    Write-Host "Pass: At least one enabled Conditional Access policy has session controls configured." -ForegroundColor Green
                }
            } catch {
                Write-Host "Error retrieving Conditional Access policies." -ForegroundColor Red
                Write-Host $_.Exception.Message
            }
        }
    },
    @{
        Name = "5.2.2.7 Sign-In Risk Policy"
        Type = "Script"
        Logic = {
            try {
    
                $policies = Get-MgIdentityConditionalAccessPolicy | ForEach-Object {
                    $resolvedIncludedUsers = @()
                    $resolvedExcludedUsers = @()
    
                    if ($_.Conditions.Users.IncludeUsers -ne $null) {
                        $resolvedIncludedUsers = $_.Conditions.Users.IncludeUsers | ForEach-Object {
                            if ($_ -eq "All") {
                                "All Users"
                            } else {
                                try {
                                    (Get-MgUser -UserId $_ -ErrorAction SilentlyContinue).DisplayName
                                } catch {
                                    $_ 
                                }
                            }
                        }
                    }
    
                    if ($_.Conditions.Users.ExcludeUsers -ne $null) {
                        $resolvedExcludedUsers = $_.Conditions.Users.ExcludeUsers | ForEach-Object {
                            try {
                                (Get-MgUser -UserId $_ -ErrorAction SilentlyContinue).DisplayName
                            } catch {
                                $_ 
                            }
                        }
                    }
    
                    [PSCustomObject]@{
                        Name             = $_.DisplayName
                        State            = $_.State
                        IncludedUsers    = $resolvedIncludedUsers -join ", "
                        ExcludedUsers    = $resolvedExcludedUsers -join ", "
                        IncludedGroups   = if ($_.Conditions.Users.IncludeGroups.Count -gt 0) { ($_.Conditions.Users.IncludeGroups -join ", ") } else { "None" }
                        ExcludedGroups   = if ($_.Conditions.Users.ExcludeGroups.Count -gt 0) { ($_.Conditions.Users.ExcludeGroups -join ", ") } else { "None" }
                        UserRiskLevels   = if ($_.Conditions.UserRiskLevels.Count -gt 0) { ($_.Conditions.UserRiskLevels -join ", ") } else { "None" }
                        SignInRiskLevels = if ($_.Conditions.SignInRiskLevels.Count -gt 0) { ($_.Conditions.SignInRiskLevels -join ", ") } else { "None" }
                    }
                }
    
                $policies | ConvertTo-Json -Depth 3 | Out-String | Write-Host -ForegroundColor Green
                Write-Host ""
                Write-Host ""
    
            } catch {
                Write-Host "Error retrieving Sign-In Risk Policies" -ForegroundColor Red
                Write-Host $_.Exception.Message
            }
        }
    },
    @{
        Name = "5.2.3.1 Microsoft Authenticator Feature Settings"
        Type = "Script"
        Logic = {
            try {


                $authenticatorSettings = (Get-MgPolicyAuthenticationMethodPolicyAuthenticationMethodConfiguration -AuthenticationMethodConfigurationId microsoftAuthenticator | 
                    Select-Object -ExpandProperty AdditionalProperties).featureSettings | ConvertTo-Json -Depth 10 | ConvertFrom-Json

                $authenticatorSettings | Format-Table -AutoSize
                Write-Host ""
                Write-Host ""

                $failFlag = $false

                foreach ($setting in $authenticatorSettings.PSObject.Properties) {
                    $state = $setting.Value.state
                    if ($state -eq "disabled") {
                        Write-Host "Fail: $($setting.Name) is disabled." -ForegroundColor Red
                        $failFlag = $true
                    }
                }

                if ($failFlag) {
                    Write-Host "Fail: Some Microsoft Authenticator settings are disabled." -ForegroundColor Red
                } else {
                    Write-Host "Pass: All Microsoft Authenticator settings are correctly configured." -ForegroundColor Green
                }
            } catch {
                Write-Host "Error retrieving Microsoft Authenticator feature settings." -ForegroundColor Red
                Write-Host $_.Exception.Message
            }
        }
    },
        
    @{
        Name = "5.2.3.2 Custom Banned Password List"
        Type = "Script"
        Logic = {
            try {
    
                $directorySettings = Get-MgBetaDirectorySetting
                
    
                if ($directorySettings.Count -eq 0) {
                    Write-Host "No directory settings found." -ForegroundColor Red
                    Write-Host "FAIL: Custom Banned Password List is empty." -ForegroundColor Red
                    return
                }
    
                $bannedPasswordListEmpty = $true
    
                foreach ($setting in $directorySettings) {
                    try {
                        $settingDetails = Get-MgBetaDirectorySetting -DirectorySettingId $setting.Id
    
                        $bannedPasswordList = $settingDetails.Values | Where-Object { $_.Name -eq "BannedPasswordList" }
    
                        if ($bannedPasswordList -and $bannedPasswordList.Value -ne "") {
                            Write-Host "Custom Banned Password List Details for ID $($setting.Id):" -ForegroundColor Green
                            $bannedPasswordList | Format-Table Name, Value -AutoSize
                        
                            $bannedPasswordListEmpty = $false
                        } else {
                            Write-Host "No banned password list found for ID $($setting.Id)." -ForegroundColor Yellow
                        }
                    } catch {
                        Write-Host "Error retrieving details for Directory Setting ID $($setting.Id)" -ForegroundColor Red
                        Write-Host $_.Exception.Message
                    }
                }
                Write-Host ""
                Write-Host ""
    
                if ($bannedPasswordListEmpty) {
                    Write-Host "FAIL: Custom Banned Password List is empty for all settings." -ForegroundColor Red
                } else {
                    Write-Host "PASS: Custom Banned Password List is configured." -ForegroundColor Green
                }
            } catch {
                Write-Host "Error retrieving directory settings." -ForegroundColor Red
                Write-Host $_.Exception.Message
            }
        }
    },    
    @{
        Name = "5.2.3.3 On-Prem Password Protection"
        Type = "Manual"
        Link = "https://entra.microsoft.com/#view/Microsoft_AAD_IAM/AuthenticationMethodsMenuBlade/~/PasswordProtection/fromNav/Identity"
        explanation = {
            Verify password protection is enabled
            Ensure 'Enable password protection on Windows Server Active Directory' is set 'Yes' and Mode is set to 'Enforced'
        }
    },
    @{
        Name = "5.2.3.4 All Users MFA Capable"
        Type = "Script"
        Logic = {
            Get-MgReportAuthenticationMethodUserRegistrationDetail `
                -Filter "IsMfaCapable eq false and UserType eq 'Member'" `
                | Format-Table UserPrincipalName, IsMfaCapable, IsAdmin
        }
    },
    @{
        Name = "5.2.3.5 Weak Authentication Methods Disabled"
        Type = "Manual"
        Link = "https://entra.microsoft.com/#view/Microsoft_AAD_IAM/AuthenticationMethodsMenuBlade/~/AdminAuthMethods/fromNav/Identity"
        explanation = {
            Verify weak authentication methods are not used
            Ensure 'SMS, Voice Call, and Email OTP' are set to 'No'
        }
    },
    @{
        Name = "5.2.4.1 Self-Service Password Reset"
        Type = "Script"
        Logic = {
            try {

                Get-MgPolicyAuthenticationMethodPolicy | Format-Table -AutoSize
            } catch {
                Write-Host "Error retrieving Self-Service Password Reset policies" -ForegroundColor Red
                Write-Host $_.Exception.Message
            }
        }
    },
    @{
        Name = "5.3.1 Privileged Identity Management"
        Type = "Manual"
        Link = "https://entra.microsoft.com/#view/Microsoft_Azure_PIMCommon/ResourceMenuBlade/~/roles/resourceId//resourceType/tenant/provider/aadroles"
        explanation = {
            Verify sensitive roles do not have a permanent role
            Click on sensitive roles such as Application Administrator -> select 'role settings' in the left pane.
            Ensure 'Allow permanent eligible assignment' and 'Allow permanent active assignment' is set to 'No'
        }
    },
    @{
        Name = "5.3.2 Access Reviews for Guest Users"
        Type = "Manual"
        Link = "https://entra.microsoft.com/#view/Microsoft_AAD_ERM/DashboardBlade/~/Controls?Microsoft_AAD_IAM_legacyAADRedirect=true"
        explanation = {
            Verify access reviews exist for guest users
            Policy must meet the following, Overview: Scope is set to Guest users only and status is Active
        }
    },
    @{
        Name = "5.3.3 Access Reviews for Privileged Roles"
        Type = "Manual"
        Link = "https://entra.microsoft.com/#view/Microsoft_AAD_ERM/DashboardBlade/~/Controls?Microsoft_AAD_IAM_legacyAADRedirect=true"
        explanation = {
            Verify access reviews exist for guest users
            Policy must meet the following, Scope: Everyone and status is Active
        }
    },
    @{
        Name = "5.3.4 Global Admin Role Approval"
        Type = "Manual"
        Link = "https://entra.microsoft.com/#view/Microsoft_Azure_PIMCommon/UserRolesViewModelMenuBlade/~/settings/menuId/members/roleName/Global%20Administrator/roleObjectId/62e90394-69f5-4237-9190-012177145e10/isRoleCustom~/false/roleTemplateId/62e90394-69f5-4237-9190-012177145e10/resourceId/816e01e5-e687-4437-bb2b-5e1507d3f8bb/isInternalCall~/true?Microsoft_AAD_IAM_legacyAADRedirect=true"
        explanation = {
            Ensure approval is required for Global Admin activation
            Click on Global Administrator -> select 'role settings' in the left pane.
            Ensure 'Require approval to activate' is set to 'Yes'
        }
    },
    @{
        Name = "6.1.1 Audit Disabled"
        Type = "Script"
        Logic = {
            try {
    
                $orgConfig = Get-OrganizationConfig | Select-Object AuditDisabled
                $orgConfig | Format-Table -AutoSize
                Write-Host ""
                Write-Host ""
    
                if ($orgConfig.AuditDisabled -eq $false) {
                    Write-Host "PASS: Audit is not disabled (AuditDisabled = False)." -ForegroundColor Green
                } elseif ($orgConfig.AuditDisabled -eq $true) {
                    Write-Host "FAIL: Audit is disabled (AuditDisabled = True)." -ForegroundColor Red
                } else {
                    Write-Host "FAIL: Unable to determine the AuditDisabled status." -ForegroundColor Red
                }
    
            } catch {
                Write-Host "Error retrieving organization configuration." -ForegroundColor Red
                Write-Host $_.Exception.Message
            }
        }
    },    
    @{
        Name = "6.1.2 Mailbox Auditing for E3 Users"
        Type = "Script"
        Logic = {
            try {

                $mailAudit = Get-EXOMailbox -PropertySets Audit -ResultSize Unlimited | 
                             Select-Object UserPrincipalName, AuditEnabled, AuditAdmin, AuditDelegate, AuditOwner

                if ($mailAudit.Count -eq 0) {
                    Write-Host "No mailbox audit data found." -ForegroundColor Yellow
                    return
                }

                $outputPath = "C:\Windows\Temp\AuditSettings.csv"
                $mailAudit | Export-Csv -Path $outputPath -NoTypeInformation
                Write-Host "Mailbox audit settings exported to: $outputPath" -ForegroundColor Green

                $mailAudit | Format-Table -AutoSize
                Write-Host ""
                Write-Host ""
            } catch {
                Write-Host "Error retrieving mailbox audit settings." -ForegroundColor Red
                Write-Host $_.Exception.Message
            }
        }
    },
    @{
        Name = "6.1.4 Audit Bypass Enabled"
        Type = "Script"
        Logic = {
            try {
    
                $MBX = Get-MailboxAuditBypassAssociation -ResultSize unlimited
    
                $auditBypassEnabled = $MBX | Where-Object { $_.AuditBypassEnabled -eq $true }
    
                if (-not $auditBypassEnabled) {
                    Write-Host "PASS: No Audit Bypass Enabled entries found." -ForegroundColor Green
                } else {
                    $auditBypassEnabled | Format-Table Name, AuditBypassEnabled -AutoSize
                    Write-Host ""
                    Write-Host ""
                    Write-Host "FAIL: Audit Bypass Enabled entries found." -ForegroundColor Red
                    
                }
            } catch {
                Write-Host "Error retrieving Audit Bypass Enabled settings." -ForegroundColor Red
                Write-Host $_.Exception.Message
            }
        }
    },        
    @{
        Name = "6.2.1 Mail Forwarding Blocked or Disabled"
        Type = "Script"
        Logic = {
            Get-TransportRule | Where-Object {$_.RedirectMessageTo -ne $null} | Format-Table Name, RedirectMessageTo
            Get-HostedOutboundSpamFilterPolicy | Format-Table Name, AutoForwardingMode
        }
    },
    @{
        Name = "6.2.2 Whitelisted Domains"
        Type = "Script"
        Logic = {
            try {
    
                $whitelistedDomains = Get-TransportRule | Where-Object { ($_.SetScl -eq -1 -and $_.SenderDomainIs -ne $null) }
    
                if ($whitelistedDomains) {
                    $whitelistedDomains | Format-Table Name, SenderDomainIs -AutoSize
                    Write-Host ""
                    Write-Host ""
                    Write-Host "FAIL: Whitelisted Domains Found" -ForegroundColor Red
                    
                } else {
                    Write-Host "PASS: No transport rules with whitelisted domains found." -ForegroundColor Green
                }
            } catch {
                Write-Host "Error retrieving whitelisted domains in transport rules." -ForegroundColor Red
                Write-Host $_.Exception.Message
            }
        }
    },    
    @{
        Name = "6.2.3 External in Outlook"
        Type = "Script"
        Logic = {
            try {
                $outlookSettings = Get-ExternalInOutlook
    
                $outlookSettings | Format-List
    
                Write-Host "" 
                Write-Host ""
    
                if ($outlookSettings.Enabled -eq $true) {
                    Write-Host "PASS: 'External in Outlook' is Enabled." -ForegroundColor Green
                } else {
                    Write-Host "FAIL: 'External in Outlook' is Disabled or not configured correctly." -ForegroundColor Red
                }
            } catch {
                Write-Host "Error retrieving 'External in Outlook' settings." -ForegroundColor Red
                Write-Host $_.Exception.Message
            }
        }
    },    
    @{
        Name = "6.5.1 Modern Auth for Exchange Online"
        Type = "Script"
        Logic = {
            try {
    
                $orgConfig = Get-OrganizationConfig | Select-Object OAuth2ClientProfileEnabled
    
                if ($orgConfig.OAuth2ClientProfileEnabled -eq $true) {
                    Write-Host "PASS: Modern Authentication (OAuth2ClientProfileEnabled) is Enabled." -ForegroundColor Green
                } else {
                    $orgConfig
                    Write-Host ""
                    Write-Host ""
                    Write-Host "FAIL: Modern Authentication (OAuth2ClientProfileEnabled) is Disabled or not configured." -ForegroundColor Red
                }
            } catch {
                Write-Host "Error retrieving Modern Authentication configuration." -ForegroundColor Red
                Write-Host $_.Exception.Message
            }
        }
    },    
    @{
        Name = "6.5.2 MailTips"
        Type = "Script"
        Logic = {
            try {
    
                $mailTips = Get-OrganizationConfig | Select-Object MailTipsAllTipsEnabled, MailTipsExternalRecipientsTipsEnabled, MailTipsGroupMetricsEnabled
    
                $mailTips | Format-Table -AutoSize
                Write-Host ""
                Write-Host ""
    
                if ($mailTips.MailTipsAllTipsEnabled -eq $true -and 
                    $mailTips.MailTipsExternalRecipientsTipsEnabled -eq $true -and 
                    $mailTips.MailTipsGroupMetricsEnabled -eq $true) {
                    Write-Host "PASS: All required MailTips settings are enabled." -ForegroundColor Green
                } else {
                    Write-Host "FAIL: One or more required MailTips settings are not enabled." -ForegroundColor Red
                }
            } catch {
                Write-Host "Error retrieving MailTips settings." -ForegroundColor Red
                Write-Host $_.Exception.Message
            }
        }
    },    
    @{
        Name = "6.5.3 Additional Storage Providers"
        Type = "Script"
        Logic = {
            try {
    
                $owaPolicies = Get-OwaMailboxPolicy | Select-Object Name, AdditionalStorageProvidersAvailable
    
                $owaPolicies | Format-Table -AutoSize
                Write-Host ""
                Write-Host ""
    
                if ($owaPolicies.AdditionalStorageProvidersAvailable -contains $true) {
                    Write-Host "FAIL: One or more policies have AdditionalStorageProvidersAvailable set to True." -ForegroundColor Red
                } else {
                    Write-Host "PASS: All policies have AdditionalStorageProvidersAvailable set to False." -ForegroundColor Green
                }
            } catch {
                Write-Host "Error retrieving Additional Storage Providers settings." -ForegroundColor Red
                Write-Host $_.Exception.Message
            }
        }
    },    
    @{
        Name = "6.5.4 SMTP Auth Disabled"
        Type = "Script"
        Logic = {
            try {
    
                $smtpAuthConfig = Get-TransportConfig | Select-Object -ExpandProperty SmtpClientAuthenticationDisabled
                Write-Host ""
                Write-Host ""
                Write-Host "SmtpClientAuthenticationDisabled"
                Write-Host "--------------------------------"
                Write-Host "$smtpAuthConfig" -ForegroundColor Yellow
                Write-Host ""
                Write-Host ""
    
                if ($smtpAuthConfig -eq $false) {
                    Write-Host "FAIL: SMTP Client Authentication is not disabled (set to false)." -ForegroundColor Red
                } else {
                    Write-Host "PASS: SMTP Client Authentication is disabled (set to true)." -ForegroundColor Green
                }
            } catch {
                Write-Host "Error retrieving SMTP client authentication settings." -ForegroundColor Red
                Write-Host $_.Exception.Message
            }
        }
    },
    @{
        Name = "7.2.1 SharePoint Modern Authentication"
        Type = "Manual"
        Link = {
            try {
                $rootSite = Get-MgSite -SiteId root
                $webUrl = $rootSite.WebUrl

                if ($webUrl -match 'https://([^\.]+)') {
                    $tenantName = $matches[1]
                    "https://${tenantName}-admin.sharepoint.com/_layouts/15/online/AdminHome.aspx#/accessControl/LegacyAuthentication"
                } else {
                    Write-Host "Failed to extract tenant name from WebUrl: $webUrl" -ForegroundColor Red
                }
                
            } catch {
                Write-Host "Error retrieving root site or processing URL." -ForegroundColor Red
                Write-Host $_.Exception.Message
            }
        
        }
        explanation = {
            Verify that 'Block Access' is selected
        }
    },
    @{
        Name = "7.2.3-7.2.11 SharePoint and OneDrive Settings"
        Type = "Manual"
        Link = {
            try {
                $rootSite = Get-MgSite -SiteId root
                $webUrl = $rootSite.WebUrl

                if ($webUrl -match 'https://([^\.]+)') {
                    $tenantName = $matches[1]
                    "https://${tenantName}-admin.sharepoint.com/_layouts/15/online/AdminHome.aspx#/sharing"
                } else {
                    Write-Host "Failed to extract tenant name from WebUrl: $webUrl" -ForegroundColor Red
                }
            } catch {
                Write-Host "Error retrieving root site or processing URL." -ForegroundColor Red
                Write-Host $_.Exception.Message
            }
        }
        explanation = {
            "7.2.3-7.2.4: Verify SharePoint and OneDrive content share settings are not set to 'Anyone'"
            "7.2.5: Expand more external sharing settings -> verify 'allow guest users to share items they don't own' is NOT selected"
            "7.2.6: Ensure Limit external sharing by domain is selected"
            "7.2.7: Ensure file and folder links is configured for 'Specific people (only the people the user specifies)'"
            "7.2.8: Ensure Allow only users in specific security groups to share externally is selected"
            "7.2.9: Ensure Guest access to a site or OneDrive will expire automatically is selected"
            "7.2.10: Ensure People who use a verification code must reauthenticate after this many days is selected and set to 15 or less"
            "7.2.11: Ensure Choose the permission that's selected by default for sharing links is set to View"
        }
    },
    @{
        Name = "7.3.2 Ensure OneDrive Sync is Restricted"
        Type = "Manual"
        Link = {
            try {
                $rootSite = Get-MgSite -SiteId root
                $webUrl = $rootSite.WebUrl

                if ($webUrl -match 'https://([^\.]+)') {
                    $tenantName = $matches[1]
                    "https://${tenantName}-admin.sharepoint.com/_layouts/15/online/AdminHome.aspx#/settings/ODBSync"
                } else {
                    Write-Host "Failed to extract tenant name from WebUrl: $webUrl" -ForegroundColor Red
                }
            } catch {
                Write-Host "Error retrieving root site or processing URL." -ForegroundColor Red
                Write-Host $_.Exception.Message
            }
        }
        explanation = {
            Ensure 'Show the Sync button on the OneDrive website' is NOT selected
        }
    },        
    @{
        Name = "8.1.1 External File Sharing in Teams"
        Type = "Script"
        Logic = {
            Get-CsTeamsClientConfiguration | Format-List AllowDropbox, AllowBox, AllowGoogleDrive, AllowShareFile, AllowEgnyte
        }
    },
    @{
        Name = "8.1.2 Email into Teams Channel"
        Type = "Script"
        Logic = {
            try {
    
                $teamsConfig = Get-CsTeamsClientConfiguration -Identity Global | Select-Object AllowEmailIntoChannel
    
                Write-Host ""
                $teamsConfig | Format-List
                Write-Host ""
                Write-Host ""
    
                if ($teamsConfig.AllowEmailIntoChannel -eq $true) {
                    Write-Host "FAIL: AllowEmailIntoChannel is set to True." -ForegroundColor Red
                } elseif ($teamsConfig.AllowEmailIntoChannel -eq $false) {
                    Write-Host "PASS: AllowEmailIntoChannel is set to False." -ForegroundColor Green
                } else {
                    Write-Host "Unknown value for AllowEmailIntoChannel." -ForegroundColor Yellow
                }
            } catch {
                Write-Host "Error retrieving Teams Client Configuration." -ForegroundColor Red
                Write-Host $_.Exception.Message
            }
        }
    },
    @{
        Name = "8.2.1 Teams Federation Configuration"
        Type = "Script"
        Logic = {
            try {
    
                $federationConfig = Get-CsTenantFederationConfiguration | Select-Object AllowFederatedUsers, AllowedDomains
                Write-Host ""
                $federationConfig | Format-List
                Write-Host ""
                Write-Host ""
    
                if ($federationConfig.AllowFederatedUsers -eq $false) {
                    Write-Host "PASS: AllowFederatedUsers is set to False." -ForegroundColor Green
                } elseif ($federationConfig.AllowFederatedUsers -eq $true) {
                    if ($federationConfig.AllowedDomains -contains "AllowAllKnownDomains") {
                        Write-Host "FAIL: AllowedDomains is set to AllowAllKnownDomains." -ForegroundColor Red
                    } elseif ($federationConfig.AllowedDomains.Count -eq 0) {
                        Write-Host "FAIL: AllowFederatedUsers is True but no domains are explicitly allowed." -ForegroundColor Red
                    } else {
                        Write-Host "PASS: AllowFederatedUsers is True and authorized domains are specified." -ForegroundColor Green
                    }
                } else {
                    Write-Host "Unknown configuration for AllowFederatedUsers." -ForegroundColor Yellow
                }
            } catch {
                Write-Host "Error retrieving Teams Federation Configuration." -ForegroundColor Red
                Write-Host $_.Exception.Message
            }
        }
    },
    @{
        Name = "8.2.2 Teams Communication Settings"
        Type = "Script"
        Logic = {
            try {
    
                $consumerFederationConfig = Get-CsTenantFederationConfiguration | Select-Object AllowTeamsConsumer
    
                Write-Host "" 
                $consumerFederationConfig | Format-List
                Write-Host ""
                Write-Host ""
    
                if ($consumerFederationConfig.AllowTeamsConsumer -eq $false) {
                    Write-Host "PASS: AllowTeamsConsumer is set to False." -ForegroundColor Green
                } else {
                    Write-Host "FAIL: AllowTeamsConsumer is set to True." -ForegroundColor Red
                }
            } catch {
                Write-Host "Error retrieving Teams Consumer Federation Configuration." -ForegroundColor Red
                Write-Host $_.Exception.Message
            }
        }
    },
    @{
        Name = "8.2.3 External Teams Communication"
        Type = "Script"
        Logic = {
            try {
    
                $inboundConfig = Get-CsTenantFederationConfiguration | Select-Object AllowTeamsConsumerInbound
    
                Write-Host ""
                $inboundConfig | Format-List
                Write-Host ""
                Write-Host ""
    
                if ($inboundConfig.AllowTeamsConsumerInbound -eq $false) {
                    Write-Host "PASS: AllowTeamsConsumerInbound is set to False." -ForegroundColor Green
                } else {
                    Write-Host "FAIL: AllowTeamsConsumerInbound is set to True." -ForegroundColor Red
                }
            } catch {
                Write-Host "Error retrieving Teams Consumer Federation Inbound Configuration." -ForegroundColor Red
                Write-Host $_.Exception.Message
            }
        }
    },
    @{
        Name = "8.2.4 Communication with Skype users"
        Type = "Script"
        Logic = {
            try {
    
                $publicUserConfig = Get-CsTenantFederationConfiguration | Select-Object AllowPublicUsers
    
                Write-Host "" -ForegroundColor Yellow
                $publicUserConfig | Format-List
                Write-Host ""
                Write-Host ""
    
                if ($publicUserConfig.AllowPublicUsers -eq $false) {
                    Write-Host "PASS: AllowPublicUsers is set to False." -ForegroundColor Green
                } else {
                    Write-Host "FAIL: AllowPublicUsers is set to True." -ForegroundColor Red
                }
            } catch {
                Write-Host "Error retrieving Teams Public Federation Configuration." -ForegroundColor Red
                Write-Host $_.Exception.Message
            }
        }
    },
    @{
        Name = "8.5.1 Anonymous Users Joining Teams Meetings"
        Type = "Script"
        Logic = {
            try {
    
                $meetingPolicyConfig = Get-CsTeamsMeetingPolicy -Identity Global | Select-Object AllowAnonymousUsersToJoinMeeting
                Write-Host ""
                $meetingPolicyConfig | Format-List
    
                Write-Host ""
                Write-Host ""
    
                if ($meetingPolicyConfig.AllowAnonymousUsersToJoinMeeting -eq $false) {
                    Write-Host "PASS: AllowAnonymousUsersToJoinMeeting is set to False." -ForegroundColor Green
                } else {
                    Write-Host "FAIL: AllowAnonymousUsersToJoinMeeting is set to True." -ForegroundColor Red
                }
            } catch {
                Write-Host "Error retrieving Teams Meeting Policy Configuration." -ForegroundColor Red
                Write-Host $_.Exception.Message
            }
        }
    },
    @{
        Name = "8.5.2 Anonymous Users Starting Teams Meetings"
        Type = "Script"
        Logic = {
            try {
    
                $meetingPolicyConfig = Get-CsTeamsMeetingPolicy -Identity Global | Select-Object AllowAnonymousUsersToStartMeeting
                Write-Host ""
                $meetingPolicyConfig | Format-List
    
                Write-Host ""
                Write-Host ""
    
                if ($meetingPolicyConfig.AllowAnonymousUsersToStartMeeting -eq $false) {
                    Write-Host "PASS: AllowAnonymousUsersToStartMeeting is set to False." -ForegroundColor Green
                } else {
                    Write-Host "FAIL: AllowAnonymousUsersToStartMeeting is set to True." -ForegroundColor Red
                }
            } catch {
                Write-Host "Error retrieving Teams Meeting Policy Configuration." -ForegroundColor Red
                Write-Host $_.Exception.Message
            }
        }
    },
    @{
        Name = "8.5.3 Teams lobby bypass"
        Type = "Script"
        Logic = {
            try {
    
                $meetingPolicyConfig = Get-CsTeamsMeetingPolicy -Identity Global | Select-Object AutoAdmittedUsers
                Write-Host ""
                $meetingPolicyConfig | Format-List
    
                Write-Host ""
                Write-Host ""
    
                if ($meetingPolicyConfig.AutoAdmittedUsers -eq "EveryoneInCompanyExcludingGuests") {
                    Write-Host "PASS: AutoAdmittedUsers is set to EveryoneInCompanyExcludingGuests." -ForegroundColor Green
                } else {
                    Write-Host "FAIL: Expected value - EveryoneInCompanyExcludingGuests." -ForegroundColor Red
                }
            } catch {
                Write-Host "Error retrieving Teams Meeting Policy Configuration." -ForegroundColor Red
                Write-Host $_.Exception.Message
            }
        }
    },
    @{
        Name = "8.5.4 Dial-in Users Bypass Lobby"
        Type = "Script"
        Logic = {
            try {
    
                $meetingPolicyConfig = Get-CsTeamsMeetingPolicy -Identity Global | Select-Object AllowPSTNUsersToBypassLobby
                Write-Host ""
                $meetingPolicyConfig | Format-List
    
                Write-Host ""
                Write-Host ""
    
                if ($meetingPolicyConfig.AllowPSTNUsersToBypassLobby -eq $false) {
                    Write-Host "PASS: AllowPSTNUsersToBypassLobby is set to False." -ForegroundColor Green
                } else {
                    Write-Host "FAIL: AllowPSTNUsersToBypassLobby is not set to False." -ForegroundColor Red
                }
            } catch {
                Write-Host "Error retrieving Teams Meeting Policy Configuration." -ForegroundColor Red
                Write-Host $_.Exception.Message
            }
        }
    },
    @{
        Name = "8.5.5 Meeting Chat Enabled"
        Type = "Script"
        Logic = {
            try {
    
                $meetingPolicyConfig = Get-CsTeamsMeetingPolicy -Identity Global | Select-Object MeetingChatEnabledType
                Write-Host ""
                $meetingPolicyConfig | Format-List
    
                Write-Host ""
                Write-Host ""
    
                if ($meetingPolicyConfig.MeetingChatEnabledType -eq "EnabledExceptAnonymous") {
                    Write-Host "PASS: MeetingChatEnabledType is set to EnabledExceptAnonymous." -ForegroundColor Green
                } else {
                    Write-Host "FAIL: Expected value - EnabledExceptAnonymous." -ForegroundColor Red
                }
            } catch {
                Write-Host "Error retrieving Teams Meeting Policy Configuration." -ForegroundColor Red
                Write-Host $_.Exception.Message
            }
        }
    },
    @{
        Name = "8.5.6 Presenter settings"
        Type = "Script"
        Logic = {
            try {
    
                $meetingPolicyConfig = Get-CsTeamsMeetingPolicy -Identity Global | Select-Object DesignatedPresenterRoleMode
                Write-Host ""
                $meetingPolicyConfig | Format-List
    
                Write-Host ""
                Write-Host ""
    
                if ($meetingPolicyConfig.DesignatedPresenterRoleMode -eq "OrganizerOnlyUserOverride") {
                    Write-Host "PASS: DesignatedPresenterRoleMode is set to OrganizerOnlyUserOverride." -ForegroundColor Green
                } else {
                    Write-Host "FAIL: Expected value - OrganizerOnlyUserOverride." -ForegroundColor Red
                }
            } catch {
                Write-Host "Error retrieving Teams Meeting Policy Configuration." -ForegroundColor Red
                Write-Host $_.Exception.Message
            }
        }
    },
    @{
        Name = "8.5.7 External Participant Give Control in Teams Meetings"
        Type = "Script"
        Logic = {
            try {
    
                $meetingPolicyConfig = Get-CsTeamsMeetingPolicy -Identity Global | Select-Object AllowExternalParticipantGiveRequestControl
                Write-Host ""
                $meetingPolicyConfig | Format-List
    
                Write-Host ""
                Write-Host ""
    
                if ($meetingPolicyConfig.AllowExternalParticipantGiveRequestControl -eq $false) {
                    Write-Host "PASS: AllowExternalParticipantGiveRequestControl is set to False." -ForegroundColor Green
                } else {
                    Write-Host "FAIL: AllowExternalParticipantGiveRequestControl is not set to False." -ForegroundColor Red
                }
            } catch {
                Write-Host "Error retrieving Teams Meeting Policy Configuration." -ForegroundColor Red
                Write-Host $_.Exception.Message
            }
        }
    },
    @{
        Name = "8.5.8 External Non-Trusted Meeting Chat in Teams Meetings"
        Type = "Script"
        Logic = {
            try {
    
                $meetingPolicyConfig = Get-CsTeamsMeetingPolicy -Identity Global | Select-Object AllowExternalNonTrustedMeetingChat
                Write-Host ""
                $meetingPolicyConfig | Format-List
    
                Write-Host ""
                Write-Host ""
    
                if ($meetingPolicyConfig.AllowExternalNonTrustedMeetingChat -eq $false) {
                    Write-Host "PASS: AllowExternalNonTrustedMeetingChat is set to False." -ForegroundColor Green
                } else {
                    Write-Host "FAIL: AllowExternalNonTrustedMeetingChat is not set to False." -ForegroundColor Red
                }
            } catch {
                Write-Host "Error retrieving Teams Meeting Policy Configuration." -ForegroundColor Red
                Write-Host $_.Exception.Message
            }
        }
    },
    @{
        Name = "8.5.9 Allow Cloud Recording in Teams Meetings"
        Type = "Script"
        Logic = {
            try {
    
                $meetingPolicyConfig = Get-CsTeamsMeetingPolicy -Identity Global | Select-Object AllowCloudRecording
                Write-Host ""
                $meetingPolicyConfig | Format-List
    
                Write-Host ""
                Write-Host ""
    
                if ($meetingPolicyConfig.AllowCloudRecording -eq $false) {
                    Write-Host "PASS: AllowCloudRecording is set to False." -ForegroundColor Green
                } else {
                    Write-Host "FAIL: AllowCloudRecording is not set to False." -ForegroundColor Red
                }
            } catch {
                Write-Host "Error retrieving Teams Meeting Policy Configuration." -ForegroundColor Red
                Write-Host $_.Exception.Message
            }
        }
    },
    @{
        Name = "8.6.1 Teams and Defender Reporting Policies"
        Type = "Script"
        Logic = {
            try {
                $orgDomains = (Get-MgOrganization).VerifiedDomains | ForEach-Object { $_.Name }
                $orgDomainsRegex = $orgDomains -join "|"
    
                Write-Host ""
                $teamsMessagingPolicy = Get-CsTeamsMessagingPolicy -Identity Global | Select-Object AllowSecurityEndUserReporting
                $teamsMessagingPolicy | Format-List
    
                Write-Host ""
                Write-Host ""
    
                if ($teamsMessagingPolicy.AllowSecurityEndUserReporting -eq $true) {
                    Write-Host "PASS: AllowSecurityEndUserReporting is set to True." -ForegroundColor Green
                } else {
                    Write-Host "FAIL: AllowSecurityEndUserReporting is not set to True." -ForegroundColor Red
                }
    
                $defenderPolicy = Get-ReportSubmissionPolicy | Select-Object ReportJunkToCustomizedAddress, ReportNotJunkToCustomizedAddress, ReportPhishToCustomizedAddress, ReportJunkAddresses, ReportNotJunkAddresses, ReportPhishAddresses, ReportChatMessageEnabled, ReportChatMessageToCustomizedAddressEnabled
                $defenderPolicy | Format-List
    
                Write-Host ""
                Write-Host ""
    
                $expectedValues = @{
                    ReportJunkToCustomizedAddress             = $true
                    ReportNotJunkToCustomizedAddress          = $true
                    ReportPhishToCustomizedAddress            = $true
                    ReportChatMessageEnabled                  = $false
                    ReportChatMessageToCustomizedAddressEnabled = $true
                }
    
                $misconfigurations = $false
    
                foreach ($key in @("ReportJunkAddresses", "ReportNotJunkAddresses", "ReportPhishAddresses")) {
                    $values = $defenderPolicy.$key
                    if ($values -and $values -notcontains $null) {
                        foreach ($email in $values) {
                            if (-not $email -match "@($orgDomainsRegex)$") {
                                Write-Host "$key contains unauthorized email: $email > Desired: Email ending with any of $($orgDomains -join ', ')" -ForegroundColor Red
                                $misconfigurations = $true
                            }
                        }
                    } else {
                        Write-Host "$key is empty or null > Desired: At least one email ending with any of $($orgDomains -join ', ')" -ForegroundColor Red
                        $misconfigurations = $true
                    }
                }
    
                foreach ($key in $expectedValues.Keys) {
                    if ($key -notin @("ReportJunkAddresses", "ReportNotJunkAddresses", "ReportPhishAddresses")) {
                        if ($defenderPolicy.$key -ne $expectedValues[$key]) {
                            Write-Host "{$key}: $($defenderPolicy.$key) > Desired: $($expectedValues[$key])" -ForegroundColor Red
                            $misconfigurations = $true
                        }
                    }
                }
    
                Write-Host ""
                Write-Host ""
    
                if (-not $misconfigurations) {
                    Write-Host "PASS: Defender Report Submission Policy matches expected configuration." -ForegroundColor Green
                } else {
                    Write-Host "FAIL: Defender Report Submission Policy has misconfigurations." -ForegroundColor Red
                }
    
            } catch {
                Write-Host "Error retrieving policy configurations." -ForegroundColor Red
                Write-Host $_.Exception.Message
            }
        }
    }
    
)

foreach ($script in $scripts) {
    Write-Host "=============================================================" -ForegroundColor Yellow
    Write-Host "Running: $($script.Name)" -ForegroundColor Cyan
    Write-Host "=============================================================" -ForegroundColor Yellow

    if ($script.Type -eq "Script") {
        try {
            & $script.Logic
            Start-Sleep -Seconds 3
        } catch {
            Write-Host "Error running script: $($script.Name)" -ForegroundColor Red
            Write-Host $_.Exception.Message
        }
    } elseif ($script.Type -eq "Manual") {
        Write-Host "Manual check required for $($script.Name)" -ForegroundColor Yellow

        $link = if ($script.Link -is [scriptblock]) {
            & $script.Link
        } else {
            $script.Link
        }

        Write-Host "Please visit: $link" -ForegroundColor Blue

        if ($script.Explanation) {
            Write-Host "`nExplanation:" -ForegroundColor Magenta
            foreach ($line in $script.Explanation) {
                Write-Host "$line" -ForegroundColor Cyan
            }
        }
        
        try {
            Start-Process $link
            Write-Host "Opening link in your default browser..." -ForegroundColor Green
        } catch {
            Write-Host "Failed to open browser for link: $link" -ForegroundColor Red
            Write-Host $_.Exception.Message
        }

        Start-Sleep -Seconds 3
    }
    Write-Host "`n"
}


Stop-Transcript
$logContent = Get-Content $transcriptFile
$htmlFile = "$PSScriptRoot\script_output.html"

$htmlContent = @"
<!DOCTYPE html>
<html lang=\"en\">
<head>
    <meta charset=\"UTF-8\">
    <meta name=\"viewport\" content=\"width=device-width, initial-scale=1.0\">
    <title>Microsoft 365 Benchmarks 4.0.0 Report</title>
    <link href=\"https://fonts.googleapis.com/css2?family=Fira+Code&display=swap\" rel=\"stylesheet\">
    <style>
        body {
            font-family: 'Fira Code', monospace;
            margin: 0;
            padding: 20px;
            background-color: #121212;
            color: #e0e0e0;
        }
        header {
            text-align: center;
            margin-bottom: 20px;
        }
        header h1 {
            font-size: 2em;
            color: #90caf9;
        }
        details {
            border: 1px solid #333;
            border-radius: 8px;
            margin: 10px 0;
            padding: 0.5em;
            background-color: #1e1e1e;
            box-shadow: 0 4px 6px rgba(0, 0, 0, 0.1);
        }
        details > summary {
            font-weight: bold;
            cursor: pointer;
            padding: 0.5em;
            background-color: #252525;
            border-radius: 8px;
            color: #ffffff;
            display: flex;
            justify-content: space-between;
            align-items: center;
        }
        details > summary.pass {
            color: #66bb6a;
        }
        details > summary.fail {
            color: #ef5350;
        }
        details > summary.manual {
            color: #ffa726;
        }
        details > summary.review {
            color: #ff9800;
        }
        details > summary:hover {
            background-color: #333333;
        }
        .status {
            font-size: 0.9em;
            padding: 0.2em 0.5em;
            border-radius: 4px;
            text-transform: uppercase;
        }
        .pass {
            color: #66bb6a;
        }
        .fail {
            color: #ef5350;
        }
        .manual {
            color: #ffa726;
        }
        .review {
            color: #ff9800;
        }
        details[open] pre {
            background-color: #23252e;
            color: #e0e0e0;
            padding: 10px;
            border-radius: 8px;
            font-size: 14px;
            overflow-x: auto;
        }
        pre {
            white-space: pre-wrap;
            word-wrap: break-word;
            margin: 0;
        }
        .reasoning {
            margin-top: 10px;
            padding: 5px 10px;
            font-size: 0.9em;
            cursor: pointer;
            color: #ffffff;
            background-color: #ef5350;
            border: none;
            border-radius: 4px;
        }
        .reasoning:hover {
            background-color: #c62828;
        }
        .reasoning-content {
            margin-top: 10px;
            padding: 10px;
            background-color: #333333;
            border-radius: 4px;
            display: none;
            color: #ffffff;
        }
    </style>
    <script>
    function toggleReasoning(button) {
        const reasoningContent = button.nextElementSibling;
        if (reasoningContent.style.display === "none" || reasoningContent.style.display === "") {
            reasoningContent.style.display = "block";
            button.textContent = "Hide Reasoning";
        } else {
            reasoningContent.style.display = "none";
            button.textContent = "Show Reasoning";
        }
    }

    document.addEventListener("DOMContentLoaded", () => {
        const reasoningElements = document.querySelectorAll(".reasoning-content");
        reasoningElements.forEach((element) => {
            element.style.display = "none";
        });
    });
    </script>
</head>
<body>
    <header>
        <h1>Script Execution Report</h1>
    </header>
"@

$currentFunction = ""
$outputBuffer = @()
$reasoning = ""
$status = "review"  
foreach ($line in $logContent) {
    if ($line -match "Running: (.+)") {
        if ($currentFunction -ne "") {
            $summaryClass = if ($status -eq "fail") { "fail" } elseif ($status -eq "pass") { "pass" } elseif ($status -eq "manual") { "manual" } else { "review" }

            $htmlContent += "<details><summary class='$summaryClass'>$currentFunction - $status</summary>"
            $htmlContent += "<pre>" + ($outputBuffer -join "`n") + "</pre>"
            if ($reasoning -ne "") {
                $htmlContent += "<button class='reasoning' onclick='toggleReasoning(this)'>Show Reasoning</button>"
                $htmlContent += "<div class='reasoning-content'>$reasoning</div>"
            }
            $htmlContent += "</details>"
        }
        $currentFunction = $matches[1]
        $outputBuffer = @()
        $reasoning = ""
        $status = "review" 
    } elseif ($line -match "PASS:(.+)" -or $line -match "(?i)^pass$") {
        $outputBuffer += "<span class='pass'>" + $line.Trim() + "</span>"
        $status = "pass"
    } elseif ($line -match "FAIL:(.+)" -or $line -match "(?i)^fail$") {
        $reasoning = $line.Trim()
        $status = "fail"
        $outputBuffer += "<span class='fail'>" + $line.Trim() + "</span>"
    } elseif ($line -match "(?i)manual check required") {
        $status = "manual"
        $outputBuffer += "<span class='manual'>" + $line.Trim() + "</span>"
    } else {
        $outputBuffer += $line.Trim()
    }
}

if ($currentFunction -ne "") {
    $summaryClass = if ($status -eq "fail") { "fail" } elseif ($status -eq "pass") { "pass" } elseif ($status -eq "manual") { "manual" } else { "review" }

    $htmlContent += "<details><summary class='$summaryClass'>$currentFunction - $status</summary>"
    $htmlContent += "<pre>" + ($outputBuffer -join "`n") + "</pre>"
    if ($reasoning -ne "") {
        $htmlContent += "<button class='reasoning' onclick='toggleReasoning(this)'>Show Reasoning</button>"
        $htmlContent += "<div class='reasoning-content'>$reasoning</div>"
    }
    $htmlContent += "</details>"
}

$htmlContent += @"
</body>
</html>
"@

Set-Content -Path $htmlFile -Value $htmlContent
Write-Host "HTML Report generated: $htmlFile" -ForegroundColor Green
