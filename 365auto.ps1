param(
    [string]$tenantid     = $env:TENANT_ID,
    [ValidateSet("all", "html", "json", "console")]
    [string]$outputFormat = "all",
    [Alias("html-only")][switch]$HtmlOnly,

    [switch]$CertAuth,
    [string]$AppId,
    [string]$Thumbprint,
    [string]$Domain
)

# If the user requests HTML-only, force outputFormat and skip the scan
if ($HtmlOnly) {
    $outputFormat = "html"
}

# Set up paths with Linux compatibility
$transcriptFile = "$PSScriptRoot\script_output.log"
$jsonOutputFile = "$PSScriptRoot\results.json"

if (-not $HtmlOnly) {
    Start-Transcript -Path $transcriptFile -Append

    # Create results object for JSON output
    $jsonResults = @{}

    # Function to add a finding to the JSON results
    function Add-Finding {
        param(
            [Parameter(Mandatory=$true)]
            [string]$CheckId,
            
            [Parameter(Mandatory=$true)]
            [string]$Asset,
            
            [Parameter(Mandatory=$true)]
            [string]$Status,
            
            [Parameter(Mandatory=$true)]
            [string]$Name,
            
            [Parameter(Mandatory=$true)]
            [string]$Description,
            
            [Parameter(Mandatory=$false)]
            [string]$Remediation = "",
            
            [Parameter(Mandatory=$false)]
            [hashtable]$Details = @{},
            
            [Parameter(Mandatory=$false)]
            [string]$Impact = "Minor",
            
            [Parameter(Mandatory=$false)]
            [string]$Likelihood = "Low",
            
            [Parameter(Mandatory=$false)]
            [string]$Risk = "Medium"
        )
        
        $finding = @{
            "asset" = $Asset
            "status" = $Status
            "name" = $Name
            "description" = $Description
            "details" = $Details
            "impact" = $Impact
            "likelihood" = $Likelihood
            "risk" = $Risk
        }
        
        if (-not [string]::IsNullOrEmpty($Remediation)) {
            $finding["remediation"] = $Remediation
        }
        
        # Create the check ID array if it doesn't exist
        $fullCheckId = "CIS_O365_v4.0.0_$CheckId"
        if (-not $jsonResults.ContainsKey($fullCheckId)) {
            $jsonResults[$fullCheckId] = @()
        }
        
        # Add the finding to the appropriate check
        $jsonResults[$fullCheckId] += $finding
    }

    # Global flags to track service availability
    $Global:TeamsAvailable = $false
    $Global:MgGraphAvailable = $false
    $Global:ExchangeAvailable = $false
    $Global:SecurityComplianceAvailable = $false

    # Define global variables to store session information
    $Global:ExchangeOnlineSession = $null
    $Global:TeamsSession = $null
    $Global:MgGraphConnection = $null
    $Global:IPPSSession = $null

    function Authenticate-Once {
    Write-Host "Authenticating to Microsoft 365 services..." -ForegroundColor Cyan

    if ([System.Threading.Thread]::CurrentThread.ApartmentState -ne "STA") {
        Write-Host "Restarting in STA mode..." -ForegroundColor Yellow
        Start-Process -FilePath "powershell.exe" -ArgumentList "-STA", "-File", $MyInvocation.MyCommand.Path -Wait
        exit
    }

    try {
        if ($CertAuth) {
            Write-Host "Using certificate-based authentication..." -ForegroundColor Yellow

            Connect-MicrosoftTeams -CertificateThumbprint "$Thumbprint" -ApplicationId "$AppId" -TenantId "$tenantid"
            Write-Host "Connected to Microsoft Teams." -ForegroundColor Green

            Connect-MgGraph -CertificateThumbprint "$Thumbprint" -ClientId "$AppId" -TenantId "$tenantid" -NoWelcome
            Write-Host "Connected to Microsoft Graph." -ForegroundColor Green

            Connect-ExchangeOnline -CertificateThumbprint "$Thumbprint" -AppId "$AppId" -Organization "$Domain" -ShowBanner:$false
            Write-Host "Connected to Exchange Online." -ForegroundColor Green

            Connect-IPPSSession -CertificateThumbprint "$Thumbprint" -AppId "$AppId" -Organization "$Domain" -ShowBanner:$false
            Write-Host "Connected to Security & Compliance Center." -ForegroundColor Green

        } else {
            Write-Host "Using interactive authentication..." -ForegroundColor Yellow

            Connect-MicrosoftTeams
            Write-Host "Connected to Microsoft Teams." -ForegroundColor Green

            Connect-MgGraph -Scopes 'Policy.Read.All, Directory.Read.All, Sites.Read.All, AuditLog.Read.All, OrgSettings-Forms.Read.All, OrgSettings-AppsAndServices.Read.All, PeopleSettings.Read.All, AuditLogsQuery-SharePoint.Read.All, SecurityEvents.Read.All, SecurityActions.Read.All' -NoWelcome
            Write-Host "Connected to Microsoft Graph." -ForegroundColor Green

            Connect-ExchangeOnline
            Write-Host "Connected to Exchange Online." -ForegroundColor Green

            Connect-IPPSSession
            Write-Host "Connected to Security & Compliance Center." -ForegroundColor Green
        }

        $Global:TeamsAvailable = $true
        $Global:MgGraphAvailable = $true
        $Global:ExchangeAvailable = $true
        $Global:SecurityComplianceAvailable = $true

    } catch {
        Write-Host "Authentication failed:" -ForegroundColor Red
        Write-Host $_.Exception.Message
    }

    Write-Host "All services authenticated successfully!" -ForegroundColor Green
}

Authenticate-Once

# Initialize JSON output mode if scanning proceeds
    $Global:JsonOutputMode = ($outputFormat -eq "all" -or $outputFormat -eq "json")

    # Modify script execution to skip Exchange-dependent functions if Exchange is not available
    $scripts = @(
        @{
            Name = "1.1.3 Amount of Global Admins"
            Type = "Script"
            CheckId = "1.1.3"
            RequiresExchange = $false
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
                        
                        # Add finding to JSON results
                        Add-Finding -CheckId $script.CheckId `
                                -Asset "/tenants/$tenantid" `
                                -Status "FAIL" `
                                -Name "Global Administrators Check" `
                                -Description "The number of Global Administrators should be 8 or fewer." `
                                -Remediation "Reduce the number of users assigned to the Global Administrator role." `
                                -Details @{ "AdminCount" = $adminCount; "MaxRecommended" = 8 } `
                                -Impact "Moderate" `
                                -Likelihood "Moderate" `
                                -Risk "Medium"
                    } else {
                        Write-Host "Pass" -ForegroundColor Green
                        
                        # Add finding to JSON results
                        Add-Finding -CheckId $script.CheckId `
                                -Asset "/tenants/$tenantid" `
                                -Status "PASS" `
                                -Name "Global Administrators Check" `
                                -Description "The number of Global Administrators should be 8 or fewer." `
                                -Details @{ "AdminCount" = $adminCount; "MaxRecommended" = 8 }
                    }
                } catch {
                    Write-Host "Error checking Global Administrators." -ForegroundColor Red
                    Write-Host $_.Exception.Message
                    
                    # Add error finding to JSON results
                    Add-Finding -CheckId $script.CheckId `
                            -Asset "/tenants/$tenantid" `
                            -Status "ERROR" `
                            -Name "Global Administrators Check" `
                            -Description "Error occurred while checking Global Administrators." `
                            -Details @{ "ErrorMessage" = $_.Exception.Message }
                }
            }
        },
        @{
            Name = "1.1.4 Admin Licenses"
            Type = "Script"
            CheckId = "1.1.4"
            Logic = {
                try {
                    $DirectoryRoles = Get-MgDirectoryRole
                    $PrivilegedRoles = $DirectoryRoles | Where-Object { $_.DisplayName -like "*Administrator*" -or $_.DisplayName -eq "Global Reader" }
                    $RoleMembers = $PrivilegedRoles | ForEach-Object { Get-MgDirectoryRoleMember -DirectoryRoleId $_.Id } | Select-Object Id -Unique
                    $PrivilegedUsers = $RoleMembers | ForEach-Object { Get-MgUser -UserId $_.Id -Property UserPrincipalName, DisplayName, Id }
                    $Report = [System.Collections.Generic.List[Object]]::new()
                    $AdminsWithoutLicense = 0
                    
                    foreach ($Admin in $PrivilegedUsers) {
                        $License = (Get-MgUserLicenseDetail -UserId $Admin.id).SkuPartNumber -join ", "
                        $Object = [pscustomobject][ordered]@{
                            DisplayName = $Admin.DisplayName
                            UserPrincipalName = $Admin.UserPrincipalName
                            License = $License
                        }
                        $Report.Add($Object)
                        
                        # Check if admin has license
                        if ([string]::IsNullOrEmpty($License)) {
                            $AdminsWithoutLicense++
                            # Add finding to JSON results
                            Add-Finding -CheckId $script.CheckId `
                                    -Asset "/tenants/$tenantid/users/$($Admin.UserPrincipalName)" `
                                    -Status "FAIL" `
                                    -Name "Admin License Check" `
                                    -Description "Administrators should have appropriate licenses assigned." `
                                    -Remediation "Assign appropriate licenses to the administrator account." `
                                    -Details @{ "DisplayName" = $Admin.DisplayName; "UserPrincipalName" = $Admin.UserPrincipalName; "License" = "None" } `
                                    -Impact "Minor" `
                                    -Likelihood "Low" `
                                    -Risk "Medium"
                        } else {
                            # Add finding to JSON results
                            Add-Finding -CheckId $script.CheckId `
                                    -Asset "/tenants/$tenantid/users/$($Admin.UserPrincipalName)" `
                                    -Status "PASS" `
                                    -Name "Admin License Check" `
                                    -Description "Administrators should have appropriate licenses assigned." `
                                    -Details @{ "DisplayName" = $Admin.DisplayName; "UserPrincipalName" = $Admin.UserPrincipalName; "License" = $License }
                        }
                    }
                    
                    # Display report in console
                    $Report | Format-Table -AutoSize
                    
                    # Add summary finding
                    if ($PrivilegedUsers.Count -gt 0) {
                        if ($AdminsWithoutLicense -gt 0) {
                            Write-Host "Fail: $AdminsWithoutLicense out of $($PrivilegedUsers.Count) administrators are missing licenses." -ForegroundColor Red
                            
                            Add-Finding -CheckId $script.CheckId `
                                    -Asset "/tenants/$tenantid" `
                                    -Status "FAIL" `
                                    -Name "Admin License Summary" `
                                    -Description "All administrators should have appropriate licenses assigned." `
                                    -Remediation "Assign appropriate licenses to all administrator accounts." `
                                    -Details @{ "TotalAdmins" = $PrivilegedUsers.Count; "AdminsWithoutLicense" = $AdminsWithoutLicense } `
                                    -Impact "Minor" `
                                    -Likelihood "Moderate" `
                                    -Risk "Medium"
                        } else {
                            Write-Host "Pass: All $($PrivilegedUsers.Count) administrators have licenses assigned." -ForegroundColor Green
                            
                            Add-Finding -CheckId $script.CheckId `
                                    -Asset "/tenants/$tenantid" `
                                    -Status "PASS" `
                                    -Name "Admin License Summary" `
                                    -Description "All administrators should have appropriate licenses assigned." `
                                    -Details @{ "TotalAdmins" = $PrivilegedUsers.Count; "AdminsWithoutLicense" = 0 }
                        }
                    } else {
                        Write-Host "Warning: No privileged users found." -ForegroundColor Yellow
                        
                        Add-Finding -CheckId $script.CheckId `
                                -Asset "/tenants/$tenantid" `
                                -Status "INFO" `
                                -Name "Admin License Summary" `
                                -Description "No privileged users were found to check for license assignment." `
                                -Details @{ "TotalAdmins" = 0 }
                    }
                } catch {
                    Write-Host "Error checking Admin Licenses." -ForegroundColor Red
                    Write-Host $_.Exception.Message
                    
                    # Add error finding to JSON results
                    Add-Finding -CheckId $script.CheckId `
                            -Asset "/tenants/$tenantid" `
                            -Status "ERROR" `
                            -Name "Admin License Check" `
                            -Description "Error occurred while checking administrator licenses." `
                            -Details @{ "ErrorMessage" = $_.Exception.Message }
                }
            }
        },
        @{
            Name = "1.2.1 Public Groups"
            Type = "Script"
            CheckId = "1.2.1"
            Logic = {
                try {
                    $publicGroups = Get-MgGroup | Where-Object {$_.Visibility -eq "Public"}
                    
                    # Display info in console
                    $publicGroups | Select-Object DisplayName, Visibility | Format-Table -AutoSize
                    Write-Host ""
                    Write-Host ""
                    
                    if ($publicGroups -and $publicGroups.Count -gt 0) {
                        Write-Host "Fail: $($publicGroups.Count) public groups found" -ForegroundColor Red
                        
                        # Add individual findings for each public group
                        foreach ($group in $publicGroups) {
                            Add-Finding -CheckId $script.CheckId `
                                    -Asset "/tenants/$tenantid/groups/$($group.Id)" `
                                    -Status "FAIL" `
                                    -Name "Public Group Check" `
                                    -Description "Groups should not be configured with public visibility." `
                                    -Remediation "Change the group visibility setting from Public to Private or Selected." `
                                    -Details @{ 
                                        "DisplayName" = $group.DisplayName
                                        "Visibility" = $group.Visibility
                                        "Id" = $group.Id
                                    } `
                                    -Impact "Minor" `
                                    -Likelihood "Moderate" `
                                    -Risk "Low"
                        }
                        
                        # Add a summary finding
                        Add-Finding -CheckId $script.CheckId `
                                -Asset "/tenants/$tenantid" `
                                -Status "FAIL" `
                                -Name "Public Groups Check" `
                                -Description "No groups should be configured with public visibility." `
                                -Remediation "Change all group visibility settings from Public to Private or Selected." `
                                -Details @{ "PublicGroupCount" = $publicGroups.Count } `
                                -Impact "Minor" `
                                -Likelihood "Moderate" `
                                -Risk "Low"
                    } else {
                        Write-Host "Pass: No public groups found" -ForegroundColor Green
                        
                        # Add a passing finding
                        Add-Finding -CheckId $script.CheckId `
                                -Asset "/tenants/$tenantid" `
                                -Status "PASS" `
                                -Name "Public Groups Check" `
                                -Description "No groups should be configured with public visibility." `
                                -Details @{ "PublicGroupCount" = 0 }
                    }
                } catch {
                    Write-Host "Error checking Public Groups." -ForegroundColor Red
                    Write-Host $_.Exception.Message
                    
                    # Add error finding to JSON results
                    Add-Finding -CheckId $script.CheckId `
                            -Asset "/tenants/$tenantid" `
                            -Status "ERROR" `
                            -Name "Public Groups Check" `
                            -Description "Error occurred while checking for public groups." `
                            -Details @{ "ErrorMessage" = $_.Exception.Message }
                }
            }
        },
        @{
            Name = "1.2.2 Sign-in to Shared Mailboxes"
            Type = "Script"
            CheckId = "1.2.2"
            RequiresExchange = $true
            Logic = {
                try {
                    Write-Host "Checking sign-in status for Shared Mailboxes..." -ForegroundColor Cyan
                    Disconnect-ExchangeOnline -Confirm:$false -ErrorAction SilentlyContinue
                    Connect-ExchangeOnline -CertificateThumbprint "$Thumbprint" -AppId "$AppId" -Organization "$Domain" -ShowBanner:$false
                    Start-Sleep 1
                    $MBX = Get-EXOMailbox -RecipientTypeDetails SharedMailbox -ErrorAction SilentlyContinue
                    if ($null -eq $MBX) {
                        Write-Host "No shared mailboxes found." -ForegroundColor Yellow
                        
                        # Add info finding
                        Add-Finding -CheckId $script.CheckId `
                                -Asset "/tenants/$tenantid" `
                                -Status "INFO" `
                                -Name "Shared Mailbox Sign-in Check" `
                                -Description "Shared mailboxes should have sign-in blocked." `
                                -Details @{ "SharedMailboxCount" = 0 }
                        return
                    }
                    
                    $enabledMailboxes = @()
                    $disabledMailboxes = @()
                    
                    foreach ($mailbox in $MBX) {
                        try {
                            $userData = Get-MgUser -UserId $mailbox.ExternalDirectoryObjectId -Property DisplayName, UserPrincipalName, AccountEnabled -ErrorAction SilentlyContinue
                            
                            if ($userData.AccountEnabled -eq $true) {
                                $enabledMailboxes += $userData
                                
                                # Add individual fail finding
                                Add-Finding -CheckId $script.CheckId `
                                        -Asset "/tenants/$tenantid/users/$($userData.UserPrincipalName)" `
                                        -Status "FAIL" `
                                        -Name "Shared Mailbox Sign-in Check" `
                                        -Description "Shared mailboxes should have sign-in blocked." `
                                        -Remediation "Disable sign-in for the shared mailbox account." `
                                        -Details @{ 
                                            "DisplayName" = $userData.DisplayName
                                            "UserPrincipalName" = $userData.UserPrincipalName
                                            "AccountEnabled" = $userData.AccountEnabled
                                        } `
                                        -Impact "Moderate" `
                                        -Likelihood "Moderate" `
                                        -Risk "Medium"
                            } else {
                                $disabledMailboxes += $userData
                                
                                # Add individual pass finding
                                Add-Finding -CheckId $script.CheckId `
                                        -Asset "/tenants/$tenantid/users/$($userData.UserPrincipalName)" `
                                        -Status "PASS" `
                                        -Name "Shared Mailbox Sign-in Check" `
                                        -Description "Shared mailboxes should have sign-in blocked." `
                                        -Details @{ 
                                            "DisplayName" = $userData.DisplayName
                                            "UserPrincipalName" = $userData.UserPrincipalName
                                            "AccountEnabled" = $userData.AccountEnabled
                                        }
                            }
                        } catch {
                            Write-Host "Error processing mailbox $($mailbox.UserPrincipalName): $($_.Exception.Message)" -ForegroundColor Yellow
                        }
                    }
                    
                    # Display results in console
                    $signInData = $enabledMailboxes + $disabledMailboxes
                    if ($signInData) {
                        $signInData | Format-Table DisplayName, UserPrincipalName, AccountEnabled -AutoSize
                        Write-Host ""
                        Write-Host ""
                    }
                    
                    # Add summary finding
                    if ($enabledMailboxes.Count -gt 0) {
                        Write-Host "Fail: $($enabledMailboxes.Count) out of $($signInData.Count) shared mailboxes have sign-in enabled." -ForegroundColor Red
                        
                        Add-Finding -CheckId $script.CheckId `
                                -Asset "/tenants/$tenantid" `
                                -Status "FAIL" `
                                -Name "Shared Mailbox Sign-in Summary" `
                                -Description "All shared mailboxes should have sign-in blocked." `
                                -Remediation "Disable sign-in for all shared mailbox accounts." `
                                -Details @{ 
                                    "TotalSharedMailboxes" = $signInData.Count
                                    "EnabledMailboxes" = $enabledMailboxes.Count
                                    "DisabledMailboxes" = $disabledMailboxes.Count
                                } `
                                -Impact "Moderate" `
                                -Likelihood "Moderate" `
                                -Risk "Medium"
                    } else {
                        Write-Host "Pass: All $($signInData.Count) shared mailboxes have sign-in disabled." -ForegroundColor Green
                        
                        Add-Finding -CheckId $script.CheckId `
                                -Asset "/tenants/$tenantid" `
                                -Status "PASS" `
                                -Name "Shared Mailbox Sign-in Summary" `
                                -Description "All shared mailboxes should have sign-in blocked." `
                                -Details @{ 
                                    "TotalSharedMailboxes" = $signInData.Count
                                    "EnabledMailboxes" = 0
                                    "DisabledMailboxes" = $signInData.Count
                                }
                    }
                } catch {
                    Write-Host "Error checking sign-in status for Shared Mailboxes." -ForegroundColor Red
                    Write-Host $_.Exception.Message
                    
                    # Add error finding to JSON results
                    Add-Finding -CheckId $script.CheckId `
                            -Asset "/tenants/$tenantid" `
                            -Status "ERROR" `
                            -Name "Shared Mailbox Sign-in Check" `
                            -Description "Error occurred while checking sign-in status for shared mailboxes." `
                            -Details @{ "ErrorMessage" = $_.Exception.Message }
                }
            }
        },
        @{
            Name = "1.3.1 Password Expiration Policy"
            Type = "Script"
            CheckId = "1.3.1"
            Logic = {
                try {
                    $domains = Get-MgDomain | Select-Object id, PasswordValidityPeriodInDays
                    
                    if ($domains) {
                        $domains | Format-Table id, PasswordValidityPeriodInDays -AutoSize
                        Write-Host ""
                        Write-Host ""
        
                        $expiredDomains = @()
                        $nonExpiredDomains = @()
                        
                        foreach ($domain in $domains) {
                            if ($domain.PasswordValidityPeriodInDays -lt 365) {
                                $expiredDomains += $domain
                                
                                # Add individual finding
                                Add-Finding -CheckId $script.CheckId `
                                        -Asset "/tenant/$tenantid/domains/$($domain.id)" `
                                        -Status "FAIL" `
                                        -Name "Password Expiration Policy Check" `
                                        -Description "Password expiration should not be set (should be 365 days or more)." `
                                        -Remediation "Configure password expiration policy to not expire passwords (set to 365 days or more)." `
                                        -Details @{ 
                                            "Domain" = $domain.id
                                            "PasswordValidityPeriodInDays" = $domain.PasswordValidityPeriodInDays
                                        } `
                                        -Impact "Moderate" `
                                        -Likelihood "Moderate" `
                                        -Risk "Medium"
                            } else {
                                $nonExpiredDomains += $domain
                                
                                # Add individual finding
                                Add-Finding -CheckId $script.CheckId `
                                        -Asset "/tenants/$tenantid/domains/$($domain.id)" `
                                        -Status "PASS" `
                                        -Name "Password Expiration Policy Check" `
                                        -Description "Password expiration should not be set (should be 365 days or more)." `
                                        -Details @{ 
                                            "Domain" = $domain.id
                                            "PasswordValidityPeriodInDays" = $domain.PasswordValidityPeriodInDays
                                        }
                            }
                        }
                        
                        # Add summary finding
                        if ($expiredDomains.Count -gt 0) {
                            Write-Host "Fail: Password expiration set" -ForegroundColor Red
                            
                            Add-Finding -CheckId $script.CheckId `
                                    -Asset "/tenants/$tenantid" `
                                    -Status "FAIL" `
                                    -Name "Password Expiration Policy Summary" `
                                    -Description "Password expiration should not be set (should be 365 days or more)." `
                                    -Remediation "Configure password expiration policy to not expire passwords (set to 365 days or more)." `
                                    -Details @{ 
                                        "TotalDomains" = $domains.Count
                                        "DomainsWithPasswordExpiration" = $expiredDomains.Count
                                    } `
                                    -Impact "Moderate" `
                                    -Likelihood "Moderate" `
                                    -Risk "Medium"
                        } else {
                            Write-Host "Pass" -ForegroundColor Green
                            
                            Add-Finding -CheckId $script.CheckId `
                                    -Asset "/tenants/$tenantid" `
                                    -Status "PASS" `
                                    -Name "Password Expiration Policy Summary" `
                                    -Description "Password expiration should not be set (should be 365 days or more)." `
                                    -Details @{ 
                                        "TotalDomains" = $domains.Count
                                        "DomainsWithPasswordExpiration" = 0
                                    }
                        }
                    } else {
                        Write-Host "No domain data found." -ForegroundColor Yellow
                        Write-Host "Pass" -ForegroundColor Green
                        
                        Add-Finding -CheckId $script.CheckId `
                                -Asset "/tenants/$tenantid" `
                                -Status "INFO" `
                                -Name "Password Expiration Policy Check" `
                                -Description "No domain data available to check password expiration policy." `
                                -Details @{ "Message" = "No domain data found" }
                    }
                } catch {
                    Write-Host "Error checking Password Expiration Policy." -ForegroundColor Red
                    Write-Host $_.Exception.Message
                    
                    Add-Finding -CheckId $script.CheckId `
                            -Asset "/tenants/$tenantid" `
                            -Status "ERROR" `
                            -Name "Password Expiration Policy Check" `
                            -Description "Error occurred while checking password expiration policy." `
                            -Details @{ "ErrorMessage" = $_.Exception.Message }
                }
            }
        },
        @{
            Name = "1.3.2 Idle Session Timeout"
            Type = "Script"
            CheckId = "1.3.2"
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
                        
                        $compliancePolicies = @()
                        $nonCompliancePolicies = @()
                        
                        foreach ($policy in $policies) {
                            if ($policy.SignOutAfterInSecs -eq $null -or $policy.SignOutAfterInSecs -lt 3) {
                                $nonCompliancePolicies += $policy
                                
                                Add-Finding -CheckId $script.CheckId `
                                        -Asset "/tenants/$tenantid/policies/$($policy.Id)" `
                                        -Status "FAIL" `
                                        -Name "Idle Session Timeout Check" `
                                        -Description "Idle session timeout should be configured appropriately (minimum 3 seconds)." `
                                        -Remediation "Configure idle session timeout settings for policy with appropriate values." `
                                        -Details @{ 
                                            "PolicyName" = $policy.DisplayName
                                            "Id" = $policy.Id
                                            "State" = $policy.State
                                            "IdleSessionSignOutEnabled" = $policy.IsEnabled
                                            "SignOutAfterInSeconds" = $policy.SignOutAfterInSecs
                                        } `
                                        -Impact "Moderate" `
                                        -Likelihood "Moderate" `
                                        -Risk "Medium"
                            } else {
                                $compliancePolicies += $policy
                                
                                Add-Finding -CheckId $script.CheckId `
                                        -Asset "/tenants/$tenantid/policies/$($policy.Id)" `
                                        -Status "PASS" `
                                        -Name "Idle Session Timeout Check" `
                                        -Description "Idle session timeout should be configured appropriately (minimum 3 seconds)." `
                                        -Details @{ 
                                            "PolicyName" = $policy.DisplayName
                                            "Id" = $policy.Id
                                            "State" = $policy.State
                                            "IdleSessionSignOutEnabled" = $policy.IsEnabled
                                            "SignOutAfterInSeconds" = $policy.SignOutAfterInSecs
                                        }
                            }
                        }
                        
                        # Add summary finding
                        if ($nonCompliancePolicies.Count -gt 0 -or $policies.Count -eq 0) {
                            Write-Host "Fail" -ForegroundColor Red
                            
                            Add-Finding -CheckId $script.CheckId `
                                    -Asset "/tenants/$tenantid" `
                                    -Status "FAIL" `
                                    -Name "Idle Session Timeout Summary" `
                                    -Description "Idle session timeout should be configured appropriately (minimum 3 seconds)." `
                                    -Remediation "Configure idle session timeout settings with appropriate values." `
                                    -Details @{ 
                                        "TotalPolicies" = $policies.Count
                                        "NonCompliantPolicies" = $nonCompliancePolicies.Count
                                        "CompliantPolicies" = $compliancePolicies.Count
                                    } `
                                    -Impact "Moderate" `
                                    -Likelihood "Moderate" `
                                    -Risk "Medium"
                        } else {
                            Write-Host "Pass" -ForegroundColor Green
                            
                            Add-Finding -CheckId $script.CheckId `
                                    -Asset "/tenants/$tenantid" `
                                    -Status "PASS" `
                                    -Name "Idle Session Timeout Summary" `
                                    -Description "Idle session timeout is configured appropriately." `
                                    -Details @{ 
                                        "TotalPolicies" = $policies.Count
                                        "CompliantPolicies" = $compliancePolicies.Count
                                    }
                        }
                    } else {
                        Write-Host "No policies found with Idle Session Timeout configured." -ForegroundColor Yellow
                        Write-Host ""
                        Write-Host ""
                        Write-Host "Fail" -ForegroundColor Red
                        
                        Add-Finding -CheckId $script.CheckId `
                                -Asset "/tenants/$tenantid" `
                                -Status "FAIL" `
                                -Name "Idle Session Timeout Check" `
                                -Description "Idle session timeout should be configured." `
                                -Remediation "Create and configure conditional access policies with idle session timeout settings." `
                                -Details @{ "Message" = "No policies found with Idle Session Timeout configured" } `
                                -Impact "Moderate" `
                                -Likelihood "Moderate" `
                                -Risk "Medium"
                    }
                } catch {
                    Write-Host "Error checking Idle Session Timeout." -ForegroundColor Red
                    Write-Host $_.Exception.Message
                    
                    Add-Finding -CheckId $script.CheckId `
                            -Asset "/tenants/$tenantid" `
                            -Status "ERROR" `
                            -Name "Idle Session Timeout Check" `
                            -Description "Error occurred while checking idle session timeout settings." `
                            -Details @{ "ErrorMessage" = $_.Exception.Message }
                }
            }
        },
        @{
            Name = "1.3.3 External Sharing"
            Type = "Script"
            CheckId = "1.3.3"
            RequiresExchange = $true
            Logic = {
                try {
                    Disconnect-ExchangeOnline -Confirm:$false -ErrorAction SilentlyContinue
                    Connect-ExchangeOnline -CertificateThumbprint "$Thumbprint" -AppId "$AppId" -Organization "$Domain" -ShowBanner:$false
                    Start-Sleep 1
                    $sharingPolicy = Get-SharingPolicy -Identity "Default Sharing Policy"
        
                    if ($sharingPolicy) {
                        $sharingPolicy | Format-Table -AutoSize
                        Write-Host ""
                        Write-Host ""
        
                        if ($sharingPolicy.Enabled -eq $false) {
                            Write-Host "Pass" -ForegroundColor Green
                            
                            Add-Finding -CheckId $script.CheckId `
                                    -Asset "/tenants/$tenantid" `
                                    -Status "PASS" `
                                    -Name "External Sharing Check" `
                                    -Description "External calendar sharing should be disabled." `
                                    -Details @{ 
                                        "PolicyName" = $sharingPolicy.Name
                                        "Enabled" = $sharingPolicy.Enabled
                                    }
                        } else {
                            Write-Host "Fail: External calendar sharing enabled" -ForegroundColor Red
                            
                            Add-Finding -CheckId $script.CheckId `
                                    -Asset "/tenants/$tenantid" `
                                    -Status "FAIL" `
                                    -Name "External Sharing Check" `
                                    -Description "External calendar sharing should be disabled." `
                                    -Remediation "Disable the default external sharing policy." `
                                    -Details @{ 
                                        "PolicyName" = $sharingPolicy.Name
                                        "Enabled" = $sharingPolicy.Enabled
                                        "Domains" = ($sharingPolicy.Domains -join ", ")
                                    } `
                                    -Impact "Moderate" `
                                    -Likelihood "Moderate" `
                                    -Risk "Medium"
                        }
                    } else {
                        Write-Host "No External Sharing Policy found." -ForegroundColor Yellow
                        Write-Host "Fail" -ForegroundColor Red
                        
                        Add-Finding -CheckId $script.CheckId `
                                -Asset "/tenants/$tenantid" `
                                -Status "FAIL" `
                                -Name "External Sharing Check" `
                                -Description "External sharing policy could not be found." `
                                -Remediation "Configure and verify external sharing settings." `
                                -Details @{ "Message" = "No External Sharing Policy found" } `
                                -Impact "Minor" `
                                -Likelihood "Low" `
                                -Risk "Low"
                    }
                } catch {
                    Write-Host "Error retrieving External Sharing Policy." -ForegroundColor Red
                    Write-Host $_.Exception.Message
                    
                    Add-Finding -CheckId $script.CheckId `
                            -Asset "/tenants/$tenantid" `
                            -Status "ERROR" `
                            -Name "External Sharing Check" `
                            -Description "Error occurred while checking external sharing policy." `
                            -Details @{ "ErrorMessage" = $_.Exception.Message }
                }
            }
        },
        @{
            Name = "1.3.4 Apps and Services Settings Check"
            Type = "Script"
            CheckId = "1.3.4"
            Logic = {
                try {
                    $endpoint = "https://graph.microsoft.com/beta/admin/appsAndServices"
                    $response = Invoke-MgGraphRequest -Uri $endpoint -Method GET

                    Write-Host "Raw API Response:"
                    Write-Host ($response | ConvertTo-Json -Depth 10)
                    Write-Host ""

                    if (-not $response.PSObject.Properties["settings"]) {
                        Write-Host "Fail: API response does not contain 'settings'." -ForegroundColor Red
                        
                        Add-Finding -CheckId $script.CheckId `
                                -Asset "/tenants/$tenantid" `
                                -Status "FAIL" `
                                -Name "Apps and Services Settings Check" `
                                -Description "Could not retrieve Apps and Services settings." `
                                -Remediation "Investigate API access to Apps and Services settings." `
                                -Details @{ "Message" = "API response does not contain 'settings'" } `
                                -Impact "Minor" `
                                -Likelihood "Low" `
                                -Risk "Low"
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
                        
                        $details = @{
                            "isOfficeStoreEnabled" = $isOfficeStoreEnabled
                            "isAppAndServicesTrialEnabled" = $isAppAndServicesTrialEnabled
                        }
                        
                        $description = "Office Store and App & Services Trial should be disabled."
                        $remediation = "Disable Office Store and App & Services Trial settings."
                        
                        if ($isOfficeStoreEnabled -eq $true) {
                            Write-Host "Fail: Office Store is enabled." -ForegroundColor Red
                        }
                        if ($isAppAndServicesTrialEnabled -eq $true) {
                            Write-Host "Fail: App and Services Trial is enabled." -ForegroundColor Red
                        }
                        
                        Add-Finding -CheckId $script.CheckId `
                                -Asset "/tenants/$tenantid" `
                                -Status "FAIL" `
                                -Name "Apps and Services Settings Check" `
                                -Description $description `
                                -Remediation $remediation `
                                -Details $details `
                                -Impact "Moderate" `
                                -Likelihood "Moderate" `
                                -Risk "Medium"
                    } else {
                        Write-Host "Pass: Both Office Store and App & Services Trial are disabled." -ForegroundColor Green
                        
                        Add-Finding -CheckId $script.CheckId `
                                -Asset "/tenants/$tenantid" `
                                -Status "PASS" `
                                -Name "Apps and Services Settings Check" `
                                -Description "Office Store and App & Services Trial are correctly disabled." `
                                -Details @{
                                    "isOfficeStoreEnabled" = $isOfficeStoreEnabled
                                    "isAppAndServicesTrialEnabled" = $isAppAndServicesTrialEnabled
                                }
                    }
                } catch {
                    Write-Host "Error retrieving Apps and Services settings." -ForegroundColor Red
                    Write-Host $_.Exception.Message
                    
                    Add-Finding -CheckId $script.CheckId `
                            -Asset "/tenants/$tenantid" `
                            -Status "ERROR" `
                            -Name "Apps and Services Settings Check" `
                            -Description "Error occurred while checking Apps and Services settings." `
                            -Details @{ "ErrorMessage" = $_.Exception.Message }
                }
            }
        },
        @{
            Name = "1.3.5 Internal Phishing Protection"
            Type = "Script"
            CheckId = "1.3.5"
            Logic = {
                try {
                    $endpoint = "https://graph.microsoft.com/beta/admin/Forms/settings"
                    $response = Invoke-MgGraphRequest -Uri $endpoint -Method GET

                    Write-Host "Raw API Response:"
                    Write-Host ($response | ConvertTo-Json -Depth 10)
                    Write-Host ""

                    if (-not $response.PSObject.Properties["isInOrgFormsPhishingScanEnabled"]) {
                        Write-Host "Fail: 'isInOrgFormsPhishingScanEnabled' not found in response." -ForegroundColor Red
                        
                        Add-Finding -CheckId $script.CheckId `
                                -Asset "/tenants/$tenantid" `
                                -Status "FAIL" `
                                -Name "Internal Phishing Protection Check" `
                                -Description "Could not retrieve Internal Phishing Protection settings." `
                                -Remediation "Investigate Forms API access and settings." `
                                -Details @{ "Message" = "'isInOrgFormsPhishingScanEnabled' not found in response" } `
                                -Impact "Moderate" `
                                -Likelihood "Moderate" `
                                -Risk "Medium"
                        return
                    }

                    $phishingScanEnabled = $response.isInOrgFormsPhishingScanEnabled

                    if ($phishingScanEnabled -eq $true) {
                        Write-Host "Pass: 'Internal Phishing Protection Enabled'" -ForegroundColor Green
                        
                        Add-Finding -CheckId $script.CheckId `
                                -Asset "/tenants/$tenantid" `
                                -Status "PASS" `
                                -Name "Internal Phishing Protection Check" `
                                -Description "Internal Phishing Protection is correctly enabled." `
                                -Details @{ "isInOrgFormsPhishingScanEnabled" = $phishingScanEnabled }
                    } else {
                        Write-Host "Fail: 'isInOrgFormsPhishingScanEnabled' is not True." -ForegroundColor Red
                        
                        Add-Finding -CheckId $script.CheckId `
                                -Asset "/tenants/$tenantid" `
                                -Status "FAIL" `
                                -Name "Internal Phishing Protection Check" `
                                -Description "Internal Phishing Protection should be enabled." `
                                -Remediation "Enable Internal Phishing Protection in Microsoft Forms settings." `
                                -Details @{ "isInOrgFormsPhishingScanEnabled" = $phishingScanEnabled } `
                                -Impact "Moderate" `
                                -Likelihood "Moderate" `
                                -Risk "Medium"
                    }
                } catch {
                    Write-Host "Error retrieving Forms settings." -ForegroundColor Red
                    Write-Host $_.Exception.Message
                    
                    Add-Finding -CheckId $script.CheckId `
                            -Asset "/tenants/$tenantid" `
                            -Status "ERROR" `
                            -Name "Internal Phishing Protection Check" `
                            -Description "Error occurred while checking Internal Phishing Protection settings." `
                            -Details @{ "ErrorMessage" = $_.Exception.Message }
                }
            }
        },
        @{
            Name = "1.3.6 Customer Lockbox"
            Type = "Script"
            CheckId = "1.3.6"
            RequiresExchange = $true
            Logic = {
                try {
                    Disconnect-ExchangeOnline -Confirm:$false -ErrorAction SilentlyContinue
                    Connect-ExchangeOnline -CertificateThumbprint "$Thumbprint" -AppId "$AppId" -Organization "$Domain" -ShowBanner:$false
                    Start-Sleep 1
                    $lockboxConfig = Get-OrganizationConfig | Select-Object CustomerLockBoxEnabled
                    $lockboxConfig | Format-Table -AutoSize
                    Write-Host ""
                    Write-Host ""
        
                    if ($lockboxConfig.CustomerLockBoxEnabled -eq $true) {
                        Write-Host "Pass" -ForegroundColor Green
                        
                        Add-Finding -CheckId $script.CheckId `
                                -Asset "/tenants/$tenantid" `
                                -Status "PASS" `
                                -Name "Customer Lockbox Check" `
                                -Description "Customer Lockbox should be enabled." `
                                -Details @{ "CustomerLockBoxEnabled" = $lockboxConfig.CustomerLockBoxEnabled }
                    } elseif ($lockboxConfig.CustomerLockBoxEnabled -eq $false) {
                        Write-Host "Fail: Customer LockBox disabled" -ForegroundColor Red
                        
                        Add-Finding -CheckId $script.CheckId `
                                -Asset "/tenants/$tenantid" `
                                -Status "FAIL" `
                                -Name "Customer Lockbox Check" `
                                -Description "Customer Lockbox should be enabled." `
                                -Remediation "Enable Customer Lockbox in organization settings." `
                                -Details @{ "CustomerLockBoxEnabled" = $lockboxConfig.CustomerLockBoxEnabled } `
                                -Impact "Moderate" `
                                -Likelihood "Moderate" `
                                -Risk "Medium"
                    } else {
                        Write-Host "Customer Lockbox status could not be determined." -ForegroundColor Yellow
                        Write-Host "Fail" -ForegroundColor Red
                        
                        Add-Finding -CheckId $script.CheckId `
                                -Asset "/tenants/$tenantid" `
                                -Status "FAIL" `
                                -Name "Customer Lockbox Check" `
                                -Description "Customer Lockbox status should be determined and enabled." `
                                -Remediation "Verify and enable Customer Lockbox in organization settings." `
                                -Details @{ "Message" = "Customer Lockbox status could not be determined" } `
                                -Impact "Minor" `
                                -Likelihood "Low" `
                                -Risk "Low"
                    }
                } catch {
                    Write-Host "Error retrieving Customer Lockbox configuration." -ForegroundColor Red
                    Write-Host $_.Exception.Message
                    Write-Host "Fail" -ForegroundColor Red
                    
                    Add-Finding -CheckId $script.CheckId `
                            -Asset "/tenants/$tenantid" `
                            -Status "ERROR" `
                            -Name "Customer Lockbox Check" `
                            -Description "Error occurred while checking Customer Lockbox configuration." `
                            -Details @{ "ErrorMessage" = $_.Exception.Message }
                }
            }
        },
        @{
            Name = "1.3.7 Third Party Storage"
            Type = "Script"
            CheckId = "1.3.7"
            Logic = {
                try {
                    $appId = "c1f33bc0-bdb4-4248-ba9b-096807ddb43e"
                    $endpoint = "https://graph.microsoft.com/v1.0/servicePrincipals?`$filter=appId eq '$appId'"

                    $response = Invoke-MgGraphRequest -Uri $endpoint -Method GET

                    Write-Host ($response | ConvertTo-Json -Depth 10)
                    Write-Host ""

                    if ($response.value -and $response.value.Count -gt 0) {
                        Write-Host "Fail: The following service principal(s) exist with App ID `${appId}`:" -ForegroundColor Red
                        
                        $spList = @()
                        foreach ($sp in $response.value) {
                            Write-Host "Display Name: $($sp.displayName)" -ForegroundColor Red
                            $spList += @{
                                "DisplayName" = $sp.displayName
                                "Id" = $sp.id
                                "AppId" = $sp.appId
                            }
                            
                            # Report each service principal as a separate finding
                            Add-Finding -CheckId $script.CheckId `
                                    -Asset "/tenants/$tenantid/servicePrincipals/$($sp.id)" `
                                    -Status "FAIL" `
                                    -Name "Third Party Storage Check" `
                                    -Description "Third party storage integration should not be enabled." `
                                    -Remediation "Disable Office integration with third-party storage providers in Microsoft 365 admin center > Settings > Services > Office on the web." `
                                    -Details @{ 
                                        "DisplayName" = $sp.displayName
                                        "Id" = $sp.id
                                        "AppId" = $sp.appId
                                        "Location" = "Microsoft 365 admin center > Settings > Services > Office on the web"
                                    } `
                                    -Impact "Moderate" `
                                    -Likelihood "Moderate" `
                                    -Risk "Medium"
                        }
                        
                        # Add a summary finding
                        Add-Finding -CheckId $script.CheckId `
                                -Asset "/tenants/$tenantid/settings/thirdPartyStorage" `
                                -Status "FAIL" `
                                -Name "Third Party Storage Summary" `
                                -Description "Third party storage integration should not be enabled." `
                                -Remediation "Disable Office integration with third-party storage providers in Microsoft 365 admin center > Settings > Services > Office on the web." `
                                -Details @{ 
                                    "AppId" = $appId
                                    "ServicePrincipals" = $spList
                                    "Count" = $response.value.Count
                                    "Location" = "Microsoft 365 admin center > Settings > Services > Office on the web"
                                } `
                                -Impact "Moderate" `
                                -Likelihood "Moderate" `
                                -Risk "Medium"
                    } else {
                        Write-Host "Pass: No service principal exists with App ID `${appId}`." -ForegroundColor Green
                        
                        Add-Finding -CheckId $script.CheckId `
                                -Asset "/tenants/$tenantid/settings/thirdPartyStorage" `
                                -Status "PASS" `
                                -Name "Third Party Storage Check" `
                                -Description "Third party storage integration is not enabled." `
                                -Details @{ 
                                    "AppId" = $appId
                                    "Location" = "Microsoft 365 admin center > Settings > Services > Office on the web"
                                }
                    }
                } catch {
                    Write-Host "Error retrieving service principal." -ForegroundColor Red
                    Write-Host $_.Exception.Message
                    
                    Add-Finding -CheckId $script.CheckId `
                            -Asset "/tenants/$tenantid/settings/thirdPartyStorage" `
                            -Status "ERROR" `
                            -Name "Third Party Storage Check" `
                            -Description "Error occurred while checking third party storage integration." `
                            -Details @{ 
                                "ErrorMessage" = $_.Exception.Message
                                "Location" = "Microsoft 365 admin center > Settings > Services > Office on the web"
                            }
                }
            }
        },
        @{
            Name = "1.3.8 Sway Sharing"
            Type = "Manual"
            CheckId = "1.3.8"
            Link = "https://admin.microsoft.com/#/Settings/Services/:/Settings/L1/Sway"
            explanation = {
                Verify that sway sharing is not allowed.
                Ensure 'Let people in the organization share their sways' is NOT checked
            }
            Logic = {
                # Add manual check finding
                Add-Finding -CheckId $script.CheckId `
                        -Asset "/tenants/$tenantid" `
                        -Status "MANUAL" `
                        -Name "Sway Sharing Check" `
                        -Description "Sway sharing should not be allowed for the organization." `
                        -Remediation "Disable 'Let people in the organization share their sways' setting." `
                        -Details @{ 
                            "ManualCheckRequired" = $true
                            "CheckLocation" = "https://admin.microsoft.com/#/Settings/Services/:/Settings/L1/Sway"
                            "VerificationSteps" = "Verify 'Let people in the organization share their sways' is NOT checked"
                        } `
                        -Impact "Minor" `
                        -Likelihood "Low" `
                        -Risk "Low"
                
                Write-Host "Manual check required for $($script.Name)" -ForegroundColor Yellow
                Write-Host "Please visit: $($script.Link)" -ForegroundColor Blue
                Write-Host "`nExplanation:" -ForegroundColor Magenta
                foreach ($line in $script.Explanation) {
                    Write-Host "$line" -ForegroundColor Cyan
                }
            }
        },
        @{
            Name = "2.1.1 SafeLinks for Office Apps"
            Type = "Script"
            CheckId = "2.1.1" 
            RequiresExchange = $true
            Logic = {
                try {
                    Disconnect-ExchangeOnline -Confirm:$false -ErrorAction SilentlyContinue
                    Connect-ExchangeOnline -CertificateThumbprint "$Thumbprint" -AppId "$AppId" -Organization "$Domain" -ShowBanner:$false
                    Start-Sleep 1
                    $safeLinksPolicies = Get-SafeLinksPolicy | Select-Object Name
        
                    if ($safeLinksPolicies.Count -eq 0) {
                        Write-Host "No SafeLinks policies found." -ForegroundColor Yellow
                        Write-Host "Fail" -ForegroundColor Red
                        
                        Add-Finding -CheckId $script.CheckId `
                                -Asset "/tenants/$tenantid" `
                                -Status "FAIL" `
                                -Name "SafeLinks for Office Apps Check" `
                                -Description "No SafeLinks policies found. SafeLinks should be configured for Office applications." `
                                -Remediation "Create and configure SafeLinks policies for Office applications." `
                                -Details @{ "Message" = "No SafeLinks policies found" } `
                                -Impact "Moderate" `
                                -Likelihood "Moderate" `
                                -Risk "Medium"
                        return
                    }
        
                    $allPoliciesPass = $true
                    $policySummaries = @()
                    
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
                            $incorrectSettings = @()
                            
                            Write-Host "`nSafeLinks Policy: $($policy.Name)`n" -ForegroundColor Cyan
                            
                            $detailsForJson = @{
                                "PolicyName" = $policyDetails.Name
                                "Settings" = @{}
                            }
        
                            foreach ($key in $expectedSettings.Keys) {
                                $actualValue = $policyDetails.$key
                                $expectedValue = $expectedSettings[$key]
                                $detailsForJson.Settings[$key] = $actualValue
        
                                if ($actualValue -ne $expectedValue) {
                                    Write-Host "{$key}: $actualValue" -ForegroundColor Red -NoNewline
                                    Write-Host " > desired: $expectedValue" -ForegroundColor Green
                                    $allSettingsCorrect = $false
                                    $incorrectSettings += @{
                                        "Setting" = $key
                                        "ActualValue" = $actualValue
                                        "ExpectedValue" = $expectedValue
                                    }
                                } else {
                                    Write-Host "{$key}: $actualValue" -ForegroundColor Green
                                }
                            }
        
                            Write-Host ""
                            
                            $policySummary = @{
                                "PolicyName" = $policyDetails.Name
                                "IsCompliant" = $allSettingsCorrect
                                "IncorrectSettings" = $incorrectSettings
                            }
                            $policySummaries += $policySummary
        
                            if ($allSettingsCorrect) {
                                Write-Host "Pass: All settings are correct for policy: $($policy.Name)" -ForegroundColor Green
                                
                                Add-Finding -CheckId $script.CheckId `
                                        -Asset "/tenants/$tenantid/defender/policies/safelinks/$($policy.Name)" `
                                        -Status "PASS" `
                                        -Name "SafeLinks Policy Check" `
                                        -Description "SafeLinks policy is correctly configured for Office applications." `
                                        -Details $detailsForJson
                            } else {
                                Write-Host "Fail: Policy $($policy.Name) has misconfigurations." -ForegroundColor Red
                                $allPoliciesPass = $false
                                
                                Add-Finding -CheckId $script.CheckId `
                                        -Asset "/tenants/$tenantid/defender/policies/safelinks/$($policy.Name)" `
                                        -Status "FAIL" `
                                        -Name "SafeLinks Policy Check" `
                                        -Description "SafeLinks policy has incorrect settings for Office applications." `
                                        -Remediation "Correct the SafeLinks policy settings to match the recommended values." `
                                        -Details @{
                                            "PolicyName" = $policyDetails.Name
                                            "IncorrectSettings" = $incorrectSettings
                                            "ActualSettings" = $detailsForJson.Settings
                                        } `
                                        -Impact "Moderate" `
                                        -Likelihood "Moderate" `
                                        -Risk "Medium"
                            }
        
                        } catch {
                            Write-Host "Failed to retrieve details for policy: $($policy.Name)" -ForegroundColor Red
                            Write-Host $_.Exception.Message
                            $allPoliciesPass = $false
                            
                            Add-Finding -CheckId $script.CheckId `
                                    -Asset "safelinks:$($policy.Name)" `
                                    -Status "ERROR" `
                                    -Name "SafeLinks Policy Check" `
                                    -Description "Error retrieving SafeLinks policy details." `
                                    -Details @{ 
                                        "PolicyName" = $policy.Name
                                        "ErrorMessage" = $_.Exception.Message 
                                    } `
                                    -Impact "Minor" `
                                    -Likelihood "Low" `
                                    -Risk "Low"
                        }
                    }
                    
                    # Add summary finding
                    if ($allPoliciesPass) {
                        Add-Finding -CheckId $script.CheckId `
                                -Asset "/tenants/$tenantid" `
                                -Status "PASS" `
                                -Name "SafeLinks for Office Apps Summary" `
                                -Description "All SafeLinks policies are correctly configured for Office applications." `
                                -Details @{ 
                                    "TotalPolicies" = $safeLinksPolicies.Count
                                    "PolicySummaries" = $policySummaries
                                }
                    } else {
                        Add-Finding -CheckId $script.CheckId `
                                -Asset "/tenants/$tenantid" `
                                -Status "FAIL" `
                                -Name "SafeLinks for Office Apps Summary" `
                                -Description "Some SafeLinks policies have incorrect settings for Office applications." `
                                -Remediation "Review and correct all SafeLinks policy settings to match the recommended values." `
                                -Details @{ 
                                    "TotalPolicies" = $safeLinksPolicies.Count
                                    "PolicySummaries" = $policySummaries
                                } `
                                -Impact "Moderate" `
                                -Likelihood "Moderate" `
                                -Risk "Medium"
                    }
                    
                } catch {
                    Write-Host "Error retrieving SafeLinks policies." -ForegroundColor Red
                    Write-Host $_.Exception.Message
                    Write-Host "$($script.Name) - Fail" -ForegroundColor Red
                    
                    Add-Finding -CheckId $script.CheckId `
                            -Asset "/tenants/$tenantid" `
                            -Status "ERROR" `
                            -Name "SafeLinks for Office Apps Check" `
                            -Description "Error occurred while checking SafeLinks policies." `
                            -Details @{ "ErrorMessage" = $_.Exception.Message } `
                            -Impact "Minor" `
                            -Likelihood "Low" `
                            -Risk "Low"
                }
            }
        },
        @{
            Name = "2.1.2 Common Attachment Types Filter"
            Type = "Script"
            CheckId = "2.1.2"
            RequiresExchange = $true
            Logic = {
                try {
                    Disconnect-ExchangeOnline -Confirm:$false -ErrorAction SilentlyContinue
                    Connect-ExchangeOnline -CertificateThumbprint "$Thumbprint" -AppId "$AppId" -Organization "$Domain" -ShowBanner:$false
                    Start-Sleep 1
                    $malwareFilterPolicy = Get-MalwareFilterPolicy -Identity Default | Select-Object EnableFileFilter
                    $malwareFilterPolicy | Format-Table -AutoSize
                    Write-Host ""
                    Write-Host ""
        
                    if ($malwareFilterPolicy.EnableFileFilter -eq $true) {
                        Write-Host "Pass" -ForegroundColor Green
                        
                        Add-Finding -CheckId $script.CheckId `
                                -Asset "/tenants/$tenantid" `
                                -Status "PASS" `
                                -Name "Common Attachment Types Filter Check" `
                                -Description "Common attachment types filter is correctly enabled." `
                                -Details @{ "EnableFileFilter" = $malwareFilterPolicy.EnableFileFilter }
                    } else {
                        Write-Host "Fail: File filter disabled" -ForegroundColor Red
                        
                        Add-Finding -CheckId $script.CheckId `
                                -Asset "/tenants/$tenantid" `
                                -Status "FAIL" `
                                -Name "Common Attachment Types Filter Check" `
                                -Description "Common attachment types filter should be enabled." `
                                -Remediation "Enable file filtering in the malware filter policy." `
                                -Details @{ "EnableFileFilter" = $malwareFilterPolicy.EnableFileFilter } `
                                -Impact "Moderate" `
                                -Likelihood "Moderate" `
                                -Risk "Medium"
                    }
                } catch {
                    Write-Host "Error retrieving Common Attachment Types Filter status." -ForegroundColor Red
                    Write-Host $_.Exception.Message
                    
                    Add-Finding -CheckId $script.CheckId `
                            -Asset "/tenants/$tenantid" `
                            -Status "ERROR" `
                            -Name "Common Attachment Types Filter Check" `
                            -Description "Error occurred while checking common attachment types filter." `
                            -Details @{ "ErrorMessage" = $_.Exception.Message } `
                            -Impact "Minor" `
                            -Likelihood "Low" `
                            -Risk "Low"
                }
            }
        },    
        @{
            Name = "2.1.3 Internal Users Sending Malware"
            Type = "Script"
            CheckId = "2.1.3"
            RequiresExchange = $true
            Logic = {
                try {
                    Disconnect-ExchangeOnline -Confirm:$false -ErrorAction SilentlyContinue
                    Connect-ExchangeOnline -CertificateThumbprint "$Thumbprint" -AppId "$AppId" -Organization "$Domain" -ShowBanner:$false
                    Start-Sleep 1
                    $malwareFilterPolicies = Get-MalwareFilterPolicy | Select-Object Identity, EnableInternalSenderAdminNotifications, InternalSenderAdminAddress
                    $pass = $false
                    $policyResults = @()
        
                    foreach ($policy in $malwareFilterPolicies) {
                        $policyResult = @{
                            "Identity" = $policy.Identity
                            "EnableInternalSenderAdminNotifications" = $policy.EnableInternalSenderAdminNotifications
                            "InternalSenderAdminAddress" = $policy.InternalSenderAdminAddress
                            "IsCompliant" = $false
                        }
                        
                        if ($policy.EnableInternalSenderAdminNotifications -eq $true -and -not [string]::IsNullOrWhiteSpace($policy.InternalSenderAdminAddress)) {
                            $pass = $true
                            $policyResult.IsCompliant = $true
                            Write-Host "Policy '$($policy.Identity)' meets the criteria:" -ForegroundColor Green
                            Write-Host "EnableInternalSenderAdminNotifications: $($policy.EnableInternalSenderAdminNotifications)" -ForegroundColor Green
                            Write-Host "InternalSenderAdminAddress: $($policy.InternalSenderAdminAddress)" -ForegroundColor Green
                        } else {
                            Write-Host "Policy '$($policy.Identity)' does not meet the criteria:" -ForegroundColor Yellow
                            Write-Host "EnableInternalSenderAdminNotifications: $($policy.EnableInternalSenderAdminNotifications)" -ForegroundColor Yellow
                            Write-Host "InternalSenderAdminAddress: $($policy.InternalSenderAdminAddress)" -ForegroundColor Yellow
                        }
                        
                        $policyResults += $policyResult
                    }
                    
                    $malwareFilterPolicies | Format-Table -AutoSize
                    Write-Host ""
                    Write-Host ""
                    
                    # Add JSON findings
                    if ($Global:JsonOutputMode) {
                        $findingData = @{}
                        
                        foreach ($policy in $policyResults) {
                            $findingData[$policy.Identity] = @{
                                "EnableInternalSenderAdminNotifications" = $policy.EnableInternalSenderAdminNotifications
                                "InternalSenderAdminAddress" = $policy.InternalSenderAdminAddress
                                "IsCompliant" = $policy.IsCompliant
                            }
                        }
                        
                        if ($pass) {
                            Add-Finding -CheckId $script.CheckId `
                                    -Asset "/tenants/$tenantid" `
                                    -Status "PASS" `
                                    -Name "Internal Users Sending Malware Check" `
                                    -Description "Internal sender admin notifications are properly configured." `
                                    -Details $findingData
                        } else {
                            Add-Finding -CheckId $script.CheckId `
                                    -Asset "/tenants/$tenantid" `
                                    -Status "FAIL" `
                                    -Name "Internal Users Sending Malware Check" `
                                    -Description "Internal sender admin notifications are not properly configured." `
                                    -Remediation "Configure internal sender admin notifications by setting EnableInternalSenderAdminNotifications to True and providing a valid InternalSenderAdminAddress." `
                                    -Details $findingData `
                                    -Impact "Moderate" `
                                    -Likelihood "Moderate" `
                                    -Risk "Medium"
                        }
                    }
        
                    if ($pass) {
                        Write-Host "Pass" -ForegroundColor Green
                    } else {
                        Write-Host "Fail: Admin notifications disabled or admin email not configured" -ForegroundColor Red
                    }
                } catch {
                    Write-Host "Error retrieving Internal Users Sending Malware settings." -ForegroundColor Red
                    Write-Host $_.Exception.Message
                    Write-Host "Fail" -ForegroundColor Red
                    
                    if ($Global:JsonOutputMode) {
                        Add-Finding -CheckId $script.CheckId `
                                -Asset "/tenants/$tenantid" `
                                -Status "ERROR" `
                                -Name "Internal Users Sending Malware Check" `
                                -Description "Error occurred while checking malware filter policy settings." `
                                -Details @{ "ErrorMessage" = $_.Exception.Message } `
                                -Impact "Minor" `
                                -Likelihood "Low" `
                                -Risk "Low"
                    }
                }
            }
        },
        @{
            Name = "2.1.4 Safe Attachments Policy"
            Type = "Script"
            CheckId = "2.1.4"
            RequiresExchange = $true
            Logic = {
                try {
                    Disconnect-ExchangeOnline -Confirm:$false -ErrorAction SilentlyContinue
                    Connect-ExchangeOnline -CertificateThumbprint "$Thumbprint" -AppId "$AppId" -Organization "$Domain" -ShowBanner:$false
                    Start-Sleep 1
                    $safeAttachmentPolicies = Get-SafeAttachmentPolicy | Select-Object Name, Enable
                    $enabledPolicies = $safeAttachmentPolicies | Where-Object { $_.Enable -eq $true }
                    
                    Write-Host "All Safe Attachment Policies:" -ForegroundColor Yellow
                    $safeAttachmentPolicies | Format-Table -AutoSize
                    Write-Host ""
                    Write-Host ""
        
                    $policyDetails = @()
                    foreach ($policy in $safeAttachmentPolicies) {
                        $policyDetails += @{
                            "Name" = $policy.Name
                            "Enabled" = $policy.Enable
                            "IsCompliant" = ($policy.Enable -eq $true)
                        }
                    }
                    
                    # Add JSON findings
                    if ($Global:JsonOutputMode) {
                        $findingData = @{
                            "TotalPolicies" = $safeAttachmentPolicies.Count
                            "EnabledPolicies" = $enabledPolicies.Count
                            "PolicyDetails" = $policyDetails
                        }
                        
                        if ($enabledPolicies.Count -gt 0) {
                            Add-Finding -CheckId $script.CheckId `
                                    -Asset "/tenants/$tenantid" `
                                    -Status "PASS" `
                                    -Name "Safe Attachments Policy Check" `
                                    -Description "At least one Safe Attachment Policy is enabled." `
                                    -Details $findingData
                        } else {
                            Add-Finding -CheckId $script.CheckId `
                                    -Asset "/tenants/$tenantid" `
                                    -Status "FAIL" `
                                    -Name "Safe Attachments Policy Check" `
                                    -Description "No Safe Attachment Policies are enabled." `
                                    -Remediation "Enable at least one Safe Attachment Policy to protect against malicious attachments." `
                                    -Details $findingData `
                                    -Impact "Moderate" `
                                    -Likelihood "Moderate" `
                                    -Risk "Medium"
                        }
                    }
                    
                    if ($enabledPolicies.Count -gt 0) {
                        Write-Host "Pass" -ForegroundColor Green
                    } else {
                        Write-Host "Fail" -ForegroundColor Red
                        Write-Host "No Safe Attachment Policies are enabled." -ForegroundColor Red
                    }
                } catch {
                    Write-Host "Error retrieving Safe Attachment Policies." -ForegroundColor Red
                    Write-Host $_.Exception.Message
                    Write-Host "Fail" -ForegroundColor Red
                    
                    if ($Global:JsonOutputMode) {
                        Add-Finding -CheckId $script.CheckId `
                                -Asset "/tenants/$tenantid" `
                                -Status "ERROR" `
                                -Name "Safe Attachments Policy Check" `
                                -Description "Error occurred while checking Safe Attachment Policies." `
                                -Details @{ "ErrorMessage" = $_.Exception.Message } `
                                -Impact "Minor" `
                                -Likelihood "Low" `
                                -Risk "Low"
                    }
                }
            }
        },
        @{
            Name = "2.1.5 Safe Attachments for SharePoint, OneDrive, and Teams"
            Type = "Script"
            CheckId = "2.1.5"
            RequiresExchange = $true
            Logic = {
                try {
                    Disconnect-ExchangeOnline -Confirm:$false -ErrorAction SilentlyContinue
                    Connect-ExchangeOnline -CertificateThumbprint "$Thumbprint" -AppId "$AppId" -Organization "$Domain" -ShowBanner:$false
                    Start-Sleep 1
                    $atpPolicies = Get-AtpPolicyForO365 | Select-Object Name, EnableATPForSPOTeamsODB, EnableSafeDocs, AllowSafeDocsOpen
                    
                    # Define the expected settings
                    $expectedSettings = @{
                        "EnableATPForSPOTeamsODB" = $true
                        "EnableSafeDocs" = $true
                        "AllowSafeDocsOpen" = $false
                    }
                    
                    $pass = $false
                    $policyResults = @()
                    
                    foreach ($policy in $atpPolicies) {
                        $policyResult = @{
                            "Name" = $policy.Name
                            "EnableATPForSPOTeamsODB" = $policy.EnableATPForSPOTeamsODB
                            "EnableSafeDocs" = $policy.EnableSafeDocs
                            "AllowSafeDocsOpen" = $policy.AllowSafeDocsOpen
                            "IsCompliant" = $false
                        }
                        
                        # Check if all conditions are met
                        if ($policy.EnableATPForSPOTeamsODB -eq $true -and 
                            $policy.EnableSafeDocs -eq $true -and 
                            $policy.AllowSafeDocsOpen -eq $false) {
                            $policyResult.IsCompliant = $true
                            $pass = $true
                            
                            Write-Host "Policy '$($policy.Name)' meets all criteria:" -ForegroundColor Green
                            Write-Host "  EnableATPForSPOTeamsODB: $($policy.EnableATPForSPOTeamsODB)" -ForegroundColor Green
                            Write-Host "  EnableSafeDocs: $($policy.EnableSafeDocs)" -ForegroundColor Green
                            Write-Host "  AllowSafeDocsOpen: $($policy.AllowSafeDocsOpen)" -ForegroundColor Green
                        } else {
                            Write-Host "Policy '$($policy.Name)' does not meet all criteria:" -ForegroundColor Yellow
                            Write-Host "  EnableATPForSPOTeamsODB: $($policy.EnableATPForSPOTeamsODB) - Expected: $($expectedSettings.EnableATPForSPOTeamsODB)" -ForegroundColor $(if ($policy.EnableATPForSPOTeamsODB -eq $expectedSettings.EnableATPForSPOTeamsODB) { "Green" } else { "Red" })
                            Write-Host "  EnableSafeDocs: $($policy.EnableSafeDocs) - Expected: $($expectedSettings.EnableSafeDocs)" -ForegroundColor $(if ($policy.EnableSafeDocs -eq $expectedSettings.EnableSafeDocs) { "Green" } else { "Red" })
                            Write-Host "  AllowSafeDocsOpen: $($policy.AllowSafeDocsOpen) - Expected: $($expectedSettings.AllowSafeDocsOpen)" -ForegroundColor $(if ($policy.AllowSafeDocsOpen -eq $expectedSettings.AllowSafeDocsOpen) { "Green" } else { "Red" })
                        }
                        
                        $policyResults += $policyResult
                    }
                    
                    # Display detailed output
                    $atpPolicies | Format-Table -AutoSize
                    Write-Host ""
                    Write-Host ""
                    
                    # Add JSON findings
                    if ($Global:JsonOutputMode) {
                        $findingData = @{
                            "TotalPolicies" = $atpPolicies.Count
                            "CompliantPolicies" = ($policyResults | Where-Object { $_.IsCompliant -eq $true }).Count
                            "PolicyDetails" = $policyResults
                            "ExpectedSettings" = $expectedSettings
                        }
                        
                        if ($pass) {
                            Add-Finding -CheckId $script.CheckId `
                                    -Asset "/tenants/$tenantid" `
                                    -Status "PASS" `
                                    -Name "Safe Attachments for SharePoint, OneDrive, and Teams Check" `
                                    -Description "At least one ATP policy is properly configured for SharePoint, OneDrive, and Teams." `
                                    -Details $findingData
                        } else {
                            Add-Finding -CheckId $script.CheckId `
                                    -Asset "/tenants/$tenantid" `
                                    -Status "FAIL" `
                                    -Name "Safe Attachments for SharePoint, OneDrive, and Teams Check" `
                                    -Description "No ATP policies are properly configured for SharePoint, OneDrive, and Teams." `
                                    -Remediation "Configure ATP policies with EnableATPForSPOTeamsODB=True, EnableSafeDocs=True, and AllowSafeDocsOpen=False." `
                                    -Details $findingData `
                                    -Impact "Moderate" `
                                    -Likelihood "Moderate" `
                                    -Risk "Medium"
                        }
                    }
                    
                    if ($pass) {
                        Write-Host "Pass" -ForegroundColor Green
                    } else {
                        Write-Host "Fail" -ForegroundColor Red
                        Write-Host "No ATP policies meet all the required criteria." -ForegroundColor Red
                    }
                } catch {
                    Write-Host "Error retrieving Safe Attachments for SharePoint, OneDrive, and Teams settings." -ForegroundColor Red
                    Write-Host $_.Exception.Message
                    Write-Host "Fail: Safe attachments disabled for services" -ForegroundColor Red
                    
                    if ($Global:JsonOutputMode) {
                        Add-Finding -CheckId $script.CheckId `
                                -Asset "/tenants/$tenantid" `
                                -Status "ERROR" `
                                -Name "Safe Attachments for SharePoint, OneDrive, and Teams Check" `
                                -Description "Error occurred while checking ATP policies." `
                                -Details @{ "ErrorMessage" = $_.Exception.Message } `
                                -Impact "Minor" `
                                -Likelihood "Low" `
                                -Risk "Low"
                    }
                }
            }
        },
        @{
            Name = "2.1.6 Exchange Online Spam Policies"
            Type = "Script"
            CheckId = "2.1.6"
            RequiresExchange = $true
            Logic = {
                try {
                    Disconnect-ExchangeOnline -Confirm:$false -ErrorAction SilentlyContinue
                    Connect-ExchangeOnline -CertificateThumbprint "$Thumbprint" -AppId "$AppId" -Organization "$Domain" -ShowBanner:$false
                    Start-Sleep 1
                    $spamPolicies = Get-HostedOutboundSpamFilterPolicy | Select-Object Identity, Name, NotifyOutboundSpamRecipients, NotifyOutboundSpam
                    
                    if ($spamPolicies.Count -eq 0) {
                        Write-Host "No Hosted Outbound Spam Filter Policies found." -ForegroundColor Yellow
                        Write-Host "Fail" -ForegroundColor Red
                        
                        if ($Global:JsonOutputMode) {
                            Add-Finding -CheckId $script.CheckId `
                                    -Asset "/tenants/$tenantid" `
                                    -Status "FAIL" `
                                    -Name "Exchange Online Spam Policies Check" `
                                    -Description "No outbound spam filter policies were found." `
                                    -Remediation "Create outbound spam filter policies with proper notification settings." `
                                    -Details @{ "Message" = "No policies found" } `
                                    -Impact "Moderate" `
                                    -Likelihood "Moderate" `
                                    -Risk "Medium"
                        }
                        return
                    }
                    
                    $pass = $false
                    $policyResults = @()
                    
                    foreach ($policy in $spamPolicies) {
                        $notifyRecipients = $policy.NotifyOutboundSpamRecipients
                        $notifyOutboundSpam = $policy.NotifyOutboundSpam
                        
                        $policyResult = @{
                            "Identity" = $policy.Identity
                            "Name" = $policy.Name
                            "NotifyOutboundSpam" = $notifyOutboundSpam
                            "NotifyOutboundSpamRecipients" = if ($notifyRecipients) { $notifyRecipients -join ", " } else { "None" }
                            "IsCompliant" = $false
                        }
                        
                        if ($notifyOutboundSpam -eq $true -and $notifyRecipients -ne $null -and $notifyRecipients.Count -gt 0) {
                            $policyResult.IsCompliant = $true
                            $pass = $true
                            
                            Write-Host "Policy '$($policy.Name)' is properly configured:" -ForegroundColor Green
                            Write-Host "  NotifyOutboundSpam: $notifyOutboundSpam" -ForegroundColor Green
                            Write-Host "  NotifyOutboundSpamRecipients: $($notifyRecipients -join ", ")" -ForegroundColor Green
                        } else {
                            Write-Host "Policy '$($policy.Name)' is not properly configured:" -ForegroundColor Yellow
                            Write-Host "  NotifyOutboundSpam: $notifyOutboundSpam - Expected: True" -ForegroundColor (if ($notifyOutboundSpam -eq $true) {"Green"} else {"Red"})
                            Write-Host "  NotifyOutboundSpamRecipients: $($notifyRecipients -join ", ") - Expected: At least one email address" -ForegroundColor (if ($notifyRecipients -ne $null -and $notifyRecipients.Count -gt 0) {"Green"} else {"Red"})
                        }
                        
                        $policyResults += $policyResult
                    }
                    $spamPolicies | Format-List
                    Write-Host ""
                    Write-Host ""
                    
                    # Add JSON findings
                    if ($Global:JsonOutputMode) {
                        $findingData = @{
                            "TotalPolicies" = $spamPolicies.Count
                            "CompliantPolicies" = ($policyResults | Where-Object { $_.IsCompliant -eq $true }).Count
                            "PolicyDetails" = $policyResults
                        }
                        
                        if ($pass) {
                            Add-Finding -CheckId $script.CheckId `
                                    -Asset "/tenants/$tenantid" `
                                    -Status "PASS" `
                                    -Name "Exchange Online Spam Policies Check" `
                                    -Description "At least one outbound spam filter policy is properly configured." `
                                    -Details $findingData
                        } else {
                            Add-Finding -CheckId $script.CheckId `
                                    -Asset "/tenants/$tenantid" `
                                    -Status "FAIL" `
                                    -Name "Exchange Online Spam Policies Check" `
                                    -Description "No outbound spam filter policies are properly configured." `
                                    -Remediation "Configure outbound spam filter policies with NotifyOutboundSpam=True and at least one email address in NotifyOutboundSpamRecipients." `
                                    -Details $findingData `
                                    -Impact "Moderate" `
                                    -Likelihood "Moderate" `
                                    -Risk "Medium"
                        }
                    }
                    
                    if ($pass) {
                        Write-Host "Pass" -ForegroundColor Green
                    } else {
                        Write-Host "Fail" -ForegroundColor Red
                        Write-Host "No properly configured outbound spam filter policies found." -ForegroundColor Red
                    }
                } catch {
                    Write-Host "Error retrieving Exchange Online Spam Policies." -ForegroundColor Red
                    Write-Host $_.Exception.Message
                    Write-Host "Fail" -ForegroundColor Red
                    
                    if ($Global:JsonOutputMode) {
                        Add-Finding -CheckId $script.CheckId `
                                -Asset "/tenants/$tenantid" `
                                -Status "ERROR" `
                                -Name "Exchange Online Spam Policies Check" `
                                -Description "Error occurred while checking outbound spam filter policies." `
                                -Details @{ "ErrorMessage" = $_.Exception.Message } `
                                -Impact "Minor" `
                                -Likelihood "Low" `
                                -Risk "Low"
                    }
                }
            }
        },
        @{
            Name = "2.1.7 Anti-Phishing Policy"
            Type = "Script"
            CheckId = "2.1.7"
            RequiresExchange = $true
            Logic = {
                try {
                    Disconnect-ExchangeOnline -Confirm:$false -ErrorAction SilentlyContinue
                    Connect-ExchangeOnline -CertificateThumbprint "$Thumbprint" -AppId "$AppId" -Organization "$Domain" -ShowBanner:$false
                    Start-Sleep 1
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
                    $policyResults = @()
        
                    foreach ($policy in $antiPhishPolicies) {
                        Write-Host "`nName: $($policy.Name)" -ForegroundColor Cyan
                        $policyPass = $true
                        $nonCompliantSettings = @()
        
                        foreach ($key in $expectedValues.Keys) {
                            $currentValue = $policy.$key
                            $desiredValue = $expectedValues[$key]
        
                            if ($currentValue -ne $desiredValue) {
                                Write-Host "$($key): " -NoNewline
                                Write-Host "$($currentValue)" -ForegroundColor Red -NoNewline
                                Write-Host " > Desired: " -NoNewline
                                Write-Host "$($desiredValue)" -ForegroundColor Green
                                $policyPass = $false
                                $nonCompliantSettings += @{
                                    "Setting" = $key
                                    "CurrentValue" = $currentValue
                                    "DesiredValue" = $desiredValue
                                }
                            } else {
                                Write-Host "$($key): $($currentValue)"
                            }
                        }
        
                        # Check for targeted users
                        if (-not $policy.TargetedUsersToProtect -or $policy.TargetedUsersToProtect.Count -eq 0) {
                            Write-Host "TargetedUsersToProtect: {}" -ForegroundColor Red -NoNewline
                            Write-Host " > Desired: Non-empty user list" -ForegroundColor Green
                            $policyPass = $false
                            $nonCompliantSettings += @{
                                "Setting" = "TargetedUsersToProtect"
                                "CurrentValue" = "Empty"
                                "DesiredValue" = "Non-empty user list"
                            }
                        } else {
                            Write-Host "TargetedUsersToProtect: $($policy.TargetedUsersToProtect -join ', ')"
                        }
        
                        # Build policy result for JSON output
                        $policyResult = @{
                            "Name" = $policy.Name
                            "IsCompliant" = $policyPass
                            "Settings" = @{}
                            "NonCompliantSettings" = $nonCompliantSettings
                        }
                        
                        # Add all settings to the JSON result
                        foreach ($key in $expectedValues.Keys) {
                            $policyResult.Settings[$key] = $policy.$key
                        }
                        
                        # Add TargetedUsersToProtect
                        $policyResult.Settings["TargetedUsersToProtect"] = if ($policy.TargetedUsersToProtect) { 
                            $policy.TargetedUsersToProtect -join ', ' 
                        } else { 
                            "Empty" 
                        }
                        
                        $policyResults += $policyResult
                        
                        if ($policyPass) {
                            $globalPass = $true
                        }
                    }
                    Write-Host ""
                    Write-Host ""
        
                    if ($Global:JsonOutputMode) {
                        $findingData = @{
                            "TotalPolicies" = $antiPhishPolicies.Count
                            "CompliantPolicies" = ($policyResults | Where-Object { $_.IsCompliant -eq $true }).Count
                            "PolicyResults" = $policyResults
                            "ExpectedValues" = $expectedValues
                        }
                        
                        if ($globalPass) {
                            Add-Finding -CheckId $script.CheckId `
                                    -Asset "/tenants/$tenantid" `
                                    -Status "PASS" `
                                    -Name "Anti-Phishing Policy Check" `
                                    -Description "At least one Anti-Phishing policy is properly configured." `
                                    -Details $findingData
                        } else {
                            Add-Finding -CheckId $script.CheckId `
                                    -Asset "/tenants/$tenantid" `
                                    -Status "FAIL" `
                                    -Name "Anti-Phishing Policy Check" `
                                    -Description "No Anti-Phishing policies are properly configured." `
                                    -Remediation "Configure Anti-Phishing policies according to the recommended settings." `
                                    -Details $findingData `
                                    -Impact "Moderate" `
                                    -Likelihood "Moderate" `
                                    -Risk "Medium"
                        }
                    }
        
                    if ($globalPass) {
                        Write-Host "`nPass: At least one policy is correctly configured." -ForegroundColor Green
                    } else {
                        Write-Host "`nFail: No policies are correctly configured." -ForegroundColor Red
                    }
                } catch {
                    Write-Host "Error retrieving Anti-Phishing Policy." -ForegroundColor Red
                    Write-Host $_.Exception.Message
                    
                    if ($Global:JsonOutputMode) {
                        Add-Finding -CheckId $script.CheckId `
                                -Asset "/tenants/$tenantid" `
                                -Status "ERROR" `
                                -Name "Anti-Phishing Policy Check" `
                                -Description "Error occurred while checking Anti-Phishing policies." `
                                -Details @{ "ErrorMessage" = $_.Exception.Message } `
                                -Impact "Minor" `
                                -Likelihood "Low" `
                                -Risk "Low"
                    }
                }
            }
        },
        @{
            Name = "2.1.8 SPF Records"
            Type = "Script"
            CheckId = "2.1.8"
            RequiresExchange = $true
            Logic = {
                try {
                    $dkimConfigs = Get-DkimSigningConfig
        
                    if (-not $dkimConfigs) {
                        Write-Host "No DKIM configurations found." -ForegroundColor Yellow
                        Write-Host "Fail" -ForegroundColor Red
                        
                        if ($Global:JsonOutputMode) {
                            Add-Finding -CheckId $script.CheckId `
                                    -Asset "/tenants/$tenantid" `
                                    -Status "FAIL" `
                                    -Name "SPF Records Check" `
                                    -Description "No DKIM configurations found to check SPF records." `
                                    -Remediation "Configure DKIM signing and ensure SPF records exist for your domains." `
                                    -Details @{ "Message" = "No DKIM configurations found" } `
                                    -Impact "Moderate" `
                                    -Likelihood "Moderate" `
                                    -Risk "Medium"
                        }
                        return
                    }
        
                    $domains = $dkimConfigs | Select-Object -ExpandProperty Domain
        
                    if (-not $domains) {
                        Write-Host "No domains found in DKIM configurations. Skipping SPF check." -ForegroundColor Yellow
                        Write-Host "Fail" -ForegroundColor Red
                        
                        if ($Global:JsonOutputMode) {
                            Add-Finding -CheckId $script.CheckId `
                                    -Asset "/tenants/$tenantid" `
                                    -Status "FAIL" `
                                    -Name "SPF Records Check" `
                                    -Description "No domains found in DKIM configurations." `
                                    -Remediation "Configure domains for DKIM signing and ensure SPF records exist." `
                                    -Details @{ "Message" = "No domains found in DKIM configurations" } `
                                    -Impact "Moderate" `
                                    -Likelihood "Moderate" `
                                    -Risk "Medium"
                        }
                        return
                    }
        
                    $pass = $true
                    $domainResults = @()
                    
                    foreach ($domain in $domains) {
                        $domainResult = @{
                            "Domain" = $domain
                            "HasSPFRecord" = $false
                            "SPFRecord" = ""
                            "Error" = $null
                        }
                        
                        try {
                            $spfRecord = Resolve-DnsName -Name $domain -Type TXT -ErrorAction Stop | 
                                        Where-Object { $_.Strings -like "*v=spf1 include:spf.protection.outlook.com*" }
                            
                            if ($spfRecord) {
                                $domainResult.HasSPFRecord = $true
                                $domainResult.SPFRecord = ($spfRecord.Strings -join " ")
                                Write-Host ""
                                Write-Host "SPF Record exists for $($domain)." -ForegroundColor Green
                                Write-Host "Record: $($domainResult.SPFRecord)" -ForegroundColor Green
                            } else {
                                $pass = $false
                                Write-Host ""
                                Write-Host "SPF Record does not exist for $($domain)." -ForegroundColor Red
                            }
                        } catch {
                            $pass = $false
                            $domainResult.Error = $_.Exception.Message
                            Write-Host "Failed to resolve SPF record for $($domain)" -ForegroundColor Red
                            Write-Host $_.Exception.Message
                        }
                        
                        $domainResults += $domainResult
                    }
                    
                    Write-Host ""
                    Write-Host ""
                    
                    # Add JSON findings
                    if ($Global:JsonOutputMode) {
                        $findingData = @{
                            "TotalDomains" = $domains.Count
                            "DomainsWithSPF" = ($domainResults | Where-Object { $_.HasSPFRecord -eq $true }).Count
                            "DomainResults" = $domainResults
                        }
                        
                        if ($pass) {
                            Add-Finding -CheckId $script.CheckId `
                                    -Asset "/tenants/$tenantid" `
                                    -Status "PASS" `
                                    -Name "SPF Records Check" `
                                    -Description "All domains have SPF records configured." `
                                    -Details $findingData
                        } else {
                            Add-Finding -CheckId $script.CheckId `
                                    -Asset "/tenants/$tenantid" `
                                    -Status "FAIL" `
                                    -Name "SPF Records Check" `
                                    -Description "One or more domains are missing SPF records." `
                                    -Remediation "Configure SPF records for all domains with 'v=spf1 include:spf.protection.outlook.com'." `
                                    -Details $findingData `
                                    -Impact "Moderate" `
                                    -Likelihood "Moderate" `
                                    -Risk "Medium"
                        }
                    }
        
                    if ($pass) {
                        Write-Host "Pass" -ForegroundColor Green
                    } else {
                        Write-Host "Fail: SPF records missing" -ForegroundColor Red
                    }
                } catch {
                    Write-Host "Error retrieving SPF Records." -ForegroundColor Red
                    Write-Host $_.Exception.Message
                    Write-Host "Fail" -ForegroundColor Red
                    
                    if ($Global:JsonOutputMode) {
                        Add-Finding -CheckId $script.CheckId `
                                -Asset "/tenants/$tenantid" `
                                -Status "ERROR" `
                                -Name "SPF Records Check" `
                                -Description "Error occurred while checking SPF records." `
                                -Details @{ "ErrorMessage" = $_.Exception.Message } `
                                -Impact "Minor" `
                                -Likelihood "Low" `
                                -Risk "Low"
                    }
                }
            }
        },
        @{
            Name = "2.1.9 DKIM Signing"
            Type = "Script"
            CheckId = "2.1.9"
            RequiresExchange = $true
            Logic = {
                try {
                    Disconnect-ExchangeOnline -Confirm:$false -ErrorAction SilentlyContinue
                    Connect-ExchangeOnline -CertificateThumbprint "$Thumbprint" -AppId "$AppId" -Organization "$Domain" -ShowBanner:$false
                    Start-Sleep 1
                    $dkimConfig = Get-DkimSigningConfig
        
                    if ($dkimConfig.Count -eq 0) {
                        Write-Host "No DKIM Signing Configurations found." -ForegroundColor Yellow
                        Write-Host "Fail" -ForegroundColor Red
                        
                        if ($Global:JsonOutputMode) {
                            Add-Finding -CheckId $script.CheckId `
                                    -Asset "/tenants/$tenantid" `
                                    -Status "FAIL" `
                                    -Name "DKIM Signing Check" `
                                    -Description "No DKIM Signing Configurations found." `
                                    -Remediation "Configure DKIM signing for your domains." `
                                    -Details @{ "Message" = "No DKIM configurations found" } `
                                    -Impact "Moderate" `
                                    -Likelihood "Moderate" `
                                    -Risk "Medium"
                        }
                        return
                    }
        
                    $filteredConfig = $dkimConfig | Where-Object { $_.Domain -notlike "*.onmicrosoft.com" }
        
                    if ($filteredConfig.Count -eq 0) {
                        Write-Host "No relevant domains found (excluding .onmicrosoft.com domains)." -ForegroundColor Yellow
                        Write-Host "Fail" -ForegroundColor Red
                        
                        if ($Global:JsonOutputMode) {
                            Add-Finding -CheckId $script.CheckId `
                                    -Asset "/tenants/$tenantid" `
                                    -Status "FAIL" `
                                    -Name "DKIM Signing Check" `
                                    -Description "No relevant domains found for DKIM signing (excluding .onmicrosoft.com domains)." `
                                    -Remediation "Configure DKIM signing for your custom domains." `
                                    -Details @{ 
                                        "Message" = "No relevant domains found (excluding .onmicrosoft.com domains)";
                                        "OnMicrosoftDomains" = ($dkimConfig | Select-Object -ExpandProperty Domain) -join ", "
                                    } `
                                    -Impact "Moderate" `
                                    -Likelihood "Moderate" `
                                    -Risk "Medium"
                        }
                        return
                    }
        
                    $allEnabled = $true
                    $domainResults = @()
                    
                    foreach ($config in $filteredConfig) {
                        $domainResult = @{
                            "Domain" = $config.Domain
                            "Enabled" = $config.Enabled
                            "Status" = $config.Status
                            "IsCompliant" = $config.Enabled -eq $true
                        }
                        
                        if (-not $config.Enabled) {
                            Write-Host "DKIM Signing is Disabled for domain: $($config.Domain)" -ForegroundColor Red
                            $allEnabled = $false
                        } else {
                            Write-Host "DKIM Signing is Enabled for domain: $($config.Domain)" -ForegroundColor Green
                        }
                        
                        $domainResults += $domainResult
                    }
                    
                    Write-Host ""
                    Write-Host ""
                    
                    # Add JSON findings
                    if ($Global:JsonOutputMode) {
                        $findingData = @{
                            "TotalDomains" = $filteredConfig.Count
                            "EnabledDomains" = ($domainResults | Where-Object { $_.Enabled -eq $true }).Count
                            "DomainResults" = $domainResults
                        }
                        
                        if ($allEnabled) {
                            Add-Finding -CheckId $script.CheckId `
                                    -Asset "/tenants/$tenantid" `
                                    -Status "PASS" `
                                    -Name "DKIM Signing Check" `
                                    -Description "DKIM signing is enabled for all relevant domains." `
                                    -Details $findingData
                        } else {
                            Add-Finding -CheckId $script.CheckId `
                                    -Asset "/tenants/$tenantid" `
                                    -Status "FAIL" `
                                    -Name "DKIM Signing Check" `
                                    -Description "DKIM signing is not enabled for all relevant domains." `
                                    -Remediation "Enable DKIM signing for all domains that do not have it enabled." `
                                    -Details $findingData `
                                    -Impact "Moderate" `
                                    -Likelihood "Moderate" `
                                    -Risk "Medium"
                        }
                    }
        
                    if ($allEnabled) {
                        Write-Host "Pass" -ForegroundColor Green
                    } else {
                        Write-Host "Fail: DKIM signing disabled" -ForegroundColor Red
                    }
                } catch {
                    Write-Host "Error retrieving DKIM Signing Configurations." -ForegroundColor Red
                    Write-Host $_.Exception.Message
                    Write-Host "Fail" -ForegroundColor Red
                    
                    if ($Global:JsonOutputMode) {
                        Add-Finding -CheckId $script.CheckId `
                                -Asset "/tenants/$tenantid" `
                                -Status "ERROR" `
                                -Name "DKIM Signing Check" `
                                -Description "Error occurred while checking DKIM signing configurations." `
                                -Details @{ "ErrorMessage" = $_.Exception.Message } `
                                -Impact "Minor" `
                                -Likelihood "Low" `
                                -Risk "Low"
                    }
                }
            }
        },
        @{
            Name = "2.1.10 DMARC Records"
            Type = "Script"
            CheckId = "2.1.10"
            RequiresExchange = $true
            Logic = {
                try {
                    $dkimConfigs = Get-DkimSigningConfig
        
                    if (-not $dkimConfigs) {
                        Write-Host "No DKIM configurations found." -ForegroundColor Yellow
                        Write-Host "Fail: No domains available for DMARC check." -ForegroundColor Red
                        
                        if ($Global:JsonOutputMode) {
                            Add-Finding -CheckId $script.CheckId `
                                    -Asset "/tenants/$tenantid" `
                                    -Status "FAIL" `
                                    -Name "DMARC Records Check" `
                                    -Description "No DKIM configurations found to check DMARC records." `
                                    -Remediation "Configure DKIM signing and ensure DMARC records exist for your domains." `
                                    -Details @{ "Message" = "No DKIM configurations found" } `
                                    -Impact "Moderate" `
                                    -Likelihood "Moderate" `
                                    -Risk "Medium"
                        }
                        return
                    }
        
                    $domains = $dkimConfigs | Select-Object -ExpandProperty Domain
        
                    if (-not $domains) {
                        Write-Host "No domains found in DKIM configurations." -ForegroundColor Yellow
                        Write-Host "Fail: No domains available for DMARC check." -ForegroundColor Red
                        
                        if ($Global:JsonOutputMode) {
                            Add-Finding -CheckId $script.CheckId `
                                    -Asset "/tenants/$tenantid" `
                                    -Status "FAIL" `
                                    -Name "DMARC Records Check" `
                                    -Description "No domains found in DKIM configurations to check DMARC records." `
                                    -Remediation "Configure domains for DKIM signing and ensure DMARC records exist." `
                                    -Details @{ "Message" = "No domains found in DKIM configurations" } `
                                    -Impact "Moderate" `
                                    -Likelihood "Moderate" `
                                    -Risk "Medium"
                        }
                        return
                    }
        
                    $missingDmarc = @()
                    $domainResults = @()
                    
                    foreach ($domain in $domains) {
                        $dmarcDomain = "_dmarc.$domain"
                        $domainResult = @{
                            "Domain" = $domain
                            "DmarcDomain" = $dmarcDomain
                            "HasDmarcRecord" = $false
                            "Error" = $null
                        }
        
                        try {
                            $dmarcRecord = Resolve-DnsName -Name $dmarcDomain -Type TXT -ErrorAction Stop
                            Write-Host "DMARC Record for $($dmarcDomain) found." -ForegroundColor Green
                            $domainResult.HasDmarcRecord = $true
                            if ($dmarcRecord.Strings) {
                                $domainResult.DmarcRecord = $dmarcRecord.Strings -join " "
                            }
                        } catch {
                            Write-Host "DMARC Record for $($dmarcDomain) not found." -ForegroundColor Red
                            $missingDmarc += $domain
                            $domainResult.Error = $_.Exception.Message
                        }
                        
                        $domainResults += $domainResult
                    }
                    
                    Write-Host ""
                    Write-Host ""
        
                    if ($missingDmarc.Count -eq 0) {
                        Write-Host "Pass: All domains have DMARC records." -ForegroundColor Green
                        
                        if ($Global:JsonOutputMode) {
                            Add-Finding -CheckId $script.CheckId `
                                    -Asset "/tenants/$tenantid" `
                                    -Status "PASS" `
                                    -Name "DMARC Records Check" `
                                    -Description "All domains have DMARC records configured." `
                                    -Details @{
                                        "TotalDomains" = $domains.Count
                                        "DomainsWithDMARC" = $domains.Count
                                        "DomainResults" = $domainResults
                                    }
                        }
                    } else {
                        Write-Host "Fail: The following domains are missing DMARC records:" -ForegroundColor Red
                        $missingDmarc | ForEach-Object { Write-Host $_ -ForegroundColor Red }
                        
                        if ($Global:JsonOutputMode) {
                            Add-Finding -CheckId $script.CheckId `
                                    -Asset "/tenants/$tenantid" `
                                    -Status "FAIL" `
                                    -Name "DMARC Records Check" `
                                    -Description "One or more domains are missing DMARC records." `
                                    -Remediation "Configure DMARC records for all domains with appropriate policy settings." `
                                    -Details @{
                                        "TotalDomains" = $domains.Count
                                        "DomainsWithDMARC" = ($domains.Count - $missingDmarc.Count)
                                        "MissingDomains" = $missingDmarc
                                        "DomainResults" = $domainResults
                                    } `
                                    -Impact "Moderate" `
                                    -Likelihood "Moderate" `
                                    -Risk "Medium"
                        }
                    }
                } catch {
                    Write-Host "Error retrieving DMARC Records." -ForegroundColor Red
                    Write-Host $_.Exception.Message
                    
                    if ($Global:JsonOutputMode) {
                        Add-Finding -CheckId $script.CheckId `
                                -Asset "/tenants/$tenantid" `
                                -Status "ERROR" `
                                -Name "DMARC Records Check" `
                                -Description "Error occurred while checking DMARC records." `
                                -Details @{ "ErrorMessage" = $_.Exception.Message } `
                                -Impact "Minor" `
                                -Likelihood "Low" `
                                -Risk "Low"
                    }
                }
            }
        },
        @{
            Name = "2.1.11 Comprehensive Attachment Filtering"
            Type = "Script"
            CheckId = "2.1.11"
            RequiresExchange = $true
            Logic = {
                try {
                    Disconnect-ExchangeOnline -Confirm:$false -ErrorAction SilentlyContinue
                    Connect-ExchangeOnline -CertificateThumbprint "$Thumbprint" -AppId "$AppId" -Organization "$Domain" -ShowBanner:$false
                    Start-Sleep 1
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
                        
                        if ($Global:JsonOutputMode) {
                            Add-Finding -CheckId $script.CheckId `
                                    -Asset "/tenants/$tenantid" `
                                    -Status "FAIL" `
                                    -Name "Comprehensive Attachment Filtering Check" `
                                    -Description "No malware filter policies with comprehensive file extension coverage were found." `
                                    -Remediation "Configure malware filter policies to include at least 50 file extensions." `
                                    -Details @{ "Message" = "No malware filter policies with over 50 extensions were found" } `
                                    -Impact "Moderate" `
                                    -Likelihood "Moderate" `
                                    -Risk "Medium"
                        }
                        return
                    }
        
                    $missingExtensionsOverall = @()
                    $policyResults = @()
                    
                    foreach ($policy in $ExtensionPolicies) {
                        $MissingExtensions = $L2Extensions | Where-Object { -not $policy.FileTypes.Contains($_) }
                        $policyResult = @{
                            "Identity" = $policy.Identity
                            "TotalFileTypes" = $policy.FileTypes.Count
                            "MissingExtensions" = $MissingExtensions
                            "IsCompliant" = ($MissingExtensions.Count -eq 0)
                        }
                        $policyResults += $policyResult
        
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
                        
                        if ($Global:JsonOutputMode) {
                            Add-Finding -CheckId $script.CheckId `
                                    -Asset "/tenants/$tenantid" `
                                    -Status "FAIL" `
                                    -Name "Comprehensive Attachment Filtering Check" `
                                    -Description "Some recommended file extensions are not covered by malware filter policies." `
                                    -Remediation "Add the missing file extensions to the malware filter policies." `
                                    -Details @{ 
                                        "TotalPolicies" = $ExtensionPolicies.Count
                                        "MissingExtensionsCount" = $missingExtensionsOverall.Count
                                        "MissingExtensions" = ($missingExtensionsOverall | Select-Object -Unique)
                                        "PolicyResults" = $policyResults
                                        "RecommendedExtensions" = $L2Extensions
                                    } `
                                    -Impact "Moderate" `
                                    -Likelihood "Moderate" `
                                    -Risk "Medium"
                            }
                        } else {
                        Write-Host "Pass: All required extensions are present in all policies." -ForegroundColor Green
                        
                        if ($Global:JsonOutputMode) {
                            Add-Finding -CheckId $script.CheckId `
                                    -Asset "/tenants/$tenantid" `
                                    -Status "PASS" `
                                    -Name "Comprehensive Attachment Filtering Check" `
                                    -Description "All recommended file extensions are covered by malware filter policies." `
                                    -Details @{ 
                                        "TotalPolicies" = $ExtensionPolicies.Count
                                        "PolicyResults" = $policyResults
                                    }
                        }
                    }
                } catch {
                    Write-Host "Error processing Comprehensive Attachment Filtering." -ForegroundColor Red
                    Write-Host $_.Exception.Message
                    
                    if ($Global:JsonOutputMode) {
                        Add-Finding -CheckId $script.CheckId `
                                -Asset "/tenants/$tenantid" `
                                -Status "ERROR" `
                                -Name "Comprehensive Attachment Filtering Check" `
                                -Description "Error occurred while checking attachment filtering policies." `
                                -Details @{ "ErrorMessage" = $_.Exception.Message } `
                                -Impact "Minor" `
                                -Likelihood "Low" `
                                -Risk "Low"
                    }
                }
            }
        },
        @{
            Name = "2.1.12 Connection Filter IP Allow List"
            Type = "Script"
            CheckId = "2.1.12"
            RequiresExchange = $true
            Logic = {
                try {
                    Disconnect-ExchangeOnline -Confirm:$false -ErrorAction SilentlyContinue
                    Connect-ExchangeOnline -CertificateThumbprint "$Thumbprint" -AppId "$AppId" -Organization "$Domain" -ShowBanner:$false
                    Start-Sleep 1
                    $connectionFilter = Get-HostedConnectionFilterPolicy -Identity Default
        
                    if ($connectionFilter.IPAllowList -ne $null -and $connectionFilter.IPAllowList.Count -gt 0) {
                        Write-Host "IPAllowList contains:" -ForegroundColor Red
                        $connectionFilter.IPAllowList | Format-Table -AutoSize
                        Write-Host ""
                        Write-Host ""
                        Write-Host "Fail: IP Allow List is not empty." -ForegroundColor Red
                        
                        if ($Global:JsonOutputMode) {
                            Add-Finding -CheckId $script.CheckId `
                                    -Asset "/tenants/$tenantid" `
                                    -Status "FAIL" `
                                    -Name "Connection Filter IP Allow List Check" `
                                    -Description "IP Allow List should be empty for security best practices." `
                                    -Remediation "Remove all IP addresses from the IP Allow List in the Connection Filter policy." `
                                    -Details @{ 
                                        "IPAllowListCount" = $connectionFilter.IPAllowList.Count
                                        "IPAllowList" = $connectionFilter.IPAllowList
                                    } `
                                    -Impact "Moderate" `
                                    -Likelihood "Moderate" `
                                    -Risk "Medium"
                        }
                        } else {
                        Write-Host ""
                        Write-Host ""
                        Write-Host "Pass: IP Allow List is empty." -ForegroundColor Green
                        
                        if ($Global:JsonOutputMode) {
                            Add-Finding -CheckId $script.CheckId `
                                    -Asset "/tenants/$tenantid" `
                                    -Status "PASS" `
                                    -Name "Connection Filter IP Allow List Check" `
                                    -Description "IP Allow List is empty as recommended." `
                                    -Details @{ "IPAllowListCount" = 0 }
                        }
                    }
                } catch {
                    Write-Host "Error checking Connection Filter IP Allow List." -ForegroundColor Red
                    Write-Host $_.Exception.Message
                    
                    if ($Global:JsonOutputMode) {
                        Add-Finding -CheckId $script.CheckId `
                                -Asset "/tenants/$tenantid" `
                                -Status "ERROR" `
                                -Name "Connection Filter IP Allow List Check" `
                                -Description "Error occurred while checking Connection Filter IP Allow List." `
                                -Details @{ "ErrorMessage" = $_.Exception.Message } `
                                -Impact "Minor" `
                                -Likelihood "Low" `
                                -Risk "Low"
                    }
                }
            }
        },
        @{
            Name = "2.1.13 Connection Filter Safe List"
            Type = "Script"
            CheckId = "2.1.13"
            RequiresExchange = $true
            Logic = {
                try {
                    Disconnect-ExchangeOnline -Confirm:$false -ErrorAction SilentlyContinue
                    Connect-ExchangeOnline -CertificateThumbprint "$Thumbprint" -AppId "$AppId" -Organization "$Domain" -ShowBanner:$false
                    Start-Sleep 1
                    $connectionFilter = Get-HostedConnectionFilterPolicy -Identity Default
        
                    if ($connectionFilter.EnableSafeList -eq $true) {
                        Write-Host ""
                        Write-Host ""
                        Write-Host "Fail: Safe List is enabled." -ForegroundColor Red
                        
                        if ($Global:JsonOutputMode) {
                            Add-Finding -CheckId $script.CheckId `
                                    -Asset "/tenants/$tenantid" `
                                    -Status "FAIL" `
                                    -Name "Connection Filter Safe List Check" `
                                    -Description "Safe List is enabled, which could allow potentially malicious messages to bypass filtering." `
                                    -Remediation "Disable the Safe List option in the Connection Filter policy." `
                                    -Details @{ "EnableSafeList" = $connectionFilter.EnableSafeList } `
                                    -Impact "Moderate" `
                                    -Likelihood "Moderate" `
                                    -Risk "Medium"
                        }
                    } else {
                        Write-Host ""
                        Write-Host ""
                        Write-Host "Pass: Safe List is disabled." -ForegroundColor Green
                        
                        if ($Global:JsonOutputMode) {
                            Add-Finding -CheckId $script.CheckId `
                                    -Asset "/tenants/$tenantid" `
                                    -Status "PASS" `
                                    -Name "Connection Filter Safe List Check" `
                                    -Description "Safe List is disabled as recommended." `
                                    -Details @{ "EnableSafeList" = $connectionFilter.EnableSafeList }
                        }
                    }
                } catch {
                    Write-Host "Error checking Connection Filter Safe List." -ForegroundColor Red
                    Write-Host $_.Exception.Message
                    
                    if ($Global:JsonOutputMode) {
                        Add-Finding -CheckId $script.CheckId `
                                -Asset "/tenants/$tenantid" `
                                -Status "ERROR" `
                                -Name "Connection Filter Safe List Check" `
                                -Description "Error occurred while checking Connection Filter Safe List." `
                                -Details @{ "ErrorMessage" = $_.Exception.Message } `
                                -Impact "Minor" `
                                -Likelihood "Low" `
                                -Risk "Low"
                    }
                }
            }
        },
        @{
            Name = "2.1.14 Inbound Anti-Spam Policies"
            Type = "Script"
            CheckId = "2.1.14"
            RequiresExchange = $true
            Logic = {
                try {
                    Disconnect-ExchangeOnline -Confirm:$false -ErrorAction SilentlyContinue
                    Connect-ExchangeOnline -CertificateThumbprint "$Thumbprint" -AppId "$AppId" -Organization "$Domain" -ShowBanner:$false
                    Start-Sleep 1
                    $antiSpamPolicy = Get-HostedContentFilterPolicy -Identity Default
                    $allOK = $true
                    $issueDetails = @{}
                    
                    Write-Host ""
                    Write-Host ""
                    
                    if ($antiSpamPolicy.HighConfidenceSpamAction -ne "Quarantine") {
                        Write-Host "Fail: HighConfidenceSpamAction is not set to Quarantine. Current value: $($antiSpamPolicy.HighConfidenceSpamAction)" -ForegroundColor Red
                        $allOK = $false
                        $issueDetails["HighConfidenceSpamAction"] = $antiSpamPolicy.HighConfidenceSpamAction
                    }
                    
                    if ($antiSpamPolicy.SpamAction -ne "MoveToJmf") {
                        Write-Host "Fail: SpamAction is not set to MoveToJmf. Current value: $($antiSpamPolicy.SpamAction)" -ForegroundColor Red
                        $allOK = $false
                        $issueDetails["SpamAction"] = $antiSpamPolicy.SpamAction
                    }
                    
                    if ($antiSpamPolicy.BulkSpamAction -ne "MoveToJmf") {
                        Write-Host "Fail: BulkSpamAction is not set to MoveToJmf. Current value: $($antiSpamPolicy.BulkSpamAction)" -ForegroundColor Red
                        $allOK = $false
                        $issueDetails["BulkSpamAction"] = $antiSpamPolicy.BulkSpamAction
                    }
                    
                    if ($antiSpamPolicy.PhishSpamAction -ne "Quarantine") {
                        Write-Host "Fail: PhishSpamAction is not set to Quarantine. Current value: $($antiSpamPolicy.PhishSpamAction)" -ForegroundColor Red
                        $allOK = $false
                        $issueDetails["PhishSpamAction"] = $antiSpamPolicy.PhishSpamAction
                    }
                    
                    if ($antiSpamPolicy.HighConfidencePhishAction -ne "Quarantine") {
                        Write-Host "Fail: HighConfidencePhishAction is not set to Quarantine. Current value: $($antiSpamPolicy.HighConfidencePhishAction)" -ForegroundColor Red
                        $allOK = $false
                        $issueDetails["HighConfidencePhishAction"] = $antiSpamPolicy.HighConfidencePhishAction
                    }
                    
                    if ($antiSpamPolicy.EnableEndUserSpamNotifications -ne $true) {
                        Write-Host "Fail: EnableEndUserSpamNotifications is not enabled. Current value: $($antiSpamPolicy.EnableEndUserSpamNotifications)" -ForegroundColor Red
                        $allOK = $false
                        $issueDetails["EnableEndUserSpamNotifications"] = $antiSpamPolicy.EnableEndUserSpamNotifications
                    }
                    
                    if ($antiSpamPolicy.SpamZapEnabled -ne $true) {
                        Write-Host "Fail: SpamZapEnabled is not enabled. Current value: $($antiSpamPolicy.SpamZapEnabled)" -ForegroundColor Red
                        $allOK = $false
                        $issueDetails["SpamZapEnabled"] = $antiSpamPolicy.SpamZapEnabled
                    }
                    
                    if ($antiSpamPolicy.PhishZapEnabled -ne $true) {
                        Write-Host "Fail: PhishZapEnabled is not enabled. Current value: $($antiSpamPolicy.PhishZapEnabled)" -ForegroundColor Red
                        $allOK = $false
                        $issueDetails["PhishZapEnabled"] = $antiSpamPolicy.PhishZapEnabled
                    }
                    
                    # Check if all tests passed
                    if ($allOK) {
                        Write-Host "Pass: All Anti-Spam settings are configured correctly." -ForegroundColor Green
                        
                        if ($Global:JsonOutputMode) {
                            Add-Finding -CheckId $script.CheckId `
                                    -Asset "/tenants/$tenantid" `
                                    -Status "PASS" `
                                    -Name "Inbound Anti-Spam Policies Check" `
                                    -Description "All Anti-Spam settings are configured correctly." `
                                    -Details @{
                                            "HighConfidenceSpamAction" = $antiSpamPolicy.HighConfidenceSpamAction
                                            "SpamAction" = $antiSpamPolicy.SpamAction
                                            "BulkSpamAction" = $antiSpamPolicy.BulkSpamAction
                                            "PhishSpamAction" = $antiSpamPolicy.PhishSpamAction
                                            "HighConfidencePhishAction" = $antiSpamPolicy.HighConfidencePhishAction
                                            "EnableEndUserSpamNotifications" = $antiSpamPolicy.EnableEndUserSpamNotifications
                                            "SpamZapEnabled" = $antiSpamPolicy.SpamZapEnabled
                                            "PhishZapEnabled" = $antiSpamPolicy.PhishZapEnabled
                                    }
                        }
                    } else {
                        if ($Global:JsonOutputMode) {
                            Add-Finding -CheckId $script.CheckId `
                                    -Asset "/tenants/$tenantid" `
                                    -Status "FAIL" `
                                    -Name "Inbound Anti-Spam Policies Check" `
                                    -Description "One or more Anti-Spam settings are not configured correctly." `
                                    -Remediation "Configure Anti-Spam policies with recommended settings:
                                        - HighConfidenceSpamAction: Quarantine
                                        - SpamAction: MoveToJmf
                                        - BulkSpamAction: MoveToJmf
                                        - PhishSpamAction: Quarantine
                                        - HighConfidencePhishAction: Quarantine
                                        - EnableEndUserSpamNotifications: True
                                        - SpamZapEnabled: True
                                        - PhishZapEnabled: True" `
                                    -Details $issueDetails `
                                    -Impact "Moderate" `
                                    -Likelihood "Moderate" `
                                    -Risk "Medium"
                        }
                    }
                } catch {
                    Write-Host "Error checking Inbound Anti-Spam Policies." -ForegroundColor Red
                    Write-Host $_.Exception.Message
                                            if ($Global:JsonOutputMode) {
                            Add-Finding -CheckId $script.CheckId `
                                -Asset "/tenants/$tenantid" `
                                -Status "ERROR" `
                                -Name "Inbound Anti-Spam Policies Check" `
                                -Description "Error occurred while checking Inbound Anti-Spam Policies." `
                                -Details @{ "ErrorMessage" = $_.Exception.Message } `
                                -Impact "Minor" `
                                -Likelihood "Low" `
                                -Risk "Low"
                    }
                }
            }
        },
        @{
        Name = "2.4.1 Priority Account Protection Check"
        Type = "Script"
        CheckId = "2.4.1"
        Logic = {
            try {
                $response = Get-EmailTenantSettings

                Write-Host "Raw Cmdlet Output:"
                Write-Host ($response | ConvertTo-Json -Depth 10)
                Write-Host ""

                if (-not $response.PSObject.Properties["EnablePriorityAccountProtection"]) {
                    Write-Host "Fail: 'EnablePriorityAccountProtection' not found in output." -ForegroundColor Red
                    
                    if ($Global:JsonOutputMode) {
                        Add-Finding -CheckId $script.CheckId `
                                -Asset "/tenants/$tenantid" `
                                -Status "FAIL" `
                                -Name "Priority Account Protection Check" `
                                -Description "Priority Account Protection property was not found in tenant settings." `
                                -Remediation "Verify that your tenant has the appropriate licenses to use Priority Account Protection." `
                                -Details @{ "Error" = "EnablePriorityAccountProtection property not found in response" } `
                                -Impact "Moderate" `
                                -Likelihood "Moderate" `
                                -Risk "Medium"
                    }
                    return
                }

                $isPriorityProtectionEnabled = $response.EnablePriorityAccountProtection

                if ($isPriorityProtectionEnabled -eq $true) {
                    Write-Host "Pass: Priority Account Protection is enabled." -ForegroundColor Green
                    
                    if ($Global:JsonOutputMode) {
                        Add-Finding -CheckId $script.CheckId `
                                -Asset "/tenants/$tenantid" `
                                -Status "PASS" `
                                -Name "Priority Account Protection Check" `
                                -Description "Priority Account Protection is enabled as recommended." `
                                -Details @{ "EnablePriorityAccountProtection" = $isPriorityProtectionEnabled }
                    }
                } else {
                    Write-Host "Fail: Priority Account Protection is not enabled." -ForegroundColor Red
                    
                    if ($Global:JsonOutputMode) {
                        Add-Finding -CheckId $script.CheckId `
                                -Asset "/tenants/$tenantid" `
                                -Status "FAIL" `
                                -Name "Priority Account Protection Check" `
                                -Description "Priority Account Protection is not enabled." `
                                -Remediation "Enable Priority Account Protection in Microsoft 365 Defender portal to provide enhanced protection for high-value users." `
                                -Details @{ "EnablePriorityAccountProtection" = $isPriorityProtectionEnabled } `
                                -Impact "Moderate" `
                                -Likelihood "Moderate" `
                                -Risk "Medium"
                    }
                }
            } catch {
                Write-Host "Error retrieving Email Tenant Settings." -ForegroundColor Red
                Write-Host $_.Exception.Message
                
                if ($Global:JsonOutputMode) {
                    Add-Finding -CheckId $script.CheckId `
                            -Asset "/tenants/$tenantid" `
                            -Status "ERROR" `
                            -Name "Priority Account Protection Check" `
                            -Description "Error occurred while checking Priority Account Protection settings." `
                            -Details @{ "ErrorMessage" = $_.Exception.Message } `
                            -Impact "Minor" `
                            -Likelihood "Low" `
                            -Risk "Low"
                }
            }
        }
    },
        @{
            Name = "2.4.4 Zero Hour Purge for Teams"
            Type = "Script"
            CheckId = "2.4.4"
            Logic = {
                try {
                    Disconnect-ExchangeOnline -Confirm:$false -ErrorAction SilentlyContinue
                    Connect-ExchangeOnline -CertificateThumbprint "$Thumbprint" -AppId "$AppId" -Organization "$Domain" -ShowBanner:$false
                    Start-Sleep 1
                    $teamsProtectionPolicies = Get-TeamsProtectionPolicy | Select-Object Name, ZapEnabled
                    
                    if ($teamsProtectionPolicies.Count -eq 0) {
                        Write-Host "No Teams Protection policies found." -ForegroundColor Yellow
                        
                        if ($Global:JsonOutputMode) {
                            Add-Finding -CheckId $script.CheckId `
                                    -Asset "/tenants/$tenantid" `
                                    -Status "FAIL" `
                                    -Name "Zero Hour Purge for Teams Check" `
                                    -Description "No Teams Protection policies were found." `
                                    -Remediation "Configure Teams Protection policies with Zero Hour Purge enabled." `
                                    -Details @{ "Message" = "No Teams Protection policies found" } `
                                    -Impact "Moderate" `
                                    -Likelihood "Moderate" `
                                    -Risk "Medium"
                        }
                        return
                    }
        
                    $isPass = $true
                    $policyDetails = @()
        
                    foreach ($policy in $teamsProtectionPolicies) {
                        $policyDetail = @{
                            "Name" = $policy.Name
                            "ZapEnabled" = $policy.ZapEnabled
                            "IsCompliant" = ($policy.ZapEnabled -eq $true)
                        }
                        $policyDetails += $policyDetail
                        
                        if ($policy.ZapEnabled -eq $true) {
                            Write-Host "Policy '$($policy.Name)' - ZapEnabled: $($policy.ZapEnabled)" -ForegroundColor Green
                        } else {
                            Write-Host "Policy '$($policy.Name)' - ZapEnabled: $($policy.ZapEnabled)" -ForegroundColor Red
                            $isPass = $false
                        }
                    }
                    Write-Host ""
                    Write-Host ""
        
                    # Show exception rules for context
                    $exceptionRules = Get-TeamsProtectionPolicyRule | Select-Object Name, ExceptIfSenderDomainIs, ExceptIfSentToMemberOf
                    if ($exceptionRules) {
                        Write-Host "Teams Protection Policy Exception Rules:" -ForegroundColor Cyan
                        $exceptionRules | Format-List
                    }
        
                    if ($isPass) {
                        Write-Host "Pass: All policies have ZapEnabled set to true." -ForegroundColor Green
                        
                        if ($Global:JsonOutputMode) {
                            Add-Finding -CheckId $script.CheckId `
                                    -Asset "/tenants/$tenantid" `
                                    -Status "PASS" `
                                    -Name "Zero Hour Purge for Teams Check" `
                                    -Description "All Teams Protection policies have Zero Hour Purge enabled." `
                                    -Details @{ 
                                        "TotalPolicies" = $teamsProtectionPolicies.Count
                                        "PolicyDetails" = $policyDetails
                                        "ExceptionRules" = $exceptionRules
                                    }
                        }
                    } else {
                        Write-Host "Fail: One or more policies have ZapEnabled not set to true." -ForegroundColor Red
                        
                        if ($Global:JsonOutputMode) {
                            Add-Finding -CheckId $script.CheckId `
                                    -Asset "/tenants/$tenantid" `
                                    -Status "FAIL" `
                                    -Name "Zero Hour Purge for Teams Check" `
                                    -Description "One or more Teams Protection policies do not have Zero Hour Purge enabled." `
                                    -Remediation "Enable Zero Hour Purge (ZapEnabled) on all Teams Protection policies to automatically remove dangerous content after detection." `
                                    -Details @{ 
                                        "TotalPolicies" = $teamsProtectionPolicies.Count
                                        "PolicyDetails" = $policyDetails
                                        "NonCompliantPolicies" = ($policyDetails | Where-Object { $_.IsCompliant -eq $false }).Count
                                        "ExceptionRules" = $exceptionRules
                                    } `
                                    -Impact "Moderate" `
                                    -Likelihood "Moderate" `
                                    -Risk "Medium"
                        }
                    }
                } catch {
                    Write-Host "Error checking Zero Hour Purge for Teams." -ForegroundColor Red
                    Write-Host $_.Exception.Message
                    
                    if ($Global:JsonOutputMode) {
                        Add-Finding -CheckId $script.CheckId `
                                -Asset "/tenants/$tenantid" `
                                -Status "ERROR" `
                                -Name "Zero Hour Purge for Teams Check" `
                                -Description "Error occurred while checking Zero Hour Purge for Teams." `
                                -Details @{ "ErrorMessage" = $_.Exception.Message } `
                                -Impact "Minor" `
                                -Likelihood "Low" `
                                -Risk "Low"
                    }
                }
            }
        },    
        @{
            Name = "3.1.1 Audit Log Search"
            Type = "Script"
            CheckId = "3.1.1"
            RequiresExchange = $true
            Logic = {
                try {
                    Disconnect-ExchangeOnline -Confirm:$false -ErrorAction SilentlyContinue
                    Connect-ExchangeOnline -CertificateThumbprint "$Thumbprint" -AppId "$AppId" -Organization "$Domain" -ShowBanner:$false
                    Start-Sleep 1
                    $auditLogConfig = Get-AdminAuditLogConfig | Select-Object UnifiedAuditLogIngestionEnabled
                    $auditLogConfig | Format-Table -AutoSize
                    Write-Host ""
                    Write-Host ""
                    
                    if ($auditLogConfig.UnifiedAuditLogIngestionEnabled -eq $true) {
                        Write-Host "Pass: Unified Audit Log Ingestion is Enabled." -ForegroundColor Green
                        
                        if ($Global:JsonOutputMode) {
                            Add-Finding -CheckId $script.CheckId `
                                    -Asset "/tenants/$tenantid" `
                                    -Status "PASS" `
                                    -Name "Audit Log Search Check" `
                                    -Description "Unified Audit Log Ingestion is enabled as recommended." `
                                    -Details @{ "UnifiedAuditLogIngestionEnabled" = $auditLogConfig.UnifiedAuditLogIngestionEnabled }
                        }
                    } else {
                        Write-Host "Fail: Unified Audit Log Ingestion is Disabled or not configured correctly." -ForegroundColor Red
                        
                        if ($Global:JsonOutputMode) {
                            Add-Finding -CheckId $script.CheckId `
                                    -Asset "/tenants/$tenantid" `
                                    -Status "FAIL" `
                                    -Name "Audit Log Search Check" `
                                    -Description "Unified Audit Log Ingestion is not enabled." `
                                    -Remediation "Enable Unified Audit Log Ingestion to ensure comprehensive auditing capabilities." `
                                    -Details @{ 
                                        "UnifiedAuditLogIngestionEnabled" = $auditLogConfig.UnifiedAuditLogIngestionEnabled 
                                    } `
                                    -Impact "Moderate" `
                                    -Likelihood "Moderate" `
                                    -Risk "Medium"
                        }
                    }
                } catch {
                    Write-Host "Error retrieving Unified Audit Log Ingestion status." -ForegroundColor Red
                    Write-Host $_.Exception.Message
                    
                    if ($Global:JsonOutputMode) {
                        Add-Finding -CheckId $script.CheckId `
                                -Asset "/tenants/$tenantid" `
                                -Status "ERROR" `
                                -Name "Audit Log Search Check" `
                                -Description "Error occurred while checking Unified Audit Log Ingestion status." `
                                -Details @{ "ErrorMessage" = $_.Exception.Message } `
                                -Impact "Minor" `
                                -Likelihood "Low" `
                                -Risk "Low"
                    }
                }
            }
        },    
        @{
            Name = "3.2.1-3.2.2 DLP Policies for Teams"
            Type = "Script"
            CheckId = "3.2.1"
            RequiresExchange = $true
            Logic = {
                try {
                    Disconnect-ExchangeOnline -Confirm:$false -ErrorAction SilentlyContinue
                    Connect-IPPSSession -CertificateThumbprint "$Thumbprint" -AppId "$AppId" -Organization "$Domain" -ShowBanner:$false
                    Start-Sleep 1
                    $dlpPolicy = Get-DlpCompliancePolicy
        
                    if ($dlpPolicy.Count -eq 0) {
                        Write-Host "No DLP policies found." -ForegroundColor Yellow
                        
                        if ($Global:JsonOutputMode) {
                            Add-Finding -CheckId $script.CheckId `
                                    -Asset "/tenants/$tenantid" `
                                    -Status "FAIL" `
                                    -Name "DLP Policies for Teams Check" `
                                    -Description "No Data Loss Prevention (DLP) policies were found." `
                                    -Remediation "Create DLP policies that include Teams workload with Mode set to Enable and apply to all Teams locations." `
                                    -Details @{ "Message" = "No DLP policies found" } `
                                    -Impact "Moderate" `
                                    -Likelihood "Moderate" `
                                    -Risk "Medium"
                        }
                        return
                    }
        
                    # Filter for Teams workload and capture for detailed reporting
                    $allDlpPolicies = $dlpPolicy | Select-Object Name, Mode, Workload, TeamsLocation, TeamsLocationException
                    $teamsDlpPolicies = $allDlpPolicies | Where-Object { $_.Workload -contains "Teams" }
                    
                    # Display in console for visual review
                    $teamsDlpPolicies | Format-Table Name, Mode, TeamsLocation, TeamsLocationException -AutoSize
                    Write-Host ""
                    Write-Host ""
        
                    if ($teamsDlpPolicies.Count -eq 0) {
                        Write-Host "Fail: No DLP policies found for Teams workload." -ForegroundColor Red
                        
                        if ($Global:JsonOutputMode) {
                            Add-Finding -CheckId $script.CheckId `
                                    -Asset "/tenants/$tenantid" `
                                    -Status "FAIL" `
                                    -Name "DLP Policies for Teams Check" `
                                    -Description "No DLP policies configured for Teams workload." `
                                    -Remediation "Configure DLP policies to include Teams workload with Mode set to Enable and apply to all Teams locations." `
                                    -Details @{ 
                                        "TotalPolicies" = $dlpPolicy.Count
                                        "TeamsWorkloadPolicies" = 0
                                        "AllPolicies" = $allDlpPolicies
                                    } `
                                    -Impact "Moderate" `
                                    -Likelihood "Moderate" `
                                    -Risk "Medium"
                        }
                        return
                    }
        
                    $isCompliant = $true
                    $policyDetails = @()
        
                    foreach ($policy in $teamsDlpPolicies) {
                        $policyDetail = @{
                            "Name" = $policy.Name
                            "Mode" = $policy.Mode
                            "TeamsLocation" = $policy.TeamsLocation -join ", "
                            "TeamsLocationException" = if ($policy.TeamsLocationException) { $policy.TeamsLocationException -join ", " } else { "None" }
                            "IsCompliant" = $false
                        }
                        
                        $mode = $policy.Mode
                        $teamsLocation = $policy.TeamsLocation
        
                        if ($mode -eq "Enable" -and ($teamsLocation -contains "All")) {
                            $policyDetail.IsCompliant = $true
                        } else {
                            $isCompliant = $false
                        }
                        
                        $policyDetails += $policyDetail
                    }
        
                    if ($isCompliant) {
                        Write-Host "Pass: All DLP policies for Teams workload are compliant." -ForegroundColor Green
                        
                        if ($Global:JsonOutputMode) {
                            Add-Finding -CheckId $script.CheckId `
                                    -Asset "/tenants/$tenantid" `
                                    -Status "PASS" `
                                    -Name "DLP Policies for Teams Check" `
                                    -Description "All DLP policies for Teams workload are properly configured." `
                                    -Details @{ 
                                        "TotalPolicies" = $dlpPolicy.Count
                                        "TeamsWorkloadPolicies" = $teamsDlpPolicies.Count
                                        "PolicyDetails" = $policyDetails
                                    }
                        }
                    } else {
                        Write-Host "Fail: Some DLP policies for Teams workload are not compliant." -ForegroundColor Red
                        
                        if ($Global:JsonOutputMode) {
                            Add-Finding -CheckId $script.CheckId `
                                    -Asset "/tenants/$tenantid" `
                                    -Status "FAIL" `
                                    -Name "DLP Policies for Teams Check" `
                                    -Description "Some DLP policies for Teams workload are not properly configured." `
                                    -Remediation "Configure all Teams DLP policies with Mode set to Enable and apply to all Teams locations." `
                                    -Details @{ 
                                        "TotalPolicies" = $dlpPolicy.Count
                                        "TeamsWorkloadPolicies" = $teamsDlpPolicies.Count
                                        "CompliantPolicies" = ($policyDetails | Where-Object { $_.IsCompliant -eq $true }).Count
                                        "NonCompliantPolicies" = ($policyDetails | Where-Object { $_.IsCompliant -eq $false }).Count
                                        "PolicyDetails" = $policyDetails
                                    } `
                                    -Impact "Moderate" `
                                    -Likelihood "Moderate" `
                                    -Risk "Medium"
                        }
                    }
                } catch {
                    Write-Host "Error retrieving or validating DLP policies." -ForegroundColor Red
                    Write-Host $_.Exception.Message
                    
                    if ($Global:JsonOutputMode) {
                        Add-Finding -CheckId $script.CheckId `
                                -Asset "/tenants/$tenantid" `
                                -Status "ERROR" `
                                -Name "DLP Policies for Teams Check" `
                                -Description "Error occurred while checking DLP policies for Teams." `
                                -Details @{ "ErrorMessage" = $_.Exception.Message } `
                                -Impact "Minor" `
                                -Likelihood "Low" `
                                -Risk "Low"
                    }
                }
            }
        },    
        @{
            Name = "3.3.1 SharePoint Protection Policies"
            Type = "Manual"
            CheckId = "3.3.1"
            Link = "https://purview.microsoft.com/informationprotection/purviewmipoverview"
            explanation = {
                Verify that SharePoint Information Protection Policies are configured.
                Scroll down to see if Sensitivity labels have been created.
            }
            Logic = {
                # Add manual check finding for JSON output
                if ($Global:JsonOutputMode) {
                    Add-Finding -CheckId $script.CheckId `
                            -Asset "/tenants/$tenantid" `
                            -Status "MANUAL" `
                            -Name "SharePoint Protection Policies Check" `
                            -Description "Manual verification required for SharePoint Information Protection Policies configuration." `
                            -Remediation "Configure Sensitivity labels and Information Protection Policies for SharePoint if not already done." `
                            -Details @{ 
                                "ManualCheckRequired" = $true
                                "CheckLocation" = "https://purview.microsoft.com/informationprotection/purviewmipoverview"
                                "VerificationSteps" = "Verify that Sensitivity labels have been created and are configured for SharePoint."
                            } `
                            -Impact "Moderate" `
                            -Likelihood "Moderate" `
                            -Risk "Medium"
                }
                
                Write-Host "Manual check required for $($script.Name)" -ForegroundColor Yellow
                Write-Host "Please visit: $($script.Link)" -ForegroundColor Blue
                Write-Host "`nExplanation:" -ForegroundColor Magenta
                foreach ($line in $script.explanation) {
                    Write-Host "$line" -ForegroundColor Cyan
                }
            }
        },
        @{
            Name = "5.1.1.1 Security Defaults"
            Type = "Script"
            CheckId = "5.1.1.1"
            Logic = {
                try {
                    $securityDefaults = Get-MgPolicyIdentitySecurityDefaultEnforcementPolicy | Select-Object IsEnabled
        
                    $securityDefaults | Format-Table -AutoSize
                    Write-Host ""
                    Write-Host ""
        
                    if ($securityDefaults.IsEnabled -eq $false) {
                        Write-Host "Pass: Security Defaults are disabled." -ForegroundColor Green
                        
                        if ($Global:JsonOutputMode) {
                            Add-Finding -CheckId $script.CheckId `
                                    -Asset "/tenants/$tenantid" `
                                    -Status "PASS" `
                                    -Name "Security Defaults Check" `
                                    -Description "Security Defaults are disabled as recommended when Conditional Access policies are in use." `
                                    -Details @{ "IsEnabled" = $securityDefaults.IsEnabled }
                        }
                    } elseif ($securityDefaults.IsEnabled -eq $true) {
                        Write-Host "Fail: Security Defaults are enabled." -ForegroundColor Red
                        
                        if ($Global:JsonOutputMode) {
                            Add-Finding -CheckId $script.CheckId `
                                    -Asset "/tenants/$tenantid" `
                                    -Status "FAIL" `
                                    -Name "Security Defaults Check" `
                                    -Description "Security Defaults are enabled, which may conflict with Conditional Access policies." `
                                    -Remediation "Disable Security Defaults and implement dedicated Conditional Access policies for more granular control." `
                                    -Details @{ "IsEnabled" = $securityDefaults.IsEnabled } `
                                    -Impact "Moderate" `
                                    -Likelihood "Moderate" `
                                    -Risk "Medium"
                        }
                    } else {
                        Write-Host "Fail: Unable to determine Security Defaults status." -ForegroundColor Red
                        
                        if ($Global:JsonOutputMode) {
                            Add-Finding -CheckId $script.CheckId `
                                    -Asset "/tenants/$tenantid" `
                                    -Status "FAIL" `
                                    -Name "Security Defaults Check" `
                                    -Description "Could not determine the status of Security Defaults." `
                                    -Remediation "Verify Security Defaults settings in the Microsoft Entra admin center." `
                                    -Details @{ "Message" = "Unable to determine Security Defaults status" } `
                                    -Impact "Minor" `
                                    -Likelihood "Low" `
                                    -Risk "Low"
                        }
                    }
                } catch {
                    Write-Host "Error retrieving Security Defaults policy." -ForegroundColor Red
                    Write-Host $_.Exception.Message
                    
                    if ($Global:JsonOutputMode) {
                        Add-Finding -CheckId $script.CheckId `
                                -Asset "/tenants/$tenantid" `
                                -Status "ERROR" `
                                -Name "Security Defaults Check" `
                                -Description "Error occurred while checking Security Defaults." `
                                -Details @{ "ErrorMessage" = $_.Exception.Message } `
                                -Impact "Minor" `
                                -Likelihood "Low" `
                                -Risk "Low"
                    }
                }
            }
        },    
        @{
            Name = "5.1.2.1 Per-User MFA State"
            Type = "Script"
            CheckId = "5.1.2.1"
            Logic = {
                try {
                    $users = Get-MgUser -All:$true | Select-Object Id, DisplayName, UserPrincipalName

                    $mfaResults = @()
                    $usersWithoutMfa = @()

                    foreach ($user in $users) {
                        $mfaState = Invoke-MgGraphRequest -Uri "https://graph.microsoft.com/beta/users/$($user.Id)/authentication/requirements" -Method GET
                        
                        $perUserMfaState = $mfaState.perUserMfaState

                        $userResult = [PSCustomObject]@{
                            DisplayName = $user.DisplayName
                            UserPrincipalName = $user.UserPrincipalName
                            PerUserMfaState = $perUserMfaState
                        }
                        
                        $mfaResults += $userResult
                        
                        if ($perUserMfaState -eq "disabled") {
                            $usersWithoutMfa += $userResult
                        }
                    }

                    $mfaResults | Format-Table -AutoSize
                    Write-Host ""
                    Write-Host ""

                    if ($mfaResults.PerUserMfaState -contains "disabled") {
                        Write-Host "Fail: Some users do not have MFA enabled." -ForegroundColor Red
                        
                        if ($Global:JsonOutputMode) {
                            # Add summary finding
                            Add-Finding -CheckId $script.CheckId `
                                    -Asset "/tenants/$tenantid" `
                                    -Status "FAIL" `
                                    -Name "Per-User MFA State Check" `
                                    -Description "Some users do not have MFA enabled." `
                                    -Remediation "Enable MFA for all users to enhance security." `
                                    -Details @{ 
                                        "TotalUsers" = $users.Count
                                        "UsersWithoutMfa" = $usersWithoutMfa.Count
                                        "UsersWithMfa" = ($users.Count - $usersWithoutMfa.Count)
                                    } `
                                    -Impact "Moderate" `
                                    -Likelihood "Moderate" `
                                    -Risk "Medium"
                            
                            # Add individual findings for each user without MFA
                            foreach ($user in $usersWithoutMfa) {
                                Add-Finding -CheckId $script.CheckId `
                                        -Asset "/tenants/$tenantid/users/$($user.UserPrincipalName)" `
                                        -Status "FAIL" `
                                        -Name "User MFA State Check" `
                                        -Description "User does not have MFA enabled." `
                                        -Remediation "Enable MFA for this user to enhance security." `
                                        -Details @{ 
                                            "DisplayName" = $user.DisplayName
                                            "UserPrincipalName" = $user.UserPrincipalName
                                            "PerUserMfaState" = $user.PerUserMfaState
                                        } `
                                        -Impact "Moderate" `
                                        -Likelihood "Moderate" `
                                        -Risk "Medium"
                            }
                        }
                    } elseif ($mfaResults.Count -gt 0) {
                        Write-Host "Pass: All users have MFA enabled." -ForegroundColor Green
                        
                        if ($Global:JsonOutputMode) {
                            Add-Finding -CheckId $script.CheckId `
                                    -Asset "/tenants/$tenantid" `
                                    -Status "PASS" `
                                    -Name "Per-User MFA State Check" `
                                    -Description "All users have MFA enabled." `
                                    -Details @{ 
                                        "TotalUsers" = $users.Count
                                        "UsersWithMfa" = $users.Count
                                    }
                        }
                    } else {
                        Write-Host "Fail: No users found or unable to determine MFA state." -ForegroundColor Red
                        
                        if ($Global:JsonOutputMode) {
                            Add-Finding -CheckId $script.CheckId `
                                    -Asset "/tenants/$tenantid" `
                                    -Status "FAIL" `
                                    -Name "Per-User MFA State Check" `
                                    -Description "No users found or unable to determine MFA state." `
                                    -Remediation "Verify user account data and MFA configuration." `
                                    -Details @{ "Message" = "No users found or unable to determine MFA state" } `
                                    -Impact "Minor" `
                                    -Likelihood "Low" `
                                    -Risk "Low"
                        }
                    }
                } catch {
                    Write-Host "Error retrieving MFA state for users." -ForegroundColor Red
                    Write-Host $_.Exception.Message
                    
                    if ($Global:JsonOutputMode) {
                        Add-Finding -CheckId $script.CheckId `
                                -Asset "/tenants/$tenantid" `
                                -Status "ERROR" `
                                -Name "Per-User MFA State Check" `
                                -Description "Error occurred while checking per-user MFA state." `
                                -Details @{ "ErrorMessage" = $_.Exception.Message } `
                                -Impact "Minor" `
                                -Likelihood "Low" `
                                -Risk "Low"
                    }
                }
            }
        },

        @{
            Name = "5.1.2.2 Third Party Application"
            Type = "Script"
            CheckId = "5.1.2.2"
            Logic = {
                try {
                    $permissions = (Get-MgPolicyAuthorizationPolicy).DefaultUserRolePermissions | Select-Object AllowedToCreateApps
        
                    $permissions | Format-Table -AutoSize
                    Write-Host ""
                    Write-Host ""
        
                    if ($permissions.AllowedToCreateApps -eq $false) {
                        Write-Host "Pass: Third party application creation is not allowed." -ForegroundColor Green
                        
                        if ($Global:JsonOutputMode) {
                            Add-Finding -CheckId $script.CheckId `
                                    -Asset "/tenants/$tenantid/policies/authorization" `
                                    -Status "PASS" `
                                    -Name "Third Party Application Creation Check" `
                                    -Description "Users are properly restricted from creating third party applications." `
                                    -Details @{ "AllowedToCreateApps" = $permissions.AllowedToCreateApps }
                        }
                    } else {
                        Write-Host "Fail: Third party application creation is allowed." -ForegroundColor Red
                        
                        if ($Global:JsonOutputMode) {
                            Add-Finding -CheckId $script.CheckId `
                                    -Asset "/tenants/$tenantid/policies/authorization" `
                                    -Status "FAIL" `
                                    -Name "Third Party Application Creation Check" `
                                    -Description "Users are allowed to create third party applications, which creates security risks." `
                                    -Remediation "Disable AllowedToCreateApps in authorization policy to prevent users from registering applications." `
                                    -Details @{ "AllowedToCreateApps" = $permissions.AllowedToCreateApps } `
                                    -Impact "Moderate" `
                                    -Likelihood "Moderate" `
                                    -Risk "Medium"
                        }
                    }
                } catch {
                    Write-Host "Error retrieving Third Party Application settings." -ForegroundColor Red
                    Write-Host $_.Exception.Message
                    
                    if ($Global:JsonOutputMode) {
                        Add-Finding -CheckId $script.CheckId `
                                -Asset "/tenants/$tenantid/policies/authorization" `
                                -Status "ERROR" `
                                -Name "Third Party Application Creation Check" `
                                -Description "Error occurred while checking third party application creation settings." `
                                -Details @{ "ErrorMessage" = $_.Exception.Message } `
                                -Impact "Minor" `
                                -Likelihood "Low" `
                                -Risk "Low"
                    }
                }
            }
        },    
        @{
            Name = "5.1.2.3 Tenant Creation"
            Type = "Script"
            CheckId = "5.1.2.3"
            Logic = {
                try {
                    $permissions = (Get-MgPolicyAuthorizationPolicy).DefaultUserRolePermissions | Select-Object AllowedToCreateTenants
        
                    $permissions | Format-Table -AutoSize
                    Write-Host ""
                    Write-Host ""
        
                    if ($permissions.AllowedToCreateTenants -eq $false) {
                        Write-Host "Pass: Tenant creation is not allowed." -ForegroundColor Green
                        
                        if ($Global:JsonOutputMode) {
                            Add-Finding -CheckId $script.CheckId `
                                    -Asset "/tenants/$tenantid/policies/authorization" `
                                    -Status "PASS" `
                                    -Name "Tenant Creation Check" `
                                    -Description "Users are properly restricted from creating new tenants." `
                                    -Details @{ "AllowedToCreateTenants" = $permissions.AllowedToCreateTenants }
                        }
                    } else {
                        Write-Host "Fail: Tenant creation is allowed." -ForegroundColor Red
                        
                        if ($Global:JsonOutputMode) {
                            Add-Finding -CheckId $script.CheckId `
                                    -Asset "/tenants/$tenantid/policies/authorization" `
                                    -Status "FAIL" `
                                    -Name "Tenant Creation Check" `
                                    -Description "Users are allowed to create new tenants, which creates security risks." `
                                    -Remediation "Disable AllowedToCreateTenants in authorization policy to prevent users from creating new tenants." `
                                    -Details @{ "AllowedToCreateTenants" = $permissions.AllowedToCreateTenants } `
                                    -Impact "Moderate" `
                                    -Likelihood "Moderate" `
                                    -Risk "Medium"
                        }
                    }
                } catch {
                    Write-Host "Error retrieving Tenant Creation settings." -ForegroundColor Red
                    Write-Host $_.Exception.Message
                    
                    if ($Global:JsonOutputMode) {
                        Add-Finding -CheckId $script.CheckId `
                                -Asset "/tenants/$tenantid/policies/authorization" `
                                -Status "ERROR" `
                                -Name "Tenant Creation Check" `
                                -Description "Error occurred while checking tenant creation settings." `
                                -Details @{ "ErrorMessage" = $_.Exception.Message } `
                                -Impact "Minor" `
                                -Likelihood "Low" `
                                -Risk "Low"
                    }
                }
            }
        },    
        @{
            Name = "5.1.2.4 Access to Entra Admin Center"
            Type = "Manual"
            CheckId = "5.1.2.4"
            Link = "https://portal.azure.com/#view/Microsoft_AAD_IAM/ActiveDirectoryMenuBlade/~/UserSettings"
            explanation = {
                Verify access to Entra admin center is restricted
                Ensure 'Restrict access to Microsoft Entra admin center' is toggled to or has a value of 'Yes'.
            }
            Logic = {
                if ($Global:JsonOutputMode) {
                    Add-Finding -CheckId $script.CheckId `
                            -Asset "/tenants/$tenantid/settings/admin-center-access" `
                            -Status "MANUAL" `
                            -Name "Admin Center Access Restriction Check" `
                            -Description "Administrator verification is required to ensure access to Microsoft Entra admin center is properly restricted." `
                            -Remediation "Enable 'Restrict access to Microsoft Entra admin center' in the portal." `
                            -Details @{ 
                                "ManualCheckRequired" = $true
                                "CheckLocation" = $script.Link
                                "VerificationSteps" = "Ensure 'Restrict access to Microsoft Entra admin center' is toggled to or has a value of 'Yes'."
                            } `
                            -Impact "Moderate" `
                            -Likelihood "Moderate" `
                            -Risk "Medium"
                }
                
                Write-Host "Manual check required for $($script.Name)" -ForegroundColor Yellow
                Write-Host "Please visit: $($script.Link)" -ForegroundColor Blue
                Write-Host "`nExplanation:" -ForegroundColor Magenta
                foreach ($line in $script.explanation) {
                    Write-Host "$line" -ForegroundColor Cyan
                }
            }
        },
        @{
            Name = "5.1.2.5 Remain Signed-in Allowed"
            Type = "Manual"
            CheckId = "5.1.2.5"
            Link = "https://portal.azure.com/#view/Microsoft_AAD_IAM/ActiveDirectoryMenuBlade/~/UserSettings"
            explanation = {
                Verify that users are not allowed to remain signed-in
                Ensure 'Show keep user signed in' is toggled to or has a value of 'No'.
            }
            Logic = {
                if ($Global:JsonOutputMode) {
                    Add-Finding -CheckId $script.CheckId `
                            -Asset "/tenants/$tenantid/settings/remain-signed-in" `
                            -Status "MANUAL" `
                            -Name "Remain Signed-in Option Check" `
                            -Description "Administrator verification is required to ensure users are not allowed to remain signed in." `
                            -Remediation "Disable 'Show keep user signed in' option in the portal." `
                            -Details @{ 
                                "ManualCheckRequired" = $true
                                "CheckLocation" = $script.Link
                                "VerificationSteps" = "Ensure 'Show keep user signed in' is toggled to or has a value of 'No'."
                            } `
                            -Impact "Moderate" `
                            -Likelihood "Moderate" `
                            -Risk "Medium"
                }
                
                Write-Host "Manual check required for $($script.Name)" -ForegroundColor Yellow
                Write-Host "Please visit: $($script.Link)" -ForegroundColor Blue
                Write-Host "`nExplanation:" -ForegroundColor Magenta
                foreach ($line in $script.explanation) {
                    Write-Host "$line" -ForegroundColor Cyan
                }
            }
        },
        @{
            Name = "5.1.2.6 LinkedIn Account Syncronizaton"
            Type = "Manual"
            CheckId = "5.1.2.6"
            Link = "https://portal.azure.com/#view/Microsoft_AAD_IAM/ActiveDirectoryMenuBlade/~/UserSettings"
            explanation = {
                Verify that users are not allowed to connect their account to LinkedIn
                Ensure 'Allow users to connect their work or school account with LinkedIn' has a value of 'No'.
            }
            Logic = {
                if ($Global:JsonOutputMode) {
                    Add-Finding -CheckId $script.CheckId `
                            -Asset "/tenants/$tenantid/settings/linkedin-integration" `
                            -Status "MANUAL" `
                            -Name "LinkedIn Account Synchronization Check" `
                            -Description "Administrator verification is required to ensure users cannot connect their accounts to LinkedIn." `
                            -Remediation "Disable 'Allow users to connect their work or school account with LinkedIn' in the portal." `
                            -Details @{ 
                                "ManualCheckRequired" = $true
                                "CheckLocation" = $script.Link
                                "VerificationSteps" = "Ensure 'Allow users to connect their work or school account with LinkedIn' has a value of 'No'."
                            } `
                            -Impact "Minor" `
                            -Likelihood "Low" `
                            -Risk "Low"
                }
                
                Write-Host "Manual check required for $($script.Name)" -ForegroundColor Yellow
                Write-Host "Please visit: $($script.Link)" -ForegroundColor Blue
                Write-Host "`nExplanation:" -ForegroundColor Magenta
                foreach ($line in $script.explanation) {
                    Write-Host "$line" -ForegroundColor Cyan
                }
            }
        },
        @{
            Name = "5.1.3.1 Dynamic Guest Group"
            Type = "Script"
            CheckId = "5.1.3.1"
            Logic = {
                try {
                    $groups = Get-MgGroup | Where-Object { $_.GroupTypes -contains "DynamicMembership" }
        
                    if ($groups) {
                        $groups | Format-Table DisplayName, GroupTypes, MembershipRule -AutoSize
                        Write-Host ""
                        Write-Host ""
                        Write-Host "Pass: Dynamic guest groups found." -ForegroundColor Green
                        
                        if ($Global:JsonOutputMode) {
                            # Add summary finding
                            Add-Finding -CheckId $script.CheckId `
                                    -Asset "/tenants/$tenantid/groups" `
                                    -Status "PASS" `
                                    -Name "Dynamic Guest Group Check" `
                                    -Description "Dynamic guest groups are properly configured." `
                                    -Details @{ 
                                        "TotalDynamicGroups" = $groups.Count
                                    }
                            
                            # Add individual findings for each dynamic group
                            foreach ($group in $groups) {
                                Add-Finding -CheckId $script.CheckId `
                                        -Asset "/tenants/$tenantid/groups/$($group.Id)" `
                                        -Status "INFO" `
                                        -Name "Dynamic Group Configuration" `
                                        -Description "Details for dynamic group '$($group.DisplayName)'." `
                                        -Details @{ 
                                            "DisplayName" = $group.DisplayName
                                            "GroupId" = $group.Id
                                            "GroupTypes" = $group.GroupTypes -join ", "
                                            "MembershipRule" = $group.MembershipRule
                                        }
                            }
                        }
                    } else {
                        Write-Host ""
                        Write-Host ""
                        Write-Host "Fail: No dynamic guest groups found." -ForegroundColor Red
                        
                        if ($Global:JsonOutputMode) {
                            Add-Finding -CheckId $script.CheckId `
                                    -Asset "/tenants/$tenantid/groups" `
                                    -Status "FAIL" `
                                    -Name "Dynamic Guest Group Check" `
                                    -Description "No dynamic guest groups found." `
                                    -Remediation "Create dynamic guest groups to automatically manage guest user access." `
                                    -Details @{ "Message" = "No dynamic membership groups configured" } `
                                    -Impact "Moderate" `
                                    -Likelihood "Moderate" `
                                    -Risk "Medium"
                        }
                    }
                } catch {
                    Write-Host "Error retrieving Dynamic Guest Group settings." -ForegroundColor Red
                    Write-Host $_.Exception.Message
                    
                    if ($Global:JsonOutputMode) {
                        Add-Finding -CheckId $script.CheckId `
                                -Asset "/tenants/$tenantid/groups" `
                                -Status "ERROR" `
                                -Name "Dynamic Guest Group Check" `
                                -Description "Error occurred while checking dynamic guest groups." `
                                -Details @{ "ErrorMessage" = $_.Exception.Message } `
                                -Impact "Minor" `
                                -Likelihood "Low" `
                                -Risk "Low"
                    }
                }
            }
        },    
        @{
            Name = "5.1.5.1 User App Consent"
            Type = "Script"
            CheckId = "5.1.5.1"
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
                            
                            if ($Global:JsonOutputMode) {
                                Add-Finding -CheckId $script.CheckId `
                                        -Asset "/tenants/$tenantid/policies/authorization/app-consent" `
                                        -Status "FAIL" `
                                        -Name "User App Consent Check" `
                                        -Description "Users are allowed to consent to low-risk applications." `
                                        -Remediation "Remove 'ManagePermissionGrantsForSelf.microsoft-user-default-low' from permission grant policies." `
                                        -Details @{ 
                                            "PermissionGrantPoliciesAssigned" = $consentPolicies
                                        } `
                                        -Impact "Moderate" `
                                        -Likelihood "Moderate" `
                                        -Risk "Medium"
                            }
                        } else {
                            Write-Host "Pass: ManagePermissionGrantsForSelf.microsoft-user-default-low is not present." -ForegroundColor Green
                            
                            if ($Global:JsonOutputMode) {
                                Add-Finding -CheckId $script.CheckId `
                                        -Asset "/tenants/$tenantid/policies/authorization/app-consent" `
                                        -Status "PASS" `
                                        -Name "User App Consent Check" `
                                        -Description "Users are not allowed to consent to applications." `
                                        -Details @{ 
                                            "PermissionGrantPoliciesAssigned" = $consentPolicies
                                        }
                            }
                        }
                    } else {
                        Write-Host "Pass: No permission grant policies assigned for user app consent." -ForegroundColor Green
                        
                        if ($Global:JsonOutputMode) {
                            Add-Finding -CheckId $script.CheckId `
                                    -Asset "/tenants/$tenantid/policies/authorization/app-consent" `
                                    -Status "PASS" `
                                    -Name "User App Consent Check" `
                                    -Description "No permission grant policies are assigned for user app consent." `
                                    -Details @{ 
                                        "PermissionGrantPoliciesAssigned" = "None"
                                    }
                        }
                    }
                } catch {
                    Write-Host "Error retrieving User App Consent settings." -ForegroundColor Red
                    Write-Host $_.Exception.Message
                    
                    if ($Global:JsonOutputMode) {
                        Add-Finding -CheckId $script.CheckId `
                                -Asset "/tenants/$tenantid/policies/authorization/app-consent" `
                                -Status "ERROR" `
                                -Name "User App Consent Check" `
                                -Description "Error occurred while checking user app consent settings." `
                                -Details @{ "ErrorMessage" = $_.Exception.Message } `
                                -Impact "Minor" `
                                -Likelihood "Low" `
                                -Risk "Low"
                    }
                }
            }
        },    
        @{
            Name = "5.1.5.2 Admin Consent Request Policy"
            Type = "Script"
            CheckId = "5.1.5.2"
            Logic = {
                try {
                    $adminConsentPolicy = Get-MgPolicyAdminConsentRequestPolicy | Select-Object IsEnabled, NotifyReviewers, RemindersEnabled, RequestDurationInDays

                    $adminConsentPolicy | Format-Table -AutoSize
                    Write-Host ""
                    Write-Host ""

                    if ($adminConsentPolicy.IsEnabled -eq $true) {
                        Write-Host "Pass: Admin Consent Request Policy is enabled." -ForegroundColor Green
                        
                        if ($Global:JsonOutputMode) {
                            Add-Finding -CheckId $script.CheckId `
                                    -Asset "/tenants/$tenantid/policies/admin-consent-request" `
                                    -Status "PASS" `
                                    -Name "Admin Consent Request Policy Check" `
                                    -Description "Admin Consent Request Policy is properly enabled." `
                                    -Details @{ 
                                        "IsEnabled" = $adminConsentPolicy.IsEnabled
                                        "NotifyReviewers" = $adminConsentPolicy.NotifyReviewers
                                        "RemindersEnabled" = $adminConsentPolicy.RemindersEnabled
                                        "RequestDurationInDays" = $adminConsentPolicy.RequestDurationInDays
                                    }
                        }
                    } else {
                        Write-Host "Fail: Admin Consent Request Policy is disabled." -ForegroundColor Red
                        
                        if ($Global:JsonOutputMode) {
                            Add-Finding -CheckId $script.CheckId `
                                    -Asset "/tenants/$tenantid/policies/admin-consent-request" `
                                    -Status "FAIL" `
                                    -Name "Admin Consent Request Policy Check" `
                                    -Description "Admin Consent Request Policy is disabled." `
                                    -Remediation "Enable the Admin Consent Request Policy to allow users to request consent for applications." `
                                    -Details @{ 
                                        "IsEnabled" = $adminConsentPolicy.IsEnabled
                                        "NotifyReviewers" = $adminConsentPolicy.NotifyReviewers
                                        "RemindersEnabled" = $adminConsentPolicy.RemindersEnabled
                                        "RequestDurationInDays" = $adminConsentPolicy.RequestDurationInDays
                                    } `
                                    -Impact "Moderate" `
                                    -Likelihood "Moderate" `
                                    -Risk "Medium"
                        }
                    }
                } catch {
                    Write-Host "Error retrieving Admin Consent Request Policy." -ForegroundColor Red
                    Write-Host $_.Exception.Message
                    
                    if ($Global:JsonOutputMode) {
                        Add-Finding -CheckId $script.CheckId `
                                -Asset "/tenants/$tenantid/policies/admin-consent-request" `
                                -Status "ERROR" `
                                -Name "Admin Consent Request Policy Check" `
                                -Description "Error occurred while checking Admin Consent Request Policy." `
                                -Details @{ "ErrorMessage" = $_.Exception.Message } `
                                -Impact "Minor" `
                                -Likelihood "Low" `
                                -Risk "Low"
                    }
                }
            }
        },
        @{
            Name = "5.1.6.1 Collaboration Invitations"
            Type = "Manual"
            CheckId = "5.1.6.1"
            Link = "https://portal.azure.com/#view/Microsoft_AAD_IAM/AllowlistPolicyBlade"
            explanation = {
                Verify collaboration invitations are restricted
                Scroll down to bottom of page to find 'Collaboration restrictions'
                Ensure 'Allow invitations to be sent to any domain' is set NOT selected
            }
            Logic = {
                if ($Global:JsonOutputMode) {
                    Add-Finding -CheckId $script.CheckId `
                            -Asset "/tenants/$tenantid/policies/collaboration" `
                            -Status "MANUAL" `
                            -Name "Collaboration Invitations Check" `
                            -Description "Administrator verification is required to ensure collaboration invitations are properly restricted." `
                            -Remediation "Disable 'Allow invitations to be sent to any domain' in the portal." `
                            -Details @{ 
                                "ManualCheckRequired" = $true
                                "CheckLocation" = $script.Link
                                "VerificationSteps" = "Scroll down to bottom of page to find 'Collaboration restrictions' and ensure 'Allow invitations to be sent to any domain' is NOT selected."
                            } `
                            -Impact "Moderate" `
                            -Likelihood "Moderate" `
                            -Risk "Medium"
                }
                
                Write-Host "Manual check required for $($script.Name)" -ForegroundColor Yellow
                Write-Host "Please visit: $($script.Link)" -ForegroundColor Blue
                Write-Host "`nExplanation:" -ForegroundColor Magenta
                foreach ($line in $script.explanation) {
                    Write-Host "$line" -ForegroundColor Cyan
                }
            }
        },
        @{
            Name = "5.1.6.2 Guest User Access"
            Type = "Script"
            CheckId = "5.1.6.2"
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
                        
                        if ($Global:JsonOutputMode) {
                            Add-Finding -CheckId $script.CheckId `
                                    -Asset "/tenants/$tenantid/policies/authorization/guest-access" `
                                    -Status "PASS" `
                                    -Name "Guest User Access Check" `
                                    -Description "Guest User Role ID is set to a most restrictive value." `
                                    -Details @{ 
                                        "GuestUserRoleId" = $guestUserPolicy
                                        "MostRestrictiveValues" = $mostRestrictiveValues
                                    }
                        }
                    } else {
                        Write-Host "Fail: Guest User Role ID is not set to a most restrictive value." -ForegroundColor Red
                        
                        if ($Global:JsonOutputMode) {
                            Add-Finding -CheckId $script.CheckId `
                                    -Asset "/tenants/$tenantid/policies/authorization/guest-access" `
                                    -Status "FAIL" `
                                    -Name "Guest User Access Check" `
                                    -Description "Guest User Role ID is not set to a most restrictive value." `
                                    -Remediation "Set GuestUserRoleId to one of the most restrictive values in the Authorization Policy." `
                                    -Details @{ 
                                        "GuestUserRoleId" = $guestUserPolicy
                                        "MostRestrictiveValues" = $mostRestrictiveValues
                                    } `
                                    -Impact "Moderate" `
                                    -Likelihood "Moderate" `
                                    -Risk "Medium"
                        }
                    }
                } catch {
                    Write-Host "Error retrieving Guest User Access settings." -ForegroundColor Red
                    Write-Host $_.Exception.Message
                    
                    if ($Global:JsonOutputMode) {
                        Add-Finding -CheckId $script.CheckId `
                                -Asset "/tenants/$tenantid/policies/authorization/guest-access" `
                                -Status "ERROR" `
                                -Name "Guest User Access Check" `
                                -Description "Error occurred while checking Guest User Access settings." `
                                -Details @{ "ErrorMessage" = $_.Exception.Message } `
                                -Impact "Minor" `
                                -Likelihood "Low" `
                                -Risk "Low"
                    }
                }
            }
        },    
        @{
            Name = "5.1.6.3 Guest User Invitations"
            Type = "Script"
            CheckId = "5.1.6.3"
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
                        
                        if ($Global:JsonOutputMode) {
                            Add-Finding -CheckId $script.CheckId `
                                    -Asset "/tenants/$tenantid/policies/authorization/guest-invitations" `
                                    -Status "PASS" `
                                    -Name "Guest User Invitations Check" `
                                    -Description "AllowInvitesFrom setting is sufficiently restrictive." `
                                    -Details @{ 
                                        "AllowInvitesFrom" = $invitesPolicy
                                        "AllowedValues" = $allowedValues
                                        "RequiredOrMore" = $allowedValues[0..$requiredIndex]
                                    }
                        }
                    } else {
                        Write-Host "Fail: Guest User Invitations setting is not restrictive enough." -ForegroundColor Red
                        
                        if ($Global:JsonOutputMode) {
                            Add-Finding -CheckId $script.CheckId `
                                    -Asset "/tenants/$tenantid/policies/authorization/guest-invitations" `
                                    -Status "FAIL" `
                                    -Name "Guest User Invitations Check" `
                                    -Description "AllowInvitesFrom setting is not restrictive enough." `
                                    -Remediation "Set AllowInvitesFrom to 'none', 'admins', or 'adminsAndGuestInviters' in the Authorization Policy." `
                                    -Details @{ 
                                        "AllowInvitesFrom" = $invitesPolicy
                                        "AllowedValues" = $allowedValues
                                        "RequiredOrMore" = $allowedValues[0..$requiredIndex]
                                    } `
                                    -Impact "Moderate" `
                                    -Likelihood "Moderate" `
                                    -Risk "Medium"
                        }
                    }
                } catch {
                    Write-Host "Error retrieving Guest User Invitations settings." -ForegroundColor Red
                    Write-Host $_.Exception.Message
                    
                    if ($Global:JsonOutputMode) {
                        Add-Finding -CheckId $script.CheckId `
                                -Asset "/tenants/$tenantid/policies/authorization/guest-invitations" `
                                -Status "ERROR" `
                                -Name "Guest User Invitations Check" `
                                -Description "Error occurred while checking Guest User Invitations settings." `
                                -Details @{ "ErrorMessage" = $_.Exception.Message } `
                                -Impact "Minor" `
                                -Likelihood "Low" `
                                -Risk "Low"
                    }
                }
            }
        },    
        @{
            Name = "5.1.8.1 Password Hash Sync"
            Type = "Script"
            CheckId = "5.1.8.1"
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
                            
                            if ($Global:JsonOutputMode) {
                                Add-Finding -CheckId $script.CheckId `
                                        -Asset "/tenants/$tenantid/directory/sync" `
                                        -Status "PASS" `
                                        -Name "Password Hash Sync Check" `
                                        -Description "Password Hash Sync is properly enabled." `
                                        -Details @{ 
                                            "OnPremisesSyncEnabled" = $hashSyncStatus
                                        }
                            }
                        } else {
                            Write-Host ""
                            Write-Host ""
                            Write-Host "Fail: Password Hash Sync is disabled." -ForegroundColor Red
                            
                            if ($Global:JsonOutputMode) {
                                Add-Finding -CheckId $script.CheckId `
                                        -Asset "/tenants/$tenantid/directory/sync" `
                                        -Status "FAIL" `
                                        -Name "Password Hash Sync Check" `
                                        -Description "Password Hash Sync is disabled, which is not recommended." `
                                        -Remediation "Enable Password Hash Sync to improve authentication resilience and security." `
                                        -Details @{ 
                                            "OnPremisesSyncEnabled" = $hashSyncStatus
                                        } `
                                        -Impact "Moderate" `
                                        -Likelihood "Moderate" `
                                        -Risk "Medium"
                            }
                        }
                    } else {
                        Write-Host "Fail: No results found for OnPremisesSyncEnabled." -ForegroundColor Red
                        
                        if ($Global:JsonOutputMode) {
                            Add-Finding -CheckId $script.CheckId `
                                    -Asset "/tenants/$tenantid/directory/sync" `
                                    -Status "FAIL" `
                                    -Name "Password Hash Sync Check" `
                                    -Description "Could not determine if Password Hash Sync is enabled." `
                                    -Remediation "Verify directory synchronization configuration." `
                                    -Details @{ 
                                        "OnPremisesSyncEnabled" = "Unknown"
                                    } `
                                    -Impact "Moderate" `
                                    -Likelihood "Moderate" `
                                    -Risk "Medium"
                        }
                    }
                } catch {
                    Write-Host "Error retrieving Password Hash Sync status." -ForegroundColor Red
                    Write-Host $_.Exception.Message
                    
                    if ($Global:JsonOutputMode) {
                        Add-Finding -CheckId $script.CheckId `
                                -Asset "/tenants/$tenantid/directory/sync" `
                                -Status "ERROR" `
                                -Name "Password Hash Sync Check" `
                                -Description "Error occurred while checking Password Hash Sync status." `
                                -Details @{ "ErrorMessage" = $_.Exception.Message } `
                                -Impact "Minor" `
                                -Likelihood "Low" `
                                -Risk "Low"
                    }
                }
            }
        },
        @{
            Name = "5.2.2.1 MFA Status for Admin Roles"
            Type = "Script"
            CheckId = "5.2.2.1"
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
                        
                        if ($Global:JsonOutputMode) {
                            Add-Finding -CheckId $script.CheckId `
                                    -Asset "/tenants/$tenantid/security/mfa" `
                                    -Status "ERROR" `
                                    -Name "MFA Status for Admin Roles Check" `
                                    -Description "Failed to retrieve Graph API token to check MFA status." `
                                    -Details @{ "ErrorMessage" = "Failed to retrieve Graph API token" } `
                                    -Impact "Minor" `
                                    -Likelihood "Low" `
                                    -Risk "Low"
                        }
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
                        
                        # Extract MFA score information
                        $mfaAdminScore = $secureScores.controlScores | Where-Object { $_.controlName -match "MFA" -and $_.controlName -match "admin" }
                        
                        if ($mfaAdminScore) {
                            $scorePercent = [Math]::Round(($mfaAdminScore.score / $mfaAdminScore.maxScore) * 100, 2)
                            
                            if ($scorePercent -ge 90) {
                                Write-Host "Pass: MFA for Admin Roles is adequately configured ($scorePercent%)." -ForegroundColor Green
                                
                                if ($Global:JsonOutputMode) {
                                    Add-Finding -CheckId $script.CheckId `
                                            -Asset "/tenants/$tenantid/security/mfa/admin-roles" `
                                            -Status "PASS" `
                                            -Name "MFA Status for Admin Roles Check" `
                                            -Description "MFA for Admin Roles is adequately configured." `
                                            -Details @{ 
                                                "ScorePercent" = $scorePercent
                                                "AdminMfaScore" = $mfaAdminScore.score
                                                "AdminMfaMaxScore" = $mfaAdminScore.maxScore
                                            }
                                }
                            } else {
                                Write-Host "Fail: MFA for Admin Roles is not sufficiently configured ($scorePercent%)." -ForegroundColor Red
                                
                                if ($Global:JsonOutputMode) {
                                    Add-Finding -CheckId $script.CheckId `
                                            -Asset "/tenants/$tenantid/security/mfa/admin-roles" `
                                            -Status "FAIL" `
                                            -Name "MFA Status for Admin Roles Check" `
                                            -Description "MFA for Admin Roles is not sufficiently configured." `
                                            -Remediation "Enable MFA for all administrator accounts." `
                                            -Details @{ 
                                                "ScorePercent" = $scorePercent
                                                "AdminMfaScore" = $mfaAdminScore.score
                                                "AdminMfaMaxScore" = $mfaAdminScore.maxScore
                                            } `
                                            -Impact "Major" `
                                            -Likelihood "High" `
                                            -Risk "Serious"
                                }
                            }
                        } else {
                            Write-Host "No MFA-specific data for admin roles found in secure scores." -ForegroundColor Yellow
                            
                            if ($Global:JsonOutputMode) {
                                Add-Finding -CheckId $script.CheckId `
                                        -Asset "/tenants/$tenantid/security/mfa/admin-roles" `
                                        -Status "WARNING" `
                                        -Name "MFA Status for Admin Roles Check" `
                                        -Description "Could not extract MFA-specific data for admin roles from secure scores." `
                                        -Remediation "Manually verify MFA configuration for all admin roles." `
                                        -Details @{ 
                                            "Message" = "No MFA-specific data for admin roles found in secure scores"
                                        } `
                                        -Impact "Moderate" `
                                        -Likelihood "Moderate" `
                                        -Risk "Medium"
                            }
                        }
                    } else {
                        Write-Host "No MFA status data found for admin roles." -ForegroundColor Yellow
                        
                        if ($Global:JsonOutputMode) {
                            Add-Finding -CheckId $script.CheckId `
                                    -Asset "/tenants/$tenantid/security/mfa/admin-roles" `
                                    -Status "WARNING" `
                                    -Name "MFA Status for Admin Roles Check" `
                                    -Description "No MFA status data found for admin roles." `
                                    -Remediation "Verify configuration of secure score metrics." `
                                    -Details @{ 
                                        "Message" = "No secure score data found"
                                    } `
                                    -Impact "Moderate" `
                                    -Likelihood "Moderate" `
                                    -Risk "Medium"
                            }
                    }
                } catch {
                    Write-Host "Error retrieving MFA status for Admin Roles" -ForegroundColor Red
                    Write-Host $_.Exception.Message
                    
                    if ($Global:JsonOutputMode) {
                        Add-Finding -CheckId $script.CheckId `
                                -Asset "/tenants/$tenantid/security/mfa/admin-roles" `
                                -Status "ERROR" `
                                -Name "MFA Status for Admin Roles Check" `
                                -Description "Error occurred while checking MFA status for admin roles." `
                                -Details @{ "ErrorMessage" = $_.Exception.Message } `
                                -Impact "Minor" `
                                -Likelihood "Low" `
                                -Risk "Low"
                    }
                }
            }
        },
        @{
            Name = "5.2.2.2 Conditional Access MFA Policy Check"
            Type = "Script"
            CheckId = "5.2.2.2"
            Logic = {
                try {

                    $policies = Get-MgIdentityConditionalAccessPolicy | Where-Object {
                        $_.DisplayName -match "MFA" -and $_.State -eq "enabled"
                    }
                    
                    $policyDetails = @()

                    if ($policies.Count -eq 0) {
                        Write-Host "Fail: No enabled Conditional Access policies contain 'MFA' in their name." -ForegroundColor Red
                        
                        if ($Global:JsonOutputMode) {
                            Add-Finding -CheckId $script.CheckId `
                                    -Asset "/tenants/$tenantid/security/conditional-access/mfa-policies" `
                                    -Status "FAIL" `
                                    -Name "Conditional Access MFA Policy Check" `
                                    -Description "No enabled Conditional Access policies contain 'MFA' in their name." `
                                    -Remediation "Create and enable Conditional Access policies that enforce MFA requirements." `
                                    -Details @{ 
                                        "Message" = "No MFA policies found"
                                    } `
                                    -Impact "Major" `
                                    -Likelihood "High" `
                                    -Risk "Serious"
                        }
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
                        $hasExclusions = ($users.excludeUsers -and $users.excludeUsers.Count -gt 0) -or 
                                        ($users.excludeGroups -and $users.excludeGroups.Count -gt 0)

                        $policyDetail = @{
                            "PolicyId" = $policyId
                            "DisplayName" = $policy.DisplayName
                            "IncludeAllUsers" = ($users.includeUsers -eq "All")
                            "HasExclusions" = $hasExclusions
                            "ExcludedUsers" = $users.excludeUsers
                            "ExcludedGroups" = $users.excludeGroups
                        }
                        $policyDetails += $policyDetail

                        if ($users.includeUsers -eq "All" -and -not $hasExclusions) {
                            Write-Host "Pass: MFA Conditional Access Policy '$($policy.DisplayName)' applies to all users." -ForegroundColor Green
                        } else {
                            Write-Host "Fail: MFA Conditional Access Policy '$($policy.DisplayName)' has exclusions." -ForegroundColor Red
                            $failFlag = $true
                        }
                    }

                    if ($failFlag) {
                        Write-Host "Fail: One or more MFA Conditional Access policies have exclusions." -ForegroundColor Red
                        
                        if ($Global:JsonOutputMode) {
                            Add-Finding -CheckId $script.CheckId `
                                    -Asset "/tenants/$tenantid/security/conditional-access/mfa-policies" `
                                    -Status "FAIL" `
                                    -Name "Conditional Access MFA Policy Check" `
                                    -Description "One or more MFA Conditional Access policies have exclusions, which creates security gaps." `
                                    -Remediation "Remove exclusions from MFA policies or ensure all users are covered by at least one MFA policy." `
                                    -Details @{ 
                                        "TotalMfaPolicies" = $policies.Count
                                        "PoliciesWithExclusions" = ($policyDetails | Where-Object { $_.HasExclusions }).Count
                                        "PolicyDetails" = $policyDetails
                                    } `
                                    -Impact "Major" `
                                    -Likelihood "High" `
                                    -Risk "Serious"
                        }
                    } else {
                        Write-Host "Pass: All MFA Conditional Access policies apply to all users with no exclusions." -ForegroundColor Green
                        
                        if ($Global:JsonOutputMode) {
                            Add-Finding -CheckId $script.CheckId `
                                    -Asset "/tenants/$tenantid/security/conditional-access/mfa-policies" `
                                    -Status "PASS" `
                                    -Name "Conditional Access MFA Policy Check" `
                                    -Description "All MFA Conditional Access policies apply to all users with no exclusions." `
                                    -Details @{ 
                                        "TotalMfaPolicies" = $policies.Count
                                        "PolicyDetails" = $policyDetails
                                    }
                        }
                    }
                } catch {
                    Write-Host "Error retrieving Conditional Access policies." -ForegroundColor Red
                    Write-Host $_.Exception.Message
                    
                    if ($Global:JsonOutputMode) {
                        Add-Finding -CheckId $script.CheckId `
                                -Asset "/tenants/$tenantid/security/conditional-access/mfa-policies" `
                                -Status "ERROR" `
                                -Name "Conditional Access MFA Policy Check" `
                                -Description "Error occurred while checking Conditional Access MFA policies." `
                                -Details @{ "ErrorMessage" = $_.Exception.Message } `
                                -Impact "Minor" `
                                -Likelihood "Low" `
                                -Risk "Low"
                    }
                }
            }
        },
        @{
            Name = "5.2.2.4 Conditional Access Session Controls Check"
            Type = "Script"
            CheckId = "5.2.2.4"
            RequiresExchange = $false
            Logic = {
                try {
                    $tenantid = (Get-MgContext).TenantId
                    $policies = Get-MgIdentityConditionalAccessPolicy | Where-Object { $_.State -eq "enabled" }

                    if ($policies.Count -eq 0) {
                        Write-Host "Fail: No enabled Conditional Access policies found." -ForegroundColor Red
                        
                        if ($Global:JsonOutputMode) {
                            Add-Finding -CheckId $script.CheckId `
                                    -Asset "/tenants/$tenantid/security/conditional-access/session-controls" `
                                    -Status "FAIL" `
                                    -Name "Conditional Access Session Controls Check" `
                                    -Description "No enabled Conditional Access policies found." `
                                    -Remediation "Create and enable Conditional Access policies." `
                                    -Details @{ 
                                        "Message" = "No enabled policies found"
                                    } `
                                    -Impact "Major" `
                                    -Likelihood "High" `
                                    -Risk "Serious"
                        }
                        return
                    }

                    $failFlag = $true
                    $policiesWithSessionControls = 0
                    $policyDetails = @()

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
                            $policiesWithSessionControls++
                            
                            $policyDetails += @{
                                "PolicyId" = $policyId
                                "PolicyName" = $policy.DisplayName
                                "HasSessionControls" = $true
                            }
                        } else {
                            $policyDetails += @{
                                "PolicyId" = $policyId
                                "PolicyName" = $policy.DisplayName
                                "HasSessionControls" = $false
                            }
                        }
                    }

                    if ($failFlag) {
                        Write-Host "Fail: No enabled Conditional Access policies have session controls configured." -ForegroundColor Red
                        
                        # Add finding to JSON results
                        Add-Finding -CheckId $script.CheckId `
                                -Asset "/tenants/$tenantid/security/conditional-access/session-controls" `
                                -Status "FAIL" `
                                -Name "Conditional Access Session Controls Check" `
                                -Description "Enabled Conditional Access policies should be configured with session controls." `
                                -Remediation "Configure at least one Conditional Access policy with session controls." `
                                -Details @{ 
                                    "EnabledPolicyCount" = $policies.Count
                                    "PoliciesWithSessionControls" = $policiesWithSessionControls
                                    "PolicyDetails" = $policyDetails
                                } `
                                -Impact "Moderate" `
                                -Likelihood "Moderate" `
                                -Risk "Medium"
                    } else {
                        Write-Host "Pass: At least one enabled Conditional Access policy has session controls configured." -ForegroundColor Green
                        
                        # Add finding to JSON results
                        Add-Finding -CheckId $script.CheckId `
                                -Asset "/tenants/$tenantid/security/conditional-access/session-controls" `
                                -Status "PASS" `
                                -Name "Conditional Access Session Controls Check" `
                                -Description "Enabled Conditional Access policies should be configured with session controls." `
                                -Details @{ 
                                    "EnabledPolicyCount" = $policies.Count
                                    "PoliciesWithSessionControls" = $policiesWithSessionControls
                                    "PolicyDetails" = $policyDetails
                                }
                    }
                } catch {
                    Write-Host "Error retrieving Conditional Access policies." -ForegroundColor Red
                    Write-Host $_.Exception.Message
                    
                    # Add error finding to JSON results
                    Add-Finding -CheckId $script.CheckId `
                            -Asset "/tenants/$tenantid/security/conditional-access/session-controls" `
                            -Status "ERROR" `
                            -Name "Conditional Access Session Controls Check" `
                            -Description "Error occurred while checking Conditional Access session controls." `
                            -Details @{ "ErrorMessage" = $_.Exception.Message } `
                            -Impact "Moderate" `
                            -Likelihood "Moderate" `
                            -Risk "Medium"
                }
            }
        },
        @{
            Name = "5.2.2.5 Conditional Access Grant Controls Check"
            Type = "Script"
            CheckId = "5.2.2.5"
            RequiresExchange = $false
            Logic = {
                try {
                    $tenantid = (Get-MgContext).TenantId
                    $policies = Get-MgIdentityConditionalAccessPolicy | Where-Object { $_.State -eq "enabled" }

                    if ($policies.Count -eq 0) {
                        Write-Host "Fail: No enabled Conditional Access policies found." -ForegroundColor Red
                        
                        # Add finding to JSON results
                        Add-Finding -CheckId $script.CheckId `
                                -Asset "/tenants/$tenantid/security/conditional-access/grant-controls" `
                                -Status "FAIL" `
                                -Name "Conditional Access Grant Controls Check" `
                                -Description "Enabled Conditional Access policies should be configured with grant controls." `
                                -Remediation "Configure at least one Conditional Access policy with grant controls." `
                                -Details @{ "EnabledPolicyCount" = 0; "PoliciesWithGrantControls" = 0 } `
                                -Impact "Moderate" `
                                -Likelihood "Moderate" `
                                -Risk "Medium"
                        return
                    }

                    $failFlag = $true
                    $policiesWithGrantControls = 0
                    $policyDetails = @()

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
                            $policiesWithGrantControls++
                            
                            $policyDetails += @{
                                "PolicyId" = $policyId
                                "PolicyName" = $policy.DisplayName
                                "HasAuthenticationStrength" = $true
                            }
                        } else {
                            $policyDetails += @{
                                "PolicyId" = $policyId
                                "PolicyName" = $policy.DisplayName
                                "HasAuthenticationStrength" = $false
                            }
                        }
                    }

                    if ($failFlag) {
                        Write-Host "Fail: No enabled Conditional Access policies have authentication strength configured in grantControls." -ForegroundColor Red
                        
                        # Add finding to JSON results
                        Add-Finding -CheckId $script.CheckId `
                                -Asset "/tenants/$tenantid/security/conditional-access/grant-controls" `
                                -Status "FAIL" `
                                -Name "Conditional Access Grant Controls Check" `
                                -Description "Enabled Conditional Access policies should be configured with grant controls." `
                                -Remediation "Configure at least one Conditional Access policy with grant controls." `
                                -Details @{ 
                                    "EnabledPolicyCount" = $policies.Count
                                    "PoliciesWithGrantControls" = $policiesWithGrantControls
                                    "PolicyDetails" = $policyDetails
                                } `
                                -Impact "Moderate" `
                                -Likelihood "Moderate" `
                                -Risk "Medium"
                    } else {
                        Write-Host "Pass: At least one enabled Conditional Access policy has authentication strength configured in grantControls." -ForegroundColor Green
                        
                        # Add finding to JSON results
                        Add-Finding -CheckId $script.CheckId `
                                -Asset "/tenants/$tenantid/security/conditional-access/grant-controls" `
                                -Status "PASS" `
                                -Name "Conditional Access Grant Controls Check" `
                                -Description "Enabled Conditional Access policies should be configured with grant controls." `
                                -Details @{ 
                                    "EnabledPolicyCount" = $policies.Count
                                    "PoliciesWithGrantControls" = $policiesWithGrantControls
                                    "PolicyDetails" = $policyDetails
                                }
                    }
                } catch {
                    Write-Host "Error retrieving Conditional Access policies." -ForegroundColor Red
                    Write-Host $_.Exception.Message
                    
                    # Add error finding to JSON results
                    Add-Finding -CheckId $script.CheckId `
                            -Asset "/tenants/$tenantid/security/conditional-access/grant-controls" `
                            -Status "ERROR" `
                            -Name "Conditional Access Grant Controls Check" `
                            -Description "Error occurred while checking Conditional Access grant controls." `
                            -Details @{ "ErrorMessage" = $_.Exception.Message } `
                            -Impact "Moderate" `
                            -Likelihood "Moderate" `
                            -Risk "Medium"
                }
            }
        },
        @{
            Name = "5.2.2.6 Conditional Access Session Controls Check"
            Type = "Script"
            CheckId = "5.2.2.6"
            RequiresExchange = $false
            Logic = {
                try {
                    $tenantid = (Get-MgContext).TenantId
                    $policies = Get-MgIdentityConditionalAccessPolicy | Where-Object { $_.State -eq "enabled" }

                    if ($policies.Count -eq 0) {
                        Write-Host "Fail: No enabled Conditional Access policies found." -ForegroundColor Red
                        
                        # Add finding to JSON results
                        Add-Finding -CheckId $script.CheckId `
                                -Asset "/tenants/$tenantid" `
                                -Status "FAIL" `
                                -Name "Conditional Access Session Controls Check" `
                                -Description "Enabled Conditional Access policies should be configured with session controls." `
                                -Remediation "Configure at least one Conditional Access policy with session controls." `
                                -Details @{ "EnabledPolicyCount" = 0; "PoliciesWithSessionControls" = 0 } `
                                -Impact "Moderate" `
                                -Likelihood "Moderate" `
                                -Risk "Medium"
                        return
                    }

                    $failFlag = $true
                    $policiesWithSessionControls = 0
                    $policyDetails = @()

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
                            $policiesWithSessionControls++
                            
                            $policyDetails += @{
                                "PolicyId" = $policyId
                                "PolicyName" = $policy.DisplayName
                                "HasSessionControls" = $true
                            }
                        } else {
                            $policyDetails += @{
                                "PolicyId" = $policyId
                                "PolicyName" = $policy.DisplayName
                                "HasSessionControls" = $false
                            }
                        }
                    }

                    if ($failFlag) {
                        Write-Host "Fail: No enabled Conditional Access policies have session controls configured." -ForegroundColor Red
                        
                        # Add finding to JSON results
                        Add-Finding -CheckId $script.CheckId `
                                -Asset "/tenants/$tenantid/security/conditional-access/session-controls" `
                                -Status "FAIL" `
                                -Name "Conditional Access Session Controls Check" `
                                -Description "Enabled Conditional Access policies should be configured with session controls." `
                                -Remediation "Configure at least one Conditional Access policy with session controls." `
                                -Details @{ 
                                    "EnabledPolicyCount" = $policies.Count
                                    "PoliciesWithSessionControls" = $policiesWithSessionControls
                                    "PolicyDetails" = $policyDetails
                                } `
                                -Impact "Moderate" `
                                -Likelihood "Moderate" `
                                -Risk "Medium"
                    } else {
                        Write-Host "Pass: At least one enabled Conditional Access policy has session controls configured." -ForegroundColor Green
                        
                        # Add finding to JSON results
                        Add-Finding -CheckId $script.CheckId `
                                -Asset "/tenants/$tenantid" `
                                -Status "PASS" `
                                -Name "Conditional Access Session Controls Check" `
                                -Description "Enabled Conditional Access policies should be configured with session controls." `
                                -Details @{ 
                                    "EnabledPolicyCount" = $policies.Count
                                    "PoliciesWithSessionControls" = $policiesWithSessionControls
                                    "PolicyDetails" = $policyDetails
                                }
                    }
                } catch {
                    Write-Host "Error retrieving Conditional Access policies." -ForegroundColor Red
                    Write-Host $_.Exception.Message
                    
                    # Add error finding to JSON results
                    Add-Finding -CheckId $script.CheckId `
                            -Asset "/tenants/$tenantid/security/conditional-access/session-controls" `
                            -Status "ERROR" `
                            -Name "Conditional Access Session Controls Check" `
                            -Description "Error occurred while checking Conditional Access session controls." `
                            -Details @{ "ErrorMessage" = $_.Exception.Message } `
                            -Impact "Moderate" `
                            -Likelihood "Moderate" `
                            -Risk "Medium"
                }
            }
        },
        @{
            Name = "5.2.2.7 Sign-In Risk Policy"
            Type = "Script"
            CheckId = "5.2.2.7"
            RequiresExchange = $false
            Logic = {
                try {
                    $tenantid = (Get-MgContext).TenantId
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
                            Id               = $_.Id
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
                    
                    # Check if there are any policies with sign-in risk levels configured
                    $signInRiskPolicies = $policies | Where-Object { $_.SignInRiskLevels -ne "None" -and $_.State -eq "enabled" }
                    
                    if ($signInRiskPolicies.Count -gt 0) {
                        Write-Host "Pass: Found $($signInRiskPolicies.Count) enabled policies with sign-in risk levels configured." -ForegroundColor Green
                        
                        if ($Global:JsonOutputMode) {
                            Add-Finding -CheckId $script.CheckId `
                                    -Asset "/tenants/$tenantid/conditional-access/policies" `
                                    -Status "PASS" `
                                    -Name "Sign-In Risk Policy Check" `
                                    -Description "Sign-in risk level policies are properly configured." `
                                    -Details @{ 
                                        "TotalPolicies" = $policies.Count
                                        "EnabledSignInRiskPolicies" = $signInRiskPolicies.Count
                                        "PolicyDetails" = $signInRiskPolicies
                                    }
                        }
                    } else {
                        Write-Host "Fail: No enabled policies with sign-in risk levels were found." -ForegroundColor Red
                        
                        if ($Global:JsonOutputMode) {
                            Add-Finding -CheckId $script.CheckId `
                                    -Asset "/tenants/$tenantid/conditional-access/policies" `
                                    -Status "FAIL" `
                                    -Name "Sign-In Risk Policy Check" `
                                    -Description "No enabled policies with sign-in risk levels were found." `
                                    -Remediation "Configure at least one Conditional Access policy with sign-in risk levels to protect against risky sign-ins." `
                                    -Details @{ 
                                        "TotalPolicies" = $policies.Count
                                        "EnabledSignInRiskPolicies" = 0
                                        "PolicyDetails" = $policies
                                    } `
                                    -Impact "Moderate" `
                                    -Likelihood "Moderate" `
                                    -Risk "Medium"
                        }
                    }
                } catch {
                    Write-Host "Error retrieving Sign-In Risk Policies" -ForegroundColor Red
                    Write-Host $_.Exception.Message
                    
                    if ($Global:JsonOutputMode) {
                        Add-Finding -CheckId $script.CheckId `
                                -Asset "/tenants/$tenantid/conditional-access/policies" `
                                -Status "ERROR" `
                                -Name "Sign-In Risk Policy Check" `
                                -Description "Error occurred while checking sign-in risk policies." `
                                -Details @{ "ErrorMessage" = $_.Exception.Message } `
                                -Impact "Minor" `
                                -Likelihood "Low" `
                                -Risk "Low"
                    }
                }
            }
        },
        @{
            Name = "5.2.3.1 Microsoft Authenticator Feature Settings"
            CheckId = "5.2.3.1"
            Type = "Script"
            Logic = {
                try {
                    $authenticatorSettings = (Get-MgPolicyAuthenticationMethodPolicyAuthenticationMethodConfiguration -AuthenticationMethodConfigurationId microsoftAuthenticator | 
                        Select-Object -ExpandProperty AdditionalProperties).featureSettings | ConvertTo-Json -Depth 10 | ConvertFrom-Json

                    $authenticatorSettings | Format-Table -AutoSize
                    Write-Host ""
                    Write-Host ""

                    $failFlag = $false
                    $disabledSettings = @()
                    $enabledSettings = @()

                    foreach ($setting in $authenticatorSettings.PSObject.Properties) {
                        $state = $setting.Value.state
                        if ($state -eq "disabled") {
                            Write-Host "Fail: $($setting.Name) is disabled." -ForegroundColor Red
                            $failFlag = $true
                            $disabledSettings += $setting.Name
                        } else {
                            $enabledSettings += $setting.Name
                        }
                    }

                    if ($failFlag) {
                        Write-Host "Fail: Some Microsoft Authenticator settings are disabled." -ForegroundColor Red
                        # Add to JSON results
                        Add-Finding -CheckId $script.CheckId `
                            -Asset "/tenants/$tenantid" `
                            -Status "FAIL" `
                            -Name "Microsoft Authenticator Feature Settings" `
                            -Description "Microsoft Authenticator settings should be enabled for secure authentication" `
                            -Remediation "Enable all Microsoft Authenticator settings" `
                            -Details @{
                                DisabledSettings = $disabledSettings
                                EnabledSettings = $enabledSettings
                                Remediation = "Enable all Microsoft Authenticator settings"
                            } `
                            -Impact "Moderate" `
                            -Likelihood "Moderate" `
                            -Risk "Medium"
                    } else {
                        Write-Host "Pass: All Microsoft Authenticator settings are correctly configured." -ForegroundColor Green
                        # Add to JSON results
                        Add-Finding -CheckId $script.CheckId `
                            -Asset "/tenants/$tenantid" `
                            -Status "PASS" `
                            -Name "Microsoft Authenticator Feature Settings" `
                            -Message "All Microsoft Authenticator settings are correctly configured" `
                            -Description "Microsoft Authenticator settings should be enabled for secure authentication" `
                            -Details @{
                                EnabledSettings = $enabledSettings
                            } `
                            -Impact "Moderate" `
                            -Likelihood "Moderate" `
                            -Risk "Medium"
                    }
                } catch {
                    Write-Host "Error retrieving Microsoft Authenticator feature settings." -ForegroundColor Red
                    Write-Host $_.Exception.Message
                    # Add error to JSON results
                    Add-Finding -CheckId $script.CheckId `
                        -Asset "/tenants/$tenantid" `
                        -Status "ERROR" `
                        -Name "Microsoft Authenticator Feature Settings" `
                        -Message "Error retrieving Microsoft Authenticator feature settings: $($_.Exception.Message)" `
                        -Description "Microsoft Authenticator settings should be enabled for secure authentication" `
                        -Impact "Moderate" `
                        -Likelihood "Moderate" `
                        -Risk "Medium"
                }
            }
        },
            
        @{
            Name = "5.2.3.2 Custom Banned Password List"
            Type = "Script"
            CheckId = "5.2.3.2"
            Logic = {
                try {
                    $tenantid = (Get-MgContext).TenantId
                    $directorySettings = Get-MgBetaDirectorySetting
        
                    if ($directorySettings.Count -eq 0) {
                        Write-Host "No directory settings found." -ForegroundColor Red
                        Write-Host "FAIL: Custom Banned Password List is empty." -ForegroundColor Red
                        
                        # Add to JSON results
                        Add-Finding -CheckId $script.CheckId `
                            -Asset "/tenants/$tenantid" `
                            -Status "FAIL" `
                            -Name "Custom Banned Password List" `
                            -Description "Custom banned password list should be configured to prevent use of common passwords" `
                            -Remediation "Configure a custom banned password list in directory settings" `
                            -Details @{
                                Remediation = "Configure a custom banned password list in directory settings"
                            } `
                            -Impact "Moderate" `
                            -Likelihood "High" `
                            -Risk "High"
                        return
                    }
        
                    $bannedPasswordListEmpty = $true
                    $foundBannedLists = @()
        
                    foreach ($setting in $directorySettings) {
                        try {
                            $settingDetails = Get-MgBetaDirectorySetting -DirectorySettingId $setting.Id
        
                            $bannedPasswordList = $settingDetails.Values | Where-Object { $_.Name -eq "BannedPasswordList" }
        
                            if ($bannedPasswordList -and $bannedPasswordList.Value -ne "") {
                                Write-Host "Custom Banned Password List Details for ID $($setting.Id):" -ForegroundColor Green
                                $bannedPasswordList | Format-Table Name, Value -AutoSize
                            
                                $bannedPasswordListEmpty = $false
                                $foundBannedLists += @{
                                    "SettingId" = $setting.Id
                                    "BannedPasswordList" = $bannedPasswordList.Value
                                }
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
                        
                        # Add to JSON results
                        Add-Finding -CheckId $script.CheckId `
                            -Asset "/tenants/$tenantid" `
                            -Status "FAIL" `
                            -Name "Custom Banned Password List" `
                            -Description "Custom banned password list should be configured to prevent use of common passwords" `
                            -Remediation "Configure a custom banned password list in directory settings" `
                            -Details @{
                                Remediation = "Configure a custom banned password list in directory settings"
                            } `
                            -Impact "Moderate" `
                            -Likelihood "High" `
                            -Risk "High"
                    } else {
                        Write-Host "PASS: Custom Banned Password List is configured." -ForegroundColor Green
                        
                        # Add to JSON results
                        Add-Finding -CheckId $script.CheckId `
                            -Asset "/tenants/$tenantid" `
                            -Status "PASS" `
                            -Name "Custom Banned Password List" `
                            -Description "Custom banned password list should be configured to prevent use of common passwords" `
                            -Details @{
                                ConfiguredSettings = $foundBannedLists
                            } `
                            -Impact "Moderate" `
                            -Likelihood "High" `
                            -Risk "High"
                    }
                } catch {
                    Write-Host "Error retrieving directory settings." -ForegroundColor Red
                    Write-Host $_.Exception.Message
                    
                    # Add error to JSON results
                    Add-Finding -CheckId $script.CheckId `
                        -Asset "/tenants/$tenantid" `
                        -Status "ERROR" `
                        -Name "Custom Banned Password List" `
                        -Description "Custom banned password list should be configured to prevent use of common passwords" `
                        -Remediation "Configure a custom banned password list in directory settings" `
                        -Details @{
                            Remediation = "Configure a custom banned password list in directory settings"
                        } `
                        -Impact "Moderate" `
                        -Likelihood "High" `
                        -Risk "High"
                }
            }
        },    
        @{
            Name = "5.2.3.3 On-Prem Password Protection"
            Type = "Manual"
            CheckId = "5.2.3.3"
            RequiresExchange = $false
            Link = "https://entra.microsoft.com/#view/Microsoft_AAD_IAM/AuthenticationMethodsMenuBlade/~/PasswordProtection/fromNav/Identity"
            explanation = {
                Verify password protection is enabled
                Ensure 'Enable password protection on Windows Server Active Directory' is set 'Yes' and Mode is set to 'Enforced'
            }
            Logic = {
                $tenantid = (Get-MgContext).TenantId
                # Manual check, add finding to JSON results
                    Add-Finding -CheckId $script.CheckId `
                        -Asset "/tenants/$tenantid" `
                        -Status "MANUAL" `
                        -Name "On-Prem Password Protection" `
                        -Description "Password protection should be enabled on Windows Server Active Directory" `
                        -Remediation "Enable password protection on Windows Server Active Directory and set Mode to 'Enforced'" `
                        -Details @{ 
                            "CheckLink" = "https://entra.microsoft.com/#view/Microsoft_AAD_IAM/AuthenticationMethodsMenuBlade/~/PasswordProtection/fromNav/Identity"
                            "VerificationSteps" = @(
                                "Verify password protection is enabled",
                                "Ensure 'Enable password protection on Windows Server Active Directory' is set 'Yes'",
                                "Ensure Mode is set to 'Enforced'"
                            )
                        } `
                            -Impact "Moderate" `
                            -Likelihood "Moderate" `
                            -Risk "Medium"
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
            CheckId = "5.2.3.5"
            RequiresExchange = $false
            Link = "https://entra.microsoft.com/#view/Microsoft_AAD_IAM/AuthenticationMethodsMenuBlade/~/AdminAuthMethods/fromNav/Identity"
            explanation = {
                Verify weak authentication methods are not used
                Ensure 'SMS, Voice Call, and Email OTP' are set to 'No'
            }
            Logic = {
                $tenantid = (Get-MgContext).TenantId
                # Manual check, add finding to JSON results
                Add-Finding -CheckId $script.CheckId `
                        -Asset "/tenants/$tenantid" `
                        -Status "MANUAL" `
                        -Name "Weak Authentication Methods Disabled" `
                        -Description "Weak authentication methods should be disabled." `
                        -Remediation "Ensure SMS, Voice Call, and Email OTP authentication methods are set to 'No'" `
                        -Details @{ 
                            "CheckLink" = "https://entra.microsoft.com/#view/Microsoft_AAD_IAM/AuthenticationMethodsMenuBlade/~/AdminAuthMethods/fromNav/Identity"
                            "VerificationSteps" = @(
                                "Verify weak authentication methods are not used",
                                "Ensure 'SMS, Voice Call, and Email OTP' are set to 'No'"
                            )
                        } `
                        -Impact "Moderate" `
                        -Likelihood "Moderate" `
                        -Risk "Medium"
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
            CheckId = "5.3.1"
            RequiresExchange = $false
            Link = "https://entra.microsoft.com/#view/Microsoft_Azure_PIMCommon/ResourceMenuBlade/~/roles/resourceId//resourceType/tenant/provider/aadroles"
            explanation = {
                Verify sensitive roles do not have a permanent role
                Click on sensitive roles such as Application Administrator -> select 'role settings' in the left pane.
                Ensure 'Allow permanent eligible assignment' and 'Allow permanent active assignment' is set to 'No'
            }
            Logic = {
                    $tenantid = (Get-MgContext).TenantId
                # Manual check, add finding to JSON results
                    Add-Finding -CheckId $script.CheckId `
                            -Asset "/tenants/$tenantid" `
                        -Status "MANUAL" `
                        -Name "Privileged Identity Management" `
                        -Description "Sensitive roles should not have permanent assignments." `
                        -Remediation "Configure role settings to disallow permanent eligible assignments and permanent active assignments." `
                        -Details @{ 
                            "CheckLink" = "https://entra.microsoft.com/#view/Microsoft_Azure_PIMCommon/ResourceMenuBlade/~/roles/resourceId//resourceType/tenant/provider/aadroles"
                            "VerificationSteps" = @(
                                "Verify sensitive roles do not have a permanent role",
                                "Click on sensitive roles such as Application Administrator -> select 'role settings' in the left pane",
                                "Ensure 'Allow permanent eligible assignment' and 'Allow permanent active assignment' is set to 'No'"
                            )
                        } `
                        -Impact "Major" `
                        -Likelihood "Moderate" `
                        -Risk "High"
            }
        },
        @{
            Name = "5.3.2 Access Reviews for Guest Users"
            Type = "Manual"
            CheckId = "5.3.2"
            RequiresExchange = $false
            Link = "https://entra.microsoft.com/#view/Microsoft_AAD_ERM/DashboardBlade/~/Controls?Microsoft_AAD_IAM_legacyAADRedirect=true"
            explanation = {
                Verify access reviews exist for guest users
                Policy must meet the following, Overview: Scope is set to Guest users only and status is Active
            }
            Logic = {
                $tenantid = (Get-MgContext).TenantId
                # Manual check, add finding to JSON results
                Add-Finding -CheckId $script.CheckId `
                        -Asset "/tenants/$tenantid" `
                        -Status "MANUAL" `
                        -Name "Access Reviews for Guest Users" `
                        -Description "Access reviews should be configured for guest users to ensure appropriate access." `
                        -Remediation "Configure access reviews with scope set to Guest users only and ensure the status is Active." `
                        -Details @{ 
                            "CheckLink" = "https://entra.microsoft.com/#view/Microsoft_AAD_ERM/DashboardBlade/~/Controls?Microsoft_AAD_IAM_legacyAADRedirect=true"
                            "VerificationSteps" = @(
                                "Verify access reviews exist for guest users",
                                "Ensure the policy scope is set to Guest users only",
                                "Ensure the policy status is Active"
                            )
                        } `
                        -Impact "Moderate" `
                        -Likelihood "Moderate" `
                        -Risk "Medium"
            }
        },
        @{
            Name = "5.3.3 Access Reviews for Privileged Roles"
            Type = "Manual"
            CheckId = "5.3.3"
            RequiresExchange = $false
            Link = "https://entra.microsoft.com/#view/Microsoft_AAD_ERM/DashboardBlade/~/Controls?Microsoft_AAD_IAM_legacyAADRedirect=true"
            explanation = {
                Verify access reviews exist for guest users
                Policy must meet the following, Scope: Everyone and status is Active
            }
            Logic = {
                $tenantid = (Get-MgContext).TenantId
                # Manual check, add finding to JSON results
                Add-Finding -CheckId $script.CheckId `
                        -Asset "/tenants/$tenantid" `
                        -Status "MANUAL" `
                        -Name "Access Reviews for Privileged Roles" `
                        -Description "Access reviews should be configured for privileged roles to ensure appropriate access." `
                        -Remediation "Configure access reviews with scope set to Everyone and ensure the status is Active." `
                        -Details @{ 
                            "CheckLink" = "https://entra.microsoft.com/#view/Microsoft_AAD_ERM/DashboardBlade/~/Controls?Microsoft_AAD_IAM_legacyAADRedirect=true"
                            "VerificationSteps" = @(
                                "Verify access reviews exist for privileged roles",
                                "Ensure the policy scope is set to Everyone",
                                "Ensure the policy status is Active"
                            )
                        } `
                        -Impact "Moderate" `
                        -Likelihood "Moderate" `
                        -Risk "Medium"
            }
        },
        @{
            Name = "5.3.4 Global Admin Role Approval"
            Type = "Manual"
            CheckId = "5.3.4"
            RequiresExchange = $false
            Link = "https://entra.microsoft.com/#view/Microsoft_Azure_PIMCommon/UserRolesViewModelMenuBlade/~/settings/menuId/members/roleName/Global%20Administrator/roleObjectId/62e90394-69f5-4237-9190-012177145e10/isRoleCustom~/false/roleTemplateId/62e90394-69f5-4237-9190-012177145e10/resourceId/816e01e5-e687-4437-bb2b-5e1507d3f8bb/isInternalCall~/true?Microsoft_AAD_IAM_legacyAADRedirect=true"
            explanation = {
                Ensure approval is required for Global Admin activation
                Click on Global Administrator -> select 'role settings' in the left pane.
                Ensure 'Require approval to activate' is set to 'Yes'
            }
            Logic = {
                $tenantid = (Get-MgContext).TenantId
                # Manual check, add finding to JSON results
                Add-Finding -CheckId $script.CheckId `
                        -Asset "/tenants/$tenantid" `
                        -Status "MANUAL" `
                        -Name "Global Admin Role Approval" `
                        -Description "Approval should be required for Global Admin activation." `
                        -Remediation "Configure Global Administrator role settings to require approval to activate." `
                        -Details @{ 
                            "CheckLink" = "https://entra.microsoft.com/#view/Microsoft_Azure_PIMCommon/UserRolesViewModelMenuBlade/~/settings/menuId/members/roleName/Global%20Administrator/roleObjectId/62e90394-69f5-4237-9190-012177145e10/isRoleCustom~/false/roleTemplateId/62e90394-69f5-4237-9190-012177145e10/resourceId/816e01e5-e687-4437-bb2b-5e1507d3f8bb/isInternalCall~/true?Microsoft_AAD_IAM_legacyAADRedirect=true"
                            "VerificationSteps" = @(
                                "Verify approval is required for Global Admin activation",
                                "Click on Global Administrator -> select 'role settings' in the left pane",
                                "Ensure 'Require approval to activate' is set to 'Yes'"
                            )
                        } `
                        -Impact "Major" `
                        -Likelihood "Moderate" `
                        -Risk "High"
            }
        },
        @{
            Name = "6.1.1 Audit Disabled"
            Type = "Script"
            CheckId = "6.1.1"
            RequiresExchange = $false
            Logic = {
                try {
                    Disconnect-ExchangeOnline -Confirm:$false -ErrorAction SilentlyContinue
                    Connect-ExchangeOnline -CertificateThumbprint "$Thumbprint" -AppId "$AppId" -Organization "$Domain" -ShowBanner:$false
                    Start-Sleep 1
                    $orgConfig = Get-OrganizationConfig | Select-Object AuditDisabled
                    $orgConfig | Format-Table -AutoSize
                    Write-Host ""
                    Write-Host ""
        
                    if ($orgConfig.AuditDisabled -eq $false) {
                        Write-Host "PASS: Audit is not disabled (AuditDisabled = False)." -ForegroundColor Green
                        Add-Finding -CheckId $script.CheckId `
                                -Asset "/tenants/$tenantid" `
                                -Status "PASS" `
                                -Name "Audit Disabled" `
                                -Description "Audit is not disabled." `
                                -Remediation "Disable audit by setting AuditDisabled to True." `
                                -Details @{ "Message" = "Audit is not disabled" } `
                                -Risk "Medium" `
                                -Impact "Moderate" `
                                -Likelihood "Moderate" `
                    } elseif ($orgConfig.AuditDisabled -eq $true) {
                        Write-Host "FAIL: Audit is disabled (AuditDisabled = True)." -ForegroundColor Red
                        Add-Finding -CheckId $script.CheckId `
                                -Asset "/tenants/$tenantid" `
                                -Status "FAIL" `
                                -Name "Audit Disabled" `
                                -Description "Audit is disabled." `
                                -Remediation "Enable audit by setting AuditDisabled to False." `
                                -Details @{ "Message" = "Audit is disabled" } `
                                -Risk "Medium" `
                                -Impact "Moderate" `
                                -Likelihood "Moderate" `
                    } else {
                        Write-Host "FAIL: Unable to determine the AuditDisabled status." -ForegroundColor Red
                        Add-Finding -CheckId $script.CheckId `
                                -Asset "/tenants/$tenantid" `
                                -Status "FAIL" `
                                -Name "Audit Disabled" `
                                -Description "Unable to determine the AuditDisabled status." `
                                -Remediation "Check the AuditDisabled status." `
                                -Details @{ "Message" = "Unable to determine the AuditDisabled status" } `
                                -Risk "Medium" `
                                -Impact "Moderate" `
                                -Likelihood "Moderate"
                    }
        
                } catch {
                    Write-Host "Error retrieving organization configuration." -ForegroundColor Red
                    Write-Host $_.Exception.Message
                    Add-Finding -CheckId $script.CheckId `
                            -Asset "/tenants/$tenantid" `
                            -Status "ERROR" `
                            -Name "Audit Disabled" `
                            -Description "Error retrieving organization configuration." `
                            -Remediation "Check the organization configuration." `
                            -Details @{ "Message" = $_.Exception.Message } `
                            -Risk "Medium" `
                            -Impact "Moderate" `
                            -Likelihood "Moderate"
                    
                }
            }
        },    
        @{
            Name = "6.1.2 Mailbox Auditing for E3 Users"
            Type = "Script"
            CheckId = "6.1.2"
            RequiresExchange = $true
            Logic = {
                try {
                    Disconnect-ExchangeOnline -Confirm:$false -ErrorAction SilentlyContinue
                    Connect-ExchangeOnline -CertificateThumbprint "$Thumbprint" -AppId "$AppId" -Organization "$Domain" -ShowBanner:$false
                    Start-Sleep 1
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
            CheckId = "6.1.4"
            RequiresExchange = $true
            Logic = {
                try {
                    Disconnect-ExchangeOnline -Confirm:$false -ErrorAction SilentlyContinue
                    Connect-ExchangeOnline -CertificateThumbprint "$Thumbprint" -AppId "$AppId" -Organization "$Domain" -ShowBanner:$false
                    Start-Sleep 1
        
                    $MBX = Get-MailboxAuditBypassAssociation -ResultSize unlimited
        
                    $auditBypassEnabled = $MBX | Where-Object { $_.AuditBypassEnabled -eq $true }
        
                    if (-not $auditBypassEnabled) {
                        Write-Host "PASS: No Audit Bypass Enabled entries found." -ForegroundColor Green
                        Add-Finding -CheckId $script.CheckId `
                                -Asset "/tenants/$tenantid" `
                                -Status "PASS" `
                                -Name "Audit Bypass Enabled" `
                                -Description "Audit bypass is not enabled." `
                                -Remediation "Disable audit bypass by setting AuditBypassEnabled to False." `
                                -Details @{ "Message" = "Audit bypass is not enabled" } `
                                -Risk "Medium" `
                                -Impact "Moderate" `
                                -Likelihood "Moderate"
                    } else {
                        $auditBypassEnabled | Format-Table Name, AuditBypassEnabled -AutoSize
                        Write-Host ""
                        Write-Host ""
                        Write-Host "FAIL: Audit Bypass Enabled entries found." -ForegroundColor Red
                        Add-Finding -CheckId $script.CheckId `
                                -Asset "/tenants/$tenantid" `
                                -Status "FAIL" `
                                -Name "Audit Bypass Enabled" `
                                -Description "Audit bypass is enabled." `
                                -Remediation "Disable audit bypass by setting AuditBypassEnabled to False." `
                                -Details @{ "Message" = "Audit bypass is enabled" } `
                                -Risk "Medium" `
                                -Impact "Moderate" `
                                -Likelihood "Moderate"
                    }
                } catch {
                    Write-Host "Error retrieving Audit Bypass Enabled settings." -ForegroundColor Red
                    Write-Host $_.Exception.Message
                    Add-Finding -CheckId $script.CheckId `
                            -Asset "/tenants/$tenantid" `
                            -Status "ERROR" `
                            -Name "Audit Bypass Enabled" `
                            -Description "Error retrieving Audit Bypass Enabled settings." `
                            -Remediation "Check the Audit Bypass Enabled settings." `
                            -Details @{ "Message" = $_.Exception.Message } `
                            -Risk "Medium" `
                            -Impact "Moderate" `
                            -Likelihood "Moderate"
                    
                }
            }
        },        
        @{
            Name = "6.2.1 Mail Forwarding Blocked or Disabled"
            Type = "Script"
            Logic = {
                Disconnect-ExchangeOnline -Confirm:$false -ErrorAction SilentlyContinue
                Connect-ExchangeOnline -CertificateThumbprint "$Thumbprint" -AppId "$AppId" -Organization "$Domain" -ShowBanner:$false
                Start-Sleep 1
                Get-TransportRule | Where-Object {$_.RedirectMessageTo -ne $null} | Format-Table Name, RedirectMessageTo
                Get-HostedOutboundSpamFilterPolicy | Format-Table Name, AutoForwardingMode
            }
        },
        @{
            Name = "6.2.2 Whitelisted Domains"
            Type = "Script"
            CheckId = "6.2.2"
            RequiresExchange = $true
            Logic = {
                try {
                    Disconnect-ExchangeOnline -Confirm:$false -ErrorAction SilentlyContinue
                    Connect-ExchangeOnline -CertificateThumbprint "$Thumbprint" -AppId "$AppId" -Organization "$Domain" -ShowBanner:$false
                    Start-Sleep 1        
                    $whitelistedDomains = Get-TransportRule | Where-Object { ($_.SetScl -eq -1 -and $_.SenderDomainIs -ne $null) }
        
                    if ($whitelistedDomains) {
                        $whitelistedDomains | Format-Table Name, SenderDomainIs -AutoSize
                        Write-Host ""
                        Write-Host ""
                        Write-Host "FAIL: Whitelisted Domains Found" -ForegroundColor Red
                        Add-Finding -CheckId $script.CheckId `
                                -Asset "/tenants/$tenantid" `
                                -Status "FAIL" `
                                -Name "Whitelisted Domains" `
                                -Description "Whitelisted domains found in transport rules." `
                                -Remediation "Remove the whitelisted domains from the transport rules." `
                                -Details @{ "Message" = "Whitelisted domains found in transport rules." } `
                                -Risk "Medium" `
                                -Impact "Moderate" `
                                -Likelihood "Moderate"
                    } else {
                        Write-Host "PASS: No transport rules with whitelisted domains found." -ForegroundColor Green
                        Add-Finding -CheckId $script.CheckId `
                                -Asset "/tenants/$tenantid" `
                                -Status "PASS" `
                                -Name "Whitelisted Domains" `
                                -Description "No transport rules with whitelisted domains found." `
                                -Details @{ "Message" = "No transport rules with whitelisted domains found." } `
                                -Risk "Medium" `
                                -Impact "Moderate" `
                                -Likelihood "Moderate"
                    }
                } catch {
                    Write-Host "Error retrieving whitelisted domains in transport rules." -ForegroundColor Red
                    Write-Host $_.Exception.Message
                    Add-Finding -CheckId $script.CheckId `
                            -Asset "/tenants/$tenantid" `
                            -Status "ERROR" `
                            -Name "Whitelisted Domains" `
                            -Description "Error retrieving whitelisted domains in transport rules." `
                            -Remediation "Check the whitelisted domains in transport rules." `
                            -Details @{ "Message" = $_.Exception.Message } `
                            -Risk "Medium" `
                            -Impact "Moderate" `
                            -Likelihood "Moderate"
                }
            }
        },    
        @{
            Name = "6.2.3 External in Outlook"
            Type = "Script"
            CheckId = "6.2.3"
            RequiresExchange = $true
            Logic = {
                try {
                    Disconnect-ExchangeOnline -Confirm:$false -ErrorAction SilentlyContinue
                    Connect-ExchangeOnline -CertificateThumbprint "$Thumbprint" -AppId "$AppId" -Organization "$Domain" -ShowBanner:$false
                    Start-Sleep 1
                    $outlookSettings = Get-ExternalInOutlook
        
                    $outlookSettings | Format-List
        
                    Write-Host "" 
                    Write-Host ""
        
                    if ($outlookSettings.Enabled -eq $true) {
                        Write-Host "PASS: 'External in Outlook' is Enabled." -ForegroundColor Green
                        Add-Finding -CheckId $script.CheckId `
                                -Asset "/tenants/$tenantid" `
                                -Status "PASS" `
                                -Name "External in Outlook" `
                                -Description "'External in Outlook' is enabled." `
                                -Remediation "'External in Outlook' is enabled." `
                                -Details @{ "Message" = "'External in Outlook' is enabled." } `
                                -Risk "Medium" `
                                -Impact "Moderate" `
                                -Likelihood "Moderate"
                    } else {
                        Write-Host "FAIL: 'External in Outlook' is Disabled or not configured correctly." -ForegroundColor Red
                        Add-Finding -CheckId $script.CheckId `
                                -Asset "/tenants/$tenantid" `
                                -Status "FAIL" `
                                -Name "External in Outlook" `
                                -Description "'External in Outlook' is disabled or not configured correctly." `
                                -Remediation "'External in Outlook' is disabled or not configured correctly." `
                                -Details @{ "Message" = "'External in Outlook' is disabled or not configured correctly." } `
                                -Risk "Medium" `
                                -Impact "Moderate" `
                                -Likelihood "Moderate"
                    }
                } catch {
                    Write-Host "Error retrieving 'External in Outlook' settings." -ForegroundColor Red
                    Write-Host $_.Exception.Message
                    Add-Finding -CheckId $script.CheckId `
                            -Asset "/tenants/$tenantid" `
                            -Status "ERROR" `
                            -Name "External in Outlook" `
                            -Description "Error retrieving 'External in Outlook' settings." `
                            -Remediation "Check the 'External in Outlook' settings." `
                            -Details @{ "Message" = $_.Exception.Message } `
                            -Risk "Medium" `
                            -Impact "Moderate" `
                            -Likelihood "Moderate"
                }
            }
        },    
        @{
            Name = "6.5.1 Modern Auth for Exchange Online"
            Type = "Script"
            CheckId = "6.5.1"
            RequiresExchange = $true
            Logic = {
                try {
                    Disconnect-ExchangeOnline -Confirm:$false -ErrorAction SilentlyContinue
                    Connect-ExchangeOnline -CertificateThumbprint "$Thumbprint" -AppId "$AppId" -Organization "$Domain" -ShowBanner:$false
                    Start-Sleep 1
                    $orgConfig = Get-OrganizationConfig | Select-Object OAuth2ClientProfileEnabled
        
                    if ($orgConfig.OAuth2ClientProfileEnabled -eq $true) {
                        Write-Host "PASS: Modern Authentication (OAuth2ClientProfileEnabled) is Enabled." -ForegroundColor Green
                        Add-Finding -CheckId $script.CheckId `
                                -Asset "/tenants/$tenantid" `
                                -Status "PASS" `
                                -Name "Modern Authentication" `
                                -Description "Modern Authentication is enabled." `
                                -Remediation "Enable Modern Authentication by setting OAuth2ClientProfileEnabled to True." `
                                -Details @{ "Message" = "Modern Authentication is enabled." } `
                                -Risk "Medium" `
                                -Impact "Moderate" `
                                -Likelihood "Moderate"
                    } else {
                        $orgConfig
                        Write-Host ""
                        Write-Host ""
                        Write-Host "FAIL: Modern Authentication (OAuth2ClientProfileEnabled) is Disabled or not configured." -ForegroundColor Red
                        Add-Finding -CheckId $script.CheckId `
                                -Asset "/tenants/$tenantid" `
                                -Status "FAIL" `
                                -Name "Modern Authentication" `
                                -Description "Modern Authentication is disabled or not configured." `
                                -Remediation "Enable Modern Authentication by setting OAuth2ClientProfileEnabled to True." `
                                -Details @{ "Message" = "Modern Authentication is disabled or not configured." } `
                                -Risk "Medium" `
                                -Impact "Moderate" `
                                -Likelihood "Moderate"
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
            CheckId = "6.5.2"
            RequiresExchange = $true
            Logic = {
                try {
                    Disconnect-ExchangeOnline -Confirm:$false -ErrorAction SilentlyContinue
                    Connect-ExchangeOnline -CertificateThumbprint "$Thumbprint" -AppId "$AppId" -Organization "$Domain" -ShowBanner:$false
                    Start-Sleep 1        
                    $mailTips = Get-OrganizationConfig | Select-Object MailTipsAllTipsEnabled, MailTipsExternalRecipientsTipsEnabled, MailTipsGroupMetricsEnabled
        
                    $mailTips | Format-Table -AutoSize
                    Write-Host ""
                    Write-Host ""
        
                    if ($mailTips.MailTipsAllTipsEnabled -eq $true -and 
                        $mailTips.MailTipsExternalRecipientsTipsEnabled -eq $true -and 
                        $mailTips.MailTipsGroupMetricsEnabled -eq $true) {
                        Write-Host "PASS: All required MailTips settings are enabled." -ForegroundColor Green
                        Add-Finding -CheckId $script.CheckId `
                                -Asset "/tenants/$tenantid" `
                                -Status "PASS" `
                                -Name "MailTips" `
                                -Description "All required MailTips settings are enabled." `
                                -Remediation "Enable all required MailTips settings by setting MailTipsAllTipsEnabled, MailTipsExternalRecipientsTipsEnabled, and MailTipsGroupMetricsEnabled to True." `
                                -Details @{ "Message" = "All required MailTips settings are enabled." } `
                                -Risk "Medium" `
                                -Impact "Moderate" `
                                -Likelihood "Moderate"
                    } else {
                        Write-Host "FAIL: One or more required MailTips settings are not enabled." -ForegroundColor Red
                        Add-Finding -CheckId $script.CheckId `
                                -Asset "/tenants/$tenantid" `
                                -Status "FAIL" `
                                -Name "MailTips" `
                                -Description "One or more required MailTips settings are not enabled." `
                                -Remediation "Enable all required MailTips settings by setting MailTipsAllTipsEnabled, MailTipsExternalRecipientsTipsEnabled, and MailTipsGroupMetricsEnabled to True." `
                                -Details @{ "Message" = "One or more required MailTips settings are not enabled." } `
                                -Risk "Medium" `
                                -Impact "Moderate" `
                                -Likelihood "Moderate"
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
            CheckId = "6.5.3"
            RequiresExchange = $true
            Logic = {
                try {
                    Disconnect-ExchangeOnline -Confirm:$false -ErrorAction SilentlyContinue
                    Connect-ExchangeOnline -CertificateThumbprint "$Thumbprint" -AppId "$AppId" -Organization "$Domain" -ShowBanner:$false
                    Start-Sleep 1        
                    $owaPolicies = Get-OwaMailboxPolicy | Select-Object Name, AdditionalStorageProvidersAvailable
        
                    $owaPolicies | Format-Table -AutoSize
                    Write-Host ""
                    Write-Host ""
        
                    if ($owaPolicies.AdditionalStorageProvidersAvailable -contains $true) {
                        Write-Host "FAIL: One or more policies have AdditionalStorageProvidersAvailable set to True." -ForegroundColor Red
                        Add-Finding -CheckId $script.CheckId `
                                -Asset "/tenants/$tenantid" `
                                -Status "FAIL" `
                                -Name "Additional Storage Providers" `
                                -Description "One or more policies have AdditionalStorageProvidersAvailable set to True." `
                                -Remediation "Disable AdditionalStorageProvidersAvailable by setting it to False." `
                                -Details @{ "Message" = "One or more policies have AdditionalStorageProvidersAvailable set to True." } `
                                -Risk "Medium" `
                                -Impact "Moderate" `
                                -Likelihood "Moderate"
                    } else {
                        Write-Host "PASS: All policies have AdditionalStorageProvidersAvailable set to False." -ForegroundColor Green
                        Add-Finding -CheckId $script.CheckId `
                                -Asset "/tenants/$tenantid" `
                                -Status "PASS" `
                                -Name "Additional Storage Providers" `
                                -Description "All policies have AdditionalStorageProvidersAvailable set to False." `
                                -Remediation "Disable AdditionalStorageProvidersAvailable by setting it to False." `
                                -Details @{ "Message" = "All policies have AdditionalStorageProvidersAvailable set to False." } `
                                -Risk "Medium" `
                                -Impact "Moderate" `
                                -Likelihood "Moderate"
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
            CheckId = "6.5.4"
            RequiresExchange = $true
            Logic = {
                try {
                    Disconnect-ExchangeOnline -Confirm:$false -ErrorAction SilentlyContinue
                    Connect-ExchangeOnline -CertificateThumbprint "$Thumbprint" -AppId "$AppId" -Organization "$Domain" -ShowBanner:$false
                    Start-Sleep 1        
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
                        Add-Finding -CheckId $script.CheckId `
                                -Asset "/tenants/$tenantid" `
                                -Status "FAIL" `
                                -Name "SMTP Client Authentication" `
                                -Description "SMTP Client Authentication is not disabled (set to false)." `
                                -Remediation "Disable SMTP Client Authentication by setting SmtpClientAuthenticationDisabled to True." `
                                -Details @{ "Message" = "SMTP Client Authentication is not disabled (set to false)." } `
                                -Risk "Medium" `
                                -Impact "Moderate" `
                                -Likelihood "Moderate"
                    } else {
                        Write-Host "PASS: SMTP Client Authentication is disabled (set to true)." -ForegroundColor Green
                        Add-Finding -CheckId $script.CheckId `
                                -Asset "/tenants/$tenantid" `
                                -Status "PASS" `
                                -Name "SMTP Client Authentication" `
                                -Description "SMTP Client Authentication is disabled (set to true)." `
                                -Remediation "Disable SMTP Client Authentication by setting SmtpClientAuthenticationDisabled to True." `
                                -Details @{ "Message" = "SMTP Client Authentication is disabled (set to true)." } `
                                -Risk "Medium" `
                                -Impact "Moderate" `
                                -Likelihood "Moderate"
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
            CheckId = "8.1.2"
            Logic = {
                try {
        
                    $teamsConfig = Get-CsTeamsClientConfiguration -Identity Global | Select-Object AllowEmailIntoChannel
        
                    Write-Host ""
                    $teamsConfig | Format-List
                    Write-Host ""
                    Write-Host ""
        
                    if ($teamsConfig.AllowEmailIntoChannel -eq $true) {
                        Write-Host "FAIL: AllowEmailIntoChannel is set to True." -ForegroundColor Red
                        Add-Finding -CheckId $script.CheckId `
                                -Asset "/tenants/$tenantid/teams/client-configuration" `
                                -Status "FAIL" `
                                -Name "Email into Teams Channel" `
                                -Description "AllowEmailIntoChannel is set to True." `
                                -Remediation "Disable AllowEmailIntoChannel by setting it to False." `
                                -Details @{ "Message" = "AllowEmailIntoChannel is set to True." } `
                                -Risk "Medium" `
                                -Impact "Moderate" `
                                -Likelihood "Moderate"
                    } elseif ($teamsConfig.AllowEmailIntoChannel -eq $false) {
                        Write-Host "PASS: AllowEmailIntoChannel is set to False." -ForegroundColor Green
                        Add-Finding -CheckId $script.CheckId `
                                -Asset "/tenants/$tenantid/teams/client-configuration" `
                                -Status "PASS" `
                                -Name "Email into Teams Channel" `
                                -Description "AllowEmailIntoChannel is set to False." `
                                -Remediation "Disable AllowEmailIntoChannel by setting it to False." `
                                -Details @{ "Message" = "AllowEmailIntoChannel is set to False." } `
                                -Risk "Medium" `
                                -Impact "Moderate" `
                                -Likelihood "Moderate"
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
            CheckId = "8.2.1"
            Logic = {
                try {
        
                    $federationConfig = Get-CsTenantFederationConfiguration | Select-Object AllowFederatedUsers, AllowedDomains
                    Write-Host ""
                    $federationConfig | Format-List
                    Write-Host ""
                    Write-Host ""
        
                    if ($federationConfig.AllowFederatedUsers -eq $false) {
                        Write-Host "PASS: AllowFederatedUsers is set to False." -ForegroundColor Green
                        Add-Finding -CheckId $script.CheckId `
                                -Asset "/tenants/$tenantid/teams/federation-configuration" `
                                -Status "PASS" `
                                -Name "Teams Federation Configuration" `
                                -Description "AllowFederatedUsers is set to False." `
                                -Remediation "Disable AllowFederatedUsers by setting it to False." `
                                -Details @{ "Message" = "AllowFederatedUsers is set to False." } `
                                -Risk "Medium" `
                                -Impact "Moderate" `
                                -Likelihood "Moderate"
                        if ($federationConfig.AllowedDomains -contains "AllowAllKnownDomains") {
                            Write-Host "FAIL: AllowedDomains is set to AllowAllKnownDomains." -ForegroundColor Red
                            Add-Finding -CheckId $script.CheckId `
                                    -Asset "/tenants/$tenantid/teams/federation-configuration" `
                                    -Status "FAIL" `
                                    -Name "Teams Federation Configuration" `
                                    -Description "AllowedDomains is set to AllowAllKnownDomains." `
                                    -Remediation "Disable AllowFederatedUsers by setting it to False." `
                                    -Details @{ "Message" = "AllowedDomains is set to AllowAllKnownDomains." } `
                                    -Risk "Medium" `
                                    -Impact "Moderate" `
                                    -Likelihood "Moderate"
                        } elseif ($federationConfig.AllowedDomains.Count -eq 0) {
                            Write-Host "FAIL: AllowFederatedUsers is True but no domains are explicitly allowed." -ForegroundColor Red
                            Add-Finding -CheckId $script.CheckId `
                                    -Asset "/tenants/$tenantid/teams/federation-configuration" `
                                    -Status "FAIL" `
                                    -Name "Teams Federation Configuration" `
                                    -Description "AllowFederatedUsers is True but no domains are explicitly allowed." `
                                    -Remediation "Specify authorized domains by setting AllowedDomains." `
                                    -Details @{ "Message" = "AllowFederatedUsers is True but no domains are explicitly allowed." } `
                                    -Risk "Medium" `
                                    -Impact "Moderate" `
                                    -Likelihood "Moderate"
                        } else {
                            Write-Host "PASS: AllowFederatedUsers is True and authorized domains are specified." -ForegroundColor Green
                            Add-Finding -CheckId $script.CheckId `
                                    -Asset "/tenants/$tenantid/teams/federation-configuration" `
                                    -Status "PASS" `
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
            CheckId = "8.2.2"
            Logic = {
                try {
        
                    $consumerFederationConfig = Get-CsTenantFederationConfiguration | Select-Object AllowTeamsConsumer
        
                    Write-Host "" 
                    $consumerFederationConfig | Format-List
                    Write-Host ""
                    Write-Host ""
        
                    if ($consumerFederationConfig.AllowTeamsConsumer -eq $false) {
                        Write-Host "PASS: AllowTeamsConsumer is set to False." -ForegroundColor Green
                        Add-Finding -CheckId $script.CheckId `
                                -Asset "/tenants/$tenantid/teams/consumer-federation-configuration" `
                                -Status "PASS" `
                                -Name "Teams Consumer Federation Configuration" `
                                -Description "AllowTeamsConsumer is set to False." `
                                -Remediation "Disable AllowTeamsConsumer by setting it to False." `
                                -Details @{ "Message" = "AllowTeamsConsumer is set to False." } `
                                -Risk "Medium" `
                                -Impact "Moderate" `
                                -Likelihood "Moderate"
                    } else {
                        Write-Host "FAIL: AllowTeamsConsumer is set to True." -ForegroundColor Red
                        Add-Finding -CheckId $script.CheckId `
                                -Asset "/tenants/$tenantid/teams/consumer-federation-configuration" `
                                -Status "FAIL" `
                                -Name "Teams Consumer Federation Configuration" `
                                -Description "AllowTeamsConsumer is set to True." `
                                -Remediation "Disable AllowTeamsConsumer by setting it to False." `
                                -Details @{ "Message" = "AllowTeamsConsumer is set to True." } `
                                -Risk "Medium" `
                                -Impact "Moderate" `
                                -Likelihood "Moderate"
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
            CheckId = "8.2.3"
            Logic = {
                try {
        
                    $inboundConfig = Get-CsTenantFederationConfiguration | Select-Object AllowTeamsConsumerInbound
        
                    Write-Host ""
                    $inboundConfig | Format-List
                    Write-Host ""
                    Write-Host ""
        
                    if ($inboundConfig.AllowTeamsConsumerInbound -eq $false) {
                        Write-Host "PASS: AllowTeamsConsumerInbound is set to False." -ForegroundColor Green
                        Add-Finding -CheckId $script.CheckId `
                                -Asset "/tenants/$tenantid/teams/consumer-federation-configuration" `
                                -Status "PASS" `
                                -Name "Teams Consumer Federation Inbound Configuration" `
                                -Description "AllowTeamsConsumerInbound is set to False." `
                                -Remediation "Disable AllowTeamsConsumerInbound by setting it to False." `
                                -Details @{ "Message" = "AllowTeamsConsumerInbound is set to False." } `
                                -Risk "Medium" `
                                -Impact "Moderate" `
                                -Likelihood "Moderate"
                    } else {
                        Write-Host "FAIL: AllowTeamsConsumerInbound is set to True." -ForegroundColor Red
                        Add-Finding -CheckId $script.CheckId `
                                -Asset "/tenants/$tenantid/teams/consumer-federation-configuration" `
                                -Status "FAIL" `
                                -Name "Teams Consumer Federation Inbound Configuration" `
                                -Description "AllowTeamsConsumerInbound is set to True." `
                                -Remediation "Disable AllowTeamsConsumerInbound by setting it to False." `
                                -Details @{ "Message" = "AllowTeamsConsumerInbound is set to True." } `
                                -Risk "Medium" `
                                -Impact "Moderate" `
                                -Likelihood "Moderate"
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
            CheckId = "8.2.4"
            Logic = {
                try {
        
                    $publicUserConfig = Get-CsTenantFederationConfiguration | Select-Object AllowPublicUsers
        
                    Write-Host "" -ForegroundColor Yellow
                    $publicUserConfig | Format-List
                    Write-Host ""
                    Write-Host ""
        
                    if ($publicUserConfig.AllowPublicUsers -eq $false) {
                        Write-Host "PASS: AllowPublicUsers is set to False." -ForegroundColor Green
                        Add-Finding -CheckId $script.CheckId `
                                -Asset "/tenants/$tenantid/teams/public-federation-configuration" `
                                -Status "PASS" `
                                -Name "Teams Public Federation Configuration" `
                                -Description "AllowPublicUsers is set to False." `
                                -Remediation "Disable AllowPublicUsers by setting it to False." `
                                -Details @{ "Message" = "AllowPublicUsers is set to False." } `
                                -Risk "Medium" `
                                -Impact "Moderate" `
                                -Likelihood "Moderate"
                    } else {
                        Write-Host "FAIL: AllowPublicUsers is set to True." -ForegroundColor Red
                        Add-Finding -CheckId $script.CheckId `
                                -Asset "/tenants/$tenantid/teams/public-federation-configuration" `
                                -Status "FAIL" `
                                -Name "Teams Public Federation Configuration" `
                                -Description "AllowPublicUsers is set to True." `
                                -Remediation "Disable AllowPublicUsers by setting it to False." `
                                -Details @{ "Message" = "AllowPublicUsers is set to True." } `
                                -Risk "Medium" `
                                -Impact "Moderate" `
                                -Likelihood "Moderate"
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
            CheckId = "8.5.1"
            Logic = {
                try {
        
                    $meetingPolicyConfig = Get-CsTeamsMeetingPolicy -Identity Global | Select-Object AllowAnonymousUsersToJoinMeeting
                    Write-Host ""
                    $meetingPolicyConfig | Format-List
        
                    Write-Host ""
                    Write-Host ""
        
                    if ($meetingPolicyConfig.AllowAnonymousUsersToJoinMeeting -eq $false) {
                        Write-Host "PASS: AllowAnonymousUsersToJoinMeeting is set to False." -ForegroundColor Green
                        Add-Finding -CheckId $script.CheckId `
                                -Asset "/tenants/$tenantid/teams/meeting-policy" `
                                -Status "PASS" `
                                -Name "Teams Meeting Policy" `
                                -Description "AllowAnonymousUsersToJoinMeeting is set to False." `
                                -Remediation "Disable AllowAnonymousUsersToJoinMeeting by setting it to False." `
                                -Details @{ "Message" = "AllowAnonymousUsersToJoinMeeting is set to False." } `
                                -Risk "Medium" `
                                -Impact "Moderate" `
                                -Likelihood "Moderate"
                    } else {
                        Write-Host "FAIL: AllowAnonymousUsersToJoinMeeting is set to True." -ForegroundColor Red
                        Add-Finding -CheckId $script.CheckId `
                                -Asset "/tenants/$tenantid/teams/meeting-policy" `
                                -Status "FAIL" `
                                -Name "Teams Meeting Policy" `
                                -Description "AllowAnonymousUsersToJoinMeeting is set to True." `
                                -Remediation "Disable AllowAnonymousUsersToJoinMeeting by setting it to False." `
                                -Details @{ "Message" = "AllowAnonymousUsersToJoinMeeting is set to True." } `
                                -Risk "Medium" `
                                -Impact "Moderate" `
                                -Likelihood "Moderate"
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
            CheckId = "8.5.2"
            Logic = {
                try {
        
                    $meetingPolicyConfig = Get-CsTeamsMeetingPolicy -Identity Global | Select-Object AllowAnonymousUsersToStartMeeting
                    Write-Host ""
                    $meetingPolicyConfig | Format-List
        
                    Write-Host ""
                    Write-Host ""
        
                    if ($meetingPolicyConfig.AllowAnonymousUsersToStartMeeting -eq $false) {
                        Write-Host "PASS: AllowAnonymousUsersToStartMeeting is set to False." -ForegroundColor Green
                        Add-Finding -CheckId $script.CheckId `
                                -Asset "/tenants/$tenantid/teams/meeting-policy" `
                                -Status "PASS" `
                                -Name "Teams Meeting Policy" `
                                -Description "AllowAnonymousUsersToStartMeeting is set to False." `
                                -Remediation "Disable AllowAnonymousUsersToStartMeeting by setting it to False." `
                                -Details @{ "Message" = "AllowAnonymousUsersToStartMeeting is set to False." } `
                                -Risk "Medium" `
                                -Impact "Moderate" `
                                -Likelihood "Moderate"
                    } else {
                        Write-Host "FAIL: AllowAnonymousUsersToStartMeeting is set to True." -ForegroundColor Red
                        Add-Finding -CheckId $script.CheckId `
                                -Asset "/tenants/$tenantid/teams/meeting-policy" `
                                -Status "FAIL" `
                                -Name "Teams Meeting Policy" `
                                -Description "AllowAnonymousUsersToStartMeeting is set to True." `
                                -Remediation "Disable AllowAnonymousUsersToStartMeeting by setting it to False." `
                                -Details @{ "Message" = "AllowAnonymousUsersToStartMeeting is set to True." } `
                                -Risk "Medium" `
                                -Impact "Moderate" `
                                -Likelihood "Moderate"
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
            CheckId = "8.5.3"
            Logic = {
                try {
        
                    $meetingPolicyConfig = Get-CsTeamsMeetingPolicy -Identity Global | Select-Object AutoAdmittedUsers
                    Write-Host ""
                    $meetingPolicyConfig | Format-List
        
                    Write-Host ""
                    Write-Host ""
        
                    if ($meetingPolicyConfig.AutoAdmittedUsers -eq "EveryoneInCompanyExcludingGuests") {
                        Write-Host "PASS: AutoAdmittedUsers is set to EveryoneInCompanyExcludingGuests." -ForegroundColor Green
                        Add-Finding -CheckId $script.CheckId `
                                -Asset "/tenants/$tenantid/teams/meeting-policy" `
                                -Status "PASS" `
                                -Name "Teams Meeting Policy" `
                                -Description "AutoAdmittedUsers is set to EveryoneInCompanyExcludingGuests." `
                                -Remediation "Set AutoAdmittedUsers to EveryoneInCompanyExcludingGuests in the Teams Meeting Policy." `
                                -Details @{ "Message" = "AutoAdmittedUsers is set to EveryoneInCompanyExcludingGuests." } `
                                -Risk "Medium" `
                                -Impact "Moderate" `
                                -Likelihood "Moderate"
                    } else {
                        Write-Host "FAIL: AutoAdmittedUsers is not set to EveryoneInCompanyExcludingGuests." -ForegroundColor Red
                        Add-Finding -CheckId $script.CheckId `
                                -Asset "/tenants/$tenantid/teams/meeting-policy" `
                                -Status "FAIL" `
                                -Name "Teams Meeting Policy" `
                                -Description "AutoAdmittedUsers is not set to EveryoneInCompanyExcludingGuests." `
                                -Remediation "Set AutoAdmittedUsers to EveryoneInCompanyExcludingGuests in the Teams Meeting Policy." `
                                -Details @{ "Message" = "AutoAdmittedUsers is not set to EveryoneInCompanyExcludingGuests." } `
                                -Risk "Medium" `
                                -Impact "Moderate" `
                                -Likelihood "Moderate"
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
            CheckId = "8.5.4"
            Logic = {
                try {
        
                    $meetingPolicyConfig = Get-CsTeamsMeetingPolicy -Identity Global | Select-Object AllowPSTNUsersToBypassLobby
                    Write-Host ""
                    $meetingPolicyConfig | Format-List
        
                    Write-Host ""
                    Write-Host ""
        
                    if ($meetingPolicyConfig.AllowPSTNUsersToBypassLobby -eq $false) {
                        Write-Host "PASS: AllowPSTNUsersToBypassLobby is set to False." -ForegroundColor Green
                        Add-Finding -CheckId $script.CheckId `
                                -Asset "/tenants/$tenantid/teams/meeting-policy" `
                                -Status "PASS" `
                                -Name "Teams Meeting Policy" `
                                -Description "AllowPSTNUsersToBypassLobby is set to False." `
                                -Remediation "Set AllowPSTNUsersToBypassLobby to False in the Teams Meeting Policy." `
                                -Details @{ "Message" = "AllowPSTNUsersToBypassLobby is set to False." } `
                                -Risk "Medium" `
                                -Impact "Moderate" `
                                -Likelihood "Moderate"
                    } else {
                        Write-Host "FAIL: AllowPSTNUsersToBypassLobby is set to True." -ForegroundColor Red
                        Add-Finding -CheckId $script.CheckId `
                                -Asset "/tenants/$tenantid/teams/meeting-policy" `
                                -Status "FAIL" `
                                -Name "Teams Meeting Policy" `
                                -Description "AllowPSTNUsersToBypassLobby is set to True." `
                                -Remediation "Set AllowPSTNUsersToBypassLobby to False in the Teams Meeting Policy." `
                                -Details @{ "Message" = "AllowPSTNUsersToBypassLobby is set to True." } `
                                -Risk "Medium" `
                                -Impact "Moderate" `
                                -Likelihood "Moderate"
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
            CheckId = "8.5.5"
            Logic = {
                try {
        
                    $meetingPolicyConfig = Get-CsTeamsMeetingPolicy -Identity Global | Select-Object MeetingChatEnabledType
                    Write-Host ""
                    $meetingPolicyConfig | Format-List
        
                    Write-Host ""
                    Write-Host ""
        
                    if ($meetingPolicyConfig.MeetingChatEnabledType -eq "EnabledExceptAnonymous") {
                        Write-Host "PASS: MeetingChatEnabledType is set to EnabledExceptAnonymous." -ForegroundColor Green
                        Add-Finding -CheckId $script.CheckId `
                                -Asset "/tenants/$tenantid/teams/meeting-policy" `
                                -Status "PASS" `
                                -Name "Teams Meeting Policy" `
                                -Description "MeetingChatEnabledType is set to EnabledExceptAnonymous." `
                                -Remediation "Set MeetingChatEnabledType to EnabledExceptAnonymous in the Teams Meeting Policy." `
                                -Details @{ "Message" = "MeetingChatEnabledType is set to EnabledExceptAnonymous." } `
                                -Risk "Medium" `
                                -Impact "Moderate" `
                                -Likelihood "Moderate"
                    } else {
                        Write-Host "FAIL: MeetingChatEnabledType is not set to EnabledExceptAnonymous." -ForegroundColor Red
                        Add-Finding -CheckId $script.CheckId `
                                -Asset "/tenants/$tenantid/teams/meeting-policy" `
                                -Status "FAIL" `
                                -Name "Teams Meeting Policy" `
                                -Description "MeetingChatEnabledType is not set to EnabledExceptAnonymous." `
                                -Remediation "Set MeetingChatEnabledType to EnabledExceptAnonymous in the Teams Meeting Policy." `
                                -Details @{ "Message" = "MeetingChatEnabledType is not set to EnabledExceptAnonymous." } `
                                -Risk "Medium" `
                                -Impact "Moderate" `
                                -Likelihood "Moderate"
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
            CheckId = "8.5.6"
            Logic = {
                try {
                    $meetingPolicyConfig = Get-CsTeamsMeetingPolicy -Identity Global | Select-Object DesignatedPresenterRoleMode
                    Write-Host ""
                    $meetingPolicyConfig | Format-List

                    Write-Host ""
                    Write-Host ""

                    if ($meetingPolicyConfig.DesignatedPresenterRoleMode -eq "OrganizerOnlyUserOverride") {
                        Write-Host "PASS: DesignatedPresenterRoleMode is set to OrganizerOnlyUserOverride." -ForegroundColor Green
                        
                        if ($Global:JsonOutputMode) {
                Add-Finding -CheckId $script.CheckId `
                                    -Asset "/tenants/$tenantid/teams/meeting-policy" `
                                    -Status "PASS" `
                                    -Name "Teams Presenter Settings Check" `
                                    -Description "Presenter role in Teams meetings is properly restricted to organizer-only by default." `
                                    -Remediation "Set DesignatedPresenterRoleMode to OrganizerOnlyUserOverride in the Teams Meeting Policy." `
                                    -Details @{ "DesignatedPresenterRoleMode" = $meetingPolicyConfig.DesignatedPresenterRoleMode }
                        }
                    } else {
                        Write-Host "FAIL: Expected value - OrganizerOnlyUserOverride." -ForegroundColor Red
                        
                        if ($Global:JsonOutputMode) {
                            Add-Finding -CheckId $script.CheckId `
                                    -Asset "/tenants/$tenantid/teams/meeting-policy" `
                                    -Status "FAIL" `
                                    -Name "Teams Presenter Settings Check" `
                                    -Description "Presenter role in Teams meetings is not properly restricted." `
                                    -Remediation "Set DesignatedPresenterRoleMode to OrganizerOnlyUserOverride in the Teams Meeting Policy." `
                        -Details @{ 
                                        "DesignatedPresenterRoleMode" = $meetingPolicyConfig.DesignatedPresenterRoleMode
                                        "ExpectedValue" = "OrganizerOnlyUserOverride"
                        } `
                        -Impact "Moderate" `
                        -Likelihood "Moderate" `
                                    -Risk "Medium"
                        }
                    }
                } catch {
                    Write-Host "Error retrieving Teams Meeting Policy Configuration." -ForegroundColor Red
                    Write-Host $_.Exception.Message
                    
                    if ($Global:JsonOutputMode) {
                        Add-Finding -CheckId $script.CheckId `
                                -Asset "/tenants/$tenantid/teams/meeting-policy" `
                            -Status "ERROR" `
                                -Name "Teams Presenter Settings Check" `
                                -Description "Error occurred while checking Teams Meeting Policy for presenter settings." `
                            -Details @{ "ErrorMessage" = $_.Exception.Message } `
                                -Impact "Minor" `
                                -Likelihood "Low" `
                                -Risk "Low"
                    }
                }
            }
        },
        @{
            Name = "8.5.7 External Participant Give Control in Teams Meetings"
            Type = "Script"
            CheckId = "8.5.7"
            Logic = {
                try {
                    $meetingPolicyConfig = Get-CsTeamsMeetingPolicy -Identity Global | Select-Object AllowExternalParticipantGiveRequestControl
                    Write-Host ""
                    $meetingPolicyConfig | Format-List

                    Write-Host ""
                    Write-Host ""

                    if ($meetingPolicyConfig.AllowExternalParticipantGiveRequestControl -eq $false) {
                        Write-Host "PASS: AllowExternalParticipantGiveRequestControl is set to False." -ForegroundColor Green
                        
                        if ($Global:JsonOutputMode) {
                            Add-Finding -CheckId $script.CheckId `
                                    -Asset "/tenants/$tenantid/teams/meeting-policy" `
                                    -Status "PASS" `
                                    -Name "External Participant Control in Teams Meetings Check" `
                                    -Description "External participants cannot give or request control in Teams meetings as recommended." `
                                    -Details @{ "AllowExternalParticipantGiveRequestControl" = $meetingPolicyConfig.AllowExternalParticipantGiveRequestControl }
                        }
                    } else {
                        Write-Host "FAIL: AllowExternalParticipantGiveRequestControl is not set to False." -ForegroundColor Red
                                            if ($Global:JsonOutputMode) {
                            Add-Finding -CheckId $script.CheckId `
                                    -Asset "/tenants/$tenantid/policies/authorization/guest-access" `
                                    -Asset "/tenants/$tenantid/teams/meeting-policy" `
                                    -Name "Guest User Access Check" `
                                    -Description "External participants can give or request control in Teams meetings, creating security risks." `
                                    -Remediation "Set AllowExternalParticipantGiveRequestControl to False in the Teams Meeting Policy." `
                                    -Details @{ "AllowExternalParticipantGiveRequestControl" = $meetingPolicyConfig.AllowExternalParticipantGiveRequestControl } `
                            -Impact "Moderate" `
                                    -Likelihood "Moderate" `
                                    -Risk "Medium"
                        }
                    }
                } catch {
                    Write-Host "Error retrieving Teams Meeting Policy Configuration." -ForegroundColor Red
                    Write-Host $_.Exception.Message
                        
                        if ($Global:JsonOutputMode) {
                            Add-Finding -CheckId $script.CheckId `
                                -Asset "/tenants/$tenantid/teams/meeting-policy" `
                                -Status "ERROR" `
                                -Name "External Participant Control in Teams Meetings Check" `
                                -Description "Error occurred while checking Teams Meeting Policy for external participant control settings." `
                                -Details @{ "ErrorMessage" = $_.Exception.Message } `
                                -Impact "Minor" `
                                -Likelihood "Low" `
                                -Risk "Low"
                    }
                }
            }
        },
        @{
            Name = "8.5.8 External Non-Trusted Meeting Chat in Teams Meetings"
            Type = "Script"
            CheckId = "8.5.8"
            Logic = {
                try {
                    $meetingPolicyConfig = Get-CsTeamsMeetingPolicy -Identity Global | Select-Object AllowExternalNonTrustedMeetingChat
                    Write-Host ""
                    $meetingPolicyConfig | Format-List

                    Write-Host ""
                    Write-Host ""

                    if ($meetingPolicyConfig.AllowExternalNonTrustedMeetingChat -eq $false) {
                        Write-Host "PASS: AllowExternalNonTrustedMeetingChat is set to False." -ForegroundColor Green
                        
                        if ($Global:JsonOutputMode) {
                            Add-Finding -CheckId $script.CheckId `
                                    -Asset "/tenants/$tenantid/teams/meeting-policy" `
                                    -Status "PASS" `
                                    -Name "External Non-Trusted Meeting Chat Check" `
                                    -Description "External non-trusted participants cannot use meeting chat as recommended." `
                                    -Remediation "Set AllowExternalNonTrustedMeetingChat to False in the Teams Meeting Policy." `
                                    -Details @{ "AllowExternalNonTrustedMeetingChat" = $meetingPolicyConfig.AllowExternalNonTrustedMeetingChat }
                                    -Impact "Moderate" `
                                    -Likelihood "Moderate" `
                                    -Risk "Medium"
                        }
                    } else {
                        Write-Host "FAIL: AllowExternalNonTrustedMeetingChat is not set to False." -ForegroundColor Red
                        
                        if ($Global:JsonOutputMode) {
                            Add-Finding -CheckId $script.CheckId `
                                    -Asset "/tenants/$tenantid/teams/meeting-policy" `
                                    -Status "FAIL" `
                                    -Name "External Non-Trusted Meeting Chat Check" `
                                    -Description "External non-trusted participants can use meeting chat, creating security risks." `
                                    -Remediation "Set AllowExternalNonTrustedMeetingChat to False in the Teams Meeting Policy." `
                                    -Details @{ "AllowExternalNonTrustedMeetingChat" = $meetingPolicyConfig.AllowExternalNonTrustedMeetingChat } `
                                    -Impact "Moderate" `
                                    -Likelihood "Moderate" `
                                    -Risk "Medium"
                        }
                    }
                } catch {
                    Write-Host "Error retrieving Teams Meeting Policy Configuration." -ForegroundColor Red
                    Write-Host $_.Exception.Message
                    
                    if ($Global:JsonOutputMode) {
                        Add-Finding -CheckId $script.CheckId `
                                -Asset "/tenants/$tenantid/teams/meeting-policy" `
                                -Status "ERROR" `
                                -Name "External Non-Trusted Meeting Chat Check" `
                                -Description "Error occurred while checking Teams Meeting Policy for external non-trusted meeting chat setting." `
                                -Details @{ "ErrorMessage" = $_.Exception.Message } `
                                -Impact "Minor" `
                                -Likelihood "Low" `
                                -Risk "Low"
                    }
                }
            }
        },
        @{
            Name = "8.5.9 Allow Cloud Recording in Teams Meetings"
            Type = "Script"
            CheckId = "8.5.9"
            Logic = {
                try {
                    $meetingPolicyConfig = Get-CsTeamsMeetingPolicy -Identity Global | Select-Object AllowCloudRecording
                    Write-Host ""
                    $meetingPolicyConfig | Format-List

                    Write-Host ""
                    Write-Host ""

                    if ($meetingPolicyConfig.AllowCloudRecording -eq $false) {
                        Write-Host "PASS: AllowCloudRecording is set to False." -ForegroundColor Green
                        
                        if ($Global:JsonOutputMode) {
                            Add-Finding -CheckId $script.CheckId `
                                    -Asset "/tenants/$tenantid/teams/meeting-policy" `
                                    -Status "PASS" `
                                    -Name "Cloud Recording in Teams Meetings Check" `
                                    -Description "Cloud recording in Teams meetings is disabled as recommended." `
                                    -Details @{ "AllowCloudRecording" = $meetingPolicyConfig.AllowCloudRecording }
                        }
                    } else {
                        Write-Host "FAIL: AllowCloudRecording is not set to False." -ForegroundColor Red
                        
                        if ($Global:JsonOutputMode) {
                            Add-Finding -CheckId $script.CheckId `
                                    -Asset "/tenants/$tenantid/teams/meeting-policy" `
                                    -Status "FAIL" `
                                    -Name "Cloud Recording in Teams Meetings Check" `
                                    -Description "Cloud recording in Teams meetings is enabled, creating potential data security and privacy risks." `
                                    -Remediation "Set AllowCloudRecording to False in the Teams Meeting Policy." `
                                    -Details @{ "AllowCloudRecording" = $meetingPolicyConfig.AllowCloudRecording } `
                                    -Impact "Moderate" `
                                    -Likelihood "Moderate" `
                                    -Risk "Medium"
                        }
                    }
                } catch {
                    Write-Host "Error retrieving Teams Meeting Policy Configuration." -ForegroundColor Red
                    Write-Host $_.Exception.Message
                    
                    if ($Global:JsonOutputMode) {
                        Add-Finding -CheckId $script.CheckId `
                                -Asset "/tenants/$tenantid/teams/meeting-policy" `
                                -Status "ERROR" `
                                -Name "Cloud Recording in Teams Meetings Check" `
                                -Description "Error occurred while checking Teams Meeting Policy for cloud recording setting." `
                                -Details @{ "ErrorMessage" = $_.Exception.Message } `
                                -Impact "Minor" `
                                -Likelihood "Low" `
                                -Risk "Low"
                    }
                }
            }
        },
        @{
            Name = "8.6.1 Teams and Defender Reporting Policies"
            Type = "Script"
            CheckId = "8.6.1"
            Logic = {
                try {
                    Disconnect-ExchangeOnline -Confirm:$false -ErrorAction SilentlyContinue
                    Connect-ExchangeOnline -CertificateThumbprint "$Thumbprint" -AppId "$AppId" -Organization "$Domain" -ShowBanner:$false
                    Start-Sleep 1
                    $orgDomains = (Get-MgOrganization).VerifiedDomains | ForEach-Object { $_.Name }
                    $orgDomainsRegex = $orgDomains -join "|"
        
                    # Check Teams Messaging Policy
                    Write-Host "Checking Teams Messaging Policy..." -ForegroundColor Cyan
                    $teamsMessagingPolicy = Get-CsTeamsMessagingPolicy -Identity Global | Select-Object AllowSecurityEndUserReporting
                    $teamsMessagingPolicy | Format-List
        
                    Write-Host ""
                    Write-Host ""
        
                    $teamsReportingPass = $teamsMessagingPolicy.AllowSecurityEndUserReporting -eq $true
                    if ($teamsReportingPass) {
                        Write-Host "PASS: AllowSecurityEndUserReporting is set to True." -ForegroundColor Green
                    } else {
                        Write-Host "FAIL: AllowSecurityEndUserReporting is not set to True." -ForegroundColor Red
                    }
        
                    # Check Defender Report Submission Policy
                    Write-Host "Checking Defender Report Submission Policy..." -ForegroundColor Cyan
                    $defenderPolicy = Get-ReportSubmissionPolicy | Select-Object ReportJunkToCustomizedAddress, ReportNotJunkToCustomizedAddress, ReportPhishToCustomizedAddress, ReportJunkAddresses, ReportNotJunkAddresses, ReportPhishAddresses, ReportChatMessageEnabled, ReportChatMessageToCustomizedAddressEnabled
                    $defenderPolicy | Format-List
        
                    Write-Host ""
                    Write-Host ""
        
                    $expectedValues = @{
                        ReportJunkToCustomizedAddress = $true
                        ReportNotJunkToCustomizedAddress = $true
                        ReportPhishToCustomizedAddress = $true
                        ReportChatMessageEnabled = $false
                        ReportChatMessageToCustomizedAddressEnabled = $true
                    }
        
                    $misconfigurations = $false
                    $issueDetails = @{}
        
                    # Check email addresses
                    foreach ($key in @("ReportJunkAddresses", "ReportNotJunkAddresses", "ReportPhishAddresses")) {
                        $values = $defenderPolicy.$key
                        $issueDetails[$key] = $values
                        
                        if ($values -and $values -notcontains $null) {
                            foreach ($email in $values) {
                                if (-not $email -match "@($orgDomainsRegex)$") {
                                    Write-Host "$key contains unauthorized email: $email > Desired: Email ending with any of $($orgDomains -join ', ')" -ForegroundColor Red
                                    $misconfigurations = $true
                                    $issueDetails["${key}_Unauthorized"] = $true
                                }
                            }
                        } else {
                            Write-Host "$key is empty or null > Desired: At least one email ending with any of $($orgDomains -join ', ')" -ForegroundColor Red
                            $misconfigurations = $true
                            $issueDetails["${key}_Missing"] = $true
                        }
                    }
        
                    # Check policy settings
                    foreach ($key in $expectedValues.Keys) {
                        $issueDetails[$key] = $defenderPolicy.$key
                        
                        if ($key -notin @("ReportJunkAddresses", "ReportNotJunkAddresses", "ReportPhishAddresses")) {
                            if ($defenderPolicy.$key -ne $expectedValues[$key]) {
                                Write-Host "${key}: $($defenderPolicy.$key) > Desired: $($expectedValues[$key])" -ForegroundColor Red
                                $misconfigurations = $true
                                $issueDetails["${key}_WrongValue"] = $true
                            }
                        }
                    }
        
                    Write-Host ""
                    Write-Host ""
        
                    $defenderReportingPass = (-not $misconfigurations)
                    if ($defenderReportingPass) {
                        Write-Host "PASS: Defender Report Submission Policy matches expected configuration." -ForegroundColor Green
                    } else {
                        Write-Host "FAIL: Defender Report Submission Policy has misconfigurations." -ForegroundColor Red
                    }
                    
                    # Add findings to JSON output
                        if ($Global:JsonOutputMode) {
                        # Teams Messaging Policy finding
                        if ($teamsReportingPass) {
                            Add-Finding -CheckId "$($script.CheckId).1" `
                                    -Asset "/tenants/$tenantid/teams/messaging-policy" `
                                    -Status "PASS" `
                                    -Name "Teams Security End User Reporting Check" `
                                    -Description "Teams Security End User Reporting should be enabled for secure communication" `
                                    -Details @{ "AllowSecurityEndUserReporting" = $teamsMessagingPolicy.AllowSecurityEndUserReporting } `
                                    -Impact "Moderate" `
                                    -Likelihood "Moderate" `
                                    -Risk "Medium"
                        } else {
                            Add-Finding -CheckId "$($script.CheckId).1" `
                                    -Asset "/tenants/$tenantid/teams/messaging-policy" `
                                    -Status "FAIL" `
                                    -Name "Teams Security End User Reporting Check" `
                                    -Description "Teams Security End User Reporting should be enabled for secure communication" `
                                    -Remediation "Enable 'AllowSecurityEndUserReporting' in the Teams Messaging Policy" `
                                    -Details @{ "AllowSecurityEndUserReporting" = $teamsMessagingPolicy.AllowSecurityEndUserReporting } `
                                    -Impact "Moderate" `
                                    -Likelihood "Moderate" `
                                    -Risk "Medium"
                        }
                        
                        # Defender Report Submission Policy finding
                        if ($defenderReportingPass) {
                            Add-Finding -CheckId "$($script.CheckId).2" `
                                    -Asset "/tenants/$tenantid/defender/report-submission-policy" `
                                    -Status "PASS" `
                                    -Name "Defender Report Submission Policy Check" `
                                    -Description "Defender Report Submission Policy should be configured for secure communication" `
                                    -Details @{ 
                                        "Policy" = $defenderPolicy
                                        "OrgDomains" = $orgDomains
                                        "ExpectedValues" = $expectedValues
                                    } `
                                    -Impact "Moderate" `
                                    -Likelihood "Moderate" `
                                    -Risk "Medium"
                        } else {
                            Add-Finding -CheckId "$($script.CheckId).2" `
                                    -Asset "/tenants/$tenantid/defender/report-submission-policy" `
                                    -Status "FAIL" `
                                    -Name "Defender Report Submission Policy Check" `
                                    -Description "Defender Report Submission Policy should be configured for secure communication" `
                                    -Remediation "Configure the Defender Report Submission Policy according to the recommended settings. Ensure report addresses use organization domains." `
                                    -Details @{ 
                                        "Policy" = $defenderPolicy
                                        "OrgDomains" = $orgDomains
                                        "ExpectedValues" = $expectedValues
                                        "Issues" = $issueDetails
                                    } `
                                    -Impact "Moderate" `
                                    -Likelihood "Moderate" `
                                    -Risk "Medium"
                        }
                    }
                } catch {
                    Write-Host "Error retrieving policy configurations." -ForegroundColor Red
                    Write-Host $_.Exception.Message
                    if ($Global:JsonOutputMode) {
                Add-Finding -CheckId $script.CheckId `
                        -Asset "/tenants/$tenantid" `
                                    -Status "ERROR" `
                                    -Name "Teams and Defender Reporting Policies Check" `
                                    -Description "Teams and Defender Reporting Policies should be configured for secure communication" `
                                    -Remediation "Configure the Teams and Defender Reporting Policies according to the recommended settings" `
                                    -Details @{ "ErrorMessage" = $_.Exception.Message } `
                                    -Impact "Minor" `
                                    -Likelihood "Low" `
                                    -Risk "Low"
                    }
                }
            }
        }
    )

    # Execute each script based on service availability
    foreach ($script in $scripts) {
        Write-Host "=============================================================" -ForegroundColor Yellow
        Write-Host "Running: $($script.Name)" -ForegroundColor Cyan
        Write-Host "=============================================================" -ForegroundColor Yellow

        # Skip Exchange-dependent scripts if Exchange is not available
        if ($script.RequiresExchange -and -not $Global:ExchangeAvailable) {
            Write-Host "Skipping Exchange-dependent check (Exchange not available on this platform)" -ForegroundColor Yellow
            continue
        }

        if ($script.Type -eq "Script") {
            try {
                & $script.Logic
                Start-Sleep -Seconds 1
                                    } catch {
                Write-Host "Error running script: $($script.Name)" -ForegroundColor Red
                Write-Host $_.Exception.Message
            }
        } elseif ($script.Type -eq "Manual") {
            Write-Host "Manual check required for $($script.Name)" -ForegroundColor Yellow

            $link = if ($script.Link -is [scriptblock]) {
                & $script.Link
                        Write-Host "Fail: No users found or unable to determine MFA state." -ForegroundColor Red
            }

            Write-Host "Please visit: $link" -ForegroundColor Blue

            if ($script.Explanation) {
                Write-Host "`nExplanation:" -ForegroundColor Magenta
                foreach ($line in $script.Explanation) {
                    Write-Host "$line" -ForegroundColor Cyan
                }
            }
            
            Start-Sleep -Seconds 1
        }
        Write-Host "`n"
    }

    # Export results to JSON file
    $jsonOutput = "[$($jsonResults | ConvertTo-Json -Depth 10)]"
    New-Item -Path (Split-Path -Parent $jsonOutputFile) -ItemType Directory -Force -ErrorAction SilentlyContinue | Out-Null
    Set-Content -Path $jsonOutputFile -Value $jsonOutput
    Write-Host "JSON Report generated: $jsonOutputFile" -ForegroundColor Green

    Stop-Transcript
}

#
# 2) Generate HTML if requested (or if html-only)
#
if ($outputFormat -eq "all" -or $outputFormat -eq "html") {
    # read in the transcript we already have
    $logContent = Get-Content $transcriptFile

    # compute summary counts
    $passCount   = ($logContent | Select-String 'PASS:'           ).Count
    $failCount   = ($logContent | Select-String 'FAIL:'           ).Count
    $manualCount = ($logContent | Select-String 'manual check required' -CaseSensitive:$false).Count

    $htmlFile = "$PSScriptRoot\script_output.html"

    # build the Bootstrap + Chart.js HTML
    $htmlContent = @"
<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>Microsoft 365 Results</title>
  <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.2/dist/css/bootstrap.min.css" rel="stylesheet">
  <link href="https://fonts.googleapis.com/css2?family=Fira+Code&display=swap" rel="stylesheet">
  <script src="https://cdn.jsdelivr.net/npm/chart.js"></script>
  <script src="https://cdn.jsdelivr.net/npm/ansi_up@5.0.0/ansi_up.min.js"></script>
  <style>
    body { font-family: 'Fira Code', monospace; background-color:rgb(3, 17, 46); color: #8488aa; }
    pre  { background: #23252e; color: #fff; border-radius:4px; padding:1em; }
    summary::-webkit-details-marker { display: none; }
    .details-summary { cursor: pointer; font-weight: bold; }
    .details-summary.pass   { color: #198754; }
    .details-summary.fail   { color: #dc3545; }
    .details-summary.manual { color: #fd7e14; }
    .details-summary.review { color: #ffc107; }
    .badge.pass   { background-color: #198754; }
    .badge.fail   { background-color: #dc3545; }
    .badge.manual { background-color: #fd7e14; }
  </style>
</head>
<body class="container py-4">
  <header class="mb-4">
    <h1 class="display-5 fw-bold">Microsoft 365 Report</h1>
    <p class="lead"></p>
  </header>

  <section class="row align-items-center mb-5">
    <div class="col-md-6">
      <canvas id="statusChart" width="300" height="300"></canvas>
    </div>
    <div class="col-md-6">
        <ul class="list-group">
            <li class="list-group-item d-flex justify-content-between" onclick="filterStatus('all')" style="cursor:pointer">
                <span>Show All</span><span class="fw-bold"> </span>
            </li>
            <li class="list-group-item d-flex justify-content-between" onclick="filterStatus('pass')" style="cursor:pointer">
                <span><span class="badge pass">PASS</span> Passed</span><span class="fw-bold">$passCount</span>
            </li>
            <li class="list-group-item d-flex justify-content-between" onclick="filterStatus('fail')" style="cursor:pointer">
                <span><span class="badge fail">FAIL</span> Failed</span><span class="fw-bold">$failCount</span>
            </li>
            <li class="list-group-item d-flex justify-content-between" onclick="filterStatus('manual')" style="cursor:pointer">
                <span><span class="badge manual">MANUAL</span> Manual</span><span class="fw-bold">$manualCount</span>
            </li>
        </ul>
    </div>
  </section>
"@

    # render each detail as a Bootstrap card
    $currentFunction = ""
    $outputBuffer    = @()
    $reasoning       = ""
    $status          = "review"

    foreach ($line in $logContent) {
        if ($line -match "Running: (.+)") {
            if ($currentFunction) {
                $cls = if ($status -eq "fail")   { "fail" }
                    elseif ($status -eq "pass") { "pass" }
                    elseif ($status -eq "manual") { "manual" }
                    else { "review" }

                $htmlContent += @"
    <div class="card shadow-sm mb-3" data-status="$cls">
        <div class="card-body p-3">
        <details>
            <summary class="$cls details-summary">
            $currentFunction - $status
            <span class="badge $cls"></span>
            </summary>
            <pre>$($outputBuffer -join "`n")</pre>
        </details>
        </div>
    </div>
"@
        }
        # reset for next block
        $currentFunction = $matches[1]
        $outputBuffer    = @()
        $status          = "review"
    }
    elseif ($line -match "PASS:(.+)" -or $line -match "(?i)^pass$") {
        $outputBuffer += "<span class='pass'>$($line.Trim())</span>"
        $status       = "pass"
    }
    elseif ($line -match "FAIL:(.+)" -or $line -match "(?i)^fail$") {
        $outputBuffer += "<span class='fail'>$($line.Trim())</span>"
        $status       = "fail"
    }
    elseif ($line -match "(?i)manual check required") {
        $outputBuffer += "<span class='manual'>$($line.Trim())</span>"
        $status       = "manual"
    }
    else {
        $outputBuffer += $line.Trim()
    }
}

    # flush last block
   if ($currentFunction) {
    $cls = if ($status -eq "fail")   { "fail" }
           elseif ($status -eq "pass") { "pass" }
           elseif ($status -eq "manual") { "manual" }
           else { "review" }

        $htmlContent += @"
    <div class="card shadow-sm mb-3" data-status="$cls">
        <div class="card-body p-3">
        <details>
            <summary class="$cls details-summary">
            $currentFunction - $status
            <span class="badge $cls"></span>
            </summary>
            <pre>$($outputBuffer -join "`n")</pre>
        </details>
        </div>
    </div>
"@
}
    $htmlContent += @"
    <script>
        function filterStatus(status) {
        document.querySelectorAll('.card[data-status]').forEach(card => {
            card.style.display = (status==='all' || card.dataset.status===status) ? '' : 'none';
        });
        }
        document.querySelectorAll('[onclick^=""filterStatus""]').forEach(li => {
        li.addEventListener('click', () => {
            document.querySelectorAll('.list-group-item').forEach(i => i.classList.remove('active'));
            li.classList.add('active');
        });
        });
    </script>

    <script>
        const ctx = document.getElementById('statusChart').getContext('2d');
        new Chart(ctx, {
            type: 'doughnut',
            data: {
            labels: ['PASS','FAIL','MANUAL'],
            datasets: [{
                data: [$passCount, $failCount, $manualCount],
                backgroundColor: ['#198754','#dc3545','#fd7e14'],
                borderWidth: 1
            }]
            },
            options: {
            plugins: { legend: { position: 'bottom' } }
            }
        });
        
    </script>
    <script>
    document.querySelectorAll('pre').forEach(pre => {
      const ansi_up = new AnsiUp();
      // take the raw text (with \x1b[31m etc) and turn it into styled HTML
      pre.innerHTML = ansi_up.ansi_to_html(pre.textContent);
    });
  </script>
</body>
</html>
"@


    # write out the HTML
    Set-Content -Path $htmlFile -Value $htmlContent -Encoding UTF8
    Write-Host "HTML Report generated: $htmlFile" -ForegroundColor Green
}
