param(
    [string]$OutputPath = "."
)

#==============================#
#  MODULE MANAGEMENT
#==============================#

function Ensure-Module {
    param([string]$Name)

    if (-not (Get-Module -ListAvailable -Name $Name)) {
        Write-Host "Module $Name not found. Installing..." -ForegroundColor Yellow
        Install-Module $Name -Scope CurrentUser -Force
    }

    Import-Module $Name -Force
}

Write-Host "=== Checking Required Modules ===" -ForegroundColor Cyan
Ensure-Module -Name "ExchangeOnlineManagement"
Ensure-Module -Name "ImportExcel"

#==============================#
# CONNECT TO PURVIEW/SCC
#==============================#

Write-Host "=== Connecting to Compliance PowerShell ===" -ForegroundColor Cyan

if (-not (Get-PSSession | Where-Object {
        $_.ConfigurationName -eq "Microsoft.Exchange" -and
        $_.ComputerName -like "*.protection.outlook.com"
    })) {

    Connect-IPPSSession -WarningAction SilentlyContinue
}
else {
    Write-Host "Reusing existing Purview PowerShell session." -ForegroundColor Yellow
}

#==============================#
# CREATE OUTPUT PATH
#==============================#

if (-not (Test-Path $OutputPath)) {
    New-Item -ItemType Directory -Path $OutputPath | Out-Null
}

#==============================#
# HELPER: FORMAT LOCATIONS
#==============================#

function Format-Loc {
    param($val)
    if ($null -eq $val) { return $null }
    if ($val -eq "All") { return "All" }
    return ($val -join ";")
}

#==============================#
# HELPER: SIT SUMMARY FROM CLASSIC OBJECT
#==============================#

function Get-SITSummaryFromObject {
    param($obj)

    if (-not $obj) { return $null }

    $result = @()

    foreach ($condition in $obj) {
        $condOp = $condition.Operator

        # Newer-style: groups + sensitivetypes/SensitiveInformation
        if ($condition.PSObject.Properties.Name -contains "groups" -and $condition.groups) {
            foreach ($group in $condition.groups) {
                $groupOp = $group.operator
                $sitStrings = @()

                $sitSource = $null
                if ($group.PSObject.Properties.Name -contains "sensitivetypes") {
                    $sitSource = $group.sensitivetypes
                }
                elseif ($group.PSObject.Properties.Name -contains "SensitiveInformation") {
                    $sitSource = $group.SensitiveInformation
                }

                if ($sitSource) {
                    foreach ($sit in $sitSource) {
                        $sitName  = $sit.Name
                        $minCount = $sit.minCount
                        if (-not $minCount) { $minCount = $sit.MinCount }
                        $minConf  = $sit.minConfidence
                        if (-not $minConf) { $minConf = $sit.MinConfidence }

                        $sitStrings += ("{0} (MinCount={1}, MinConfidence={2})" -f `
                                        $sitName, $minCount, $minConf)
                    }
                }

                $result += ("CondOp={0}; GroupOp={1}; SITs=[{2}]" -f `
                            $condOp, $groupOp, ($sitStrings -join " | "))
            }
        }
        # Older-style: SensitiveInformation directly on condition
        elseif ($condition.PSObject.Properties.Name -contains "SensitiveInformation" -and $condition.SensitiveInformation) {
            $sitStrings = @()

            foreach ($sit in $condition.SensitiveInformation) {
                $sitName  = $sit.Name
                $minCount = $sit.minCount
                if (-not $minCount) { $minCount = $sit.MinCount }
                $minConf  = $sit.minConfidence
                if (-not $minConf) { $minConf = $sit.MinConfidence }

                $sitStrings += ("{0} (MinCount={1}, MinConfidence={2})" -f `
                                $sitName, $minCount, $minConf)
            }

            $result += ("CondOp={0}; SITs=[{1}]" -f `
                        $condOp, ($sitStrings -join " | "))
        }
    }

    if ($result.Count -eq 0) { return $null }

    return ($result -join " || ")
}

#==============================#
# HELPER: SIT SUMMARY FROM AdvancedRule JSON
#==============================#

function Get-SITSummaryFromAdvancedRule {
    param([string]$AdvancedRuleJson)

    if ([string]::IsNullOrWhiteSpace($AdvancedRuleJson)) { return $null }

    try {
        $adv = $AdvancedRuleJson | ConvertFrom-Json -Depth 50
    }
    catch {
        return $null
    }

    $summaries = @()

    function Walk-Condition {
        param($cond)

        if (-not $cond) { return }

        $op = $cond.Operator

        if ($cond.SubConditions) {
            foreach ($sub in $cond.SubConditions) {

                # ContentContainsSensitiveInformation subcondition
                if ($sub.ConditionName -eq "ContentContainsSensitiveInformation") {
                    if ($sub.Value) {
                        foreach ($val in $sub.Value) {
                            $sitName  = $val.Name
                            $minCount = $val.minCount
                            if (-not $minCount) { $minCount = $val.MinCount }
                            $minConf  = $val.minConfidence
                            if (-not $minConf) { $minConf = $val.MinConfidence }

                            $summaries += ("CondOp={0}; SIT={1} (MinCount={2}, MinConfidence={3})" -f `
                                            $op, $sitName, $minCount, $minConf)
                        }
                    }
                }
                # Nested condition (e.g. for NOT/AND/OR trees)
                elseif ($sub.Condition) {
                    Walk-Condition -cond $sub.Condition
                }
            }
        }
    }

    if ($adv.Condition) {
        Walk-Condition -cond $adv.Condition
    }

    if ($summaries.Count -eq 0) { return $null }

    return ($summaries -join " || ")
}

#==============================#
# RETRIEVE POLICIES
#==============================#

Write-Host "=== Retrieving DLP Policies ===" -ForegroundColor Cyan
$allPolicies = Get-DlpCompliancePolicy

Write-Host "All Policies (Name / Mode / Workload):" -ForegroundColor DarkCyan
$allPolicies | Select-Object Name, Mode, Workload | Format-Table -AutoSize

# Enabled (not test/simulation)
$policies = $allPolicies | Where-Object { $_.Mode -eq "Enable" }

Write-Host "Enabled policies: $($policies.Count)" -ForegroundColor Green
$policies | Select-Object Name, Priority, Workload | Format-Table -AutoSize

# Index for policy metadata
$policyIndex = @()

$policyReport = foreach ($p in $policies) {

    # Compute effective workloads from locations
    $effective = @()

    $hasExchange = ($p.ExchangeLocation -eq "All" -or
                    ($p.ExchangeLocation -and $p.ExchangeLocation.Count -gt 0) -or
                    ($p.ExchangeLocationException -and $p.ExchangeLocationException.Count -gt 0))
    if ($hasExchange) { $effective += "Exchange" }

    $hasSPO = ($p.SharePointLocation -eq "All" -or
               ($p.SharePointLocation -and $p.SharePointLocation.Count -gt 0) -or
               ($p.SharePointLocationException -and $p.SharePointLocationException.Count -gt 0))
    if ($hasSPO) { $effective += "SharePoint" }

    $hasODB = ($p.OneDriveLocation -eq "All" -or
               ($p.OneDriveLocation -and $p.OneDriveLocation.Count -gt 0) -or
               ($p.OneDriveLocationException -and $p.OneDriveLocationException.Count -gt 0))
    if ($hasODB) { $effective += "OneDrive" }

    $hasM365Groups = ($p.ModernGroupLocation -eq "All" -or
                      ($p.ModernGroupLocation -and $p.ModernGroupLocation.Count -gt 0) -or
                      ($p.ModernGroupLocationException -and $p.ModernGroupLocationException.Count -gt 0))
    if ($hasM365Groups) { $effective += "M365Groups" }

    $hasTeams = ($p.TeamsLocation -eq "All" -or
                 ($p.TeamsLocation -and $p.TeamsLocation.Count -gt 0) -or
                 ($p.TeamsLocationException -and $p.TeamsLocationException.Count -gt 0))
    if ($hasTeams) { $effective += "Teams" }

    $hasEndpoint = ($p.EndpointDlpLocation -eq "All" -or
                    ($p.EndpointDlpLocation -and $p.EndpointDlpLocation.Count -gt 0))
    if ($hasEndpoint) { $effective += "Endpoint" }

    $hasOnPrem = ($p.OnPremisesFileShareLocation -eq "All" -or
                  ($p.OnPremisesFileShareLocation -and $p.OnPremisesFileShareLocation.Count -gt 0))
    if ($hasOnPrem) { $effective += "OnPremFileShares" }

    $hasThirdParty = ($p.ThirdPartyAppDlpLocation -eq "All" -or
                      ($p.ThirdPartyAppDlpLocation -and $p.ThirdPartyAppDlpLocation.Count -gt 0) -or
                      ($p.ThirdPartyAppDlpLocationException -and $p.ThirdPartyAppDlpLocationException.Count -gt 0))
    if ($hasThirdParty) { $effective += "ThirdPartyApps" }

    $hasPowerBI = ($p.PowerBIDlpLocation -eq "All" -or
                   ($p.PowerBIDlpLocation -and $p.PowerBIDlpLocation.Count -gt 0) -or
                   ($p.PowerBIDlpLocationException -and $p.PowerBIDlpLocationException.Count -gt 0))
    if ($hasPowerBI) { $effective += "PowerBI" }

    $effectiveWorkloads = if ($effective.Count -gt 0) { $effective -join ";" } else { $null }

    # Store for rules
    $policyIndex += [pscustomobject]@{
        Name              = $p.Name
        Priority          = $p.Priority
        EffectiveWorkloads= $effectiveWorkloads
    }

    [pscustomobject]@{
        PolicyName                 = $p.Name
        PolicyId                   = $p.Guid
        PolicyPriority             = $p.Priority
        Mode                       = $p.Mode

        WorkloadsRaw               = ($p.Workload -join ";")
        EffectiveWorkloads         = $effectiveWorkloads

        Exchange_Include           = Format-Loc $p.ExchangeLocation
        Exchange_Exclude           = Format-Loc $p.ExchangeLocationException

        SharePoint_Include         = Format-Loc $p.SharePointLocation
        SharePoint_Exclude         = Format-Loc $p.SharePointLocationException

        OneDrive_Include           = Format-Loc $p.OneDriveLocation
        OneDrive_Exclude           = Format-Loc $p.OneDriveLocationException

        M365Groups_Include         = Format-Loc $p.ModernGroupLocation
        M365Groups_Exclude         = Format-Loc $p.ModernGroupLocationException

        Teams_Include              = Format-Loc $p.TeamsLocation
        Teams_Exclude              = Format-Loc $p.TeamsLocationException

        Endpoint                   = Format-Loc $p.EndpointDlpLocation
        OnPremFileShares           = Format-Loc $p.OnPremisesFileShareLocation
        ThirdPartyApps             = Format-Loc $p.ThirdPartyAppDlpLocation
        ThirdPartyApps_Exclude     = Format-Loc $p.ThirdPartyAppDlpLocationException
        PowerBI_Include            = Format-Loc $p.PowerBIDlpLocation
        PowerBI_Exclude            = Format-Loc $p.PowerBIDlpLocationException

        Description                = $p.Comment
    }
}

#==============================#
# RETRIEVE RULES (PER POLICY)
#==============================#

Write-Host "=== Retrieving DLP Rules ===" -ForegroundColor Cyan

$ruleReport = @()

foreach ($p in $policies) {

    Write-Host "Processing rules for policy: $($p.Name)" -ForegroundColor Cyan

    $policyRules = Get-DlpComplianceRule -Policy $p.Name

    if (-not $policyRules) {
        Write-Host "  No rules for this policy." -ForegroundColor DarkYellow
        continue
    }

    $enabledRules = $policyRules | Where-Object { $_.Disabled -ne $true }

    Write-Host "  Rules found: $($policyRules.Count) | Enabled: $($enabledRules.Count)" -ForegroundColor Green

    $meta = $policyIndex | Where-Object { $_.Name -eq $p.Name }
    $policyPriority       = $meta.Priority
    $policyEffWorkloads   = $meta.EffectiveWorkloads

    foreach ($r in $enabledRules) {

        # Prefer classic fields; if empty, fall back to AdvancedRule JSON
        $classicCond     = $r.ContentContainsSensitiveInformation
        $classicExcept   = $r.ExceptIfContentContainsSensitiveInformation
        $classicOther    = $r.Conditions
        $advancedJson    = $r.AdvancedRule

        $sitCondSummary  = $null
        $sitExceptSummary= $null
        $sitCondRaw      = $null
        $sitExceptRaw    = $null
        $otherCondRaw    = $null

        if ($classicCond) {
            $sitCondSummary = Get-SITSummaryFromObject -obj $classicCond
            $sitCondRaw     = ($classicCond | ConvertTo-Json -Depth 20 -Compress)
        }
        elseif ($advancedJson) {
            $sitCondSummary = Get-SITSummaryFromAdvancedRule -AdvancedRuleJson $advancedJson
            $sitCondRaw     = $advancedJson
        }

        if ($classicExcept) {
            $sitExceptSummary = Get-SITSummaryFromObject -obj $classicExcept
            $sitExceptRaw     = ($classicExcept | ConvertTo-Json -Depth 20 -Compress)
        }
        elseif ($advancedJson) {
            # Best-effort: in many tenants, exceptions live in same AdvancedRule tree.
            # We don't try to fully separate them; expose raw JSON.
            $sitExceptRaw = $advancedJson
        }

        if ($classicOther) {
            $otherCondRaw = ($classicOther | ConvertTo-Json -Depth 20 -Compress)
        }
        elseif ($advancedJson) {
            $otherCondRaw = $advancedJson
        }

        $ruleReport += [pscustomobject]@{
            PolicyName               = $p.Name
            PolicyPriority           = $policyPriority
            PolicyEffectiveWorkloads = $policyEffWorkloads

            RuleName                 = $r.Name
            RuleId                   = $r.Guid
            Priority                 = $r.Priority
            Severity                 = $r.Severity
            RuleDisabled             = $r.Disabled
            StopProcessing           = $r.StopPolicyProcessing

            SIT_Conditions           = $sitCondSummary
            SIT_Exceptions           = $sitExceptSummary
            SIT_Conditions_RawJson   = $sitCondRaw
            SIT_Exceptions_RawJson   = $sitExceptRaw

            OtherConditions          = $otherCondRaw

            Actions                  = ($r.Actions | ConvertTo-Json -Depth 20 -Compress)
            BlockAccess              = $r.BlockAccess
            BlockAccessScope         = ($r.BlockAccessScope -join ";")

            Notifications            = ($r.UserNotifications | ConvertTo-Json -Depth 20 -Compress)
            IncidentReportConfig     = ($r.IncidentReportConfiguration | ConvertTo-Json -Depth 20 -Compress)

            Comments                 = $r.Comment
        }
    }
}

Write-Host "Total enabled rules exported: $($ruleReport.Count)" -ForegroundColor Green

#==============================#
# SORT & EXPORT RESULTS
#==============================#

$polCsv = Join-Path $OutputPath "DlpPolicies.csv"
$ruleCsv = Join-Path $OutputPath "DlpRules.csv"
$xlsx   = Join-Path $OutputPath "DlpExport.xlsx"

$policyReportSorted = $policyReport | Sort-Object PolicyPriority, PolicyName
$ruleReportSorted   = $ruleReport   | Sort-Object PolicyPriority, Priority, PolicyName, RuleName

$policyReportSorted | Export-Csv -Path $polCsv -NoTypeInformation -Encoding UTF8
$ruleReportSorted   | Export-Csv -Path $ruleCsv -NoTypeInformation -Encoding UTF8

$policyReportSorted | Export-Excel -Path $xlsx -WorksheetName "Policies" -AutoSize -FreezeTopRow
$ruleReportSorted   | Export-Excel -Path $xlsx -WorksheetName "Rules" -AutoSize -FreezeTopRow -Append

Write-Host "=== Export Complete ===" -ForegroundColor Green
Write-Host "Policies CSV: $polCsv"
Write-Host "Rules CSV:    $ruleCsv"
Write-Host "Excel file:   $xlsx"
