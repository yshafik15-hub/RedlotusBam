#requires -Version 5.1

<#
    RedLotusBam
    Made by Mazaag
    BAM forensic viewer for Windows 10/11
#>

$ErrorActionPreference = "SilentlyContinue"

Add-Type -AssemblyName System.Windows.Forms
Add-Type -AssemblyName System.Drawing

function Test-Admin {
    $id = [Security.Principal.WindowsIdentity]::GetCurrent()
    $p = New-Object Security.Principal.WindowsPrincipal($id)
    return $p.IsInRole([Security.Principal.WindowsBuiltinRole]::Administrator)
}

if (-not (Test-Admin)) {
    [System.Windows.Forms.MessageBox]::Show(
        "Please run RedLotusBam as Administrator.",
        "RedLotusBam",
        [System.Windows.Forms.MessageBoxButtons]::OK,
        [System.Windows.Forms.MessageBoxIcon]::Warning
    ) | Out-Null
    exit
}

function Get-SignatureStatus {
    param([string]$FilePath)

    if ([string]::IsNullOrWhiteSpace($FilePath)) {
        return ""
    }

    if (-not (Test-Path -LiteralPath $FilePath -PathType Leaf)) {
        return "File Was Not Found"
    }

    try {
        $status = (Get-AuthenticodeSignature -LiteralPath $FilePath).Status

        switch ($status) {
            "Valid" {
                return "Valid Signature"
            }

            "NotSigned" {
                return "Invalid Signature (NotSigned)"
            }

            "HashMismatch" {
                return "Invalid Signature (HashMismatch)"
            }

            "NotTrusted" {
                return "Invalid Signature (NotTrusted)"
            }

            default {
                return "Invalid Signature ($status)"
            }
        }
    }
    catch {
        return "Invalid Signature (UnknownError)"
    }
}

function Convert-BamPath {
    param([string]$Item)

    if ([string]::IsNullOrWhiteSpace($Item)) {
        return ""
    }

    if ($Item -match '^\\Device\\HarddiskVolume(\d+)\\(.+)$') {
        $rest = $Matches[2]
        $winDrive = $env:SystemDrive

        return ($winDrive.TrimEnd('\') + "\" + $rest)
    }

    return ""
}

function Get-BamResults {

    $results = New-Object System.Collections.Generic.List[object]

    try {

        if (-not (Get-PSDrive -Name HKLM -PSProvider Registry)) {
            New-PSDrive `
                -Name HKLM `
                -PSProvider Registry `
                -Root HKEY_LOCAL_MACHINE | Out-Null
        }

        $roots = @(
            "HKLM:\SYSTEM\CurrentControlSet\Services\bam\",
            "HKLM:\SYSTEM\CurrentControlSet\Services\bam\State\"
        )

        $sids = New-Object System.Collections.Generic.HashSet[string]

        foreach ($root in $roots) {

            $userSettings = Join-Path $root "UserSettings"

            if (Test-Path $userSettings) {

                Get-ChildItem -Path $userSettings | ForEach-Object {
                    [void]$sids.Add($_.PSChildName)
                }
            }
        }

        foreach ($sid in $sids) {

            $user = ""

            try {

                $sidObj = New-Object `
                    System.Security.Principal.SecurityIdentifier($sid)

                $user = $sidObj.Translate(
                    [System.Security.Principal.NTAccount]
                ).Value

            }
            catch {}

            foreach ($root in $roots) {

                $keyPath = Join-Path `
                    (Join-Path $root "UserSettings") `
                    $sid

                if (-not (Test-Path $keyPath)) {
                    continue
                }

                $key = Get-Item -Path $keyPath

                foreach ($item in $key.Property) {

                    try {

                        $raw = (Get-ItemProperty `
                            -Path $keyPath).$item

                        if ($raw -is [byte[]] -and $raw.Length -eq 24) {

                            $hex = [System.BitConverter]::ToString(
                                $raw[7..0]
                            ) -replace "-", ""

                            $fileTime = [Convert]::ToInt64(
                                $hex,
                                16
                            )

                            $utc = [DateTime]::FromFileTimeUtc(
                                $fileTime
                            )

                            $local = $utc.ToLocalTime()

                            $path = Convert-BamPath $item

                            $application = Split-Path `
                                -Leaf $item

                            $signature = ""

                            if ($path) {
                                $signature = Get-SignatureStatus $path
                            }

                            $results.Add(
                                [PSCustomObject]@{

                                    "Examiner Time" =
                                        $local.ToString(
                                            "yyyy-MM-dd HH:mm:ss"
                                        )

                                    "Last Execution Time (UTC)" =
                                        $utc.ToString(
                                            "yyyy-MM-dd HH:mm:ss"
                                        )

                                    "Application" =
                                        $application

                                    "Path" =
                                        $path

                                    "Signature" =
                                        $signature

                                    "User" =
                                        $user

                                    "SID" =
                                        $sid

                                    "Registry Path" =
                                        $root
                                }
                            )
                        }
                    }
                    catch {}
                }
            }
        }
    }
    catch {
        throw
    }

    return $results
}

# ============================================================
# GUI
# ============================================================

$script:AllResults = @()
$script:FilteredResults = @()

$form = New-Object System.Windows.Forms.Form

$form.Text = "RedLotusBam — Made by Mazaag"

$form.Size = New-Object System.Drawing.Size(
    1100,
    700
)

$form.MinimumSize = New-Object System.Drawing.Size(
    900,
    600
)

$form.StartPosition = "CenterScreen"

$form.BackColor =
    [System.Drawing.Color]::FromArgb(
        24,
        24,
        28
    )

# ------------------------------------------------------------
# Title
# ------------------------------------------------------------

$title = New-Object System.Windows.Forms.Label

$title.Text = "RedLotusBam"

$title.ForeColor =
    [System.Drawing.Color]::White

$title.Font =
    New-Object System.Drawing.Font(
        "Segoe UI",
        24,
        [System.Drawing.FontStyle]::Bold
    )

$title.Location =
    New-Object System.Drawing.Point(
        25,
        20
    )

$title.AutoSize = $true

$form.Controls.Add($title)

# ------------------------------------------------------------
# Made By
# ------------------------------------------------------------

$made = New-Object System.Windows.Forms.Label

$made.Text = "Made by Mazaag"

$made.ForeColor =
    [System.Drawing.Color]::FromArgb(
        190,
        190,
        200
    )

$made.Font =
    New-Object System.Drawing.Font(
        "Segoe UI",
        10
    )

$made.Location =
    New-Object System.Drawing.Point(
        30,
        65
    )

$made.AutoSize = $true

$form.Controls.Add($made)

# ------------------------------------------------------------
# Status
# ------------------------------------------------------------

$status = New-Object System.Windows.Forms.Label

$status.Text = "Ready"

$status.ForeColor =
    [System.Drawing.Color]::FromArgb(
        100,
        200,
        120
    )

$status.Font =
    New-Object System.Drawing.Font(
        "Segoe UI",
        10,
        [System.Drawing.FontStyle]::Bold
    )

$status.Location =
    New-Object System.Drawing.Point(
        30,
        105
    )

$status.AutoSize = $true

$form.Controls.Add($status)

# ------------------------------------------------------------
# Scan Button
# ------------------------------------------------------------

$scan = New-Object System.Windows.Forms.Button

$scan.Text = "Start BAM Scan"

$scan.Size =
    New-Object System.Drawing.Size(
        150,
        38
    )

$scan.Location =
    New-Object System.Drawing.Point(
        900,
        25
    )

$scan.Anchor =
    "Top,Right"

$form.Controls.Add($scan)

# ------------------------------------------------------------
# Progress
# ------------------------------------------------------------

$progress = New-Object System.Windows.Forms.ProgressBar

$progress.Style = "Marquee"

$progress.Visible = $false

$progress.Location =
    New-Object System.Drawing.Point(
        30,
        135
    )

$progress.Size =
    New-Object System.Drawing.Size(
        1015,
        10
    )

$progress.Anchor =
    "Top,Left,Right"

$form.Controls.Add($progress)

# ------------------------------------------------------------
# Results Label
# ------------------------------------------------------------

$resultsLabel =
    New-Object System.Windows.Forms.Label

$resultsLabel.Text = "Results"

$resultsLabel.ForeColor =
    [System.Drawing.Color]::White

$resultsLabel.Font =
    New-Object System.Drawing.Font(
        "Segoe UI",
        13,
        [System.Drawing.FontStyle]::Bold
    )

$resultsLabel.Location =
    New-Object System.Drawing.Point(
        30,
        165
    )

$resultsLabel.AutoSize = $true

$form.Controls.Add($resultsLabel)

# ------------------------------------------------------------
# Search Label
# ------------------------------------------------------------

$searchLabel =
    New-Object System.Windows.Forms.Label

$searchLabel.Text =
    "Search client / application:"

$searchLabel.ForeColor =
    [System.Drawing.Color]::Gainsboro

$searchLabel.Location =
    New-Object System.Drawing.Point(
        30,
        202
    )

$searchLabel.AutoSize = $true

$form.Controls.Add($searchLabel)

# ------------------------------------------------------------
# Search Box
# ------------------------------------------------------------

$search =
    New-Object System.Windows.Forms.TextBox

$search.Location =
    New-Object System.Drawing.Point(
        205,
        198
    )

$search.Size =
    New-Object System.Drawing.Size(
        300,
        28
    )

$search.Enabled = $false

$form.Controls.Add($search)

# ------------------------------------------------------------
# Clear Filter
# ------------------------------------------------------------

$clear =
    New-Object System.Windows.Forms.Button

$clear.Text = "Clear Filter"

$clear.Location =
    New-Object System.Drawing.Point(
        515,
        197
    )

$clear.Size =
    New-Object System.Drawing.Size(
        100,
        30
    )

$clear.Enabled = $false

$form.Controls.Add($clear)

# ------------------------------------------------------------
# Count
# ------------------------------------------------------------

$count =
    New-Object System.Windows.Forms.Label

$count.Text = "0 entries"

$count.ForeColor =
    [System.Drawing.Color]::Silver

$count.Location =
    New-Object System.Drawing.Point(
        635,
        203
    )

$count.AutoSize = $true

$form.Controls.Add($count)

# ------------------------------------------------------------
# DataGrid
# ------------------------------------------------------------

$grid =
    New-Object System.Windows.Forms.DataGridView

$grid.Location =
    New-Object System.Drawing.Point(
        30,
        240
    )

$grid.Size =
    New-Object System.Drawing.Size(
        1015,
        350
    )

$grid.Anchor =
    "Top,Bottom,Left,Right"

$grid.ReadOnly = $true

$grid.AllowUserToAddRows = $false

$grid.AllowUserToDeleteRows = $false

$grid.AutoSizeColumnsMode =
    "DisplayedCells"

$grid.SelectionMode =
    "FullRowSelect"

$grid.MultiSelect = $true

$grid.BackgroundColor =
    [System.Drawing.Color]::FromArgb(
        32,
        32,
        37
    )

$grid.GridColor =
    [System.Drawing.Color]::FromArgb(
        60,
        60,
        65
    )

$grid.ForeColor =
    [System.Drawing.Color]::White

$grid.EnableHeadersVisualStyles = $false

$grid.ColumnHeadersDefaultCellStyle.BackColor =
    [System.Drawing.Color]::FromArgb(
        45,
        45,
        52
    )

$grid.ColumnHeadersDefaultCellStyle.ForeColor =
    [System.Drawing.Color]::White

$grid.DefaultCellStyle.BackColor =
    [System.Drawing.Color]::FromArgb(
        32,
        32,
        37
    )

$grid.DefaultCellStyle.ForeColor =
    [System.Drawing.Color]::White

$grid.DefaultCellStyle.SelectionBackColor =
    [System.Drawing.Color]::FromArgb(
        70,
        70,
        85
    )

$grid.DefaultCellStyle.SelectionForeColor =
    [System.Drawing.Color]::White

$form.Controls.Add($grid)

# ------------------------------------------------------------
# Export
# ------------------------------------------------------------

$export =
    New-Object System.Windows.Forms.Button

$export.Text = "Export CSV"

$export.Location =
    New-Object System.Drawing.Point(
        30,
        605
    )

$export.Size =
    New-Object System.Drawing.Size(
        110,
        34
    )

$export.Anchor =
    "Bottom,Left"

$export.Enabled = $false

$form.Controls.Add($export)

# ------------------------------------------------------------
# Copy
# ------------------------------------------------------------

$copy =
    New-Object System.Windows.Forms.Button

$copy.Text = "Copy Selected"

$copy.Location =
    New-Object System.Drawing.Point(
        150,
        605
    )

$copy.Size =
    New-Object System.Drawing.Size(
        120,
        34
    )

$copy.Anchor =
    "Bottom,Left"

$copy.Enabled = $false

$form.Controls.Add($copy)

# ------------------------------------------------------------
# Open
# ------------------------------------------------------------

$open =
    New-Object System.Windows.Forms.Button

$open.Text = "Open File"

$open.Location =
    New-Object System.Drawing.Point(
        280,
        605
    )

$open.Size =
    New-Object System.Drawing.Size(
        110,
        34
    )

$open.Anchor =
    "Bottom,Left"

$open.Enabled = $false

$form.Controls.Add($open)

# ------------------------------------------------------------
# Hint
# ------------------------------------------------------------

$hint =
    New-Object System.Windows.Forms.Label

$hint.Text =
    "Search client name: Lunar, Badlion, Feather, etc."

$hint.ForeColor =
    [System.Drawing.Color]::FromArgb(
        155,
        155,
        165
    )

$hint.Location =
    New-Object System.Drawing.Point(
        405,
        613
    )

$hint.AutoSize = $true

$form.Controls.Add($hint)

# ============================================================
# UPDATE GRID
# ============================================================

function Update-Grid {

    param(
        [string]$Filter = ""
    )

    if (
        [string]::IsNullOrWhiteSpace(
            $Filter
        )
    ) {

        $script:FilteredResults =
            @(
                $script:AllResults
            )

    }
    else {

        $needle =
            $Filter.Trim()

        $script:FilteredResults =
            @(
                $script:AllResults |
                Where-Object {

                    ($_.Application -like "*$needle*") -or

                    ($_.Path -like "*$needle*") -or

                    ($_.User -like "*$needle*")
                }
            )
    }

    $grid.DataSource = $null

    if (
        $script:FilteredResults.Count -gt 0
    ) {

        $grid.DataSource =
            [System.Collections.ArrayList]
            $script:FilteredResults
    }

    $count.Text =
        "$($script:FilteredResults.Count) / $($script:AllResults.Count) entries"
}

# ============================================================
# SEARCH
# ============================================================

$search.Add_TextChanged({

    Update-Grid `
        -Filter $search.Text
})

# ============================================================
# CLEAR
# ============================================================

$clear.Add_Click({

    $search.Text = ""
})

# ============================================================
# COPY SELECTED
# ============================================================

$copy.Add_Click({

    if ($grid.SelectedRows.Count -eq 0) {
        return
    }

    $lines = foreach (
        $row in $grid.SelectedRows
    ) {

        $v =
            $row.DataBoundItem

        "$($v.Application) | $($v.Path) | $($v.Signature) | $($v.User) | $($v.'Last Execution Time (UTC)')"
    }

    [System.Windows.Forms.Clipboard]::SetText(
        ($lines -join [Environment]::NewLine)
    )
})

# ============================================================
# OPEN FILE
# ============================================================

$open.Add_Click({

    if ($grid.SelectedRows.Count -ne 1) {
        return
    }

    $v =
        $grid.SelectedRows[0].DataBoundItem

    if (
        $v.Path -and
        (Test-Path -LiteralPath $v.Path)
    ) {

        Start-Process explorer.exe `
            -ArgumentList "/select,`"$($v.Path)`""

    }
    else {

        [System.Windows.Forms.MessageBox]::Show(
            "The file was not found at:`r`n$($v.Path)",
            "RedLotusBam"
        ) | Out-Null
    }
})

# ============================================================
# EXPORT CSV
# ============================================================

$export.Add_Click({

    if (
        $script:FilteredResults.Count -eq 0
    ) {
        return
    }

    $dialog =
        New-Object System.Windows.Forms.SaveFileDialog

    $dialog.Filter =
        "CSV files (*.csv)|*.csv"

    $dialog.FileName =
        "RedLotusBam_$(
            (Get-Date).ToString(
                'yyyyMMdd_HHmmss'
            )
        ).csv"

    if (
        $dialog.ShowDialog() -eq "OK"
    ) {

        $script:FilteredResults |
            Export-Csv `
                -Path $dialog.FileName `
                -NoTypeInformation `
                -Encoding UTF8

        [System.Windows.Forms.MessageBox]::Show(
            "Export complete.`r`n$($dialog.FileName)",
            "RedLotusBam"
        ) | Out-Null
    }
})

# ============================================================
# START SCAN
# ============================================================

$scan.Add_Click({

    $scan.Enabled = $false

    $progress.Visible = $true

    $status.Text =
        "Scanning BAM registry..."

    $status.ForeColor =
        [System.Drawing.Color]::Gold

    $form.Refresh()

    try {

        $script:AllResults =
            @(Get-BamResults)

        Update-Grid

        $search.Enabled = $true
        $clear.Enabled = $true
        $export.Enabled = $true
        $copy.Enabled = $true
        $open.Enabled = $true

        $status.Text =
            "Scan complete"

        $status.ForeColor =
            [System.Drawing.Color]::FromArgb(
                100,
                220,
                130
            )

        if (
            $grid.Rows.Count -gt 0
        ) {

            $grid.Rows[0].Selected = $true

            $grid.FirstDisplayedScrollingRowIndex = 0
        }

        [System.Windows.Forms.MessageBox]::Show(
            "BAM scan completed.`r`n`r`nFound $($script:AllResults.Count) entries.",
            "RedLotusBam — Results",
            [System.Windows.Forms.MessageBoxButtons]::OK,
            [System.Windows.Forms.MessageBoxIcon]::Information
        ) | Out-Null

    }
    catch {

        $status.Text =
            "Scan failed"

        $status.ForeColor =
            [System.Drawing.Color]::Tomato

        [System.Windows.Forms.MessageBox]::Show(
            "BAM scan failed:`r`n$($_.Exception.Message)",
            "RedLotusBam",
            [System.Windows.Forms.MessageBoxButtons]::OK,
            [System.Windows.Forms.MessageBoxIcon]::Error
        ) | Out-Null
    }

    finally {

        $progress.Visible = $false

        $scan.Enabled = $true
    }
})

# ============================================================
# FORM
# ============================================================

$form.Add_Shown({

    $status.Text =
        "Ready — click Start BAM Scan"
})

[void]$form.ShowDialog()
