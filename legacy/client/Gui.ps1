#Requires -RunAsAdministrator
Add-Type -AssemblyName System.Windows.Forms
Add-Type -AssemblyName System.Drawing
[Windows.Forms.Application]::EnableVisualStyles()
$root = Join-Path $env:ProgramData 'SelectiveTunnel'
$form = New-Object Windows.Forms.Form
$form.Text = 'SelectiveTunnel 1.1.0'
$form.Size = New-Object Drawing.Size(650,420)
$form.StartPosition = 'CenterScreen'
$form.FormBorderStyle = 'FixedDialog'
$form.MaximizeBox = $false
$form.Font = New-Object Drawing.Font('Segoe UI',10)
$title = New-Object Windows.Forms.Label
$title.Text = 'ChatGPT / Codex / Figma'
$title.Font = New-Object Drawing.Font('Segoe UI',16,[Drawing.FontStyle]::Bold)
$title.Location = New-Object Drawing.Point(22,20)
$title.Size = New-Object Drawing.Size(550,38)
$form.Controls.Add($title)
$note = New-Object Windows.Forms.Label
$note.Text = 'Выбранные домены — через прокси. Остальной трафик — напрямую.'
$note.Location = New-Object Drawing.Point(22,65)
$note.Size = New-Object Drawing.Size(550,40)
$form.Controls.Add($note)
$status = New-Object Windows.Forms.Label
$status.Location = New-Object Drawing.Point(22,110)
$status.Size = New-Object Drawing.Size(590,100)
$form.Controls.Add($status)
$script:probe = $null
$script:probeFile = Join-Path $root 'probe.txt'
$buttons = @(@('Подключить','Connect'),@('Блокировать','Block'),@('Настройки','Settings'),@('Проверить IP','Verify'),@('Импорт правил','Import'),@('Обновить правила','Refresh'))
for ($i=0; $i -lt $buttons.Count; $i++) {
    $button = New-Object Windows.Forms.Button
    $button.Text = $buttons[$i][0]
    $button.Tag = $buttons[$i][1]
    $button.Location = New-Object Drawing.Point((22 + 200*($i % 3)),(220 + 47*[math]::Floor($i / 3)))
    $button.Size = New-Object Drawing.Size(185,38)
    $button.Add_Click({
        try {
            if ($this.Tag -eq 'Verify') {
                if (-not $script:probe -or $script:probe.HasExited) {
                    $script:probe = Start-Process "$env:SystemRoot\System32\WindowsPowerShell\v1.0\powershell.exe" -ArgumentList @('-NoProfile','-ExecutionPolicy','Bypass','-File',('"'+"$PSScriptRoot\Control.ps1"+'"'),'-Action','Verify') -WindowStyle Hidden -PassThru -RedirectStandardOutput $script:probeFile -RedirectStandardError "$root\probe-error.txt"
                }
            } elseif ($this.Tag -eq 'Settings') { & "$PSScriptRoot\Edit-Connection.ps1" }
            elseif ($this.Tag -eq 'Import') { & "$PSScriptRoot\Import-Rules.ps1" }
            else { & "$PSScriptRoot\Control.ps1" -Action $this.Tag }
        } catch { [Windows.Forms.MessageBox]::Show($_.Exception.Message,'SelectiveTunnel') | Out-Null }
    })
    $form.Controls.Add($button)
}
$footer = New-Object Windows.Forms.Label
$footer.Text = 'Закрытие окна не отключает защиту. Приложения должны использовать системный DNS.'
$footer.Location = New-Object Drawing.Point(22,330)
$footer.Size = New-Object Drawing.Size(550,40)
$form.Controls.Add($footer)
$timer = New-Object Windows.Forms.Timer
$timer.Interval = 1500
$timer.Add_Tick({
    try {
        $s = Get-Content "$root\status.json" -Raw | ConvertFrom-Json
        $age = [DateTime]::UtcNow - [DateTime]::Parse($s.updated_utc).ToUniversalTime()
        $states=@{running='Движок работает — проверьте IP';blocked='Выбранные сервисы заблокированы';error='Ошибка: проверьте настройки, DNS и брандмауэр'}
        $state = if ($age.TotalSeconds -gt 60) { 'Нет свежего статуса фонового процесса' } elseif ($states.ContainsKey($s.state)) { $states[$s.state] } else { $s.state }
        $status.Text = "$state`r`nПравила: версия $($s.policy_version)"
        if ($s.update_error) { $status.Text += "`r`nАвтообновление списка недоступно. Можно импортировать правила." }
    } catch { $status.Text = 'Ожидание фонового процесса...' }
    if ($script:probe -and $script:probe.HasExited) {
        $text = (Get-Content $script:probeFile -Raw -ErrorAction SilentlyContinue)
        $text += (Get-Content "$root\probe-error.txt" -Raw -ErrorAction SilentlyContinue)
        $script:probe.Dispose(); $script:probe=$null
        [Windows.Forms.MessageBox]::Show($text,'Egress verification') | Out-Null
    }
})
$timer.Start()
try { [Windows.Forms.Application]::Run($form) } finally { $timer.Dispose(); $form.Dispose() }
