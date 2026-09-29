Set-StrictMode -Version Latest
function Show-ProxySettings($Current = $null) {
    Add-Type -AssemblyName System.Windows.Forms
    Add-Type -AssemblyName System.Drawing
    [Windows.Forms.Application]::EnableVisualStyles()
    if ($null -eq $Current) {
        $Current = [pscustomobject]@{schema=2;protocol='socks5';server_ip='176.119.140.14';server_port=14073;
            username='';password='';expected_exit_ip='176.119.140.14';tls_server_name='';policy_url='';policy_public_key=''}
    }
    $form = New-Object Windows.Forms.Form
    $form.Text='Настройка прокси — SelectiveTunnel'
    $form.ClientSize=New-Object Drawing.Size(570,530)
    $form.StartPosition='CenterScreen'; $form.FormBorderStyle='FixedDialog'; $form.MaximizeBox=$false
    $form.Font=New-Object Drawing.Font('Segoe UI',10)
    $labels=@('Протокол','IP прокси','Порт','Логин прокси','Пароль прокси','Ожидаемый внешний IP','Имя в TLS-сертификате')
    $fields=@{}
    $names=@('protocol','server_ip','server_port','username','password','expected_exit_ip','tls_server_name')
    for ($i=0;$i -lt $names.Count;$i++) {
        $label=New-Object Windows.Forms.Label
        $label.Text=$labels[$i]; $label.Location=New-Object Drawing.Point(20,(22+45*$i)); $label.Size=New-Object Drawing.Size(235,25)
        $form.Controls.Add($label)
        if ($i -eq 0) {
            $field=New-Object Windows.Forms.ComboBox
            $field.DropDownStyle='DropDownList'
            $field.Items.AddRange([object[]]@('socks5','http','https'))
            $field.SelectedItem=$Current.protocol
        } else {
            $field=New-Object Windows.Forms.TextBox
            if ($names[$i] -ne 'password') { $field.Text=[string]$Current.($names[$i]) }
            else { $field.UseSystemPasswordChar=$true }
        }
        $field.Location=New-Object Drawing.Point(265,(20+45*$i)); $field.Size=New-Object Drawing.Size(280,28)
        $fields[$names[$i]]=$field; $form.Controls.Add($field)
    }
    $note=New-Object Windows.Forms.Label
    $note.Location=New-Object Drawing.Point(20,345); $note.Size=New-Object Drawing.Size(525,110)
    $note.Text="Нужны данные самого прокси, а не аккаунта Proxys.io.`r`nSOCKS5: 14073; HTTP: 4073. Пароль зашифрован на диске.`r`nSOCKS5/HTTP не шифруют вход на прокси; HTTPS выбирайте только при подтверждённом TLS.`r`nЕсли пароль уже сохранён, пустое поле оставит его прежним."
    $form.Controls.Add($note)
    $save=New-Object Windows.Forms.Button
    $save.Text='Сохранить'; $save.Location=New-Object Drawing.Point(305,478); $save.Size=New-Object Drawing.Size(115,33)
    $save.Add_Click({
        try {
            $candidate=[pscustomobject]@{schema=2;protocol=[string]$fields.protocol.SelectedItem;
                server_ip=$fields.server_ip.Text.Trim();server_port=0;username=$fields.username.Text;
                password=$fields.password.Text;expected_exit_ip=$fields.expected_exit_ip.Text.Trim();
                tls_server_name=$fields.tls_server_name.Text.Trim();policy_url=$Current.policy_url;policy_public_key=$Current.policy_public_key}
            $candidate.server_port=[int]$fields.server_port.Text
            if (-not $candidate.password) { $candidate.password=$Current.password }
            Assert-Profile $candidate
            $form.Tag=$candidate; $form.DialogResult=[Windows.Forms.DialogResult]::OK; $form.Close()
        } catch { [Windows.Forms.MessageBox]::Show($_.Exception.Message,'Проверьте настройки') | Out-Null }
    }.GetNewClosure())
    $cancel=New-Object Windows.Forms.Button
    $cancel.Text='Отмена'; $cancel.Location=New-Object Drawing.Point(430,478); $cancel.Size=New-Object Drawing.Size(115,33)
    $cancel.DialogResult=[Windows.Forms.DialogResult]::Cancel
    $form.Controls.AddRange([Windows.Forms.Control[]]@($save,$cancel)); $form.AcceptButton=$save; $form.CancelButton=$cancel
    try {
        if ($form.ShowDialog() -eq [Windows.Forms.DialogResult]::OK) { return $form.Tag }
        return $null
    } finally { $fields.password.Clear(); $form.Dispose() }
}
Export-ModuleMember -Function Show-ProxySettings
