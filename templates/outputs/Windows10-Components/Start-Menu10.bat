@echo off
setlocal
chcp 65001 >nul
echo Пуск Windows 10 — проверенная конфигурация с плитками.
echo Видимое меню проверено вместе с Explorer из Start-Explorer10-Compatible.bat.
echo Текущий тест работает до 60 минут; затем возвращается штатный Пуск.
echo Системные файлы не заменяются. Долговременная стабильность ещё проверяется.
echo Не запускайте второй экземпляр одновременно.
"%SystemRoot%\System32\WindowsPowerShell\v1.0\powershell.exe" -NoProfile -ExecutionPolicy Bypass -File "%~dp0Lab\StartCompat\Test-BrokerStartCompat.ps1" -Seconds 3600 -DetachAfterBootstrap
echo.
echo Сеанс завершён. Результат восстановления указан выше.
pause
