@echo off
setlocal
chcp 65001 >nul
set "py=@PYTHON_DIR@\python.exe"
:menu
cls
echo Windows 10 на Windows 11 - лаборатория совместимости
echo 1. Текущее состояние и результаты реальных проверок
echo 2. Загрузка адаптера USER32 ^(скрытый процесс, 5 секунд^)
echo 3. Исходный тест старых shell DLL ^(скрытый desktop, 12 секунд^)
echo 4. Проверка VFS и фактически загруженных USER32 / win32u
echo 5. Прямые углы окон / восстановление / состояние
echo 6. Полная карта компонентов интерфейса
echo 7. Новый legacy-watchers: скрытая проверка всех текущих адаптеров
echo 8. Host-DComp: скрытая проверка с точечным исправлением XAML
echo 9. Пуск Windows 10 с плитками — проверенный запуск, до 60 минут
echo R. Вернуть штатный Пуск из активного теста
echo Q. Выход
echo.
echo Скрытые тесты не подтверждают работу меню и горячих клавиш.
choice /c 123456789RQ /n /m "Выберите пункт: "
if errorlevel 11 exit /b
if errorlevel 10 goto restorestart
if errorlevel 9 goto oldstart
if errorlevel 8 goto packaged
if errorlevel 7 goto latest
if errorlevel 6 goto map
if errorlevel 5 goto corners
if errorlevel 4 goto known
if errorlevel 3 goto explorer
if errorlevel 2 goto imports
type "%~dp0Progress-2026-10-05.txt"
goto done
:imports
"%py%" "%~dp0Probe-USVFS.py" --preset loadtest-compat --seconds 5
goto done
:explorer
"%py%" "%~dp0Probe-USVFS.py" --preset immersive-compat --capture-debug --seconds 12
goto done
:known
"%py%" "%~dp0Probe-USVFS.py" --preset known-dlls --seconds 5
goto done
:corners
call "%~dp0WindowStyle\WindowStyle.bat"
goto menu
:map
type "%~dp0Component-Map.txt"
goto done
:latest
"%SystemRoot%\System32\WindowsPowerShell\v1.0\powershell.exe" -NoProfile -ExecutionPolicy Bypass -File "%~dp0Start-Explorer10-VFS.ps1" -PreflightOnly -Profile legacy-watchers -XamlQuirk -NoLegacyTouchpad -CaptureDebug
goto done
:packaged
"%SystemRoot%\System32\WindowsPowerShell\v1.0\powershell.exe" -NoProfile -ExecutionPolicy Bypass -File "%~dp0Start-Explorer10-VFS.ps1" -PreflightOnly -Profile host-dcomp-resource -XamlQuirk -CaptureDebug
goto done
:oldstart
"%SystemRoot%\System32\WindowsPowerShell\v1.0\powershell.exe" -NoProfile -ExecutionPolicy Bypass -File "%~dp0Start-Menu10-Background.ps1"
goto done
:restorestart
call "%~dp0Stop-Menu10.bat"
goto menu
:done
echo.
echo Отчеты: %~dp0Metadata и %~dp0state-vfs
pause
goto menu
