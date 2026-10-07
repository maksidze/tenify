from pathlib import Path
out=Path('outputs/Shell10-Test')
lines=['@echo off','setlocal','chcp 866 >nul','title Shell 10 - Test Settings','set "PS=%SystemRoot%\System32\WindowsPowerShell\v1.0\powershell.exe"','set "BACKEND=%~dp0SettingsBackend.ps1"','if not exist "%BACKEND%" (echo SettingsBackend.ps1 missing& pause& exit /b 1)','if /i "%~1"=="--check" goto check','goto main',':ps','"%PS%" -NoLogo -NoProfile -ExecutionPolicy Bypass -File "%BACKEND%" %*','if errorlevel 1 pause','exit /b',':check','"%PS%" -NoLogo -NoProfile -ExecutionPolicy Bypass -File "%BACKEND%" -Action Status','exit /b %errorlevel%']
menus={
'main':('ПАРАМЕТРЫ ОБОЛОЧКИ WINDOWS 10 — ТЕСТ',[('1','Панель задач','goto taskbar'),('2','Проводник и параметры папок','goto files'),('3','Меню Пуск','goto start'),('4','Цвета и оформление','goto desktop'),('S','Состояние всех параметров','call :ps -Action Status\npause\ngoto main'),('U','Откатить применённые тестовые изменения','call :ps -Action Undo\npause\ngoto main'),('D','Очистить очередь изменений','call :ps -Action Discard\ngoto main'),('Q','Выход','exit /b 0')]),
'taskbar':('ПАНЕЛЬ ЗАДАЧ',[('1','Закрепление панели','call :ps -Action Toggle -Id lock'),('2','Маленькие кнопки','call :ps -Action Toggle -Id small'),('3','Значки уведомлений','call :ps -Action Toggle -Id badges'),('4','Кнопка Представление задач','call :ps -Action Toggle -Id taskview'),('5','Объединение кнопок','goto grouping'),('6','Панель на всех мониторах','call :ps -Action Toggle -Id multim'),('7','Положение панели','goto position')]),
'files':('ПРОВОДНИК',[('1','Расширения файлов','call :ps -Action Toggle -Id extensions'),('2','Скрытые файлы','call :ps -Action Toggle -Id hidden'),('3','Флажки выбора','call :ps -Action Toggle -Id checks'),('4','Эскизы вместо значков','call :ps -Action Toggle -Id thumbnails'),('5','Строка состояния','call :ps -Action Toggle -Id statusbar'),('6','Отдельный процесс для окон папок','call :ps -Action Toggle -Id separate'),('7','Начальная папка','goto launch')]),
'start':('МЕНЮ ПУСК',[('1','Недавние элементы в списках переходов','call :ps -Action Toggle -Id recent'),('2','Часто используемые приложения','call :ps -Action Toggle -Id used'),('3','Недавно добавленные приложения','call :ps -Action Toggle -Id added'),('4','Больше плиток','call :ps -Action Toggle -Id tiles')]),
'desktop':('ЦВЕТА И ОФОРМЛЕНИЕ',[('1','Светлая или тёмная тема приложений','call :ps -Action Toggle -Id appslight'),('2','Светлая или тёмная тема Windows','call :ps -Action Toggle -Id systemlight'),('3','Прозрачность','call :ps -Action Toggle -Id transparency'),('4','Акцентный цвет панели задач и Пуска','call :ps -Action Toggle -Id accent')]),
'position':('ПОЛОЖЕНИЕ ПАНЕЛИ — ПРИМЕНЯЕТСЯ КОМАНДОЙ R',[('1','Слева','call :ps -Action Set -Id position -Value 0\ngoto taskbar'),('2','Сверху','call :ps -Action Set -Id position -Value 1\ngoto taskbar'),('3','Справа','call :ps -Action Set -Id position -Value 2\ngoto taskbar'),('4','Снизу','call :ps -Action Set -Id position -Value 3\ngoto taskbar'),('B','Назад','goto taskbar'),('Q','Выход','exit /b 0')]),
'grouping':('ОБЪЕДИНЕНИЕ КНОПОК',[('1','Всегда скрывать подписи','call :ps -Action Set -Id grouping -Value 0\ngoto taskbar'),('2','Только при заполнении панели','call :ps -Action Set -Id grouping -Value 1\ngoto taskbar'),('3','Никогда','call :ps -Action Set -Id grouping -Value 2\ngoto taskbar'),('B','Назад','goto taskbar'),('Q','Выход','exit /b 0')]),
'launch':('НАЧАЛЬНАЯ ПАПКА',[('1','Этот компьютер','call :ps -Action Set -Id launch -Value 1\ngoto files'),('2','Быстрый доступ','call :ps -Action Set -Id launch -Value 2\ngoto files'),('B','Назад','goto files'),('Q','Выход','exit /b 0')])}
for label,(title,items) in menus.items():
 items=list(items)
 if label in ['taskbar','files','start','desktop']:
  items += [('A','Применить без перезапуска','call :ps -Action Apply\npause'),('R','Применить и перезапустить Explorer 10','echo Перезапуск закроет окна старого Explorer. Может появиться запрос UAC.\ncall :ps -Action Restart\npause'),('U','Откатить изменения','call :ps -Action Undo\npause'),('D','Очистить очередь','call :ps -Action Discard'),('B','Главное меню','goto main'),('Q','Выход','exit /b 0')]
 lines+=[':'+label,'cls','echo '+title,'echo.']
 if label=='main':lines+=['echo Выбор пунктов создаёт очередь. A применяет, R перезапускает Explorer 10.','echo U восстанавливает значения до первого применения.','echo.']
 if label in ['taskbar','files','start','desktop']:lines+=['call :ps -Action Status -Group '+label,'echo.','echo Звёздочка * означает изменение в очереди.']
 if label=='start':lines+=['echo Старый Explorer не заменяет StartMenuExperienceHost. Пункты экспериментальные.']
 if label=='position':lines+=['echo Перенос пока поддержан только при одном мониторе.']
 for key,name,_ in items:lines+=['echo   '+key+' - '+name]
 lines+=['echo.','choice /N /C '+''.join(i[0] for i in items)+' /M "Выбор: "','if errorlevel 255 goto '+label,'if errorlevel 1 goto '+label+'_%errorlevel%','goto '+label]
 for i,(_,_,action) in enumerate(items,1):
  lines+=[':'+label+'_'+str(i)]+action.splitlines()
  if not action.splitlines()[-1].startswith(('goto ','exit ')):lines+=['goto '+label]
(out/'Shell10-Settings.bat').write_bytes(('\r\n'.join(lines)+'\r\n').replace('—','-').replace('«','"').replace('»','"').replace(chr(11),chr(92)+'v').encode('cp866'))
p=out/'SettingsBackend.ps1';p.write_text(p.read_text(encoding='utf-8-sig'),encoding='utf-8-sig')
(out/'Readme.txt').write_text('''Тестовые Параметры оболочки Windows 10

Запуск: двойной щелчок Shell10-Settings.bat, без запуска от администратора.
BAT отображает меню, PowerShell выполняет чтение и запись. Оба файла должны оставаться рядом.

1 — панель задач; 2 — Проводник; 3 — Пуск; 4 — оформление.
Цифры переключают пункты или открывают подменю. Enter не требуется.
A — применить очередь без перезапуска. Положение панели не применяется этой командой.
R — применить очередь и перезапустить именно Explorer_10. Закрывает его окна.
U — вернуть все значения, которые изменил этот тест, к состоянию перед первым применением.
D — очистить очередь, не меняя применённых значений.
B — назад; Q — выход.

Для переноса панели вверх: 1, 7, 2, R.
Перенос в тестовой версии поддержан при одном мониторе и формате StuckRects3 размером 48 байт.
R использует ранее созданный outputs\\Start-Explorer10.ps1 для временного управления автоперезапуском Windows. Файл должен оставаться на один каталог выше Shell10-Test.
R работает только если Explorer_10 уже владеет рабочим столом и панелью задач. На штатном Explorer 11 команда откажет до изменения настроек.
Для R требуется штатный запрос UAC. HKLM AutoRestartShell восстанавливается тем же защитным процессом, что использован в предыдущем запуске Explorer 10.

Снимки исходных значений — state\\backup.json. Не удаляйте state до отката.
Откат сохраняет отсутствующие значения как отсутствующие и сохраняет исходный тип данных. После U для панели нажмите R; папки закройте и откройте заново.
Изменения темы могут затронуть и другие приложения. Настройки Пуска зависят от StartMenuExperienceHost и в Windows 11 могут не давать эффекта.
При отсутствии значения статус использует предполагаемое значение по умолчанию; реальная настройка может определяться политикой или другим компонентом.

Проверки выполняются отдельно от рабочего реестра в изолированной тестовой ветке. Реальное перемещение панели и перезапуск не выполняются автоматическими проверками.
''',encoding='utf-8-sig')
print('BAT written',len(lines),'lines')
