from pathlib import Path
import json,hashlib
root=Path(__file__).resolve().parent.parent;base=root/'outputs/Windows10-Components';builds=root/'outputs/Windows10-Builds'
p=builds/'checkpoint.py';s=p.read_text()
s=s.replace("'StartSessionCompat','SettingsUntilStopCompat','SettingsControlTextCompat','SettingsEnumCompat','SettingsPowerCompat'","'StartSessionCompat','SettingsUntilStopCompat','SettingsEnumCompat','SettingsDetachCompat'")
s=s.replace("'active-session.txt'}","'active-session.txt','active-network-session.txt'}")
s=s.replace("        if re.fullmatch(r's_[0-9a-f]{32}\\.ini',p.name):continue", "        if 'NetworkTrayCompat' in rel.parts and p.name.startswith(('run-','live-controller')):continue\n        if re.fullmatch(r's_[0-9a-f]{32}\\.ini',p.name):continue")
s=s.replace("outputs/Windows10-Components/Start-Windows10-Maximum.bat","outputs/Windows10-Components/Start-Windows10-OneClick.bat")
old="Windows10 UI, repeat opening and single About user-confirmed in session336aa1; subsequent VFS logger lifetime failure under repair. Missing taskbar labels and blank power/sleep choices known; Update page low priority. All sections and setters unverified. UntilStop drafts excluded."
new="Windows10 Settings repeat opening and single About user-confirmed previously. New content chain installed in session21ef2ad: 16 real taskbar description fallbacks and 2 power fallbacks, no adapter failures; visible UI pending. Eight taskbar descriptions and four AC/DC power provider getters tested. Tablet-autohide object missing; Display unresolved; Update low priority. Rare debugger detach BOOLfalse/error5 remains fail-closed. Network original SSO standalone lifecycle active; visible icon/click behavior unverified. UntilStop and detach research excluded."
assert old in s;s=s.replace(old,new);p.write_text(s,encoding='utf8')
text='''КОНТРОЛЬНАЯ СБОРКА ДЛЯ ТЕКУЩЕЙ WINDOWS 11 — 05.10.2026

Основной запуск после восстановления: Start-Windows10-OneClick.bat.
Включает текущий Explorer 10, Пуск 10, поддержку представления задач,
старые Параметры с новыми исправлениями подписей и списков питания,
обработчик значка сети Windows 10, квадратные углы и отключение Snap hover.
Системные файлы Windows 11 не заменяются.

Видимый результат новых подписей, списков и значка сети пока не подтверждён.
Настоящие обработчики проверены в собственных процессах и подключены в
действующий Settings; журнал содержит успешные реальные обращения.
В Settings остаётся редкий отказ отключения отладчика: такой процесс
защита завершает. Планшетное автоскрытие, недостающие элементы Дисплея и
Центра обновления не исправлены. Значок сети: инициализация обработчика
подтверждена, его отображение и щелчки ещё требуют проверки.

READY означает согласованный снимок файлов, а не полную совместимость.
Image, USVFS, Python и некоторые системные DLL — внешние зависимости,
проверяемые по SHA256. Это не переносимая установка/ISO.

Start-Build.bat проверяет снимок, зависимости и текущий workspace. Если
workspace отличается, сначала завершите частные сеансы штатным сценарием
«Вернуть Windows 11.bat», затем явно восстановите сборку:
powershell -NoProfile -ExecutionPolicy Bypass -File .\\Start-Build.ps1 -Restore
Восстановление делает резервные копии перезаписываемых файлов. Компоненты
затем запускаются по исходным путям рабочего каталога. Не запускайте
вложенные BAT напрямую из снимка: часть DLL содержит абсолютные пути.

Запускать обычным двойным щелчком, не от имени администратора. Проводник
может запросить UAC для временного защитного помощника восстановления.
Сеансы Пуска, Settings, сети и публикации мониторов ограничены одним часом.
Повторное использование не продлевает срок. Квадратные углы действуют до
вызова восстановления. Откат — «Вернуть Windows 11.bat» в workspace либо
Windows10-OneClick.ps1 -Mode Restore.

Подробности: Content-and-Network-2026-10-05.txt и Lab/SettingsContentCompat/
Readme.txt, Lab/NetworkTrayCompat/Readme.txt. Изменения настроек питания в
тестах не выполнялись. Ранее подтверждены плитки Пуска, горизонтальный
язык, работа Win+Tab/кнопки представления задач, квадратные углы/Snap hover.
Представление задач сейчас использует компоненты Windows 11.
'''
(builds/'Инструкция-сборки.txt').write_text(text,encoding='utf-8-sig')
network=base/'Lab/NetworkTrayCompat';p=network/'manifest.json';m=json.loads(p.read_text(encoding='utf-8-sig'))
extra=network/'Ensure-NetworkTray.ps1'
if not any(x['Path']==str(extra) for x in m['Files']):m['Files'].append({'Path':str(extra),'SHA256':hashlib.sha256(extra.read_bytes()).hexdigest()})
p.write_text(json.dumps(m,indent=2),encoding='utf8')
note='''

Обновление 05.10.2026 (oneclick-02): включены исправления восьми подписей
панели задач и списков экранного тайм-аута/сна. При первом включении были
успешные обращения в реальном Settings; визуальная проверка ещё ожидается.
Добавлен оригинальный обработчик сетевого значка pnidui.dll Windows 10 в
отдельном процессе без замены stobject.dll. Срок — до одного часа.
Планшетное автоскрытие и недостающие элементы Дисплея ещё не исправлены.
Возможен прежний редкий отказ отсоединения отладчика: окно тогда закрывается.
'''
p=root/'Запуск Windows 10 — инструкция.txt';p.write_text(p.read_text(encoding='utf-8-sig')+note,encoding='utf-8-sig')
p=base/'Content-and-Network-2026-10-05.txt';p.write_text(p.read_text()+note+'\nСеанс Settings: 21ef2ad0979f42bcba1eb43784f42d8c, PID10156.\nNetwork: run-3674f5ec0d5b47f8a07f8cb31237afcd, PID7864.\nПроверка общего запуска Check прошла, сеть повторно используется без дубликата.\n',encoding='utf8')
print('Checkpoint plan and current instructions updated; no system activation.')
