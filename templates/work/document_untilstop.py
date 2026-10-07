from pathlib import Path
root=Path(__file__).resolve().parent.parent
base=root/'outputs/Windows10-Components'
doc='''ЗАПУСК WINDOWS 10 НА WINDOWS 11 — oneclick-03, 5 октября 2026

Запуск: «Запустить Windows 10.bat» в папке проекта либо
outputs\\Windows10-Components\\Start-Windows10-OneClick.bat.
Обычный двойной щелчок, не от имени администратора. При перезапуске
оболочки может появиться UAC для временного защитного контроллера.
Перед первым включением закройте штатные «Параметры» Windows 11.

СРОК РАБОТЫ
Часовой предел убран. «Пуск», «Параметры», источник мониторов и обработчик
сети используют UntilStop: здоровые компоненты не выключаются по таймеру.
Они завершаются по команде возврата, при выходе из учётной записи либо
потере своего контроллера; Пуск/мониторы/сеть также привязаны к точному
экземпляру Explorer. Тайм-ауты первоначальной загрузки и защита от
зависаний сохранены. Повторный BAT использует уже работающие сеансы.
Автозапуск после перезагрузки не установлен: снова запустите BAT.

ВКЛЮЧЕНО
Explorer Windows 10, XAML и горизонтальный индикатор языка; Пуск с плитками;
публикация мониторов для Alt+Tab/Win+Tab/кнопки представления задач;
повторное открытие Параметров 10 с исправлением повторов «О системе»,
восьми подписей панели задач и поставщиков списков экранного тайм-аута/сна;
оригинальный обработчик сетевого значка; квадратные углы и отключение
Snap Layouts при наведении; проверенный набор 31 группы системных иконок 10.

ИКОНКИ
Только в процессе Explorer: приватные ресурсы imageres.dll.mun и
shell32.dll.mun. Код shell32 остаётся штатным. Сохраняются ресурсы Windows 11,
которые не входят в проверенный набор. Значки самих приложений этим не
заменяются. Проверено 34 stock ID: соответствие старому набору в собственном
процессе; 31 образец отличается от Windows 11. Для применения запускается
новый Explorer, его окна могут закрыться. Глобальный кэш иконок не удаляется.

ОГРАНИЧЕНИЯ
Это эксперимент для данной установки, не полная Windows 10. Представление
задач использует интерфейс Windows 11. Визуальная полнота значков, сетевого
индикатора и исправленных страниц ещё не подтверждена. Планшетное
автоскрытие, недостающие элементы Дисплея и Центра обновления не исправлены.
Theme10, полная палитра, старые уведомления/Action Center, поиск, диспетчеры
задач и устройств не включены. При ошибке одного компонента остальные
продолжают работу; точная причина записана в status.json.

ВОЗВРАТ И ДИАГНОСТИКА
«Вернуть Windows 11.bat» отключает принадлежащие проекту сеансы,
восстанавливает исходные углы/Snap и штатный Explorer. Старые окна Settings
и Explorer при возврате закрываются. «Проверить запуск Windows 10.bat»
проверяет наличие файлов и SHA256 без переключения оболочки.
Журналы: outputs\\Windows10-Components\\state-oneclick и state-persistent.
Подробные сеансы: Lab\\StartSessionCompat\\sessions,
Lab\\SettingsUntilStopCompat\\sessions, Lab\\DisplayMonitorPublisher,
Lab\\NetworkTrayUntilStopCompat. Сценарии с явным -Seconds оставлены только
для ограниченных диагностических запусков; обычные BAT используют UntilStop.

Системные файлы не заменяются. Используются частные копии, VFS,
изменения памяти своих процессов и обратимые настройки пользователя.
Не перемещайте Image/Tools/Runtime/Lab и Python runtime: проект зависит от
исходных путей и точных версий системных компонентов.
'''
(root/'Запуск Windows 10 — инструкция.txt').write_text(doc,encoding='utf-8-sig')
(base/'UntilStop-and-Icons-2026-10-05.txt').write_text(doc,encoding='utf-8-sig')
p=root/'outputs/Windows10-Builds/Инструкция-сборки.txt'
t=p.read_text(encoding='utf-8-sig')
t=t.replace('обработчик значка сети Windows 10, квадратные углы и отключение Snap hover.','обработчик значка сети Windows 10, 31 группу системных иконок Windows 10,\nквадратные углы и отключение Snap hover.')
t=t.replace('Сеансы Пуска, Settings, сети и публикации мониторов ограничены одним часом.\nПовторное использование не продлевает срок. Квадратные углы действуют до\nвызова восстановления.', 'Пуск, Settings, сеть и публикация мониторов работают UntilStop: без часового\nпредела, до явной остановки/выхода или потери контроллера/связанной оболочки.\nЗащита первоначальной загрузки остаётся ограниченной по времени.\nАвтозапуск при входе не устанавливается.')
t+='\nВыпуск b003 включает UntilStop и набор Icons10. Подробнее в\nUntilStop-and-Icons-2026-10-05.txt. READY не означает визуальную проверку\nвсех страниц/значков или гарантированное отсутствие сбоев.\n'
p.write_text(t,encoding='utf-8-sig')
p=root/'outputs/Windows10-Builds/checkpoint.py';t=p.read_text(encoding='utf8')
t=t.replace("'StartSessionCompat','SettingsUntilStopCompat',",'')
t=t.replace("if 'UntilStop' in p.name or p.name.startswith(('untilstop-','publisher-untilstop-')):continue", "if p.name.startswith(('publisher-untilstop-',)) or p.name=='untilstop-current-state.txt':continue")
t=t.replace("if 'NetworkTrayCompat' in rel.parts and p.name.startswith(('run-','live-controller')):continue", "if ({'NetworkTrayCompat','NetworkTrayUntilStopCompat'} & set(rel.parts)) and p.name.startswith(('run-','live-controller')):continue")
t=t.replace('UntilStop and detach research excluded.', 'UntilStop Start/Settings/network/publisher runtime included. Icons10 resource overlay included. No scheduled healthy-session deadline; finite bootstrap/owner-loss watchdogs retained. UI visual completeness unverified.')
p.write_text(t,encoding='utf8')
print('UntilStop/icon instructions and checkpoint selection updated')
