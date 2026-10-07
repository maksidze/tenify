from pathlib import Path
b=Path('outputs/Windows10-Components')
p=b/'WindowStyle/Readme.txt';s=p.read_text(encoding='utf-8-sig').replace('Enable-WindowCorners.bat /\nDisable-WindowCorners.bat / Status-WindowCorners.bat в корне комплекта.', 'Lab\\WindowStyleSession\\Enable.bat / Disable.bat / Status.bat.');p.write_text(s,encoding='utf-8-sig')
for name in ['Readme.txt','Запуск-и-статус.txt','Settings10-State.txt','Progress-2026-10-05.txt']:
 p=b/name;s=p.read_text(encoding='utf-8-sig');s+='\nИзвестная следующая ошибка Settings: на пользовательских снимках страницы\nпанели задач отсутствуют некоторые подписи. Причина исследуется; видимый UI,\nповторное открытие и single About не означают исправление всех страниц.\n';p.write_text(s,encoding='utf-8-sig')
