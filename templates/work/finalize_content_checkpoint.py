from pathlib import Path
import json
root=Path(__file__).resolve().parent.parent;base=root/'outputs/Windows10-Components';builds=root/'outputs/Windows10-Builds'
note='''

Финальное обновление стабильности запуска, 05.10.2026:
Устранено преждевременное CloseHandle для CREATE_THREAD_DEBUG_EVENT.
Принадлежность этого дескриптора Windows подтверждена документацией и
собственной проверкой повторного использования. Канонический исходник
сохранён; преобразование применяется только к частному Settings backend.
Дополнительно проверяется BOOL результата ContinueDebugEvent.
29 из 30 исследовательских запусков прошли инициализацию и detach;
один завершён по тайм-ауту до инициализации. После включения исправления
оба повтора полного VFS/bootstrap прошли (2/2), а новый реальный сеанс
eaf99ecf3a0b4dfd99c44c2ce1961580, PID9328, дал initializer0,
detach success1, debuggerPresent0, 16 обращений за подписями без ошибок.
Это исправление конкретной ошибки владения HANDLE, не гарантия отсутствия
всех тайм-аутов или ошибок совместимости.
Источник: https://learn.microsoft.com/en-us/windows/win32/api/debugapi/nf-debugapi-waitfordebugevent
Доказательства: Lab/SettingsSessionCompat/DebugHandleProof.
'''
for p in [base/'Content-and-Network-2026-10-05.txt',base/'Lab/SettingsContentCompat/Readme.txt']:
 s=p.read_text(encoding='utf-8-sig')
 s=s.replace('- repeated-vfs-own-proof.json: оба процесса','- before-handle-fix-proof.json (до исправления HANDLE): оба процесса')
 p.write_text(s+note,encoding='utf8')
p=root/'Запуск Windows 10 — инструкция.txt';s=p.read_text(encoding='utf-8-sig')
s=s.replace('Возможен прежний редкий отказ отсоединения отладчика: окно тогда закрывается.','Ошибка раннего закрытия дескриптора отладчика исправлена; тайм-ауты\nинициализации остаются возможны, при них защита завершает только свой процесс.')
p.write_text(s,encoding='utf-8-sig')
p=builds/'Инструкция-сборки.txt';s=p.read_text(encoding='utf-8-sig')
s=s.replace('В Settings остаётся редкий отказ отключения отладчика: такой процесс\nзащита завершает.','Исправлено раннее закрытие дескриптора отладчика. Тайм-ауты инициализации\nостаются возможны; защита завершает только свой процесс.')
p.write_text(s,encoding='utf-8-sig')
p=builds/'checkpoint.py';s=p.read_text(encoding='utf8')
s=s.replace('Rare debugger detach BOOLfalse/error5 remains fail-closed.','Debug-event handle early-close repaired; 29 successful init/detach runs plus 1 initializer timeout, then 2/2 integrated VFS passes and actual Settings PID9328 detach success. Other startup timeouts remain possible.')
p.write_text(s,encoding='utf8')
(builds/'freeze-authorized.json').write_text(json.dumps({'milestone':'b002-content-network','authorization':'Root confirms stable production source; live states and separate research excluded; user requested periodic current-system builds.'}),encoding='utf8')
print('Production and instructions finalized; checkpoint freeze authorized.')
