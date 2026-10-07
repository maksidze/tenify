from pathlib import Path
import datetime,hashlib,json
R=Path(__file__).resolve().parent.parent;B=R/'outputs/Windows10-Components'
read=lambda p:json.loads(p.read_text(encoding='utf-8-sig'))
sha=lambda p:hashlib.sha256(p.read_bytes()).hexdigest()
one=read(max((B/'state-oneclick').glob('*/status.json'),key=lambda p:p.stat().st_mtime))
assert one['Version']=='oneclick-09' and one['Status']=='started'
persistent=read(Path(one['MaximumState']));vfs=read(Path(persistent['Explorer']['VfsRun'])/'status.json')
assert vfs['theme10Hook']['applied']==1 and vfs['shellUXRevision']==9
proof={'RecordedUtc':datetime.datetime.now(datetime.timezone.utc).isoformat(),'OneClick':one,'Persistent':persistent,'Theme':vfs['theme10Hook'],'MenuSquare':vfs['menuSquareHook'],'Preflight':read(B/'state-vfs/preflight-d3d8b1c2e1164b2e83e2ef6a69dfedaa/status.json'),'VisualVerification':'pending user confirmation','SystemFilesModified':False,'Scope':'Explorer Win32 visual styles only; XAML/network unchanged'}
(B/'b008-live-proof.json').write_text(json.dumps(proof,ensure_ascii=False,indent=2),encoding='utf-8')
m=read(B/'oneclick-08-manifest.json');paths={Path(x['Path'])for x in m['Files']}
paths|={B/'Launch-Theme10Compat.py',B/'Lab/Theme10Compat/manifest.json',B/'Lab/Theme10Compat/Theme10Compat.dll'}
m.update(Version='oneclick-09',Proof='b008-live-proof.json',Files=[{'Path':str(p),'SHA256':sha(p)}for p in sorted(paths)])
(B/'oneclick-09-manifest.json').write_text(json.dumps(m,indent=2),encoding='utf-8')
doc=(B/'OneClick-08-Instructions.txt').read_text(encoding='utf-8-sig').replace('— oneclick-08,','— oneclick-09,').replace('b007-live-proof.json','b008-live-proof.json').replace('Theme10, полная палитра','Полная палитра')
doc+='\nВ oneclick-09 подключена частная aero.msstyles Windows 10 для нового Explorer.\nОна меняет обычные Win32-кнопки, поля, списки и полосы прокрутки внутри этого\nпроцесса. Физические DLL, версия и путь старой темы проверены; общий скрытый\nExplorer и живой запуск прошли. Это не глобальная тема Windows и не изменение\nXAML-кнопок Параметров, Пуска, сети или сторонних программ.\nПосле смены системной темы при возврате нового оформления выполните возврат к Windows 11 и затем снова запустите набор.\nДля полного возврата используйте «Вернуть Windows 11.bat».\nТекущая работа по NetworkUX/JumpView отмечена отдельно, она ещё не включена.\n'
for p in [R/'Запуск Windows 10 — инструкция.txt',B/'OneClick-09-Instructions.txt']:p.write_text(doc,encoding='utf-8-sig')
p=B/'Lab/Theme10Compat/Readme.txt';s=p.read_text(encoding='utf-8-sig');s=s.replace('Видимый рабочий Explorer пока работает без этой опции.','В oneclick-09 опция включена для Explorer; загрузка проверена, визуальное подтверждение ожидается.').replace('Эти режимы ещё не добавлены в профиль по умолчанию.','В oneclick-09 Theme10 включён в профиль по умолчанию; общий UntilStop запуск сохраняет Пуск и остальные компоненты.')
p.write_text(s,encoding='utf-8-sig')
print(json.dumps({'PID':persistent['Explorer']['Pid'],'ThemePath':vfs['theme10Hook']['after'],'Version':one['Version']}))
