from pathlib import Path
import xml.etree.ElementTree as E,winreg as w,ctypes as c,json,csv,re,collections
sysroot=Path(r'C:\Users\MAKSIDZE\Documents\ImmersiveControlPanel_10')
out=Path('outputs/Shell10-Catalog');out.mkdir(exist_ok=True)
f=c.WinDLL('shlwapi').SHLoadIndirectString;f.argtypes=[c.c_wchar_p,c.c_wchar_p,c.c_uint,c.c_void_p];f.restype=c.c_long

def resolve(s):
 if not s:return ''
 b=c.create_unicode_buffer(4096)
 return b.value if f(s,b,4096,None)==0 else ''
def regvals(root,path):
 try:
  with w.OpenKey(root,path) as k:
   d={}
   for i in range(w.QueryInfoKey(k)[1]):
    n,v,t=w.EnumValue(k,i);d[n]=v.hex() if isinstance(v,bytes) else v
   return d
 except OSError:return {}
xmlfile=next((sysroot/'Settings').glob('AllSystemSettings*.xml'))
r=E.parse(xmlfile).getroot();allrows=[]
for i,e in enumerate(r):
 d={'sourceIndex':i+1,'filename':e.findtext('Filename',''),'pageId':e.findtext('SettingIdentity/PageID',''),'settingId':e.findtext('SettingIdentity/SettingID',''),'groupId':e.findtext('SettingIdentity/GroupID',''),'deepLink':e.findtext('ApplicationInformation/DeepLink',''),'descriptionResource':e.findtext('SettingInformation/Description',''),'condition':e.findtext('SettingIdentity/Condition',''),'featureConditions':dict(e.attrib),'source':str(xmlfile)}
 allrows.append(d)
(out/'all-settings-index.json').write_text(json.dumps(allrows,ensure_ascii=False,indent=2),encoding='utf-8')
pages={'SettingsPageTaskbar':'Панель задач','SettingsPageStart':'Пуск','SettingsPageBackground':'Рабочий стол и фон','SettingsPageColors':'Цвета','SettingsPageThemes':'Темы и значки','SettingsPageLockScreen':'Экран блокировки','SettingsPageMultiTasking':'Многозадачность','SettingsPageAppsNotifications':'Уведомления','SettingsPagePCSystemShellMode':'Режим планшета'}
labels={}
raw='''Autohide|Автоматически скрывать панель задач
Badging|Показывать значки уведомлений на кнопках
Feeds|Новости и интересы
FeedsLearnMoreLink|Справка о новостях и интересах
FeedsOpenOnHover|Открывать новости при наведении
FeedsReduceUpdates|Уменьшить частоту обновлений новостей
FeedsViewMode|Режим отображения новостей
GlommingPrimary|Объединение кнопок основной панели задач
GlommingSecondary|Объединение кнопок дополнительных панелей
Help|Справка по панели задач
Location|Положение панели задач: слева, сверху, справа, снизу
Lock|Закрепить панель задач
MultiMon|Показывать панель задач на всех мониторах
MultiMonTaskbarMode|Где показывать кнопки на нескольких мониторах
PeekPreviewDesktop|Предварительный просмотр рабочего стола при наведении
People|Показывать «Люди» на панели задач
PeopleAppUpsell|Предложения приложений в «Люди»
PeopleBarCapacity|Количество контактов на панели задач
ReplaceCommandPromptWithPowerShellWinX|Заменить командную строку PowerShell в меню Win+X
SelectIconsToAppearOnTaskbar|Выбор значков в области уведомлений
ShoulderTap|Уведомления от контактов «Люди»
ShoulderTapAudio|Звук уведомлений от контактов
SmallButtons|Маленькие кнопки панели задач
SystemIcons|Включение и отключение системных значков'''
for row in raw.splitlines():k,v=row.split('|');labels['SystemSettings_Taskbar_'+k]=v
raw='''AccountNotifications|Уведомления учётной записи в меню «Пуск»
LinkToPlacesPage|Папки, отображаемые в меню «Пуск»
MoreTilesEnabled|Показывать больше плиток
ShowAppList|Показывать список приложений
ShowMostUsedApps|Показывать часто используемые приложения
ShowRecentlyAddedAppsGroup|Показывать недавно добавленные приложения
ShowSuggestedAppsGroup|Предложения в меню «Пуск»
Size|Открывать меню «Пуск» на весь экран
StoreRecentlyOpenedItems|Недавние элементы в списках переходов и быстром доступе'''
for row in raw.splitlines():k,v=row.split('|');labels['SystemSettings_Start_'+k]=v
raw='''Background_ChooseBackground|Тип и изображение фона рабочего стола
Background_ChooseFit|Размещение изображения фона
Color_AppsUseLightTheme|Светлая или тёмная тема приложений
Color_ColorMode|Режим цвета: светлый, тёмный, настраиваемый
Color_ColorPrevalence|Акцентный цвет в меню «Пуск», панели задач и центре уведомлений
Color_ColorPrevalenceTitleBar|Акцентный цвет заголовков и границ окон
Color_EnableAutoColor|Автоматический выбор акцентного цвета
Color_EnableTransparency|Эффекты прозрачности
Color_SystemUsesLightTheme|Светлая или тёмная тема Windows
LockScreenAppsBadge|Приложение с подробным состоянием на экране блокировки
LockScreenAppsTile|Приложения с кратким состоянием на экране блокировки
LockScreenChooseBackgroundType|Фон экрана блокировки
LockScreenSlideshowAdvanced|Дополнительные параметры слайд-шоу блокировки
LockScreenSlideshowSource_CloudBrandName|Источник изображений слайд-шоу блокировки
LockScreenWelcomeScreenEnabled|Советы и интересные факты на экране блокировки
LogonScreenBackgroundUseColor|Изображение фона на экране входа'''
for row in raw.splitlines():k,v=row.split('|');labels['SystemSettings_Personalize_'+k]=v
raw='''MultiTasking_AeroSnapEnabled|Прикрепление окон к краям экрана
MultiTasking_JointResizeEnabled|Совместное изменение размера прикреплённых окон
MultiTasking_SnapAssistEnabled|Предложения соседних окон при прикреплении
MultiTasking_SnapFillEnabled|Автоматически заполнять доступное место при прикреплении
VirtualDesktops_AltTabFilter|Окна каких рабочих столов показывать в Alt+Tab
VirtualDesktops_TaskbarFilter|Окна каких рабочих столов показывать на панели задач
Timeline_SuggestionsEnabled|Предложения на временной шкале
TabWindows_AddAppDialog|Диалог добавления приложения во вкладки окон
TabWindows_AltTabFilter|Вкладки окон в Alt+Tab
TabWindows_AppToAppLaunch|Запуск приложений во вкладках окон
TabWindows_CloseAllDialog|Подтверждение закрытия всех вкладок окон
ShellMode_TaskbarTabletModeAutohide|Автоскрытие панели задач в режиме планшета'''
for row in raw.splitlines():k,v=row.split('|');labels['SystemSettings_'+k]=v
labels.update({
'SystemSettings_ControlCenter_EditModeLink':'Редактировать быстрые действия центра уведомлений',
'SystemSettings_ControlCenter_MicrosoftFlowEnabled':'Интеграция Microsoft Flow с быстрыми действиями',
'SystemSettings_Notifications_CortanaManagedNotifications':'Уведомления, управляемые Cortana',
'SystemSettings_Notifications_CustomizableQuickActions':'Настраиваемые быстрые действия',
'SystemSettings_Notifications_SelectIconsToAppearOnTaskbar':'Выбор значков области уведомлений',
'SystemSettings_Notifications_SoftLandingEnabled':'Предложения при знакомстве с Windows',
'SystemSettings_Notifications_SystemIcons':'Включение и отключение системных значков',
'SystemSettings_ShellMode_ModeChangeConfig':'Поведение при переключении режима планшета',
'SystemSettings_ShellMode_Preference':'Режим оболочки при входе в систему',
'SystemSettings_ShellMode_TaskbarAppsVisibility':'Видимость кнопок приложений в режиме планшета',
'SystemSettings_ShellMode_TouchImprovementAdvanced':'Дополнительные улучшения сенсорного режима'
})
catalog=[];seen=set()
for d in allrows:
 p=d['pageId']
 if p not in pages:continue
 sid=d['settingId']
 if not sid:continue
 if sid in seen:continue
 seen.add(sid)
 rd=regvals(w.HKEY_LOCAL_MACHINE,r'SOFTWARE\Microsoft\SystemSettings\SettingId'+'\\'+sid)
 label=labels.get(sid);resolved=resolve(d['descriptionResource'])
 catalog.append({'id':sid,'category':pages[p],'name':label or resolved or sid,'nameSource':'ручное пояснение идентификатора' if label else 'ресурс установленной Windows 11' if resolved else 'исходный идентификатор','kind':'link' if any(x in sid.lower() for x in ['link','help','selecticons','systemicons','dialog']) else 'setting','verification':'Найдено в индексе Windows 10; применение не проверено','hostHandler':rd.get('DllPath',''),'hostType':rd.get('Type',''),'registry':{},'evidence':[d], 'notes':'Индекс поиска включает экспериментальные и условные функции; наличие записи не подтверждает наличие элемента в интерфейсе.'})
# Classic Folder Options definitions are host metadata; Windows 11-only options excluded.
base=r'SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced\Folder'
def folderwalk(path):
 try:
  with w.OpenKey(w.HKEY_LOCAL_MACHINE,path) as k:
   children=[w.EnumKey(k,i) for i in range(w.QueryInfoKey(k)[0])]
 except OSError:return
 for n in children:
  sub=path+'\\'+n;d=regvals(w.HKEY_LOCAL_MACHINE,sub)
  if n in ['UseCompactMode','FriendlyDates']:continue
  if d.get('Type') in ['checkbox','radio'] and d.get('ValueName'):
   catalog.append({'id':'FolderOptions.'+sub[len(base)+1:].replace('\\','.'),'category':'Проводник: параметры папок','name':resolve(d.get('Text','')) or n,'nameSource':'ресурс установленной Windows 11','kind':'setting','verification':'Определение классического параметра на Windows 11; работа с Explorer 10 не проверена','hostHandler':'shell32.dll','hostType':d.get('Type',''),'registry':{k:d[k] for k in ['HKeyRoot','RegPath','ValueName','CheckedValue','UncheckedValue','DefaultValue'] if k in d},'evidence':[{'source':'HKLM\\'+sub,'raw':d}],'notes':'Текущая схема реестра, а не экспорт реестра Windows 10. Для записи предпочтительно использовать API оболочки.'})
  folderwalk(sub)
folderwalk(base)
# Additional UI settings outside Settings search index. Storage is intentionally left unverified.
extras={
'Проводник: общие':['Открывать Проводник в быстром доступе или «Этот компьютер»','Открывать папки в том же или в отдельном окне','Открывать элементы одним или двойным щелчком','Подчёркивание имён при открытии одним щелчком','Показывать недавние файлы в быстром доступе','Показывать часто используемые папки в быстром доступе','Очистить историю Проводника'],
'Проводник: поиск':['Не использовать индекс при поиске в папках файловой системы','Включать системные каталоги при поиске в неиндексируемых местах','Включать сжатые файлы при поиске','Всегда искать по именам файлов и содержимому'],
'Проводник: вид папки':['Режим представления: значки, список, таблица, плитки, содержимое','Размер значков','Сортировка и направление сортировки','Группировка и направление группировки','Выбор, порядок и ширина столбцов','Область навигации','Область предварительного просмотра','Область сведений','Показывать все папки в области навигации','Разворачивать область навигации до открытой папки','Показывать библиотеки','Показывать избранное в области навигации','Свернуть или развернуть ленту','Панель быстрого доступа: команды и расположение','Применить вид к папкам того же типа','Сбросить представления папок','Шаблон папки: общие, документы, изображения, музыка, видео'],
'Рабочий стол и фон':['Изображение рабочего стола','Сплошной цвет фона','Папки изображений для слайд-шоу','Интервал смены слайдов','Перемешивание слайдов','Слайд-шоу при питании от батареи','Изображение фона для отдельного монитора','Показывать значки рабочего стола','Размер значков рабочего стола','Сортировка значков рабочего стола','Автоматическое упорядочивание значков','Выравнивание значков по сетке'],
'Темы и значки':['Выбор, сохранение и удаление темы','Акцентный цвет вручную','Значок «Этот компьютер» на рабочем столе','Значок папки пользователя на рабочем столе','Значок «Сеть» на рабочем столе','Значок «Корзина» на рабочем столе','Значок «Панель управления» на рабочем столе','Изменение значков рабочего стола','Разрешить темам изменять значки рабочего стола','Звуковая схема','Схема указателей мыши','Выбор экранной заставки','Время ожидания экранной заставки','Запрашивать вход после экранной заставки'],
'Пуск':['Папки «Проводник», «Параметры», «Документы», «Загрузки», «Музыка», «Изображения», «Видео», «Сеть», личная папка','Размер меню «Пуск»','Размер плиток','Закрепление и открепление приложений и плиток','Группы и папки плиток','Живые плитки'],
'Панель задач':['Показ кнопки «Представление задач»','Показ кнопки Cortana','Режим поиска: скрыт, значок, поле','Показ кнопки сенсорной клавиатуры','Показ кнопки сенсорной панели','Панели инструментов: адрес, ссылки, рабочий стол, пользовательская папка','Высота и ширина панели задач','Закрепление и открепление приложений','Порядок кнопок приложений','Автоскрытие панели в режиме рабочего стола'],
'Экран блокировки':['Изображение экрана блокировки','Папки изображений слайд-шоу блокировки','Windows: интересное на экране блокировки']}
for group,names in extras.items():
 for i,name in enumerate(names):
  catalog.append({'id':'Supplement.'+str(list(extras).index(group))+'.'+str(i+1),'category':group,'name':name,'nameSource':'дополнение по классическому интерфейсу оболочки','kind':'action' if any(x in name for x in ['Очистить','Сбросить','Применить']) else 'setting','verification':'Дополнительный пункт интерфейса; точный механизм применения требует проверки','hostHandler':'','hostType':'','registry':{},'evidence':[],'notes':'Дополняет индекс поиска, не является извлечённым SystemSettings ID. Некоторые пункты относятся к текущей папке, плитке, монитору или значку.'})
# References to registry names actually present in the decompiled Windows 10 binary.
old=Path(r'C:\Users\MAKSIDZE\Documents\Explorer_10\explorer.exe.c')
terms=['StuckRects3','TaskbarSizeMove','TaskbarGlomLevel','MMTaskbarGlomLevel','MMTaskbarMode','MMTaskbarEnabled','EnableAutoTray','SearchboxTaskbarMode','TaskbarSmallIcons','ShowTaskViewButton','ShowCortanaButton','DisablePreviewDesktop','TaskbarAnimations','TaskbarBadges','PeopleBand']
hits={t:[] for t in terms}
for no,line in enumerate(old.read_text(encoding='utf-8',errors='replace').splitlines(),1):
 for t in terms:
  if 'L"'+t+'"' in line and len(hits[t])<8:hits[t].append({'line':no,'text':line.strip()})
(out/'explorer10-code-evidence.json').write_text(json.dumps({'source':str(old),'registryNameReferences':hits},ensure_ascii=False,indent=2),encoding='utf-8')
meta={'scope':'Оболочка Windows 10: панель задач, Пуск, рабочий стол, окна Проводника; смежные разделы блокировки, уведомлений и многозадачности','date':'2026-10-03','count':len(catalog),'byCategory':dict(collections.Counter(d['category'] for d in catalog)),'indexRows':len(allrows),'limitations':['Индекс поиска не является полным описанием UI и не содержит всех значений настроек.','Каталог объединяет записи Windows 10, определения классических Folder Options на хосте и отдельно помеченные дополнения.','Ни один параметр не проверен записью; применение в Windows 11 зависит от активной оболочки, служб и политик.','Групповые политики, скрытые флаги функций, расширения сторонних программ и все настройки каждой отдельной папки не включены как отдельные пункты.'],'sources':['https://learn.microsoft.com/en-us/windows/win32/api/shlobj_core/nf-shlobj_core-shgetsetsettings','https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-gppref/a6ca3a17-1971-4b22-bf3b-e1a5d5c50fca','https://learn.microsoft.com/en-us/windows/configuration/taskbar/policy-settings','https://support.microsoft.com/en-gb/windows/experience/fileexplorer/file-explorer-in-windows?nochrome=true']}
(out/'shell-settings.json').write_text(json.dumps({'metadata':meta,'settings':catalog},ensure_ascii=False,indent=2),encoding='utf-8')
with (out/'shell-settings.csv').open('w',encoding='utf-8-sig',newline='') as fcsv:
 writer=csv.writer(fcsv,delimiter=';');writer.writerow(['Раздел','Название','ID','Тип','Источник названия','Проверка','Обработчик на Windows 11','Тип обработчика','Реестр'])
 for d in catalog:writer.writerow([d['category'],d['name'],d['id'],d['kind'],d['nameSource'],d['verification'],d['hostHandler'],d['hostType'],json.dumps(d['registry'],ensure_ascii=False)])
print(json.dumps(meta,ensure_ascii=True,indent=2));print('unnamed',sum(d['name']==d['id'] for d in catalog))

