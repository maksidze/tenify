from pathlib import Path
import ctypes as C,shutil,json
root=Path(__file__).resolve().parent.parent;lab=root/'outputs/Windows10-Components/Lab/HostMultitaskingCompat';src=Path('C:/Windows/System32')
k=C.WinDLL('kernel32',use_last_error=True);u=C.WinDLL('user32',use_last_error=True)
k.LoadLibraryExW.argtypes=[C.c_wchar_p,C.c_void_p,C.c_uint32];k.LoadLibraryExW.restype=C.c_void_p
k.FreeLibrary.argtypes=[C.c_void_p];u.LoadStringW.argtypes=[C.c_void_p,C.c_uint32,C.c_wchar_p,C.c_int];u.LoadStringW.restype=C.c_int
def test(path):
 h=k.LoadLibraryExW(str(path),None,0x22)
 if not h:raise C.WinError(C.get_last_error())
 try:
  b=C.create_unicode_buffer(512);n=u.LoadStringW(h,0x34bd,b,512);return {'length':n,'text':b.value,'error':C.get_last_error()}
 finally:k.FreeLibrary(h)
report={'native':test(src/'twinui.pcshell.dll'),'labBefore':test(lab/'twinui.pcshell.dll')}
for lang in ['ru-RU','en-US']:
 f=src/lang/'twinui.pcshell.dll.mui'
 if f.exists():(lab/lang).mkdir(exist_ok=True);shutil.copy2(f,lab/lang/f.name)
report['labAfter']=test(lab/'twinui.pcshell.dll')
(lab/'mui-probe.json').write_text(json.dumps(report,ensure_ascii=False,indent=2),encoding='utf8')
print(json.dumps(report,ensure_ascii=True))
