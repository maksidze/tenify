from pathlib import Path
root=Path('.').resolve();base=root/'outputs/Windows10-Components';lab=base/'Lab/SettingsIdentity';lab.mkdir(exist_ok=True)
s=(base/'Probe-Explorer10.py').read_text();s='import os\nos.chdir('+repr(str(root))+')\n'+s
needle="result.update(created=True,pid=pi.pid,desktop=si.desktop)"
s=s.replace(needle,needle+'''
 packageSelf=api(kernel,'GetCurrentPackageFullName',C.c_long,[C.POINTER(D),W.LPWSTR]);packageChild=api(kernel,'GetPackageFullName',C.c_long,[P,C.POINTER(D),W.LPWSTR]);n=D(4096);b=C.create_unicode_buffer(4096);status=packageSelf(C.byref(n),b);result['controllerPackage']={'error':status,'name':b.value};n=D(4096);b=C.create_unicode_buffer(4096);status=packageChild(pi.process,C.byref(n),b);result['childPackage']={'error':status,'name':b.value}
''')
(lab/'Probe-SettingsIdentity.py').write_text(s,encoding='utf8')
