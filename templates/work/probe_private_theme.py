"""Own-process only UXTheme test loader; never apply a global theme."""
from pathlib import Path
import ctypes as C,ctypes.wintypes as W,hashlib,json,sys,subprocess,uuid
ROOT=Path(__file__).resolve().parents[1]
NATIVE=Path('C:/Windows/System32/uxtheme.dll')
HASH='8c5347d464b4b74a17fbc7ab84e2e1f18c1b77fae964caf4f8566df5a7a4a07b'
OLD=ROOT/'outputs/Windows10-Components/Image/4/Windows/Resources/Themes/aero/aero.msstyles'
def worker(path,out):
    def save(d):out.write_text(json.dumps(d,ensure_ascii=False,indent=2),encoding='utf8')
    assert hashlib.sha256(NATIVE.read_bytes()).hexdigest()==HASH
    u=C.WinDLL(str(NATIVE));k=C.WinDLL('kernel32',use_last_error=True)
    k.GetProcAddress.argtypes=[W.HMODULE,C.c_void_p];k.GetProcAddress.restype=C.c_void_p
    u.OpenThemeData.argtypes=[W.HWND,W.LPCWSTR];u.OpenThemeData.restype=W.HANDLE
    u.CloseThemeData.argtypes=[W.HANDLE];u.CloseThemeData.restype=C.c_long
    u.GetThemeColor.argtypes=[W.HANDLE,C.c_int,C.c_int,C.c_int,C.POINTER(W.DWORD)];u.GetThemeColor.restype=C.c_long
    u.GetCurrentThemeName.argtypes=[W.LPWSTR,C.c_int,W.LPWSTR,C.c_int,W.LPWSTR,C.c_int];u.GetCurrentThemeName.restype=C.c_long
    def current():
        b=[C.create_unicode_buffer(1024) for _ in range(3)]
        hr=u.GetCurrentThemeName(b[0],1024,b[1],1024,b[2],1024)
        return dict(hr=f'{hr&0xffffffff:08x}',path=b[0].value,color=b[1].value,size=b[2].value)
    def colors(theme_file=None):
        ret={}
        open_file=C.WINFUNCTYPE(W.HANDLE,C.c_void_p,W.HWND,W.LPCWSTR,C.c_int)(k.GetProcAddress(u._handle,C.c_void_p(16)))
        for name,part,states in [('Button',1,[1,2,3,4,5]),('Edit',1,[1,4]),('ListView',1,[1,2,3,4,5]),('TreeView',1,[1,2,3,4,5]),('Toolbar',1,[1,2,3,4,5]),('Explorer::ListView',1,[1,2,3,4,5])]:
            h=open_file(theme_file,None,name,1) if theme_file else u.OpenThemeData(None,name);d={'handle':hex(h or 0),'values':{}};ret[name]=d
            if not h:continue
            for state in states:
                for prop in [3801,3802,3803,3810,3817,3821,3827]:
                    v=W.DWORD(0xfeedbeef);hr=u.GetThemeColor(h,part,state,prop,C.byref(v))
                    d['values'][f'{part}/{state}/{prop}']={'hr':f'{hr&0xffffffff:08x}','colorref':f'{v.value:08x}'}
            u.CloseThemeData(h)
        return ret
    def render(label,theme_file=None):
        from PIL import Image,ImageDraw
        g=C.WinDLL('gdi32',use_last_error=True)
        g.CreateCompatibleDC.argtypes=[W.HDC];g.CreateCompatibleDC.restype=W.HDC
        g.CreateDIBSection.argtypes=[W.HDC,C.c_void_p,W.UINT,C.POINTER(C.c_void_p),W.HANDLE,W.DWORD];g.CreateDIBSection.restype=W.HBITMAP
        g.SelectObject.argtypes=[W.HDC,W.HGDIOBJ];g.SelectObject.restype=W.HGDIOBJ
        g.DeleteObject.argtypes=[W.HGDIOBJ];g.DeleteDC.argtypes=[W.HDC]
        u.DrawThemeBackground.argtypes=[W.HANDLE,W.HDC,C.c_int,C.c_int,C.POINTER(W.RECT),C.c_void_p];u.DrawThemeBackground.restype=C.c_long
        opener=C.WINFUNCTYPE(W.HANDLE,C.c_void_p,W.HWND,W.LPCWSTR,C.c_int)(k.GetProcAddress(u._handle,C.c_void_p(16)))
        cases=[('Button',1),('Edit',1),('ListView',1),('TreeView',1),('Toolbar',1),('Header',1),('ScrollBar',1),('Explorer::ListView',1),('ItemsView::ListView',1),('Explorer::Header',1),('Explorer::CommandModule',1),('Window',1)]
        width,height=600,len(cases)*48
        bmi=C.create_string_buffer(40);vals=(C.c_uint32*10).from_buffer(bmi);vals[0]=40;vals[1]=width;vals[2]=(-height)&0xffffffff;vals[3]=1|(32<<16)
        dc=g.CreateCompatibleDC(None);bits=C.c_void_p();bmp=g.CreateDIBSection(dc,bmi,0,C.byref(bits),None,0);assert dc and bmp and bits.value
        prev=g.SelectObject(dc,bmp);C.memset(bits,255,width*height*4);report=[]
        for row,(name,part) in enumerate(cases):
            h=opener(theme_file,None,name,1) if theme_file else u.OpenThemeData(None,name)
            rowdata={'class':name,'handle':bool(h),'hr':[]}
            if h:
                for state in range(1,6):
                    x=state*92+60;y=row*48+8;r=W.RECT(x,y,x+80,y+30)
                    hr=u.DrawThemeBackground(h,dc,part,state,C.byref(r),None);rowdata['hr'].append(f'{hr&0xffffffff:08x}')
                u.CloseThemeData(h)
            report.append(rowdata)
        data=C.string_at(bits,width*height*4);g.SelectObject(dc,prev);g.DeleteObject(bmp);g.DeleteDC(dc)
        im=Image.frombytes('RGB',(width,height),data,'raw','BGRX');draw=ImageDraw.Draw(im)
        for row,(name,part) in enumerate(cases):draw.text((2,row*48+16),name,fill='black')
        dest=out.with_name(out.stem+'-'+label+'.png');im.save(dest)
        return {'path':str(dest),'pixelsSha256':hashlib.sha256(data).hexdigest(),'cases':report}
    result={'scope':'own disposable process only; no HWND, no global theme API','target':str(path),'before':current(),'native':colors(),'nativeRender':render('before'),'phase':'before loader'};save(result)
    buffers=[C.create_unicode_buffer(str(path)),C.create_unicode_buffer('NormalColor'),C.create_unicode_buffer('NormalSize')]
    params=C.create_string_buffer(0x80)
    C.c_uint32.from_buffer(params,0).value=0x58
    for offset,b in zip((8,0x10,0x18),buffers):C.c_void_p.from_buffer(params,offset).value=C.addressof(b)
    # Native 26100.6584 disassembly: struct[0x24]=forced DPI; 0 leaves normal DPI.
    # [0x44] loader flags=0, [0x48] forced high contrast=0, [0x50] output CUxThemeFile*.
    addr=k.GetProcAddress(u._handle,C.c_void_p(127));assert addr==u._handle+0x5f7c0
    fn=C.WINFUNCTYPE(C.c_long,C.c_void_p)(addr)
    hr=fn(C.byref(params));result.update(phase='loader returned',hr=f'{hr&0xffffffff:08x}',themeFile=hex(C.c_void_p.from_buffer(params,0x50).value or 0));save(result)
    if hr>=0:
        theme_file=C.c_void_p.from_buffer(params,0x50).value
        result['private']=colors(theme_file);result['privateRender']=render('private',theme_file)
        result['afterPublicRender']=render('after-public')
    result['after']=current();result['phase']='complete';save(result)
    return 0 if hr>=0 else 2
if __name__=='__main__':
    if '--worker' in sys.argv:raise SystemExit(worker(Path(sys.argv[2]),Path(sys.argv[3])))
    run=ROOT/'work'/('private-theme-proof-'+uuid.uuid4().hex[:12]);run.mkdir()
    summaries=[]
    for name,p in [('native',Path('C:/Windows/Resources/Themes/aero/aero.msstyles')),('old',OLD)]:
        out=run/(name+'.json')
        with (run/(name+'.stdout')).open('wb') as so,(run/(name+'.stderr')).open('wb') as se:
            child=subprocess.Popen([sys.executable,__file__,'--worker',str(p),str(out)],stdout=so,stderr=se,creationflags=subprocess.CREATE_NO_WINDOW)
            try:code=child.wait(timeout=25)
            except subprocess.TimeoutExpired:child.kill();child.wait();code='timeout'
        summaries.append(dict(name=name,exit=code,result=str(out),stderr=(run/(name+'.stderr')).read_text(errors='replace')))
    print(json.dumps(summaries,ensure_ascii=False,indent=2))
