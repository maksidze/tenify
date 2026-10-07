"""Own hidden top-level window for ordinary session-end cleanup; no user input."""
import ctypes as C, threading, time
from ctypes import wintypes as W
from pathlib import Path

class SessionEndObserver:
    def __init__(self,cancel,restored):
        self.cancel=Path(cancel);self.restored=Path(restored);self.ready=threading.Event();self.error=None;self.tid=0
        self.thread=threading.Thread(target=self._run,name='StartSessionEndObserver',daemon=True)
        self.thread.start()
        if not self.ready.wait(5) or self.error:raise RuntimeError('Session-end observer failed: '+str(self.error))
    def _run(self):
        u=C.WinDLL('user32',use_last_error=True);k=C.WinDLL('kernel32',use_last_error=True)
        callback=C.WINFUNCTYPE(C.c_ssize_t,W.HWND,W.UINT,W.WPARAM,W.LPARAM)
        class WC(C.Structure):
            _fields_=[('style',W.UINT),('proc',callback),('extra',C.c_int),('wndextra',C.c_int),('instance',W.HINSTANCE),('icon',W.HICON),('cursor',W.HANDLE),('brush',W.HBRUSH),('menu',W.LPCWSTR),('name',W.LPCWSTR)]
        class MSG(C.Structure):
            _fields_=[('window',W.HWND),('message',W.UINT),('wparam',W.WPARAM),('lparam',W.LPARAM),('time',W.DWORD),('point',W.POINT),('private',W.DWORD)]
        k.GetCurrentThreadId.restype=W.DWORD;k.GetModuleHandleW.restype=W.HINSTANCE;k.GetModuleHandleW.argtypes=[W.LPCWSTR]
        u.DefWindowProcW.restype=C.c_ssize_t;u.DefWindowProcW.argtypes=[W.HWND,W.UINT,W.WPARAM,W.LPARAM]
        u.RegisterClassW.restype=W.ATOM;u.RegisterClassW.argtypes=[C.POINTER(WC)]
        u.CreateWindowExW.restype=W.HWND;u.CreateWindowExW.argtypes=[W.DWORD,W.LPCWSTR,W.LPCWSTR,W.DWORD,C.c_int,C.c_int,C.c_int,C.c_int,W.HWND,W.HMENU,W.HINSTANCE,C.c_void_p]
        u.DestroyWindow.argtypes=[W.HWND];u.UnregisterClassW.argtypes=[W.LPCWSTR,W.HINSTANCE]
        u.GetMessageW.argtypes=[C.POINTER(MSG),W.HWND,W.UINT,W.UINT];u.DispatchMessageW.argtypes=[C.POINTER(MSG)];u.DispatchMessageW.restype=C.c_ssize_t
        @callback
        def proc(window,msg,wp,lp):
            if msg==0x11 or (msg==0x16 and wp):
                self.cancel.write_text('session-end',encoding='utf-8')
                # Let the independent guard disable registration while the OS is
                # still allowing session-end processing. Never veto sign-out.
                if msg==0x11:
                    end=time.monotonic()+4
                    while time.monotonic()<end and not self.restored.exists():time.sleep(.05)
                return 1
            return u.DefWindowProcW(window,msg,wp,lp)
        window=None;atom=0;instance=k.GetModuleHandleW(None);name='Start10SessionEnd_'+str(id(self))
        try:
            self.tid=k.GetCurrentThreadId();wc=WC();wc.proc=proc;wc.instance=instance;wc.name=name
            atom=u.RegisterClassW(C.byref(wc))
            if not atom:raise C.WinError(C.get_last_error())
            # Hidden top-level window receives WM_QUERYENDSESSION. A message-only
            # window would not receive that broadcast. No WS_VISIBLE is supplied.
            window=u.CreateWindowExW(0,name,'',0,0,0,0,0,None,None,instance,None)
            if not window:raise C.WinError(C.get_last_error())
            self.ready.set();message=MSG()
            while u.GetMessageW(C.byref(message),None,0,0)>0:u.DispatchMessageW(C.byref(message))
        except Exception as e:self.error=str(e);self.ready.set()
        finally:
            if window:u.DestroyWindow(window)
            if atom:u.UnregisterClassW(name,instance)
    def close(self):
        u=C.WinDLL('user32',use_last_error=True);u.PostThreadMessageW.argtypes=[W.DWORD,W.UINT,W.WPARAM,W.LPARAM]
        if self.tid:u.PostThreadMessageW(self.tid,0x12,0,0)
        self.thread.join(timeout=5)
        if self.thread.is_alive():raise RuntimeError('Own session observer did not stop')
