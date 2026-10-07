"""Run an existing controller inside an inherited, verified package identity.

Only the new process is affected. The caller owns shell recovery and lifetime.
"""
import ctypes
import json
import os
from pathlib import Path
import runpy
import sys
import time


def main():
    handshake, nonce, expected_family, controller, run_directory = sys.argv[1:6]
    arguments = sys.argv[6:]
    run = Path(run_directory).resolve()
    sys.stdout = open(run / 'helper.stdout.log', 'a', encoding='utf-8', buffering=1)
    sys.stderr = open(run / 'helper.stderr.log', 'a', encoding='utf-8', buffering=1)
    kernel = ctypes.WinDLL('kernel32', use_last_error=True)
    identity = {}
    for api in ('GetCurrentPackageFullName', 'GetCurrentPackageFamilyName'):
        function = getattr(kernel, api)
        function.argtypes = [ctypes.POINTER(ctypes.c_uint32), ctypes.c_wchar_p]
        function.restype = ctypes.c_long
        length = ctypes.c_uint32()
        error = function(ctypes.byref(length), None)
        if error != 122:
            raise RuntimeError(f'{api}: {error}; package identity is required')
        buffer = ctypes.create_unicode_buffer(length.value)
        error = function(ctypes.byref(length), buffer)
        if error:
            raise RuntimeError(f'{api}: {error}')
        identity[api] = buffer.value
    if identity['GetCurrentPackageFamilyName'].casefold() != expected_family.casefold():
        raise RuntimeError('Package family mismatch')
    controller = str(Path(controller).resolve())
    os.chdir(Path(controller).parent)
    state = dict(nonce=nonce, helperPid=os.getpid(), python=sys.executable,
                 controller=controller, runDirectory=str(run), arguments=arguments,
                 packageFullName=identity['GetCurrentPackageFullName'],
                 packageFamilyName=identity['GetCurrentPackageFamilyName'],
                 createdAt=time.time())
    temporary = Path(handshake + '.tmp')
    temporary.write_text(json.dumps(state, indent=2), encoding='utf-8')
    os.replace(temporary, handshake)
    sys.argv = [controller, *arguments]
    # The controller runs in this same process, so the returned Process handle
    # remains the actual VFS controller throughout the Explorer child lifetime.
    runpy.run_path(controller, run_name='__main__')


if __name__ == '__main__':
    main()
