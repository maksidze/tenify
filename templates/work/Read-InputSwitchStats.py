"""Read only adapter counters from an exact owned Explorer launch."""
from pathlib import Path
import ctypes as C
from ctypes import wintypes as W
import datetime, importlib.util, json, sys

run = Path(sys.argv[1]).resolve()
state = json.loads((run / 'status.json').read_text(encoding='utf-8-sig'))
base = Path(__file__).resolve().parent.parent / 'outputs/Windows10-Components'
spec = importlib.util.spec_from_file_location('input_adapter', base / 'Launch-InputSwitchCompat.py')
adapter = importlib.util.module_from_spec(spec); spec.loader.exec_module(adapter)
k = C.WinDLL('kernel32', use_last_error=True)
def bind(name, result, args):
    f = getattr(k, name); f.restype = result; f.argtypes = args; return f
open_process = bind('OpenProcess', C.c_void_p, [W.DWORD, W.BOOL, W.DWORD])
query_path = bind('QueryFullProcessImageNameW', W.BOOL, [C.c_void_p, W.DWORD, W.LPWSTR, C.POINTER(W.DWORD)])
read = bind('ReadProcessMemory', W.BOOL, [C.c_void_p, C.c_void_p, C.c_void_p, C.c_size_t, C.POINTER(C.c_size_t)])
times = bind('GetProcessTimes', W.BOOL, [C.c_void_p] + [C.POINTER(W.FILETIME)] * 4)
debug = bind('CheckRemoteDebuggerPresent', W.BOOL, [C.c_void_p, C.POINTER(W.BOOL)])
close = bind('CloseHandle', W.BOOL, [C.c_void_p])
if state['status'] != 'running' or state['preflight']:
    raise RuntimeError('Requires active interactive owned Explorer run')
handle = open_process(0x1410, False, state['pid'])
if not handle:
    raise C.WinError(C.get_last_error())
try:
    path = C.create_unicode_buffer(32768); size = W.DWORD(len(path))
    if not query_path(handle, 0, path, C.byref(size)):
        raise C.WinError(C.get_last_error())
    if Path(path.value).resolve() != (base / 'Runtime/Explorer10/explorer.exe').resolve():
        raise RuntimeError('Owned Explorer executable mismatch')
    created, ended, kernel, user = (W.FILETIME() for _ in range(4))
    if not times(handle, C.byref(created), C.byref(ended), C.byref(kernel), C.byref(user)):
        raise C.WinError(C.get_last_error())
    timestamp = ((created.dwHighDateTime << 32) | created.dwLowDateTime) / 1e7 - 11644473600
    recorded = datetime.datetime.fromisoformat(state['createdAt'].replace('Z', '+00:00')).timestamp()
    if abs(timestamp - recorded) > 10:
        raise RuntimeError('Owned process creation time mismatch')
    address = int(state['inputSwitchHook']['statsAddress'], 16)
    data = C.create_string_buffer(72); size_read = C.c_size_t()
    if not read(handle, address, data, 72, C.byref(size_read)) or size_read.value != 72:
        raise C.WinError(C.get_last_error())
    debugger = W.BOOL()
    if not debug(handle, C.byref(debugger)):
        raise C.WinError(C.get_last_error())
    result = {'pid': state['pid'], 'checkedAt': datetime.datetime.now(datetime.timezone.utc).isoformat(),
              'debuggerPresent': bool(debugger.value), 'stats': adapter.decode_stats(data.raw),
              'visibleOrientationVerified': False, 'readOnly': True}
    (run / 'input-switch-runtime.json').write_text(json.dumps(result, indent=2), encoding='utf-8')
    if len(sys.argv) == 4 and sys.argv[2] == '--taskview-host':
        import struct
        address = int(sys.argv[3], 16)
        data = C.create_string_buffer(0x310); size_read = C.c_size_t()
        if not read(handle, address, data, len(data), C.byref(size_read)) or size_read.value != len(data):
            raise C.WinError(C.get_last_error())
        events = [json.loads(line) for line in (run / 'manual-taskview-trace.jsonl').read_text(encoding='utf-8').splitlines()]
        bases = {int(x['base'], 16) for x in events if x['type'] == 'module' and x.get('path', '').lower().endswith('\\lab\\hostmultitaskingcompat\\twinui.pcshell.dll')}
        if len(bases) != 1 or struct.unpack_from('<Q', data.raw, 0)[0] != next(iter(bases)) + 0x892258:
            raise RuntimeError('TaskViewHost exact native vtable mismatch')
        frames_begin, frames_end = struct.unpack_from('<QQ', data.raw, 0x140)
        host = {'checkedAt': result['checkedAt'], 'pid': state['pid'], 'object': hex(address),
                'vtableVerified': True, 'framesBegin': hex(frames_begin), 'framesEnd': hex(frames_end),
                'frameCount': (frames_end - frames_begin) // 8,
                'monitorCount': struct.unpack_from('<I', data.raw, 0x2e0)[0],
                'state2e8': struct.unpack_from('<I', data.raw, 0x2e8)[0],
                'flag70': data.raw[0x70], 'readOnly': True}
        def read_bytes(address, size):
            buffer = C.create_string_buffer(size); length = C.c_size_t()
            if not read(handle, address, buffer, size, C.byref(length)) or length.value != size:
                raise C.WinError(C.get_last_error())
            return buffer.raw
        service_events = [x for x in events if x.get('label') == 'TaskView.ToggleService.Enter']
        service = int(service_events[-1]['registers']['rcx'], 16)
        service_data = read_bytes(service, 0x20)
        native_base = next(iter(bases))
        if struct.unpack_from('<Q', service_data)[0] != native_base + 0x700ff8:
            raise RuntimeError('Exact AllUpViewInvoker vtable mismatch')
        scheduler = struct.unpack_from('<Q', service_data, 0x10)[0]
        scheduler_data = read_bytes(scheduler, 0xa8)
        scheduler_vtable = struct.unpack_from('<Q', scheduler_data)[0]
        queue_method = struct.unpack('<Q', read_bytes(scheduler_vtable + 0x18, 8))[0]
        if queue_method != native_base + 0x21d50:
            raise RuntimeError('Exact scheduler QueueTask vtable mismatch')
        host['scheduler'] = {'object': hex(scheduler), 'queueMethodVerified': True,
                             'manager': hex(struct.unpack_from('<Q', scheduler_data, 0x40)[0]),
                             'taskPoolContext': hex(struct.unpack_from('<I', scheduler_data, 0xa0)[0])}
        import hashlib
        if hashlib.sha256(Path('C:/Windows/System32/SHCore.dll').read_bytes()).hexdigest() != 'a7c4b5669679ea96455ae20c69ffaeb25e9803d9b8e0f0af98d76c57327edb90':
            raise RuntimeError('Unsupported SHCore build')
        shcore_bases = {int(x['base'], 16) for x in events if x['type'] == 'module' and x.get('path', '').lower().endswith('\\windows\\system32\\shcore.dll')}
        if len(shcore_bases) != 1:
            raise RuntimeError('Ambiguous SHCore identity')
        shcore = next(iter(shcore_bases))
        head = struct.unpack('<Q', read_bytes(shcore + 0xda290, 8))[0]
        worker = head; visited = set(); workers = []
        while worker and worker not in visited and len(visited) < 128:
            visited.add(worker); raw = read_bytes(worker, 0xd8)
            if struct.unpack_from('<Q', raw)[0] != shcore + 0x9a108:
                raise RuntimeError('SHCore worker changed during non-atomic read')
            workers.append({'object': hex(worker), 'threadId': struct.unpack_from('<I', raw, 0x50)[0],
                            'currentContext': hex(struct.unpack_from('<I', raw, 0x98)[0]),
                            'currentTask': hex(struct.unpack_from('<Q', raw, 0xb0)[0]),
                            'queueFirst': hex(struct.unpack_from('<Q', raw, 0x18)[0]),
                            'queueSentinel': hex(worker + 0x18)})
            worker = struct.unpack_from('<Q', raw, 0x10)[0]
        host['shcoreWorkers'] = workers
        host['workersReadIsAtomic'] = False
        (run / 'taskview-host-state.json').write_text(json.dumps(host, indent=2), encoding='utf-8')
        result['taskViewHost'] = host
    print(json.dumps(result, indent=2))
finally:
    close(handle)
