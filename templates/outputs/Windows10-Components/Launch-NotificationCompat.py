"""Adapt ISO Explorer's private notification callback to the host record ABI.

Only a new, owned, entrypoint-paused child is accepted. No file is modified.
The host NotificationControllerPS remains native; callbacks still execute.
"""
import hashlib
import os
from pathlib import Path

EXPLORER_SHA256 = 'b059f455b37047f4e2b5eae01b21715e4baa304888ac31e44905b41ff6bbcbd0'
HOST_PROXY_SHA256 = '43cd9b9cc26b767b362aa89e754b4a1e96496ee108711dc049c7dbe74b56d240'
PATCHES = (
    (0x27529e, bytes.fromhex('4d8db088000000'), bytes.fromhex('4d8db0a0000000'), 'NOC_GROUP pointer +0x88 -> +0xa0'),
    (0x2752a5, bytes.fromhex('41f646d801'), bytes.fromhex('41f646d001'), 'flags: r14-0x28 -> r14-0x30, record +0x70'),
    (0x275333, bytes.fromhex('4981c658010000'), bytes.fromhex('4981c670010000'), 'record stride 0x158 -> 0x170'),
)

def install_notification_hook(bootstrap):
    if not bootstrap.primary_suspended or not bootstrap.entry_restored or not bootstrap.image_base:
        raise RuntimeError('Notification adapter requires owned child paused at restored entrypoint')
    digest=hashlib.sha256(bootstrap.exe.read_bytes()).hexdigest()
    if digest!=EXPLORER_SHA256:
        raise RuntimeError('Unsupported Explorer build for notification adapter: '+digest)
    host_proxy=Path(os.environ['SystemRoot'])/'System32/NotificationControllerPS.dll'
    if hashlib.sha256(host_proxy.read_bytes()).hexdigest()!=HOST_PROXY_SHA256:
        raise RuntimeError('Unsupported host NotificationControllerPS build for notification adapter')
    # Validate the entire set before touching any instruction.
    for rva,old,new,note in PATCHES:
        actual=bootstrap.read(bootstrap.image_base+rva,len(old))
        if actual!=old:
            raise RuntimeError('Notification adapter expected bytes mismatch at '+hex(rva))
    applied=[]
    try:
        for rva,old,new,note in PATCHES:
            bootstrap.patch(bootstrap.image_base+rva,new,executable=True)
            applied.append((rva,old))
            if bootstrap.read(bootstrap.image_base+rva,len(new))!=new:
                raise RuntimeError('Notification adapter verification failed at '+hex(rva))
    except Exception:
        for rva,old in reversed(applied):
            bootstrap.patch(bootstrap.image_base+rva,old,executable=True)
        raise
    result={'type':'notificationCompat','pid':int(bootstrap.pi.pid),'explorerSha256':digest,
            'callbackRva':'0x275270','changes':[{'rva':hex(r),'before':o.hex(),'after':n.hex(),'reason':note} for r,o,n,note in PATCHES]}
    bootstrap.events.append(result)
    if bootstrap.observer:bootstrap.observer(result)
    return result
