from pathlib import Path
import subprocess
H=Path(__file__).resolve().parent;R=H.parents[3];z=R/'work/compat-research/toolchain/zig-x86_64-windows-0.15.2/zig.exe'
cmd=[str(z),'c++','-target','x86_64-windows-gnu','-O2','-std=c++17','-shared',str(H/'WinXCompat.Immersive.cpp'),'-o',str(H/'WinXCompat.Immersive.dll'),'-lole32','-luuid','-lapi-ms-win-core-winrt-string-l1-1-0','-lapi-ms-win-core-winrt-l1-1-0','-luser32','-lshell32','-lbcrypt','-lpsapi']
r=subprocess.run(cmd,capture_output=True,creationflags=subprocess.CREATE_NO_WINDOW,timeout=90);(H/'native-build.log').write_bytes(r.stdout+r.stderr);assert r.returncode==0
# Rebuild invalidates pinned artifacts; rerun owncombined fixture and refresh NEW manifests before use.
