param(
    [ValidateSet('Status','Square','Restore','Watch','Library')][string]$Action='Status',
    [int]$TargetProcessId=0,
    [ValidateRange(0,86400)][int]$WatchSeconds=0,
    [string]$StatePath=(Join-Path $PSScriptRoot 'state.json')
)
$ErrorActionPreference='Stop'
Add-Type -TypeDefinition @'
using System;
using System.Text;
using System.Collections.Generic;
using System.Runtime.InteropServices;
public static class SquareWindows {
 public delegate bool EnumProc(IntPtr h, IntPtr p);
 [DllImport("user32.dll")] public static extern bool EnumWindows(EnumProc p, IntPtr x);
 [DllImport("user32.dll")] public static extern bool IsWindow(IntPtr h);
 [DllImport("user32.dll")] public static extern bool IsWindowVisible(IntPtr h);
 [DllImport("user32.dll")] public static extern uint GetWindowThreadProcessId(IntPtr h,out uint pid);
 [DllImport("user32.dll",CharSet=CharSet.Unicode)] static extern int GetClassName(IntPtr h,StringBuilder b,int n);
 [DllImport("user32.dll",CharSet=CharSet.Unicode)] public static extern bool SetProp(IntPtr h,string n,IntPtr v);
 [DllImport("user32.dll",CharSet=CharSet.Unicode)] public static extern IntPtr GetProp(IntPtr h,string n);
 [DllImport("user32.dll",CharSet=CharSet.Unicode)] public static extern IntPtr RemoveProp(IntPtr h,string n);
 [DllImport("dwmapi.dll")] public static extern int DwmGetWindowAttribute(IntPtr h,int a,out int v,int n);
 [DllImport("dwmapi.dll")] public static extern int DwmSetWindowAttribute(IntPtr h,int a,ref int v,int n);
 public static string Class(IntPtr h){var b=new StringBuilder(256);GetClassName(h,b,256);return b.ToString();}
 public static long[] Windows(){var a=new List<long>();EnumWindows((h,p)=>{if(IsWindowVisible(h))a.Add(h.ToInt64());return true;},IntPtr.Zero);return a.ToArray();}
}
'@
$propName='Codex.WindowStyle.Baseline.v1'
function Save-Journal($entries) {
    $parent=Split-Path -Parent $StatePath
    if($parent){New-Item -ItemType Directory -Force -Path $parent | Out-Null}
    $tmp=$StatePath+'.tmp'
    ConvertTo-Json -InputObject @($entries) -Depth 5 | Set-Content -LiteralPath $tmp -Encoding UTF8
    Move-Item -LiteralPath $tmp -Destination $StatePath -Force
}
function Read-Journal {
    if(Test-Path -LiteralPath $StatePath){foreach($e in @(Get-Content -LiteralPath $StatePath -Raw | ConvertFrom-Json)){if($null -ne $e){$e}}}
}
function Get-Identity([long]$handle) {
    $h=[IntPtr]$handle
    if(-not [SquareWindows]::IsWindow($h)){return}
    [uint32]$ownerPid=0
    $tid=[SquareWindows]::GetWindowThreadProcessId($h,[ref]$ownerPid)
    try{$p=Get-Process -Id $ownerPid -ErrorAction Stop; $ticks=$p.StartTime.ToUniversalTime().Ticks}catch{return}
    [pscustomobject]@{Handle=$handle;Pid=[int]$ownerPid;Thread=[long]$tid;Started=[string]$ticks;Class=[SquareWindows]::Class($h)}
}
function Same-Identity($a,$b) {
    $null -ne $b -and $a.Handle -eq $b.Handle -and $a.Pid -eq $b.Pid -and $a.Thread -eq $b.Thread -and $a.Started -eq $b.Started -and $a.Class -ceq $b.Class
}
function Get-Candidates {
    foreach($handle in [SquareWindows]::Windows()) {
        $id=Get-Identity $handle
        if($null -eq $id){continue}
        if($TargetProcessId -gt 0 -and $id.Pid -ne $TargetProcessId){continue}
        if($id.Class -match '^(Progman|WorkerW|Shell_TrayWnd|Shell_SecondaryTrayWnd|DV2ControlHost|Windows\.UI\.Core\.CoreWindow|XamlExplorerHostIslandWindow|MultitaskingViewFrame|DummyDWMListenerWindow|EdgeUiInputTopWndClass|Dwm|#32768)$'){continue}
        try{$name=(Get-Process -Id $id.Pid -ErrorAction Stop).ProcessName}catch{continue}
        if($name -eq 'explorer' -and $id.Class -notmatch '^(CabinetWClass|ExploreWClass|#32770)$'){continue}
        if($name -match '^(dwm|csrss|winlogon|ShellExperienceHost|StartMenuExperienceHost|ShellHost|LockApp|SearchHost|TextInputHost)$'){continue}
        $id
    }
}
function Show-Status {
    foreach($id in Get-Candidates) {
        [int]$v=0;$hr=[SquareWindows]::DwmGetWindowAttribute([IntPtr]$id.Handle,33,[ref]$v,4)
        [pscustomobject]@{Handle=$id.Handle;Pid=$id.Pid;Class=$id.Class;Preference=$v;HRESULT=('0x{0:X8}' -f $hr)}
    }
}
function Set-Square {
    $entries=@(Read-Journal | Where-Object {
        (Same-Identity $_ (Get-Identity $_.Handle)) -and [SquareWindows]::GetProp([IntPtr][long]$_.Handle,$propName).ToInt64() -eq [long]$_.Token
    })
    Save-Journal $entries
    foreach($id in Get-Candidates) {
        if(@($entries | Where-Object {Same-Identity $_ $id}).Count){continue}
        $h=[IntPtr]$id.Handle
        if([SquareWindows]::GetProp($h,$propName) -ne [IntPtr]::Zero){Write-Warning "Window $($id.Handle): owned by another helper; skipped.";continue}
        [int]$old=0
        $hr=[SquareWindows]::DwmGetWindowAttribute($h,33,[ref]$old,4)
        if($hr -ne 0){Write-Warning "Get attribute failed for $($id.Handle): $hr";continue}
        $token=Get-Random -Minimum 1 -Maximum 2147483647
        $entry=[pscustomobject]@{Handle=$id.Handle;Pid=$id.Pid;Thread=$id.Thread;Started=$id.Started;Class=$id.Class;Original=$old;Token=$token;Applied=$false}
        $entries+= $entry
        Save-Journal $entries # Durable baseline before changing the window.
        if(-not (Same-Identity $entry (Get-Identity $entry.Handle)) -or -not [SquareWindows]::SetProp($h,$propName,[IntPtr]$token)) {
            $entries=@($entries | Where-Object {$_ -ne $entry});Save-Journal $entries;continue
        }
        if(-not (Same-Identity $entry (Get-Identity $entry.Handle))){continue}
        [int]$v=1;$hr=[SquareWindows]::DwmSetWindowAttribute($h,33,[ref]$v,4)
        [int]$actual=0;$verify=[SquareWindows]::DwmGetWindowAttribute($h,33,[ref]$actual,4)
        $entry.Applied=($hr -eq 0 -and $verify -eq 0 -and $actual -eq 1)
        Save-Journal $entries
        Write-Output "Window $($entry.Handle), PID $($entry.Pid): Set=$hr Get=$verify preference=$actual saved=$old"
    }
}
function Restore-Windows {
    $remaining=@()
    foreach($entry in @(Read-Journal)) {
        if($TargetProcessId -gt 0 -and $entry.Pid -ne $TargetProcessId){$remaining+=$entry;continue}
        $h=[IntPtr][long]$entry.Handle
        if(-not (Same-Identity $entry (Get-Identity $entry.Handle))){Write-Output "Window $($entry.Handle): closed/reused, skipped.";continue}
        if([SquareWindows]::GetProp($h,$propName).ToInt64() -ne [long]$entry.Token){Write-Output "Window $($entry.Handle): token absent/changed, skipped.";continue}
        [int]$current=0;$get=[SquareWindows]::DwmGetWindowAttribute($h,33,[ref]$current,4)
        if($get -ne 0){$remaining+=$entry;continue}
        if($current -ne 1 -and $current -ne $entry.Original){Write-Warning "Window $($entry.Handle): application changed its preference; keeping it."}
        elseif($current -ne $entry.Original) {
            [int]$v=$entry.Original;$hr=[SquareWindows]::DwmSetWindowAttribute($h,33,[ref]$v,4)
            [int]$actual=0;$verify=[SquareWindows]::DwmGetWindowAttribute($h,33,[ref]$actual,4)
            if($hr -ne 0 -or $verify -ne 0 -or $actual -ne $v){$remaining+=$entry;Write-Warning "Restore failed for $($entry.Handle): $hr/$verify";continue}
            Write-Output "Window $($entry.Handle): restored preference=$actual"
        }
        [void][SquareWindows]::RemoveProp($h,$propName)
    }
    Save-Journal $remaining
}
if($Action -eq 'Library'){return}
$sha=[Security.Cryptography.SHA256]::Create()
try{$hash=[BitConverter]::ToString($sha.ComputeHash([Text.Encoding]::UTF8.GetBytes([IO.Path]::GetFullPath($StatePath).ToLowerInvariant()))).Replace('-','')}finally{$sha.Dispose()}
$mutex=New-Object Threading.Mutex($false,('Local\CodexWindowStyle_'+$hash))
$locked=$false
try {
    try{$locked=$mutex.WaitOne(0)}catch [Threading.AbandonedMutexException]{$locked=$true}
    if(-not $locked){throw 'Another WindowStyle operation is running. Stop Watch with Ctrl+C before Restore.'}
    switch($Action) {
    Status {Show-Status | Format-Table -AutoSize}
    Square {Set-Square}
    Restore {Restore-Windows}
    Watch {
        if(@(Read-Journal).Count){throw 'Restore existing changes before starting Watch.'}
        $deadline=if($WatchSeconds -gt 0){(Get-Date).AddSeconds($WatchSeconds)}else{[DateTime]::MaxValue}
        Write-Output 'Watching new visible windows. Ctrl+C stops and restores. Closing this terminal forcibly requires Restore.bat.'
        try{while((Get-Date) -lt $deadline){Set-Square;Start-Sleep -Seconds 1}}finally{Restore-Windows}
    }
    }
} finally {
    if($locked){$mutex.ReleaseMutex()}
    $mutex.Dispose()
}
