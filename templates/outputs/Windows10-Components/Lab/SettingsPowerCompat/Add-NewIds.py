from pathlib import Path
p=Path('outputs/Windows10-Components/Lab/SettingsPowerCompat/ItemProbe.cs');s=p.read_text(encoding='utf-8-sig').replace('"SystemSettings_Taskbar_Location"','"SystemSettings_Taskbar_Location","SystemSettings_PowerTimeouts_DisplayOff_AC","SystemSettings_PowerTimeouts_Sleep_AC","SystemSettings_PowerTimeouts_DisplayOff_DC"');p.write_text(s)
