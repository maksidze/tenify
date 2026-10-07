import json
import unittest
from pathlib import Path

class SettingsDependencyTests(unittest.TestCase):
    def test_caption_environment_is_extracted_copied_pinned_and_granted(self):
        root=Path(__file__).resolve().parents[1]
        source='Windows/System32/SettingsEnvironment.Desktop.dll'
        target='outputs/Windows10-Components/Lab/SettingsDynamicTextCompat/IsolatedOld/SettingsEnvironment.Desktop.dll'
        media=json.loads((root/'packaging/media-files.json').read_text())
        copies=json.loads((root/'packaging/copy-artifacts.json').read_text())
        item=next(e for e in copies if e['Output']==target)
        self.assertEqual(item['Source'],source)
        self.assertEqual(item['SHA256'],media[source])
        for name in ['manifest.json','source-paths.json']:
            data=json.loads((root/'templates/outputs/Windows10-Components/Lab/SettingsNoVfsSessionCompat'/name).read_text())
            entry=next(e for e in data['Files'] if e['Path'].endswith(target.replace('/','\\')))
            self.assertEqual(entry['SHA256'],media[source])

    def test_old_taskbar_resources_and_power_provider_are_granted(self):
        root=Path(__file__).resolve().parents[1]
        paths=['Windows/SystemResources/Windows.UI.SettingsHandlers-nt/Windows.UI.SettingsHandlers-nt.pri','Windows/SystemResources/Windows.UI.SettingsHandlers-nt/pris/Windows.UI.SettingsHandlers-nt.ru-RU.pri','Windows/System32/SettingsHandlers_OneCore_PowerAndSleep.dll']
        media=json.loads((root/'packaging/media-files.json').read_text())
        for name in ['manifest.json','source-paths.json']:
            data=json.loads((root/'templates/outputs/Windows10-Components/Lab/SettingsNoVfsSessionCompat'/name).read_text())
            for path in paths:
                entry=next(e for e in data['Files'] if e['Path'].endswith(path.replace('/','\\')))
                self.assertEqual(entry['SHA256'],media[path])
