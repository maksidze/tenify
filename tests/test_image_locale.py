import sys,unittest,xml.etree.ElementTree as ET
from pathlib import Path
sys.path.insert(0,str(Path(__file__).resolve().parents[1]/'tools'))
from image_locale import image_languages,localized_path,resource_file
class Locale(unittest.TestCase):
 def test_russian(self):
  w=ET.fromstring('<WINDOWS><LANGUAGES><LANGUAGE>ru-RU</LANGUAGE><DEFAULT>ru-RU</DEFAULT></LANGUAGES></WINDOWS>')
  self.assertEqual(image_languages(w),('ru-RU',['ru-RU']))
 def test_english_primary_in_multilanguage_image(self):
  w=ET.fromstring('<WINDOWS><LANGUAGES><LANGUAGE>ru-RU</LANGUAGE><LANGUAGE>en-US</LANGUAGE><DEFAULT>en-US</DEFAULT></LANGUAGES></WINDOWS>')
  self.assertEqual(image_languages(w)[0],'en-US')
  self.assertEqual(localized_path('Windows/ru-RU/explorer.exe.mui','en-US'),'Windows/en-US/explorer.exe.mui')
  self.assertEqual(localized_path('pris/Test.ru-RU.pri','en-US'),'pris/Test.en-US.pri')
 def test_invalid_language_refused(self):
  with self.assertRaises(RuntimeError):image_languages(ET.fromstring('<WINDOWS><LANGUAGES><DEFAULT>../../evil</DEFAULT></LANGUAGES></WINDOWS>'))
 def test_abi_files_are_not_resources(self):
  self.assertFalse(resource_file('SystemSettings.dll'))
  self.assertTrue(resource_file('SystemSettings.exe.mui'))
if __name__=='__main__':unittest.main()
