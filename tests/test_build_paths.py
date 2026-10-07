import importlib.util,os,sys,tempfile,unittest
from pathlib import Path
sys.path.insert(0,str(Path(__file__).resolve().parents[1]/'tools'))
import build
class BuildPaths(unittest.TestCase):
 def test_containment(self):
  with tempfile.TemporaryDirectory() as t:
   root=Path(t)
   self.assertEqual(build.under(root,'a/b'),root/'a/b')
   with self.assertRaises(RuntimeError):build.under(root,'../outside')
 def test_windows_path_tokens(self):
  root=Path('C:/Users/Example/Runtime');python=Path('C:/Tools/Python/python.exe')
  self.assertIn('C:/Users/Example/Runtime',build.expand('@WORKSPACE@',root,python))
  self.assertEqual(build.expand('@WORKSPACE_ESC@',root,python),str(root).replace('\\','\\\\'))
 def test_hash_replacement_bytes(self):
  old='aa'*32;new='bb'*32
  self.assertEqual(build.replace_hashes(','.join(['0xaa']*32),{old:new}),','.join(['0xbb']*32))
 def test_wrong_host_rejected_before_writes(self):
  original=build.read
  try:
   build.read=lambda _: {'System32/does-not-exist-b013.dll':'00'*32}
   with self.assertRaisesRegex(RuntimeError,'Unsupported Windows11'):build.host_check()
  finally:build.read=original
if __name__=='__main__':unittest.main()
