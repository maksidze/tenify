import sys,unittest
from pathlib import Path
sys.path.insert(0,str(Path(__file__).resolve().parents[1]/'tools'))
from signatures import matches,parse
class Signatures(unittest.TestCase):
 def test_mask_and_shift(self):
  pattern='01 02 03 04 ?? ? 07 08 09 0A'
  self.assertEqual(matches(b'prefix'+bytes([1,2,3,4,99,88,7,8,9,10]),pattern),[6])
 def test_duplicates_are_observable(self):
  data=bytes(range(12));p='00 01 02 03 ?? ?? 06 07 08 09'
  self.assertEqual(matches(data+data,p),[0,12])
 def test_changed_fixed_byte_rejected(self):
  self.assertEqual(matches(bytes(range(12)),'00 01 FF 03 ?? ?? 06 07 08 09'),[])
 def test_underconstrained_rejected(self):
  with self.assertRaises(ValueError):parse('AA BB ?? ?? CC DD')
if __name__=='__main__':unittest.main()
