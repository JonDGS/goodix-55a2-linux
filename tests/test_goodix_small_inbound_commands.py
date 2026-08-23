import importlib.util,struct,tempfile,unittest
from pathlib import Path
P=Path(__file__).parents[1]/'tools'/'goodix_small_inbound_commands.py'
def load():
 s=importlib.util.spec_from_file_location('goodix_small_inbound_commands',P);assert s and s.loader
 m=importlib.util.module_from_spec(s);s.loader.exec_module(m);return m
class T(unittest.TestCase):
 def test_emits_split_reply_command_without_raw_byte_or_body(self):
  m=load();g=struct.pack('<IHHIIII',0xA1B2C3D4,2,4,0,0,65535,249)
  p=bytes([0xa0,6,0,0xa6,0xb0])+b'body'
  r=struct.pack('<HQIHBHHBBI',27,1,0,9,1,2,3,0x82,3,len(p))+p
  blob=g+struct.pack('<IIII',1,0,len(r),len(r))+r
  with tempfile.NamedTemporaryFile(suffix='.pcap') as f:f.write(blob);f.flush();o=m.classify_small_inbound_commands(Path(f.name))
  x=o['commands'][0];self.assertEqual((x['category'],x['command']),(11,0));self.assertNotIn('raw_command',x);self.assertNotIn('body',x)
if __name__=='__main__':unittest.main()
