import importlib.util, struct, tempfile, unittest
from pathlib import Path
MODULE_PATH=Path(__file__).parents[1]/'tools'/'goodix_outbound_commands.py'
def load_module():
 spec=importlib.util.spec_from_file_location('goodix_outbound_commands',MODULE_PATH);assert spec and spec.loader
 m=importlib.util.module_from_spec(spec);spec.loader.exec_module(m);return m
def rec(payload): return struct.pack('<HQIHBHHBBI',27,1,0,9,0,2,3,1,3,len(payload))+payload
class CommandTests(unittest.TestCase):
 def test_emits_command_fields_without_raw_command_or_body(self):
  m=load_module();gh=struct.pack('<IHHIIII',0xA1B2C3D4,2,4,0,0,65535,249)
  payload=bytes([0xa0,7,0,0xa7,0xd2])+b'sensitive'
  blob=gh+struct.pack('<IIII',1,0,len(rec(payload)),len(rec(payload)))+rec(payload)
  with tempfile.NamedTemporaryFile(suffix='.pcap') as f:
   f.write(blob);f.flush();out=m.classify_outbound_commands(Path(f.name))
  item=out['commands'][0]
  self.assertEqual(item['category'],13);self.assertEqual(item['command'],1);self.assertFalse(item['lsb_set'])
  self.assertNotIn('command_byte',item);self.assertNotIn('payload',item);self.assertNotIn('body',item)
if __name__=='__main__':unittest.main()
