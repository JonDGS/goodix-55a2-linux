import importlib.util,struct,tempfile,unittest
from pathlib import Path
P=Path(__file__).parents[1]/'tools'/'goodix_small_inbound_envelopes.py'
def load():
 s=importlib.util.spec_from_file_location('goodix_small_inbound_envelopes',P);assert s and s.loader
 m=importlib.util.module_from_spec(s);s.loader.exec_module(m);return m
def rec(endpoint,payload):return struct.pack('<HQIHBHHBBI',27,1,0,9,1,2,3,endpoint,3,len(payload))+payload
class Tests(unittest.TestCase):
 def test_reads_only_small_inbound_outer_header(self):
  m=load();g=struct.pack('<IHHIIII',0xA1B2C3D4,2,4,0,0,65535,249)
  small=rec(0x82,bytes([0xa0,6,0,0xa6])+b'body');large=rec(0x82,b'x'*100)
  blob=g+struct.pack('<IIII',1,0,len(small),len(small))+small+struct.pack('<IIII',2,0,len(large),len(large))+large
  with tempfile.NamedTemporaryFile(suffix='.pcap') as f:
   f.write(blob);f.flush();o=m.inspect_small_inbound_envelopes(Path(f.name))
  self.assertEqual(o['envelope_count'],1);i=o['envelopes'][0]
  self.assertEqual(i['flags'],'0xa0');self.assertEqual(i['declared_length'],6);self.assertNotIn('body',i);self.assertNotIn('payload',i)
if __name__=='__main__':unittest.main()
