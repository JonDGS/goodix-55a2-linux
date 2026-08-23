import importlib.util
import struct
import tempfile
import unittest
from pathlib import Path

MODULE_PATH = Path(__file__).parents[1] / "tools" / "goodix_outbound_envelopes.py"

def load_module():
    spec=importlib.util.spec_from_file_location("goodix_outbound_envelopes", MODULE_PATH)
    assert spec and spec.loader
    module=importlib.util.module_from_spec(spec); spec.loader.exec_module(module)
    return module

def record(endpoint, payload):
    h=struct.pack("<HQIHBHHBBI",27,1,0,9,0,2,3,endpoint,3,len(payload))
    return h+payload

class EnvelopeTests(unittest.TestCase):
    def test_reports_only_four_byte_outer_header_for_outbound_messages(self):
        module=load_module()
        gh=struct.pack("<IHHIIII",0xA1B2C3D4,2,4,0,0,65535,249)
        outbound=record(0x01,bytes([0xA0,0x3C,0x00,0x5A])+b"sensitive-body")
        inbound=record(0x82,b"inbound-data")
        content=gh+struct.pack("<IIII",1,0,len(outbound),len(outbound))+outbound+struct.pack("<IIII",2,0,len(inbound),len(inbound))+inbound
        with tempfile.NamedTemporaryFile(suffix='.pcap') as f:
            f.write(content);f.flush(); result=module.inspect_outbound_envelopes(Path(f.name))
        self.assertEqual(result['envelope_count'],1)
        item=result['envelopes'][0]
        self.assertEqual(item['flags'],'0xa0')
        self.assertEqual(item['declared_length'],60)
        self.assertEqual(item['checksum'],'0x5a')
        self.assertNotIn('payload',item)
        self.assertNotIn('body',item)
if __name__=='__main__': unittest.main()
