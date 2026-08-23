#!/usr/bin/env python3
"""Inspect only four-byte Goodix outer envelopes in outbound USBPcap bulk data."""
import argparse,json,struct
from pathlib import Path
MAGIC=b'\xd4\xc3\xb2\xa1'; FMT='<HQIHBHHBBI'; HLEN=struct.calcsize(FMT)
def inspect_outbound_envelopes(path:Path)->dict:
    size=path.stat().st_size; envelopes=[]; record_index=0
    with path.open('rb') as f:
        if f.read(4)!=MAGIC: raise ValueError('expected little-endian microsecond classic PCAP')
        rest=f.read(20)
        if len(rest)!=20 or struct.unpack('<HHIIII',rest)[-1]!=249: raise ValueError('expected USBPcap linktype 249')
        while p:=f.read(16):
            if len(p)!=16: raise ValueError('truncated PCAP packet header')
            _,_,included,_=struct.unpack('<IIII',p);record_index+=1
            if included<HLEN: raise ValueError('USBPcap record shorter than base header')
            raw=f.read(HLEN)
            if len(raw)!=HLEN: raise ValueError('truncated USBPcap header')
            hlen,_irp,_status,_function,info,bus,device,endpoint,transfer,length=struct.unpack(FMT,raw)
            if hlen<HLEN or hlen>included: raise ValueError('invalid USBPcap header length')
            remaining=included-HLEN
            if transfer==3 and endpoint==1 and not info&1 and length>=4 and remaining>=4:
                outer=f.read(4); remaining-=4
                flags,declared,checksum=outer[0],int.from_bytes(outer[1:3],'little'),outer[3]
                envelopes.append({'record_index':record_index,'bus':bus,'device':device,'flags':f'0x{flags:02x}','declared_length':declared,'checksum':f'0x{checksum:02x}'})
            f.seek(remaining,1)
            if f.tell()>size: raise ValueError('truncated PCAP record')
    return {'format':'goodix-outbound-envelope-index','envelope_count':len(envelopes),'envelopes':envelopes}
def main():
    p=argparse.ArgumentParser(description='Read only four-byte outbound Goodix envelope headers; never emit bodies.')
    p.add_argument('capture',type=Path);print(json.dumps(inspect_outbound_envelopes(p.parse_args().capture),indent=2))
if __name__=='__main__':main()
