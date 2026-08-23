#!/usr/bin/env python3
"""Inspect only four-byte envelopes of small Goodix IN replies."""
import argparse,json,struct
from pathlib import Path
MAGIC=b'\xd4\xc3\xb2\xa1';FMT='<HQIHBHHBBI';HLEN=struct.calcsize(FMT)
def inspect_small_inbound_envelopes(path:Path)->dict:
 size=path.stat().st_size;out=[];index=0
 with path.open('rb') as f:
  if f.read(4)!=MAGIC:raise ValueError('expected little-endian microsecond classic PCAP')
  r=f.read(20)
  if len(r)!=20 or struct.unpack('<HHIIII',r)[-1]!=249:raise ValueError('expected USBPcap linktype 249')
  while p:=f.read(16):
   if len(p)!=16:raise ValueError('truncated PCAP packet header')
   _,_,inc,_=struct.unpack('<IIII',p);index+=1
   if inc<HLEN:raise ValueError('USBPcap record shorter than base header')
   h=f.read(HLEN)
   if len(h)!=HLEN:raise ValueError('truncated USBPcap header')
   hlen,_irp,_status,_fn,info,bus,device,endpoint,transfer,length=struct.unpack(FMT,h)
   if hlen<HLEN or hlen>inc:raise ValueError('invalid USBPcap header length')
   remaining=inc-HLEN
   if transfer==3 and endpoint==0x82 and info&1 and 4<=length<=64 and remaining>=4:
    x=f.read(4);remaining-=4
    out.append({'record_index':index,'bus':bus,'device':device,'flags':f'0x{x[0]:02x}','declared_length':int.from_bytes(x[1:3],'little'),'checksum':f'0x{x[3]:02x}'})
   f.seek(remaining,1)
   if f.tell()>size:raise ValueError('truncated PCAP record')
 return {'format':'goodix-small-inbound-envelope-index','envelope_count':len(out),'envelopes':out}
def main():
 p=argparse.ArgumentParser(description='Read only four-byte small Goodix IN reply envelopes.')
 p.add_argument('capture',type=Path);print(json.dumps(inspect_small_inbound_envelopes(p.parse_args().capture),indent=2))
if __name__=='__main__':main()
