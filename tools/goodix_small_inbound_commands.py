#!/usr/bin/env python3
"""Classify one-byte headers from small Goodix IN replies without bodies."""
import argparse,json,struct
from pathlib import Path
MAGIC=b'\xd4\xc3\xb2\xa1';FMT='<HQIHBHHBBI';HLEN=struct.calcsize(FMT)
def classify_small_inbound_commands(path:Path)->dict:
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
   if transfer==3 and endpoint==0x82 and info&1 and 5<=length<=64 and remaining>=5:
    x=f.read(5);remaining-=5
    if x[0]==0xa0:
     cmd=x[4];out.append({'record_index':index,'bus':bus,'device':device,'category':cmd>>4,'command':(cmd&15)>>1,'lsb_set':bool(cmd&1)})
   f.seek(remaining,1)
   if f.tell()>size:raise ValueError('truncated PCAP record')
 return {'format':'goodix-small-inbound-command-index','command_count':len(out),'commands':out}
def main():
 p=argparse.ArgumentParser(description='Read one small Goodix IN reply command byte; never emit bodies.')
 p.add_argument('capture',type=Path);print(json.dumps(classify_small_inbound_commands(p.parse_args().capture),indent=2))
if __name__=='__main__':main()
