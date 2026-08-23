#!/usr/bin/env python3
"""Classify one-byte Goodix outbound command headers without exporting bodies."""
import argparse,json,struct
from pathlib import Path
MAGIC=b'\xd4\xc3\xb2\xa1';FMT='<HQIHBHHBBI';HLEN=struct.calcsize(FMT)
def classify_outbound_commands(path:Path)->dict:
 size=path.stat().st_size; commands=[];index=0
 with path.open('rb') as f:
  if f.read(4)!=MAGIC:raise ValueError('expected little-endian microsecond classic PCAP')
  rest=f.read(20)
  if len(rest)!=20 or struct.unpack('<HHIIII',rest)[-1]!=249:raise ValueError('expected USBPcap linktype 249')
  while p:=f.read(16):
   if len(p)!=16:raise ValueError('truncated PCAP packet header')
   _,_,included,_=struct.unpack('<IIII',p);index+=1
   if included<HLEN:raise ValueError('USBPcap record shorter than base header')
   raw=f.read(HLEN)
   if len(raw)!=HLEN:raise ValueError('truncated USBPcap header')
   hlen,_irp,_status,_function,info,bus,device,endpoint,transfer,length=struct.unpack(FMT,raw)
   if hlen<HLEN or hlen>included:raise ValueError('invalid USBPcap header length')
   remaining=included-HLEN
   if transfer==3 and endpoint==1 and not info&1 and length>=5 and remaining>=5:
    outer_and_command=f.read(5);remaining-=5
    flags=outer_and_command[0];command=outer_and_command[4]
    if flags==0xa0:
     commands.append({'record_index':index,'bus':bus,'device':device,'category':command>>4,'command':(command&0x0f)>>1,'lsb_set':bool(command&1)})
   f.seek(remaining,1)
   if f.tell()>size:raise ValueError('truncated PCAP record')
 return {'format':'goodix-outbound-command-index','command_count':len(commands),'commands':commands}
def main():
 p=argparse.ArgumentParser(description='Read one Goodix command byte and emit only split command fields.')
 p.add_argument('capture',type=Path);print(json.dumps(classify_outbound_commands(p.parse_args().capture),indent=2))
if __name__=='__main__':main()
