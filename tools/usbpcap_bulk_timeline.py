#!/usr/bin/env python3
"""Build a payload-free relative timeline for USBPcap bulk cycles."""
import argparse, json, struct
from pathlib import Path

MAGIC=b"\xd4\xc3\xb2\xa1"; LINKTYPE=249; FMT="<HQIHBHHBBI"; HLEN=struct.calcsize(FMT)

def index_bulk_timeline(path: Path) -> dict:
    size=path.stat().st_size
    with path.open("rb") as f:
        if f.read(4)!=MAGIC: raise ValueError("expected little-endian microsecond classic PCAP")
        rest=f.read(20)
        if len(rest)!=20: raise ValueError("truncated PCAP global header")
        if struct.unpack("<HHIIII",rest)[-1]!=LINKTYPE: raise ValueError("expected USBPcap linktype 249")
        aliases={}; counts={}; pending={}; cycles=[]; index=0; origin=None
        while header:=f.read(16):
            if len(header)!=16: raise ValueError("truncated PCAP packet header")
            seconds,micros,included,_=struct.unpack("<IIII",header); index+=1
            if included<HLEN: raise ValueError("USBPcap record shorter than base header")
            raw=f.read(HLEN)
            if len(raw)!=HLEN: raise ValueError("truncated USBPcap header")
            hlen,irp,status,_function,info,bus,device,endpoint,transfer,length=struct.unpack(FMT,raw)
            if hlen<HLEN or hlen>included: raise ValueError("invalid USBPcap header length")
            f.seek(included-HLEN,1)
            if f.tell()>size: raise ValueError("truncated PCAP record")
            if transfer!=3: continue
            now=seconds*1_000_000+micros
            if origin is None: origin=now
            offset=now-origin
            op=aliases.setdefault(irp,f"op-{len(aliases)+1:03d}")
            if not info&1:
                counts[irp]=counts.get(irp,0)+1
                cycles.append({"cycle":f"{op}.cycle-{counts[irp]:03d}","operation":op,"bus":bus,"device":device,"endpoint":f"0x{endpoint:02x}","submitted_record_index":index,"submitted_offset_us":offset,"submitted_data_length":length,"completion_record_index":None,"completion_offset_us":None,"completion_data_length":None,"completion_status":None})
                pending[irp]=len(cycles)-1
            elif irp in pending:
                c=cycles[pending.pop(irp)]; c.update({"completion_record_index":index,"completion_offset_us":offset,"completion_data_length":length,"completion_status":f"0x{status:08x}"})
            else:
                counts[irp]=counts.get(irp,0)+1
                cycles.append({"cycle":f"{op}.cycle-{counts[irp]:03d}","operation":op,"bus":bus,"device":device,"endpoint":f"0x{endpoint:02x}","submitted_record_index":None,"submitted_offset_us":None,"submitted_data_length":None,"completion_record_index":index,"completion_offset_us":offset,"completion_data_length":length,"completion_status":f"0x{status:08x}"})
    return {"format":"usbpcap-bulk-relative-timeline","cycle_count":len(cycles),"cycles":cycles}

def main():
    p=argparse.ArgumentParser(description="Emit relative USBPcap bulk cycle offsets without payloads or wall-clock times.")
    p.add_argument("capture",type=Path); print(json.dumps(index_bulk_timeline(p.parse_args().capture),indent=2))
if __name__=="__main__": main()
