import ipaddress,struct,json
from pathlib import Path

def checksum(b):
 if len(b)%2:b+=b'\0'
 n=sum(struct.unpack('!%dH'%(len(b)//2),b))
 while n>>16:n=(n&65535)+(n>>16)
 return (~n)&65535

def packet(v,proto,options=False,extensions=False,surplus=False,zero=False):
 src=ipaddress.ip_address('192.0.2.9'if v==4 else'2001:db8::9').packed;dst=ipaddress.ip_address('198.51.100.2'if v==4 else'2001:db8:1::2').packed
 payload=b'golden-independent-payload'
 h=bytearray(8 if proto==17 else 24 if options else 20)
 struct.pack_into('!HH',h,0,2000,53)
 if proto==17:struct.pack_into('!H',h,4,len(h)+len(payload))
 else:h[12]=len(h)//4<<4;h[13]=0x18;struct.pack_into('!HH',h,4,0x1234,0x5678);struct.pack_into('!H',h,14,4096)
 segment=h+payload
 pseudo=src+dst+(struct.pack('!BBH',0,proto,len(segment))if v==4 else struct.pack('!I3xB',len(segment),proto))
 value=checksum(pseudo+segment);value=value or 65535 if proto==17 else value
 struct.pack_into('!H',segment,6 if proto==17 else 16,0 if zero else value)
 if surplus:segment+=b'udp-options'
 ext=bytes([60,0,1,0,0,0,0,0,proto,0,1,0,0,0,0,0])if extensions else b''
 if v==4:
  header=bytearray(24 if options else 20);header[0]=0x40|len(header)//4;header[8]=64;header[9]=proto;header[12:16]=src;header[16:20]=dst
  if options:header[20:]=b'\1\1\1\1'
  struct.pack_into('!H',header,2,len(header)+len(segment));struct.pack_into('!H',header,10,checksum(header))
 else:header=bytearray(struct.pack('!IHBB16s16s',0x60012345,len(ext)+len(segment),0 if extensions else proto,64,src,dst))
 return bytes(header)+ext+segment,len(header)+len(ext)

vectors=[]
for name,v,proto,opts,ext,surplus,zero in [('ipv4-udp',4,17,False,False,False,False),('ipv4-tcp-options',4,6,True,False,False,False),('ipv6-udp-extensions',6,17,False,True,False,False),('ipv6-tcp',6,6,False,False,False,False),('udp-options',4,17,False,False,True,False),('udp-zero-checksum',4,17,False,False,False,True)]:
 b,at=packet(v,proto,opts,ext,surplus,zero)
 fields=[(0,2),(4,10)]if v==4 else[(1,4)]
 if proto==17:
  if not surplus:fields.append((2 if v==4 else 3,at+4))
  if not zero:fields.append((7 if v==4 else 8,at+6))
 else:fields.append((5 if v==4 else 6,at+16))
 for label,selected in [(name,fields)]+[(name+'-field-'+str(kind),[(kind,offset)])for kind,offset in fields]:
  skip={i for _,offset in selected for i in [offset,offset+1]};compact=bytes(x for i,x in enumerate(b)if i not in skip);mask=sum(1<<kind for kind,_ in selected)
  vectors.append(dict(name=label,original=b.hex(),compact=compact.hex(),mask=mask))
Path('native/testdata/masque-contexts.json').write_text(json.dumps(vectors,indent=2)+'\n')
print(len(vectors),'independent checksum/field vectors')
