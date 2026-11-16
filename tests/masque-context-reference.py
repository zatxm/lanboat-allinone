#!/usr/bin/env python3
"""Independent HTTP/1 Capsule fixture for the published compression-02 wire format."""
import base64,json,socket,sys

ASSIGN,ACK,CLOSE=0x3ee3143f,0x3ee31440,0x3ee31441
PREFIX=b'reference-'

def number(n):
 size=next(size for size in (1,2,4,8)if n < 1<<(size*8-2))
 return (n | {1:0,2:1<<14,4:2<<30,8:3<<62}[size]).to_bytes(size,'big')

def read_exact(s,n):
 data=b''
 while len(data)<n:
  block=s.recv(n-len(data))
  if not block:raise EOFError('unexpected capsule EOF')
  data+=block
 return data

def read_number(s):
 first=read_exact(s,1);size=1<<(first[0]>>6)
 return int.from_bytes(bytes([first[0]&63])+read_exact(s,size-1),'big')

def capsule(s,kind,data):s.sendall(number(kind)+number(len(data))+data)
def receive(s):
 kind=read_number(s);n=read_number(s)
 if n>65543:raise ValueError('oversize capsule')
 return kind,read_exact(s,n)

def header(s):
 data=bytearray()
 while not data.endswith(b'\r\n\r\n'):
  data+=read_exact(s,1)
  if len(data)>8192:raise ValueError('oversize HTTP header')
 lines=data.decode('ascii').split('\r\n')
 return lines[0],dict((k.lower(),v.strip())for line in lines[1:]if line for k,v in [line.split(':',1)])

def template(s,id):capsule(s,ASSIGN,number(id)+number(0)+number(0)+number(len(PREFIX))+PREFIX)

def server(port):
 listener=socket.create_server(('127.0.0.1',port));listener.settimeout(10)
 print('ready',flush=True)
 s,_=listener.accept();s.settimeout(10)
 first,h=header(s)
 assert first.startswith('GET /.well-known/masque/udp/')and h['upgrade']=='connect-udp'
 assert h['authorization']=='Basic '+base64.b64encode(b'client:private').decode()
 assert 'max-templates='in h['http-datagram-contexts'] and 'derived='not in h['http-datagram-contexts']
 s.sendall(b'HTTP/1.1 101 Switching Protocols\r\nConnection: Upgrade\r\nUpgrade: connect-udp\r\nCapsule-Protocol: ?1\r\nHttp-Datagram-Contexts: max-templates=4, mtu=65535\r\n\r\n')
 for count in range(3):
  kind,data=receive(s);assert kind==0 and data[0]==0
  payload=data[1:];assert payload.startswith(PREFIX)
  if count==0:
   template(s,1)
   kind,data=receive(s);assert kind==ACK and data==number(1)
  capsule(s,0,number(1)+payload[len(PREFIX):])
 s.close();listener.close();print(json.dumps(dict(reference='python-stdlib',direction='reference-server',compressed_datagrams=3,context_id=1)),flush=True)

def client(port,target_port):
 s=socket.create_connection(('127.0.0.1',port),timeout=10)
 request=(f'GET /.well-known/masque/udp/127.0.0.1/{target_port}/ HTTP/1.1\r\nHost: localhost\r\nConnection: Upgrade\r\nUpgrade: connect-udp\r\nCapsule-Protocol: ?1\r\nAuthorization: Basic '+base64.b64encode(b'client:private').decode()+'\r\nHttp-Datagram-Contexts: max-templates=0, mtu=65535\r\n\r\n')
 s.sendall(request.encode());first,h=header(s);assert first.startswith('HTTP/1.1 101 ')
 assert 'max-templates=32'in h['http-datagram-contexts']
 template(s,2);kind,data=receive(s);assert kind==ACK and data==number(2)
 capsule(s,0,number(98)+b'unknown-context-must-not-be-forwarded')
 for size in (1,511,4096):
  payload=PREFIX+bytes([size%251])*size;capsule(s,0,number(2)+payload[len(PREFIX):])
  kind,data=receive(s);assert kind==0 and data==b'\0'+payload,(kind,len(data))
 capsule(s,CLOSE,number(2))
 capsule(s,0,number(2)+b'closed-context-must-not-be-forwarded')
 payload=b'base-context-remains-usable';capsule(s,0,b'\0'+payload);kind,data=receive(s);assert kind==0 and data==b'\0'+payload
 s.close();print(json.dumps(dict(reference='python-stdlib',direction='reference-client',compressed_datagrams=3,context_id=2,closed_and_unknown_dropped=True)))

if __name__=='__main__':
 if sys.argv[1]=='server':server(int(sys.argv[2]))
 elif sys.argv[1]=='client':client(int(sys.argv[2]),int(sys.argv[3]))
 else:raise ValueError('invalid fixture mode')
