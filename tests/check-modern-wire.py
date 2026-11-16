import json,socket,struct,tempfile,subprocess,time,pathlib,os,hashlib
root=pathlib.Path(__file__).resolve().parents[1]
def readn(s,n):
 b=b''
 while len(b)<n:
  x=s.recv(n-len(b))
  if not x:raise RuntimeError('unexpected EOF')
  b+=x
 return b

def address(s):
 kind=readn(s,1)[0]
 if kind==1:host=socket.inet_ntoa(readn(s,4))
 elif kind==4:host=socket.inet_ntop(socket.AF_INET6,readn(s,16))
 else:host=readn(s,readn(s,1)[0]).decode()
 return host,struct.unpack('!H',readn(s,2))[0]

def query(port,name,typ):
 with socket.create_connection(('127.0.0.1',port),timeout=2) as control:
  control.sendall(b'\x05\x01\x00');assert readn(control,2)==b'\x05\x00'
  control.sendall(b'\x05\x03\x00\x01'+bytes(6));assert readn(control,3)==b'\x05\x00\x00';host,p=address(control)
  with socket.socket(socket.AF_INET,socket.SOCK_DGRAM) as udp:
   udp.settimeout(3)
   data=b'\x12\x34\x01\x00\x00\x01'+bytes(6)+b''.join(bytes([len(x)])+x.encode() for x in name.split('.'))+b'\0'+struct.pack('!HH',typ,1)
   udp.sendto(bytes(3)+b'\x01\xc0\x00\x02\x01\x00\x35'+data,(host if host!='0.0.0.0' else '127.0.0.1',p))
   packet,_=udp.recvfrom(65535)
   kind=packet[3];off=10 if kind==1 else 22 if kind==4 else 7+packet[4]
   answer=packet[off:];assert answer[:2]==data[:2] and answer[3]&15==0
   return {'rcode':answer[3]&15,'answers':int.from_bytes(answer[6:8],'big'),'last_rdata_hex':answer[-(4 if typ==1 else 12):].hex()}

def main():
 results=[]
 with tempfile.TemporaryDirectory() as tmp:
  work=pathlib.Path(tmp)
  for label,binary in [('native',root/'build/lanboat-allinone'),('sing-box-1.15.0-alpha.13',pathlib.Path(os.environ.get('LANBOAT_TEST_SINGBOX15',root/'.cache/sing-box-1.15.0-alpha.13/sing-box')))]:
   with socket.socket() as s:s.bind(('127.0.0.1',0));port=s.getsockname()[1]
   cfg={'log':{'disabled':True},'inbounds':[{'type':'mixed','tag':'in','listen':'127.0.0.1','listen_port':port}],'outbounds':[{'type':'direct','tag':'direct'}],'route':{'rules':[{'port':53,'action':'hijack-dns'}],'final':'direct'},'dns':{'servers':[{'type':'hosts','tag':'hosts','predefined':{'modern.test':'10.0.0.7'}}],'rules':[{'domain':'txt.test','action':'predefined','answer':'txt.test. 60 IN TXT "hello world"'},{'action':'evaluate','server':'hosts','tag':'candidate'},{'match_response':'candidate','ip_cidr':'10.0.0.0/8','action':'respond'}]}}
   path=work/(label+'.json');path.write_text(json.dumps(cfg));log=(work/(label+'.log')).open('w+')
   process=subprocess.Popen([str(binary),'run','-c',str(path)],cwd=work,stdout=log,stderr=log)
   try:
    for _ in range(100):
     if process.poll() is not None:log.seek(0);raise RuntimeError(log.read())
     try:s=socket.create_connection(('127.0.0.1',port),timeout=.05);s.close();break
     except OSError:time.sleep(.02)
    results.append({'engine':label,'binary_sha256':hashlib.sha256(binary.read_bytes()).hexdigest(),'evaluate_respond_A':query(port,'modern.test',1),'predefined_TXT':query(port,'txt.test',16)})
   finally:
    process.terminate();process.wait(timeout=5);log.close()
  assert results[0]['evaluate_respond_A']==results[1]['evaluate_respond_A'],results
  assert results[0]['predefined_TXT']==results[1]['predefined_TXT'],results
 (root/'.cache/modern-wire.json').write_text(json.dumps(results,indent=2)+'\n')
 print(json.dumps(results,indent=2))

if __name__ == '__main__':
 main()
