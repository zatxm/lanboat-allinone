"""Exercise the unmodified MIT GSSAPI through its public C ABI, outside the core."""
import base64,ctypes as C,json,os,sys

U=C.c_uint32
class Buffer(C.Structure):_fields_=[('length',C.c_size_t),('value',C.c_void_p)]
class OID(C.Structure):_fields_=[('length',U),('elements',C.c_void_p)]
class Bindings(C.Structure):
    _fields_=[('initiator_addrtype',U),('initiator_address',Buffer),('acceptor_addrtype',U),('acceptor_address',Buffer),('application_data',Buffer)]

lib=C.CDLL(os.path.join(os.environ['LANBOAT_TEST_KERBEROS'],'usr/lib/x86_64-linux-gnu/libgssapi_krb5.so.2'))
def bind(name,args):
    f=getattr(lib,name);f.restype=U;f.argtypes=args;return f
ptr=C.c_void_p;P=C.POINTER
import_name=bind('gss_import_name',[P(U),P(Buffer),P(OID),P(ptr)])
init=bind('gss_init_sec_context',[P(U),ptr,P(ptr),ptr,P(OID),U,U,P(Bindings),P(Buffer),P(ptr),P(Buffer),P(U),P(U)])
accept=bind('gss_accept_sec_context',[P(U),P(ptr),ptr,P(Buffer),P(Bindings),P(ptr),P(ptr),P(Buffer),P(U),P(U),P(ptr)])
release_buffer=bind('gss_release_buffer',[P(U),P(Buffer)])
release_name=bind('gss_release_name',[P(U),P(ptr)])
display_name=bind('gss_display_name',[P(U),ptr,P(Buffer),P(ptr)])
delete_context=bind('gss_delete_sec_context',[P(U),P(ptr),P(Buffer)])

def buffer(data):
    storage=C.create_string_buffer(data)
    return storage,Buffer(len(data),C.cast(storage,ptr))
def oid(data):
    storage=C.create_string_buffer(data)
    return storage,OID(len(data),C.cast(storage,ptr))
host_storage,host_oid=oid(bytes.fromhex('2a864886f71201020104'))
spnego_storage,spnego=oid(bytes.fromhex('2b0601050502'))
context=ptr();name=ptr();minor=U()
settings=json.loads(sys.stdin.readline())
binding_storage,application=buffer(b'tls-server-end-point:'+base64.b64decode(settings['binding'],validate=True))
binding=Bindings(255,Buffer(),255,Buffer(),application)
client=sys.argv[1]=='client'
if client:
    target_storage,target=buffer(settings['service'].replace('/', '@',1).encode())
    major=import_name(C.byref(minor),C.byref(target),C.byref(host_oid),C.byref(name))
    if major:raise SystemExit('GSS import failed')
try:
    for line in sys.stdin:
        message=json.loads(line)
        if message.get('close'):break
        incoming_storage,incoming=buffer(base64.b64decode(message['token'],validate=True))
        outgoing=Buffer();flags=U();life=U();peer=ptr();principal=""
        if client:
            major=init(C.byref(minor),None,C.byref(context),name,C.byref(spnego),2|4|8|32,0,C.byref(binding),C.byref(incoming),None,C.byref(outgoing),C.byref(flags),C.byref(life))
        else:
            major=accept(C.byref(minor),C.byref(context),None,C.byref(incoming),C.byref(binding),C.byref(peer),None,C.byref(outgoing),C.byref(flags),C.byref(life),None)
        status=minor.value
        token=C.string_at(outgoing.value,outgoing.length) if outgoing.length else b''
        if outgoing.value:release_buffer(C.byref(minor),C.byref(outgoing))
        if peer.value:
            shown=Buffer()
            if display_name(C.byref(minor),peer,C.byref(shown),None)==0:
                principal=C.string_at(shown.value,shown.length).decode()
                release_buffer(C.byref(minor),C.byref(shown))
            release_name(C.byref(minor),C.byref(peer))
        result={'token':base64.b64encode(token).decode(),'complete':major==0,'principal':principal}
        if major not in (0,1):result['error']='GSS status %d minor %d'%(major,status)
        print(json.dumps(result),flush=True)
finally:
    if context.value:delete_context(C.byref(minor),C.byref(context),None)
    if name.value:release_name(C.byref(minor),C.byref(name))
