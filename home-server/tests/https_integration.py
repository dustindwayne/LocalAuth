"""Integration test: start an isolated loopback server and exercise actual TLS routes."""
import base64, hashlib, http.client, json, os, pathlib, socket, ssl, subprocess, sys, tempfile, time
from cryptography.hazmat.primitives.asymmetric import ec, rsa, padding
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
ROOT=pathlib.Path(__file__).resolve().parents[1]
SERVER=pathlib.Path(sys.argv[1]).resolve() if len(sys.argv)>1 else ROOT/'target/release'/('localauth-home.exe' if os.name=='nt' else 'localauth-home')
def freeport():
 with socket.socket() as s:s.bind(('127.0.0.1',0));return s.getsockname()[1]
def enc(b):return base64.urlsafe_b64encode(b).decode().rstrip('=')
def dec(s):return base64.urlsafe_b64decode(s+'='*((4-len(s)%4)%4))
def main():
 with tempfile.TemporaryDirectory() as folder:
  data=pathlib.Path(folder);port=freeport();adminport=freeport()
  process=subprocess.Popen([str(SERVER),'--data',str(data),'--port',str(port),'--admin-port',str(adminport),'--no-discovery','--bind-address','127.0.0.1'],stdout=subprocess.PIPE,stderr=subprocess.PIPE,text=True,creationflags=getattr(subprocess,"CREATE_NO_WINDOW",0))
  try:
   first=process.stdout.readline().strip();assert first.startswith('Local dashboard:');token=first.split('#')[1]
   deadline=time.monotonic()+15
   while not (data/'server.pem').exists():
    assert time.monotonic()<deadline;time.sleep(.05)
   ctx=ssl.create_default_context(cafile=str(data/'server.pem'))
   def call(method,path,body=b'',headers=None,admin=False):
    connection=http.client.HTTPConnection('127.0.0.1',adminport,timeout=8) if admin else http.client.HTTPSConnection('localhost',port,context=ctx,timeout=8)
    hdr=dict(headers or {})
    if admin:hdr['Authorization']='Bearer '+token
    connection.request(method,path,body,hdr);r=connection.getresponse();out=(r.status,r.read(),dict(r.getheaders()));connection.close();return out
   for _ in range(100):
    try:assert call('GET','/v1/health')[0]==200;break
    except (ConnectionRefusedError,OSError):time.sleep(.05)
   else:raise AssertionError('TLS server failed to start')
   assert call('GET','/admin/status',headers={'Host':'evil.example'},admin=True)[0]==403
   raw=http.client.HTTPConnection('127.0.0.1',adminport);raw.request('GET','/admin/status');assert raw.getresponse().status==401;raw.close()
   status,body,_=call('POST','/admin/offer',json.dumps({'url':f'https://localhost:{port}'}).encode(),{'Content-Type':'application/json'},True);assert status==200
   offer=json.loads(body);assert '<svg' in dec(offer['qr']).decode();pairing=json.loads(dec(offer['pairing'].split(':',1)[1]))
   certificate=ssl.PEM_cert_to_DER_cert((data/'server.pem').read_text());assert pairing['pin']==hashlib.sha256(certificate).hexdigest()
   key=ec.generate_private_key(ec.SECP256R1());public=enc(key.public_key().public_bytes(serialization.Encoding.DER,serialization.PublicFormat.SubjectPublicKeyInfo))
   label='Integration phone'
   message=f"LocalAuth pair v2\n{pairing['pin']}\n{pairing['ticket']}\n{public}\n{hashlib.sha256(label.encode()).hexdigest()}".encode()
   proof=enc(key.sign(message,ec.ECDSA(hashes.SHA256())))
   payload=json.dumps({'ticket':pairing['ticket'],'public_key':public,'label':label,'proof':proof}).encode()
   unsigned=json.dumps({'ticket':pairing['ticket'],'public_key':public,'label':label,'proof':''}).encode()
   assert call('POST','/v1/pair',unsigned,{'Content-Type':'application/json'})[0]==401
   status,body,_=call('POST','/v1/pair',payload,{'Content-Type':'application/json'});assert status==200;device=json.loads(body)['device']
   assert call('POST','/v1/pair',payload,{'Content-Type':'application/json'})[0]==401
   def signed(method,body=b'',clone=False):
    assert call('GET','/v1/challenge/'+device)[0]==401
    client_nonce=enc(os.urandom(32));timestamp=int(time.time()*1000)
    bootstrap=f"LocalAuth challenge v2\n{pairing['pin']}\n{device}\n{client_nonce}\n{timestamp}".encode()
    headers={'X-Client-Nonce':client_nonce,'X-Client-Time':str(timestamp),'X-Signature':enc(key.sign(bootstrap,ec.ECDSA(hashes.SHA256())))}
    status,reply,_=call('GET','/v1/challenge/'+device,headers=headers);assert status==200
    assert call('GET','/v1/challenge/'+device,headers=headers)[0]==401
    assert json.loads(reply)['protocol']==2
    nonce=json.loads(reply)['challenge'];canonical=f'LocalAuth request v2\n{device}\n{nonce}\n{method}\n/v1/backup\n{hashlib.sha256(body).hexdigest()}'.encode()
    signer=ec.generate_private_key(ec.SECP256R1()) if clone else key
    signature=enc(signer.sign(canonical,ec.ECDSA(hashes.SHA256())))
    return {'X-Device':device,'X-Challenge':nonce,'X-Signature':signature}
   # Unsigned/clone attempts cannot allocate server challenges.
   timestamp=int(time.time()*1000);client_nonce=enc(os.urandom(32))
   bootstrap=f"LocalAuth challenge v2\n{pairing['pin']}\n{device}\n{client_nonce}\n{timestamp}".encode()
   fake=ec.generate_private_key(ec.SECP256R1())
   bad={'X-Client-Nonce':client_nonce,'X-Client-Time':str(timestamp),'X-Signature':enc(fake.sign(bootstrap,ec.ECDSA(hashes.SHA256())))}
   assert call('GET','/v1/challenge/'+device,headers=bad)[0]==401
   for _ in range(10):assert call('GET','/v1/challenge/'+device)[0]==401
   recovery=AESGCM.generate_key(bit_length=256);plain=json.dumps([{'id':'fixture','label':'Example:alice','secret':'MY','algorithm':'SHA1','digits':6,'period':30}]).encode();iv=os.urandom(12);blob=b'LAB1'+iv+AESGCM(recovery).encrypt(iv,plain,b'LocalAuth portable backup v1')
   assert call('POST','/v1/backup',blob,signed('POST',blob,clone=True))[0]==401
   headers=signed('POST',blob);assert call('POST','/v1/backup',blob+b'x',headers)[0]==401
   assert call('POST','/v1/backup',blob,headers)[0]==200
   assert call('POST','/v1/backup',blob,headers)[0]==401
   status,download,_=call('GET','/v1/backup',headers=signed('GET'));assert status==200;assert download==blob
   assert AESGCM(recovery).decrypt(download[4:16],download[16:],b'LocalAuth portable backup v1')==plain
   status,export,_=call('GET','/admin/export/'+device,admin=True);assert status==200 and export==blob
   # LAB2 interoperable envelope: RSA3072 OAEP SHA256/MGF1SHA256, AES256GCM.
   recipient=rsa.generate_private_key(public_exponent=65537,key_size=3072)
   aes=os.urandom(32);iv=os.urandom(12)
   wrapped=recipient.public_key().encrypt(aes,padding.OAEP(mgf=padding.MGF1(hashes.SHA256()),algorithm=hashes.SHA256(),label=None))
   header=b'LAB2'+len(wrapped).to_bytes(2,'big')+wrapped+iv
   capsule=header+AESGCM(aes).encrypt(iv,b'[]',header)
   assert len(capsule)==420
   assert call('POST','/v1/backup',capsule,signed('POST',capsule))[0]==200
   status,download,_=call('GET','/v1/backup',headers=signed('GET'));assert status==200 and download==capsule
   opened=recipient.decrypt(download[6:390],padding.OAEP(mgf=padding.MGF1(hashes.SHA256()),algorithm=hashes.SHA256(),label=None))
   assert AESGCM(opened).decrypt(download[390:402],download[402:],download[:402])==b'[]'
   def acquire(identity,signer):
    nonce=enc(os.urandom(32));stamp=int(time.time()*1000)
    msg=f"LocalAuth challenge v2\n{pairing['pin']}\n{identity}\n{nonce}\n{stamp}".encode()
    return call('GET','/v1/challenge/'+identity,headers={'X-Client-Nonce':nonce,'X-Client-Time':str(stamp),'X-Signature':enc(signer.sign(msg,ec.ECDSA(hashes.SHA256())))})
   capped=False
   for _ in range(5):
    code,_,_=acquire(device,key)
    if code==401:capped=True;break
    assert code==200
   assert capped
   status,reply,_=call('POST','/admin/offer',json.dumps({'url':f'https://localhost:{port}'}).encode(),{'Content-Type':'application/json'},True);assert status==200
   fresh=json.loads(dec(json.loads(reply)['pairing'].split(':',1)[1]))
   second=ec.generate_private_key(ec.SECP256R1());public2=enc(second.public_key().public_bytes(serialization.Encoding.DER,serialization.PublicFormat.SubjectPublicKeyInfo));label2='Independent phone'
   msg=f"LocalAuth pair v2\n{fresh['pin']}\n{fresh['ticket']}\n{public2}\n{hashlib.sha256(label2.encode()).hexdigest()}".encode()
   payload2=json.dumps({'ticket':fresh['ticket'],'public_key':public2,'label':label2,'proof':enc(second.sign(msg,ec.ECDSA(hashes.SHA256())))}).encode()
   status,reply,_=call('POST','/v1/pair',payload2,{'Content-Type':'application/json'});assert status==200
   second_id=json.loads(reply)['device']
   assert acquire(second_id,second)[0]==200
   assert call('POST','/admin/revoke/'+device,admin=True)[0]==204
   assert call('GET','/v1/challenge/'+device)[0]==401
   assert call('GET','/admin/export/'+device,admin=True)[0]==200
   assert call('POST','/v1/backup',blob)[0]==401
   print('PASS: protocol2 signed pairing, signed challenge acquisition, bootstrap replay/unsigned/clone rejection, live per-device quota fairness, real TLS certificate pin, QR, signatures, cloned-key rejection, payload binding, replay rejection, encrypted LAB1/LAB2 restore, revocation and admin recovery')
  finally:
   process.terminate()
   try:process.wait(timeout=10)
   except subprocess.TimeoutExpired:process.kill();process.wait()
if __name__=='__main__':main()
