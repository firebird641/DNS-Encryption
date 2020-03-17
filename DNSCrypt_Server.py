import socket
from scapy.all import *
import nacl.utils, binascii, codecs
from nacl.public import *
from scapy.all import conf as scapyconf

def generate_keypair():
    skbob = PrivateKey.generate()
    pkbob = skbob.public_key
    enc_skbob = skbob.encode(encoder=nacl.encoding.HexEncoder)
    enc_pkbob = pkbob.encode(encoder=nacl.encoding.HexEncoder)
    b64_skbob = codecs.encode(codecs.decode(enc_skbob, 'hex'), 'base64').decode()
    b64_pkbob = codecs.encode(codecs.decode(enc_pkbob, 'hex'), 'base64').decode()
    return b64_skbob,b64_pkbob

def import_public_key(b64_pkbob):
    enc_pkbob = codecs.encode(codecs.decode(b64_pkbob.encode(),'base64'),'hex')
    pkbob = PublicKey(binascii.unhexlify(enc_pkbob))
    return pkbob

def import_private_key(b64_skbob):
    enc_skbob = codecs.encode(codecs.decode(b64_skbob.encode(),'base64'),'hex')
    skbob = PrivateKey(binascii.unhexlify(enc_skbob))
    return skbob

def encryption(msg, pkbob):
    sealed_box = SealedBox(pkbob)
    encrypted = sealed_box.encrypt(msg.encode())
    enc_encrypted = binascii.hexlify(encrypted)
    b64_encrypted = codecs.encode(codecs.decode(enc_encrypted, 'hex'), 'base64').decode()
    return b64_encrypted

def decryption(msg, skbob):
    msg = codecs.encode(codecs.decode(msg.encode(),'base64'), 'hex')
    msg = binascii.unhexlify(msg)
    unseal_box = SealedBox(skbob)
    plaintext = unseal_box.decrypt(msg)
    enc_plaintext = plaintext.decode()
    return enc_plaintext

my_secret = import_private_key("VPWkmWSoAqgJRuMApOFVUXGWKsDseRqfiFvzVsd2lKA=")
server_public = import_public_key("pVszwjFgtYdyIMRNV9Asp8g5XR3Z9T3lKSLOwCXpuBc=")

class ECC(Packet):
    name = "DNSCrypt"
    fields_desc = [ StrField("crypto", "") ]

def resolve_local(hostname):
    ip = socket.gethostbyname(hostname)
    return ip

bind_layers(UDP, ECC, sport=3215)
bind_layers(UDP, ECC, dport=3216)

def handle_resolver(p):
    if p.haslayer(UDP) and p.haslayer(ECC) and p[IP].dst=="192.168.178.56":
         try:
             packetload = p[ECC].crypto.decode().replace("\n",'')
             payload = decryption(packetload,my_secret)
             hostname = payload.strip()
             ip = encryption(resolve_local(hostname),server_public).replace("\n",'')
             send(IP(dst=p[IP].src)/UDP(sport=3216,dport=3215)/ECC(crypto=ip),verbose=0)
         except:
             pass

sniff(prn=handle_resolver)
