import socket
from scapy.all import *
import nacl.utils, binascii, codecs
from nacl.public import *

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
    encrypted = sealed_box.encrypt(msg)
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

my_secret = import_private_key("rdSX7bH8SDUMlp8ITnlm6MEvYb5IMmrch/Gjw51zND0=")
resolver_public = import_public_key("rqp9WM4KMc6o1qKncyf2DmybehvocXiXz3aFGmGYC2Q=")

resolver = "1.2.3.4"

class ECC(Packet):
    name = "DNSCrypt"
    fields_desc = [ StrLenField("crypto", '') ]

split_layers(IP, ICMP)
bind_layers(UDP, ECC, sport=3215)
bind_layers(UDP, ECC, dport=3216)

def resolve_dns(hostname):
        encrypted_request = encryption(hostname,resolver_public).replace('\n','')
        packet = IP(dst=resolver)/UDP(sport=3215,dport=3216)/ECC(crypto=encrypted_request)
        try:
                ans = sr1(packet,verbose=0,timeout=4)
                c = decryption(ans[Raw].load.decode().replace("\n",''), my_secret)
                return c
        except:
                return False

s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
s.bind(('0.0.0.0', 53))
while True:
         message, address = s.recvfrom(8192)
         if len(message)>0:
                         dns = DNS(message)
                         if dns.haslayer(DNSQR):
                                 ip = resolve_dns(dns.qd.qname)
                                 if ip!=False:
                                         dns_response = DNS(id=dns.id, qd=dns.qd, aa = 1, qr=1, an=DNSRR(rrname=dns.qd.qname,  ttl=10, rdata=ip))
                                         response = bytes(dns_response)
                                         s.sendto(response, address)
                                 else:
                                         pass
