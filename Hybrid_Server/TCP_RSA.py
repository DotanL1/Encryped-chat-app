
import rsa
import socket
from tcp_by_size import send_with_size, recv_by_size  
TCP_DEBUG = True
LEN_TO_PRINT = 100



def send_with_RSA(sock,data,public_key):
    if isinstance(data,str):
        data = data.encode()
    key = rsa.PublicKey.load_pkcs1(public_key.encode('utf-8'))
    encrypted = rsa.encrypt(data,key)

    if TCP_DEBUG:
        print(f'Sent RSA ({len(encrypted)}) >>>>> {data}')

    send_with_size(sock,encrypted)





def recv_with_RSA(sock,priv_key):
    data = recv_by_size(sock)
    key = rsa.PrivateKey.load_pkcs1(priv_key.encode('utf-8'))

    if TCP_DEBUG:
        print(f'Recieved RSA Data({len(rsa.decrypt(data,key))})  >>>>>  {rsa.decrypt(data,key)}')
    return rsa.decrypt(data,key)





   



