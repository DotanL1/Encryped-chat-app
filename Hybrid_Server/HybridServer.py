import secrets
import sympy
from AsyncMessages import AsyncMessages
import socket, threading
from tcp_by_size import send_with_size, recv_by_size
import pickle
import hashlib
import os
import random
from TCP_AES import recv_with_AES, send_with_AES
from TCP_RSA import send_with_RSA,send_with_RSA
import rsa


private,public = None,None
with open('server_public.key','r') as f:
    public = f.read()
with open('server_private.key','r') as f:
    private = f.read()


lock = threading.Lock()

srv_sock = socket.socket()
srv_sock.bind(('0.0.0.0', 1233))
am = AsyncMessages()
srv_sock.listen(20)
ip_by_user = {}
connected_users = []
userList = {}
client_keys = {}
msgs = None

def generate_large_prime(bits=2048):
    return sympy.randprime(2 ** (bits - 1), 2 ** bits)

def df_helman(cli_sock):
    p = generate_large_prime()
    g = 2
    secret_a = random.getrandbits(512)
    public_a = pow(g, secret_a, p)
    am.put_msg_in_async_msgs(b'DFH@' + str(p).encode() + b'@' + str(g).encode() + b'@' + str(public_a).encode(), cli_sock)
    return secret_a,p
    
def generate_df_key(secret_a,p,data,cli_sock):
    data = data.split('@')
    if data[0] == 'DFH':
        a = int(data[1]) 
        df_helman_key = pow(a, secret_a, p)
        client_keys[cli_sock] = df_helman_key
        print(df_helman_key)


def hashdata(data):
    return hashlib.sha256(data.encode()).hexdigest()

def load_users():
    global userList
    userList.clear()
    if os.path.exists('Users.pkl'):
        with open('Users.pkl', 'rb') as f:
            try:
                while True:
                    user = pickle.load(f)
                    split_user_data = user.split(':')
                    username = split_user_data[0]
                    hashed_password = split_user_data[1]
                    salt = split_user_data[2]
                    userList[username] = (hashed_password, salt)
            except:
                pass

def handle_login(username, password, cli_sock,ip):
    if username in userList:
        stored_hashed_pass, salt = userList[username]
        login_attempt_hash = hashdata(password+salt)
        if login_attempt_hash == stored_hashed_pass:
            with lock:
                if username not in connected_users: 
                    am.sock_by_user[username] = cli_sock
                    am.put_msg_in_async_msgs(f'LGS@{username}@Login Successful'.encode(), cli_sock)

                    serielized_users = pickle.dumps(connected_users)
                    am.put_msg_in_async_msgs(b'USR@' + serielized_users, cli_sock)
                    am.put_msg_to_all(f'NEW@User {username} connected')
                    connected_users.append(username)
                    ip_by_user[username] = ip
                    return
    am.put_msg_in_async_msgs(b'ERR@2@ERROR LOGGING IN', cli_sock)
        


def handle_client(cli_sock, ip):
    global msgs
    send_RSA= False
    secret_a,p = None,None
    key = None
    cli_key = None
    while True:
        try:
            cli_sock.settimeout(1)
            if cli_sock in client_keys.keys():
                data = recv_with_AES(cli_sock,str(client_keys[cli_sock])).decode()
                split_data = data.split('@')
                request_code = split_data[0]
            else:
                data = recv_by_size(cli_sock).decode()
                split_data = data.split('@')
                request_code = split_data[0]
            
            if request_code == 'LGN':
                handle_login(split_data[1], split_data[2], cli_sock,ip)
            elif request_code == 'SGU':
                handle_signup(split_data[1], split_data[2], cli_sock)
            elif request_code == 'DFH':
                if split_data[1] == '':
                    secret_a,p = df_helman(cli_sock)
                else:
                    generate_df_key(secret_a,p,data,cli_sock)
            elif request_code == 'COM':
                handle_start_of_communication(split_data[1],split_data[2],split_data[3],cli_sock)
            elif request_code == 'EXT':
                handle_exit(split_data[1],cli_sock)

            elif request_code == 'RSA':
                if split_data[1] != '':
                    cli_key=split_data[1]
                key = handle_RSA(cli_sock,split_data[1])
                send_RSA = True
                raise socket.timeout
            
        except socket.timeout:
            try:
                msgs = am.get_async_messages_to_send(cli_sock)
                if send_RSA:
                    for msg in msgs:
                        send_with_RSA(cli_sock,msg,cli_key)
                    client_keys[cli_sock] = key
                    send_RSA = False
                    print('!!!!!!!',key)
                if cli_sock in client_keys.keys():
                    for msg in msgs:
                        send_with_AES(cli_sock, msg,str(client_keys[cli_sock]))
                else:
                    for msg in msgs:
                        send_with_size(cli_sock,msg)
            except:
                continue

        except socket.error:
            cli_sock.close()
            break



def handle_RSA(cli_sock,cli_key):
    key = str(os.urandom(32))
    am.put_msg_in_async_msgs(key,cli_sock)
    return key




def handle_start_of_communication(code, username_from, username_to, cli_sock):
    if code == '1':
        am.put_msg_by_user(f'COM@2@{username_from}', username_to)
    elif code == '3':
        am.put_msg_by_user(f'COM@3@user {username_from} Declined', username_to)
    elif code == '4':
        am.put_msg_by_user(f'COM@4@{username_from}', username_to)




def handle_exit(Username,socket):
    am.delete_socket(socket)
    if Username in connected_users:
        am.put_msg_to_all(f'EXT@{Username}'.encode())
        connected_users.remove(Username)


def salt_password(password):
    salt = secrets.token_hex(16)
    hashed_pass = hashdata(password + salt)
    return f'{hashed_pass}:{salt}'

def handle_signup(username, password, cli_sock):
    if username in userList:
        am.put_msg_in_async_msgs(b'ERR@1@Username Taken', cli_sock)
    else:
        with open('Users.pkl', 'ab') as f:
            pickle.dump(f'{username}:{salt_password(password)}', f)
        load_users()
        am.put_msg_in_async_msgs(b'SUS@Sign Up Successful', cli_sock)

def main():
    threads = []
    while True:
        print('Before accepting...')
        cli_sock, addr = srv_sock.accept()
        ip = addr[0]
        am.add_new_socket(cli_sock)
        t = threading.Thread(target=handle_client, args=(cli_sock, ip))
        t.start()
        threads.append(t)
        
        if len(threads) > 100:
            print('Server full')
            break

    srv_sock.close()
    for t in threads:
        t.join()

if __name__ == '__main__':
    load_users()
    main()
