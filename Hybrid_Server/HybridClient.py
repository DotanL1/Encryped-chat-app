import wx
import socket
import time
import sympy
import random
import threading
import pickle
import rsa
import os

from TCP_AES import send_with_AES, recv_with_AES
from tcp_by_size import send_with_size, recv_by_size
from TCP_RSA import recv_with_RSA,send_with_RSA





APPWIDTH = 900
APPHEIGHT = 900
p2p_port = 2122
server_port = 1233

class Application(wx.Dialog):
    def __init__(self, parent, id, title, ip):
        wx.Dialog.__init__(self, parent, id, title, size=(APPWIDTH, APPHEIGHT))

        self.rsa_public,self.rsa_private = rsa.newkeys(2048)
        self.rsa_public = self.rsa_public.save_pkcs1().decode('utf-8')
        self.rsa_private = self.rsa_private.save_pkcs1().decode('utf-8')



        self.CliSock = socket.socket()
        self.p2pSock = socket.socket()
        self.ip = ip
        self.connected = False 
        self.Server_key = None
        self.Username = None
        self.Password = None
        self.other_user = None
        self.p2p_key = None  
        self.use_df_helman = False
        self.Show()

        self.font = wx.Font(28, wx.FONTFAMILY_DEFAULT, wx.FONTSTYLE_NORMAL, wx.FONTWEIGHT_BOLD)
        self.Bind(wx.EVT_CLOSE, self.WhenExit)

        self.DF__button = wx.Button(self,5,'Use DF hellman',(700,100),(100,60))
        self.DF__button.Bind(wx.EVT_BUTTON,self.use_df_handler)

        self.RSA__button = wx.Button(self,5,'Use RSA',(600,100),(100,60))
        self.RSA__button.Bind(wx.EVT_BUTTON,self.use_RSA_handler)


        self.log_btn = wx.Button(self, 2, 'Login', (400, 150), (150, 30))
        self.log_btn.Bind(wx.EVT_BUTTON, self.HandleLogin)
        self.log_btn.Hide()

        self.signup_btn = wx.Button(self, 3, 'Sign Up', (400, 600), (150, 30))
        self.signup_btn.Bind(wx.EVT_BUTTON, self.handle_signup)
        self.signup_btn.Hide()

        self.name = wx.TextCtrl(self, pos=(400, 50), size=(150, 27))
        self.name.SetHint('Enter Your Name:')
        self.name.Hide()
        
        self.password = wx.TextCtrl(self, pos=(400, 77), size=(150, 27), style=wx.TE_PASSWORD)
        self.password.SetHint('Enter Your Password:')
        self.password.Hide()

        self.connect_button = wx.Button(self, 4, 'Connect', (400, 150), (150, 30))
        self.connect_button.Bind(wx.EVT_BUTTON, self.TryConnect)

        self.IpTxt = wx.TextCtrl(self, pos=(400, 105), size=(150, 27))
        self.IpTxt.SetHint('Enter IP Address')

        self.UserList = wx.ListBox(self, pos=(50, 400), size=(300, 300))
        self.UserList.Bind(wx.EVT_LISTBOX, self.start_com)
        self.UserList.Append('(Press here to reset the choosing process)')
        self.UserList.Hide()

        self.timer = wx.Timer(self)
        self.Bind(wx.EVT_TIMER, self.remove_text, self.timer)

        self.dissalaowed_message = wx.StaticText(self, label=f'User Declined Communication', pos=(400, 300))
        self.dissalaowed_message.Hide()
        self.ErrorFont = wx.Font(14, wx.FONTFAMILY_DEFAULT, wx.FONTSTYLE_NORMAL, wx.FONTWEIGHT_NORMAL)
        self.SetBackgroundColour(wx.Colour(100, 180, 255))

        self.message_input = wx.TextCtrl(self, pos=(50, 720), size=(600, 30))
        self.message_input.Hide()
        self.send_button = wx.Button(self, label="Send", pos=(660, 720), size=(80, 30))
        self.send_button.Bind(wx.EVT_BUTTON, self.send_message)
        self.send_button.Hide()

        self.chat_display = wx.TextCtrl(self, pos=(50, 50), size=(600, 650), style=wx.TE_MULTILINE | wx.TE_READONLY)
        self.chat_display.Hide()

        self.dissconect = wx.Button(self, label='Disconnect',pos=(750,720),size=(80,30))
        self.dissconect.Bind(wx.EVT_BUTTON,self.P2P_dissconect)
        self.dissconect.Hide()

        self.error_signing_in = wx.StaticText(self,label='Wrong password or username/User connected from another device',pos=(300,250))
        self.error_signing_in.SetForegroundColour(wx.Colour(255,0,0))
        self.error_signing_in.Hide()


        self.connect_button.Show()
        self.IpTxt.Show()
        self.Centre()


    def use_RSA_handler(self,event):

        self.use_df_helman = False
        print (self.use_df_helman)

    def use_df_handler(self, event):

        self.use_df_helman = True
        print (self.use_df_helman)

    def P2P_dissconect(self,event):
        try:
            send_with_AES(self.p2pSock,'PEX@Bye'.encode(),self.p2p_key)
            self.p2pSock.close()
            self.remove_p2p_gui()
        except:
            self.p2pSock.close()
            self.remove_p2p_gui()
        finally:
            self.p2pSock = socket.socket()


    def remove_p2p_gui(self):
        self.dissconect.Hide()
        self.chat_display.Hide()
        self.send_button.Hide()
        self.message_input.Hide()
        self.UserList.Show()
        self.chat_display.Clear()
        self.RSA__button.Show()
        self.DF__button.Show()
        self.Layout()



    def send_message(self, event):
        message = self.message_input.GetValue()
        if message:
            send_with_AES(self.p2pSock, f'MSG@{message}'.encode(), self.p2p_key)
            self.chat_display.AppendText(f"You: {message}\n")
            self.message_input.Clear()

    def p2p_comm(self, other_sock):
        while True:
            try:
                data = recv_with_AES(other_sock, self.p2p_key)
                if data:
                    split_data = data.decode().split('@')
                    if split_data[0] == 'MSG':
                        wx.CallAfter(self.chat_display.AppendText, f"{self.other_user}: {split_data[1]}\n")
            except Exception as e:
                self.P2P_dissconect(None)
                break



    def start_com(self, event):
        selected_user = self.UserList.GetStringSelection()
        if selected_user != '(Press here to reset the choosing process)':
            self.other_user = selected_user
            send_with_AES(self.CliSock, f'COM@1@{self.Username}@{selected_user}'.encode(), self.Server_key)
            

    def comm_layout(self):
        self.message_input.Show()
        self.send_button.Show()
        self.chat_display.Show()
        self.dissconect.Show()
        self.UserList.Hide()
        self.RSA__button.Hide()
        self.DF__button.Hide()
        self.Layout()


    def login_successful(self, Username):
        loginTxt = wx.StaticText(self, label=f'User: {Username}', pos=(0, 0))
        loginTxt.SetFont(self.font)
        self.UserList.Show()
        self.RSA__button.Show()
        self.DF__button.Show()

    def TryConnect(self, event):
        try:
            self.CliSock.connect((self.ip, server_port))
            self.connected = True
            self.RSA__button.Hide()
            self.DF__button.Hide()
            listener = threading.Thread(target=self.listen, args=(self.CliSock,),daemon=True)
            listener.start()
            if self.use_df_helman:
                send_with_size(self.CliSock,b'DFH@')
            while not self.Server_key:
                pass

            
            
            self.start_gui()
        except Exception as e:
            error_msg = wx.StaticText(self, label=f'Error: {e}', pos=(1, 300))
            error_msg.SetFont(self.ErrorFont)
            self.Layout()
            self.Update()
            error_msg.Show()
            time.sleep(5)
            self.Destroy()

    def start_gui(self):
        self.connect_button.Hide()
        self.IpTxt.Hide()
        self.password.Show()
        self.name.Show()
        self.log_btn.Show()
        self.signup_btn.Show()
        self.Layout()
        self.Update()


    def listen(self, Socket):
        while True:
            
            try:
                
                if self.Server_key == None:
                    if self.use_df_helman:
                        data = recv_by_size(Socket)
                        Socket.settimeout(1)
                        if not data:
                            break 
                    else:
                        send_with_size(self.CliSock,f'RSA@{self.rsa_public}')
                        self.handle_RSA_with_server()
                        Socket.settimeout(1)
                        continue
                        
                else:
                    data = recv_with_AES(Socket, self.Server_key)

                split_data = data.split(b'@')
                request_code = split_data[0]
                if request_code == b'DFH':
                    self.get_df_helman_from_server(split_data[1:])
                elif request_code == b'RSA':
                    self.handle_RSA_with_server(split_data[1],)
                elif request_code == b'LGS':
                    wx.CallAfter(self.login_successful, split_data[1].decode())
                elif request_code == b'USR':
                    wx.CallAfter(self.load_users, split_data[1])
                elif request_code == b'NEW':
                    name = split_data[1].split(b' ')[1]
                    name = name.decode()
                    if name != self.Username:
                        wx.CallAfter(self.add_user, name)
                elif request_code == b'EXT':
                    users = self.UserList.GetItems()
                    user_index = users.index(split_data[1].decode())
                    self.UserList.Delete(user_index)
                        
                    
                elif request_code == b'COM':
                    wx.CallAfter(self.Handle_communication, split_data[1].decode(), split_data[2].decode())
                elif request_code == b'ANS':
                    print(split_data[1])
                elif request_code == b'PEX':
                    wx.CallAfter(self.remove_p2p_gui())
                elif request_code == b'ERR':
                    wx.CallAfter(self.handle_errors,split_data[1].decode(),split_data[2].decode)
            except socket.timeout:
                continue
            except Exception as e:
                raise




    def handle_errors(self,error_code,error):
        if error_code == '2':
            self.error_signing_in.Show()
            self.start_gui()
            self.Layout()

    def handle_RSA_with_server(self):
        self.Server_key = recv_with_RSA(self.CliSock,self.rsa_private)
       


    def Handle_communication(self, code, answer):
        if code == '3':
            self.Cancel_comm_text()
            self.remove_p2p_gui()
            return
        elif code == '2': 
            self.other_user = answer
            self.asking_for_comm = wx.StaticText(self, label=f'User {answer} is asking for communication. Allow?', pos=(400, 300))
            self.yes_button = wx.Button(self, label="Yes", pos=(450, 350), size=(50, 50))
            self.no_button = wx.Button(self, label='No', pos=(500, 350), size=(50, 50))

            self.yes_button.Bind(wx.EVT_BUTTON, self.Create_server_for_comm)    
            self.no_button.Bind(wx.EVT_BUTTON, self.Cancel_comm)

            self.asking_for_comm.Show()
            self.yes_button.Show()
            self.no_button.Show()

            self.Layout()
            self.Refresh()
        elif code == '4': 
            self.connect_to_other_client(answer)

    def Cancel_comm(self, event):
        self.asking_for_comm.Hide()
        self.yes_button.Hide()
        self.no_button.Hide()
        send_with_AES(self.CliSock, f'COM@3@{self.Username}@{self.other_user}', self.Server_key)

    def Cancel_comm_text(self):
        self.dissalaowed_message.Show()
        self.Layout()
        self.timer.Start(2000)

    def remove_text(self, event):
        self.dissalaowed_message.Hide()
        self.Layout()
        self.timer.Stop()

    def add_user(self, user):
        if user != self.Username and self.UserList.FindString(user) == wx.NOT_FOUND:
            self.UserList.Append(user)

    def load_users(self, serialized_data):
        try:
            users = pickle.loads(serialized_data)
            for user in users:
                self.add_user(user)
        except Exception as e:
            print(f"Error loading users: {e}")


    def Create_server_for_comm(self, event):
        self.asking_for_comm.Hide()
        self.yes_button.Hide()
        self.no_button.Hide()
        self.comm_layout()

        send_with_AES(self.CliSock, f'COM@4@{self.ip}@{self.other_user}'.encode(), self.Server_key)
        
        self.p2pSock.bind((self.ip, p2p_port))
        self.p2pSock.listen(1)

        other_sock, addr = self.p2pSock.accept()
        self.p2pSock = other_sock
        print (self.use_df_helman)
        if self.use_df_helman:
            p = self.generate_large_prime(bits=256)
            g = 2
            secret = random.getrandbits(128)
            public = pow(g, secret, p)

            send_with_size(self.p2pSock, f'DFH@{p}@{g}@{public}'.encode())

            data = recv_by_size(self.p2pSock).decode()
            if data.startswith("DFH@"):
                _, other_public = data.split("@")
                shared_key = pow(int(other_public), secret, p)
                self.p2p_key = str(shared_key)
        else:
            send_with_size(self.p2pSock,f'RSA@{self.rsa_public}')
            self.p2p_key = recv_with_RSA(self.p2pSock,self.rsa_private)



        t = threading.Thread(target=self.p2p_comm, args=(self.p2pSock,),daemon=True)
        t.start()


    def connect_to_other_client(self, ip):
        self.p2pSock.connect((ip, p2p_port))
        self.comm_layout()
        data = recv_by_size(self.p2pSock).decode()
        if data.startswith("DFH@"):
            _, p, g, other_public = data.split("@")
            p, g, other_public = int(p), int(g), int(other_public)

            secret = random.getrandbits(128)
            public = pow(g, secret, p)

            send_with_size(self.p2pSock, f'DFH@{public}'.encode())

            shared_key = pow(other_public, secret, p)
            self.p2p_key = str(shared_key)
        elif data.startswith('RSA@'):
            data = data.split('@')
            public_key = data[1]
            key = str(os.urandom(32))
            self.p2p_key = key
            send_with_RSA(self.p2pSock,key,public_key)




        t = threading.Thread(target=self.p2p_comm, args=(self.p2pSock,),daemon=True)
        t.start()

    def generate_large_prime(self, bits=2048):
        return sympy.randprime(2 ** (bits - 1), 2 ** bits)

    def get_df_helman_from_server(self, data):
        bit_size_number = 20
        secret_a = random.getrandbits(bit_size_number)
        p, g, a = data
        p, g, a = int(p), int(g), int(a)
        public_a = pow(g, secret_a, p)
        send_with_size(self.CliSock, b'DFH@' + str(public_a).encode())
        self.Server_key = str(pow(int(a), secret_a, p))

    

    def generate_large_prime(self,bits=2048):
        return sympy.randprime(2 ** (bits - 1), 2 ** bits)





    def df_helman(self,cli_sock):
        p = self.generate_large_prime()
        g = 2
        secret_a = random.getrandbits(512)
        public_a = pow(g, secret_a, p)
        send_with_size(cli_sock,b'DFH@' + str(p).encode() + b'@' + str(g).encode() + b'@' + str(public_a).encode())
        return secret_a,p,public_a
        
    def generate_df_key(self,secret_a,p,data):
        data = data.split('@')
        if data[0] == 'DFH':
            a = int(data[1]) 
            p2p = pow(a, secret_a, p)
            self.p2p_key = str(p2p)
            print(self.p2p_key)


    def WhenExit(self, event):
        try:
            send_with_AES(self.CliSock, f'EXT@{self.Username}'.encode(), self.Server_key)
        except:
            self.Destroy()
        finally:
            self.Destroy()

        self.Destroy()

    def handle_signup(self, event):
        self.signup_btn.Hide()
        UserName = self.name.GetValue()
        Password = self.password.GetValue()
        self.Send_SignUp(UserName, Password)

    def HandleLogin(self, event):
        self.log_btn.Hide()
        self.name.Hide()
        self.password.Hide()
        self.IpTxt.Hide()
        self.signup_btn.Hide()

        if self.connected: 
            self.Username = self.name.GetValue()
            self.Password = self.password.GetValue()
            self.SendLogIn(self.Username, self.Password)

    def Send_SignUp(self, Username, Password):
        send_with_AES(self.CliSock, b'SGU@' + Username.encode() + b'@' + Password.encode(), self.Server_key)

    def SendLogIn(self, Username, Password):
        try:
            send_with_AES(self.CliSock, b'LGN@' + Username.encode() + b'@' + Password.encode(), self.Server_key)
            self.error_signing_in.Hide()
        except Exception as e:
            error_msg = wx.StaticText(self, label=e, pos=(280, 300))
            error_msg.SetFont(self.ErrorFont)
            self.Layout()
            self.Update()
            error_msg.Show()
            time.sleep(5)
            self.Destroy()


if __name__ == "__main__":
    app = wx.App(0)
    Application(None, -1, 'Hybrid Server', '127.0.0.1')
    app.MainLoop()