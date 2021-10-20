
from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
import socket


#128 biti -> 16 bytes
K = get_random_bytes(16)
Kprim = b'1122334455667788'  #bytes

PORT = 65432   # Port to listen on
HOST = '127.0.0.1'  #adresa serverului



def sendKtoA(conn):
    #Creaza un obiect AES cu cheia de criptare K' si modul de criptare alg ECB
    cipher = AES.new(Kprim, AES.MODE_ECB)
    encryptedKey=cipher.encrypt(K)  #criptam cheia K
    conn.send( encryptedKey)  #trimitem cheia criptata clientului
    conn.close()  #inchidem conexiunea


def start():
    #cream un obiect de tip socket cu AF_INET (internet adress pentru IPv4) si socketul SOCK_STREAM specific TCP
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.bind((HOST, PORT))  #asociem socketului adresa si portul
    s.listen()  #permitem serverului sa accepte conexiuni
    conn, addr = s.accept()  #acceptam conexiuni #When a client connects, it returns a new socket object representing the connection and a tuple holding the address of the client. The tuple will contain (host, port) for IPv4 connections
    sendKtoA(conn)

if __name__ == '__main__':
    start()