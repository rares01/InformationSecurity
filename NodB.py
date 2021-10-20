
from Crypto.Cipher import AES
from Crypto.Util.strxor import strxor
import socket


Kprim = b'1122334455667788'
initializationVector = b'0099887766554433'

PORT = 65433
HOST= '127.0.0.1'




def receivefromA(conn):
    opMode = conn.recv(3).decode('utf-8')  #primeste modul de operare de la A
    Key = conn.recv(16)   #primeste cheia
    decipher = AES.new(Kprim, AES.MODE_ECB)  #decriptam cu modul ECB - mai simplu
    Key = decipher.decrypt(Key) #decripteaza cheia primita de la A cu cheia K'
    conn.send('Success'.encode('utf-8')) #ii trimite lui A mesajul de incepere a comunicarii

    cipher = AES.new(Key, AES.MODE_ECB)  #obiect de tip aes cu cheia primita de la A si decriptata si ecb mode.
    ciphertext = initializationVector
    block=conn.recv(16)
    plain=b""
    while block:
        print(block)
        if opMode == 'ECB':
            block = cipher.decrypt(block)
            plain = plain + block
            # cipher = AES.new(Key, AES.MODE_ECB)
            # plain=plain+cipher.decrypt(block).decode('utf-8')


        elif opMode == 'CFB':
            #CFB
            plain = plain +  strxor(cipher.encrypt(ciphertext), block)
            ciphertext = block
            # cipher = AES.new(Key, AES.MODE_CFB, initializationVector)  #se face xor dintre blocul primit de la A si ciphertext
            # plain = plain + cipher.decrypt(block).decode('utf-8')                      #care initial este vectorul de init

        block = conn.recv(16)

    print(plain.decode("utf-8"))

    # print(plain)

def start():
    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server.bind((HOST,PORT))
    server.listen()
    conn, addr = server.accept()
    receivefromA(conn)

if __name__ == '__main__':
    start()