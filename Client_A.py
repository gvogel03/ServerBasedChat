import socket
import json
import hashlib
import base64
import threading
import time

from cryptography.fernet import Fernet

client_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
tcp_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
#Unique client information
clientID = "1"
secret = 32739670
last_activity_time = time.time()
killTimerThread = False

def createKey(rand):
    result = rand + secret
    stringEncoder = str(result)
    CK_A = hashlib.sha256(stringEncoder.encode())
    KeyA = CK_A.digest()
    KeyA = base64.urlsafe_b64encode(KeyA)
    #Create a fernet encryption key using the cipher key we just hashed
    fernetEncryptor = Fernet(KeyA)
    return fernetEncryptor

def check_inactivity():
    global last_activity_time
    global killTimerThread
    killTimerThread = False
    last_activity_time = time.time()
    while True:
        if(killTimerThread):
            break
        if time.time() - last_activity_time > 60: # 300 seconds = 5 minutes of inactivity
            print("You have been inactive for too long. You will be logged off.")
            encryptedMessage = fernet_Encryptor._encrypt_from_parts(b"LOG OFF", 0,b'\xbd\xc0,\x16\x87\xd7G\xb5\xe5\xcc\xdb\xf9\x07\xaf\xa0\xfa')
            tcp_socket.send(encryptedMessage)
            break
        time.sleep(1) # Check for inactivity every second

def receive_messages(fernet_Encryptor):
    while True:
        data = tcp_socket.recv(4096)
        if data: 
            decrypted_data = fernet_Encryptor.decrypt(data)
            if(decrypted_data == b"CHAT_STARTED"):
                print("Chat started")
            elif(b"CHAT_STARTED WITH" in decrypted_data):
                clientLetter = decrypted_data[-1:]
                msg = b"Chat initiated with client: " + clientLetter
                print(msg.decode())
                encryptedMessage = fernet_Encryptor._encrypt_from_parts(msg, 0,b'\xbd\xc0,\x16\x87\xd7G\xb5\xe5\xcc\xdb\xf9\x07\xaf\xa0\xfa')           
                tcp_socket.send(encryptedMessage)
            elif(b"UNREACHABLE" == decrypted_data):
                print("Correspondent unreachable")
                
            elif(b"END NOTIF" == decrypted_data):
                print("chat ended")
                encryptedMessage = fernet_Encryptor._encrypt_from_parts(b"INCHAT_FALSE", 0,b'\xbd\xc0,\x16\x87\xd7G\xb5\xe5\xcc\xdb\xf9\x07\xaf\xa0\xfa')
                tcp_socket.send(encryptedMessage)
            elif(b"END REQUEST 2" == decrypted_data):
                print("chat ended")
                encryptedMessage = fernet_Encryptor._encrypt_from_parts(b"END REQUEST 2", 0,b'\xbd\xc0,\x16\x87\xd7G\xb5\xe5\xcc\xdb\xf9\x07\xaf\xa0\xfa')
                tcp_socket.send(encryptedMessage)
            elif(b"LOG OFF" == decrypted_data):
                print("You have been successfully logged off.")
                
            else:
                print(decrypted_data.decode())

while True:
    msg = input("")
    last_activity_time = time.time()
    if(msg == "log on"):
        #HELLO protocol
        msg = "Hello"
        data_string = json.dumps({"a": msg, "b":clientID})
        client_socket.sendto(data_string.encode(), ('127.0.0.1',12345))
    #Store CHALLENGE sent from server

    message, client_address = client_socket.recvfrom(4096)
    rand = message.decode()
    #If server rejects our login due to Client ID issue, exit and let the client know
    if str(message) == "Client ID not accepted":
        print('User is not in list of subscribers')
        continue
    #Now calculate our res HASH
    result = secret + int(rand)
    stringEncoder = str(result)
    hashObject = hashlib.md5(stringEncoder.encode())
    RES = hashObject.hexdigest()
    #Send our RES message to the server
    client_socket.sendto(str(RES).encode(), ('127.0.0.1',12345))

    #Server now sends back authentication check. Test if failed, if not move forward
    random_cookie, addr = client_socket.recvfrom(4096)
    port, addr = client_socket.recvfrom(4096)
    #If auth failed, random_cookie will contain the failure
    if(random_cookie.lower() == 'client has failed authentication'):
        print("Client has failed authentication")
        continue
    else:
        print("Connected")
    #We know authentication was succesful
    #Now to decrypt random_cookie and port
    #Create our encryption/decryption device
    fernet_Encryptor = createKey(int(rand))
    decrypted_rand = fernet_Encryptor.decrypt(random_cookie)
    decrypted_rand = int.from_bytes(decrypted_rand, "big")
    decrypted_port = fernet_Encryptor.decrypt(port)
    decrypted_port = int.from_bytes(decrypted_port, "big")

    #Now we must send CONNECT
    client_socket.sendto(random_cookie, ('127.0.0.1',12345))
    tcp_socket.connect(('127.0.0.1',decrypted_port))
    data = tcp_socket.recv(4096)
    decrypted_data = fernet_Encryptor.decrypt(data)
    #Loop to handle TCP messages
    threading.Thread(target=receive_messages, args = [fernet_Encryptor]).start()
    threading.Thread(target=check_inactivity).start()
    while True:
        message = input("")
        last_activity_time = time.time()
        encryptedMessage = fernet_Encryptor._encrypt_from_parts(bytes(message,'utf-8' ), 0,b'\xbd\xc0,\x16\x87\xd7G\xb5\xe5\xcc\xdb\xf9\x07\xaf\xa0\xfa')
        if(message == "log off"):
            print("You have successfully logged off")
            encryptedMessage = fernet_Encryptor._encrypt_from_parts(b"LOG OFF", 0,b'\xbd\xc0,\x16\x87\xd7G\xb5\xe5\xcc\xdb\xf9\x07\xaf\xa0\xfa')
            tcp_socket.sendall(encryptedMessage)
            killTimerThread = True

        elif(message == "end chat"):
            print("chat ended")
            #END REQUEST
            encryptedMessage = fernet_Encryptor._encrypt_from_parts(b"END REQUEST", 0,b'\xbd\xc0,\x16\x87\xd7G\xb5\xe5\xcc\xdb\xf9\x07\xaf\xa0\xfa')
            tcp_socket.sendall(encryptedMessage)
            #break
        elif("Chat Client-ID" in message):
            #CHAT REQUEST
            tcp_socket.sendall(encryptedMessage)
        elif("History" in message):
            #HISTORY REQ
            tcp_socket.sendall(encryptedMessage)
        else:
            tcp_socket.sendall(encryptedMessage)

    