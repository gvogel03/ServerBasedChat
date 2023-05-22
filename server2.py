import socket
import json
import hashlib
import base64
import random
import threading
import queue
import time
import select
import threading
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.fernet import Fernet

#Create UDP Socket
sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
#Bind UDP socket
sock.bind(('127.0.0.1', 12345))

#Create TCP Socket
server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

#Variables

#Keeps track of each clients secret key
secretKeys = [32739670, 22375432, 16991266, 19015368, 14999921, 45979295, 17056450, 96676913, 97153915, 11779913]
#Keep track of all connected clients
connectedClients = ''
#Keeps track of which clients are currently chatting with each other
clientsInChat = ""
#Used to keep track of each different clients encryption key
Fernet_Keys = [Fernet] * 10
XRES = ""
#Keeps track of client addresses
UDPclients = [None] * 10
#Random TCP port we are using for all communications
Tcp_port = 200
#Used to keep track of each clients unique TCP socket
sockets = {}
#Keeps track of history
history = [""] * 10
#Function to create RES 
def createRes(data):
    clientSecret = secretKeys[int(data) - 1]   
    # Processes XRES
    result = rand + clientSecret
    stringEncoder = str(result)
    hashObject = hashlib.md5(stringEncoder.encode())
    XRES = hashObject.hexdigest()
    return XRES    

#Used to create CK_A - an encryption key based on the hash of Random and clientSecret. This is used to create a fernetEncryptor, allowing our CK_A to encrypt messages
def createKey(clientID, rand):
    #CK_A = hash2(rand + K_A)
    result = rand + secretKeys[int(clientID) -1]
    stringEncoder = str(result)
    CK_A = hashlib.sha256(stringEncoder.encode())
    KeyA = CK_A.digest()
    KeyA = base64.urlsafe_b64encode(KeyA)
    #Create a fernet encryption key using the cipher key we just hashed
    fernetEncryptor = Fernet(KeyA)
    Fernet_Keys[int(clientID) -1] = fernetEncryptor
    #Return the encryption object
    return fernetEncryptor

#Handles TCP communication by creating new threads for each unique client
def handle_client(clientID):
    #Variables
    inchat = False
    clientID2 = 0
    global clientsInChat
    #Set up TCP connection and store in sockets
    conn, addr = server_socket.accept()
    sockets[int(clientID)] = conn
    print(f"New connection from {addr}")
    sessionID = addr[1]
    #CONNECTED
    welcomeMessage = Fernet_Keys[int(clientID) - 1]._encrypt_from_parts((b"Welcome to the server!"),0,b'\xbd\xc0,\x16\x87\xd7G\xb5\xe5\xcc\xdb\xf9\x07\xaf\xa0\xfa')
    conn.send(welcomeMessage)
    recipientSocket = conn
    print("history under")
    print(history[int(clientID) - 1])
    #Loop for handling input
    while True:
        #Receieve messages
        data = conn.recv(1024)
        #All messages received are encrypted, must decrypt to see contents
        decryptedData = Fernet_Keys[int(clientID) - 1].decrypt(data)
        if not data:
            break
        #Print data and where it is from, debugging purposes DELETE LATER
        print(f"Received from {addr}: {decryptedData}")
        #Check if client is trying to initiate conversation with other client
        if(b"Chat initiated with client" in decryptedData):
            print("Client initiated chat")
            decryptedData = Fernet_Keys[int(clientID) - 1].decrypt(data)
            clientLetter = decryptedData[-1:]
            clientID2 = ord(clientLetter) - 64
            inchat = True
            clientsInChat += clientLetter.decode().upper()
            recipientSocket = sockets[clientID2]
            while True:
                data = conn.recv(4096)
                #All messages are encrypted, must decrypt to see contents
                decryptedData = Fernet_Keys[int(clientID) - 1].decrypt(data)
                print("Int below")
                print(int(clientID) -1)
                if(b"INCHAT_FALSE" == decryptedData):
                    letter1 = chr(int(clientID) + 64)
                    letter2 = chr(clientID2 + 64)
                    #Have to clear out clientsInChat to allow these clients to receive/create new connections
                    clientsInChat = clientsInChat.replace(str(letter1), "")
                    clientsInChat = clientsInChat.replace(str(letter2), "")
                    inchat = False
                    break
                if(b"END REQUEST" == decryptedData):
                    #Send this to other user
                    encryptedMessage = Fernet_Keys[int(clientID2) - 1]._encrypt_from_parts(b"END REQUEST 2",0,b'\xbd\xc0,\x16\x87\xd7G\xb5\xe5\xcc\xdb\xf9\x07\xaf\xa0\xfa')
                    recipientSocket.send(encryptedMessage)
                    inchat = False
                    break
                letter2 = chr(int(clientID) + 64)
                history[int(clientID) - 1] += letter2 + ", " + decryptedData.decode() + ": "
                history[int(clientID2) - 1] += letter2 + ", " + decryptedData.decode() + ": "
                print(history[int(clientID) - 1])
                print(history[int(clientID2) - 1])
                encryptedMessage = Fernet_Keys[int(clientID2) - 1]._encrypt_from_parts(decryptedData,0,b'\xbd\xc0,\x16\x87\xd7G\xb5\xe5\xcc\xdb\xf9\x07\xaf\xa0\xfa')
                recipientSocket.send(encryptedMessage)
            #break
        elif(b"Chat Client-ID" in decryptedData):
            #Grab the client they are trying to talk to from our data
            clientLetter = decryptedData[-1:]
            #Convert this to a corresponding integer value. This will be used to get the correct encryption protocol
            clientID2 = ord(clientLetter) - 64
            print("Current chat members: " + clientsInChat)
            print("Client letter: " + str(clientLetter)[2])
            print("clientID2: " + str(clientID2))
            #Check if client is trying to chat with themselves
            if(clientID2 == int(clientID)):
                print("You cannot chat with yourself!")
                encryptedMessage = Fernet_Keys[int(clientID) - 1]._encrypt_from_parts((b"You cannot chat with yourself!"),0,b'\xbd\xc0,\x16\x87\xd7G\xb5\xe5\xcc\xdb\xf9\x07\xaf\xa0\xfa')
                conn.send(encryptedMessage)       
            #If client is already chatting with someone else, generate an error
            elif(str(clientLetter)[2] in clientsInChat):
                #UNREACHABLE
                print("Client " + str(clientLetter) + " is trying to connect to Client " + str(clientID2))
                encryptedMessage = Fernet_Keys[int(clientID) - 1]._encrypt_from_parts((b"UNREACHABLE"),0,b'\xbd\xc0,\x16\x87\xd7G\xb5\xe5\xcc\xdb\xf9\x07\xaf\xa0\xfa')
                conn.send(encryptedMessage)
            elif(str(clientID2) in connectedClients):
                inchat = True
                #Put this client in list of clients currently chatting
                num = int(clientID)
                letter = chr(num + 64)
                if(str(letter).upper()  not in clientsInChat):
                    clientsInChat += str(letter).upper()
                letter2 = chr(clientID2 + 64)
                if(str(letter2) not in clientsInChat):
                    clientsInChat += str(letter2)
                print("Clients in chat: " + str(clientsInChat))
                #retrieves recipient's socket from dictionary
                recipientSocket = sockets[clientID2]
                encryptedMessage = Fernet_Keys[int(clientID) - 1]._encrypt_from_parts((b"CHAT_STARTED"),0,b'\xbd\xc0,\x16\x87\xd7G\xb5\xe5\xcc\xdb\xf9\x07\xaf\xa0\xfa')
                conn.send(encryptedMessage)
                #Convert client ID to corresponding letter
                letterID = chr(int(clientID) + 64)
                recipientSocket.send(Fernet_Keys[int(clientID2) - 1]._encrypt_from_parts((b"CHAT_STARTED WITH CLIENT: " + bytes(letterID, 'utf-8')),0,b'\xbd\xc0,\x16\x87\xd7G\xb5\xe5\xcc\xdb\xf9\x07\xaf\xa0\xfa'))

            else:
                encryptedMessage = Fernet_Keys[int(clientID) - 1]._encrypt_from_parts((b"UNREACHABLE"),0,b'\xbd\xc0,\x16\x87\xd7G\xb5\xe5\xcc\xdb\xf9\x07\xaf\xa0\xfa')
                conn.send(encryptedMessage)
    
            
        elif(b"History Client-ID" in decryptedData):
            tempID = decryptedData[-1:].decode()
            print(tempID)
            clientLetter = chr(int(clientID) + 64)
            print(clientLetter)
            histList = history[int(clientID) - 1].split(": ")
            print(history[int(clientID) - 1])
            for message in histList:
                print(message)
                if(len(message) > 1):
                    if(message[0] == tempID or message[0] == clientLetter):
                        encryptedMessage = Fernet_Keys[int(clientID) - 1]._encrypt_from_parts((bytes(message, 'utf-8')),0,b'\xbd\xc0,\x16\x87\xd7G\xb5\xe5\xcc\xdb\xf9\x07\xaf\xa0\xfa')
                        conn.sendall(encryptedMessage)
        elif(b"END REQUEST" == decryptedData):
            recipSocket = sockets[clientID2]
            encryptedMessage = Fernet_Keys[int(clientID2) - 1]._encrypt_from_parts((b"END NOTIF"),0,b'\xbd\xc0,\x16\x87\xd7G\xb5\xe5\xcc\xdb\xf9\x07\xaf\xa0\xfa')
            recipSocket.send(encryptedMessage)
            clientsInChat.replace(clientID, '')
            clientsInChat.replace(str(clientID2), '')
            inchat = False
            continue
        #Because of how our nested loop works, we need a way for inchat to be set to FALSE for both clients. While in retrospect there are simpler ways to do this, adding a new request works in all scenarios
        elif(b"END REQUEST 2" == decryptedData):
            clientsInChat.replace(clientID, '')
            clientsInChat.replace(str(clientID2), '')
            inchat = False
            continue
        elif(inchat == False):
            '''encrypted_data = Fernet_Keys[(int(clientID)) - 1]._encrypt_from_parts((decryptedData),0,b'\xbd\xc0,\x16\x87\xd7G\xb5\xe5\xcc\xdb\xf9\x07\xaf\xa0\xfa')
            print("sending " + str(data) + " to " + str(recipientSocket))
            conn.send(encrypted_data)'''
        elif(inchat == True):
            #data = encrypted by initiating client
            #decrypted_data 
            letter = chr(num + 64)
            history[int(clientID) - 1] += letter + ", " + decryptedData.decode() + ": "
            history[int(clientID2) - 1] += letter + ", " + decryptedData.decode() + ": "
            print("Within true chat")
            print(history)
            encrypted_data = Fernet_Keys[(int(clientID2)) - 1]._encrypt_from_parts((decryptedData),0,b'\xbd\xc0,\x16\x87\xd7G\xb5\xe5\xcc\xdb\xf9\x07\xaf\xa0\xfa')
            print("sending " + str(data) + " to " + str(recipientSocket))
            recipientSocket.send(encrypted_data)

        elif(b"LOG OFF" == decryptedData):
            encryptedMessage = fernet_Encryptor._encrypt_from_parts(b"LOG OFF", 0,b'\xbd\xc0,\x16\x87\xd7G\xb5\xe5\xcc\xdb\xf9\x07\xaf\xa0\xfa')
            conn.sendall(encryptedMessage)
            print(decryptedData)
            print(encryptedMessage)
            
            conn.close()
            
    #cleaning after client ends connection. removes socket from dictionary, closes connection.
    del sockets[int(clientID)]
    conn.close()
    connectedClients.replace(clientID, '')
    print(f"Connection closed from {addr}")
    #This erases the presence of the client from clients in chat - allowing them to be open to receiving connections from other clients
    clientsInChat.replace(clientID, '')


#Bind TCP port, can really be done wherever 
server_socket.bind(('127.0.0.1', Tcp_port))

#Receive new UDP messages
while True:
    # Receive incoming messages from clients
    recData, client_address = sock.recvfrom(4096)
    data = json.loads(recData.decode())
    messageValue = data.get("a")
    clientID = data.get("b")
    rand = random.randint(1,100)
    rand_cookie = random.randint(1,100)
    #See if client ID is accepted
    # Add the client address to the list of connected clients
    if(messageValue == "Hello"):
        if(int(clientID) < 1 or int(clientID) > 5):
            print("Client ID not accepted")
            Authentication = b"Client ID not accepted"
            sock.sendto(Authentication,client_address)
            break
        #Begin connection process
        elif client_address not in UDPclients:           
            UDPclients[int(clientID) -1] = client_address
            connectedClients += str(clientID)
            #Send back CHALLENGE 
            challenge = rand
            sock.sendto(str(challenge).encode('ascii'),client_address)
            #Receive RES from user
            RES, client_address = sock.recvfrom(4096)
            RES = RES.decode()
            #Create our own Res
            XRES = createRes(clientID)
            #Make sure the two are the same
            if(XRES == RES):
                #donothing
                a = 1
            else:
                print("Error authenticating")
                sock.sendto(b"Client has failed authentication", client_address)
                sock.sendto(b"Formatting message, ignore", client_address)
                UDPclients[int(clientID) -1] = 0
                continue
            #Create a fernet encryption key using the cipher key we just hashed
            fernet_Encryptor = createKey(clientID, rand)
            #Now encrypt our random cookie
            encrypted_random = fernet_Encryptor._encrypt_from_parts(rand_cookie.to_bytes(2, 'big'), 0,b'\xbd\xc0,\x16\x87\xd7G\xb5\xe5\xcc\xdb\xf9\x07\xaf\xa0\xfa')
            #Encrypt our port
            EncryptedPort = fernet_Encryptor._encrypt_from_parts(Tcp_port.to_bytes(2, 'big'), 0,b'\xbd\xc0,\x16\x87\xd7G\xb5\xe5\xcc\xdb\xf9\x07\xaf\xa0\xfa')
            #Send encrypted port and random
            sock.sendto(encrypted_random, client_address)
            sock.sendto(EncryptedPort, client_address)
            #Want different TCP ports for each connection
        else:
            print("Already connected")

        #Now receive CONNECT message
        connMessage, client_address = sock.recvfrom(4096)
    
        server_socket.listen(10)
            # Accept a new connection
            # Start a new thread to handle the connection
        t = threading.Thread(target=handle_client, args = clientID)
        t.start()




  

    











