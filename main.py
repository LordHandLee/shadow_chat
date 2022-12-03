##TODO##
# ask for user username, send username to server so client knows who they are chatting with
# do initial scan to map ip addresses to networks and save to database
# periodically do scan to detect changes and update database
# use database to reduce search time to 0 when targeting network
import json
import urllib.request
#import ipaddress
from itertools import product
import time
from socket import *
import threading
from queue import *
import rsa

pub = {'e':65537, 'n':6840329405354158825935811487735653937726223310556535182461476478972023350689721178294535060329678937257808641950171663055140305413308602841005927907274523}
priv = {'d':3674992727200206482768511260557736471723458851712705857370166269811021896348782617397020082148196884984147143443971503858452529318327652673129960115169313,
'p':4452567913584497100240412803028838245003287279767580678145854277377888492698979049, 'q':1536266158790022190712751955030168664787945784213343579276269431911849827}
pub1 = rsa.PublicKey(n=pub['n'], e=pub['e'])
priv1 = rsa.PrivateKey(n=pub['n'], e=pub['e'],d=priv['d'], p=priv['p'], q=priv['q'])

def decrypt(m):
    message1 = rsa.decrypt(m, priv1).decode('utf-8')
    return message1
def encrypt(m):
    crypt = rsa.encrypt(m.encode('utf-8'), pub1)
    return crypt

clientSocket = socket(AF_INET, SOCK_STREAM) #intialize our socket

def get_ip_info(ip):
    GEO_IP_API_URL  = 'http://ip-api.com/json/'
    # Can be also site URL like this : 'google.com'
    IP_TO_SEARCH    = ip
    # Creating request object to GeoLocation API
    req = urllib.request.Request(GEO_IP_API_URL+IP_TO_SEARCH)
    # Getting in response JSON
    response = urllib.request.urlopen(req).read()
    # Loading JSON from text to object
    json_response = json.loads(response.decode('utf-8'))
    return json_response['city'],json_response['region'],json_response['country'],json_response['as']
def find_target(city_tar, region_tar,q):
    message = "Is this Ethan's chat client?"
    for i,j in product(range(152,153),range(20,21)):
        # loop through all class b network addresses and find target
        #print("{0}.{1}.0.0".format(i,j))
        # check queue for ip address, if one, break loop and return ip
        if q.qsize() > 0:
            ip = q.get()
            return ip
        ip = "{0}.{1}.0.0".format(i,j)
        city, region, country, provider = get_ip_info(ip)
        print(city, region)
        if city == city_tar and region == region_tar:
            print("yes")
            for p,g in product(range(256),range(256)):
                ip = "{0}.{1}.{2}.{3}".format(i,j,p,g)
                print("connecting")
                clientSocket.settimeout(5)
                try:
                    clientSocket.connect((ip, 12000)) # connect to the server
                    clientSocket.send(message.encode()) #encode and send message
                    print("message sent ")
                    reply = clientSocket.recv(1024) # receive message from server
                    #print("From Server: ", reply.decode()) #display response from server
                    if reply.decode() == "Yes, this is Ethan's chat client.": # reply.decode().split(" ")[0]
                        clientSocket.close() #close connection
                        return ip
                    clientSocket.close() #close connection
                except:
                    print("Connection timed out. Port most likely closed.")
                    continue
        time.sleep(2)
    return "No targets available."
def server_function(q):
    serverPort = 12000
    serverSocket = socket(AF_INET, SOCK_STREAM)
    # handle address already in use error
    try:
        serverSocket.bind(("",serverPort))
        serverSocket.listen(1)
    except OSError:
        print("Address already in use. Server was not shut down properly?")
    print("The server is ready to receive")
    while True:
        connectionSocket,addr = serverSocket.accept() #accept incoming connection
        sentence = connectionSocket.recv(1024).decode() #receive data
        if sentence: # if data, do stuff
            #print(sentence)
            #q.put(addr)
            if sentence == "Is this Ethan's chat client?":
                q.put(addr)
                status = "Yes, this is Ethan's chat client."
                connectionSocket.send(status.encode()) #encode and send message to client
                connectionSocket.close() # close connection
            else:
                print(decrypt(sentence))
def main():
    # ask for target
    # proceed to find target
    #spawn find server in new thread
    # if no target, check again in 10 minutes
    # if target, listen/send messages
    # if connection has been established thru server, stop trying to find target
    # server always runs and listens for messages
    # listen to user input in main loop and send to other user server.
    city = input("Please enter target city.")
    region = input("Please enter target region.")
    q = Queue()
    server = threading.Thread(target=server_function, args=[q], daemon=True)
    server.start()
    guest_ip = None
    while True:
        print(q.qsize())
        # if q.qsize() > 0:
        #     print("something was put in the queue")
        #     f = q.get()
        #     print(f[0])
        # time.sleep(1)
        print("Finding a target client.")
        ip = find_target(city, region, q)
        
        if ip != "No targets available.": #check for targets
            print("Found client! Connecting to :", ip)
            clientSocket.connect((ip, 12000)) # connect to ip
            guest_ip = ip[0]
            break
        if ip == "No targets available.":
            print("No targets available. Resuming in 5.")
            time.sleep(60*5)
    while True:
        # find target breaks out of loop bcus server connection
        # ask user for message
        # send message to server
        # if no response from server, find target again

        # server receives message and prints, puts ip address in queue if incoming connection
        # main loop checks for user input and sends to other person
        # if len(q) > 0:
        #     q.clear()
        message = input("Enter message: ") #get the message
        if message:
            if guest_ip != None:
                try:
                    clientSocket.send(encrypt(message)) #encode and send message to server
                except:
                    # find new target ip
                    print("Could not send message to other party. Acquiring new target.")
                    while True:
                        ip = find_target(city, region, q)
                        if ip != "No targets available.": #check for targets
                            print("Found client! Connecting to :", ip)
                            clientSocket.connect((ip, 12000)) # connect to ip
                            guest_ip = ip
                            break
                        if ip == "No targets available.":
                            print("No targets available. Resuming in 5.")
                            time.sleep(60*5)


main()
