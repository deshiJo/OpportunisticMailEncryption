#!/usr/bin/env python3

import sys
import json
import struct
import re
import socket
#import smtplib import SMTP

#app manifest location:
#https://developer.mozilla.org/en-US/docs/Mozilla/Add-ons/WebExtensions/Native_manifests#Manifest_location

server = ""
recipient = ""
OK_RECV = "OK RECV"
RECV = "RECV: "
OK_SERVER = "OK SERVER"
SERVER = "SERVER: "
FAIL = "FAIL"
NOT_SUPPORTED = "NOT_SUPPORTED"
CERT_RESPONSE = "CERT: "
OK = "OK: "
WHITESPACE = " "
EHLO = "EHLO "
XCERTREQ = "XCERTREQ"
STARTTLS = "STARTTLS"
QUIT = "QUIT"
CRLF = "\r\n"
#https://www.regextester.com/19
mail_regex = re.compile("^[a-zA-Z0-9.!#$%&'*+=?^_`{|}~-]+@[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?(?:\.[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?)*$")

try:
    # Python 3.x version
    # Read a message from stdin and decode it.
    def getMessage():
        rawLength = sys.stdin.buffer.read(4)
        if len(rawLength) == 0:
            sys.exit(0)
        messageLength = struct.unpack('@I', rawLength)[0]
        message = sys.stdin.buffer.read(messageLength).decode('utf-8')
        return json.loads(message)

    # Encode a message for transmission,
    # given its content.
    def encodeMessage(messageContent):
        encodedContent = json.dumps(messageContent).encode('utf-8')
        encodedLength = struct.pack('@I', len(encodedContent))
        return {'length': encodedLength, 'content': encodedContent}

    # Send an encoded message to stdout
    def sendMessage(encodedMessage):
        sys.stdout.buffer.write(encodedMessage['length'])
        sys.stdout.buffer.write(encodedMessage['content'])
        sys.stdout.buffer.flush()

    def start_Exchange(server, recipient):

        #for tests: remove these:
        server = "mail1.de"
        port = 25
        recipient = "<joachim@mail1>"

        fqdn = socket.getfqdn().encode()
        # server_info = (server, port)
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.connect((server, port))
            s.send(EHLO.encode() + fqdn + CRLF.encode())
            r = s.recv(1024)

            #send message to connection.js, to print it on console.log
            sendMessage(encodeMessage(OK+r.decode()))
            sendMessage(encodeMessage(OK+socket.getfqdn()))

            #check if smtp server supports XCERTREQ and STARTTLS 
            if not STARTTLS in r.decode() or not XCERTREQ in r.decode():
                sendMessage(encodeMessage(NOT_SUPPORTED))






    while True:
        receivedMessage = getMessage()

        #received recipient mail address
        if receivedMessage.startswith(RECV):
            splittedMSG = receivedMessage.split()
            if len(splittedMSG) == 2:
                if mail_regex.match(splittedMSG[1]):
                    recipient = splittedMSG[1]
                    sendMessage(encodeMessage(OK_RECV))
                else:
                    #message does not match mail address regex
                    sendMessage(encodeMessage(FAIL))
            else:
                #unknown message
                sendMessage(encodeMessage(FAIL))
        elif receivedMessage.startswith(SERVER):
            #TODO edit if I know, how to extract this information
            # maybe access prefs.js instead of getting through message ? 
            sendMessage(encodeMessage(OK_SERVER))
            start_Exchange(server, recipient)
            
except AttributeError:
    pass
