"""
Author :- Ganesh T S, Manas Kumar mishra
Task :- Design for Transaction processing system (TPS). That perform the OTP part.
Begin DATE :- 05- MARCH- 2021
"""

from socket import *
import datetime
from random import randint
from AES_Encrypt import*  #Python file name for encryption
from AES_Decrypt import*  #Python file name for decryption

# CIF Customer Information file
# It maaps between the Card info to the Bank information
global CIF_number
CIF_number={
    "1001 0110 2002 0011":"98765432011",
    "1001 0110 2002 0026":"98765432026",
    "1001 0110 2002 0006":"98765432006"
}

# Mapping between the CIF number to the Account detalis
global accountDetails
accountDetails={
    "98765432011":["00000000011", "RBIS0PFMS01"],
    "98765432026":["00000000026", "RBIS0PFMS01"],
    "98765432006":["00000000006", "RBIS0PFMS01"],
}

# function for converting the binary message into list
# Input is receved message from payment gateway
# output is full message in list
def give_list(recvMessage):
	recvMessage = recvMessage.decode()

	recvMessage2 = eval(recvMessage)

	return recvMessage2

# Funtion for generating the Otp
# Input is nothing
# Output is Generated Otp

def otp_gen():
    otpgenerated = randint(100001, 999999)

    print("Generated OTP is :- ", otpgenerated)

    return otpgenerated


TpsPortNumber = 9980

TpsServer = socket(AF_INET, SOCK_STREAM)

TpsServer.bind(('192.168.43.99', TpsPortNumber))
TpsServer.listen(1)


print("TPS is ready to connected with pp ...")


a=datetime.datetime.now()

"""
NOTE:- for ganesh, Amount is coming in the while loop , 3rd element of the recvInfo list is the amount.
Hence if you can add all your socket connection and processes into this while loop then we won't face any issue.
"""
amount=1000
amount1=amount*1.1

try:
    ppInstance, ppAddress = TpsServer.accept()
    print("Connection accepted with pp...")
except:
    print("Connection not accepted!!!")


while 1:

    # try:
    #     ppInstance, ppAddress = TpsServer.accept()
    #     print("Connection accepted with pp...")
    # except:
    #     print("Connection not accepted!!!")

    
    # print("Connection established...")

    # todo:- Receiving the list 
    shky=share_key()
    ppInstance.send(shky.encode())
    recvMsgFromPP = ppInstance.recv(2048)
    #recvInfo = give_list(recvMsgFromPP)

    recvMsgFromPP=recvMsgFromPP.decode()
    recvMsgFromPP=eval(recvMsgFromPP)	
    recvMsgFromPP = AES_Decrypt(recvMsgFromPP[0],recvMsgFromPP[1])	
    recvInfo=recvMsgFromPP.split(",")
    print('decrypt',recvInfo)

    print("Received message...")
    print(recvInfo)

    cardNumber = recvInfo[0]
    print(cardNumber)
    print(CIF_number[str(cardNumber)])

    merchantinfo = recvInfo[3]
    print("Merchent name : ",merchantinfo)

    # Todo :- From cif number pick account number
    #  
    OTP = otp_gen()

    shky=share_key()
    ppInstance.send(shky.encode())

    receivedOtp=ppInstance.recv(2048)
    #recvotp = receivedOtp.decode()
    receivedOtp=receivedOtp.decode()
    receivedOtp=eval(receivedOtp)	
    recvotp = AES_Decrypt(receivedOtp[0],receivedOtp[1])


    print("RECEIVED OTP from the user :- ",recvotp)

    if recvotp == str(OTP):
        print('otp checked')
        #ppInstance.send("True".encode())
        sharekey=ppInstance.recv(2048)
        print('shke',sharekey)
        Plaintext='True'
        encrypteddata=str(AES_encrypt(sharekey,Plaintext))
        ppInstance.send(encrypteddata.encode())
        print('feedbcack sent')
        
    else:
        print('otp wrong')
        #ppInstance.send("False".encode())
        sharekey=ppInstance.recv(2048)
        Plaintext='False'
        encrypteddata=str(AES_encrypt(sharekey,Plaintext))
        ppInstance.send(encrypteddata.encode())

    # ppInstance.close()
    # ppInstance.send("1".encode())


# Todo:- ADD all below work inside the while loop such that it can communicate properly with bank1, and bank2. 

