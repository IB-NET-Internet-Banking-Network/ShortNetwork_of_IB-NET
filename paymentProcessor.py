"""
Author :- Manas Kumar Mishra
Task :- Payment process (client for card company and server for payment gateway)
Begin date :- 21 - March - 2021 
"""

from socket import*
from random import randint
from AES_Encrypt import*  #Python file name for encryption
from AES_Decrypt import*  #Python file name for decryption


global dataofUsers
dataofUsers ={
	'MANAS':['MANAS', '1001 0110 2002 0011', '2023-07-31', '000', 'MANAS KUMAR MISHRA'],
	'MISS KR':['MISS KR','1001 0110 2002 0026','2023-07-31','001','KARTHIKA RAJESH'],
	"GANESH":['GANESH','1001 0110 2002 0006','2023-07-31','002','GANESH T S']
}

# function for converting the binary message into list
# Input is receved message from payment gateway
# output is full message in list
def give_list(recvMessage):
	recvMessage = recvMessage.decode()

	recvMessage2 = eval(recvMessage)

	return recvMessage2

	


payProPortNumber = 9990

TPSportnumber = 9980
TPSipaddress = '192.168.43.99'

payProInstance = socket(AF_INET, SOCK_STREAM)
TPSsocket = socket(AF_INET,SOCK_STREAM)


payProInstance.bind(('',payProPortNumber))
payProInstance.listen(1)


print("Payment processor is listening...")
while 1:
	
	paygateInstance, paygetAddress = payProInstance.accept()
	TPSsocket.connect((TPSipaddress, TPSportnumber))
	print("Connection excepted...:)")
	
	# recieving user data 

	Shared=share_key() #sharing public key for encryption
	paygateInstance.send(Shared.encode())
	
	#Decryption
	recvMessage = paygateInstance.recv(4096)
	print("Something RECEIVED...:)",recvMessage)
	#recvMsg = give_list(recvMessage)
	recvmsg=recvMessage.decode()
	recvMsg=eval(recvmsg)	
	recvMsg = AES_Decrypt(recvMsg[0],recvMsg[1])	
	recvMsg=recvMsg.split(",")
	print('decrypted message',recvMsg)
	
	if(recvMsg==list(dataofUsers['MANAS']) or recvMsg==list(dataofUsers['MISS KR']) or recvMsg == list(dataofUsers['GANESH'])):
		'''paygateInstance.send("True".encode())

		# Receive the amount details
		recvAmount = paygateInstance.recv(2048)

		recvAmt = give_list(recvAmount)'''

		#send feedback after data verification
		sharekey=paygateInstance.recv(2048)
		Plaintext='True'
		encrypteddata=str(AES_encrypt(sharekey,Plaintext))
		paygateInstance.send(encrypteddata.encode())

		# Receiving the amount details 
		print("Receiveing the amount info....")
		shky=share_key()
		paygateInstance.send(shky.encode())
		recvAmount = paygateInstance.recv(2048)
		recvAmt = recvAmount.decode()
		recvAmt = eval(recvAmt)
		recvAmt = AES_Decrypt(recvAmt[0],recvAmt[1])
		recvAmt=recvAmt.split(",")

		print("Amount received...")
		
		print("Amount requested :", recvAmt)

		paygateInstance.close()

		# Todo:- TPS PART. 
		# Here , we are making a packet for communicating with TPS layer
		packet = []
		# Card number 
		packet.append(recvMsg[1]) 

		# Card holder name 
		packet.append(recvMsg[4])

		# Amount and merchent 
		packet.append(recvAmt[0])
		packet.append(recvAmt[1])
		packet.append(recvAmt[2])

		#packet = str(packet)
		#TPSsocket.send(packet.encode())
		Plaintext=str(packet[0])
		for i in range(1,len(packet)):
			Plaintext=Plaintext +','+ packet[i]
		
		#print('plaintext',Plaintext)

		#Sending Packet to TPS layer 1
		shkey=TPSsocket.recv(2048)
		encrypteddata=str(AES_encrypt(shkey,Plaintext))
		TPSsocket.send(encrypteddata.encode())

		
		print("Amount requested :", recvAmt[0])

	else:
		#paygateInstance.send("False".encode())
		shkey=TPSsocket.recv(2048)
		Plaintext='False'
		encrypteddata=str(AES_encrypt(shkey,Plaintext))
		TPSsocket.send(encrypteddata.encode())
		paygateInstance.close()

		print("Wrong detalis")


	otpinstance, otpaddress = payProInstance.accept()
	
	print("Ready to listen OTP...")
	
	#recvOTP = otpinstance.recv(2048)
	shky=share_key()
	otpinstance.send(shky.encode())
	recvotp = otpinstance.recv(4096)
	recvotp = recvotp.decode()
	recvotp = eval(recvotp)
	recvotp = AES_Decrypt(recvotp[0],recvotp[1])
	print('otp recieved')
	
	# Todo :- Encryption and decryption
	#TPSsocket.send(recvOTP)
	shkey=TPSsocket.recv(2048)	
	encrypteddata=str(AES_encrypt(shkey,recvotp))
	TPSsocket.send(encrypteddata.encode())	
	

	print("Otp send to the TPS")
	#recv = TPSsocket.recv(2048)
	shky=share_key()	
	TPSsocket.send(shky.encode())
	recve = TPSsocket.recv(2048)
	recve = recve.decode()
	recve = eval(recve)	
	recve = AES_Decrypt(recve[0],recve[1])

	
	#otpinstance.send(recv)
	shkey=otpinstance.recv(2048)	
	encrypteddata=str(AES_encrypt(shkey,recve))
	otpinstance.send(encrypteddata.encode())
	print("Received feedback about otp")


	TPSsocket.close()
	otpinstance.close()

    
   


