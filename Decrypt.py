### Call syntax
### Decrypt.py CipherText.txt Message.txt
### The decrypted message is sent to the file message.txt

import sys
from BitVector import *

if len(sys.argv) is not 3:
    sys.exit('''Please run this script with the correct number of arguments.''')

BLOCKSIZE=64
numBytesPerBlock = BLOCKSIZE // 8
numCharsPerBlock = numBytesPerBlock

PassPhrase = "I want to learn cryptograph and network security"

bv_iv = BitVector(size = BLOCKSIZE)                                    
for i in range(0,len(PassPhrase) // numCharsPerBlock):                                
    textstr = PassPhrase[i*numCharsPerBlock:(i+1)*numCharsPerBlock]                          
    bv_iv ^= BitVector( textstring = textstr )                              

key= None
if sys.version_info[0]==3:
    key = input('\nEnter Key: ')
else:
    key = raw_input('\nEnter Key: ')
key=key.strip()

key_bv=BitVector(size=BLOCKSIZE)
for i in range(0,len(key)//numCharsPerBlock):
    key_bv ^= BitVector(textstring = key[i*numCharsPerBlock:(i+1)*numCharsPerBlock])

data=None
with open(sys.argv[1],'r') as file1:
    data=file1.read()

res_bv = BitVector(size=0)
for i in range((len(data)//(2*numCharsPerBlock))-1,0,-1):
    cb_bv=BitVector(intVal=int(data[i*2*numCharsPerBlock:(i+1)*2*numCharsPerBlock],16))
    pb_bv=BitVector(intVal=int(data[(i-1)*2*numCharsPerBlock:i*2*numCharsPerBlock],16))
    res_bv= ((cb_bv^pb_bv)^key_bv) + res_bv

res_bv = BitVector(intVal=int(data[0:2*numCharsPerBlock],16))^bv_iv + res_bv

with open(sys.argv[2],'w') as file1:
    file1.write(res_bv.get_bitvector_in_ascii())
