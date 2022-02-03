#!/usr/bin/python3

import sys

def main():
    if (len(sys.argv)!=3):
        print('Correct syntax is getKey <message> <output>')
        return

    msg=sys.argv[1]
    out=sys.argv[2]

    key=''    
    for i in range(len(msg)):
        op1=ord(msg[i])
        op2=int(out[2*i:2*i+2], 16)
        result=chr((op1^op2))
        key=key+result

    print('')
    print(key)
    return

main()
