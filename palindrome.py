#!/usr/bin/env python3
import string
s = input("Enter The String : ")
s = s.lower()
exclude = set(string.punctuation)
s = ''.join(ch for ch in s if ch not in exclude)
s = ''.join(s.split())
print (s)
r = s[::-1]
print (r)
if( s == r ):
    print ("Palindrome")
else:
    print ("Not a Palindrome")
