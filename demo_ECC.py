# -*- coding:UTF-8
from demo_euclid_extend import *
import random as rd
import math as m

def get_point_list(a=2,b=2,p=17,x=5,y=1):
   point_list = []
   # define the curve E: y^2 = x^3 + 2x + 2 (mod 17)  #E=19
   # the primitive point (x1,y1)=(5,1)   
   x1 = x2 = x
   y1 = y2 = y
##   print (str(1)+"P:\t", (x1, y1))
   point_list.append((x1,y1))
   i = 1
   while(1):
      i+=1
      s = 0
      if x1 == x2 and y2==-y1:
##            print("end1")
            break
      if (x1 == x2 and y1==y2):
         if x1==0 and i>2:
##            print("end2")
            break
          # indentical point
         s = ((3 * (x1 ** 2) + a) * modinv(2 * y1, p))%p
      else:
         if x1==x2:
##            print("end3")
            break
          # different points
         s = ((y2 - y1) * modinv(x2 - x1, p))%p
      # calculate i.P
      x3 = (s ** 2 - x1 - x2) % p
      y3 = (s*(x1 - x3) - y1) % p
##      print (str(i) + "P:\t", (x3,y3))
      point_list.append((x3,y3))
      (x2, y2) = (x3, y3)
      
   
   return point_list


def get_k_point(a=2,b=2,p=17,k=17,x=5,y=1):
   # define the curve E: y^2 = x^3 + 2x + 2 (mod 17)  #E=19
   # the primitive point (x1,y1)=(5,1)   
   x1 = x2 = x
   y1 = y2 = y
##   print (str(1)+"P:\t", (x1, y1))
   

   for i in range(2,k+1):
      s = 0
      if x1 == x2 and y2==-y1:
##            print("end1")
            break
      if (x1 == x2 and y1==y2):
         if x1==0 and i>2:
##            print("end2")
            break
          # indentical point
         s = ((3 * (x1 ** 2) + a) * modinv(2 * y1, p))%p
      else:
         if x1==x2:
##            print("end3")
            break
          # different points
         s = ((y2 - y1) * modinv(x2 - x1, p))%p
      # calculate i.P
      x3 = (s ** 2 - x1 - x2) % p
      y3 = (s*(x1 - x3) - y1) % p
##      print (str(i) + "P:\t", (x3,y3))
      (x2, y2) = (x3, y3)
   return (x3,y3)

def add_point(X1,X2,p):
   x1,y1 = X1[0],X1[1]
   x2,y2 = X2[0],X2[1]
   
   s = ((y2 - y1) * modinv(x2 - x1, p))%p
   x3 = (s ** 2 - x1 - x2) % p
   y3 = (s*(x1 - x3) - y1) % p
   return (x3,y3)

def point_encode(m,curve_point_list,k):
   x = m #m*k+1
   i = 0
   while(1):
      for point in curve_point_list:
         x_curve = point[0]
         
         if x_curve == x:
            P_m = (x,point[1])
            return [P_m,i]
      x +=1
      i +=1
         
def point_decode(x,k,i):
   return x-i #m.floor((x-1)/k)



##point_list = get_point_list(-1,188,751,0,376)
##P_m = point_encode(11,point_list,20)
##print("P_m",P_m)
##
### private key of B
##n_B = 85
### public key of B
##P_B = point_list[n_B-1]
##print("P_B: ",P_B)
##
### A choose random k
##k  = rd.randint(1,751)
##k = 113
##print("k:" ,k)
##k_PB = get_k_point(-1,188,751,k,P_B[0],P_B[1])
##print("kpb",k_PB)
##P_c = (point_list[k-1],add_point(P_m,k_PB,751))
##print("pc",P_c)
##t = get_k_point(-1,188,751,85,P_c[0][0],P_c[0][1])
##P_m = add_point(P_c[1],(t[0],-t[1]%751),751)
##print(point_decode(P_m[0],20))

def demo():
   a = -1
   b = 188
   p = 751
   x = 0
   y = 376
   G = get_point_list(a,b,p,x,y)
   print(G)
   #private key
   pr_key = rd.randint(1,len(G))
   print("Private key: ", pr_key)

   #public key
   p_key  = G[pr_key-1]
   print("Public key: ",p_key)

   #random k1 to encode ascii number to point
   k1 = rd.randint(1,2)
   
   message = "Hello World"
   print("Message: ", message)

   print("\nEncode...\n")
   char_list = [char for char in message]
   print(char_list)
   ascii_encoded_list = [ord(char) for char in message]
   print("Ascii: ",ascii_encoded_list)
   curve_point_encoded = [point_encode(code,G,k1)[0] for code in ascii_encoded_list]
   i_l = [point_encode(code,G,k1)[1] for code in ascii_encoded_list]
   print("Curve point: ",curve_point_encoded)

   #random k2 to encode points to ciphertext points
   k2 = rd.randint(1,200)

   #encode points to ciphertext point  
   k_PB = get_k_point(a,b,p,k2,p_key[0],p_key[1])
   cip_point_list = [(G[k2-1],add_point(point,k_PB,p)) for point in curve_point_encoded]
   print("Ciphertext point: ",cip_point_list)

   
   print("\nDecode...\n")
   #decode ciphertext points to curve points
   curve_point_decoded = []
   for cp in cip_point_list:
      k_cp0 = get_k_point(a,b,p,pr_key,cp[0][0],cp[0][1])
      curve_point = add_point(cp[1],(k_cp0[0],-k_cp0[1]%p),p)
      curve_point_decoded.append(curve_point)
   print("Decoded curve point: ",curve_point_decoded)

   #decode curve points to ascii
   ascii_decoded_list = []
   for ipoint in range (len(curve_point_decoded)):
      ascii_decoded_list.append(point_decode(curve_point_decoded[ipoint][0],k1,i_l[ipoint]))
   print(ascii_decoded_list)

   #decode ascii code mess
   decoded_char_list = [chr(code)for code in ascii_decoded_list]  
   print("Decoded char list: ",decoded_char_list)
   decoded_mess = "".join(decoded_char_list)
   print("Decoded mess: ", decoded_mess)
##demo()
