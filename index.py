import tkinter as tk
from demo_RSA import *
from demo_ECC import *

def display_string(event,context,string="null string"):
    context.configure(state="normal")
    context.delete("1.0","end")
    context.insert('end', string)
    context.configure(state="disabled")

def display_gen_key(event,context):
    keys = list(gen_key())
    keys_dict = {"e": keys[0],
                 "d": keys[1],
                 "n": keys[2],
                 "fi_n": keys[3],
                 "p": keys[4],
                 "q": keys[5]}
    keys = [key+ ": " + str(keys_dict[key]) for key in keys_dict]
    keys = "\n".join(keys)
    display_string(event,context,keys)

def display_RSA_encoded(event,context,mess,pub_key,n):
    print(mess.get())
    mess = [ord(char) for char in mess.get()]
    encoded = [str(RSA_encode(char,int(pub_key.get()),int(n.get()))) for char in mess]
    encoded = " ".join(encoded)
    print(encoded)
    display_string(event,context,encoded)

def display_RSA_decoded(event,context,mess,pri_key,n):
    mess = mess.get().split(" ")
    print(type(mess[0]))
    decoded = [chr(RSA_decode(int(char),int(pri_key.get()),int(n.get()))) for char in mess]
    decoded = "".join(decoded)
    print(decoded)
    display_string(event,context,decoded)

def RSA_form():
    # Create RSA Window
    rsa_window = tk.Tk()
    rsa_window.title("RSA Form")
    rsa_window.geometry("800x600")
    tk.Label(rsa_window, text ="RSA", font = 30).pack()

    # Create key generation frame
    gen_key_frame = tk.Frame(rsa_window)
    gen_key_frame.pack()
    gen_key_tbox = tk.Text(gen_key_frame, width=30,height=6)
    gen_key_tbox.insert("end","Click generate key button...")
    gen_key_tbox.configure(state = 'disabled')
    gen_key_tbox.pack()
    gen_key_btn = tk.Button(gen_key_frame, text= "Generate key", width=10, height=1, fg = "white" ,bg= "lightblue")
    gen_key_btn.bind("<Button-1>", lambda e: display_gen_key(e,gen_key_tbox))
    gen_key_btn.pack(pady=10)

    # Create encode frame
    encode_frame = tk.Frame(rsa_window)
    encode_frame.pack()
    
    tk.Label(encode_frame, text="Enter message: ").grid(row=0,column=0, sticky= tk.W)
    mess = tk.Entry(encode_frame)
    mess.grid(row=0,column=1)
    
    tk.Label(encode_frame, text="Enter public key: ").grid(row=1,column=0,sticky= tk.W)
    public_key = tk.Entry(encode_frame)
    public_key.grid(row=1,column=1)

    tk.Label(encode_frame, text="Enter n: ").grid(row=2,column=0,sticky=tk.W)
    n = tk.Entry(encode_frame)
    n.grid(row=2,column=1)

    tk.Label(encode_frame, text="Encoded result:").grid(row=3,column=0,sticky= tk.W)
    encode_tbox = tk.Text(encode_frame,state= "disabled",width=15,height=3)
    encode_tbox.grid(row=3,column=1)
    
    encode_btn = tk.Button(encode_frame, text= "Encode", width=10, height=1, fg= "white" , bg= "lightblue")
    encode_btn.grid(row=4,column=1,sticky= tk.E,pady=10)
    entrs = [mess,public_key,n]
    encode_btn.bind("<Button-1>", lambda e,context=encode_tbox: display_RSA_encoded(e,context,*entrs))
       
    # Create decode frame
    decode_frame = tk.Frame(rsa_window)
    decode_frame.pack()

    tk.Label(decode_frame, text="Enter message: ").grid(row=0,column=0,sticky= tk.W)
    mess1 = tk.Entry(decode_frame)
    mess1.grid(row=0,column=1)
    
    tk.Label(decode_frame, text="Enter private key: ").grid(row=1,column=0,sticky= tk.W)
    private_key = tk.Entry(decode_frame)
    private_key.grid(row=1,column=1)

    tk.Label(decode_frame, text="Enter n: ").grid(row=2,column=0,sticky=tk.W)
    n1 = tk.Entry(decode_frame)
    n1.grid(row=2,column=1)

    tk.Label(decode_frame, text="Decoded result:").grid(row=3,column=0,sticky= tk.W)
    decode_tbox = tk.Text(decode_frame,state= "disabled",width=15,height=3)
    decode_tbox.grid(row=3,column=1)

    entrs1 = [mess1,private_key,n1]
    decode_btn = tk.Button(decode_frame, text= "Decode", width=10, height=1, fg= "white" , bg= "lightblue")
    decode_btn.grid(row=4,column=1, sticky= tk.E,pady=10)
    decode_btn.bind("<Button-1>",lambda e,context=decode_tbox: display_RSA_decoded(e,context,*entrs1))

def display_gen_curve(event,context,a,b,p,x,y):
    global G
    a = int(a.get())
    b = int(b.get())
    p = int(p.get())
    x = int(x.get())
    y = int(y.get())
    
    G = get_point_list(a,b,p,x,y)
    point = ""
    for i in range (len(G)):
        point = point + str(i)+": " + str(G[i]) + "\n"
    display_string(event, context,point)

def display_pub_key(event,context,pri_key):
    pub_key = str(G[int(pri_key.get())-1])
    display_string(event,context,pub_key)

def display_ECC_encoded(event,context,mess,pub_key,k1,k2,a,b,p):
    mess = mess.get()
    a = int(a.get())
    b = int(b.get())
    p = int(p.get())
    pub_key = pub_key.get()

    pub_key = pub_key.replace(" ","")
    pub_key = pub_key.replace("(","")
    pub_key = pub_key.replace(")","")
    pub_key = [int(i) for i in pub_key.split(",")]

    k1 = int(k1.get())
    k2 = int(k2.get())
    
    mess = [ord(char) for char in mess]
    curve_point_encoded = [point_encode(code,G,k1) for code in mess]
    print("Curve point: ",curve_point_encoded)

    #encode points to ciphertext point  
    k_PB = get_k_point(a,b,p,k2,pub_key[0],pub_key[1])
    cip_point_list = [str((G[k2-1],add_point(point[0],k_PB,p),point[1])) for point in curve_point_encoded]
    print("Ciphertext point: ",cip_point_list)
    encoded = ";".join(cip_point_list)
    display_string(event,context,encoded)
    
def display_ECC_decode(event,context,mess,pri_key,k1,k2,a,b,p):
    mess = mess.get()
    a = int(a.get())
    b = int(b.get())
    p = int(p.get())
    pri_key = int(pri_key.get())

    k1 = int(k1.get())
    k2 = int(k2.get())
    cip_point_list = []
    mess = mess.split(";")
    for el in mess:
        el = el.replace("(","")
        el = el.replace(")","")
        el = el.replace(" ","")
        el = [int(i) for i in el.split(",")]
        cip_point_list.append(((el[0],el[1]),(el[2],el[3]),el[4]))
    print(cip_point_list)
    
    #decode ciphertext points to curve points
    curve_point_decoded = []
    for cp in cip_point_list:
        k_cp0 = get_k_point(a,b,p,pri_key,cp[0][0],cp[0][1])
        curve_point = add_point(cp[1],(k_cp0[0],-k_cp0[1]%p),p)
        curve_point_decoded.append([curve_point,cp[2]])
    print("Decoded curve point: ",curve_point_decoded)

    #decode curve points to ascii
    ascii_decoded_list = []
    for ipoint in range (len(curve_point_decoded)):
        
        ascii_decoded_list.append(point_decode(curve_point_decoded[ipoint][0][0],k1,curve_point_decoded[ipoint][1]))
    print(ascii_decoded_list)

    #decode ascii code mess
    decoded_char_list = [chr(code)for code in ascii_decoded_list]  
    print("Decoded char list: ",decoded_char_list)
    decoded_mess = "".join(decoded_char_list)
    print("Decoded mess: ", decoded_mess)

    display_string(event,context,decoded_mess)
    
def ECC_form():
    global G
    G = []
    ecc_window = tk.Tk()
    ecc_window.title("ECC Form")
    ecc_window.geometry("800x800")
    label = tk.Label(ecc_window, text= "ECC",font=30).pack()

    # Create init a,b,p,x,y,G frame
    gen_curve_frame = tk.Frame(ecc_window)
    gen_curve_frame.pack()

    tk.Label(gen_curve_frame, text="Enter a:").grid(row=0,column=0,sticky=tk.W)
    a = tk.Entry(gen_curve_frame,width=30)
    a.grid(row=0, column=1)

    tk.Label(gen_curve_frame, text="Enter b:").grid(row=1,column=0,sticky=tk.W)
    b = tk.Entry(gen_curve_frame,width=30)
    b.grid(row=1, column=1)

    tk.Label(gen_curve_frame, text="Enter p:").grid(row=2,column=0,sticky=tk.W)
    p = tk.Entry(gen_curve_frame,width=30)
    p.grid(row=2, column=1)

    tk.Label(gen_curve_frame, text="Enter x:").grid(row=3,column=0,sticky=tk.W)
    x = tk.Entry(gen_curve_frame,width=30)
    x.grid(row=3, column=1)

    tk.Label(gen_curve_frame, text="Enter y:").grid(row=4,column=0,sticky=tk.W)
    y = tk.Entry(gen_curve_frame,width=30)
    y.grid(row=4, column=1)

    tk.Label(gen_curve_frame, text="Points in curve: ").grid(row=6,column=0,sticky=tk.W)
    gen_curve_tbox = tk.Text(gen_curve_frame,state= "disabled",width=30,height=3)
    gen_curve_tbox.grid(row=6,column=1)

    entrs = [a,b,p,x,y]
    gen_curve_btn = tk.Button(gen_curve_frame, text= "Generate curve", width=15, height=1, fg= "white" , bg= "lightblue")
    gen_curve_btn.grid(row=7,column=1,sticky=tk.E,pady=10)
    gen_curve_btn.bind("<Button-1>",
                       lambda e,context=gen_curve_tbox: display_gen_curve(e,context,*entrs))

    # Create choose key frame
    pick_key_frame = tk.Frame(ecc_window)
    pick_key_frame.pack()

    tk.Label(pick_key_frame, text="Enter private key: ").grid(row=0,column=0,sticky=tk.W)
    private_key = tk.Entry(pick_key_frame,width=30)
    private_key.grid(row=0, column=1)

    tk.Label(pick_key_frame, text="Public key: ").grid(row=1,column=0,sticky=tk.W)
    public_key = tk.Text(pick_key_frame,width=30,height=1)
    public_key.grid(row=1, column=1)
    public_key.insert("end","Click button...")
    public_key.configure(state="disabled")

    pick_key_btn = tk.Button(pick_key_frame,text="Get key",width=15,height=1, fg= "white" , bg= "lightblue")
    pick_key_btn.grid(row=2,column=1,sticky=tk.E,pady=10)
    pick_key_btn.bind("<Button-1>",
                      lambda e, context=public_key,pri_key=private_key: display_pub_key(e,context,pri_key))

    # Create encode frame
    encode_frame = tk.Frame(ecc_window)
    encode_frame.pack()

    tk.Label(encode_frame,text="Enter message: ").grid(row=0,column=0,sticky=tk.W)
    mess = tk.Entry(encode_frame,width=30)
    mess.grid(row=0,column=1)

    tk.Label(encode_frame, text = "Enter public key: ").grid(row=1,column=0,sticky=tk.W)
    pub_key = tk.Entry(encode_frame,width=30)
    pub_key.grid(row=1,column=1)

    tk.Label(encode_frame, text = "Enter k1: ").grid(row=2,column=0,sticky=tk.W)
    k1 = tk.Entry(encode_frame,width=30)
    k1.grid(row=2,column=1)

    tk.Label(encode_frame, text = "Enter k2: ").grid(row=3,column=0,sticky=tk.W)
    k2 = tk.Entry(encode_frame,width=30)
    k2.grid(row=3,column=1)   

    tk.Label(encode_frame, text = "Encode result: ").grid(row=4, column=0,sticky=tk.W)
    encode_tbox = tk.Text(encode_frame,state = "disabled",width=30,height=3)
    encode_tbox.grid(row=4,column=1)

    entrs1 = [mess,pub_key,k1,k2,a,b,p]
    encode_btn = tk.Button(encode_frame,text="Encode",width=15,height=1, fg= "white" , bg= "lightblue")
    encode_btn.grid(row=5,column=1,sticky=tk.E,pady=10)
    encode_btn.bind("<Button-1>",
                      lambda e, context=encode_tbox: display_ECC_encoded(e,context,*entrs1))

    # Create decode frame
    decode_frame = tk.Frame(ecc_window)
    decode_frame.pack()

    tk.Label(decode_frame,text= "Enter message: ").grid(row=0,column=0,sticky=tk.W)
    mess_dec = tk.Entry(decode_frame,width=30)
    mess_dec.grid(row=0,column=1)

    tk.Label(decode_frame,text= "Enter private key: ").grid(row=1, column=0,sticky=tk.W)
    pri_key_dec = tk.Entry(decode_frame,width=30)
    pri_key_dec.grid(row=1,column=1)

    tk.Label(decode_frame, text="Enter k1: ").grid(row=2,column=0,sticky=tk.W)
    k1_dec = tk.Entry(decode_frame,width=30)
    k1_dec.grid(row=2,column=1)

    tk.Label(decode_frame, text = "Enter k2: ").grid(row=3,column=0,sticky=tk.W)
    k2_dec = tk.Entry(decode_frame,width=30)
    k2_dec.grid(row=3,column=1)

    tk.Label(decode_frame, text = "Decode result").grid(row=4, column=0,sticky=tk.W)
    decode_tbox = tk.Text(decode_frame, state= "disabled", width=30, height=3)
    decode_tbox.grid(row=4, column=1)

    entrs2 = [mess_dec,pri_key_dec,k1_dec,k2_dec,a,b,p]
    decode_btn = tk.Button(decode_frame, text="Decode",width=15,height=1,fg= "white", bg= "lightblue")
    decode_btn.grid(row=5, column=1, sticky=tk.E, pady=10)
    decode_btn.bind("<Button-1>",
                    lambda e, context=decode_tbox: display_ECC_decode(e,context,*entrs2))

root = tk.Tk()
root.title("My Software")
root.geometry("300x200")

tk.Label(root, text ="Choose Algorithm", font = 30).pack()
n = tk.Entry(root, textvariable="name")
frame = tk.Frame(root)
frame.pack()
button1 = tk.Button(frame, text = "RSA", width=10, height=1, fg = "white" ,bg= "lightblue",command = RSA_form)
button1.pack(side=tk.LEFT)
button2 = tk.Button(frame, text = "ECC", width=10, height=1, fg = "white" ,bg= "lightblue",command = ECC_form)
button2.pack(side=tk.LEFT)
root.mainloop()
