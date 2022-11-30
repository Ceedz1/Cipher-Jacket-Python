import rsa
import os
import msvcrt

#-------------------------------------------------------------

def generateKeys():
    (pubK, privK) = rsa.newkeys(1024)                
    with open('keys/pubK.pem', 'wb') as p:           
        p.write(pubK.save_pkcs1('PEM'))

    with open('keys/privK.pem', 'wb') as p:
        p.write(privK.save_pkcs1('PEM'))


def loadKeys():
    with open('keys/pubK.pem', 'rb') as p:
        pubK = rsa.PublicKey.load_pkcs1(p.read())
    
    with open('keys/privK.pem', 'rb') as p:
        privK = rsa.PrivateKey.load_pkcs1(p.read())
    return pubK, privK

    
def encrypt(msg, key):
    return rsa.encrypt(msg.encode('ascii'), key)
    

def decrypt(ciphertext, key):
    try:
        return rsa.decrypt(ciphertext, key).decode('ascii')
    except:
        return False



#-------------------------------------------------------------


def atbashFormula(plaintext):
    if plaintext.isalpha():
        firstChar = 'a'
        if plaintext.isupper():
            firstChar = 'A'
        oldCharPos = ord(plaintext) - ord(firstChar)
        newCharPos = -(oldCharPos + 1) % 26       
        return chr(newCharPos + ord(firstChar)) #we take the ascii value and convert it back to character

    return plaintext   #we string includes special char and numbers just return it as is
        
def encpt_decpt_func(text):
    recievedText = ''
    for char in text:
        recievedText += atbashFormula(char)
    return recievedText

    
#----------------------------------------------------------------


secret_word = "e"

while True:
    
    print("\n\nOperation Menu")
    print("-------------------")
    print("[a] Encrypt")
    print("[b] Decrypt")
    print("[c] Encrypt File")
    print("[d] Decrypt File")
    print("[e] Exit")
    print("-------------------")
    intOperation = input("Enter Operation: ")
    
    match intOperation:
        case "a":
            plaintext = input("Enter plaintext: ")

            generateKeys()
            pubK, privK = loadKeys()
            ciphertext = encpt_decpt_func(plaintext)
            encrypted = encrypt(ciphertext, pubK)
            
            with open('cipher.bin', 'wb') as binary_file:
                binary_file.write(encrypted)
                binary_file.close()

            print("Encrypted: ", ciphertext)
            print("Encrypted: ", encrypted)
            char = msvcrt.getch()
            os.system("cls")
        

        case "b":
            with open("cipher.bin", "rb") as binary_file:
                data = binary_file.readline()
                binary_file.close()

            generateKeys()
            decpt = decrypt(data, privK)
            decrypted = encpt_decpt_func(decpt)

            if decrypted:
                print("Decrypted: ", decrypted)
            else:
                print("could not decrypt the message.")
            char = msvcrt.getch()
            os.system("cls")



        case "c":
            with open("upload.txt", "r") as file:
                uploadedtext = file.readline()
                file.close()

            generateKeys()
            pubK, privK = loadKeys()
            ciphertext = encpt_decpt_func(uploadedtext)
            with open("upload.txt", "w") as file:
                file.write(ciphertext)
                file.close()


            encrypted = encrypt(ciphertext, pubK)
            with open('upload.bin', 'wb') as binary_file:
                binary_file.write(encrypted)
                binary_file.close()

            print("Encrypted: ", ciphertext)
            print("Encrypted: ", encrypted)
            char = msvcrt.getch()
            os.system("cls")


        case "d":
            with open('upload.bin', 'rb') as binary_file:
                uploadData = binary_file.readline()
                binary_file.close()

            generateKeys()
            decpt = decrypt(uploadData, privK)
            decrypted = encpt_decpt_func(decpt)
            
            with open("upload.txt", "w") as file:
                file.write(decrypted)
                file.close()
            if decrypted:
                print("Decrypted: ", decrypted)
            else:
                print("could not decrypt the message.")
            char = msvcrt.getch()
            os.system("cls")
    if intOperation == secret_word:
        os.system("cls")
        break
    



