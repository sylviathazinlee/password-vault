import os
from Crypto.Protocol.KDF import scrypt
from Crypto.Random import get_random_bytes
from Crypto.Cipher import AES
from base64 import b64decode
import json
from base64 import b64encode
import os.path
import hashlib
import random
import string
import sys


#PasswordVault is a List of String
#Each string in a password value is of the form: ``username:password:domain''
def encryptFile(plaintextData,key):
    nonce = get_random_bytes(AES.block_size)
    cipher = AES.new(key, AES.MODE_GCM, nonce = nonce)
    ciphertext, tag = cipher.encrypt_and_digest(plaintextData); 
    json_k = ['nonce', 'header', 'ciphertext', 'tag']
    json_v = [b64encode(x).decode('utf-8') for x in (nonce, b"", ciphertext, tag)]
        
    encryptionResults = json.dumps(dict(zip(json_k, json_v)))
    return encryptionResults



def decryptFile(encryptedJson, key):
    values = json.loads(encryptedJson)
    json_k = ['nonce', 'header', 'ciphertext', 'tag']
    json_v = [b64decode(values[x]) for x in json_k]
    cipher = AES.new(key, AES.MODE_GCM, nonce = dict(zip(json_k, json_v))['nonce'])

    plaintextData = cipher.decrypt_and_verify(dict(zip(json_k, json_v))['ciphertext'], dict(zip(json_k, json_v))['tag'])
    return plaintextData.decode('utf-8')


# computerMasterKey : String -> String of bytes 
# Calculates the encryption key from the user password
def computerMasterKey(password):
    salt = "<\n<~\x0e\xeetGR\xfe;\xec \xfc)8"
    key = scrypt(password.encode(), salt, key_len=32, N=2**14, r=8, p=1)
    return key



def decryptAndReconstructVault(hashedusername, password):

    key = computerMasterKey(password)
    magicString = '101010101010101010102020202020202020202030303030303030303030\n'

    with open(hashedusername, "r") as file:
        fileread = file.read()
    file.close()

    decryptedresults = decryptFile(fileread, key)

    if magicString not in decryptedresults:
        raise ValueError("Magic string is not in decoded content.")
    else:
        decodedContent = decryptedresults.split(magicString, 1)[1]


    passwordvault = decodedContent.splitlines()

    return passwordvault



def checkVaultExistenceOrCreate():
    passwordvault = []
    maxAttempts = 3
    for attempt in range(maxAttempts):
        username = input('Enter vault username: ')
        password = input('Enter vault password: ')

        if username and password:
            hashedusername = hashlib.sha256(username.encode("utf-8")).hexdigest()
            if os.path.exists(hashedusername):
                try:
                    passwordvault = decryptAndReconstructVault(hashedusername, password)
                    return username, password, hashedusername, passwordvault
                except ValueError:
                    print("Incorrect password. Please try again.")
            else:
                print("Password vault not found. Creating a new one.")
                return username, password, hashedusername, []
        else:
            print("Both username and password are required.")
    
    print("Maximum login attempts reached. Quitting.")
    quit()



def generatePassword():
    characters = string.ascii_letters + string.digits
    result = ''.join(random.choice(characters) for _ in range(16))
    return result



def AddPassword(passwordvault):
    username = input("Enter username: ")
    password = input("Enter password: ")
    domain = input("Enter domain: ")

    entry = f"{username}:{password}:{domain}"
    passwordvault.append(entry)
    print('Record Entry added')



def CreatePassword(passwordvault):
    username = input('Enter username: ')
    domain = input('Enter domain: ')
    password = generatePassword()
    entry = f'{username}:{password}:{domain}'
    passwordvault.append(entry)
    print('Record Entry added')



def UpdatePassword(passwordvault):
    domainUpdated = input('Enter the domain to update: ')
    newPassword = input('Enter new password: ')
    for i, entry in enumerate(passwordvault):
        if entry.endswith(f':{domainUpdated}'):
            username, _, _ = entry.split(':')
            passwordvault[i] = f'{username}:{newPassword}:{domainUpdated}'
    print('Record Entry Updated')



def LookupPassword(passwordvault):
    domainTarget = input('Enter domain to lookup: ')
    for entry in passwordvault:
        if entry.endswith(f':{domainTarget}'):
            username, password, _ = entry.split(':')
            print(f'Username: {username}')
            print(f'Password: {password}')
            print(f'Domain: {domainTarget}')
            return



def DeletePassword(passwordvault):
    domainDeleted = input('Enter domain you want to delete: ')
    for entry in passwordvault[:]:
        if entry.endswith(f':{domainDeleted}'):
            passwordvault.remove(entry)
    print('Record Entry Deleted')


def displayVault(passwordvault):
    print(passwordvault)



def EncryptVaultAndSave(passwordvault, password, hashedusername):
    writeString = ''
    magicString = '101010101010101010102020202020202020202030303030303030303030\n'
     # writeString + magicString
    key = computerMasterKey(password)
    finalString = ''
    finalString = finalString + magicString

    for entry in passwordvault:
        record = entry + '\n'
        finalString = finalString + record 

    finaldbBytes = bytes(finalString, 'utf-8')
    finaldbBytesEncrypted = encryptFile(finaldbBytes,key)


    with open(hashedusername, "w") as file:
        file.write(finaldbBytesEncrypted)
    file.close()
    print("Password Vault encrypted and saved to file")



def main():
    username, password, hashedusername, passwordvault = checkVaultExistenceOrCreate()
    while(True):

        print('Password Management')
        print('-----------------------')
        print('-----------------------')
        print('1 - Add password')
        print('2 - Create password')
        print('3 - Update password')
        print('4 - Lookup password')
        print('5 - Delete password')
        print('6 - Display Vault')
        print('7 - Save Vault and Quit')
        choice = input('')


        if choice == ('1'):
            AddPassword(passwordvault)

        elif choice == ('2'):
            CreatePassword(passwordvault)

        elif choice == ('3'):
            UpdatePassword(passwordvault)

        elif choice == ('4'):
            LookupPassword(passwordvault)

        elif choice == ('5'):
            DeletePassword(passwordvault)
        elif choice == ('6'):
            displayVault(passwordvault)

        elif choice == ('7'):
            EncryptVaultAndSave(passwordvault, password, hashedusername)
            quit()
        else:
            print('Invalid choice please try again')

if __name__ == "__main__":
    main()
