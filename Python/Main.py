import EncryptDecrypt


print("\nEnter your message to be encrypted: ")

message = input()

output = EncryptDecrypt.encrypt(message)

message = EncryptDecrypt.decrypt(output)

print("\nYour decrypted message is: ", message)
