import hashlib

key = input("Enter key:")
message = input("Enter messege:")

print("Plain text=" + key + message)

print("MAC(" + key+message + ")=" + hashlib.sha1(key.encode() + message.encode()).hexdigest())

print("MAC(123654)=" + hashlib.sha1(b'123654').hexdigest())
