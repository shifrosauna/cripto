import hashlib
import bcrypt

word_list = [
    "08122988399",
    "nampoly2537",
    "lasabre97",
    "as534031",
    "Victor_",
    "16MSTF68AYSL",
    "hhrules",
    "cpt704242",
    "gracemac",
    "rayas123123"]

for i in word_list:
    i = i.encode()
    print(i, "sha256:", hashlib.sha256(i).hexdigest(), "md5:", hashlib.md5(i).hexdigest())
    print("bcrypt: ", bcrypt.hashpw(i, b'$2b$15$NSVH/I.9u1l/WoYUd/sSI.'))
