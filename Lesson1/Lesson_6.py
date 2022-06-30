class InvalidMessageException(Exception):
    pass

from binascii import hexlify, unhexlify
with open('6.txt') as data_file:
    ciphertext_list = [
        # the 'strip' is to remove the "newline" character
        # which python keeps when reading a file line by line
        unhexlify(line.strip())
        for line in data_file
    ]

#print(ciphertext_list)
def letter_ratio(input_bytes):
    nb_letters = sum([ x in ascii_text_chars for x in input_bytes])
    return nb_letters / len(input_bytes)
def is_probably_text(input_bytes):
    r = letter_ratio(input_bytes)
    return True if r>0.7 else False
ascii_text_chars = list(range(97, 122)) + [32]
def bxor(a, b):
    "bitwise XOR of bytestrings"
    return bytes([ x^y for (x,y) in zip(a, b)])

def attack_single_byte_xor(ciphertext):
    # a variable to keep track of the best candidate so far
    best = None
    for i in range(2**8): # for every possible key
        # converting the key from a number to a byte
        candidate_key = i.to_bytes(1, byteorder='big')
        keystream = candidate_key*len(ciphertext)
        candidate_message = bxor(ciphertext, keystream)
        nb_letters = sum([ x in ascii_text_chars for x in candidate_message])
        # if the obtained message has more letters than any other candidate before
        if best == None or nb_letters > best['nb_letters']:
            # store the current key and message as our best candidate so far
            best = {"message": candidate_message, 'nb_letters': nb_letters, 'key': candidate_key}
    return best

candidates = list()
# for the "enumerate" builtin function, see
# https://docs.python.org/3/library/functions.html#enumerate
for (line_nb, ciphertext) in enumerate(ciphertext_list):
    try:
        message = attack_single_byte_xor(ciphertext)['message']
    except InvalidMessageException:
        pass
    else:
        candidates.append({
            'line_nb': line_nb,
            'ciphertext': ciphertext,
            'message': message
        })


else:
    for (key, value) in candidates[0].items():
        print(f'{key}: {value}')
    is_probably_text(candidates[0]['message'])