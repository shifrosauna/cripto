from binascii import hexlify, unhexlify


def bxor(a, b):
    "bitwise XOR of bytestrings"
    return bytes([ x^y for (x,y) in zip(a, b)])

message = b"Burning 'em, if you ain't quick and nimble\nI go crazy when I hear a cymbal"
key = b'ICE'
# We have to repeat the key until the keystream is at least as long as the message
# our "bxor" function gives an output as long as the shortest input
# so the output will be as long as the message here
keystream = key*(len(message)//len(key) + 1)

ciphertext = bxor(message, keystream)
expected_result = unhexlify(
    b'0b3637272a2b2e63622c2e69692a23693a2a3c6324202d623d6'
    b'3343c2a26226324272765272a282b2f20430a652e2c652a3124'
    b'333a653e2b2027630c692b20283165286326302e27282f'
)

print(expected_result)
print(ciphertext)
if expected_result == ciphertext:
    print("OK")