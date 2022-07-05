
def pkcs7_padding(message, block_size):
    padding_length = block_size - ( len(message) % block_size )

    if padding_length == 0:
        padding_length = block_size
    padding = bytes([padding_length]) * padding_length
    return message + padding

print( pkcs7_padding(b'YELLOW SUBMARINE', 20) )