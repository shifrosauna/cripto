# !/usr/bin/env python
# Written against python 3.3.1
# Matasano Problem 31
# Implement HMAC-SHA1 and break it with an artificial timing leak.
from prob18 import raw_xor
from prob1 import hexToRaw, rawToHex
from prob28 import sha1_from_github
import threading
import webserver
import time
import socket
import os
from prob17 import setByte


BLOCKSIZE = 64;
DELAY = .05


def myhmac(hash_function, message, key):
    if (len(key) > BLOCKSIZE):
        key = hash(key)
    if (len(key) < BLOCKSIZE):
        key += (b'\x00' * (BLOCKSIZE - len(key)));

    opad = raw_xor(b'\x5c' * BLOCKSIZE, key);
    ipad = raw_xor(b'\x36' * BLOCKSIZE, key);

    return hash_function(opad + hexToRaw(hash_function(ipad + message)));


def test_hmac():
    # HMAC_SHA1("", "") = 0xfbdb1d1b18aa6c08324b7d64b71fb76370690e1d
    # HMAC_SHA1("key", "The quick brown fox jumps over the lazy dog") = 0xde7c9b85b8b78aa6bc8a7a36f70a90701c9db4d9
    keys = [b'', b'key']
    messages = [b'', b'The quick brown fox jumps over the lazy dog'];
    answers = ['fbdb1d1b18aa6c08324b7d64b71fb76370690e1d',
               'de7c9b85b8b78aa6bc8a7a36f70a90701c9db4d9']
    for i in range(len(keys)):
        if (myhmac(sha1_from_github, messages[i], keys[i]) != answers[i]):
            print("hmac error");
            exit(-1);

def startserver(delay):
    server_thread = threading.Thread(target=webserver.start_server, args=[delay])
    server_thread.start();


# Using the timing leak in this application, write a program that
# discovers the valid MAC for any file.
def discover_mac(message):
    guess_mac = b'\x00' * 20;
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM);
    sock.connect(('127.0.0.1', 9000))
    for i in range(20):
        nextbyte = guess_byte(sock, message, i, guess_mac);
        guess_mac = setByte(guess_mac, i, nextbyte);
    print(rawToHex(guess_mac));
    return guess_mac;


def guess_byte(sock, message, index, guess_mac, numtrials=5):
    timings = [0] * 256;
    # try each byte at the index
    for i in range(256):
        this_guess = setByte(guess_mac, index, i);
        url = b'test?file=' + message + b'&signature=' + rawToHex(this_guess) + b'\n';
        start = time.perf_counter()
        for j in range(numtrials):
            sock.send(url);
            data = sock.recv(1024)
        stop = time.perf_counter()
        timings[i] = stop - start;
    # astume the largest timing is the right one
    value = timings.index(max(timings));
    print("index: " + str(index) + " : value: " + hex(value));
    return value;


def do31():
    test_hmac();
    startserver(DELAY);
    # known answer: b'6262261f054f0a17dfa68d87bf64f5416c128340'
    discover_mac(b'Mary had a little lamb');


if __name__ == "__main__":
    do31();
    os._exit(0);
