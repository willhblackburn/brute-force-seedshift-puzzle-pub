# seedshift-crack.py

# seedshift information here: https://github.com/mifunetoshiro/Seedshift
# puzzle information here: https://www.reddit.com/r/CryptoCurrency/comments/ovrnvp/bruteforceable_puzzle_free_crypto_for_whoever/

# import libs
import datetime
import binascii
import hashlib
from sys import dont_write_bytecode
from base58 import b58encode_check
from ecdsa.curves import SECP256k1
import codecs
import ecdsa
from Crypto.Hash import keccak
import requests

# import util
import util as u

# import data
from date_importer import twentieth_century_dates_array, twenty_first_century_dates_array

# setup variables
checked_private_keys = []
bip39 = {}
bip39_list = []
input_words = []
shift_values = []
input_numbers = []
shifted_words = []
shifted_numbers = []
shifted_value = []

addresses_to_check_batch = []

# set words - from puzzle
input_words = "REMOVED-TO-AVOID-SCRAPPING-CAN-FIND-IN-REDDIT-PUZZLE".lower().split()

# read in the known 2048 word list for mnemonic phrases
with open("english.txt") as wordlist:
    line = wordlist.readline()
    count = 1
    while line:
        bip39[count] = line.strip()
        bip39_list.append(line.strip())
        line = wordlist.readline()
        count += 1
    if len(bip39) != 2048:
        raise ValueError("english.txt has " + str(len(bip39)) + " lines, expected 2048!")

# decrypt function provided by the puzzle
# uses dates to shift words in a phrase back to the decrypted string
def decrypt(words):
    count = 0
    for word in words:
        if count == len(shift_values):
            count = 0
        number = list(bip39.keys())[list(bip39.values()).index(word)]
        input_numbers.append(number)
        try:
            number -= shift_values[count]
            shifted_words.append(bip39[number])
            shifted_numbers.append(number)
            shifted_value.append(shift_values[count])
            count += 1
        except KeyError:
            index = number % 2048
            if index == 0:
                index = 2048
            shifted_words.append(bip39[index])
            shifted_numbers.append(index)
            shifted_value.append(shift_values[count])
            count += 1

# checksum on phrase to see if it is a valid phrase
# check checksum function code from https://github.com/trezor/python-mnemonic, Copyright (c) 2013-2018 Pavol Rusnak
def check(mnemonic):
    mnemonic = mnemonic.split(' ')
    try:
        idx = map(lambda x: bin(bip39_list.index(x))[2:].zfill(11), mnemonic)
        b = ''.join(idx)
    except:
        return False
    l = len(b)
    d = b[:l // 33 * 32]
    h = b[-l // 33:]
    nd = binascii.unhexlify(hex(int(d, 2))[2:].rstrip('L').zfill(l // 33 * 8))
    nh = bin(int(hashlib.sha256(nd).hexdigest(), 16))[2:].zfill(256)[:l // 33]
    return h == nh

# check for a valid response and then check if the balance is greater than 0
# TODO - fix this ugliness and properly handle failures
def check_response(response):
    if response:
        if response.json():
            if response.json()['status']:
                if int(response.json()['status']) == 1:
                    accounts = response.json()['result']
                    for account in accounts:
                        value = int(account['balance'])
                        if value > 0:
                            # get private key
                            private_key = ''
                            first_date = ''
                            second_date = ''
                            for account_information in addresses_to_check_batch:
                                if account_information[0] == account['account']:
                                    private_key = account_information[1]
                                    first_date = str(account[2])
                                    second_date = str(account[3])
                            file_name1 = 'keys_'+account['account'][0:6]+'.txt'
                            new_file = open(file_name1, 'w+')
                            new_file.write('Address: '+account['account'])
                            new_file.write('Private Key: '+private_key)
                            new_file.close()
                            print('\n\n\n~~~~~~~~~~~~~~~~~~~~~~~~FOUND!~~~~~~~~~~~~~~~~~~~~~~~~')
                            print('Address: '+account['account'])
                            print('Private Key: '+private_key)
                            print('\nFirst Date: '+first_date)
                            print('\nSecond Date: '+second_date) 
                            print('~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~\n\n\n')
                else:
                    print('bad api call! 4')
            else:
                print('bad api call! 3')
        else:
            print('bad api call! 2')
    else:
        print('bad api call! 1')

# call the api with 20 addresses
def call_api_for_balance():
    # build api string
    api_string = 'https://api.etherscan.io/api?module=account&action=balancemulti&address='
    for account in addresses_to_check_batch:
        api_string += account[0]+','
    #remove last comma
    api_string = api_string[:-1]
    api_string += '&tag=latest&apikey=APIKEYREMOVED'

    response = requests.get(api_string)
    check_response(response)

# batch addresses together into groups of 20 to more efficiently check balances
def add_address_for_api_calling(address, private_key, first_date, second_date):
    # store addresses in array until len == 20
    addresses_to_check_batch.append([address, private_key, first_date, second_date])
    # check length
    if len(addresses_to_check_batch) == 20:
        call_api_for_balance()
        # clear addresses
        addresses_to_check_batch.clear()

# with our private key, get the address so that we can use it with the etherscan API to check for a balance
def check_private_key(private_key, first_date, second_date):
    private_key_bytes = codecs.decode(private_key, 'hex')
    # Get ECDSA public key
    key = ecdsa.SigningKey.from_string(private_key_bytes, curve=ecdsa.SECP256k1).verifying_key
    key_bytes = key.to_string()
    public_key = codecs.encode(key_bytes, 'hex')
    public_key_bytes = codecs.decode(public_key, 'hex')
    keccak_hash = keccak.new(digest_bits=256)
    keccak_hash.update(public_key_bytes)
    keccak_digest = keccak_hash.hexdigest()
    # Take the last 20 bytes
    wallet_len = 40
    wallet = '0x' + keccak_digest[-wallet_len:]
    add_address_for_api_calling(wallet, private_key, first_date, second_date)

# we have a valid phrase, so we need to check private keys
# note, we are checking two private keys for each phrase - one at m/44'/60'/0'/0/0 and one at m/44'/60'/0'/0
def check_wallet(phrase, first_date, second_date):
    # use the utility file to get the private keys from the phrase
    key1, key2 = u.get_private_key(phrase)
    check_private_key(key1, first_date, second_date)
    check_private_key(key2, first_date, second_date)

# check two dates by decrypting the phrase  
def start(first_date, second_date):
    decrypt(input_words)
    phrase = " ".join(shifted_words)
    # use the checksum to ensure we have a new valid phrase
    if check(phrase):
        check_wallet(phrase, first_date, second_date)    

# get two dates, ensure they are valid dates, and then begin the decrypting process
notification_array = []
def run_two_dates():
    print("         starting two dates")
    for first_date in twentieth_century_dates_array:
        for second_date in twenty_first_century_dates_array:
            input_dates = []
            dates_sorted = []
            input_dates = []

            # look to skip
            date1 = datetime.datetime(2021,8,2)
            date2 = datetime.datetime(2021,8,2)
            failed = False
            try:
                date1 = datetime.datetime.strptime(first_date, "%Y-%m-%d")
                date2 = datetime.datetime.strptime(second_date, "%Y-%m-%d")
            except:
                failed = True

            if not failed:
                
                second_failed = False
                try:
                    input_dates = [
                        datetime.datetime.strptime(first_date, "%Y-%m-%d"),
                        datetime.datetime.strptime(second_date, "%Y-%m-%d")
                    ]
                except:
                    second_failed = True

                if not second_failed:
                    input_dates.sort()
                    dates_sorted = [datetime.datetime.strftime(d, "%Y-%m-%d") for d in input_dates]
                    shift_values.clear()
                    shifted_words.clear()
                    shifted_numbers.clear()
                    shifted_value.clear()
                    for d in dates_sorted:
                        shift_values.extend(map(int, d.split("-")))
                    start(first_date, second_date)


        # track on year of first date
        if first_date not in notification_array:
            print("Finished: "+first_date)
            notification_array.append(first_date)

    print("         finished two dates")

# start the program here checking two date pairs
run_two_dates()

# if we finish all the dates, hah, check the last batch
if len(addresses_to_check_batch) > 0:
    call_api_for_balance()
