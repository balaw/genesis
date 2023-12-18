"""File containing functions for the creation of transactions, input and output scripts."""
import struct
from genesiscreator.compat import hexencode, hexdecode
from construct import Byte
from construct import Bytes
from construct import StaticField
from construct import Struct
from construct import UBInt32

import hashlib



from construct import Bytes
from construct import Struct

import argparse
import sys

# from genesiscreator import constants
from genesiscreator.block import create_block

COIN = 100000000

parser = argparse.ArgumentParser()
parser.add_argument('--nTime', dest='nTime', default=1231006505,
                    type=int, help='the (unix) time when the genesisblock is created')

parser.add_argument('--pszTimestamp', dest='pszTimestamp', default='The Times 03/Jan/2009 Chancellor on brink of second bailout for banks',
                    type=str, help='the pszTimestamp message found in the coinbase of the genesisblock')

parser.add_argument('--nNonce', dest='nNonce', default=2083236893,
                    type=int, help='the first value of the nonce that will be incremented when searching the genesis hash')

parser.add_argument('--algorithm', dest='algorithm', default='SHA256',
                    type=str, choices=['SHA256', 'Scrypt', 'X11', 'X13', 'X15'], help='the PoW algorithm to use for the genesis block')

parser.add_argument('--pubkey', dest='pubkey',
                    default='04678afdb0fe5548271967f1a67130b7105cd6a828e03909a67962e0ea1f61deb649f6bc3f4cef38c4f35'
                    '504e51ec112de5c384df7ba0b8d578a4c702b6bf11d5f',
                    type=str, help='the pubkey found in the output script')

# parser.add_argument('--nValue', dest='nValue', default=50 * constants.COIN,
parser.add_argument('--nValue', dest='nValue', default=50 * COIN,
                    type=int, help='the value in coins for the output, full value '
                    '(exp. in bitcoin 5000000000 - To get other coins value: Block Value * 100000000)')

parser.add_argument('--nBits', dest='nBits', default=0x1d00ffff,
                    type=lambda x: int(x, 0), help='the target in hex')

parser.add_argument('--nVersion', dest='nVersion', default=1,
                    type=int, help='The Block Version')


# def main(argv=sys.argv):
#     args = parser.parse_args()
#     print(args)

#     block_data = create_block(args.pszTimestamp, args.pubkey, args.nValue, args.algorithm,
#                               args.nTime, args.nBits, args.nNonce, args.nVersion)

#     print("""
#         Algorithm: {algorithm}
#         Hash Merkle Root: {hashMerkleRoot}
#         pszTimestamp: {pszTimestamp}
#         pubkey: {pubkey}
#         nTime: {nTime}
#         nBits: {nBits}
#         nNonce: {nNonce}
#         hashGenesisBlock: {hashGenesisBlock}
#     """.format(**block_data))
#     return block_data



def hexencode(str) -> str:
    return str.encode().hex()

def hexdecode(hex_str) -> bytes:
    return bytes.fromhex(hex_str)


def create_input_script(psz_timestamp):
    """Using a timestamp string create the input script."""
    psz_prefix = ''
    # use OP_PUSHDATA1 if required
    if len(psz_timestamp) > 76:
        psz_prefix = '4c'

    script_prefix = '04ffff001d0104' + psz_prefix + hexencode(chr(len(psz_timestamp)))
    return hexdecode(script_prefix + hexencode(psz_timestamp))

def create_output_script(pubkey):
    """Create an output script for paying to a pubkey from coinbase."""
    script_len = '41'
    OP_CHECKSIG = 'ac'
    return hexdecode(script_len + pubkey + OP_CHECKSIG)


def create_genesis_transaction(psz_timestamp, coinbase_value, pubkey):
    """Create the genesis transaction from the details passed."""
    input_script = create_input_script(psz_timestamp)
    output_script = create_output_script(pubkey)

    transaction = Struct('transaction',
                         Bytes('version', 4),
                         Byte('num_inputs'),
                         StaticField('prev_output', 32),
                         UBInt32('prev_out_idx'),
                         Byte('input_script_len'),
                         Bytes('input_script', len(input_script)),
                         UBInt32('sequence'),
                         Byte('num_outputs'),
                         Bytes('out_value', 8),
                         Byte('output_script_len'),
                         Bytes('output_script', 0x43),
                         UBInt32('locktime'))

    tx = transaction.parse(b'\x00' * (127 + len(input_script)))
    tx.version = struct.pack('<I', 1)
    tx.num_inputs = 1
    tx.prev_output = struct.pack('<qqqq', 0, 0, 0, 0)
    tx.prev_out_idx = 0xFFFFFFFF
    tx.input_script_len = len(input_script)
    tx.input_script = input_script
    tx.sequence = 0xFFFFFFFF
    tx.num_outputs = 1
    tx.out_value = struct.pack('<q', coinbase_value)
    tx.output_script_len = 0x43
    tx.output_script = output_script
    tx.locktime = 0
    return transaction.build(tx)

BlockHeader = Struct('block_header',
                     Bytes('version', 4),
                     Bytes('hash_prev_bock', 32),
                     Bytes('hash_merkle_root', 32),
                     Bytes('time', 4),
                     Bytes('bits', 4),
                     Bytes('nonce', 4)
                     )


NEEDS_HEADER_HASH = [
    'x11',
    'x13',
    'x15',
    'quark',
]


def is_need_header_hash(algorithm):
    if algorithm in NEEDS_HEADER_HASH:
        return True
    return False


def hash_sha256d(data):
    return hashlib.sha256(hashlib.sha256(data).digest()).digest()


def hash_scrypt(data):
    import scrypt
    return scrypt.hash(data, data, 1024, 1, 1, 32)


def hash_x11(data):
    import x11_hash
    return x11_hash.getPoWHash(data)


def hash_x13(data):
    import x13_hash
    return x13_hash.getPoWHash(data)


def hash_x15(data):
    import x15_hash
    return x15_hash.getPoWHash(data)


def hash_quark(data):
    import quark_hash
    return quark_hash.getPoWHash(data)


ALGORITHMS = {
    'sha256': hash_sha256d,
    'scrypt': hash_scrypt,
    'x11': hash_x11,
    'x13': hash_x13,
    'x15': hash_x15,
    'quark': hash_quark,
}


def create_block(pszTimestamp, pubkey, nValue, algorithm, nTime, nBits, nNonce, nVersion, test_mode=False):
    algorithm = algorithm.lower().strip()
    if algorithm not in ALGORITHMS:
        raise Exception('Invalid Algorithm Passed')

    block_data = {'pszTimestamp': pszTimestamp, 'pubkey': pubkey, 'nValue': nValue, 'algorithm': algorithm,
                  'nTime': nTime, 'nBits': nBits, 'nNonce': nNonce, 'nVersion': nVersion}

    # Create Coinbase Transaction
    tx = create_genesis_transaction(pszTimestamp, nValue, pubkey)

    # Calculate Merkle Root
    hash_merkle_root = hash_sha256d(tx)
    block_data['hashMerkleRoot'] = '0x' + hash_merkle_root[::-1].hex()

    # Construct block
    genesisblock = BlockHeader.parse(b'\x00' * 80)
    genesisblock.version = struct.pack('<I', nVersion)
    genesisblock.hash_prev_block = struct.pack('<qqqq', 0, 0, 0, 0)
    genesisblock.hash_merkle_root = hash_merkle_root
    genesisblock.time = struct.pack('<I', nTime)
    genesisblock.bits = struct.pack('<I', nBits)
    genesisblock.nonce = struct.pack('<I', nNonce)
    block = BlockHeader.build(genesisblock)

    # Hash Block
    target = (nBits & 0xffffff) * 2**(8 * ((nBits >> 24) - 3))

    # Edge case for testing
    if test_mode:
        sha256_hash = hash_sha256d(block)[::-1]
        header_hash = ALGORITHMS[algorithm](block)[::-1]
        if is_need_header_hash(algorithm):
            block_data['hashGenesisBlock'] = '0x' + header_hash.hex()
        else:
            block_data['hashGenesisBlock'] = '0x' + sha256_hash.hex()
        return block_data

    while True:
        sha256_hash = hash_sha256d(block)[::-1]
        header_hash = ALGORITHMS[algorithm](block)[::-1]

        if int(header_hash.hex(), 16) < target:
            block_data['nTime'] = nTime
            block_data['nNonce'] = nNonce
            if is_need_header_hash(algorithm):
                block_data['hashGenesisBlock'] = '0x' + header_hash.hex()
            else:
                block_data['hashGenesisBlock'] = '0x' + sha256_hash.hex()
            return block_data
        else:
            nNonce += 1
            if (nNonce > 4294967295):
                nTime += 1
                block = block[0:len(block) - 12] + struct.pack('<I', nTime)
            block = block[0:len(block) - 4] + struct.pack('<I', nNonce)



def main(argv=sys.argv):
    args = parser.parse_args()
    print(args)

    block_data = create_block(args.pszTimestamp, args.pubkey, args.nValue, args.algorithm,
                              args.nTime, args.nBits, args.nNonce, args.nVersion)

    print("""
        Algorithm: {algorithm}
        Hash Merkle Root: {hashMerkleRoot}
        pszTimestamp: {pszTimestamp}
        pubkey: {pubkey}
        nTime: {nTime}
        nBits: {nBits}
        nNonce: {nNonce}
        hashGenesisBlock: {hashGenesisBlock}
    """.format(**block_data))
    return block_data
if __name__ == '__main__':
    sys.exit(main())
