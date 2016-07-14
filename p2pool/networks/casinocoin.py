from p2pool.bitcoin import networks

PARENT = networks.nets['casinocoin']
SHARE_PERIOD = 10 # seconds
CHAIN_LENGTH = 24*60*60//10 # shares
REAL_CHAIN_LENGTH = 24*60*60//10 # shares
TARGET_LOOKBEHIND = 20 # shares
SPREAD = 60 # blocks
IDENTIFIER = '7A1B73A729CF5FC1'.decode('hex')
PREFIX = '79A544E00296E8BA'.decode('hex')
P2P_PORT = 23640
MIN_TARGET = 0
MAX_TARGET = 2**256//2**20 - 1
PERSIST = False
WORKER_PORT = 8840
BOOTSTRAP_ADDRS = 'xpool.net'.split(' ')
ANNOUNCE_CHANNEL = '#p2pool-csc'
VERSION_CHECK = lambda v: True
VERSION_WARNING = lambda v: None
