from p2pool.bitcoin import networks

PARENT = networks.nets['worldcoin']
SHARE_PERIOD = 10 # seconds
CHAIN_LENGTH = 24*60*60//10 # shares
REAL_CHAIN_LENGTH = 24*60*60//10 # shares
TARGET_LOOKBEHIND = 200 # shares
SPREAD = 60 # blocks
IDENTIFIER = '5AE1DD1E84E6EC3A'.decode('hex')
PREFIX = '43B80223C931E0A0'.decode('hex')
P2P_PORT = 23620
MIN_TARGET = 0
MAX_TARGET = 2**256//2**20 - 1
PERSIST = False
WORKER_PORT = 8820
BOOTSTRAP_ADDRS = 'xpool.net'.split(' ')
ANNOUNCE_CHANNEL = '#p2pool-wdc'
VERSION_CHECK = lambda v: True
VERSION_WARNING = lambda v: None
