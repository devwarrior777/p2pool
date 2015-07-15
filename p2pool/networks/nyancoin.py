from p2pool.bitcoin import networks

PARENT = networks.nets['nyancoin']
SHARE_PERIOD = 10 # seconds
CHAIN_LENGTH = 24*60*60//10 # shares
REAL_CHAIN_LENGTH = 24*60*60//10 # shares
TARGET_LOOKBEHIND = 20 # shares
SPREAD = 30 # blocks
IDENTIFIER = '4C23586A88899B0A'.decode('hex')
PREFIX = '5B737D77555B284E'.decode('hex')
P2P_PORT = 23670
MIN_TARGET = 0
MAX_TARGET = 2**256//2**20 - 1
PERSIST = False
WORKER_PORT = 8870
BOOTSTRAP_ADDRS = 'xpool.net'.split(' ')
ANNOUNCE_CHANNEL = '#p2pool-nyan'
VERSION_CHECK = lambda v: True
VERSION_WARNING = lambda v: None
