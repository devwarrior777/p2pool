from p2pool.bitcoin import networks

PARENT = networks.nets['anoncoin']
SHARE_PERIOD = 10 # seconds
CHAIN_LENGTH = 24*60*60//10 # shares
REAL_CHAIN_LENGTH = 24*60*60//10 # shares
TARGET_LOOKBEHIND = 200 # shares
SPREAD = 10 # blocks
IDENTIFIER = '40C08900F98B2AFA'.decode('hex')
PREFIX = '43F8D4260E9F8E60'.decode('hex')
P2P_PORT = 23650
MIN_TARGET = 0
MAX_TARGET = 2**256//2**20 - 1
PERSIST = False
WORKER_PORT = 8850
BOOTSTRAP_ADDRS = 'xpool.net'.split(' ')
ANNOUNCE_CHANNEL = '#p2pool-anc'
VERSION_CHECK = lambda v: True
VERSION_WARNING = lambda v: None
