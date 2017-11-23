from p2pool.decred import networks
#https://decredtalk.org/index.php?topic=457574.0      how to fixup some of these
PARENT = networks.nets['decred_testnet']
SHARE_PERIOD = 30 # seconds                            # <- ?
CHAIN_LENGTH = 60*60//10 # shares                      # <- ?  
REAL_CHAIN_LENGTH = 60*60//10 # shares                 # <- ?
TARGET_LOOKBEHIND = 200 # shares# <- ?
SPREAD = 6 # blocks                                    # <- ?
IDENTIFIER = 'deadbeefcafebabe'.decode('hex')          # <- ?
PREFIX = 'c001c001cafebabe'.decode('hex')              # <- ?
P2P_PORT = 17333                                        # Used by p2pool to connect or allow connection to other peers (p2pool servers)
MIN_TARGET = 0
MAX_TARGET = 2**256//2**32 - 1
PERSIST = False
WORKER_PORT = 17332                                     # <- connect my worker here (over stratum?)
BOOTSTRAP_ADDRS = ''.split(' ')                        # <- ? dont have any anyway
ANNOUNCE_CHANNEL = '#p2pool-dcr-alt'
VERSION_CHECK = lambda v: None if 01010000 <= v else 'Decred version too old. Upgrade to 1.1.1 or newer!' # not a bug. BIP65 support is ensured by SOFTFORKS_REQUIRED
VERSION_WARNING = lambda v: None

#SOFTFORKS_REQUIRED = set(['bip65', 'csv', 'segwit'])
#MINIMUM_PROTOCOL_VERSION = 1600
#NEW_MINIMUM_PROTOCOL_VERSION = 1700
#SSEGWIT_ACTIVATION_VERSION = 15
