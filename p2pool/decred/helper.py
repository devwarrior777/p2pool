import sys
import time

from twisted.internet import defer

import p2pool
from p2pool.decred import decred_data
from p2pool.util import pack                    # debug
from p2pool.util import deferral, jsonrpc


@deferral.retry('Error while checking Decred connection:', 1)
@defer.inlineCallbacks
def check(dcrd, net):
    if not (yield net.PARENT.RPC_CHECK(dcrd)):
        print >>sys.stderr, "    Check failed! Make sure that you're connected to the right dcrd with --dcrd-rpc-port!"
        raise deferral.RetrySilentlyException()
    version_check_result = net.VERSION_CHECK((yield dcrd.rpc_getinfo())['version'])
    if version_check_result == True: version_check_result = None # deprecated
    if version_check_result == False: version_check_result = 'Coin daemon too old! Upgrade!' # deprecated
    if version_check_result is not None:
        print >>sys.stderr, '    ' + version_check_result
        raise deferral.RetrySilentlyException()

#gf: check forever
# @deferral.retry('Error while checking Decred Wallet connection:', delay=1)
# @defer.inlineCallbacks
# def checkwallet(dcrdwallet, net, tries):
#     print('wallet_check')
#     wallet_dcrd_server_check_result = (yield dcrdwallet.rpc_walletinfo())['daemonconnected']
#     tries = tries - 1 
#     if wallet_dcrd_server_check_result == False:
#         print >>sys.stderr, '    ' + wallet_dcrd_server_check_result
#         raise deferral.RetrySilentlyException()

#
# Check 3 up to times if the wallet is online
#
# @return True if online, False if not online
#
@defer.inlineCallbacks
def checkwallet(dcrdwallet, net, tries=3, waittime=1):
    print('wallet_check')
    for i in range(tries):
        res = False
        try:
            res = (yield dcrdwallet.rpc_walletinfo())['daemonconnected']
            defer.returnValue(True)
        except Exception:
            print >>sys.stderr, '... connect fail'
            time.sleep(waittime)
    defer.returnValue(False)

#gf:beta getblocktemplate
# @deferral.retry('Error getting work from dcrd:', 3)
@deferral.retry('Error getting work from dcrd:', 13)
#<-gf:
@defer.inlineCallbacks
def getwork(dcrd, use_getblocktemplate=True):
    def go():
        print 'Getting blocktemplate ...'
        if not use_getblocktemplate:
            raise Exception("getblocktemplate only")
        return dcrd.rpc_getblocktemplate(dict(mode='template'))
    try:
        start = time.time()
        work = yield go()
        end = time.time()
    except jsonrpc.Error_for_code(-32601): # Method not found
        print >>sys.stderr, 'Error: Decred version too old! Upgrade to v1.1.1 or newer!'
        raise deferral.RetrySilentlyException()

    #
    # work
    #
    work['currtime'] = time.time()

    #
    # Block Header
    #
    block_header = work['header']
    packed_header = block_header.decode('hex')
    block_header_record = decred_data.block_header_type.unpack(packed_header)
    work['version'] = block_header_record.version
    work['bits'] = block_header_record.bits
    work['height'] = block_header_record.height
    work['previousblockhash'] = "{0:x}".format(block_header_record.previous_block)
    if p2pool.DEBUG:
        assert work['height'] == (yield dcrd.rpc_getblock(work['previousblockhash']))['height'] + 1

    #
    # Transactions
    #
    txs = []
    for regtx in work['transactions']:
#         ptx = tx['data'].decode('hex')
#         hash = pack.IntType(256, endianness='big').unpack(tx['hash'].decode('hex'))
#         packed_txs.append({'tx': ptx, 'hash': hash})
        tx = regtx['data']
        hash = regtx['hash']
        txs.append({'tx': tx, 'hash': hash})
    stxs = []
    for staketx in work['stransactions']:
        stx = staketx['data']
        hash = staketx['hash']
        stxs.append({'tx': stx, 'hash': hash}) 
    
    all_transactions = []
    all_transactions.extend(txs)
    all_transactions.extend(stxs)

    transaction_records = []
    transaction_hashes = []
    for t in all_transactions:
        ptx = t['tx'].decode('hex')
        ptx_hash = t['hash'].decode('hex')
        tx_full = decred_data.tx_type.unpack(ptx)
        tx_full_hash = pack.IntType(256, endianness='big').unpack(ptx_hash)         # sent in on getblocktemplate
        transaction_records.append(tx_full)
        transaction_hashes.append(tx_full_hash)
        #
        # TODO: Find out if we need the prefix hashes at a later point in the logic flow
        #
        if p2pool.DEBUG:
            alldata = decred_data.tx_type.get_all(ptx)
            print(hex(tx_full_hash), 'tx_full_hash:')
            print(hex(alldata['tx_full_hash']), 'alldata.tx_full_hash')
            print(hex(alldata['prefix_hash']), 'alldata.prefix_hash')
            print(hex(alldata['witness_hash']), 'alldata.witness_hash')
            assert tx_full_hash == alldata['tx_full_hash']
            print
    
    wd = dict(
        version=work['version'],
        previous_block=int(work['previousblockhash'], 16),
        transactions=transaction_records,
        transaction_hashes=transaction_hashes,
        transaction_fees=[x.get('fee', None) if isinstance(x, dict) else None for x in work['transactions']], # TODO: FixMe for trans + strans
        subsidy=work['coinbasevalue'],
        time=work['currtime'],
        bits=decred_data.FloatingInteger(work['bits']),
        coinbaseflags=''.join(x.decode('hex') for x in work['coinbaseaux'].itervalues()),
        height=work['height'],
        last_update=time.time(),
        use_getblocktemplate=use_getblocktemplate,
        latency=end - start,
    )
    defer.returnValue(wd)
#     defer.returnValue(dict(
#         version=work['version'],
#         previous_block=int(work['previousblockhash'], 16),
#         transactions=map(decred_data.tx_type.unpack, packed_transactions),
#         transaction_hashes=map(decred_data.hash256, packed_transactions),
#         transaction_fees=[x.get('fee', None) if isinstance(x, dict) else None for x in work['transactions']],
#         subsidy=work['coinbasevalue'],
#         time=work['time'] if 'time' in work else work['curtime'],
#         bits=decred_data.FloatingIntegerType().unpack(work['bits'].decode('hex')[::-1]) if isinstance(work['bits'], (str, unicode)) else decred_data.FloatingInteger(work['bits']),
#         coinbaseflags=work['coinbaseflags'].decode('hex') if 'coinbaseflags' in work else ''.join(x.decode('hex') for x in work['coinbaseaux'].itervalues()) if 'coinbaseaux' in work else '',
#         height=work['height'],
#         last_update=time.time(),
#         use_getblocktemplate=use_getblocktemplate,
#         latency=end - start,
#     ))


@deferral.retry('Error submitting primary block: (will retry)', 10, 10)
def submit_block_p2p(block, factory, net):
    if factory.conn.value is None:
        print >>sys.stderr, 'No dcrd connection when block submittal attempted! %s%064x' % (net.PARENT.BLOCK_EXPLORER_URL_PREFIX, decred_data.hash256(decred_data.block_header_type.pack(block['header'])))
        raise deferral.RetrySilentlyException()
    factory.conn.value.send_block(block=block)


@deferral.retry('Error submitting block: (will retry)', 10, 10)
@defer.inlineCallbacks
def submit_block_rpc(block, ignore_failure, dcrd, dcrd_work, net):
    if dcrd_work.value['use_getblocktemplate']:
        try:
            result = yield dcrd.rpc_submitblock(decred_data.block_type.pack(block).encode('hex'))
        except jsonrpc.Error_for_code(-32601): # Method not found, for older litecoin versions
            result = yield dcrd.rpc_getblocktemplate(dict(mode='submit', data=decred_data.block_type.pack(block).encode('hex')))
        success = result is None
    else:
        result = yield dcrd.rpc_getmemorypool(decred_data.block_type.pack(block).encode('hex'))
        success = result
    success_expected = net.PARENT.POW_FUNC(decred_data.block_header_type.pack(block['header'])) <= block['header']['bits'].target
    if (not success and success_expected and not ignore_failure) or (success and not success_expected):
        print >>sys.stderr, 'Block submittal result: %s (%r) Expected: %s' % (success, result, success_expected)

def submit_block(block, ignore_failure, factory, dcrd, dcrd_work, net):
    submit_block_p2p(block, factory, net)
    submit_block_rpc(block, ignore_failure, dcrd, dcrd_work, net)

@defer.inlineCallbacks
def check_genesis_block(dcrd, genesis_block_hash):
    try:
        yield dcrd.rpc_getblock(genesis_block_hash)
    except jsonrpc.Error_for_code(-5):
        defer.returnValue(False)
    else:
        defer.returnValue(True)
