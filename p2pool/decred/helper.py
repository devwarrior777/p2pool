import sys
import time

from twisted.internet import defer

import p2pool
from p2pool.decred import decred_data
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

@deferral.retry('Error while checking Decred Wallet connection:', 1)
@defer.inlineCallbacks
def checkwallet(dcrdwallet, net):
    print('wallet_check')
    wallet_dcrd_server_check_result = (yield dcrdwallet.rpc_walletinfo())['daemonconnected']
    if wallet_dcrd_server_check_result == False:
        print >>sys.stderr, '    ' + wallet_dcrd_server_check_result
        raise deferral.RetrySilentlyException()

@deferral.retry('Error getting work from dcrd:', 3)
@defer.inlineCallbacks
def getwork(dcrd, use_getblocktemplate=True):
    def go():
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
    packed_txs = []
    for tx in work['transactions']:
        ptx = tx['data'].decode('hex')
        phash = tx['hash'].decode('hex')
        packed_txs.append({'ptx': ptx, 'phash': phash, 'tree': 0}) 
    packed_stxxs = []
    for stxx in work['stransactions']:
        ptx = stxx['data'].decode('hex')
        phash = stxx['hash'].decode('hex')
        packed_stxxs.append({'ptx': ptx, 'phash': phash, 'tree': 1}) 
    
    packed_transactions = []
    packed_transactions.extend(packed_txs)
    packed_transactions.extend(packed_stxxs)

    transaction_records = []
    transaction_hashes = []
    for packed_tx in packed_transactions:
        txrec = decred_data.tx_type.unpack(packed_tx['ptx'])
        transaction_records.append(txrec)
        transaction_hashes.append(packed_tx['ptx'])
    
    wd = dict(
        version=work['version'],
        previous_block=int(work['previousblockhash'], 16),
        transactions=transaction_records,
        transaction_hashes=transaction_hashes,
        transaction_fees=[x.get('fee', None) if isinstance(x, dict) else None for x in work['transactions']],
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
