from __future__ import division
from collections import deque

import base64
import random
import re
import sys
import time

from twisted.internet import defer
from twisted.python import log

import p2pool.decred.decred_data as decred_data
import p2pool.decred.decred_addr as decred_addr
from p2pool.decred import helper, script, worker_interface
from util import forest, jsonrpc, variable, deferral, math, pack
import p2pool, p2pool.data as p2pool_data

print_throttle = 0.0

class WorkerBridge(worker_interface.WorkerBridge):
    COINBASE_NONCE_LENGTH = 8
    
    def __init__(self, node, my_pubkey_hash, donation_percentage, worker_fee, args, pubkeys, dcrd):
        worker_interface.WorkerBridge.__init__(self)
        self.recent_shares_ts_work = []
        
        self.node = node

        self.dcrd = dcrd
        self.pubkeys = pubkeys
        self.args = args
        self.my_pubkey_hash = my_pubkey_hash

        self.donation_percentage = args.donation_percentage
        self.worker_fee = args.worker_fee
        
        self.net = self.node.net.PARENT
        self.running = True
        self.pseudoshare_received = variable.Event()
        self.share_received = variable.Event()
        self.local_rate_monitor = math.RateMonitor(10*60)
        self.local_addr_rate_monitor = math.RateMonitor(10*60)
        
        self.removed_unstales_var = variable.Variable((0, 0, 0))
        self.removed_doa_unstales_var = variable.Variable(0)
        
        self.last_work_shares = variable.Variable( {} )
        self.my_share_hashes = set()
        self.my_doa_share_hashes = set()

        self.address_throttle = 0
        
        self.tracker_view = forest.TrackerView(self.node.tracker, forest.get_attributedelta_type(dict(forest.AttributeDelta.attrs,
            my_count=lambda share: 1 if share.hash in self.my_share_hashes else 0,
            my_doa_count=lambda share: 1 if share.hash in self.my_doa_share_hashes else 0,
            my_orphan_announce_count=lambda share: 1 if share.hash in self.my_share_hashes and share.share_data['stale_info'] == 'orphan' else 0,
            my_dead_announce_count=lambda share: 1 if share.hash in self.my_share_hashes and share.share_data['stale_info'] == 'doa' else 0,
        )))
        
        @self.node.tracker.verified.removed.watch
        def _(share):
            if share.hash in self.my_share_hashes and self.node.tracker.is_child_of(share.hash, self.node.best_share_var.value):
                assert share.share_data['stale_info'] in [None, 'orphan', 'doa'] # we made these shares in this instance
                self.removed_unstales_var.set((
                    self.removed_unstales_var.value[0] + 1,
                    self.removed_unstales_var.value[1] + (1 if share.share_data['stale_info'] == 'orphan' else 0),
                    self.removed_unstales_var.value[2] + (1 if share.share_data['stale_info'] == 'doa' else 0),
                ))
            if share.hash in self.my_doa_share_hashes and self.node.tracker.is_child_of(share.hash, self.node.best_share_var.value):
                self.removed_doa_unstales_var.set(self.removed_doa_unstales_var.value + 1)
        
       
        # COMBINE WORK
        
        self.current_work = variable.Variable(None)
        def compute_work():
            t = self.node.dcrd_work.value
            bb = self.node.best_block_header.value
            if bb is not None and bb['previous_block'] == t['previous_block'] and self.node.net.PARENT.POW_FUNC(decred_data.block_header_type.pack(bb)) <= t['bits'].target:
                print 'Skipping from block %x to block %x!' % (bb['previous_block'],
                    decred_data.hash256(decred_data.block_header_type.pack(bb)))
                t = dict(
                    version=bb['version'],
                    previous_block=decred_data.hash256(decred_data.block_header_type.pack(bb)),
                    bits=bb['bits'], # not always true
                    coinbaseflags='',
                    height=t['height'] + 1,
                    time=bb['timestamp'] + 600, # better way?
                    transactions=[],
                    transaction_fees=[],
                    merkle_link=decred_data.calculate_merkle_link([None], 0),
                    subsidy=self.node.net.PARENT.SUBSIDY_FUNC(self.node.dcrd_work.value['height']),
                    last_update=self.node.dcrd_work.value['last_update'],
                )
            
            self.current_work.set(t)
        self.node.dcrd_work.changed.watch(lambda _: compute_work())
        self.node.best_block_header.changed.watch(lambda _: compute_work())
        compute_work()
        
        self.new_work_event = variable.Event()
        @self.current_work.transitioned.watch
        def _(before, after):
            # trigger LP if version/previous_block/bits changed or transactions changed from nothing
            if any(before[x] != after[x] for x in ['version', 'previous_block', 'bits']) or (not before['transactions'] and after['transactions']):
                self.new_work_event.happened()
        self.node.best_share_var.changed.watch(lambda _: self.new_work_event.happened())
    
    def stop(self):
        self.running = False
    
    def get_stale_counts(self):
        '''Returns (orphans, doas), total, (orphans_recorded_in_chain, doas_recorded_in_chain)'''
        my_shares = len(self.my_share_hashes)
        my_doa_shares = len(self.my_doa_share_hashes)
        delta = self.tracker_view.get_delta_to_last(self.node.best_share_var.value)
        my_shares_in_chain = delta.my_count + self.removed_unstales_var.value[0]
        my_doa_shares_in_chain = delta.my_doa_count + self.removed_doa_unstales_var.value
        orphans_recorded_in_chain = delta.my_orphan_announce_count + self.removed_unstales_var.value[1]
        doas_recorded_in_chain = delta.my_dead_announce_count + self.removed_unstales_var.value[2]
        
        my_shares_not_in_chain = my_shares - my_shares_in_chain
        my_doa_shares_not_in_chain = my_doa_shares - my_doa_shares_in_chain
        
        return (my_shares_not_in_chain - my_doa_shares_not_in_chain, my_doa_shares_not_in_chain), my_shares, (orphans_recorded_in_chain, doas_recorded_in_chain)
    
    @defer.inlineCallbacks
    def freshen_addresses(self, c):
        self.cur_address_throttle = time.time()
        if self.cur_address_throttle - self.address_throttle < 30:
            return
        self.address_throttle=time.time()
        print "ATTEMPTING TO FRESHEN ADDRESS."
        self.address = yield deferral.retry('Error getting a dynamic address from dcrd:', 5)(lambda: self.dcrd.rpc_getnewaddress('p2pool'))()
        new_pubkey = decred_addr.address_to_pubkey_hash(self.address, self.net)
        self.pubkeys.popleft()
        self.pubkeys.addkey(new_pubkey)
        print " Updated payout pool:"
        for i in range(len(self.pubkeys.keys)):
            print '    ...payout %d: %s(%f)' % (i, decred_addr.pubkey_hash_to_address(self.pubkeys.keys[i], self.net),self.pubkeys.keyweights[i],)
        self.pubkeys.updatestamp(c)
        print " Next address rotation in : %fs" % (time.time()-c+self.args.timeaddresses)
 
    def get_user_details(self, username):
        contents = re.split('([+/])', username)
        assert len(contents) % 2 == 1
        
        user, contents2 = contents[0], contents[1:]
        
        desired_pseudoshare_target = None
        desired_share_target = None
        for symbol, parameter in zip(contents2[::2], contents2[1::2]):
            if symbol == '+':
                try:
                    desired_pseudoshare_target = decred_data.difficulty_to_target(float(parameter))
                except:
                    if p2pool.DEBUG:
                        log.err()
            elif symbol == '/':
                try:
                    desired_share_target = decred_data.difficulty_to_target(float(parameter))
                except:
                    if p2pool.DEBUG:
                        log.err()

        if self.args.address == 'dynamic':
            i = self.pubkeys.weighted()
            pubkey_hash = self.pubkeys.keys[i]

            c = time.time()
            if (c - self.pubkeys.stamp) > self.args.timeaddresses:
                self.freshen_addresses(c)

        if random.uniform(0, 100) < self.worker_fee:
            pubkey_hash = self.my_pubkey_hash
        else:
            try:
                pubkey_hash = decred_addr.address_to_pubkey_hash(user, self.node.net.PARENT)
            except: # XXX blah
                if self.args.address != 'dynamic':
                    pubkey_hash = self.my_pubkey_hash
        
        return user, pubkey_hash, desired_share_target, desired_pseudoshare_target
    
    def preprocess_request(self, user):
        if (self.node.p2p_node is None or len(self.node.p2p_node.peers) == 0) and self.node.net.PERSIST:
            raise jsonrpc.Error_for_code(-12345)(u'p2pool is not connected to any peers')
        if time.time() > self.current_work.value['last_update'] + 60:
            raise jsonrpc.Error_for_code(-12345)(u'lost contact with dcrd')
        user, pubkey_hash, desired_share_target, desired_pseudoshare_target = self.get_user_details(user)
        return pubkey_hash, desired_share_target, desired_pseudoshare_target
    
    def _estimate_local_hash_rate(self):
        if len(self.recent_shares_ts_work) == 50:
            hash_rate = sum(work for ts, work in self.recent_shares_ts_work[1:])//(self.recent_shares_ts_work[-1][0] - self.recent_shares_ts_work[0][0])
            if hash_rate > 0:
                return hash_rate
        return None
    
    def get_local_rates(self):
        miner_hash_rates = {}
        miner_dead_hash_rates = {}
        datums, dt = self.local_rate_monitor.get_datums_in_last()
        for datum in datums:
            miner_hash_rates[datum['user']] = miner_hash_rates.get(datum['user'], 0) + datum['work']/dt
            if datum['dead']:
                miner_dead_hash_rates[datum['user']] = miner_dead_hash_rates.get(datum['user'], 0) + datum['work']/dt
        return miner_hash_rates, miner_dead_hash_rates
    
    def get_local_addr_rates(self):
        addr_hash_rates = {}
        datums, dt = self.local_addr_rate_monitor.get_datums_in_last()
        for datum in datums:
            addr_hash_rates[datum['pubkey_hash']] = addr_hash_rates.get(datum['pubkey_hash'], 0) + datum['work']/dt
        return addr_hash_rates
    
    def get_work(self, pubkey_hash, desired_share_target, desired_pseudoshare_target):
        global print_throttle
        if (self.node.p2p_node is None or len(self.node.p2p_node.peers) == 0) and self.node.net.PERSIST:
            raise jsonrpc.Error_for_code(-12345)(u'p2pool is not connected to any peers')
        if self.node.best_share_var.value is None and self.node.net.PERSIST:
            raise jsonrpc.Error_for_code(-12345)(u'p2pool is downloading shares')
        
        mm_data = ''
        mm_later = []
        
        tx_hashes = [decred_data.hash256(decred_data.tx_type.pack(tx)) for tx in self.current_work.value['transactions']]
        tx_map = dict(zip(tx_hashes, self.current_work.value['transactions']))
        
        previous_share = self.node.tracker.items[self.node.best_share_var.value] if self.node.best_share_var.value is not None else None
        if previous_share is None:
            share_type = p2pool_data.Share
        else:
            previous_share_type = type(previous_share)
            
            if previous_share_type.SUCCESSOR is None or self.node.tracker.get_height(previous_share.hash) < self.node.net.CHAIN_LENGTH:
                share_type = previous_share_type
            else:
                successor_type = previous_share_type.SUCCESSOR
                
                counts = p2pool_data.get_desired_version_counts(self.node.tracker,
                    self.node.tracker.get_nth_parent_hash(previous_share.hash, self.node.net.CHAIN_LENGTH*9//10), self.node.net.CHAIN_LENGTH//10)
                upgraded = counts.get(successor_type.VERSION, 0)/sum(counts.itervalues())
                if upgraded > .65:
                    print 'Switchover imminent. Upgraded: %.3f%% Threshold: %.3f%%' % (upgraded*100, 95)
                # Share -> NewShare only valid if 95% of hashes in [net.CHAIN_LENGTH*9//10, net.CHAIN_LENGTH] for new version
                if counts.get(successor_type.VERSION, 0) > sum(counts.itervalues())*95//100:
                    share_type = successor_type
                else:
                    share_type = previous_share_type
        
        if desired_share_target is None:
            desired_share_target = decred_data.difficulty_to_target(float(1.0 / self.node.net.PARENT.DUMB_SCRYPT_DIFF))
            local_hash_rate = self._estimate_local_hash_rate()
            if local_hash_rate is not None:
                desired_share_target = min(desired_share_target,
                    decred_data.average_attempts_to_target(local_hash_rate * self.node.net.SHARE_PERIOD / 0.0167)) # limit to 1.67% of pool shares by modulating share difficulty
            
            local_addr_rates = self.get_local_addr_rates()
            lookbehind = 3600//self.node.net.SHARE_PERIOD
            block_subsidy = self.node.dcrd_work.value['subsidy']
            if previous_share is not None and self.node.tracker.get_height(previous_share.hash) > lookbehind:
                expected_payout_per_block = local_addr_rates.get(pubkey_hash, 0)/p2pool_data.get_pool_attempts_per_second(self.node.tracker, self.node.best_share_var.value, lookbehind) \
                    * block_subsidy*(1-self.donation_percentage/100) # XXX doesn't use global stale rate to compute pool hash
                if expected_payout_per_block < self.node.net.PARENT.DUST_THRESHOLD:
                    desired_share_target = min(desired_share_target,
                        decred_data.average_attempts_to_target((decred_data.target_to_average_attempts(self.node.dcrd_work.value['bits'].target)*self.node.net.SPREAD)*self.node.net.PARENT.DUST_THRESHOLD/block_subsidy)
                    )
        
        if True:
            share_info, gentx, other_transaction_hashes, get_share = share_type.generate_transaction(
                tracker=self.node.tracker,
                share_data=dict(
                    previous_share_hash=self.node.best_share_var.value,
                    coinbase=(script.create_push_script([
                        self.current_work.value['height'],
                        ] + ([mm_data] if mm_data else []) + [
                    ]) + self.current_work.value['coinbaseflags'])[:100],
                    nonce=random.randrange(2**32),
                    pubkey_hash=pubkey_hash,
                    subsidy=self.current_work.value['subsidy'],
                    donation=math.perfect_round(65535*self.donation_percentage/100),
                    stale_info=(lambda (orphans, doas), total, (orphans_recorded_in_chain, doas_recorded_in_chain):
                        'orphan' if orphans > orphans_recorded_in_chain else
                        'doa' if doas > doas_recorded_in_chain else
                        None
                    )(*self.get_stale_counts()),
                    desired_version=(share_type.SUCCESSOR if share_type.SUCCESSOR is not None else share_type).VOTING_VERSION,
                ),
                block_target=self.current_work.value['bits'].target,
                desired_timestamp=int(time.time() + 0.5),
                desired_target=desired_share_target,
                ref_merkle_link=dict(branch=[], index=0),
                desired_other_transaction_hashes_and_fees=zip(tx_hashes, self.current_work.value['transaction_fees']),
                net=self.node.net,
                known_txs=tx_map,
                base_subsidy=self.node.net.PARENT.SUBSIDY_FUNC(self.current_work.value['height']),
            )
        
        packed_gentx = decred_data.tx_type.pack(gentx)
        other_transactions = [tx_map[tx_hash] for tx_hash in other_transaction_hashes]
        
        mm_later = [(dict(aux_work, target=aux_work['target'] if aux_work['target'] != 'p2pool' else share_info['bits'].target), index, hashes) for aux_work, index, hashes in mm_later]
        
        if desired_pseudoshare_target is None:
            target = 2**256-1
            local_hash_rate = self._estimate_local_hash_rate()
            if local_hash_rate is not None:
                target = min(target,
                    decred_data.average_attempts_to_target(local_hash_rate * 1)) # limit to 1 share response every second by modulating pseudoshare difficulty
        else:
            target = desired_pseudoshare_target
        target = max(target, share_info['bits'].target)
        for aux_work, index, hashes in mm_later:
            target = max(target, aux_work['target'])
        target = math.clip(target, self.node.net.PARENT.SANE_TARGET_RANGE)
        
        getwork_time = time.time()
        lp_count = self.new_work_event.times
        merkle_link = decred_data.calculate_merkle_link([None] + other_transaction_hashes, 0)
        
        if print_throttle is 0.0:
            print_throttle = time.time()
        else:
            current_time = time.time()
            if (current_time - print_throttle) > 5.0:
                print 'New work for worker! Difficulty: %.06f Share difficulty: %.06f Total block value: %.6f %s including %i transactions' % (
                    decred_data.target_to_difficulty(target),
                    decred_data.target_to_difficulty(share_info['bits'].target),
                    self.current_work.value['subsidy']*1e-8, self.node.net.PARENT.SYMBOL,
                    len(self.current_work.value['transactions']),
                )
                print_throttle = time.time()

        #need this for stats
        self.last_work_shares.value[decred_addr.pubkey_hash_to_address(pubkey_hash, self.node.net.PARENT)]=share_info['bits']
        
        ba = dict(
            version=min(self.current_work.value['version'], 3),
            previous_block=self.current_work.value['previous_block'],
            merkle_link=merkle_link,
            coinb1=packed_gentx[:-self.COINBASE_NONCE_LENGTH-4],
            coinb2=packed_gentx[-4:],
            timestamp=self.current_work.value['time'],
            bits=self.current_work.value['bits'],
            share_target=target,
        )
        
        received_header_hashes = set()
        
        def got_response(header, user, coinbase_nonce):
            assert len(coinbase_nonce) == self.COINBASE_NONCE_LENGTH
            new_packed_gentx = packed_gentx[:-self.COINBASE_NONCE_LENGTH-4] + coinbase_nonce + packed_gentx[-4:] if coinbase_nonce != '\0'*self.COINBASE_NONCE_LENGTH else packed_gentx
            new_gentx = decred_data.tx_type.unpack(new_packed_gentx) if coinbase_nonce != '\0'*self.COINBASE_NONCE_LENGTH else gentx
            
            header_hash = decred_data.hash256(decred_data.block_header_type.pack(header))
            pow_hash = self.node.net.PARENT.POW_FUNC(decred_data.block_header_type.pack(header))
            try:
                if pow_hash <= header['bits'].target or p2pool.DEBUG:
                    helper.submit_block(dict(header=header, txs=[new_gentx] + other_transactions), False, self.node.factory, self.node.dcrd, self.node.dcrd_work, self.node.net)
                    if pow_hash <= header['bits'].target:
                        print
                        print 'GOT BLOCK FROM MINER! Passing to dcrd! %s%064x' % (self.node.net.PARENT.BLOCK_EXPLORER_URL_PREFIX, header_hash)
                        print
            except:
                log.err(None, 'Error while processing potential block:')
            
            user, _, _, _ = self.get_user_details(user)
            assert header['previous_block'] == ba['previous_block']
            assert header['merkle_root'] == decred_data.check_merkle_link(decred_data.hash256(new_packed_gentx), merkle_link)
            assert header['bits'] == ba['bits']
            
            on_time = self.new_work_event.times == lp_count
            
            if pow_hash <= share_info['bits'].target and header_hash not in received_header_hashes:
                last_txout_nonce = pack.IntType(8*self.COINBASE_NONCE_LENGTH).unpack(coinbase_nonce)
                share = get_share(header, last_txout_nonce)
                
                print 'GOT SHARE! %s %s prev %s age %.2fs%s' % (
                    user,
                    p2pool_data.format_hash(share.hash),
                    p2pool_data.format_hash(share.previous_hash),
                    time.time() - getwork_time,
                    ' DEAD ON ARRIVAL' if not on_time else '',
                )
                self.my_share_hashes.add(share.hash)
                if not on_time:
                    self.my_doa_share_hashes.add(share.hash)
                
                self.node.tracker.add(share)
                self.node.set_best_share()
                
                try:
                    if (pow_hash <= header['bits'].target or p2pool.DEBUG) and self.node.p2p_node is not None:
                        self.node.p2p_node.broadcast_share(share.hash)
                except:
                    log.err(None, 'Error forwarding block solution:')
                
                self.share_received.happened(decred_data.target_to_average_attempts(share.target), not on_time, share.hash)
            
            if pow_hash > target:
                print 'Worker %s submitted share with hash > target:' % (user,)
                print '    Hash:   %56x' % (pow_hash,)
                print '    Target: %56x' % (target,)
            elif header_hash in received_header_hashes:
                print >>sys.stderr, 'Worker %s submitted share more than once!' % (user,)
            else:
                received_header_hashes.add(header_hash)
                
                self.pseudoshare_received.happened(decred_data.target_to_average_attempts(target), not on_time, user)
                self.recent_shares_ts_work.append((time.time(), decred_data.target_to_average_attempts(target)))
                while len(self.recent_shares_ts_work) > 50:
                    self.recent_shares_ts_work.pop(0)
                self.local_rate_monitor.add_datum(dict(work=decred_data.target_to_average_attempts(target), dead=not on_time, user=user, share_target=share_info['bits'].target))
                self.local_addr_rate_monitor.add_datum(dict(work=decred_data.target_to_average_attempts(target), pubkey_hash=pubkey_hash))
            
            return on_time
        
        return ba, got_response
