# firewalled ECDSA signatures
#
# https://github.com/oreparaz/fecdsa
#
# DO NOT USE - experimental quality software

# Known issues:
# - Nonce generation has not been tested. Assume it is broken.
# - The state machine is loose: a correct calling order is not
#   enforced, and different messages aren't tied to each other.

import ec
import ecdsa
import random
import hashlib

rand = random.SystemRandom()
H = hashlib.sha256
curve = ec.nistp256

_version = "2020-05-01/001"


def commitment(v, r):
    return H(str({'version': _version, 'v': v, 'r': r}) ).hexdigest()

def sum_dictelem(x, key):
    cum = 0
    for idx, val in x.items():
        cum = cum + val[key]
    return cum

def check_openings(openings, comms, number_comms, party_index):
    for i in range(number_comms):
        if i == party_index:
            continue
        H_ours = commitment(openings[i]['v'], openings[i]['r'])
        assert H_ours == comms[i]

class Signer:
    def __init__(self, k, number_firewalls):
        self.k = k
        self.their_commitments = {}
        self.their_openings = {}
        self.number_firewalls = number_firewalls

    def recv_commitment(self, their_commitment, who):
        self.their_commitments[who] = their_commitment['H']

    def generate_nonceshare(self):
        self.vp = rand.randrange(0, curve.n - 1)
        self.bigVp = curve.base_mul(self.vp)
        return {'Vp': self.bigVp}

    def recv_opening(self, their_opening, who):
        self.their_openings[who] = their_opening

    def compute_privnonce(self):
        check_openings(self.their_openings,
                       self.their_commitments,
                       self.number_firewalls,
                       -1)
        vsum = sum_dictelem(self.their_openings, 'v')
        self.x, = ec.modp(curve.n, self.vp + vsum)
        self.bX = curve.base_mul(int(self.x))

    def sign(self, msg):
        return ecdsa.sign(curve, H, self.k, msg, (int(self.x), self.bX))


class Firewall:
    def __init__(self, Q, number_firewalls, party_index):
        assert curve.point_on_curve(Q)
        self.Q = Q
        self.their_commitments = {}
        self.their_openings = {}
        self.number_firewalls = number_firewalls
        self.party_index = party_index

    def recv_commitment(self, their_commitment, who):
        self.their_commitments[who] = their_commitment['H']

    def recv_opening(self, their_opening, who):
        self.their_openings[who] = their_opening

    def prepare_commitment(self):
        self.v = rand.randrange(0, curve.n - 1)
        self.r = rand.randrange(0, curve.n - 1)
        return {'H': commitment(self.v, self.r)}

    def open_commitment(self):
        return {'v': self.v, 'r': self.r}

    def compute_pubnonce(self, signer_share):
        check_openings(self.their_openings,
                       self.their_commitments,
                       self.number_firewalls,
                       self.party_index) 
        Vp = signer_share['Vp']
        assert curve.point_on_curve(Vp)
        vsum = sum_dictelem(self.their_openings, 'v')
        self.X = curve.point_add(Vp, curve.base_mul(self.v + vsum))
        return {'v': self.v, 'r': self.r}

    def sanitize(self, sig, msg):
        ecdsa.verify(curve, H, self.Q, msg, sig)
        r, s = sig
        p1 = curve.base_mul(ecdsa._hash_message(curve, H, msg))
        p2 = curve.point_mul(r, self.Q)
        Rabs = curve.point_mul(int(1/ec.modp(curve.n, s)[0]), curve.point_add(p1, p2))
        assert Rabs == self.X  # up to a sign
        other_sig = (r, curve.n-s)
        ecdsa.verify(curve, H, self.Q, msg, other_sig)
        
        # XXX: flip this coin properly
        coin = (self.v + sum_dictelem(self.their_openings, 'v')) % 2

        if coin: chosen = sig
        else: chosen = other_sig

        ecdsa.verify(curve, H, self.Q, msg, chosen)
        return chosen


def test_correctness(number_firewalls=4):
    k, Q = curve.generate_key()
    signer = Signer(k, number_firewalls)

    f = []
    comms = []
    for i in range(number_firewalls):
        f.append(Firewall(Q, number_firewalls, i))
        comms.append(f[i].prepare_commitment())
        
    for i in range(number_firewalls):
        signer.recv_commitment(comms[i], i)
        for j in range(number_firewalls):
            if i==j: continue
            f[j].recv_commitment(comms[i], i)

    # missing check here on every state machine:
    # continue only commitments have been received

    openings = []
    for i in range(number_firewalls):
        openings.append(f[i].open_commitment())
    
    for i in range(number_firewalls):
        signer.recv_opening(openings[i], i)
        for j in range(number_firewalls):
            if i==j: continue
            f[i].recv_opening(openings[j], j)
    
    nonce_share = signer.generate_nonceshare()     

    for i in range(number_firewalls):
        f[i].compute_pubnonce(nonce_share)
    signer.compute_privnonce()

    # missing proper msg construction
    # (probably want to include pk)
    msg = 'hello world ' + str(rand.randrange(0, 2**64))
    print "msg: ", msg

    presig = signer.sign(msg)
    
    fw_signatures = []
    for i in range(number_firewalls):
        fw_signatures.append(f[i].sanitize(presig, msg))

    assert(len(set(fw_signatures)) == 1) # check all signatures are identical
    print "sig: ", fw_signatures[0]


if __name__ == "__main__":
    while True:
        test_correctness()
        print "OK"
