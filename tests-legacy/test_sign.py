from hashlib import sha256
import json
from pathlib import Path
from typing import Tuple, List, Dict, Any
import pytest
from io import BytesIO

from ecdsa.curves import SECP256k1
from ecdsa.keys import VerifyingKey
from ecdsa.util import sigdecode_der

from bitcoin_client.hwi.serialization import CTransaction, CTxInWitness, deser_ops, deser_string_vector
from bitcoin_client.exception import ConditionOfUseNotSatisfiedError
from utils import has_automation


def sign_from_json(cmd, filepath: Path):
    tx_dct: Dict[str, Any] = json.load(open(filepath, "r"))

    raw_utxos: List[Tuple[bytes, int]] = [
        (bytes.fromhex(utxo_dct["raw"]), output_index)
        for utxo_dct in tx_dct["utxos"]
        for output_index in utxo_dct["output_indexes"]
    ]
    to_address: str = tx_dct["to"]
    to_amount: int = tx_dct["amount"]
    fees: int = tx_dct["fees"]

    use_raw = tx_dct.get('use_raw', False)

    sigs = cmd.sign_new_tx(address=to_address,
                           amount=to_amount,
                           fees=fees,
                           change_path=tx_dct["change_path"],
                           sign_paths=tx_dct["sign_paths"],
                           raw_utxos=raw_utxos,
                           lock_time=tx_dct["lock_time"],
                           override_transaction=bytes.fromhex(tx_dct["raw"]) if use_raw else None
                           )

    expected_tx = CTransaction.from_bytes(bytes.fromhex(tx_dct["raw"]))

    def convertVinSigToWitness(vin):
        signature_raw = vin.scriptSig
        l = deser_string_vector(BytesIO(b'\x02' + signature_raw))
        wit = CTxInWitness()
        wit.scriptWitness.stack.append(l[0][:-1])
        wit.scriptWitness.stack.append(l[1])
        return wit

    witnesses = expected_tx.wit.vtxinwit
    # or map(convertVinSigToWitness, expected_tx.vin)
    # doesn't look like the original tests check for this, so i won't either

    for witness, (tx_hash_digest, sign_pub_key, (v, der_sig)) in zip(witnesses, sigs):
        expected_der_sig, expected_pubkey = witness.scriptWitness.stack
        assert expected_pubkey == sign_pub_key
        assert expected_der_sig == der_sig
        pk: VerifyingKey = VerifyingKey.from_string(
            sign_pub_key,
            curve=SECP256k1,
            hashfunc=sha256
        )
        assert pk.verify_digest(signature=der_sig[:-1],  # remove sighash
                                digest=tx_hash_digest,
                                sigdecode=sigdecode_der) is True

def test_untrusted_hash_sign_fail_nonzero_p1_p2(cmd, transport):
    # payloads do not matter, should check and fail before checking it (but non-empty is required)
    sw, _ = transport.exchange(0xE0, 0x48, 0x01, 0x01, None, b"\x00")
    assert sw == 0x6B00, "should fail with p1 and p2 both non-zero"
    sw, _ = transport.exchange(0xE0, 0x48, 0x01, 0x00, None, b"\x00")
    assert sw == 0x6B00, "should fail with non-zero p1"
    sw, _ = transport.exchange(0xE0, 0x48, 0x00, 0x01, None, b"\x00")
    assert sw == 0x6B00, "should fail with non-zero p2"


def test_untrusted_hash_sign_fail_short_payload(cmd, transport):
    # should fail if the payload is less than 7 bytes
    sw, _ = transport.exchange(0xE0, 0x48, 0x00, 0x00, None, b"\x01\x02\x03\x04\x05\x06")
    assert sw == 0x6700

# AVN Does not support segwit, though this logic does not change from BTC
'''
@has_automation("automations/accept.json")
def test_sign_p2wpkh_accept(cmd):
    for filepath in Path("data").rglob("p2wpkh/tx.json"):
        sign_from_json(cmd, filepath)


@has_automation("automations/accept.json")
def test_sign_p2sh_p2wpkh_accept(cmd):
    for filepath in Path("data").rglob("p2sh-p2wpkh/tx.json"):
        sign_from_json(cmd, filepath)
'''

@has_automation("automations/accept.json")
def test_sign_p2pkh_accept(cmd):
    for filepath in Path("data").rglob("p2pkh/tx.json"):
        print(filepath)
        sign_from_json(cmd, filepath)

@has_automation("automations/reject.json")
def test_sign_fail_p2pkh_reject(cmd):
    with pytest.raises(ConditionOfUseNotSatisfiedError):
        sign_from_json(cmd, "./data/one-to-one/p2pkh/tx.json")

@has_automation("automations/accept.json")
def test_sign_avian_create(cmd):
    sign_from_json(cmd, 'data/avian/create/tx.json')

@has_automation("automations/accept.json")
def test_sign_avian_reissue(cmd):
    sign_from_json(cmd, 'data/avian/reissue/tx.json')

@has_automation("automations/accept.json")
def test_sign_avian_tag_qual(cmd):
    sign_from_json(cmd, 'data/avian/qualify_address/tx.json')

@has_automation("automations/accept.json")
def test_sign_avian_restricted(cmd):
    sign_from_json(cmd, 'data/avian/reissue_restricted/tx.json')

@has_automation("automations/accept.json")
def test_sign_avian_global_freeze(cmd):
    sign_from_json(cmd, 'data/avian/global_freeze/tx.json')
