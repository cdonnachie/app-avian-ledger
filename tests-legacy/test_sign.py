from hashlib import sha256
import json
from pathlib import Path
from typing import Tuple, List, Dict, Any
import pytest

from ecdsa.curves import SECP256k1
from ecdsa.keys import VerifyingKey
from ecdsa.util import sigdecode_der

from bitcoin_client.hwi.serialization import CTransaction
from bitcoin_client.exception import ConditionOfUseNotSatisfiedError
from utils import automation


def sign_from_json(cmd, filepath: Path):

    BTCHIP_CLA = 0xe0
    BTCHIP_INS_GET_TRUSTED_INPUT = 0x42

    def write_varint(i):
        assert i >= 0, i
        if i<0xfd:
            return i.to_bytes(1, 'big')
        elif i<=0xffff:
            return "fd"+i.to_bytes(2, 'big')
        elif i<=0xffffffff:
            return "fe"+i.to_bytes(4, 'big')
        else:
            return "ff"+i.to_bytes(8, 'big')

    def getTrustedInput(transaction: CTransaction, index):
        result = {}
        # Header
        apdu = [BTCHIP_CLA, BTCHIP_INS_GET_TRUSTED_INPUT, 0x00, 0x00]
        params = bytearray.fromhex("%.8x" % index)
        params.extend(transaction.nVersion.to_bytes(4, 'little'))
        params.extend(write_varint(len(transaction.vin)))
        apdu.append(len(params))
        apdu.extend(params)
        cmd.transport.send_raw(bytearray(apdu))
        sw, response = cmd.transport.recv()

        # Each input

        for vin in transaction.vin:

            apdu = [BTCHIP_CLA, BTCHIP_INS_GET_TRUSTED_INPUT, 0x80, 0x00]
            params = bytearray(vin.prevout.serialize())
            params.extend(write_varint(len(vin.scriptSig)))
            apdu.append(len(params))
            apdu.extend(params)
            cmd.transport.send_raw(bytearray(apdu))
            sw, response = cmd.transport.recv()

            offset = 0
            while True:
                blockLength = 251
                if ((offset + blockLength) < len(vin.scriptSig)):
                    dataLength = blockLength
                else:
                    dataLength = len(vin.scriptSig) - offset
                params = bytearray(vin.scriptSig[offset: offset + dataLength])
                if ((offset + dataLength) == len(vin.scriptSig)):
                    params.extend(vin.nSequence.to_bytes(4, 'little'))
                apdu = [BTCHIP_CLA, BTCHIP_INS_GET_TRUSTED_INPUT, 0x80, 0x00, len(params)]
                apdu.extend(params)
                cmd.transport.send_raw(bytearray(apdu))
                sw, response = cmd.transport.recv()

                offset += dataLength
                if (offset >= len(vin.scriptSig)):
                    break

        # Number of outputs
        apdu = [BTCHIP_CLA, BTCHIP_INS_GET_TRUSTED_INPUT, 0x80, 0x00]
        params = bytearray(write_varint(len(transaction.vout)))
        apdu.append(len(params))
        apdu.extend(params)
        cmd.transport.send_raw(bytearray(apdu))
        sw, response = cmd.transport.recv()

        # Each output
        indexOutput = 0
        for vout in transaction.vout:
            
            apdu = [BTCHIP_CLA, BTCHIP_INS_GET_TRUSTED_INPUT, 0x80, 0x00]
            params = bytearray(vout.nValue.to_bytes(8, 'little'))
            params.extend(write_varint(len(vout.scriptPubKey)))
            apdu.append(len(params))
            apdu.extend(params)
            cmd.transport.send_raw(bytearray(apdu))
            sw, response = cmd.transport.recv()

            offset = 0
            while (offset < len(vout.scriptPubKey)):
                blockLength = 255
                if ((offset + blockLength) < len(vout.scriptPubKey)):
                    dataLength = blockLength
                else:
                    dataLength = len(vout.scriptPubKey) - offset
                apdu = [BTCHIP_CLA, BTCHIP_INS_GET_TRUSTED_INPUT, 0x80, 0x00, dataLength]
                apdu.extend(vout.scriptPubKey[offset: offset + dataLength])
                cmd.transport.send_raw(bytearray(apdu))
                sw, response = cmd.transport.recv()
                offset += dataLength

        # Locktime
        apdu = [BTCHIP_CLA, BTCHIP_INS_GET_TRUSTED_INPUT, 0x80, 0x00, 4]
        apdu.extend(transaction.nLockTime.to_bytes(4, 'little'))
        sw = cmd.transport.send_raw(bytearray(apdu))
        print(sw)
        sw, response = cmd.transport.recv()
        print(sw, response)
        result['trustedInput'] = True
        result['value'] = response
        return result


    tx_dct: Dict[str, Any] = json.load(open(filepath, "r"))

    raw_utxos: List[Tuple[bytes, int]] = [
        (bytes.fromhex(utxo_dct["raw"]), output_index)
        for utxo_dct in tx_dct["utxos"]
        for output_index in utxo_dct["output_indexes"]
    ]

    #for utxo, i in raw_utxos:
    #    tx = CTransaction.from_bytes(utxo)
    #    trustedInput = getTrustedInput(tx, i)

    to_address: str = tx_dct["to"]
    to_amount: int = tx_dct["amount"]
    fees: int = tx_dct["fees"]

    
    sigs = cmd.sign_new_tx(address=to_address,
                           amount=to_amount,
                           fees=fees,
                           change_path=tx_dct["change_path"],
                           sign_paths=tx_dct["sign_paths"],
                           raw_utxos=raw_utxos,
                           lock_time=tx_dct["lock_time"])

    expected_tx = CTransaction.from_bytes(bytes.fromhex(tx_dct["raw"]))
    
    expected_sigs = {vin.prevout: vin.scriptSig.hex() for vin in expected_tx.vin}

    for (tx_hash_digest, sign_pub_key, (v, der_sig)) in sigs:
        pk: VerifyingKey = VerifyingKey.from_string(
            sign_pub_key,
            curve=SECP256k1,
            hashfunc=sha256
        )
        assert pk.verify_digest(signature=der_sig[:-1],  # remove sighash
                                digest=tx_hash_digest,
                                sigdecode=sigdecode_der) is True

    
#def test_untrusted_hash_sign_fail_nonzero_p1_p2(cmd, transport):
    # payloads do not matter, should check and fail before checking it (but non-empty is required)
#    sw, _ = transport.exchange(0xE0, 0x48, 0x01, 0x01, None, b"\x00")
#    assert sw == 0x6B00, "should fail with p1 and p2 both non-zero"
#    sw, _ = transport.exchange(0xE0, 0x48, 0x01, 0x00, None, b"\x00")
#    assert sw == 0x6B00, "should fail with non-zero p1"
#    sw, _ = transport.exchange(0xE0, 0x48, 0x00, 0x01, None, b"\x00")
#    assert sw == 0x6B00, "should fail with non-zero p2"


#def test_untrusted_hash_sign_fail_short_payload(cmd, transport):
    # should fail if the payload is less than 7 bytes
#    sw, _ = transport.exchange(0xE0, 0x48, 0x00, 0x00, None, b"\x01\x02\x03\x04\x05\x06")
#    assert sw == 0x6700


#@automation("automations/accept.json")
#def test_sign_p2wpkh_accept(cmd):
#    for filepath in Path("data").rglob("p2wpkh/tx.json"):
#        sign_from_json(cmd, filepath)


#@automation("automations/accept.json")
#def test_sign_p2sh_p2wpkh_accept(cmd):
#    for filepath in Path("data").rglob("p2sh-p2wpkh/tx.json"):
#        sign_from_json(cmd, filepath)


#@automation("automations/accept.json")
def test_sign_p2pkh_accept(cmd):
    #for filepath in Path("data").rglob("p2pkh/tx.json"):
    #    sign_from_json(cmd, filepath)
    sign_from_json(cmd, "./data/assets/one-to-one/p2pkh/tx.json")

#@automation("automations/reject.json")
#def test_sign_fail_p2pkh_reject(cmd):
#    with pytest.raises(ConditionOfUseNotSatisfiedError):
#        sign_from_json(cmd, "./data/one-to-one/p2pkh/tx.json")