def test_get_coin_version(cmd):
    a, b, c = cmd.get_firmware_version()

    print(f'{a} {b} {c}')

    (p2pkh_prefix, p2sh_prefix, coin_family, coin_name, coin_ticker) = cmd.get_coin_version()

    # Ravencoin Testnet: (0x6F, 0xC4, 0x01, "Ravencoin", "TRVN")
    # Ravencoin app: (0x3C, 0x7A, 0x01, "Ravencoin", "RVN")
    assert (p2pkh_prefix,
            p2sh_prefix,
            coin_family,
            coin_name,
            coin_ticker) == (0x6F, 0xC4, 0x01, "Raven", "TRVN")
