"""HTB LovelyMalware Example"""

from pathlib import Path

from chopchop import Chopchop

_HTB_LOVELYMALWARE_DIGESTS = (
    0x90AD04A2,
    0x68936BC0,
    # add more digests here
)


def _htb_lovely(data: bytes) -> str:
    value = 0
    for b in data:
        pvshr = (value >> 0x0D) & 0xFFFFFFFF
        pvshl = (value << 0x13) & 0xFFFFFFFF
        pvshc = (pvshr | pvshl) & 0xFFFFFFFF
        it_pv_add = (b + value) & 0xFFFFFFFF
        value = (it_pv_add + pvshc) & 0xFFFFFFFF
    return value.to_bytes(4, byteorder='little').hex()


def main():
    with Chopchop(
        database=Path('chopchop.db'),
        custom_digest=_htb_lovely,
    ) as chopchop:
        if chopchop.rowcount == 0:
            chopchop.populate(
                Path('C:\\Windows\\System32'),
                {
                    'ntdll.dll',
                    'user32.dll',
                    'ws2_32.dll',
                    'crypt32.dll',
                    'shlwapi.dll',
                    'kernel32.dll',
                },
            )
        for digest in _HTB_LOVELYMALWARE_DIGESTS:
            for name in chopchop.search_digest(digest):
                print(f"{digest} {name}")


if __name__ == '__main__':
    main()
