# Chopchop

Chopchop aims at building API digests databases to accelerate reverse engineering of malwares using this technique.

Chopchop implements commonly found digest algorithms like MD5, SHA1 and CRC-32 and **allows customization with an algorithm of your choice**.

Chopchop can be used on Linux on Windows.

Chopchop could be used to build plugins for reverse engineering software such as Ghidra.

Chopchop can be used in combination with [HashDB](https://github.com/OALabs/HashDB) and **extends automation capabilities** using [LIEF](https://github.com/lief-project/LIEF) to parse PE and ELF files found in the system to populate the hash database.

```bash
# example of database creation on windows
chopchop populate 'C:\Windows\System32\' '*32.dll'
# example of database creation on linux
chopchop populate /usr 'libc.so*'
```

Chopchop allows to display database rowcount.

```bash
# example of rowcount query
chopchop rowcount
```

Chopchop allows to search for digests as hex (use little endian).

```bash
# example of digest search
chopchop search digest 93fcf5a0 bc98338e
```
```text
93fcf5a0 WSAStartup
bc98338e WSACleanup
```

Chopchop allows to search for digests as dword and qword as well.

```bash
# example of digest search
chopchop search digest 0xa0f5fc93 0x8e3398bc
```
```text
0xa0f5fc93 WSAStartup
0x8e3398bc WSACleanup
```

Chopchop allows to search for names too.

```bash
# example of exact name search
chopchop search name WSAStartup WSACleanup
```
```text
3348c912c6675c8f2529d02074ab351c dbd033c09ea20026948ae0fda0b88a61a2592db0 93fcf5a0 None WSAStartup
69fb9edb7e9516765f7522eb63cd6f5f 5938b1a77a4e193c3eb1ab7e9e0a8255e14eb622 bc98338e None WSACleanup
```

Chopchop also allow name patterns using SQL LIKE syntax.

```bash
# example of name pattern search
chopchop search name '%FileA'
```
```text
58aa70d53ced396e83e6bdb20da12249 121caa0785234479b2e4b27ab3c1349498534d95 99dc9901 None CopyFileA
271478687275d462fb895d72b3cddba2 c5d4401e8135bcd66a0bcc067ddcf202bf40043f 785c3b55 None CreateFileA
b80c10990f0b1f673a48866de5a1c649 5cf8a5588fc4db4c34dbd4282ff950c033f4308a cb6b9b91 None DeleteFileA
1a5dbe95bb7a8c390120b6d071dd80a2 89e7c89d4fd769ade16936658e17f4e23d548bd4 ced5ebc9 None FindFirstFileA
dec3c82dcd28797815e7ac6eb4be01b8 b7b7ff8839351f7bf1d945c9c21ebb950e5fd8f6 48292775 None FindNextFileA
bb9ef5e02f2b95ca746f937ecd8b614d 5ede90aa390c0603671a454189f01d6648e1c51b abb5e996 None LZOpenFileA
f9ac08d03c65ba530f25224288b80886 1e442c52fe508175350b3c7f79f63b66768da51f d1f09fde None MoveFileA
937d49b4de577d8fba3761d69a067e67 b6450b54cc49152a036dc8893dcc926eb6033d8c da6e2ff1 None ReplaceFileA
936473ee205b0519befa5f9a98d3a1f3 6d20ecfc18b64127b9959409884b3bca3e715d77 c1608031 None LoadCursorFromFileA
c6dccbb652142c798c61d3ff895b1cb0 a68d81af77910dcb887ffccb3c0d8c3b6aa56416 414524d0 None SHCreateStreamOnFileA
```
