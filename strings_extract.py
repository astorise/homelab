from pathlib import Path
binary = Path(r'c:/Users/astor/Git/homelab/target/release/home-dns.exe').read_bytes()
needle = b'build tag='
pos = binary.find(needle)
if pos != -1:
    print(binary[pos:pos+80])
else:
    print('not found')
