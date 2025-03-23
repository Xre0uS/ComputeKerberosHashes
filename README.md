## ComputeKerberosHashes

This tool computes Kerberos hashes from a given password.

I did not write the code here, it is taken from the ![Rubeus](https://github.com/GhostPack/Rubeus) project.

The hash function from Rubeus is useful for various Kerberos attacks, since there are no similar tools and Rubeus is considered a malware, I have taken code from the hash function to make a standalone tool.

```
ComputeKerberosHashes.exe /user:testuser /password:P@ssw0rd /domain:domain.local

[*] Action: Calculate Password Hash(es)

[*] Input password             : P@ssw0rd
[*] Input username             : testuser
[*] Input domain               : domain.local
[*] Salt                       : DOMAIN.LOCALtestuser
[*]       rc4_hmac             : E19CCF75EE54E06B06A5907AF13CEF42
[*]       aes128_cts_hmac_sha1 : 160B8DFFB36FD8549A3B0CC14D8A48E3
[*]       aes256_cts_hmac_sha1 : 79064F21A1208BB377CC5D74BBCE6F515D4E0406A25CCD773BC67D54FE9AE9A3
[*]       des_cbc_md5          : DAAE29323829852F
```
```
Rubeus.exe hash /user:testuser /password:P@ssw0rd /domain:domain.local

   ______        _
  (_____ \      | |
   _____) )_   _| |__  _____ _   _  ___
  |  __  /| | | |  _ \| ___ | | | |/___)
  | |  \ \| |_| | |_) ) ____| |_| |___ |
  |_|   |_|____/|____/|_____)____/(___/

  v2.2.0


[*] Action: Calculate Password Hash(es)

[*] Input password             : P@ssw0rd
[*] Input username             : testuser
[*] Input domain               : domain.local
[*] Salt                       : DOMAIN.LOCALtestuser
[*]       rc4_hmac             : E19CCF75EE54E06B06A5907AF13CEF42
[*]       aes128_cts_hmac_sha1 : 160B8DFFB36FD8549A3B0CC14D8A48E3
[*]       aes256_cts_hmac_sha1 : 79064F21A1208BB377CC5D74BBCE6F515D4E0406A25CCD773BC67D54FE9AE9A3
[*]       des_cbc_md5          : DAAE29323829852F
```
