# Demo session (copy-paste)

Assumes editable installs of cryptolab-kit and cryptolab-suite (see README).

```bash
suite kit-check

# EDUCATIONAL Shamir (GF(256))
suite share-split --secret 'lab-demo-secret' -n 5 -k 3 --out /tmp/shares
suite share-combine /tmp/shares/share-01.txt /tmp/shares/share-03.txt /tmp/shares/share-05.txt

# Merkle
printf 'alpha\nbeta\ngamma\ndelta\n' > /tmp/leaves.txt
suite merkle-build --leaves /tmp/leaves.txt --out /tmp/tree.json
suite merkle-prove --tree /tmp/tree.json --index 1 --out /tmp/proof.json
suite merkle-verify --proof /tmp/proof.json --leaf <(printf 'beta')

# X.509 lab CA
suite cert-ca --cn 'Demo CA' --key-type ec --out /tmp/demo-ca
suite cert-issue --ca-cert /tmp/demo-ca/ca.crt --ca-key /tmp/demo-ca/ca.key \
  --cn app.demo.test --san app.demo.test --san localhost --out /tmp/demo-leaf
suite cert-show --cert /tmp/demo-leaf/leaf.crt

# Vault
suite vault-init --path /tmp/demo.vault --passphrase 'demo-only'
suite vault-set --path /tmp/demo.vault --passphrase 'demo-only' --name token --value 'abc'
suite vault-list --path /tmp/demo.vault --passphrase 'demo-only'
suite vault-get --path /tmp/demo.vault --passphrase 'demo-only' --name token

# Streaming
suite stream-encrypt --src README.md --dest /tmp/readme.strm --key-out /tmp/stream.key
suite stream-decrypt --src /tmp/readme.strm --dest /tmp/readme.out --key-file /tmp/stream.key

# Handshake + challenges + bench
suite handshake-demo
suite challenge list
suite challenge solve chal-01 --answer 'CRYPTOGRAPHY IS FUN'
suite bench
```

Measured bench sample: [bench_sample.txt](bench_sample.txt).
