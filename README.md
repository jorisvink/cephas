# Cephas

Cephas is a way of distributing KEKs over unauthenticated links once
both peers are joined in the same flock over reliquary.

It uses the reliquary infrastructure to establish a p2p e2ee
tunnel over which the secret is then sent.

For this it derives a secret from a long passphrase (20 words,
selected at random) which is used as the shared secret in the
sanctum tunnel establishment.

## Passphrases

The passphrases consist of 20 words selected at random from a word
list of 7776 words. This means each word is worth about 12.92 bits of entropy.

## KEK security

When using cephas your KEKs their security depends on the ECDH+ML-KEM
exchange and the random passphrase you should only ever give to your peer.

**The best way to distribute KEKs is still in physical form.**

Using cephas however beats simply scp'ing them over or doing other
clever tricks to try and get them to your peer.
