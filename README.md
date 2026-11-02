# Cephas

Cephas is a way of distributing KEKs over unauthenticated links once
both peers are joined in the same flock over reliquary.

It is ment to be used with <a href="https://reliquary.se">The Reliquary</a>
only.

It uses that infrastructure to establish a p2p e2ee tunnel over
which the secret is then sent.

For this it derives a secret from a long passphrase (20 words,
selected at random) which is used as the shared secret in the
sanctum tunnel establishment.

## Passphrases

The passphrases consist of 20 words selected at random from a word
list of 7776 words. This means each word is worth about 12.92 bits of entropy.

## Covenant

The Covenant app can be used to remote provision via cephas and hand over
a KEK. Covenant provides 33 words instead of the 20. The 13 extra words
are routing information on how to reach the remote provisioning node.

Running against a Covenant app provisioner means you only need to
supply your local relevant information:

```
$ cephas -l <cs id> -o cosk-<cs id> -s id-<cs id> recv kek-0x<kek id>
```

When a KEK arrives cephas acks it with its SHA3-256 digest, the sender
only takes a matching digest as done.

## KEK security

When using cephas your KEKs their security depends on the ECDH+ML-KEM
exchange and the random passphrase you should only ever give to your peer.

**The best way to distribute KEKs is still in physical form.**

Using cephas however beats simply scp'ing them over or doing other
clever tricks to try and get them to your peer.
