# Encrypted vCon fixtures

`tests/vcon_encrypt_test.rs` reads these files. Every private key here is a
published test key. None of them protects anything.

| File | Source | SHA-256 |
|------|--------|---------|
| `ab_call_ext_rec_encrypted.vcon` | `examples/ab_call_ext_rec_encrypted.vcon` in [ietf-wg-vcon/draft-ietf-vcon-vcon-core](https://github.com/ietf-wg-vcon/draft-ietf-vcon-vcon-core), commit `c9ee897319ce8d9cc85beab1ca217b557d25da19`. Appendix A.7 of draft-ietf-vcon-vcon-core-04 prints it | `9e0a85404e7cfad359e811f7af4b841774c5143871d77e54202fdadecf92ffcb` |
| `fake_grp.key` | `certs/fake_grp.key` in [vcon-dev/vcon](https://github.com/vcon-dev/vcon), commit `e7f5d6d8721b44b641e40255f92462328705313c`, the key Appendix A.7 names for decrypting the example. Later commits removed the file | `e29acf9ae3490a8054875b7107c8f05ff5455d091c8f735e7f25fdc9bb38ee91` |
| `fake_grp.crt` | `certs/fake_grp.crt`, same commit. The certificate the example's signature carries first in `x5c`, and the one it was encrypted to | `409743610cc747bd4082e2281c53a6548874ebe7a72be4a3c8cb1bcac897bcd6` |
| `fake_div.crt` | `certs/fake_div.crt`, same commit. The issuer of `fake_grp.crt` | `f1f38d89b741a1576ecc8f78e15fef30bfc7ddaf1e9ca7703ca4d5da85f659db` |
| `fake_ca_root.crt` | `certs/fake_ca_root.crt`, same commit. The issuer of `fake_div.crt` | `e9d37cf9fe7ef5e723089bb2814ec388348f244923b70099f77d100112f6bd23` |
| `LICENSE-vcon-dev` | `LICENSE` of vcon-dev/vcon (MIT) | `bfcb60659598a8dbd104db0f284cd9462f2f4004d97c492f09693479b6f13a94` |
| `other.key`, `other.crt` | Generated for these tests with `openssl req -x509 -newkey rsa:2048 -nodes -days 36500 -subj "/CN=other.invalid"`: a key the example was not encrypted to | `8181fa5e63512bed1835f650fd92bcf1e02507dbd8fbedb1662e45f8875997eb`, `70d574a83891502beb060d04a44811a242ddf013429f6d04a73331b6d536acf3` |

The example was produced by the working group's reference tool, py-vcon, with
`vcon sign` and then `vcon encrypt` (the `Makefile` in the draft's `examples`
directory). It is the one encrypted vCon in the draft, so sipnab decrypting
it and verifying its signature, and producing the same RS256 signature over
the same bytes with the same key, is the interoperability check.
