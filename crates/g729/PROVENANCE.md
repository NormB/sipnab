# Provenance of the G.729 clean-room data

## Oracle

Date: 2026-10-14.

In this clean-room process, only the oracle role read the ITU-T G.729 reference C code: the ITU-T G.729 (06/2012) software package, Release 3, Annex A decoder and Annex A+B decoder. The oracle wrote no decoder code. Its only code is oracle-side tooling, which stays in the oracle working directory and is not shared with the implementer. That tooling consists of: scripts that extract and check the tables; a small program that prints the compiled reference tables; and value-capture hooks inserted into a private copy of the reference decoders to produce the traces.

### Package

- Source URL: `https://www.itu.int/rec/dologin_pub.asp?lang=e&id=T-REC-G.729-201206-I!!SOFT-ZST-E&type=items`
- Size: 18476968 bytes
- sha256: `979680ff3b52b13a5701453178efd32b53e340114638fd330fdb6669eec86620`
- Clause numbers in the extracted data were checked against the Recommendation text, ITU-T G.729 (06/2012) e-book edition (`T-REC-G.729-201206-I!!EPB-E`, sha256 `60d6896ce0106f9535f7f441cc0bd0a3585843caa9e7274d76d938626d761e3f`).

### Files read

The oracle read these files, in full or in part. Paths are relative to `Software/G729_Release3/` in the package.

| File | sha256 |
|---|---|
| `../readme_G729Release3.doc` (package readme, text extracted) | `b62e57d3086b16cca872346369a4519529f4cc3dcba4c7f057ae0faef0157f31` |
| `g729AnnexA/c_code/README.TXT` | `d265bf8e3745da3b3189d3efcac5c63fab982a1e51b1a7cb2eb9b66a72f2a036` |
| `g729AnnexA/c_code/DECODER.MAK` | `d8ec0e13ad42fba1eb051775261420252a49f73fd354b7fdd5826d606b7fa4d2` |
| `g729AnnexA/c_code/TYPEDEF.H` | `c7d1f81ec24666ac619e465e7eeee44cd372f00d5daa4217b1f6f28a1e018294` |
| `g729AnnexA/c_code/LD8A.H` | `e53cb6066d554792260ad7b19756e01dda035a0ca1dd266c23d25a199e8ca43c` |
| `g729AnnexA/c_code/TAB_LD8A.H` | `88610e2da06b51b5201860350329a973027c4077fb25567b83332fcc7f40f9de` |
| `g729AnnexA/c_code/TAB_LD8A.C` | `deefd5e1b7d02d6994cdbc65491d9eafe40fe52e5291eaaf26848cd2132fe5a1` |
| `g729AnnexA/c_code/BASIC_OP.H` | `2a9b712a1190ac977818bbbb095d81af9b06e65b6160737c567e16aaabfd8293` |
| `g729AnnexA/c_code/BASIC_OP.C` | `e185708d080fd55a91da195354550d0cedf6f0123352965b5d76c112bac1b42c` |
| `g729AnnexA/c_code/OPER_32B.H` | `934e758abe3633c0b5067b22ec5b328828c242c7e2dae8a73e5e34256f90879d` |
| `g729AnnexA/c_code/OPER_32B.C` | `801e6db2b0b869bbe27f0a88479c68913022529ec46fae5060a84e58afe1eaf9` |
| `g729AnnexA/c_code/DECODER.C` | `0bf6bf0d34069faf851c1c8178759584f8982f746268708764042c55a2098617` |
| `g729AnnexA/c_code/BITS.C` | `36aec3f68e53b07cb7ebc7a5d62f91c6fa7fe7096ce7f53689ce68a6e4df13f2` |
| `g729AnnexA/c_code/DEC_LD8A.C` | `981d1047fb350b46f391bc1585df50cd4f7c3da216e9789efcbaf303eb594f5c` |
| `g729AnnexA/c_code/LSPDEC.C` | `6d0580cd282aee4e99082a89b7fcb3a075f8500e6d54be7b1aae34df32c7f859` |
| `g729AnnexA/c_code/LSPGETQ.C` | `0523193b1876069f262c9ddddbd47ba3718b13f74652094a42167d49fdaaacab` |
| `g729AnnexA/c_code/LPCFUNC.C` | `e87de93a75c715507bd26c5a6cc76a6a06efd6149e34fd422c382ae1911fe80d` |
| `g729AnnexA/c_code/DEC_GAIN.C` | `07fb8695db5d46e76af9cf6e8c23faa5c3ca26bff202ba36db806b6e8fb2932c` |
| `g729AnnexA/c_code/GAINPRED.C` | `c9f9a64d895a2212f4b59adda2db6063d54bea766671df32b53960da60d2a426` |
| `g729AnnexA/c_code/DE_ACELP.C` | `1e517c5cf1fb3cb6ea9330edd911482f7fe146dfa5d72da9a781ec35e3664f5d` |
| `g729AnnexA/c_code/DEC_LAG3.C` | `a87d4537d46e5da931a58ae115a66fea3493b946858994035cf4c739bb2fd653` |
| `g729AnnexA/c_code/PRED_LT3.C` | `d6e2aca0f5b699e3abe293e959f40f3f5132693f6e492ada6a8e82b8026c6143` |
| `g729AnnexA/c_code/P_PARITY.C` | `2a34177565aa997c364073d1c74d641941d372e9acff5c59cd433029d628b5ce` |
| `g729AnnexA/c_code/FILTER.C` | `2cc25e53d6e2b659c2cd3de2b4f7c212b354770ca7dfbce08b42e8876b8b14f9` |
| `g729AnnexA/c_code/POSTFILT.C` | `5cb46384777ddac5764684790f4578632eabcf0085c5094750b635fa179cd614` |
| `g729AnnexA/c_code/POST_PRO.C` | `759deaa585be96584ad10a5d1484093b8c21483234eb13a660906e257330cb91` |
| `g729AnnexA/c_code/DSPFUNC.C` | `bc66cfeb9c3f279f465dd36d08bed4b6314f6c3d4f694df6bb10c62aa283334f` |
| `g729AnnexA/c_code/UTIL.C` | `8f0bd79ab8807ad1d5b350c0ec3a1cf9423dcf7abc4a74d5a9e165d591564fc5` |
| `g729AnnexA/test_vectors/READMETV.txt` | `a502368ff011a51096856b05c7e1d7ccad5204d4fe8958c012ea4e88fda5d54e` |
| `g729AnnexA/test_vectors/TEST.BAT` | `325fc498d399b617168ce173e0b27d3a7c5615f0cbf221dcce7f58b93168520f` |
| `g729AnnexB/c_codeBA/readme.txt` | `03a5cb996b8c4ff9603e1a867b2352e15a107cbed1548e65bfe71f494970e5e6` |
| `g729AnnexB/c_codeBA/decoder.mak` | `88d9aaea3008ba33bee36ae1c1a32c1310b207c1bf075b8e95002d13f6e9538b` |
| `g729AnnexB/c_codeBA/typedef.h` | `c74e4ac21b28e344b202047d452e5fcd5da535b407d30169e7608a3551fb3ae4` |
| `g729AnnexB/c_codeBA/ld8a.h` | `b56234b0890b2d3ee59cfc09b7b9def0cb0cb1eab926566fb81b6a249ad62293` |
| `g729AnnexB/c_codeBA/tab_ld8a.h` | `e9f5d2496d27805e2f90e1bcfd12f0a3f702b35cb6e3d7c494239d75dc4b98f3` |
| `g729AnnexB/c_codeBA/tab_ld8a.c` | `d2e9271cd7e1931fe1fabe3029881f6fbf83576e9360c9b2bd6a2fffdd9e6226` |
| `g729AnnexB/c_codeBA/basic_op.h` | `fd082320505ef2676f149969a26b31cfe6f2ad9e995a4c59da3713f1b1b2e357` |
| `g729AnnexB/c_codeBA/basic_op.c` | `a56ccc0d20fcd682dea61bb5f983d6367d31d569b7fb4aa5812331e0d45b499c` |
| `g729AnnexB/c_codeBA/oper_32b.h` | `611acff807969bc96d434f3163962b2c3e5e69167b2c4af61d85e3fb6c7e317f` |
| `g729AnnexB/c_codeBA/oper_32b.c` | `e1439ad552ca5ad6586a17a402d4347da8723aa502b897fbfb306f9edac1e968` |
| `g729AnnexB/c_codeBA/decoder.c` | `b1ce51cac31d61677c0b8b08f7357e09809c3091adf1189e616df0d17b50f4e9` |
| `g729AnnexB/c_codeBA/bits.c` | `5b701960c3749a624775c34d98c155da432aaeda30e59ef88a6e027031bd07bd` |
| `g729AnnexB/c_codeBA/dec_ld8a.c` | `1c89bc67947af3cdb575a6fc7be533796204094550cf9d657084dbb5436bfab9` |
| `g729AnnexB/c_codeBA/lspdec.c` | `ddcff2d84dcc99f9313afa1bfee07306fd1698f4559279d162fcb0cfac632480` |
| `g729AnnexB/c_codeBA/lspgetq.c` | `43cf17c126575d2eaa76988ecf4a25b2691496035a570b5f42091bee7c7cac8a` |
| `g729AnnexB/c_codeBA/lpcfunc.c` | `603c74ea94c75abe8aeb36e11e061eee50410177585449e1d0d2cab0aa2da976` |
| `g729AnnexB/c_codeBA/dec_gain.c` | `7600929737b8f1f554e76fcaeac834c5ffe3498a2cd3af9e5afcedb57dac294f` |
| `g729AnnexB/c_codeBA/gainpred.c` | `fffa2723c330afc8e4116b5e1ac8b817c404b83717cadd386666ff103d7edd01` |
| `g729AnnexB/c_codeBA/de_acelp.c` | `7377b5610d59722cc938483157ad5c8bbe3d18e9cde2196f48a22b4d169972d0` |
| `g729AnnexB/c_codeBA/dec_lag3.c` | `023ff744c022dfe217066e5fefe9d7ecf260705f352ebcc0be5c6d2287003629` |
| `g729AnnexB/c_codeBA/pred_lt3.c` | `7e3d5e0b08e54c1cc82e790082494aa821eaee45dc10abe5cec5d008fb584b3b` |
| `g729AnnexB/c_codeBA/p_parity.c` | `2fad17d05d077202a49ae196167f8c4499f7c429cf2de321a69672e3b63a91c8` |
| `g729AnnexB/c_codeBA/filter.c` | `dd5ebedc2f68315089096e23b3b2eb37bae4ce5d485e73958e70e638ff461834` |
| `g729AnnexB/c_codeBA/postfilt.c` | `83a48bb5c3d1074e957679b0e187ddf90300ab637570b1aad7f5f9dcd29f6f34` |
| `g729AnnexB/c_codeBA/post_pro.c` | `de5887e2fa7d48abc6efdc3291ad27867aec9d8fd5eadafdc572af12f9f5df6b` |
| `g729AnnexB/c_codeBA/dspfunc.c` | `4b03c431fa419105a7006d4eebf14a95fa8df2d975bb3968a897d45f3a6f83c2` |
| `g729AnnexB/c_codeBA/util.c` | `6801ee21f0d77f141fdc59cad66b541ed43bcd16eb090d442f94dfc100ef64cc` |
| `g729AnnexB/c_codeBA/dtx.h` | `1abf6fd06e46e1d25e55b39dce27d3704b711d563f9f618a3c3287706116d352` |
| `g729AnnexB/c_codeBA/octet.h` | `813afebb43e88174e1c6a9669136d8782f804b3867b9e6fb5251ba0a7f865941` |
| `g729AnnexB/c_codeBA/sid.h` | `fd7d41652e9a1b0542379d9e3aa3e137a419813cb8d7eb2f9350687c765a623f` |
| `g729AnnexB/c_codeBA/vad.h` | `5fafcf473f967286de9c71bbaea7fbc95bf0f530a5645a519c469d1b967f9e9b` |
| `g729AnnexB/c_codeBA/tab_dtx.h` | `6b620fc325393c543eb84362208a5337eaba45da76338f65a0f6ec88c77e6c8f` |
| `g729AnnexB/c_codeBA/tab_dtx.c` | `165ed446bc179aaad30673aa8390139bdfab13f7ea6e0322285f14d0320ba325` |
| `g729AnnexB/c_codeBA/dec_sid.c` | `951942993deb24afdcd82f7a4265f7072b3b4cf8b768a20b404fe0dd64f11f1d` |
| `g729AnnexB/c_codeBA/qsidgain.c` | `931663dd17a7095233bb9c4e0b3d54bac9ed5c3aa5575bbcfc501494e7909eb7` |
| `g729AnnexB/c_codeBA/calcexc.c` | `997fc1954fadf89a4e6aab181456144f54a0b37d55202d6f39308eef8dbf988d` |
| `g729AnnexB/c_codeBA/taming.c` | `753a9887ff4c50692336e5ff85a74570845b8572bef9a405f8a31c8db50255e0` |
| `g729AnnexB/test_vectors/readmeabTV.txt` | `c8f9de17cfc1bc36b8730114b85022ebf49195a338c9a204f9ddb9cf2c2feae8` |
| `g729AnnexB/test_vectors/test_ab.bat` | `41c48d869b3c86ff167170455824c820b60acdc113f120e0cf3fed85b778f5e9` |

The oracle compiled the following encoder-side files, only to list the symbols they define and reference. It did not read them:

| File | sha256 |
|---|---|
| `g729AnnexA/c_code/ACELP_CA.C` | `6772264d3b5cc344ce0e2693233e1e8da3eea89aa5fe87ccd38ade72237eacf4` |
| `g729AnnexA/c_code/COD_LD8A.C` | `90da71aa246525240e72909665ffb7dbc2c27634ec85cfbb90b3aeba27386a9f` |
| `g729AnnexA/c_code/CODER.C` | `3168c7d91fc045d9d3cd2a3ed88f8e2a57e088c1c66030db4e3da53429f5cb04` |
| `g729AnnexA/c_code/COR_FUNC.C` | `ef762fedac2658883ea205116ef1168614e0ba9105e5e85e9c93d616d8fc7efa` |
| `g729AnnexA/c_code/LPC.C` | `3d633aa3026574c896f0c0b9de3e877723ed6d3fa669a9cbcbf7a8d78ae76057` |
| `g729AnnexA/c_code/PITCH_A.C` | `a8855c2e1a8523bc15e9b08066880cb42a7d0511ccbb5c66504a341c256e30ff` |
| `g729AnnexA/c_code/PRE_PROC.C` | `d85b770e0d4353d909ceb74a5bf6db47790f13ec8901a144347780925793525d` |
| `g729AnnexA/c_code/QUA_GAIN.C` | `1f04087ef92879f2e1262f801a35332d96c9f5f6e9eed65f576161097ec54964` |
| `g729AnnexA/c_code/QUA_LSP.C` | `53199bcdab4138053aa4ed786baf47b38c8ddd1411bb8002a05d7fe13dff3ed5` |
| `g729AnnexA/c_code/TAMING.C` | `5ffb0c134ef4233ab0f533396fb7a577a6195d3cfccd2d9c5c3ace9daf153aae` |
| `g729AnnexB/c_codeBA/acelp_ca.c` | `5f88b7f3d12db00e6e7857744013b65424857e484e0f3d8342fd8504ed732c18` |
| `g729AnnexB/c_codeBA/cod_ld8a.c` | `9b69833ab4244c1f833bb2af78dd18f5e73d9a6c6b712de2ef0abc8295604e05` |
| `g729AnnexB/c_codeBA/coder.c` | `6f0b3af8d6236abc9ff382c22f5da8592586e3b0a25173cc004479cad8b75154` |
| `g729AnnexB/c_codeBA/cor_func.c` | `8d9f338199fa229eb516a66da28bf547451fa02318463db6f2421269c8b46135` |
| `g729AnnexB/c_codeBA/lpc.c` | `5cba017d5f746eb03631147015f09f530b2cae6c35dafccf2ea77c0d0e5eba2e` |
| `g729AnnexB/c_codeBA/pitch_a.c` | `29a4d7d46de435e1baa8768a8680f004ea54f2962c0e5fd0284fb6cd0d074edc` |
| `g729AnnexB/c_codeBA/pre_proc.c` | `24b91ef8cafe406f85f1984336a04aa26e3d2fdb2e517a810058422e18ee3343` |
| `g729AnnexB/c_codeBA/qua_gain.c` | `d31ca5438fc8ae576c2d86204e6cacf4717563715d4c24cf92f110feab34d60c` |
| `g729AnnexB/c_codeBA/qua_lsp.c` | `70b97e440263d8fbe2abd972cc4bb5fc29a8c5e823b3f9322df7191861769e59` |
| `g729AnnexB/c_codeBA/dtx.c` | `92e14e90da61633750b4a31f3b1073d5cfa14828f994fc1d619d124dc8f5c84f` |
| `g729AnnexB/c_codeBA/vad.c` | `4bb34d74b58dac9ee1297a8e96cdd53c6e898f7ae2e3a64b38d90504e5bf5698` |
| `g729AnnexB/c_codeBA/qsidlsf.c` | `6516739fa25ebee607319c8ef63bc0ef1f44fd9af6686874ccc83b878144a481` |

### Extracted

- `tables.toml` (first written to `crates/g729/data/`, moved on 2026-10-14 to `.git/g729-reference/tables.toml` in the main checkout, outside every worktree, because ITU-derived table values may not appear in any committable file): 30 constant tables (2324 values) used by the Annex A decoder and the Annex A+B decoder/comfort-noise generator, plus 59 scalar constants. Each entry gives its source file, line range and sha256. The oracle self-check passed. It re-parses every C initializer and compares it with the TOML values, dimensions and line ranges. It also compares the global tables with the values printed by a program linked against the compiled reference table objects of both packages. One table (the SID LSF MA predictor) is computed by the reference at initialization; its values were captured from the running reference build.
- `.git/g729-traces/` in the main checkout: per-frame and per-subframe intermediate values for all 16 decoder vectors (gzip JSON Lines, field definitions in its README.md).

### Bit-exact reproduction

Build: the unmodified sources, compiled with `gcc (Ubuntu 13.3.0-6ubuntu2~24.04.1) 13.3.0` on aarch64, flags `-O2 -fwrapv -fsigned-char`. Each output was compared with `cmp` against the expected file. `build-a`/`build-ab` are the unmodified Annex A and Annex A+B decoders. `inst-a`/`inst-ab` are the instrumented copies that produced the traces.

```
build-a ALGTHM.BIT -> ALGTHM.PST: exit=0 IDENTICAL (5600 bytes)
inst-a ALGTHM.BIT -> ALGTHM.PST: exit=0 IDENTICAL (5600 bytes)
build-a ERASURE.BIT -> ERASURE.PST: exit=0 IDENTICAL (48000 bytes)
inst-a ERASURE.BIT -> ERASURE.PST: exit=0 IDENTICAL (48000 bytes)
build-a FIXED.BIT -> FIXED.PST: exit=0 IDENTICAL (19200 bytes)
inst-a FIXED.BIT -> FIXED.PST: exit=0 IDENTICAL (19200 bytes)
build-a LSP.BIT -> LSP.PST: exit=0 IDENTICAL (357120 bytes)
inst-a LSP.BIT -> LSP.PST: exit=0 IDENTICAL (357120 bytes)
build-a OVERFLOW.BIT -> OVERFLOW.PST: exit=0 IDENTICAL (61440 bytes)
inst-a OVERFLOW.BIT -> OVERFLOW.PST: exit=0 IDENTICAL (61440 bytes)
build-a PARITY.BIT -> PARITY.PST: exit=0 IDENTICAL (48000 bytes)
inst-a PARITY.BIT -> PARITY.PST: exit=0 IDENTICAL (48000 bytes)
build-a PITCH.BIT -> PITCH.PST: exit=0 IDENTICAL (293600 bytes)
inst-a PITCH.BIT -> PITCH.PST: exit=0 IDENTICAL (293600 bytes)
build-a SPEECH.BIT -> SPEECH.PST: exit=0 IDENTICAL (600000 bytes)
inst-a SPEECH.BIT -> SPEECH.PST: exit=0 IDENTICAL (600000 bytes)
build-a TAME.BIT -> TAME.PST: exit=0 IDENTICAL (20480 bytes)
inst-a TAME.BIT -> TAME.PST: exit=0 IDENTICAL (20480 bytes)
build-a TEST.BIT -> TEST.pst: exit=0 IDENTICAL (28160 bytes)
inst-a TEST.BIT -> TEST.pst: exit=0 IDENTICAL (28160 bytes)
build-ab tstseq1a.bit -> tstseq1a.out: exit=0 IDENTICAL (159680 bytes)
inst-ab tstseq1a.bit -> tstseq1a.out: exit=0 IDENTICAL (159680 bytes)
build-ab tstseq2a.bit -> tstseq2a.out: exit=0 IDENTICAL (43680 bytes)
inst-ab tstseq2a.bit -> tstseq2a.out: exit=0 IDENTICAL (43680 bytes)
build-ab tstseq3a.bit -> tstseq3a.out: exit=0 IDENTICAL (136960 bytes)
inst-ab tstseq3a.bit -> tstseq3a.out: exit=0 IDENTICAL (136960 bytes)
build-ab tstseq4a.bit -> tstseq4a.out: exit=0 IDENTICAL (128000 bytes)
inst-ab tstseq4a.bit -> tstseq4a.out: exit=0 IDENTICAL (128000 bytes)
build-ab tstseq5.bit -> tstseq5a.out: exit=0 IDENTICAL (7360 bytes)
inst-ab tstseq5.bit -> tstseq5a.out: exit=0 IDENTICAL (7360 bytes)
build-ab tstseq6.bit -> tstseq6a.out: exit=0 IDENTICAL (16000 bytes)
inst-ab tstseq6.bit -> tstseq6a.out: exit=0 IDENTICAL (16000 bytes)
```

Trace check: the concatenated per-subframe post-processing output of every trace equals the expected output file:

```
ALGTHM    frames=   35 subframes=   70 output==expected:yes fields:ok  decoded_speech=35 erased=0 ltp_on=34 parity_error=0 received_speech=35
ERASURE   frames=  300 subframes=  600 output==expected:yes fields:ok  decoded_speech=300 erased=60 ltp_on=285 parity_error=60 received_speech=300
FIXED     frames=  120 subframes=  240 output==expected:yes fields:ok  decoded_speech=120 erased=0 ltp_on=39 parity_error=0 received_speech=120
LSP       frames= 2232 subframes= 4464 output==expected:yes fields:ok  decoded_speech=2232 erased=0 ltp_on=4105 parity_error=0 received_speech=2232
OVERFLOW  frames=  384 subframes=  768 output==expected:yes fields:ok  decoded_speech=384 erased=1 ltp_on=759 overflow_subframes=3 parity_error=1 received_speech=384
PARITY    frames=  300 subframes=  600 output==expected:yes fields:ok  decoded_speech=300 erased=0 ltp_on=312 parity_error=60 received_speech=300
PITCH     frames= 1835 subframes= 3670 output==expected:yes fields:ok  decoded_speech=1835 erased=0 ltp_on=2349 parity_error=0 received_speech=1835
SPEECH    frames= 3750 subframes= 7500 output==expected:yes fields:ok  decoded_speech=3750 erased=0 ltp_on=3871 parity_error=0 received_speech=3750
TAME      frames=  128 subframes=  256 output==expected:yes fields:ok  decoded_speech=128 erased=0 ltp_on=252 parity_error=0 received_speech=128
TEST      frames=  176 subframes=  352 output==expected:yes fields:ok  decoded_speech=176 erased=0 ltp_on=147 parity_error=0 received_speech=176
tstseq1a  frames=  998 subframes= 1996 output==expected:yes fields:ok  decoded_no_transmission=428 decoded_sid=85 decoded_speech=485 erased=0 ltp_on=480 parity_error=0 received_no_transmission=428 received_sid=85 received_speech=485
tstseq2a  frames=  273 subframes=  546 output==expected:yes fields:ok  decoded_no_transmission=130 decoded_sid=13 decoded_speech=130 erased=0 ltp_on=70 parity_error=0 received_no_transmission=130 received_sid=13 received_speech=130
tstseq3a  frames=  856 subframes= 1712 output==expected:yes fields:ok  decoded_no_transmission=475 decoded_sid=79 decoded_speech=302 erased=0 ltp_on=405 parity_error=0 received_no_transmission=475 received_sid=79 received_speech=302
tstseq4a  frames=  800 subframes= 1600 output==expected:yes fields:ok  decoded_no_transmission=266 decoded_sid=62 decoded_speech=472 erased=0 ltp_on=576 parity_error=0 received_no_transmission=266 received_sid=62 received_speech=472
tstseq5   frames=   46 subframes=   92 output==expected:yes fields:ok  decoded_sid=1 decoded_speech=45 erased=0 ltp_on=12 overflow_subframes=1 parity_error=15 received_sid=1 received_speech=45
tstseq6   frames=  100 subframes=  200 output==expected:yes fields:ok  decoded_no_transmission=19 decoded_sid=6 decoded_speech=75 erased=2 ltp_on=90 parity_error=0 received_no_transmission=19 received_sid=7 received_speech=74
ALL TRACE CHECKS PASS
```

### Copyright and license statements (verbatim)

The package-level readme `Software/readme_G729Release3.doc` contains no copyright or license statement. The statements below are copied from the readme files of the two code directories used.

From `Software/G729_Release3/g729AnnexA/c_code/README.TXT`:

```
SOFTWARE AND INTELLECTUAL PROPERTY
----------------------------------
This software package is provided as part of ITU-T Recommendation G.729A.

   Copyright (c) 1996,
   AT&T, France Telecom, NTT, Universite de Sherbrooke
   All rights reserved.

The copy of the source C code, version 1.1, is given under Copyright of the
authors, only for the purpose of establishing the specification of a codec.
```

From `Software/G729_Release3/g729AnnexB/c_codeBA/readme.txt`:

```
SOFTWARE AND INTELLECTUAL PROPERTY
----------------------------------
This software package is provided as part of ITU-T Recommendation G.729B.

 Copyright (c) 1996, AT&T, France Telecom, Lucent Technologies, NTT, 
                     Rockwell International, Universite de Sherbrooke.
 All rights reserved.

The copy of the source C code, version 1.5, is given under Copyright of the 
authors, only for the purpose of establishing the specification of a codec.
```

## Implementer

Date: 2026-10-14.

### Tables are user-supplied

No file of this crate holds an ITU-derived table value. The decoder takes a
`Tables` value, which only `Tables::from_bytes` builds, from a table file that
`import_from_itu` produces from the ITU-T package (both behind the `std`
feature). `src/tables.rs` records, for every one of the oracle's 30 tables and
59 scalars, whether it is computed from a formula of the Recommendation, a
constant the text states, a word of the serial vector format, user-supplied, or
computed at import (`CLASSIFICATION`).

The importer locates each of 16 source files by the sha256 recorded by the
oracle, reads only the line range the oracle recorded for each entry, removes C
comments and collects integer literals. It never compiles or runs anything. The
implementer chose the literal rule and, for each scalar, which literal of its
line to take, with a scratch script that compared the extracted integers with
`tables.toml` and printed only counts, equality flags and literal positions,
never file content.

### Pinned values hash

`VALUES_SHA256` = `e4846d29f3da09451781e61187fceac230d12cb0c6be0a85348a524137852ac2`.

It was computed once from `.git/g729-reference/tables.toml`: the `values` of
the 18 user-supplied tables, then the `value` of the 26 user-supplied scalars,
in the order of `ENTRIES` in `src/tables.rs`, each written as a little-endian
16-bit integer, hashed with sha256 (44 entries, 2069 values). The SID LSF MA
predictor is included as the oracle captured it from the running reference; the
importer computes it from equation (B.18), and the import reproduces the hash.

### Test vectors and sources

`scripts/fetch-g729-vectors.py` downloads the package (sha256
`979680ff3b52b13a5701453178efd32b53e340114638fd330fdb6669eec86620`), extracts
only the two `test_vectors/` directories and the 16 pinned source files into the
gitignored `crates/g729/test-vectors/`, verifies every file's sha256, and
deletes the download.

### What the implementer read

- ITU-T G.729 (06/2012) e-book edition (`T-REC-G.729-201206-I!!EPB-E`, sha256
  `60d6896ce0106f9535f7f441cc0bd0a3585843caa9e7274d76d938626d761e3f`): the main
  body, Annex A and Annex B, text and equation images.
- The prose STL manual chapter on the basic operators
  (`doc/manual/basop.tex` of github.com/openitu/STL); nothing under `src/`.
- [RFC 3551 section 4.5.6](https://www.rfc-editor.org/rfc/rfc3551.html#section-4.5.6).
- The oracle's `tables.toml` (now `.git/g729-reference/`), its traces and
  their README, and this file.
- The ITU test vectors, extracted by `scripts/fetch-g729-vectors.py`.
- The 16 pinned source files were read only by code (the scratch extraction
  check and `import_from_itu`), which reduced them to integers; their text was
  never displayed.

### How the arithmetic was established

The Recommendation text gives the algorithm, not its 16-bit arithmetic. Each
fixed-point form in this crate was proposed by the implementer and accepted
only when it reproduced the oracle's traces exactly over every subframe of the
16 vectors (the stage tests). Some forms were found by searching the traces
(for example the LSF rearrangement shift, the long-term postfilter's scaling
by 4 and energies starting at 1, the tilt correlations taken unnormalized, the
AGC normalization, the 16-bit truncation of log2 in the gain-predictor update,
the comfort-noise draw layout and the gain smoothing). Others came from the
implementer's general knowledge of fixed-point speech-codec practice and were
then confirmed by the traces: the split 32x16 product, the table
interpolation of the base-2 logarithm, power and inverse square root, and the
structure of the predicted-gain computation. That knowledge comes from model
training, which this process cannot control; the auditor comparison covers it.

### Round 2 (2026-10-15)

The oracle answered the round-1 questions with numbers only, in
`.git/g729-reference/` (`cng_traces/`, `basic_operations.json`,
`sid_ma_predictor_derivation.json`, 20 synthetic streams under
`conformance/`). The implementer read those files and their README. Each step
of the comfort-noise Gaussian scaling, the fixed gain Gf and the lost-SID gain
recovery is now pinned field by field by the stage tests. The basic operators
are checked against every reference row. The 20 synthetic streams decode
bit-exactly (dev-only, `RUSTFLAGS='--cfg g729_oracle' cargo test -p sipnab-g729`).

Differences between the Recommendation text and the reference, followed here
as clauses 2.4, A.2.1 and B.5 require:

- Equation (B.21): the reference computes E_x and I on the mixed excitation
  Ga ea(n) + ex2(n), not on ea(n) alone as the text writes.
- When (B.21) has no real root, the reference sets Ga to 0 and solves for
  ex2(n) alone with the energy (1 - alpha^2) K, alpha = 0.5. The text says
  instead to choose Ga in a bounded range (B.22).
- The Gaussian excitation is scaled with alpha = 0.5 (and its 1 - alpha^2 =
  0.75), while the text's mixing (B.25, B.26) uses alpha = 0.6.
- Clause B.4.5: after a lost first SID frame the comfort-noise LSP vector is
  the last SID vector, not the LSPs of the last active frame.
- The G.192 reader treats any first word other than 0x6B21 as an erased
  frame (oracle note).
- `norm_s`/`norm_l` of a negative power of two shift it to the minimum value
  (`norm_s(-1)` = 15). The round-1 implementation followed the STL manual's
  wording instead, which the reference rows contradicted.

### Round 5 (2026-10-15)

The oracle's round-3 data (`.git/g729-reference/round3/`) is decoded
bit-exactly by `tests/round3.rs` (dev-only, `--cfg g729_oracle`): 21 case-A
streams in the Annex A and A+B builds, 31 case-B streams, the full
1,343,488-row SID energy quantizer grid, and 10 general A+B streams of
40,000 frames. These behaviors were established from that data alone:

- Clause 4.4: after an erased subframe the carried integer delay is the
  delay plus 1, bounded by 143, also when the delay is 144 (a top-of-range
  second-subframe delay with a fraction of -1).
- Clause B.4.2.1 quantizer: the log2 fraction is rounded to Q10, and the
  knee between the 4 dB and 2 dB steps is compared after the high-region
  offset is taken off.
- Clause B.4.4: the comfort-noise excitation of both subframes is built
  before either is synthesized, so the division of u(n) by 4 after a
  saturated first-subframe synthesis also scales the second subframe's
  excitation.
- Clause A.4.2.1: a negative correlation at the selected postfilter delay is
  taken as 0. When the delayed energy also rounds to 0, the long-term filter
  is then on with the weights (1, 0).

## Audit 1 remediation

Date: 2026-10-15. An independent auditor compared this crate with other
implementations and reported REVIEW for the ranges below (line numbers as of
00:24). The auditor did not say which names or which implementation; the
implementer did not look. Every range was reworked as follows, and every
suite was re-run afterwards, bit-exact: 16 ITU vectors, 20 synthetic
streams, 19 stage tests and the basic-operator rows (`--cfg g729_oracle`).

Identifier ranges (every function, variable, constant and parameter in the
range renamed, to the Recommendation's symbols where it has one, otherwise to
plain descriptive English):

- `basic_op.rs:214-288`: the seven helpers that are not STL basic operators
  are now `split_high_low`, `join_high_low`, `multiply_split_by_16`,
  `multiply_32_by_16`, `base2_log`, `base2_power` and
  `inverse_square_root`. All their parameters and locals were renamed, and
  the three lookups now share one interpolation helper. STL names (`add`,
  `l_mult`, `l_mac` and so on) are unchanged.
- `lib.rs:93-187`: the decoder's fields are named after their symbols or
  roles (`q_previous` for q(previous) of (24), `beta` for (47), `u_buffer`
  for u(n), `s_hat_tail` for the synthesis memory, `lsf_quantizer`,
  `delay_tracker`, `erasure_seed`, `gain_predictor`, `postfilter`,
  `output_highpass`, `last_frame_active`, `comfort_noise`). Its methods are
  `decode_voice_frame`, `decode_comfort_noise_frame`, `reconstruct` and the
  new shared `finish_subframe`, and every local was renamed (omega_hat,
  q_current, a_hat, t_integer, c_vector, v_vector, u_vector, ...).
  `decode_rtp` now chains the voice frames and the optional SID frame into
  one iterator. The frame-decision variants are now `Voice` and
  `ComfortNoise`.
- `lsp.rs:18-91`: the state is `LsfQuantizerMemory` (fields `l_hat_past`,
  `predictor_last_good`, `omega_last_good`; methods `past_outputs`,
  `replace_past_outputs`, `past_output_rows`, `remember_output`,
  `decode_frame`). `new` is kept as the Rust constructor convention.
- `postfilter.rs:21-240`: the whole module was rewritten: `AdaptivePostfilter`
  with `run` and `run_traced`, `PostfilterTrace` and `PostfilterInput`, and
  the helpers `inverse_filter`, `long_term_analysis`, `tilt_factor_of` and
  `gain_target_of`. The constants are `MAX_DELAY` and `H_F_LENGTH`, and all
  fields and locals use the clause's symbols (r_hat, s_hat, sf, g_agc,
  h_f, r_h0, r_h1, ...).
- `cng.rs:562-567`: the comfort-noise frame path. `CngState`'s fields are now
  `noise_seed`, `q_sid`, `g_sid`, `g_target` and `saved_excitation_energy`,
  and every local in the frame and excitation routines was renamed.

Token-similarity ranges (re-expressed in a different structure; where the
fixed-point arithmetic requires an order, the order is kept):

- `lsp.rs:107-158`: the rearrangement is a pairwise `spread_pair` helper over
  split slices. The MA prediction (20) and its inverse (92) are folds. The
  stability ordering uses the library sort instead of an explicit exchange
  sort: a sorted result does not depend on the sorting algorithm. Order kept:
  the pairs are adjusted left to right, because each pair sees the previous
  pair's update. Each prediction sum takes the current term first, then the
  past terms by age, because the saturating additions depend on that order.
  The minimum-distance pass also runs left to right.
- `lpc.rs:12-62`: the f1/f2 recursion is now an out-of-place stage function
  (`next_stage`) that builds each polynomial from the previous one. This
  gives the same arithmetic as an in-place descending update, which also
  reads only old values. Equations (25) and (26) are written with array
  maps. Order kept: the new highest coefficient is still formed as
  2 f(i-2) - 2 q f(i-1). The general three-term form would saturate
  differently on large coefficients.
- `post_process.rs:26-44`: the high-pass is a per-sample `step` with
  array-held history and folds over (sample, weight) pairs. Order kept: the
  feedback terms are accumulated before the feedforward terms, newest first,
  because the additions saturate.
- `cng.rs:622-629`: the B.19 smoothing is a fold over (gain, weight) pairs,
  and the B.23 composition is an array map. Order kept: 7/8 of the previous
  gain is added before 1/8 of the SID gain (saturating addition, each term
  rounded separately).

Mutations of the restructured code turned the stage and conformance tests
red (the postfilter's first-maximum rule, the LP top coefficient, the
high-pass feedback order, the spacing direction, the B.19 rounding), and each
restore was proven identical with `cmp -s`.
