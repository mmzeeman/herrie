herrie
=====

Herrie — [Noise Protocol](https://noiseprotocol.org/) Framework for Erlang/BEAM

`herrie` provides a generic handshake mechanism, that can be used in a couple
of different ways. There is also a plain `gen_tcp`-wrapper, where you can
"upgrade" a TCP socket to a Noise socket and use it in much the same way as you
would use `gen_tcp`.

Herrie is derived from the original [enoise](https://github.com/aeternity/enoise)
project, developed by the aeternity developers. The original implementation is
Copyright (c) 2018, aeternity developers and is distributed under the ISC License.
Herrie is independently maintained and includes subsequent modifications and
improvements.

Interactive handshake
---------------------

When using `herrie` to do an interactive handshake, `herrie` will only take
care of message composition/decompositiona and encryption/decryption - i.e. the
user has to do the actual sending and receiving.

An example of the interactive handshake can be seen in the `noise_interactive`
test in `test/herrie_tests.erl`.

Generic handshake
-----------------

There is also the option to use an automated handshake procedure. If provided
with a generic _Communication state_ that describe how data is sent and
received, the handshake procedure is done automatically. The result of a
successful handshake is two Cipher states that can be used to encrypt/decrypt a
RX channel and a TX channel respectively.

The provided `gen_tcp`-wrapper is implemented using the generic handshake, see
`src/herrie.erl`.

Security considerations
-----------------------

To minimize the risk of accidental exposure of raw key material in crash dumps,
process inspection (`sys:get_status/1`), or tracing if a process fails mid-handshake,
processes performing Noise handshakes or handling secret keys should set:

```erlang
process_flag(sensitive, true)
```

Build
-----

    $ rebar3 compile

Test
----

    $ rebar3 eunit

Typecheck
---------

    $ rebar3 dialyzer
    $ elp --eqwalize-all --rebar
