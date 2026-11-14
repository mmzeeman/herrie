%%% ------------------------------------------------------------------
%%% @copyright 2018, Aeternity Anstalt
%%%
%%% @doc Module implementing crypto primitives needed by Noise protocol
%%%
%%% @end
%%% ------------------------------------------------------------------

-module(herrie_crypto).

-include("herrie.hrl").

-export([ decrypt/5
        , dh/3
        , dhlen/1
        , encrypt/5
        , encrypt_iolist/5
        , hash/2
        , hashlen/1
        , hkdf/3
        , hmac/3
        , pad/3
        , rekey/2
        ]).

-define(MAC_LEN, 16).

-type keypair() :: herrie_keypair:keypair().

%% @doc Perform a Diffie-Hellman calculation with the secret key from `Key1'
%% and the public key from `Key2' with algorithm `Algo'.
-spec dh(Algo :: herrie_hs_state:noise_dh(),
         Key1:: keypair(), Key2 :: keypair()) -> binary().
dh(Type, Key1, Key2) when Type =:= dh25519; Type =:= dh448 ->
    dh_(ecdh_type(Type), herrie_keypair:pubkey(Key2), herrie_keypair:seckey(Key1));
dh(Type, _Key1, _Key2) ->
    error({unsupported_diffie_hellman, Type}).

ecdh_type(dh25519) -> x25519;
ecdh_type(dh448)   -> x448.

dh_(DHType, OtherPub, MyPriv) ->
    crypto:compute_key(ecdh, OtherPub, MyPriv, DHType).

-spec hmac(Hash :: herrie_sym_state:noise_hash(),
           Key :: binary(), Data :: iodata()) -> binary().
hmac(Hash, Key, Data)
  when Hash =:= sha512; Hash =:= sha256; Hash =:= blake2s; Hash =:= blake2b ->
    crypto:mac(hmac, Hash, Key, Data);
hmac(Hash, _Key, _Data) ->
    error({hash_not_implemented_yet, Hash}).

-spec hkdf(Hash :: herrie_sym_state:noise_hash(),
           Key :: binary(), Data :: iodata()) -> [binary()].
hkdf(Hash, Key, Data) ->
    TempKey = hmac(Hash, Key, Data),
    Output1 = hmac(Hash, TempKey, [1]),
    Output2 = hmac(Hash, TempKey, [Output1, 2]),
    Output3 = hmac(Hash, TempKey, [Output2, 3]),
    [Output1, Output2, Output3].

-spec rekey(Cipher :: herrie_cipher_state:noise_cipher(), Key :: binary()) -> binary().
rekey(Cipher, K0) ->
    <<K:32/binary, _/binary>> = encrypt(Cipher, K0, ?MAX_NONCE, <<>>, <<0:(32*8)>>),
    K.

-spec encrypt(Cipher :: herrie_cipher_state:noise_cipher(), Key :: binary(),
              Nonce :: non_neg_integer(), Ad :: binary(), PlainText :: binary()) -> binary().
encrypt(Cipher, K, N, Ad, PlainText) ->
    {CText, CTag} = crypto:crypto_one_time_aead(cipher(Cipher), K, nonce(Cipher, N), PlainText, Ad, true),
    <<CText/binary, CTag/binary>>.

-spec encrypt_iolist(Cipher :: herrie_cipher_state:noise_cipher(), Key :: binary(),
                     Nonce :: non_neg_integer(), Ad :: binary(), PlainText :: iodata()) -> iolist().
encrypt_iolist(Cipher, K, N, Ad, PlainText) ->
    tuple_to_list(
      crypto:crypto_one_time_aead(cipher(Cipher), K, nonce(Cipher, N), PlainText, Ad, true)).

-spec decrypt(Cipher ::herrie_cipher_state:noise_cipher(), Key :: binary(),
              Nonce :: non_neg_integer(), AD :: binary(),
              CipherText :: binary()) -> binary() | {error, term()}.
decrypt(Cipher, K, N, Ad, CipherText0) ->
    CTLen = byte_size(CipherText0) - ?MAC_LEN,
    <<CText:CTLen/binary, MAC:?MAC_LEN/binary>> = CipherText0,
    case crypto:crypto_one_time_aead(cipher(Cipher), K, nonce(Cipher, N), CText, Ad, MAC, false) of
        error -> {error, decrypt_failed};
        Data  -> Data
    end.

nonce('ChaChaPoly', N) -> <<0:32, N:64/little-unsigned-integer>>;
nonce('AESGCM', N)     -> <<0:32, N:64/big-unsigned-integer>>.

cipher('ChaChaPoly') -> chacha20_poly1305;
cipher('AESGCM')     -> aes_256_gcm.

-spec hash(Hash :: herrie_sym_state:noise_hash(), Data :: iodata()) -> binary().
hash(Hash, Data)
  when Hash =:= sha512; Hash =:= sha256; Hash =:= blake2s; Hash =:= blake2b ->
    crypto:hash(Hash, Data);
hash(Hash, _Data) ->
    error({hash_not_implemented_yet, Hash}).

-spec pad(Data :: binary(), MinSize :: non_neg_integer(),
          PadByte :: byte()) -> binary().
pad(Data, MinSize, _PadByte) when byte_size(Data) >= MinSize ->
    Data;
pad(Data, MinSize, PadByte) when PadByte >= 0, PadByte =< 255 ->
    Padding = binary:copy(<<PadByte:8>>, MinSize - byte_size(Data)),
    <<Data/binary, Padding/binary>>.

-spec hashlen(Hash :: herrie_sym_state:noise_hash()) -> non_neg_integer().
hashlen(sha256)  -> 32;
hashlen(sha512)  -> 64;
hashlen(blake2s) -> 32;
hashlen(blake2b) -> 64.

-spec dhlen(DH :: herrie_hs_state:noise_dh()) -> non_neg_integer().
dhlen(dh25519) -> 32;
dhlen(dh448)   -> 56.

