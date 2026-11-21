%%% ------------------------------------------------------------------
%%% @copyright 2018, Aeternity Anstalt
%%% @copyright 2026, herrie developers
%%%
%%% @doc Module encapsulating a Noise symmetric (hash) state
%%%
%%% @end
%%% ------------------------------------------------------------------

-module(herrie_sym_state).

-export([ cipher_state/1
        , decrypt_and_hash/2
        , encrypt_and_hash/2
        , h/1
        , hash/1
        , init/1
        , mix_hash/2
        , mix_key/2
        , mix_key_and_hash/2
        , split/1
        ]).

-ifdef(TEST).
-export([ ck/1 ]).
-endif.

-include("herrie.hrl").

-type noise_hash() :: sha256 | sha512 | blake2s | blake2b.

-record(noise_ss, { cs   :: herrie_cipher_state:state()
                  , ck   :: herrie_crypto:key_fun()
                  , h    :: binary()
                  , hash :: noise_hash() }).

-opaque state() :: #noise_ss{}.
-export_type([noise_hash/0, state/0]).

-spec init(Protocol :: herrie_protocol:protocol()) -> state().
init(Protocol) ->
    Hash    = herrie_protocol:hash(Protocol),
    Cipher  = herrie_protocol:cipher(Protocol),
    Name    = herrie_protocol:to_name(Protocol),
    HashLen = herrie_crypto:hashlen(Hash),
    H1 =
        case byte_size(Name) > HashLen of
            true  -> herrie_crypto:hash(Hash, Name);
            false -> herrie_crypto:pad(Name, HashLen, 16#00)
        end,
    #noise_ss{ h = H1
             , ck = herrie_crypto:wrap(H1)
             , hash = Hash
             , cs = herrie_cipher_state:init(empty, Cipher) }.

-spec mix_key(SState :: state(), InputKeyMaterial :: binary()) -> state().
mix_key(SState = #noise_ss{ hash = Hash, ck = CK0, cs = CS0 }, InputKeyMaterial) ->
    [CK1, <<TempK:32/binary, _/binary>> | _] =
        herrie_crypto:hkdf(Hash, CK0(), InputKeyMaterial),
    CS1 = herrie_cipher_state:set_key(CS0, TempK),
    SState#noise_ss{ ck = herrie_crypto:wrap(CK1), cs = CS1 }.

-spec mix_hash(SState :: state(), Data :: binary()) -> state().
mix_hash(SState = #noise_ss{ hash = Hash, h = H0 }, Data) ->
    H1 = herrie_crypto:hash(Hash, <<H0/binary, Data/binary>>),
    SState#noise_ss{ h = H1 }.

-spec mix_key_and_hash(SState :: state(), InputKeyMaterial :: binary()) -> state().
mix_key_and_hash(SState = #noise_ss{ hash = Hash, ck = CK0, cs = CS0 }, InputKeyMaterial) ->
    [CK1, TempH, <<TempK:32/binary, _/binary>>] =
        herrie_crypto:hkdf(Hash, CK0(), InputKeyMaterial),
    CS1 = herrie_cipher_state:set_key(CS0, TempK),
    mix_hash(SState#noise_ss{ ck = herrie_crypto:wrap(CK1), cs = CS1 }, TempH).

-spec encrypt_and_hash(SState :: state(), PlainText :: binary()) -> {ok, state(), binary()}.
encrypt_and_hash(SState = #noise_ss{ cs = CS0, h = H }, PlainText) ->
    {ok, CS1, CipherText} = herrie_cipher_state:encrypt_with_ad(CS0, H, PlainText),
    {ok, mix_hash(SState#noise_ss{ cs = CS1 }, CipherText), CipherText}.

-spec decrypt_and_hash(SState :: state(), CipherText :: binary()) ->
                {ok, state(), binary()} | {error, term()}.
decrypt_and_hash(SState = #noise_ss{ cs = CS0, h = H }, CipherText) ->
    case herrie_cipher_state:decrypt_with_ad(CS0, H, CipherText) of
        Err = {error, _} ->
            Err;
        {ok, CS1, PlainText} ->
            {ok, mix_hash(SState#noise_ss{ cs = CS1 }, CipherText), PlainText}
    end.

-spec split(SState :: state()) -> {herrie_cipher_state:state(), herrie_cipher_state:state()}.
split(#noise_ss{ hash = Hash, ck = CK, cs = CS }) ->
    [<<TempK1:32/binary, _/binary>>, <<TempK2:32/binary, _/binary>>, _] =
         herrie_crypto:hkdf(Hash, CK(), <<>>),
    {herrie_cipher_state:set_key(CS, TempK1),
     herrie_cipher_state:set_key(CS, TempK2)}.

-spec cipher_state(SState :: state()) -> herrie_cipher_state:state().
cipher_state(#noise_ss{ cs = CS }) ->
    CS.


-spec h(SState :: state()) -> binary().
h(#noise_ss{ h = H }) ->
    H.

-spec hash(SState :: state()) -> noise_hash().
hash(#noise_ss{ hash = Hash }) ->
    Hash.

-ifdef(TEST).

-spec ck(SState :: state()) -> binary().
ck(#noise_ss{ ck = CK }) ->
    CK().

-endif.
