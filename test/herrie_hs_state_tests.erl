%%%-------------------------------------------------------------------
%%% @copyright (C) 2018, Aeternity Anstalt
%%%-------------------------------------------------------------------

-module(herrie_hs_state_tests).

-include_lib("eunit/include/eunit.hrl").

noise_hs_test_() ->
    %% Test vectors from https://raw.githubusercontent.com/rweather/noise-c/master/tests/vector/noise-c-basic.txt
    {setup,
        fun() -> test_utils:noise_test_vectors() end,
        fun(_X) -> ok end,
        fun(Tests) ->
            [ {maps:get(protocol_name, T), fun() -> noise_hs_test(T) end}
              || T <- test_utils:noise_test_filter(Tests) ]
        end
    }.

noise_hs_test(V = #{ protocol_name := Name }) ->
    Protocol = herrie_protocol:from_name(Name),

    FixK = fun(undefined) -> undefined;
              (Bin) -> test_utils:hex_str_to_bin("0x" ++ binary_to_list(Bin)) end,

    Init = #{ prologue => FixK(maps:get(init_prologue, V, <<>>))
            , e        => FixK(maps:get(init_ephemeral, V, undefined))
            , s        => FixK(maps:get(init_static, V, undefined))
            , rs       => FixK(maps:get(init_remote_static, V, undefined)) },
    Resp = #{ prologue => FixK(maps:get(resp_prologue, V, <<>>))
            , e        => FixK(maps:get(resp_ephemeral, V, undefined))
            , s        => FixK(maps:get(resp_static, V, undefined))
            , rs       => FixK(maps:get(resp_remote_static, V, undefined)) },
    Messages = maps:get(messages, V),
    HandshakeHash = maps:get(handshake_hash, V),

    noise_test(Name, Protocol, Init, Resp, Messages, FixK(HandshakeHash)),

    ok.

noise_test(_Name, Protocol, Init, Resp, Messages, HSHash) ->
    DH = herrie_protocol:dh(Protocol),
    SecK = fun(undefined) -> undefined; (Sec) -> herrie_keypair:new(DH, Sec, undefined) end,
    PubK = fun(undefined) -> undefined; (Pub) -> herrie_keypair:new(DH, Pub) end,
    HSInit = fun(P, R, #{ e := E, s := S, rs := RS, prologue := PL }) ->
                 {ok, HS} = herrie_hs_state:init(P, R, PL, {SecK(S), SecK(E), PubK(RS), undefined}),
                 HS
             end,

    InitHS = HSInit(Protocol, initiator, Init),
    RespHS = HSInit(Protocol, responder, Resp),

    noise_test(oneway(Protocol), Messages, InitHS, RespHS, HSHash),

    ok.

oneway(P) -> lists:member(herrie_protocol:pattern(P), [n, k, x]).

noise_test(Oneway, [M = #{ payload := PL0, ciphertext := CT0 } | Msgs], SendHS, RecvHS, HSHash) ->
    PL = test_utils:hex_str_to_bin("0x" ++ binary_to_list(PL0)),
    CT = test_utils:hex_str_to_bin("0x" ++ binary_to_list(CT0)),
    case {herrie_hs_state:next_message(SendHS), herrie_hs_state:next_message(RecvHS)} of
        {out, in} ->
            {ok, SendHS1, Message} = herrie_hs_state:write_message(SendHS, PL),
            ?assertEqual(CT, Message),
            {ok, RecvHS1, PL1} = herrie_hs_state:read_message(RecvHS, Message),
            ?assertEqual(PL, PL1),
            noise_test(Oneway, Msgs, RecvHS1, SendHS1, HSHash);
        {done, done} ->
            {ok, #{ rx := RX1, tx := TX1, hs_hash := HSHash1 }} = herrie_hs_state:finalize(SendHS),
            {ok, #{ rx := RX2, tx := TX2, hs_hash := HSHash2 }} = herrie_hs_state:finalize(RecvHS),
            ?assertEqual(RX1, TX2), ?assertEqual(RX2, TX1),
            ?assertEqual(HSHash, HSHash1), ?assertEqual(HSHash, HSHash2),
            %% Only one party will send/encrypt in One-way scenario
            if not Oneway -> noise_test(Oneway, [M | Msgs], TX1, TX2);
               Oneway     -> noise_test(Oneway, [M | Msgs], TX2, TX1)
            end;
        {Out, In} -> ?assertMatch({out, in}, {Out, In})
    end.

noise_test(_, [], _, _) -> ok;
noise_test(Oneway, [#{ payload := PL0, ciphertext := CT0 } | Msgs], CA, CB) ->
    PL = test_utils:hex_str_to_bin("0x" ++ binary_to_list(PL0)),
    CT = test_utils:hex_str_to_bin("0x" ++ binary_to_list(CT0)),

    {ok, CA1, CT1} = herrie_cipher_state:encrypt_with_ad(CA, <<>>, PL),
    ?assertEqual(CT, CT1),
    {ok, CA2, PL1} = herrie_cipher_state:decrypt_with_ad(CA, <<>>, CT1),
    ?assertEqual(CA1, CA2),
    ?assertEqual(PL, PL1),

    %% Only one party will send/encrypt in One-way scenario
    if not Oneway -> noise_test(Oneway, Msgs, CB, CA1);
       Oneway     -> noise_test(Oneway, Msgs, CA1, CB)
    end.

finalize_does_not_return_private_key_material_test() ->
    Protocol = herrie_protocol:from_name(
                 <<"Noise_N_25519_ChaChaPoly_BLAKE2b">>),
    LocalStatic = herrie_keypair:new(dh25519, <<1:256>>, undefined),
    Ephemeral = herrie_keypair:new(dh25519, <<2:256>>, undefined),
    RemoteKey = herrie_keypair:new(dh25519, <<3:256>>, undefined),
    RemoteStatic = herrie_keypair:new(
                     dh25519, herrie_keypair:pubkey(RemoteKey)),
    {ok, HS0} = herrie_hs_state:init(
                  Protocol, initiator, <<>>,
                  {LocalStatic, Ephemeral, RemoteStatic, undefined}),
    {ok, HS1, _Message} = herrie_hs_state:write_message(HS0, <<>>),

    {ok, Finalized} = herrie_hs_state:finalize(HS1),

    ?assertEqual([final_state, hs_hash, rx, tx],
                 lists:sort(maps:keys(Finalized))),
    ?assertMatch({noise_hs, undefined, undefined, undefined, undefined,
                  undefined, initiator, dh25519, []},
                 maps:get(final_state, Finalized)).
