%%%-------------------------------------------------------------------
%%% @copyright (C) 2018, Aeternity Anstalt
%%%-------------------------------------------------------------------

-module(herrie_protocol_tests).

-include_lib("eunit/include/eunit.hrl").

name_test() ->
    roundtrip("Noise_XK_25519_ChaChaPoly_SHA512"),
    roundtrip("Noise_NN_25519_AESGCM_BLAKE2b").

name2_test() ->
    Name = "Noise_NXpsk2_25519_AESGCM_SHA512",
    ?assertError({unsupported_protocol, Name}, herrie_protocol:from_name(Name)).

name_pattern_test() ->
    Pat = "XKfallback+psk0",
    RoundPat = herrie_protocol:to_name_pattern(herrie_protocol:from_name_pattern(Pat)),
    ?assertEqual(Pat, RoundPat).

roundtrip(Name) ->
    ExpectedName = iolist_to_binary(Name),
    ?assertMatch(ExpectedName, herrie_protocol:to_name(herrie_protocol:from_name(Name))).
