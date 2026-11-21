%%%-------------------------------------------------------------------
%%% @copyright (C) 2018, Aeternity Anstalt
%%% @copyright (C) 2026, herrie developers
%%%-------------------------------------------------------------------

-module(herrie_connection_tests).

-include_lib("eunit/include/eunit.hrl").

format_status_redacts_sensitive_state_test() ->
    OwnerRef = make_ref(),

    State = {state, rx_secret, tx_secret, self(), OwnerRef, socket, true,
             [plaintext], <<>>},

    Status = #{ state => State,
                message => message,
                reason => reason,
                log => []
              },

    #{ state := FormattedState,
       message := message,
       reason := reason,
       log := [] } = herrie_connection:format_status(Status),

    ?assertEqual(
       {state, redacted, redacted, self(), OwnerRef, socket, true,
        redacted, redacted},
       FormattedState).
