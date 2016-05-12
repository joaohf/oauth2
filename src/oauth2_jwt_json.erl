-module(oauth2_jwt_json).

-export([encode/1
        ,decode/1]).

-type oauth2_jwt_json() :: tuple() | list().

-export_type([oauth2_jwt_json/0]).

%%--------------------------------------------------------------------
%% @doc
%% Encodes the user-supplied `Json' with the user's defined JSON
%% module (defaults to `jsx`)
%% In particular, this function cannot be used to encode any JSON
%% built internally to `erlastic_search` as we do not know how
%% the user's JSON module encodes JSONs in Erlang
%% @end
%%--------------------------------------------------------------------
-spec encode(oauth2_jwt_json()) -> binary().
encode(Json) ->
    ?OAUTH2_JWT_TOKEN_JSON_MODULE:encode(Json).

%%--------------------------------------------------------------------
%% @doc
%% Decodes the given `BinaryJson' with the user's defined JSON
%% module (defaults to `jsx`)
%% The same caveat as for `encode/1' above applies
%% @end
%%--------------------------------------------------------------------
-spec decode(binary()) -> oauth2_jwt_json().
decode(BinaryJson) ->
    ?OAUTH2_JWT_TOKEN_JSON_MODULE:decode(BinaryJson).
