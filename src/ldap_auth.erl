-module(ldap_auth).

-include_lib("couch/include/couch_db.hrl").

%% API

-export([default_authentication_handler/1,
         cookie_authentication_handler/1,
         handle_session_req/1]).

%% -compile([export_all]). % FIXME

-define(SESSION_COOKIE, "LDAPAuthSession").
-define(TIMESTAMP_ENCODE_BASE, 16).

config(cookie_timeout) ->
    config:get_integer("couch_httpd_auth", "timeout", 600);
config(secret) ->
    case config:get("couch_httpd_auth", "secret", undefined) of
        undefined ->
            undefined;
        Str when is_list(Str) ->
            ?l2b(Str)
    end.


default_authentication_handler(Req) ->
    case couch_httpd_auth:basic_name_pw(Req) of
        {Username, Password} ->
            couch_log:notice("ldap_authentication_handler ~p:~p",
                             [Username, Password]),
            case ldap_interface:authorized_roles(Username, Password) of
                {ok, Roles} ->
                    couch_log:notice("ldap_authentication_handler roles ~p",
                                     [Roles]),
                    Req#httpd{user_ctx=#user_ctx{name=?l2b(Username),
                                                 roles=Roles}};
                Other ->
                    couch_log:notice("ldap_authentication_handler fail ~p", [Other]),
                    Req
            end;
        _ ->
            Req
    end.


form_credentials(#httpd{mochi_req=MochiReq}) ->
    Form = form(MochiReq),
    UserName = couch_httpd_auth:extract_username(Form),
    Password = couch_util:get_value("password", Form, ""),
    {UserName, Password}.

form(MochiReq) ->
    ReqBody = MochiReq:recv_body(),
    case MochiReq:get_primary_header_value("content-type") of
        "application/x-www-form-urlencoded" ++ _ ->
            mochiweb_util:parse_qs(ReqBody);
        "application/json" ++ _ ->
            {Pairs} = ?JSON_DECODE(ReqBody),
            [{?b2l(Key), ?b2l(Value)} || {Key, Value} <- Pairs];
        _ ->
            []
    end.    

handle_session_req(#httpd{method='POST'}=Req) ->
    {Username, Password} = form_credentials(Req),
    case ldap_interface:authorized_roles(Username, Password) of
        {ok, Roles} ->
            Header = session_header(Req, Username, Roles),
            Json = {[{ok, true}, {name, ?l2b(Username)}, {roles, Roles}]},
            couch_httpd:send_json(Req, 200, [Header], Json);
        _ ->
            couch_httpd_auth:authentication_warning(Req, Username),
            Header = clear_session_header(Req),
            Json = {[{error, unauthorized},
                     {reason, <<"Name or password is incorrect.">>}]},
            couch_httpd:send_json(Req, 401, [Header], Json)
    end.


session_header(Req, Username, Roles) ->
    Timestamp = couch_httpd_auth:make_cookie_time(),
    Secret = couch_httpd_auth:ensure_cookie_auth_secret(),
    Session = encode_session(Username, Timestamp, Roles),
    Hash = hash(Secret, Session),
    Opts = [{path, "/"}] ++ couch_httpd_auth:cookie_scheme(Req)
        ++ couch_httpd_auth:max_age(),
    mochiweb_cookies:cookie(?SESSION_COOKIE, encode_cookie(Session, Hash), Opts).
    
clear_session_header(Req) ->
    Opts = [{path, "/"}] ++ couch_httpd_auth:cookie_scheme(Req),
    mochiweb_cookies:cookie(?SESSION_COOKIE, "", Opts).


encode_cookie(Session, Hash) ->
    b64url:encode(Session ++ ":" ++ ?b2l(Hash)).

encode_session(Username, Timestamp, Roles) ->
    Username ++ ":" ++ encode_timestamp(Timestamp) ++ ":" ++ encode_roles(Roles).

hash(Secret, Session) ->
    crypto:hmac(sha, Secret, Session).    

encode_roles(Roles) ->
    encode_roles(Roles, []).

encode_roles([Role|Roles], []) ->
    encode_roles(Roles, encode_role(Role));
encode_roles([Role|Roles], Acc) ->
    encode_roles(Roles, Acc ++ "," ++ encode_role(Role));
encode_roles([], Acc) ->
    Acc.

encode_role(server_admin) ->
    "server_admin";
encode_role(Bin) when is_binary(Bin) ->
    ?b2l(Bin).


decode_roles(RolesStr) ->
    [ldap_interface:fixup_role(Role)
     || Role <- re:split(RolesStr, ",", [{return, list}])].


encode_timestamp(Timestamp) ->
    integer_to_list(Timestamp, ?TIMESTAMP_ENCODE_BASE).

decode_timestamp(TimeStr) ->
    list_to_integer(TimeStr, ?TIMESTAMP_ENCODE_BASE).


decode_cookie(Encoded) ->
    try
        Cookie = b64url:decode(Encoded),
        [Username, TimeStr, RolesStr, HashStr] =
            re:split(Cookie, ":", [{return, list}, {parts, 4}]),
        {Username, decode_timestamp(TimeStr), decode_roles(RolesStr), ?l2b(HashStr)}
    catch
        error:Error ->
            couch_log:info("ldap_auth:decode_cookie ~p",[Error]),
            Reason =
                io_lib:format("Malformed ~s cookie. Please clear your cookies.",
                              [?SESSION_COOKIE]),
            throw({bad_request, ?l2b(Reason)})
    end.    

cookie_authentication_handler(#httpd{mochi_req=MochiReq}=Req) ->
    case MochiReq:get_cookie_value(?SESSION_COOKIE) of
        undefined ->
            Req;
        [] ->
            Req;
        EncodedCookie ->
            maybe_authenticate(Req, EncodedCookie)
    end.

maybe_authenticate(Req, EncodedCookie) ->
    {Username, Timestamp, Roles, Hash} = decode_cookie(EncodedCookie),
    case config(secret) of
        undefined ->
            couch_log:info("ldap_auth cookie no secret ~p", [Username]),
            Req;
        Secret ->
            Session = encode_session(Username, Timestamp, Roles),
            ExpectedHash = hash(Secret, Session),
            case couch_passwords:verify(ExpectedHash, Hash) of
                false ->
                    couch_log:info(
                      "ldap_auth cookie hash mismatch ~p",
                      [Username]),
                    Req;
                true ->
                    authenticate_if_unexpired(Req, Secret, Username, Timestamp, Roles)
            end
    end.

authenticate_if_unexpired(Req, Secret, Username, Timestamp, Roles) ->
    CurrentTime = couch_httpd_auth:make_cookie_time(),
    Timeout = config(cookie_timeout),
    TimeLeft = Timestamp + Timeout - CurrentTime,
    case TimeLeft > 0 of
        false ->
            couch_log:info("ldap_auth cookie expired ~p", [Username]),
            Req;
        true ->
            couch_log:info("ldap_auth cookie success ~p", [Username]),
            Req#httpd{user_ctx=#user_ctx{
                                  name=?l2b(Username),
                                  roles=Roles},
                      auth={Secret, TimeLeft < Timeout*0.9}}
    end.
