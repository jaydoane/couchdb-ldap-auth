-module(ldap_auth).
-author("jdoane@us.ibm.com").

-include_lib("couch/include/couch_db.hrl").
-include_lib("eldap/include/eldap.hrl").

%% API

-export([default_authentication_handler/1,
         handle_session_req/1]).

-compile([export_all]). % FIXME

-define(SESSION_COOKIE, "LDAPAuthSession").
-define(TIMESTAMP_ENCODE_BASE, 16).

-define(SECTION, "ldap_auth").

-define(CLASS_ATTRIBUTE, "objectClass").

config(servers) ->
    config:get(?SECTION, "servers", ["127.0.0.1"]);
config(port) ->
    config:get_integer(?SECTION, "port", 10389);
config(ssl_port) ->
    config:get_integer(?SECTION, "ssl_port", 10636);
config(use_ssl) ->
    list_to_existing_atom(config:get(?SECTION, "use_ssl", "false"));
config(connect_timeout) ->
    config:get_integer(?SECTION, "timeout", 5000);
config(cookie_timeout) ->
    config:get_integer("couch_httpd_auth", "timeout", 600);

config(user_base_dn) ->
    config:get(?SECTION, "user_base_dn", "ou=users,dc=example,dc=com");
config(user_uid_attribute) ->
    config:get(?SECTION, "user_uid_attribute", "uid");
config(user_password_attribute) ->
    config:get(?SECTION, "user_password_attribute", "userPassword");

config(group_base_dn) ->
    config:get(?SECTION, "group_base_dn", "ou=groups,dc=example,dc=com");
config(group_search_class) ->
    config:get(?SECTION, "group_search_class", "posixGroup");
config(group_member_attribute) ->
    config:get(?SECTION, "group_member_attribute", "memberUid");
config(group_role_attribute) ->
    config:get(?SECTION, "group_role_attribute", "description");

%% FIXME search_user hopefully unnecessary...
config(search_user_dn) ->
    config:get(?SECTION, "search_user_dn",
               "uid=ldapsearch,ou=users,dc=example,dc=com");
config(search_user_password) ->
    config:get(?SECTION, "search_user_password", "secret");

config(secret) ->
    case config:get("couch_httpd_auth", "secret", undefined) of
        undefined ->
            undefined;
        Str when is_list(Str) ->
            ?l2b(Str)
    end;

config(_) ->
    throw(unknown_config_param).



user_dn(Uid) ->
    Prefix = io_lib:format("~s=~s,", [config(user_uid_attribute), Uid]),
    lists:flatten([Prefix, config(user_base_dn)]).

user_search(Uid) ->
    Filter = eldap:equalityMatch(config(user_uid_attribute), Uid),
    #eldap_search{base=config(user_base_dn),
                  filter=Filter,
                  attributes=[config(user_password_attribute)]}.

group_search() ->
    %% FIXME to support multiple group search classes
    Filter = eldap:equalityMatch(?CLASS_ATTRIBUTE, config(group_search_class)),
    #eldap_search{base=config(group_base_dn),
                  filter=Filter,
                  attributes=[config(group_member_attribute),
                              config(group_role_attribute)]}.

open() ->
    BaseOpts = [{timeout, config(connect_timeout)}],
    Opts = case config(use_ssl) of
               true ->
                   [{ssl, true},
                    {port, config(ssl_port)}];
               false ->
                   [{port, config(port)}]
           end ++ BaseOpts,
    eldap:open(config(servers), Opts).


authorized_roles(Uid, Password) ->
    {ok, Handle} = open(),
    try eldap:simple_bind(Handle, user_dn(Uid), Password) of
        ok ->
            case eldap:search(Handle, group_search()) of
                {ok, #eldap_search_result{entries=Entries}} ->
                    {ok, roles(Uid, Entries)};
                Else ->
                    Else
            end;
        Else ->
            Else
    after
        eldap:close(Handle)
    end.

roles(Uid, Entries) ->
    roles(Uid, Entries, []).

roles(_Uid, [], Acc) ->
    [fixup_role(Role) || Role <- lists:usort(Acc)];
roles(Uid, [#eldap_entry{attributes=Attributes}|Rest], Acc) ->
    Uids = proplists:get_value(config(group_member_attribute), Attributes),
    case lists:member(Uid, Uids) of
        false ->
            roles(Uid, Rest, Acc);
        true ->
            Roles = proplists:get_value(config(group_role_attribute), Attributes),
            roles(Uid, Rest, Acc ++ Roles)
    end.

fixup_role("server_admin") ->
    server_admin;
fixup_role(Role) when is_list(Role) ->
    ?l2b(Role).

search_user(Uid) ->
    {ok, Handle} = open(),
    DN = config(search_user_dn),
    Password = config(search_user_password),
    try eldap:simple_bind(Handle, DN, Password) of
        ok ->
            case eldap:search(Handle, user_search(Uid)) of
                {ok, #eldap_search_result{
                        entries=[#eldap_entry{
                                    attributes=[{_, [EncodedPassword]}]}]}} ->
                    {ok, EncodedPassword};
                Error ->
                    Error
            end;
        Error ->
            Error
    after
        eldap:close(Handle)
    end.

default_authentication_handler(Req) ->
    case couch_httpd_auth:basic_name_pw(Req) of
        {Username, Password} ->
            couch_log:notice("ldap_authentication_handler ~p:~p",
                             [Username, Password]),
            case authorized_roles(Username, Password) of
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
    case authorized_roles(Username, Password) of
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
    [fixup_role(Role) || Role <- re:split(RolesStr, ",", [{return, list}])].


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
