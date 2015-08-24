%%%-------------------------------------------------------------------
%%% @author dmoore
%%% @copyright (C) 2013, <COMPANY>
%%% @doc
%%%
%%% @end
%%% Created : 13. Oct 2013 6:09 PM
%%%-------------------------------------------------------------------
-module(ldap_auth).
-author("dmoore").
-include("couch_db.hrl").
-include_lib("eldap/include/eldap.hrl").

-define(replace(L, K, V), lists:keystore(K, 1, L, {K, V})).

%% API
-export([handle_basic_auth_req/1, handle_admin_role/1]).
-export([handle_session_req/1]).
%% -export([ldap_authentication_handler/1]).
%% -export([authenticate/3]).
-compile([export_all]).

-import(couch_httpd, [header_value/2, send_json/2, send_json/4, send_method_not_allowed/2]).

-import(ldap_auth_config, [get_config/1]).
-import(ldap_auth_gateway, [connect/0, authenticate/3, get_user_dn/2, get_group_memberships/2]).
%%-import(ldap_auth_gateway, [connect/0, get_user_dn/2, get_group_memberships/2]).

-define(CONFIG_PREFIX, "ldap_auth").
-define(SERVERS_KEY, "servers").
-define(PORT_KEY, "port").
-define(BASE_DN_KEY, "base_dn").

-define(DEFAULT_LDAP_SERVERS, ["127.0.0.1"]).
-define(DEFAULT_LDAP_PORT, 10389).
-define(DEFAULT_BASE_DN, "dc=example,dc=com").


config(servers) ->
    config:get(?CONFIG_PREFIX, ?SERVERS_KEY, ?DEFAULT_LDAP_SERVERS);
config(port) ->
    config:get_integer(?CONFIG_PREFIX, ?PORT_KEY, ?DEFAULT_LDAP_PORT);
config(base_dn) ->
    config:get(?CONFIG_PREFIX, ?BASE_DN_KEY, ?DEFAULT_BASE_DN);
config(search_user_dn) ->
    "uid=ldapsearch,ou=users,dc=example,dc=com"; % FIXME
config(search_user_password) ->
    "secret"; % FIXME
config({user_dn, Uid}) ->
    DNFormat = "uid=~s,ou=users,dc=example,dc=com", % FIXME
    lists:flatten(io_lib:format(DNFormat, [Uid]));
config(group_search_filter) ->
    eldap:equalityMatch("objectClass", "posixGroup"); % FIXME
config(group_search_attributes) ->
    ["memberUid", "description"]; % FIXME
config(group_search) ->
    #eldap_search{base=config(base_dn),
                  filter=config(group_search_filter),
                  attributes=config(group_search_attributes)};
config(group_uid_attribute) ->
    "memberUid"; % FIXME
config(group_role_attribute) ->
    "description"; % FIXME
config(password_attribute) ->
    "userPassword"; % FIXME
config({user_search_filter, Uid}) ->
    eldap:equalityMatch("uid", Uid); % FIXME
config({user_search, Uid}) ->
    #eldap_search{base=config(base_dn),
                  filter=config({user_search_filter, Uid}),
                  attributes=[config(password_attribute)]}; % FIXME
config(_) ->
    throw(unknown_config_key).

open() ->
    Opts = [{port, config(port)}],
    eldap:open(config(servers), Opts).

search_user(Uid) ->
    {ok, Handle} = open(),
    DN = config(search_user_dn),
    Password = config(search_user_password),
    try eldap:simple_bind(Handle, DN, Password) of
        ok ->
            case eldap:search(Handle, config({user_search, Uid})) of
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

auth_roles(Uid, Password) ->
    {ok, Handle} = open(),
    try eldap:simple_bind(Handle, config({user_dn, Uid}), Password) of
        ok ->
            case eldap:search(Handle, config(group_search)) of
                {ok, #eldap_search_result{entries=Entries}} ->
                    {ok, roles(Uid, Entries)};
                Other ->
                    Other
            end;
        Other ->
            Other
    after
        eldap:close(Handle)
    end.

roles(Uid, Entries) ->
    roles(Uid, Entries, []).

roles(_Uid, [], Acc) ->
    lists:usort(Acc);
roles(Uid, [#eldap_entry{attributes=Attributes}|Rest], Acc) ->
    Uids = proplists:get_value(config(group_uid_attribute), Attributes),
    case lists:member(Uid, Uids) of
        false ->
            roles(Uid, Rest, Acc);
        true ->
            Roles = proplists:get_value(config(group_role_attribute), Attributes),
            roles(Uid, Rest, Acc ++ Roles)
    end.

% many functions in here are taken from or based on things here:
% https://github.com/davisp/couchdb/blob/5d4ef93048f4aca24bef00fb5b2c13c54c2bbbb3/src/couchdb/couch_httpd_auth.erl

%% ldap_authentication_handler(Req) ->
%%     case couch_httpd_auth:basic_name_pw(Req) of
%%         {User, Pass} ->
%%             couch_log:notice("ldap_authentication_handler ~p:~p", [User, Pass]),
%%             case authenticate(User, Pass) of
%%                 {ok, Roles} ->
%%                     couch_log:notice("ldap_authentication_handler success ~p", [Roles]),
%%                     Req#httpd{user_ctx = #user_ctx{name = ?l2b(User),
%%                                                    roles = Roles}};
%%                 Other ->
%%                     couch_log:notice("ldap_authentication_handler fail ~p", [Other]),
%%                     Req
%%             end;
%%         _ ->
%%             Req
%%     end.

handle_basic_auth_req(Req) ->
  case basic_name_pw(Req) of
    {UserName, Password} ->
      case authenticate_user(UserName, Password) of
        {ok, Roles} ->
          Req#httpd{
            user_ctx = #user_ctx {
              name = ?l2b(UserName),
              roles = Roles
            }
          };
        _ -> Req
      end;
    nil ->
      Req
  end.

handle_admin_role(Req) ->
  % This is a workaround pending a resolution to https://issues.apache.org/jira/browse/COUCHDB-2034
  [AuthenticationHandlers] = get_config(["AuthenticationHandlers"]),
  {ok, Tokens, _} = erl_scan:string("[" ++ AuthenticationHandlers ++ "]."),
  {ok, Term} = erl_parse:parse_term(Tokens),
  AuthedReq = run_auth_handlers(Req, Term),
  prepend_admin_role(AuthedReq).

prepend_admin_role(#httpd{ user_ctx = #user_ctx{ name = User, roles = Roles } = UserCtx } = Req) when length(Roles) > 0 ->
  [SystemAdminRoleName] = get_config(["SystemAdminRoleName"]),
  ?LOG_DEBUG("Checking for system admin role ~p for user ~p with roles: ~p", [ SystemAdminRoleName, User, Roles ]),
  case lists:member(?l2b(SystemAdminRoleName), Roles) of
    true -> Req#httpd{ user_ctx = UserCtx#user_ctx{ roles = [<<"_admin">>|Roles] } };
    _ -> Req
  end;
prepend_admin_role(#httpd{} = Req) -> Req.

run_auth_handlers(Req, []) -> Req;
run_auth_handlers(Req, [ {Mod, Fun} | Rem]) -> run_auth_handlers(Mod:Fun(Req), Rem);
run_auth_handlers(Req, [ {Mod, Fun, SpecArg} | Rem]) -> run_auth_handlers(Mod:Fun(Req, SpecArg), Rem).

% session handlers
% Login handler with user db
handle_session_req(#httpd{method='POST', mochi_req=MochiReq}=Req) ->
  {UserName, Password} = get_req_credentials(Req),
  ?LOG_DEBUG("Attempt Login: ~s",[UserName]),
  User = case couch_auth_cache:get_user_creds(UserName) of
           nil -> [];
           Result -> Result
         end,
  UserSalt = couch_util:get_value(<<"salt">>, User, <<>>),
  case authenticate_user(UserName, Password) of
    {ok, Roles} ->
      set_user_roles(UserName, Roles),

      % setup the session cookie
      Secret = ?l2b(ensure_cookie_auth_secret()),
      CurrentTime = make_cookie_time(),
      Cookie = cookie_auth_cookie(Req, ?b2l(UserName), <<Secret/binary, UserSalt/binary>>, CurrentTime),
      % TODO document the "next" feature in Futon
      {Code, Headers} = redirect_or_default(Req, "next", {200, [Cookie]}),
      send_json(Req#httpd{req_body=MochiReq:recv_body()}, Code, Headers,
        {[
          {ok, true},
          {name, UserName},
          {roles, Roles}
        ]});
    _Else ->
      % clear the session
      Cookie = mochiweb_cookies:cookie("AuthSession", "", [{path, "/"}] ++ cookie_scheme(Req)),
      {Code, Headers} = redirect_or_default(Req, "fail", {401, [Cookie]}),
      send_json(Req, Code, Headers, {[{error, <<"unauthorized">>},{reason, <<"Name or password is incorrect.">>}]})
  end;
% get user info
% GET /_session
handle_session_req(#httpd{method='GET', user_ctx=UserCtx}=Req) ->
  Name = UserCtx#user_ctx.name,
  ForceLogin = couch_httpd:qs_value(Req, "basic", "false"),
  case {Name, ForceLogin} of
    {null, "true"} ->
      throw({unauthorized, <<"Please login.">>});
    {Name, _} ->
      send_json(Req, {[
        % remove this ok
        {ok, true},
        {<<"userCtx">>, {[
          {name, Name},
          {roles, UserCtx#user_ctx.roles}
        ]}},
        {info, {get_auth_info(Req)}}
      ]})
  end;
% logout by deleting the session
handle_session_req(#httpd{method='DELETE'}=Req) ->
  Cookie = mochiweb_cookies:cookie("AuthSession", "", [{path, "/"}] ++ cookie_scheme(Req)),
  {Code, Headers} = redirect_or_default(Req, "next", {200, [Cookie]}),
  send_json(Req, Code, Headers, {[{ok, true}]});
handle_session_req(Req) ->
  send_method_not_allowed(Req, "GET,HEAD,POST,DELETE").

auth_name(String) when is_list(String) ->
  [_,_,_,_,_,Name|_] = re:split(String, "[\\W_]", [{return, list}]),
  ?l2b(Name).

redirect_or_default(Req, RedirectHeaderKey, {_DefaultCode, DefaultHeaders} = Default) ->
  case couch_httpd:qs_value(Req, RedirectHeaderKey, nil) of
    nil -> Default;
    Redirect ->
      {302, DefaultHeaders ++ {"Location", couch_httpd:absolute_uri(Req, Redirect)}}
  end.

ensure_cookie_auth_secret() ->
  case couch_config:get("couch_httpd_auth", "secret", nil) of
    nil ->
      NewSecret = ?b2l(couch_uuids:random()),
      couch_config:set("couch_httpd_auth", "secret", NewSecret),
      NewSecret;
    Secret -> Secret
  end.

make_cookie_time() ->
  {NowMS, NowS, _} = erlang:now(),
  NowMS * 1000000 + NowS.

cookie_scheme(#httpd{mochi_req=MochiReq}) ->
  [{http_only, true}] ++
  case MochiReq:get(scheme) of
    http -> [];
    https -> [{secure, true}]
  end.

cookie_auth_cookie(Req, User, Secret, TimeStamp) ->
  SessionData = User ++ ":" ++ erlang:integer_to_list(TimeStamp, 16),
  Hash = crypto:hmac(sha, Secret, SessionData),
  mochiweb_cookies:cookie("AuthSession",
    couch_util:encodeBase64Url(SessionData ++ ":" ++ ?b2l(Hash)),
    [{path, "/"}] ++ cookie_scheme(Req) ++ max_age()).

max_age() ->
  case couch_config:get("couch_httpd_auth", "allow_persistent_cookies", "false") of
    "false" ->
      [];
    "true" ->
      Timeout = list_to_integer(
        couch_config:get("couch_httpd_auth", "timeout", "600")),
      [{max_age, Timeout}]
  end.

get_auth_info(#httpd{ user_ctx = #user_ctx { handler = Handler } }) ->
  [
    {authentication_db, ?l2b(couch_config:get("couch_httpd_auth", "authentication_db"))},
    {authentication_handlers, [auth_name(H) || H <- couch_httpd:make_fun_spec_strs(
      couch_config:get("httpd", "authentication_handlers"))]}
  ] ++
  case Handler of
    undefined -> [];
    Handler -> [{ authenticated, auth_name(?b2l(Handler)) }]
  end.

get_req_credentials(#httpd{method='POST', mochi_req=MochiReq}) ->
  ReqBody = MochiReq:recv_body(),
  Form = case MochiReq:get_primary_header_value("content-type") of
           % content type should be json
           "application/x-www-form-urlencoded" ++ _ ->
             mochiweb_util:parse_qs(ReqBody);
           "application/json" ++ _ ->
             {Pairs} = ?JSON_DECODE(ReqBody),
             [{?b2l(Key), ?b2l(Value)} || {Key, Value} <- Pairs];
           _ ->
             []
         end,
  UserName = ?l2b(couch_util:get_value("name", Form, "")),
  Password = ?l2b(couch_util:get_value("password", Form, "")),
  {UserName, Password}.

set_user_roles(UserName, Roles) ->
  ?LOG_INFO("Assigning user ~s roles: ~p", [UserName, Roles]),

  DbName = ?l2b(couch_config:get("couch_httpd_auth", "authentication_db")),
  DbOptions = [{user_ctx, #user_ctx{roles = [<<"_admin">>]}}],
  {ok, AuthDb} = couch_db:open_int(DbName, DbOptions),

  DocId =  <<<<"org.couchdb.user:">>/binary, UserName/binary>>,
  Doc = case couch_db:open_doc(AuthDb, DocId, [ejson_body]) of
          {ok, OldDoc = #doc{body = {DocBody}}} ->
            OldDoc#doc{
              body = {?replace(DocBody, <<"roles">>, Roles)}
            };
          {not_found, _} ->
            #doc{
              id = DocId,
              body = {[
                {'_id', DocId},
                {type, <<"user">>},
                {name, UserName},
                {salt, couch_uuids:random()},
                {roles, Roles}
              ]}
            }
        end,

  ?LOG_INFO("Assigning _users/~s roles ~p", [DocId, Roles]),

  % disable validation so we can put _admin in the _users db.
  case couch_db:update_doc(AuthDb#db{ validate_doc_funs=[] }, Doc, []) of
    {ok, _} -> ok;
    {error, _} = Error -> throw(Error)
  end.

authenticate_user(_UserName, _Password) when _UserName == <<"">>; _Password == <<"">> ->
  {error, missing_user_name_or_password};
authenticate_user(UserName, Password) ->
  ?LOG_INFO("Authenticating user: ~p", [UserName]),
  case connect() of
    {error, Reason} = Error ->
      ?LOG_ERROR("Could not connect to LDAP. Reason: ~p", [Reason]),
      Error;
    {ok, LdapConnection} ->
      case authenticate(LdapConnection, UserName, Password) of
        {error, Reason} = Error ->
          ?LOG_ERROR("Could not authenticate user ~p over LDAP. Reason: ~p", [UserName, Reason]),
          Error;
        {ok, UserDN} ->
          Groups = get_group_memberships(LdapConnection, UserDN),
          eldap:close(LdapConnection),
          {ok, [ ?l2b(string:to_lower(G)) || G <- Groups ]}
      end
  end.

basic_name_pw(Req) ->
  AuthorizationHeader = couch_httpd:header_value(Req, "Authorization"),
  case AuthorizationHeader of
    "Basic " ++ Base64Value ->
      case re:split(base64:decode(Base64Value), ":",
        [{return, list}, {parts, 2}]) of
        ["_", "_"] ->
          % special name and pass to be logged out
          nil;
        [User, Pass] ->
          {User, Pass};
        _ ->
          nil
      end;
    _ ->
      ?LOG_INFO("Could not recognize auth header ~p", [AuthorizationHeader]),
      nil
  end.
