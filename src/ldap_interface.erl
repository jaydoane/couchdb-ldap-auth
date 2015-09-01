-module(ldap_interface).

-export([authorized_roles/2,
         search_user/1]).

-include_lib("eldap/include/eldap.hrl").

-define(SECTION, "ldap_auth").

-define(CLASS_ATTRIBUTE, "objectClass").

config(servers) ->
    config:get(?SECTION, "servers", ["127.0.0.1"]);
config(port) ->
    config:get_integer(?SECTION, "port", 10389);
config(ssl_port) ->
    config:get_integer(?SECTION, "ssl_port", 10636);
config(use_ssl) ->
    config:get_boolean(?SECTION, "use_ssl", false);
config(connect_timeout) ->
    config:get_integer(?SECTION, "timeout", 5000);

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
    [ldap_auth:decode_role(Role) || Role <- lists:usort(Acc)];
roles(Uid, [#eldap_entry{attributes=Attributes}|Rest], Acc) ->
    Uids = proplists:get_value(config(group_member_attribute), Attributes),
    case lists:member(Uid, Uids) of
        false ->
            roles(Uid, Rest, Acc);
        true ->
            Roles = proplists:get_value(config(group_role_attribute), Attributes),
            roles(Uid, Rest, Acc ++ Roles)
    end.

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
