%% Copyright (c) 2012, Travelping GmbH <info@travelping.com>
%% All rights reserved.
%%
%% Redistribution and use in source and binary forms, with or without
%% modification, are permitted provided that the following conditions
%% are met:
%%
%% Redistributions of source code must retain the above copyright
%% notice, this list of conditions and the following disclaimer.
%%
%% Redistributions in binary form must reproduce the above copyright
%% notice, this list of conditions and the following disclaimer in the
%% documentation and/or other materials provided with the distribution.
%%
%% Neither the name of the author nor the names of its contributors
%% may be used to endorse or promote products derived from this software
%% without specific prior written permission.
%%
%% THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
%% "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
%% LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS
%% FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE
%% COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT,
%% INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING,
%% BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
%% LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER
%% CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
%% LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN
%% ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
%% POSSIBILITY OF SUCH DAMAGE.

-module(gen_socket).
-include("gen_socket.hrl").

-on_load(init/0).

-export([controlling_process/2, socket/3, socketat/4,
	 raw_socket/3, raw_socketat/4, getsocktype/1,
	 getsockopt/3, getsockopt/4, getsockopt/5, setsockopt/4,
         getsockname/1, getpeername/1, bind/2, connect/2, accept/1,
	 input_event/2, output_event/2,
         recv/1, recv/2, recvmsg/2, recvmsg/3, recvfrom/1, recvfrom/2,
         send/2, sendto/3,
	 read/1, read/2, write/2,
	 getfd/1,
         listen/2, ioctl/3,
         shutdown/2, close/1]).
-export([family/1, type/1, protocol/1, arphdr/1]).

%% for debugging/testing only
-export([nif_encode_sockaddr/1, nif_decode_sockaddr/1]).

-export_type([socket/0,
              option_level/0, option_name/0, prim_socket_option/0, protocol_name/0,
              port_number/0, sockaddr/0]).

-record(gen_socket, {port, fd, family, type, protocol}).

-opaque socket() :: #gen_socket{} | integer().
-define(IS_SOCKET(Term),
	(is_record(Term, gen_socket) andalso
	 is_port(Term#gen_socket.port))).
-define(IS_NIF_SOCKET(Term),
	(?IS_SOCKET(Term) orelse is_integer(Term))).

-define(IS_TIMEOUT(Term),
    ((Term == infinity) orelse (is_integer(Term) andalso Term >= 0))).

%% DRIVER CONSTANTS (calls, etc.), see ../c_src/gen_socket_drv.c
-define(GS_CALL_SETSOCKET,   $S).
-define(GS_CALL_POLL_INPUT,  $I).
-define(GS_CALL_POLL_OUTPUT, $O).

-type option_level() :: sol_socket | protocol_name() | integer().
-type option_name() :: prim_socket_option() | integer().
-type prim_socket_option() ::
    so_debug | so_reuseaddr | so_type | so_error |
    so_dontroute | so_broadcast | so_sndbuf | so_rcvbuf.

-type port_number() :: 0..65535.
-type sockaddr() :: {unix, Path::iodata()}
                  | {inet4, inet:ip4_address(), port_number()}
                  | {unknown, binary()}.

-type posix_error() :: file:posix().

%% Must be after exports (function definitions)
-include("gen_socket_shared.hrl").

init() ->
    LibDir = filename:join([filename:dirname(code:which(?MODULE)), "..", "priv", "lib"]),

    %% load our nif library
    case erlang:load_nif(filename:join(LibDir, "gen_socket_nif"), 0) of
        ok ->
            ok;
        {error, {reload, _}} ->
            ok;
        {error, Error} ->
            error_logger:error_msg("could not load gen_socket nif library: ~p", [Error]),
            error({load_nif, Error})
    end,

    %% load our driver
    erl_ddll:start(),
    case erl_ddll:load_driver(LibDir, "gen_socket") of
        ok ->
            ok;
        {error, permanent} ->
            ok;
        {error, ErrorDesc} ->
            {load_driver_error, erl_ddll:format_error(ErrorDesc)}
    end.

%% internal accessors
-compile([{inline, nif_socket_of/1}, {inline, port_of/1}]).
nif_socket_of(Fd) when is_integer(Fd) -> Fd;
nif_socket_of(#gen_socket{fd = Fd}) -> Fd.
port_of(#gen_socket{port = Port}) -> Port.

%% -------------------------------------------------------------------------------------------------
%% -- Socket API
-spec controlling_process(socket(), pid()) -> {ok, OldOwner} | {error, closed}
    when OldOwner :: pid().
controlling_process(Socket, NewOwner) when ?IS_SOCKET(Socket) ->
    case erlang:port_info(port_of(Socket), connected) of
        undefined ->
            {error, closed};
        {connected, OldOwner} ->
            erlang:port_connect(port_of(Socket), NewOwner),
            {ok, OldOwner}
    end;
controlling_process(Socket, NewOwner) ->
    error(badarg, [Socket, NewOwner]).

-spec getfd(socket()) -> integer().
getfd(Socket) ->
    nif_socket_of(Socket).

-spec close(socket()) -> ok.
close(Socket) when is_integer(Socket) ->
    nif_close(Socket);
close(Socket) when ?IS_SOCKET(Socket) ->
    erlang:port_close(port_of(Socket)),
    nif_close(nif_socket_of(Socket));
close(Socket) ->
    error(badarg, [Socket]).

-spec shutdown(socket(), read | write | read_write) -> ok.
shutdown(Socket, read) when ?IS_NIF_SOCKET(Socket) ->
    nif_shutdown(nif_socket_of(Socket), 0);
shutdown(Socket, write) when ?IS_NIF_SOCKET(Socket) ->
    nif_shutdown(nif_socket_of(Socket), 1);
shutdown(Socket, read_write) when ?IS_NIF_SOCKET(Socket) ->
    nif_shutdown(nif_socket_of(Socket), 2);
shutdown(Socket, How) ->
    error(badarg, [Socket, How]).

-spec socket(term(), term(), term()) -> {ok, socket()} | {error, term()}.
socket(Family0, Type0, Protocol0) ->
    raw_socket(Family0, Type0, Protocol0,
	       fun(Family, Type, Protocol, Fd) ->
		       CmdStr = lists:flatten(io_lib:format("gen_socket ~w", [Fd])),
		       Port = open_port({spawn_driver, CmdStr}, [binary]),
		       Socket = #gen_socket{port = Port, fd = Fd, family = Family, type = Type, protocol = Protocol},
		       erlang:port_call(Port, ?GS_CALL_SETSOCKET, Socket),
		       {ok, Socket}
	       end).

-spec raw_socket(term(), term(), term()) -> {ok, socket()} | {error, term()}.
raw_socket(Family, Type, Protocol) ->
    raw_socket(Family, Type, Protocol, fun(_,_,_,Fd) -> {ok, Fd} end).

raw_socket(Family, Type, Protocol, PostFun) when is_atom(Family) ->
    raw_socket(family(Family), Type, Protocol, PostFun);
raw_socket(Family, Type, Protocol, PostFun) when is_atom(Type) ->
    raw_socket(Family, type(Type), Protocol, PostFun);
raw_socket(Family, Type, Protocol, PostFun) when is_atom(Protocol) ->
    raw_socket(Family, Type, protocol(Protocol), PostFun);
raw_socket(Family, Type, Protocol, PostFun) when is_integer(Family), is_integer(Type), is_integer(Protocol) ->
    ok     = init(), %% TODO: make this unnecessary by fixing the on_load handler
    case nif_socket(Family, Type, Protocol) of
	{ok, Fd} ->
	    PostFun(Family, Type, Protocol, Fd);
	Error ->
	    Error
    end;
raw_socket(Family, Type, Protocol, _PostFun) ->
    error(badarg, [Family, Type, Protocol]).

-spec socketat(term(), term(), term(), term()) -> {ok, socket()} | {error, term()}.
socketat(NetNsFile0, Family0, Type0, Protocol0) ->
    raw_socketat(NetNsFile0, Family0, Type0, Protocol0,
		 fun(_, Family, Type, Protocol, Fd) ->
			 CmdStr = lists:flatten(io_lib:format("gen_socket ~w", [Fd])),
			 Port = open_port({spawn_driver, CmdStr}, [binary]),
			 Socket = #gen_socket{port = Port, fd = Fd, family = Family, type = Type, protocol = Protocol},
			 erlang:port_call(Port, ?GS_CALL_SETSOCKET, Socket),
			 {ok, Socket}
		 end).

-spec raw_socketat(term(), term(), term(), term()) -> {ok, socket()} | {error, term()}.
raw_socketat(NetNsFile, Family, Type, Protocol) ->
    raw_socketat(NetNsFile, Family, Type, Protocol, fun(_,_,_,_,Fd) -> {ok, Fd} end).

raw_socketat(NetNsFile, Family, Type, Protocol, PostFun) when is_list(NetNsFile) ->
    raw_socketat(iolist_to_binary(NetNsFile), Family, Type, Protocol, PostFun);
raw_socketat(NetNsFile, Family, Type, Protocol, PostFun) when is_atom(Family) ->
    raw_socketat(NetNsFile, family(Family), Type, Protocol, PostFun);
raw_socketat(NetNsFile, Family, Type, Protocol, PostFun) when is_atom(Type) ->
    raw_socketat(NetNsFile, Family, type(Type), Protocol, PostFun);
raw_socketat(NetNsFile, Family, Type, Protocol, PostFun) when is_atom(Protocol) ->
    raw_socketat(NetNsFile, Family, Type, protocol(Protocol), PostFun);
raw_socketat(NetNsFile, Family, Type, Protocol, PostFun) when is_binary(NetNsFile), is_integer(Family), is_integer(Type), is_integer(Protocol) ->
    ok     = init(), %% TODO: make this unnecessary by fixing the on_load handler
    case nif_socketat(NetNsFile, Family, Type, Protocol) of
	{ok, Fd} ->
	    PostFun(NetNsFile, Family, Type, Protocol, Fd);
	Error ->
	    Error
    end;
raw_socketat(NetNsFile, Family, Type, Protocol, _PostFun) ->
    error(badarg, [NetNsFile, Family, Type, Protocol]).

%% @doc Get the family, type, and protocol of a socket.
getsocktype(#gen_socket{family = Family, type = Type, protocol = Protocol}) ->
    {family_to_atom(Family), type_to_atom(Type), protocol_to_atom(Protocol)};
getsocktype(Socket) ->
    error(badarg, [Socket]).

-spec getsockopt(socket(), option_level(), option_name()) -> {ok, Value} | {error, Error}
    when Value :: binary(),
         Error :: closed | enoprotoopt | enotsup.
getsockopt(Socket, Level, OptName) when is_atom(Level) ->
    getsockopt(Socket, opt_level_to_int(Level), OptName);
getsockopt(Socket, Level, OptName) when is_integer(Level), is_atom(OptName) ->
    getsockopt(Socket, Level, opt_name_to_int(Level, OptName));
getsockopt(Socket, ?SOL_SOCKET, ?SO_ERROR) when ?IS_NIF_SOCKET(Socket) ->
    nif_getsock_error(nif_socket_of(Socket));
getsockopt(Socket, Level, OptName) when ?IS_NIF_SOCKET(Socket), is_integer(Level), is_integer(OptName) ->
    OptLen = sockopt_len(Level, OptName),
    decode_sockopt(Level, OptName, nif_getsockopt(nif_socket_of(Socket), Level, OptName, <<>>, OptLen));
getsockopt(Socket, Level, OptName) ->
    error(badarg, [Socket, Level, OptName]).

-spec getsockopt(socket(), option_level(), option_name(), integer() | binary()) -> {ok, Value} | {error, Error}
    when Value :: binary(),
         Error :: closed | enoprotoopt | enotsup.
getsockopt(Socket, Level, OptName, Opt) when is_binary(Opt) ->
    getsockopt(Socket, Level, OptName, Opt, size(Opt));
getsockopt(Socket, Level, OptName, OptLen) when is_atom(Level) ->
    getsockopt(Socket, opt_level_to_int(Level), OptName, OptLen);
getsockopt(Socket, Level, OptName, OptLen) when is_integer(Level), is_atom(OptName) ->
    getsockopt(Socket, Level, opt_name_to_int(Level, OptName), OptLen);
getsockopt(Socket, ?SOL_SOCKET, ?SO_ERROR, _) when ?IS_NIF_SOCKET(Socket) ->
    nif_getsock_error(nif_socket_of(Socket));
getsockopt(Socket, Level, OptName, OptLen) when ?IS_NIF_SOCKET(Socket), is_integer(Level), is_integer(OptName), is_integer(OptLen), OptLen > 0 ->
    nif_getsockopt(nif_socket_of(Socket), Level, OptName, <<>>, OptLen);
getsockopt(Socket, Level, OptName, OptLen) ->
    error(badarg, [Socket, Level, OptName, OptLen]).

-spec getsockopt(socket(), option_level(), option_name(), binary(), integer()) -> {ok, Value} | {error, Error}
    when Value :: binary(),
         Error :: closed | enoprotoopt | enotsup.
getsockopt(Socket, Level, OptName, Opt, OptLen) when is_atom(Level) ->
    getsockopt(Socket, opt_level_to_int(Level), OptName, Opt, OptLen);
getsockopt(Socket, Level, OptName, Opt, OptLen) when is_integer(Level), is_atom(OptName) ->
    getsockopt(Socket, Level, opt_name_to_int(Level, OptName), Opt, OptLen);
getsockopt(Socket, ?SOL_SOCKET, ?SO_ERROR, _, _) when ?IS_NIF_SOCKET(Socket) ->
    nif_getsock_error(nif_socket_of(Socket));
getsockopt(Socket, Level, OptName, Opt, OptLen) when ?IS_NIF_SOCKET(Socket), is_integer(Level), is_integer(OptName), is_binary(Opt), is_integer(OptLen), OptLen > 0 ->
    nif_getsockopt(nif_socket_of(Socket), Level, OptName, Opt, OptLen);
getsockopt(Socket, Level, OptName, Opt, OptLen) ->
    error(badarg, [Socket, Level, OptName, Opt, OptLen]).

-spec setsockopt(socket(), option_level(), option_name(), Value) -> ok | {error, Error}
    when Value :: boolean() | integer() | binary(),
         Error :: closed | enoprotoopt | enotsup | einval.
setsockopt(Socket, Level, OptName, Val) when is_atom(Level) ->
    setsockopt(Socket, opt_level_to_int(Level), OptName, Val);
setsockopt(Socket, Level, OptName, Val) when is_integer(Level), is_atom(OptName) ->
    setsockopt(Socket, Level, opt_name_to_int(Level, OptName), Val);
setsockopt(Socket, Level, OptName, true) ->
    setsockopt(Socket, Level, OptName, <<1:32/native-integer>>);
setsockopt(Socket, Level, OptName, false) ->
    setsockopt(Socket, Level, OptName, <<0:32/native-integer>>);
setsockopt(Socket, Level, OptName, Val) when is_integer(Val) ->
    setsockopt(Socket, Level, OptName, <<Val:32/native-integer>>);
setsockopt(Socket, Level, OptName, Val) when ?IS_NIF_SOCKET(Socket), is_binary(Val) ->
    nif_setsockopt(nif_socket_of(Socket), Level, OptName, Val);
setsockopt(Socket, Level, OptName, Val) ->
    error(badarg, [Socket, Level, OptName, Val]).

-spec getsockname(socket()) -> {ok, sockaddr()} | {error, closed}.
getsockname(Socket) when ?IS_NIF_SOCKET(Socket) ->
    nif_getsockname(nif_socket_of(Socket));
getsockname(Socket) ->
    error(badarg, [Socket]).

-spec getpeername(socket()) -> {ok, sockaddr()} | {error, closed}.
getpeername(Socket) when ?IS_NIF_SOCKET(Socket) ->
    nif_getpeername(nif_socket_of(Socket));
getpeername(Socket) ->
    error(badarg, [Socket]).

-spec bind(socket(), sockaddr()) -> ok | {error, atom()}.
bind(Socket, Address) when ?IS_NIF_SOCKET(Socket) ->
    nif_bind(nif_socket_of(Socket), Address);
bind(Socket, _) ->
    error(badarg, [Socket]).

-spec connect(socket(), sockaddr()) -> ok | {error, atom()}.
connect(Socket, Address) when ?IS_NIF_SOCKET(Socket) ->
    nif_connect(nif_socket_of(Socket), Address);
connect(Socket, _) ->
    error(badarg, [Socket]).

-spec accept(socket()) -> ok | {error, atom()}.
accept(Socket) when ?IS_NIF_SOCKET(Socket) ->
    nif_accept(nif_socket_of(Socket));
accept(Socket) ->
    error(badarg, [Socket]).

input_event(Socket, Set) when ?IS_SOCKET(Socket), is_boolean(Set) ->
    erlang:port_call(port_of(Socket), ?GS_CALL_POLL_INPUT, Set);
input_event(Socket, Set) ->
    error(badarg, [Socket, Set]).

output_event(Socket, Set) when ?IS_SOCKET(Socket), is_boolean(Set) ->
    erlang:port_call(port_of(Socket), ?GS_CALL_POLL_OUTPUT, Set);
output_event(Socket, Set) ->
    error(badarg, [Socket, Set]).

-spec recv(socket()) -> {ok, binary()} | {error, closed} | {error, posix_error()}.
recv(Socket) when ?IS_NIF_SOCKET(Socket) ->
    nif_recv(nif_socket_of(Socket), -1).

-spec recv(socket(), non_neg_integer()) -> {ok, binary()} | {error, closed} | {error, posix_error()}.
recv(Socket, Length) when ?IS_NIF_SOCKET(Socket), is_integer(Length), Length > 0 ->
    nif_recv(nif_socket_of(Socket), Length);
recv(Socket, Length) ->
    error(badarg, [Socket, Length]).

-spec recvmsg(socket(), non_neg_integer()) -> {ok, Sender, CMsg, Data} | {error, closed} | {error, posix_error()}
    when Sender :: sockaddr(), CMsg :: list(), Data :: binary().
recvmsg(Socket, Flag) when ?IS_NIF_SOCKET(Socket) ->
    nif_recvmsg(nif_socket_of(Socket), Flag, -1);
recvmsg(Socket, Flag) ->
    error(badarg, [Socket, Flag]).

-spec recvmsg(socket(), non_neg_integer(), non_neg_integer()) -> {ok, Sender, CMsg, Data} | {error, closed} | {error, posix_error()}
    when Sender :: sockaddr(), CMsg :: list(), Data :: binary().
recvmsg(Socket, Flag, Length) when ?IS_NIF_SOCKET(Socket), is_integer(Length), Length > 0 ->
    nif_recvmsg(nif_socket_of(Socket), Flag, Length);
recvmsg(Socket, Flag, Length) ->
    error(badarg, [Socket, Flag, Length]).

-spec recvfrom(socket()) -> {ok, Sender, Data} | {error, closed} | {error, posix_error()}
    when Sender :: sockaddr(), Data :: binary().
recvfrom(Socket) when ?IS_NIF_SOCKET(Socket) ->
    nif_recvfrom(nif_socket_of(Socket), -1);
recvfrom(Socket) ->
    error(badarg, [Socket]).

-spec recvfrom(socket(), non_neg_integer()) -> {ok, Sender, Data} | {error, closed} | {error, posix_error()}
    when Sender :: sockaddr(), Data :: binary().
recvfrom(Socket, Length) when ?IS_NIF_SOCKET(Socket), is_integer(Length), Length > 0 ->
    nif_recvfrom(nif_socket_of(Socket), Length);
recvfrom(Socket, Length) ->
    error(badarg, [Socket, Length]).

-spec send(socket(), iolist()) -> ok.
send(Socket, Data) when ?IS_NIF_SOCKET(Socket) ->
    nif_send(nif_socket_of(Socket), Data, 0);
send(Socket, Data) ->
    error(badarg, [Socket, Data]).

-spec sendto(socket(), sockaddr(), iolist()) -> ok.
sendto(Socket, Address, Data) when ?IS_NIF_SOCKET(Socket), is_binary(Data) ->
    nif_sendto(nif_socket_of(Socket), Data, 0, Address);
sendto(Socket, Address, Data) ->
    error(badarg, [Socket, Address, Data]).

-spec read(socket()) -> {ok, binary()} | {error, closed} | {error, posix_error()}.
read(Socket) when ?IS_NIF_SOCKET(Socket) ->
    nif_read(nif_socket_of(Socket), -1).

-spec read(socket(), non_neg_integer()) -> {ok, binary()} | {error, closed} | {error, posix_error()}.
read(Socket, Length) when ?IS_NIF_SOCKET(Socket), is_integer(Length), Length > 0 ->
    nif_read(nif_socket_of(Socket), Length);
read(Socket, Length) ->
    error(badarg, [Socket, Length]).

-spec write(socket(), iolist()) -> ok.
write(Socket, Data) when ?IS_NIF_SOCKET(Socket) ->
    nif_write(nif_socket_of(Socket), Data);
write(Socket, Data) ->
    error(badarg, [Socket, Data]).

-spec listen(socket(), pos_integer()) -> ok | {error, closed} | {error, posix_error()}.
listen(Socket, Backlog) when ?IS_NIF_SOCKET(Socket), is_integer(Backlog), Backlog >= 0 ->
    nif_listen(nif_socket_of(Socket), Backlog);
listen(Socket, Backlog) ->
    error(badarg, [Socket, Backlog]).

-spec ioctl(socket(), integer(), binary()) -> ok | {error, closed} | {error, posix_error()}.
ioctl(Socket, Request, Data) when ?IS_NIF_SOCKET(Socket), is_integer(Request), is_binary(Data) ->
    nif_ioctl(nif_socket_of(Socket), Request, Data);
ioctl(Socket, Request, Data) ->
    error(badarg, [Socket, Request, Data]).

%% -------------------------------------------------------------------------------------------------
%% -- NIF stubs
nif_encode_sockaddr(_Sockaddr) ->
    error(nif_not_loaded).
nif_decode_sockaddr(_Sockaddr) ->
    error(nif_not_loaded).

nif_socket(_Family, _Type, _Protocol) ->
    error(nif_not_loaded).
nif_socketat(_NetNsFile, _Family, _Type, _Protocol) ->
    error(nif_not_loaded).
nif_close(_NifSocket) ->
    error(nif_not_loaded).
nif_getsockname(_NifSocket) ->
    error(nif_not_loaded).
nif_getpeername(_NifSocket) ->
    error(nif_not_loaded).
nif_setsockopt(_NifSocket, _Level, _Name, _Val) ->
    error(nif_not_loaded).
nif_getsockopt(_NifSocket, _Level, _Name, _Opt, _OptLen) ->
    error(nif_not_loaded).
nif_getsock_error(_NifSocket) ->
    error(nif_not_loaded).
nif_bind(_NifSocket, _Address) ->
    error(nif_not_loaded).
nif_connect(_NifSocket, _Address) ->
    error(nif_not_loaded).
nif_accept(_NifSocket) ->
    error(nif_not_loaded).
nif_recv(_NifSocket, _Length) ->
    error(nif_not_loaded).
nif_recvmsg(_NifSocket, _Flag, _Length) ->
    error(nif_not_loaded).
nif_recvfrom(_NifSocket, _Length) ->
    error(nif_not_loaded).
nif_send(_NifSocket, _Data, _Flags) ->
    error(nif_not_loaded).
nif_sendto(_NifSocket, _Data, _Flags, _Address) ->
    error(nif_not_loaded).
nif_read(_NifSocket, _Length) ->
    error(nif_not_loaded).
nif_write(_NifSocket, _Data) ->
    error(nif_not_loaded).
nif_ioctl(_NifSocket, _Request, _Data) ->
    error(nif_not_loaded).
nif_listen(_NifSocket, _Backlog) ->
    error(nif_not_loaded).
nif_shutdown(_NifSocket, _How) ->
    error(nif_not_loaded).

%% -------------------------------------------------------------------------------------------------
%% -- Enums
opt_level_to_int(sol_ip)     -> ?SOL_IP;
opt_level_to_int(sol_socket) -> ?SOL_SOCKET;
opt_level_to_int(X)          -> protocol_to_int(X).


opt_name_to_int(?SOL_IP, tos)			-> ?IP_TOS;
opt_name_to_int(?SOL_IP, ttl)			-> ?IP_TTL;
opt_name_to_int(?SOL_IP, options)		-> ?IP_OPTIONS;
opt_name_to_int(?SOL_IP, hdrincl)		-> ?IP_HDRINCL;
opt_name_to_int(?SOL_IP, router_alert)		-> ?IP_ROUTER_ALERT;
opt_name_to_int(?SOL_IP, recvopts)		-> ?IP_RECVOPTS;
opt_name_to_int(?SOL_IP, retopts)		-> ?IP_RETOPTS;
opt_name_to_int(?SOL_IP, pktinfo)		-> ?IP_PKTINFO;
opt_name_to_int(?SOL_IP, pktoptions)		-> ?IP_PKTOPTIONS;
opt_name_to_int(?SOL_IP, pmtudisc)		-> ?IP_PMTUDISC;
opt_name_to_int(?SOL_IP, mtu_discover)		-> ?IP_MTU_DISCOVER;
opt_name_to_int(?SOL_IP, recverr)		-> ?IP_RECVERR;
opt_name_to_int(?SOL_IP, recvttl)		-> ?IP_RECVTTL;
opt_name_to_int(?SOL_IP, recvtos)		-> ?IP_RECVTOS;
opt_name_to_int(?SOL_IP, mtu)			-> ?IP_MTU;
opt_name_to_int(?SOL_IP, freebind)		-> ?IP_FREEBIND;
opt_name_to_int(?SOL_IP, ipsec_policy)		-> ?IP_IPSEC_POLICY;
opt_name_to_int(?SOL_IP, xfrm_policy)		-> ?IP_XFRM_POLICY;
opt_name_to_int(?SOL_IP, passsec)		-> ?IP_PASSSEC;
opt_name_to_int(?SOL_IP, transparent)		-> ?IP_TRANSPARENT;
opt_name_to_int(?SOL_IP, origdstaddr)		-> ?IP_ORIGDSTADDR;
opt_name_to_int(?SOL_IP, minttl)		-> ?IP_MINTTL;
opt_name_to_int(?SOL_IP, nodefrag)		-> ?IP_NODEFRAG;
opt_name_to_int(?SOL_IP, multicast_if)		-> ?IP_MULTICAST_IF;
opt_name_to_int(?SOL_IP, multicast_ttl)		-> ?IP_MULTICAST_TTL;
opt_name_to_int(?SOL_IP, multicast_loop)	-> ?IP_MULTICAST_LOOP;
opt_name_to_int(?SOL_IP, add_membership)	-> ?IP_ADD_MEMBERSHIP;
opt_name_to_int(?SOL_IP, drop_membership)	-> ?IP_DROP_MEMBERSHIP;
opt_name_to_int(?SOL_IP, unblock_source)	-> ?IP_UNBLOCK_SOURCE;
opt_name_to_int(?SOL_IP, block_source)		-> ?IP_BLOCK_SOURCE;
opt_name_to_int(?SOL_IP, add_source_membership)		-> ?IP_ADD_SOURCE_MEMBERSHIP;
opt_name_to_int(?SOL_IP, drop_source_membership)	-> ?IP_DROP_SOURCE_MEMBERSHIP;
opt_name_to_int(?SOL_IP, msfilter)		-> ?IP_MSFILTER;
opt_name_to_int(?SOL_IP, mcast_join_group)		-> ?MCAST_JOIN_GROUP;
opt_name_to_int(?SOL_IP, mcast_block_source)		-> ?MCAST_BLOCK_SOURCE;
opt_name_to_int(?SOL_IP, mcast_unblock_source)		-> ?MCAST_UNBLOCK_SOURCE;
opt_name_to_int(?SOL_IP, mcast_leave_group)		-> ?MCAST_LEAVE_GROUP;
opt_name_to_int(?SOL_IP, mcast_join_source_group)	-> ?MCAST_JOIN_SOURCE_GROUP;
opt_name_to_int(?SOL_IP, mcast_leave_source_group)	-> ?MCAST_LEAVE_SOURCE_GROUP;
opt_name_to_int(?SOL_IP, mcast_msfilter)		-> ?MCAST_MSFILTER;
opt_name_to_int(?SOL_IP, multicast_all)		-> ?IP_MULTICAST_ALL;
opt_name_to_int(?SOL_IP, unicast_if)		-> ?IP_UNICAST_IF;

opt_name_to_int(?SOL_SOCKET, debug)		-> ?SO_DEBUG;
opt_name_to_int(?SOL_SOCKET, reuseaddr)		-> ?SO_REUSEADDR;
opt_name_to_int(?SOL_SOCKET, type)		-> ?SO_TYPE;
opt_name_to_int(?SOL_SOCKET, error)		-> ?SO_ERROR;
opt_name_to_int(?SOL_SOCKET, dontroute)		-> ?SO_DONTROUTE;
opt_name_to_int(?SOL_SOCKET, broadcast)		-> ?SO_BROADCAST;
opt_name_to_int(?SOL_SOCKET, sndbuf)		-> ?SO_SNDBUF;
opt_name_to_int(?SOL_SOCKET, rcvbuf)		-> ?SO_RCVBUF;
opt_name_to_int(?SOL_SOCKET, sndbufforce)	-> ?SO_SNDBUFFORCE;
opt_name_to_int(?SOL_SOCKET, rcvbufforce)	-> ?SO_RCVBUFFORCE;
opt_name_to_int(?SOL_SOCKET, keepalive)		-> ?SO_KEEPALIVE;
opt_name_to_int(?SOL_SOCKET, oobinline)		-> ?SO_OOBINLINE;
opt_name_to_int(?SOL_SOCKET, no_check)		-> ?SO_NO_CHECK;
opt_name_to_int(?SOL_SOCKET, priority)		-> ?SO_PRIORITY;
opt_name_to_int(?SOL_SOCKET, linger)		-> ?SO_LINGER;
opt_name_to_int(?SOL_SOCKET, bsdcompat)		-> ?SO_BSDCOMPAT;
opt_name_to_int(?SOL_SOCKET, passcred)		-> ?SO_PASSCRED;
opt_name_to_int(?SOL_SOCKET, peercred)		-> ?SO_PEERCRED;
opt_name_to_int(?SOL_SOCKET, rcvlowat)		-> ?SO_RCVLOWAT;
opt_name_to_int(?SOL_SOCKET, sndlowat)		-> ?SO_SNDLOWAT;
opt_name_to_int(?SOL_SOCKET, rcvtimeo)		-> ?SO_RCVTIMEO;
opt_name_to_int(?SOL_SOCKET, sndtimeo)		-> ?SO_SNDTIMEO;
opt_name_to_int(?SOL_SOCKET, security_authentication)		-> ?SO_SECURITY_AUTHENTICATION;
opt_name_to_int(?SOL_SOCKET, security_encryption_transport)	-> ?SO_SECURITY_ENCRYPTION_TRANSPORT;
opt_name_to_int(?SOL_SOCKET, security_encryption_network)	-> ?SO_SECURITY_ENCRYPTION_NETWORK;
opt_name_to_int(?SOL_SOCKET, bindtodevice)	-> ?SO_BINDTODEVICE;
opt_name_to_int(?SOL_SOCKET, attach_filter)	-> ?SO_ATTACH_FILTER;
opt_name_to_int(?SOL_SOCKET, detach_filter)	-> ?SO_DETACH_FILTER;
opt_name_to_int(?SOL_SOCKET, peername)		-> ?SO_PEERNAME;
opt_name_to_int(?SOL_SOCKET, timestamp)		-> ?SO_TIMESTAMP;
opt_name_to_int(?SOL_SOCKET, acceptconn)	-> ?SO_ACCEPTCONN;
opt_name_to_int(?SOL_SOCKET, peersec)		-> ?SO_PEERSEC;
opt_name_to_int(?SOL_SOCKET, passsec)		-> ?SO_PASSSEC;
opt_name_to_int(?SOL_SOCKET, timestampns)	-> ?SO_TIMESTAMPNS;
opt_name_to_int(?SOL_SOCKET, mark)		-> ?SO_MARK;
opt_name_to_int(?SOL_SOCKET, timestamping)	-> ?SO_TIMESTAMPING;
opt_name_to_int(?SOL_SOCKET, protocol)		-> ?SO_PROTOCOL;
opt_name_to_int(?SOL_SOCKET, domain)		-> ?SO_DOMAIN;
opt_name_to_int(?SOL_SOCKET, rxq_ovfl)		-> ?SO_RXQ_OVFL.






sockopt_len(?SOL_IP, OptName)
  when OptName == ?IP_HDRINCL; OptName == ?IP_TOS, OptName == ?IP_TTL;
       OptName == ?IP_MTU_DISCOVER; OptName == ?IP_MTU ->
    4;

sockopt_len(?SOL_IP, OptName)
  when OptName == ?IP_RECVOPTS; OptName == ?IP_ROUTER_ALERT; OptName == ?IP_PKTINFO;
       OptName == ?IP_RECVERR; OptName == ?IP_RECVTTL; OptName == ?IP_RECVTOS;
       OptName == ?IP_MULTICAST_ALL ->
    4;

sockopt_len(?SOL_IP, OptName)
  when OptName == ?IP_OPTIONS; OptName == ?IP_RETOPTS ->
    44;

sockopt_len(?SOL_SOCKET, OptName)
  when OptName == ?SO_ACCEPTCONN; OptName == ?SO_BROADCAST; OptName == ?SO_BSDCOMPAT;
       OptName == ?SO_DEBUG; OptName == ?SO_DONTROUTE; OptName == ?SO_KEEPALIVE;
       OptName == ?SO_OOBINLINE; OptName == ?SO_PASSCRED; OptName == ?SO_REUSEADDR;
       OptName == ?SO_TIMESTAMP ->
    4;

sockopt_len(?SOL_SOCKET, OptName)
  when OptName == ?SO_DOMAIN; OptName == ?SO_ERROR; OptName == ?SO_PRIORITY;
       OptName == ?SO_PROTOCOL; OptName == ?SO_TYPE ->
    4;

sockopt_len(?SOL_SOCKET, OptName)
  when OptName == ?SO_RCVBUF; OptName == ?SO_RCVBUFFORCE; OptName == ?SO_RCVLOWAT;
       OptName == ?SO_SNDLOWAT; OptName == ?SO_SNDBUF; OptName == ?SO_SNDBUFFORCE ->
    4;

sockopt_len(?SOL_SOCKET, OptName)
  when OptName == ?SO_RCVTIMEO; OptName == ?SO_SNDTIMEO ->
    16;
sockopt_len(?SOL_SOCKET, ?SO_LINGER) ->
    8;

sockopt_len(?SOL_SOCKET, ?SO_PEERCRED) ->
    64;
sockopt_len(_Level, _OptName) ->
    128.

decode_sockopt(?SOL_IP, OptName, <<Value:32/native-integer>>)
  when OptName == ?IP_HDRINCL; OptName == ?IP_TOS, OptName == ?IP_TTL;
       OptName == ?IP_MTU_DISCOVER; OptName == ?IP_MTU ->
    Value;

decode_sockopt(?SOL_IP, OptName, <<Value:32/native-integer>>)
  when OptName == ?IP_RECVOPTS; OptName == ?IP_ROUTER_ALERT; OptName == ?IP_PKTINFO;
       OptName == ?IP_RECVERR; OptName == ?IP_RECVTTL; OptName == ?IP_RECVTOS;
       OptName == ?IP_MULTICAST_ALL ->
    Value /= 0;

decode_sockopt(?SOL_SOCKET, OptName, <<Value:32/native-integer>>)
  when OptName == ?SO_ACCEPTCONN; OptName == ?SO_BROADCAST; OptName == ?SO_BSDCOMPAT;
       OptName == ?SO_DEBUG; OptName == ?SO_DONTROUTE; OptName == ?SO_KEEPALIVE;
       OptName == ?SO_OOBINLINE; OptName == ?SO_PASSCRED; OptName == ?SO_REUSEADDR;
       OptName == ?SO_TIMESTAMP ->
    Value /= 0;

decode_sockopt(?SOL_SOCKET, OptName, <<Value:32/native-integer>>)
  when OptName == ?SO_DOMAIN; OptName == ?SO_ERROR; OptName == ?SO_PRIORITY;
       OptName == ?SO_PROTOCOL; OptName == ?SO_TYPE ->
    Value;

decode_sockopt(?SOL_SOCKET, OptName, <<Value:32/native-integer>>)
  when OptName == ?SO_RCVBUF; OptName == ?SO_RCVBUFFORCE; OptName == ?SO_RCVLOWAT;
       OptName == ?SO_SNDLOWAT; OptName == ?SO_SNDBUF; OptName == ?SO_SNDBUFFORCE ->
    Value;

decode_sockopt(?SOL_SOCKET, OptName, <<Sec:64/native-integer, USec:64/native-integer>>)
  when OptName == ?SO_RCVTIMEO; OptName == ?SO_SNDTIMEO ->
    {Sec, USec};

decode_sockopt(?SOL_SOCKET, ?SO_LINGER, <<OnOff:32/native-integer, Linger:32/native-integer>>) ->
    {OnOff /= 0, Linger};
decode_sockopt(_, _, OptValue) ->
    OptValue.

%% Socket type
type_to_int(stream) -> 1;
type_to_int(dgram)  -> 2;
type_to_int(raw)    -> 3.

type_to_atom(1)     -> stream;
type_to_atom(2)     -> dgram;
type_to_atom(3)     -> raw;
type_to_atom(_)     -> unknown.

type(X) when is_atom(X)    -> type_to_int(X);
type(X) when is_integer(X) -> type_to_atom(X).

