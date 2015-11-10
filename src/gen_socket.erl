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
         recv/1, recv/2, recvfrom/1, recvfrom/2,
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
-type protocol_name() ::
    default | ip | icmp | igmp | ipip | tcp | egp | pup |
    udp | idp | tp | dccp | ipv6 | routing | fragment |
    rsvp | gre | esp | ah | icmpv6 | none | dstopts |
    mtp | encap | pim | comp | sctp | udplite | raw.

-type port_number() :: 0..65535.
-type sockaddr() :: {unix, Path::iodata()}
                  | {inet4, inet:ip4_address(), port_number()}
                  | {unknown, binary()}.

-type posix_error() :: file:posix().

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
getsockopt(Socket, Level, OptName) when is_atom(OptName) ->
    getsockopt(Socket, Level, opt_name_to_int(OptName));
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
getsockopt(Socket, Level, OptName, OptLen) when is_atom(OptName) ->
    getsockopt(Socket, Level, opt_name_to_int(OptName), OptLen);
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
getsockopt(Socket, Level, OptName, Opt, OptLen) when is_atom(OptName) ->
    getsockopt(Socket, Level, opt_name_to_int(OptName), Opt, OptLen);
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
setsockopt(Socket, Level, OptName, Val) when is_atom(OptName) ->
    setsockopt(Socket, Level, opt_name_to_int(OptName), Val);
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
opt_level_to_int(sol_socket) -> ?SOL_SOCKET;
opt_level_to_int(X)          -> protocol_to_int(X).

opt_name_to_int(debug)		-> ?SO_DEBUG;
opt_name_to_int(reuseaddr)	-> ?SO_REUSEADDR;
opt_name_to_int(type)		-> ?SO_TYPE;
opt_name_to_int(error)		-> ?SO_ERROR;
opt_name_to_int(dontroute)	-> ?SO_DONTROUTE;
opt_name_to_int(broadcast)	-> ?SO_BROADCAST;
opt_name_to_int(sndbuf)		-> ?SO_SNDBUF;
opt_name_to_int(rcvbuf)		-> ?SO_RCVBUF;
opt_name_to_int(sndbufforce)	-> ?SO_SNDBUFFORCE;
opt_name_to_int(rcvbufforce)	-> ?SO_RCVBUFFORCE;
opt_name_to_int(keepalive)	-> ?SO_KEEPALIVE;
opt_name_to_int(oobinline)	-> ?SO_OOBINLINE;
opt_name_to_int(no_check)	-> ?SO_NO_CHECK;
opt_name_to_int(priority)	-> ?SO_PRIORITY;
opt_name_to_int(linger)		-> ?SO_LINGER;
opt_name_to_int(bsdcompat)	-> ?SO_BSDCOMPAT;
opt_name_to_int(passcred)	-> ?SO_PASSCRED;
opt_name_to_int(peercred)	-> ?SO_PEERCRED;
opt_name_to_int(rcvlowat)	-> ?SO_RCVLOWAT;
opt_name_to_int(sndlowat)	-> ?SO_SNDLOWAT;
opt_name_to_int(rcvtimeo)	-> ?SO_RCVTIMEO;
opt_name_to_int(sndtimeo)	-> ?SO_SNDTIMEO;
opt_name_to_int(security_authentication)	-> ?SO_SECURITY_AUTHENTICATION;
opt_name_to_int(security_encryption_transport)	-> ?SO_SECURITY_ENCRYPTION_TRANSPORT;
opt_name_to_int(security_encryption_network)	-> ?SO_SECURITY_ENCRYPTION_NETWORK;
opt_name_to_int(bindtodevice)	-> ?SO_BINDTODEVICE;
opt_name_to_int(attach_filter)	-> ?SO_ATTACH_FILTER;
opt_name_to_int(detach_filter)	-> ?SO_DETACH_FILTER;
opt_name_to_int(peername)	-> ?SO_PEERNAME;
opt_name_to_int(timestamp)	-> ?SO_TIMESTAMP;
opt_name_to_int(acceptconn)	-> ?SO_ACCEPTCONN;
opt_name_to_int(peersec)	-> ?SO_PEERSEC;
opt_name_to_int(passsec)	-> ?SO_PASSSEC;
opt_name_to_int(timestampns)	-> ?SO_TIMESTAMPNS;
opt_name_to_int(mark)		-> ?SO_MARK;
opt_name_to_int(timestamping)	-> ?SO_TIMESTAMPING;
opt_name_to_int(protocol)	-> ?SO_PROTOCOL;
opt_name_to_int(domain)		-> ?SO_DOMAIN;
opt_name_to_int(rxq_ovfl)	-> ?SO_RXQ_OVFL.

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
    

%% Protocol family (aka domain)
family_to_int(unspec)     -> 0;
family_to_int(local)      -> 1;
family_to_int(unix)       -> 1;
family_to_int(file)       -> 1;
family_to_int(inet)       -> 2;
family_to_int(ax25)       -> 3;
family_to_int(ipx)        -> 4;
family_to_int(appletalk)  -> 5;
family_to_int(netrom)     -> 6;
family_to_int(bridge)     -> 7;
family_to_int(atmpvc)     -> 8;
family_to_int(x25)        -> 9;
family_to_int(inet6)      -> 10;
family_to_int(rose)       -> 11;
family_to_int(decnet)     -> 12;
family_to_int(netbeui)    -> 13;
family_to_int(security)   -> 14;
family_to_int(key)        -> 15;
family_to_int(netlink)    -> 16;
family_to_int(route)      -> 16;
family_to_int(packet)     -> 17;
family_to_int(ash)        -> 18;
family_to_int(econet)     -> 19;
family_to_int(atmsvc)     -> 20;
family_to_int(rds)        -> 21;
family_to_int(sna)        -> 22;
family_to_int(irda)       -> 23;
family_to_int(pppox)      -> 24;
family_to_int(wanpipe)    -> 25;
family_to_int(llc)        -> 26;
family_to_int(can)        -> 29;
family_to_int(tipc)       -> 30;
family_to_int(bluetooth)  -> 31;
family_to_int(iucv)       -> 32;
family_to_int(rxrpc)      -> 33;
family_to_int(isdn)       -> 34;
family_to_int(phonet)     -> 35;
family_to_int(ieee802154) -> 36.

family_to_atom(0)         -> unspec;
family_to_atom(1)         -> unix;
family_to_atom(2)         -> inet;
family_to_atom(3)         -> ax25;
family_to_atom(4)         -> ipx;
family_to_atom(5)         -> appletalk;
family_to_atom(6)         -> netrom;
family_to_atom(7)         -> bridge;
family_to_atom(8)         -> atmpvc;
family_to_atom(9)         -> x25;
family_to_atom(10)        -> inet6;
family_to_atom(11)        -> rose;
family_to_atom(12)        -> decnet;
family_to_atom(13)        -> netbeui;
family_to_atom(14)        -> security;
family_to_atom(15)        -> key;
family_to_atom(17)        -> packet;
family_to_atom(18)        -> ash;
family_to_atom(19)        -> econet;
family_to_atom(20)        -> atmsvc;
family_to_atom(21)        -> rds;
family_to_atom(22)        -> sna;
family_to_atom(23)        -> irda;
family_to_atom(24)        -> pppox;
family_to_atom(25)        -> wanpipe;
family_to_atom(26)        -> llc;
family_to_atom(29)        -> can;
family_to_atom(30)        -> tipc;
family_to_atom(31)        -> bluetooth;
family_to_atom(32)        -> iucv;
family_to_atom(33)        -> rxrpc;
family_to_atom(34)        -> isdn;
family_to_atom(35)        -> phonet;
family_to_atom(36)        -> ieee802154;
family_to_atom(_)         -> unknown.

family(X) when is_atom(X)    -> family_to_int(X);
family(X) when is_integer(X) -> family_to_atom(X).

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

% Select a protocol within the family (0 means use the default
% protocol in the family)
-spec protocol_to_int(protocol_name()) -> integer().
protocol_to_int(default)  -> 0;
protocol_to_int(ip)       -> 0;
protocol_to_int(icmp)     -> 1;
protocol_to_int(igmp)     -> 2;
protocol_to_int(ipip)     -> 4;
protocol_to_int(tcp)      -> 6;
protocol_to_int(egp)      -> 8;
protocol_to_int(pup)      -> 12;
protocol_to_int(udp)      -> 17;
protocol_to_int(idp)      -> 22;
protocol_to_int(tp)       -> 29;
protocol_to_int(dccp)     -> 33;
protocol_to_int(ipv6)     -> 41;
protocol_to_int(routing)  -> 43;
protocol_to_int(fragment) -> 44;
protocol_to_int(rsvp)     -> 46;
protocol_to_int(gre)      -> 47;
protocol_to_int(esp)      -> 50;
protocol_to_int(ah)       -> 51;
protocol_to_int(icmpv6)   -> 58;
protocol_to_int(none)     -> 59;
protocol_to_int(dstopts)  -> 60;
protocol_to_int(mtp)      -> 92;
protocol_to_int(encap)    -> 98;
protocol_to_int(pim)      -> 103;
protocol_to_int(comp)     -> 108;
protocol_to_int(sctp)     -> 132;
protocol_to_int(udplite)  -> 136;
protocol_to_int(raw)      -> 255.

protocol_to_atom(0)       -> ip;
protocol_to_atom(1)       -> icmp;
protocol_to_atom(2)       -> igmp;
protocol_to_atom(4)       -> ipip;
protocol_to_atom(6)       -> tcp;
protocol_to_atom(8)       -> egp;
protocol_to_atom(12)      -> pup;
protocol_to_atom(17)      -> udp;
protocol_to_atom(22)      -> idp;
protocol_to_atom(29)      -> tp;
protocol_to_atom(33)      -> dccp;
protocol_to_atom(41)      -> ipv6;
protocol_to_atom(43)      -> routing;
protocol_to_atom(44)      -> fragment;
protocol_to_atom(46)      -> rsvp;
protocol_to_atom(47)      -> gre;
protocol_to_atom(50)      -> esp;
protocol_to_atom(51)      -> ah;
protocol_to_atom(58)      -> icmpv6;
protocol_to_atom(59)      -> none;
protocol_to_atom(60)      -> dstopts;
protocol_to_atom(92)      -> mtp;
protocol_to_atom(98)      -> encap;
protocol_to_atom(103)     -> pim;
protocol_to_atom(108)     -> comp;
protocol_to_atom(132)     -> sctp;
protocol_to_atom(136)     -> udplite;
protocol_to_atom(255)     -> raw;
protocol_to_atom(_X)      -> unknown.

protocol(X) when is_atom(X)    -> protocol_to_int(X);
protocol(X) when is_integer(X) -> protocol_to_atom(X).

arphdr(?ARPHRD_NETROM)             -> arphrd_netrom;
arphdr(?ARPHRD_ETHER)              -> arphrd_ether;
arphdr(?ARPHRD_EETHER)             -> arphrd_eether;
arphdr(?ARPHRD_AX25)               -> arphrd_ax25;
arphdr(?ARPHRD_PRONET)             -> arphrd_pronet;
arphdr(?ARPHRD_CHAOS)              -> arphrd_chaos;
arphdr(?ARPHRD_IEEE802)            -> arphrd_ieee802;
arphdr(?ARPHRD_ARCNET)             -> arphrd_arcnet;
arphdr(?ARPHRD_APPLETLK)           -> arphrd_appletlk;
arphdr(?ARPHRD_DLCI)               -> arphrd_dlci;
arphdr(?ARPHRD_ATM)                -> arphrd_atm;
arphdr(?ARPHRD_METRICOM)           -> arphrd_metricom;
arphdr(?ARPHRD_IEEE1394)           -> arphrd_ieee1394;
arphdr(?ARPHRD_EUI64)              -> arphrd_eui64;
arphdr(?ARPHRD_INFINIBAND)         -> arphrd_infiniband;
arphdr(?ARPHRD_SLIP)               -> arphrd_slip;
arphdr(?ARPHRD_CSLIP)              -> arphrd_cslip;
arphdr(?ARPHRD_SLIP6)              -> arphrd_slip6;
arphdr(?ARPHRD_CSLIP6)             -> arphrd_cslip6;
arphdr(?ARPHRD_RSRVD)              -> arphrd_rsrvd;
arphdr(?ARPHRD_ADAPT)              -> arphrd_adapt;
arphdr(?ARPHRD_ROSE)               -> arphrd_rose;
arphdr(?ARPHRD_X25)                -> arphrd_x25;
arphdr(?ARPHRD_HWX25)              -> arphrd_hwx25;
arphdr(?ARPHRD_CAN)                -> arphrd_can;
arphdr(?ARPHRD_PPP)                -> arphrd_ppp;
arphdr(?ARPHRD_HDLC)               -> arphrd_hdlc;
arphdr(?ARPHRD_LAPB)               -> arphrd_lapb;
arphdr(?ARPHRD_DDCMP)              -> arphrd_ddcmp;
arphdr(?ARPHRD_RAWHDLC)            -> arphrd_rawhdlc;
arphdr(?ARPHRD_TUNNEL)             -> arphrd_tunnel;
arphdr(?ARPHRD_TUNNEL6)            -> arphrd_tunnel6;
arphdr(?ARPHRD_FRAD)               -> arphrd_frad;
arphdr(?ARPHRD_SKIP)               -> arphrd_skip;
arphdr(?ARPHRD_LOOPBACK)           -> arphrd_loopback;
arphdr(?ARPHRD_LOCALTLK)           -> arphrd_localtlk;
arphdr(?ARPHRD_FDDI)               -> arphrd_fddi;
arphdr(?ARPHRD_BIF)                -> arphrd_bif;
arphdr(?ARPHRD_SIT)                -> arphrd_sit;
arphdr(?ARPHRD_IPDDP)              -> arphrd_ipddp;
arphdr(?ARPHRD_IPGRE)              -> arphrd_ipgre;
arphdr(?ARPHRD_PIMREG)             -> arphrd_pimreg;
arphdr(?ARPHRD_HIPPI)              -> arphrd_hippi;
arphdr(?ARPHRD_ASH)                -> arphrd_ash;
arphdr(?ARPHRD_ECONET)             -> arphrd_econet;
arphdr(?ARPHRD_IRDA)               -> arphrd_irda;
arphdr(?ARPHRD_FCPP)               -> arphrd_fcpp;
arphdr(?ARPHRD_FCAL)               -> arphrd_fcal;
arphdr(?ARPHRD_FCPL)               -> arphrd_fcpl;
arphdr(?ARPHRD_FCFABRIC)           -> arphrd_fcfabric;
arphdr(?ARPHRD_IEEE802_TR)         -> arphrd_ieee802_tr;
arphdr(?ARPHRD_IEEE80211)          -> arphrd_ieee80211;
arphdr(?ARPHRD_IEEE80211_PRISM)    -> arphrd_ieee80211_prism;
arphdr(?ARPHRD_IEEE80211_RADIOTAP) -> arphrd_ieee80211_radiotap;
arphdr(?ARPHRD_IEEE802154)         -> arphrd_ieee802154;
arphdr(?ARPHRD_PHONET)             -> arphrd_phonet;
arphdr(?ARPHRD_PHONET_PIPE)        -> arphrd_phonet_pipe;
arphdr(?ARPHRD_CAIF)               -> arphrd_caif;
arphdr(?ARPHRD_VOID)               -> arphrd_void;
arphdr(?ARPHRD_NONE)               -> arphrd_none;

arphdr(arphrd_netrom)              -> ?ARPHRD_NETROM;
arphdr(arphrd_ether)               -> ?ARPHRD_ETHER;
arphdr(arphrd_eether)              -> ?ARPHRD_EETHER;
arphdr(arphrd_ax25)                -> ?ARPHRD_AX25;
arphdr(arphrd_pronet)              -> ?ARPHRD_PRONET;
arphdr(arphrd_chaos)               -> ?ARPHRD_CHAOS;
arphdr(arphrd_ieee802)             -> ?ARPHRD_IEEE802;
arphdr(arphrd_arcnet)              -> ?ARPHRD_ARCNET;
arphdr(arphrd_appletlk)            -> ?ARPHRD_APPLETLK;
arphdr(arphrd_dlci)                -> ?ARPHRD_DLCI;
arphdr(arphrd_atm)                 -> ?ARPHRD_ATM;
arphdr(arphrd_metricom)            -> ?ARPHRD_METRICOM;
arphdr(arphrd_ieee1394)            -> ?ARPHRD_IEEE1394;
arphdr(arphrd_eui64)               -> ?ARPHRD_EUI64;
arphdr(arphrd_infiniband)          -> ?ARPHRD_INFINIBAND;
arphdr(arphrd_slip)                -> ?ARPHRD_SLIP;
arphdr(arphrd_cslip)               -> ?ARPHRD_CSLIP;
arphdr(arphrd_slip6)               -> ?ARPHRD_SLIP6;
arphdr(arphrd_cslip6)              -> ?ARPHRD_CSLIP6;
arphdr(arphrd_rsrvd)               -> ?ARPHRD_RSRVD;
arphdr(arphrd_adapt)               -> ?ARPHRD_ADAPT;
arphdr(arphrd_rose)                -> ?ARPHRD_ROSE;
arphdr(arphrd_x25)                 -> ?ARPHRD_X25;
arphdr(arphrd_hwx25)               -> ?ARPHRD_HWX25;
arphdr(arphrd_can)                 -> ?ARPHRD_CAN;
arphdr(arphrd_ppp)                 -> ?ARPHRD_PPP;
arphdr(arphrd_cisco)               -> ?ARPHRD_CISCO;
arphdr(arphrd_hdlc)                -> ?ARPHRD_HDLC;
arphdr(arphrd_lapb)                -> ?ARPHRD_LAPB;
arphdr(arphrd_ddcmp)               -> ?ARPHRD_DDCMP;
arphdr(arphrd_rawhdlc)             -> ?ARPHRD_RAWHDLC;
arphdr(arphrd_tunnel)              -> ?ARPHRD_TUNNEL;
arphdr(arphrd_tunnel6)             -> ?ARPHRD_TUNNEL6;
arphdr(arphrd_frad)                -> ?ARPHRD_FRAD;
arphdr(arphrd_skip)                -> ?ARPHRD_SKIP;
arphdr(arphrd_loopback)            -> ?ARPHRD_LOOPBACK;
arphdr(arphrd_localtlk)            -> ?ARPHRD_LOCALTLK;
arphdr(arphrd_fddi)                -> ?ARPHRD_FDDI;
arphdr(arphrd_bif)                 -> ?ARPHRD_BIF;
arphdr(arphrd_sit)                 -> ?ARPHRD_SIT;
arphdr(arphrd_ipddp)               -> ?ARPHRD_IPDDP;
arphdr(arphrd_ipgre)               -> ?ARPHRD_IPGRE;
arphdr(arphrd_pimreg)              -> ?ARPHRD_PIMREG;
arphdr(arphrd_hippi)               -> ?ARPHRD_HIPPI;
arphdr(arphrd_ash)                 -> ?ARPHRD_ASH;
arphdr(arphrd_econet)              -> ?ARPHRD_ECONET;
arphdr(arphrd_irda)                -> ?ARPHRD_IRDA;
arphdr(arphrd_fcpp)                -> ?ARPHRD_FCPP;
arphdr(arphrd_fcal)                -> ?ARPHRD_FCAL;
arphdr(arphrd_fcpl)                -> ?ARPHRD_FCPL;
arphdr(arphrd_fcfabric)            -> ?ARPHRD_FCFABRIC;
arphdr(arphrd_ieee802_tr)          -> ?ARPHRD_IEEE802_TR;
arphdr(arphrd_ieee80211)           -> ?ARPHRD_IEEE80211;
arphdr(arphrd_ieee80211_prism)     -> ?ARPHRD_IEEE80211_PRISM;
arphdr(arphrd_ieee80211_radiotap)  -> ?ARPHRD_IEEE80211_RADIOTAP;
arphdr(arphrd_ieee802154)          -> ?ARPHRD_IEEE802154;
arphdr(arphrd_phonet)              -> ?ARPHRD_PHONET;
arphdr(arphrd_phonet_pipe)         -> ?ARPHRD_PHONET_PIPE;
arphdr(arphrd_caif)                -> ?ARPHRD_CAIF;
arphdr(arphrd_void)                -> ?ARPHRD_VOID;
arphdr(arphrd_none)                -> ?ARPHRD_NONE;

arphdr(X)                          -> X.

