%% Copyright (c) 2010, Travelping GmbH <info@travelping.com
%% All rights reserved.
%%  
%% based on procket:
%%
%% Copyright (c) 2010, Michael Santos <michael.santos@gmail.com>
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

-export([
         init/0,
         socket/3,
         listen/1, listen/2,
         connect/2,
         accept/1, accept/2,
         close/1,
         recv/2, recvfrom/2, recvfrom/4,
         send/3, sendto/4,
         bind/2,
         ioctl/3,
         setsockopt/4,
         setsockoption/4
    ]).
-export([progname/0]).
-export([family/1, type/1, protocol/1, arphdr/1]).

-on_load(on_load/0).

%%
%% grep define include/gen_socket.hrl | awk -F"[(,]" '{ printf "enc_opt(%s)%*s ?%s;\n", tolower($2), 32 - length($2), "->", $2 }
%%
enc_opt(sol_socket)                    -> ?SOL_SOCKET;
enc_opt(so_debug)                      -> ?SO_DEBUG;
enc_opt(so_reuseaddr)                  -> ?SO_REUSEADDR;
enc_opt(so_type)                       -> ?SO_TYPE;
enc_opt(so_error)                      -> ?SO_ERROR;
enc_opt(so_dontroute)                  -> ?SO_DONTROUTE;
enc_opt(so_broadcast)                  -> ?SO_BROADCAST;
enc_opt(so_sndbuf)                     -> ?SO_SNDBUF;
enc_opt(so_rcvbuf)                     -> ?SO_RCVBUF.

init() ->
    on_load().

on_load() ->
    erlang:load_nif(progname(), []).


close(_) ->
    erlang:error(not_implemented).

accept(Socket) ->
    case accept(Socket, 0) of
        {ok, FD, <<>>} -> {ok, FD};
        Error -> Error
    end.
accept(_,_) ->
    erlang:error(not_implemented).

bind(_,_) ->
    erlang:error(not_implemented).

connect(_,_) ->
    erlang:error(not_implemented).

listen(Socket) when is_integer(Socket) ->
    listen(Socket, ?BACKLOG).
listen(_,_) ->
    erlang:error(not_implemented).

recv(Socket,Size) ->
    recvfrom(Socket,Size).
recvfrom(Socket,Size) ->
    case recvfrom(Socket, Size, 0, 0) of
        {ok, Buf, <<>>} -> {ok, Buf}; 
        Error -> Error
    end.
recvfrom(_,_,_,_) ->
    erlang:error(not_implemented).

socket(Family, Type, Protocol) when is_atom(Family) ->
    socket(family(Family), Type, Protocol);
socket(Family, Type, Protocol) when is_atom(Type) ->
    socket(Family, type(Type), Protocol);
socket(Family, Type, Protocol) when is_atom(Protocol) ->
    socket(Family, Type, protocol(Protocol));
socket(Family, Type, Protocol) when is_integer(Family); is_integer(Type); is_integer(Protocol) ->
    socket3(Family, Type, Protocol).

socket3(_,_,_) ->
    erlang:error(not_implemented).

ioctl(_,_,_) ->
    erlang:error(not_implemented).

sendto(_,_,_,_) ->
    erlang:error(not_implemented).

send(_,_,_) ->
    erlang:error(not_implemented).

setsockopt(_,_,_,_) ->
    erlang:error(not_implemented).

setsockoption(Socket, Level, OptName, Val) when is_atom(Level) ->
    setsockoption(Socket, enc_opt(Level), OptName, Val);
setsockoption(Socket, Level, OptName, Val) when is_atom(OptName) ->
    setsockoption(Socket, Level, enc_opt(OptName), Val);
setsockoption(Socket, Level, OptName, Val) when is_atom(Val) ->
    setsockoption(Socket, Level, OptName, enc_opt(Val));
setsockoption(Socket, Level, OptName, Val) when is_integer(Val) ->
    setsockopt(Socket, Level, OptName, << Val:32/native >>).

progname() ->
    filename:join([
        filename:dirname(code:which(?MODULE)),
        "..",
        "priv",
        "lib",
        ?MODULE
    ]).

%% Protocol family (aka domain)
family(unspec) -> 0;
family(inet) -> 2;
family(ax25) -> 3;
family(ipx) -> 4;
family(appletalk) -> 5;
family(netrom) -> 6;
family(bridge) -> 7;
family(atmpvc) -> 8;
family(x25) -> 9;
family(inet6) -> 10;
family(rose) -> 11;
family(decnet) -> 12;
family(netbeui) -> 13;
family(security) -> 14;
family(key) -> 15;
family(packet) -> 17;
family(ash) -> 18;
family(econet) -> 19;
family(atmsvc) -> 20;
family(rds) -> 21;
family(sna) -> 22;
family(irda) -> 23;
family(pppox) -> 24;
family(wanpipe) -> 25;
family(llc) -> 26;
family(can) -> 29;
family(tipc) -> 30;
family(bluetooth) -> 31;
family(iucv) -> 32;
family(rxrpc) -> 33;
family(isdn) -> 34;
family(phonet) -> 35;
family(ieee802154) -> 36;
family(Proto) when Proto == local; Proto == unix; Proto == file -> 1;
family(Proto) when Proto == netlink; Proto == route -> 16;

family(0) -> unspec;
family(1) -> unix;
family(2) -> inet;
family(3) -> ax25;
family(4) -> ipx;
family(5) -> appletalk;
family(6) -> netrom;
family(7) -> bridge;
family(8) -> atmpvc;
family(9) -> x25;
family(10) -> inet6;
family(11) -> rose;
family(12) -> decnet;
family(13) -> netbeui;
family(14) -> security;
family(15) -> key;
family(17) -> packet;
family(18) -> ash;
family(19) -> econet;
family(20) -> atmsvc;
family(21) -> rds;
family(22) -> sna;
family(23) -> irda;
family(24) -> pppox;
family(25) -> wanpipe;
family(26) -> llc;
family(29) -> can;
family(30) -> tipc;
family(31) -> bluetooth;
family(32) -> iucv;
family(33) -> rxrpc;
family(34) -> isdn;
family(35) -> phonet;
family(36) -> ieee802154.

%% Socket type
type(stream) -> 1;
type(dgram) -> 2;
type(raw) -> 3;

type(1) -> stream;
type(2) -> dgram;
type(3) -> raw.


% Select a protocol within the family (0 means use the default
% protocol in the family)
protocol(ip) -> 0;
protocol(icmp) -> 1;
protocol(igmp) -> 2;
protocol(ipip) -> 4;
protocol(tcp) -> 6;
protocol(egp) -> 8;
protocol(pup) -> 12;
protocol(udp) -> 17;
protocol(idp) -> 22;
protocol(tp) -> 29;
protocol(dccp) -> 33;
protocol(ipv6) -> 41;
protocol(routing) -> 43;
protocol(fragment) -> 44;
protocol(rsvp) -> 46;
protocol(gre) -> 47;
protocol(esp) -> 50;
protocol(ah) -> 51;
protocol(icmpv6) -> 58;
protocol(none) -> 59;
protocol(dstopts) -> 60;
protocol(mtp) -> 92;
protocol(encap) -> 98;
protocol(pim) -> 103;
protocol(comp) -> 108;
protocol(sctp) -> 132;
protocol(udplite) -> 136;
protocol(raw) -> 255;

protocol(0) -> ip;
protocol(1) -> icmp;
protocol(2) -> igmp;
protocol(4) -> ipip;
protocol(6) -> tcp;
protocol(8) -> egp;
protocol(12) -> pup;
protocol(17) -> udp;
protocol(22) -> idp;
protocol(29) -> tp;
protocol(33) -> dccp;
protocol(41) -> ipv6;
protocol(43) -> routing;
protocol(44) -> fragment;
protocol(46) -> rsvp;
protocol(47) -> gre;
protocol(50) -> esp;
protocol(51) -> ah;
protocol(58) -> icmpv6;
protocol(59) -> none;
protocol(60) -> dstopts;
protocol(92) -> mtp;
protocol(98) -> encap;
protocol(103) -> pim;
protocol(108) -> comp;
protocol(132) -> sctp;
protocol(136) -> udplite;
protocol(255) -> raw;
protocol(X) -> X.

arphdr(?ARPHRD_NETROM)                 -> arphrd_netrom;
arphdr(?ARPHRD_ETHER)                  -> arphrd_ether;
arphdr(?ARPHRD_EETHER)                 -> arphrd_eether;
arphdr(?ARPHRD_AX25)                   -> arphrd_ax25;
arphdr(?ARPHRD_PRONET)                 -> arphrd_pronet;
arphdr(?ARPHRD_CHAOS)                  -> arphrd_chaos;
arphdr(?ARPHRD_IEEE802)                -> arphrd_ieee802;
arphdr(?ARPHRD_ARCNET)                 -> arphrd_arcnet;
arphdr(?ARPHRD_APPLETLK)               -> arphrd_appletlk;
arphdr(?ARPHRD_DLCI)                   -> arphrd_dlci;
arphdr(?ARPHRD_ATM)                    -> arphrd_atm;
arphdr(?ARPHRD_METRICOM)               -> arphrd_metricom;
arphdr(?ARPHRD_IEEE1394)               -> arphrd_ieee1394;
arphdr(?ARPHRD_EUI64)                  -> arphrd_eui64;
arphdr(?ARPHRD_INFINIBAND)             -> arphrd_infiniband;
arphdr(?ARPHRD_SLIP)                   -> arphrd_slip;
arphdr(?ARPHRD_CSLIP)                  -> arphrd_cslip;
arphdr(?ARPHRD_SLIP6)                  -> arphrd_slip6;
arphdr(?ARPHRD_CSLIP6)                 -> arphrd_cslip6;
arphdr(?ARPHRD_RSRVD)                  -> arphrd_rsrvd;
arphdr(?ARPHRD_ADAPT)                  -> arphrd_adapt;
arphdr(?ARPHRD_ROSE)                   -> arphrd_rose;
arphdr(?ARPHRD_X25)                    -> arphrd_x25;
arphdr(?ARPHRD_HWX25)                  -> arphrd_hwx25;
arphdr(?ARPHRD_CAN)                    -> arphrd_can;
arphdr(?ARPHRD_PPP)                    -> arphrd_ppp;
arphdr(?ARPHRD_HDLC)                   -> arphrd_hdlc;
arphdr(?ARPHRD_LAPB)                   -> arphrd_lapb;
arphdr(?ARPHRD_DDCMP)                  -> arphrd_ddcmp;
arphdr(?ARPHRD_RAWHDLC)                -> arphrd_rawhdlc;
arphdr(?ARPHRD_TUNNEL)                 -> arphrd_tunnel;
arphdr(?ARPHRD_TUNNEL6)                -> arphrd_tunnel6;
arphdr(?ARPHRD_FRAD)                   -> arphrd_frad;
arphdr(?ARPHRD_SKIP)                   -> arphrd_skip;
arphdr(?ARPHRD_LOOPBACK)               -> arphrd_loopback;
arphdr(?ARPHRD_LOCALTLK)               -> arphrd_localtlk;
arphdr(?ARPHRD_FDDI)                   -> arphrd_fddi;
arphdr(?ARPHRD_BIF)                    -> arphrd_bif;
arphdr(?ARPHRD_SIT)                    -> arphrd_sit;
arphdr(?ARPHRD_IPDDP)                  -> arphrd_ipddp;
arphdr(?ARPHRD_IPGRE)                  -> arphrd_ipgre;
arphdr(?ARPHRD_PIMREG)                 -> arphrd_pimreg;
arphdr(?ARPHRD_HIPPI)                  -> arphrd_hippi;
arphdr(?ARPHRD_ASH)                    -> arphrd_ash;
arphdr(?ARPHRD_ECONET)                 -> arphrd_econet;
arphdr(?ARPHRD_IRDA)                   -> arphrd_irda;
arphdr(?ARPHRD_FCPP)                   -> arphrd_fcpp;
arphdr(?ARPHRD_FCAL)                   -> arphrd_fcal;
arphdr(?ARPHRD_FCPL)                   -> arphrd_fcpl;
arphdr(?ARPHRD_FCFABRIC)               -> arphrd_fcfabric;
arphdr(?ARPHRD_IEEE802_TR)             -> arphrd_ieee802_tr;
arphdr(?ARPHRD_IEEE80211)              -> arphrd_ieee80211;
arphdr(?ARPHRD_IEEE80211_PRISM)        -> arphrd_ieee80211_prism;
arphdr(?ARPHRD_IEEE80211_RADIOTAP)     -> arphrd_ieee80211_radiotap;
arphdr(?ARPHRD_IEEE802154)             -> arphrd_ieee802154;
arphdr(?ARPHRD_PHONET)                 -> arphrd_phonet;
arphdr(?ARPHRD_PHONET_PIPE)            -> arphrd_phonet_pipe;
arphdr(?ARPHRD_CAIF)                   -> arphrd_caif;
arphdr(?ARPHRD_VOID)                   -> arphrd_void;
arphdr(?ARPHRD_NONE)                   -> arphrd_none;

arphdr(arphrd_netrom)                  -> ?ARPHRD_NETROM;
arphdr(arphrd_ether)                   -> ?ARPHRD_ETHER;
arphdr(arphrd_eether)                  -> ?ARPHRD_EETHER;
arphdr(arphrd_ax25)                    -> ?ARPHRD_AX25;
arphdr(arphrd_pronet)                  -> ?ARPHRD_PRONET;
arphdr(arphrd_chaos)                   -> ?ARPHRD_CHAOS;
arphdr(arphrd_ieee802)                 -> ?ARPHRD_IEEE802;
arphdr(arphrd_arcnet)                  -> ?ARPHRD_ARCNET;
arphdr(arphrd_appletlk)                -> ?ARPHRD_APPLETLK;
arphdr(arphrd_dlci)                    -> ?ARPHRD_DLCI;
arphdr(arphrd_atm)                     -> ?ARPHRD_ATM;
arphdr(arphrd_metricom)                -> ?ARPHRD_METRICOM;
arphdr(arphrd_ieee1394)                -> ?ARPHRD_IEEE1394;
arphdr(arphrd_eui64)                   -> ?ARPHRD_EUI64;
arphdr(arphrd_infiniband)              -> ?ARPHRD_INFINIBAND;
arphdr(arphrd_slip)                    -> ?ARPHRD_SLIP;
arphdr(arphrd_cslip)                   -> ?ARPHRD_CSLIP;
arphdr(arphrd_slip6)                   -> ?ARPHRD_SLIP6;
arphdr(arphrd_cslip6)                  -> ?ARPHRD_CSLIP6;
arphdr(arphrd_rsrvd)                   -> ?ARPHRD_RSRVD;
arphdr(arphrd_adapt)                   -> ?ARPHRD_ADAPT;
arphdr(arphrd_rose)                    -> ?ARPHRD_ROSE;
arphdr(arphrd_x25)                     -> ?ARPHRD_X25;
arphdr(arphrd_hwx25)                   -> ?ARPHRD_HWX25;
arphdr(arphrd_can)                     -> ?ARPHRD_CAN;
arphdr(arphrd_ppp)                     -> ?ARPHRD_PPP;
arphdr(arphrd_cisco)                   -> ?ARPHRD_CISCO;
arphdr(arphrd_hdlc)                    -> ?ARPHRD_HDLC;
arphdr(arphrd_lapb)                    -> ?ARPHRD_LAPB;
arphdr(arphrd_ddcmp)                   -> ?ARPHRD_DDCMP;
arphdr(arphrd_rawhdlc)                 -> ?ARPHRD_RAWHDLC;
arphdr(arphrd_tunnel)                  -> ?ARPHRD_TUNNEL;
arphdr(arphrd_tunnel6)                 -> ?ARPHRD_TUNNEL6;
arphdr(arphrd_frad)                    -> ?ARPHRD_FRAD;
arphdr(arphrd_skip)                    -> ?ARPHRD_SKIP;
arphdr(arphrd_loopback)                -> ?ARPHRD_LOOPBACK;
arphdr(arphrd_localtlk)                -> ?ARPHRD_LOCALTLK;
arphdr(arphrd_fddi)                    -> ?ARPHRD_FDDI;
arphdr(arphrd_bif)                     -> ?ARPHRD_BIF;
arphdr(arphrd_sit)                     -> ?ARPHRD_SIT;
arphdr(arphrd_ipddp)                   -> ?ARPHRD_IPDDP;
arphdr(arphrd_ipgre)                   -> ?ARPHRD_IPGRE;
arphdr(arphrd_pimreg)                  -> ?ARPHRD_PIMREG;
arphdr(arphrd_hippi)                   -> ?ARPHRD_HIPPI;
arphdr(arphrd_ash)                     -> ?ARPHRD_ASH;
arphdr(arphrd_econet)                  -> ?ARPHRD_ECONET;
arphdr(arphrd_irda)                    -> ?ARPHRD_IRDA;
arphdr(arphrd_fcpp)                    -> ?ARPHRD_FCPP;
arphdr(arphrd_fcal)                    -> ?ARPHRD_FCAL;
arphdr(arphrd_fcpl)                    -> ?ARPHRD_FCPL;
arphdr(arphrd_fcfabric)                -> ?ARPHRD_FCFABRIC;
arphdr(arphrd_ieee802_tr)              -> ?ARPHRD_IEEE802_TR;
arphdr(arphrd_ieee80211)               -> ?ARPHRD_IEEE80211;
arphdr(arphrd_ieee80211_prism)         -> ?ARPHRD_IEEE80211_PRISM;
arphdr(arphrd_ieee80211_radiotap)      -> ?ARPHRD_IEEE80211_RADIOTAP;
arphdr(arphrd_ieee802154)              -> ?ARPHRD_IEEE802154;
arphdr(arphrd_phonet)                  -> ?ARPHRD_PHONET;
arphdr(arphrd_phonet_pipe)             -> ?ARPHRD_PHONET_PIPE;
arphdr(arphrd_caif)                    -> ?ARPHRD_CAIF;
arphdr(arphrd_void)                    -> ?ARPHRD_VOID;
arphdr(arphrd_none)                    -> ?ARPHRD_NONE;

arphdr(X)                              -> X.


