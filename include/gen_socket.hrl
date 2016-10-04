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

-ifndef(_GEN_SOCKET).
-define(_GEN_SOCKET, 1).
-define(UNIX_PATH_MAX, 108).
-define(BACKLOG, 50).

-define(SOCK_STREAM, 1).    % Sequenced, reliable, connection-based byte streams.
-define(SOCK_DGRAM, 2).     % Connectionless, unreliable datagrams of fixed maximum length.
-define(SOCK_RAW, 3).       % Raw protocol interface.
%-define(SOCK_RDM, 4).       % Reliably-delivered messages.
%-define(SOCK_SEQPACKET,5).  % Sequenced, reliable, connection-based, datagrams of fixed maximum length.
%-define(SOCK_DCCP, 6).      % Datagram Congestion Control Protocol.
%-define(SOCK_PACKET, 10).   % Linux specific way of getting packets at the dev level.
                            % For writing rarp and other similar things on the user level.

% Protocol families
-define(PF_UNSPEC,0).       % Unspecified.
-define(PF_LOCAL, 1).       % Local to host (pipes and file-domain).
-define(PF_UNIX, ?PF_LOCAL) % POSIX name for PF_LOCAL.
-define(PF_INET, 2).        % IP protocol family.
-define(PF_INET6, 10).      % IP version 6.
-define(PF_PACKET, 17).     % Packet family.

-define(SOL_IP,     0).
-define(SOL_SOCKET, 1).

-define(SO_DEBUG,        1).
-define(SO_REUSEADDR,    2).
-define(SO_TYPE,         3).
-define(SO_ERROR,        4).
-define(SO_DONTROUTE,    5).
-define(SO_BROADCAST,    6).
-define(SO_SNDBUF,       7).
-define(SO_RCVBUF,       8).
-define(SO_SNDBUFFORCE,  32).
-define(SO_RCVBUFFORCE,  33).
-define(SO_KEEPALIVE,    9).
-define(SO_OOBINLINE,    10).
-define(SO_NO_CHECK,     11).
-define(SO_PRIORITY,     12).
-define(SO_LINGER,       13).
-define(SO_BSDCOMPAT,    14).
%%, powerpc, might, have, different, values
-define(SO_PASSCRED,     16).
-define(SO_PEERCRED,     17).
-define(SO_RCVLOWAT,     18).
-define(SO_SNDLOWAT,     19).
-define(SO_RCVTIMEO,     20).
-define(SO_SNDTIMEO,     21).
-define(SO_SECURITY_AUTHENTICATION,              22).
-define(SO_SECURITY_ENCRYPTION_TRANSPORT,        23).
-define(SO_SECURITY_ENCRYPTION_NETWORK,          24).
-define(SO_BINDTODEVICE, 25).
-define(SO_ATTACH_FILTER,        26).
-define(SO_DETACH_FILTER,        27).
-define(SO_PEERNAME,             28).
-define(SO_TIMESTAMP,            29).
-define(SO_ACCEPTCONN,           30).
-define(SO_PEERSEC,              31).
-define(SO_PASSSEC,              34).
-define(SO_TIMESTAMPNS,          35).
-define(SO_MARK,                 36).
-define(SO_TIMESTAMPING,         37).
-define(SO_PROTOCOL,             38).
-define(SO_DOMAIN,               39).
-define(SO_RXQ_OVFL,             40).

%% ifi_type
%% taken from /usr/include/linux/if_arp.h
%% ARP protocol HARDWARE identifiers.
-define(ARPHRD_NETROM, 0).              %% from KA9Q: NET/ROM pseudo
-define(ARPHRD_ETHER , 1).               %% Ethernet 10Mbps
-define(ARPHRD_EETHER, 2).              %% Experimental Ethernet
-define(ARPHRD_AX25,   3).              %% AX.25 Level 2
-define(ARPHRD_PRONET, 4).              %% PROnet token ring
-define(ARPHRD_CHAOS,  5).              %% Chaosnet
-define(ARPHRD_IEEE802,6).              %% IEEE 802.2 Ethernet/TR/TB
-define(ARPHRD_ARCNET, 7).              %% ARCnet
-define(ARPHRD_APPLETLK, 8).              %% APPLEtalk
-define(ARPHRD_DLCI,     15).             %% Frame Relay DLCI
-define(ARPHRD_ATM,      19).             %% ATM
-define(ARPHRD_METRICOM, 23).             %% Metricom STRIP (new IANA id)
-define(ARPHRD_IEEE1394, 24).             %% IEEE 1394 IPv4 - RFC 2734
-define(ARPHRD_EUI64,    27).             %% EUI-64
-define(ARPHRD_INFINIBAND, 32).           %% InfiniBand
%% Dummy types for non ARP hardware
-define(ARPHRD_SLIP,     256).
-define(ARPHRD_CSLIP,    257).
-define(ARPHRD_SLIP6,    258).
-define(ARPHRD_CSLIP6,   259).
-define(ARPHRD_RSRVD,    260).           %% Notional KISS type
-define(ARPHRD_ADAPT,    264).
-define(ARPHRD_ROSE,     270).
-define(ARPHRD_X25,      271).            %% CCITT X.25
-define(ARPHRD_HWX25,    272).            %% Boards with X.25 in firmware
-define(ARPHRD_CAN,      280).            %% Controller Area Network
-define(ARPHRD_PPP,      512).
-define(ARPHRD_CISCO,    513).            %% Cisco HDLC
-define(ARPHRD_HDLC,     513).
-define(ARPHRD_LAPB,     516).            %% LAPB
-define(ARPHRD_DDCMP,    517).            %% Digitals DDCMP protocol
-define(ARPHRD_RAWHDLC,  518).            %% Raw HDLC
-define(ARPHRD_TUNNEL,   768).            %% IPIP tunnel
-define(ARPHRD_TUNNEL6,  769).            %% IP6IP6 tunnel
-define(ARPHRD_FRAD,     770).            %% Frame Relay Access Device
-define(ARPHRD_SKIP,     771).            %% SKIP vif
-define(ARPHRD_LOOPBACK, 772).            %% Loopback device
-define(ARPHRD_LOCALTLK, 773).            %% Localtalk device
-define(ARPHRD_FDDI,     774).            %% Fiber Distributed Data Interface
-define(ARPHRD_BIF,      775).            %% AP1000 BIF
-define(ARPHRD_SIT,      776).            %% sit0 device - IPv6-in-IPv4
-define(ARPHRD_IPDDP,    777).            %% IP over DDP tunneller
-define(ARPHRD_IPGRE,    778).            %% GRE over IP
-define(ARPHRD_PIMREG,   779).            %% PIMSM register interface
-define(ARPHRD_HIPPI,    780).            %% High Performance Parallel Interface
-define(ARPHRD_ASH,      781).            %% Nexus 64Mbps Ash
-define(ARPHRD_ECONET,   782).            %% Acorn Econet
-define(ARPHRD_IRDA,     783).            %% Linux-IrDA
%% ARP works differently on different FC media .. so
-define(ARPHRD_FCPP,     784).            %% Point to point fibrechannel
-define(ARPHRD_FCAL,     785).            %% Fibrechannel arbitrated loop
-define(ARPHRD_FCPL,     786).            %% Fibrechannel public loop
-define(ARPHRD_FCFABRIC, 787).            %% Fibrechannel fabric
        %% 787->799 reserved for fibrechannel media types
-define(ARPHRD_IEEE802_TR, 800).          %% Magic type ident for TR
-define(ARPHRD_IEEE80211, 801).           %% IEEE 802.11
-define(ARPHRD_IEEE80211_PRISM, 802).     %% IEEE 802.11 + Prism2 header
-define(ARPHRD_IEEE80211_RADIOTAP, 803).  %% IEEE 802.11 + radiotap header
-define(ARPHRD_IEEE802154,         804).
-define(ARPHRD_PHONET,   820).            %% PhoNet media type
-define(ARPHRD_PHONET_PIPE, 821).         %% PhoNet pipe header
-define(ARPHRD_CAIF,     822).            %% CAIF media type

-define(ARPHRD_VOID,       65535).       %% Void type, nothing is known
-define(ARPHRD_NONE,       65534).       %% zero header length


-define(IP_TOS,				1).
-define(IP_TTL,				2).
-define(IP_OPTIONS,			4).
-define(IP_HDRINCL,			3).
-define(IP_ROUTER_ALERT,		5).
-define(IP_RECVOPTS,			6).
-define(IP_RETOPTS,			7).
-define(IP_PKTINFO,			8).
-define(IP_PKTOPTIONS,			9).
-define(IP_PMTUDISC,			10).
-define(IP_MTU_DISCOVER,		10).
-define(IP_RECVERR,			11).
-define(IP_RECVTTL,			12).
-define(IP_RECVTOS,			13).
-define(IP_MTU,				14).
-define(IP_FREEBIND,			15).
-define(IP_IPSEC_POLICY,		16).
-define(IP_XFRM_POLICY,			17).
-define(IP_PASSSEC,			18).
-define(IP_TRANSPARENT,			19).
-define(IP_ORIGDSTADDR,			20).
-define(IP_MINTTL,			21).
-define(IP_NODEFRAG,			22).
-define(IP_MULTICAST_IF,		32).
-define(IP_MULTICAST_TTL,		33).
-define(IP_MULTICAST_LOOP,		34).
-define(IP_ADD_MEMBERSHIP,		35).
-define(IP_DROP_MEMBERSHIP,		36).
-define(IP_UNBLOCK_SOURCE,		37).
-define(IP_BLOCK_SOURCE,		38).
-define(IP_ADD_SOURCE_MEMBERSHIP,	39).
-define(IP_DROP_SOURCE_MEMBERSHIP,	40).
-define(IP_MSFILTER,			41).
-define(MCAST_JOIN_GROUP,		42).
-define(MCAST_BLOCK_SOURCE,		43).
-define(MCAST_UNBLOCK_SOURCE,		44).
-define(MCAST_LEAVE_GROUP,		45).
-define(MCAST_JOIN_SOURCE_GROUP,	46).
-define(MCAST_LEAVE_SOURCE_GROUP,	47).
-define(MCAST_MSFILTER,			48).
-define(IP_MULTICAST_ALL,		49).
-define(IP_UNICAST_IF,			50).

-record(sock_err, {errno, origin, type, code, info, data}).


-define(MSG_OOB,             16#01).			%% Process out-of-band data.
-define(MSG_PEEK,            16#02).			%% Peek at incoming messages.
-define(MSG_DONTROUTE,       16#04).			%% Don't use local routing.
-define(MSG_CTRUNC,          16#08).			%% Control data lost before delivery.
-define(MSG_PROXY,           16#10).			%% Supply or ask second address.
-define(MSG_TRUNC,           16#20).
-define(MSG_DONTWAIT,        16#40).			%% Nonblocking IO.
-define(MSG_EOR,             16#80).			%% End of record.
-define(MSG_WAITALL,         16#100).			%% Wait for a full request.
-define(MSG_FIN,             16#200).
-define(MSG_SYN,             16#400).
-define(MSG_CONFIRM,         16#800).			%% Confirm path validity.
-define(MSG_RST,             16#1000).
-define(MSG_ERRQUEUE,        16#2000).			%% Fetch message from error queue.
-define(MSG_NOSIGNAL,        16#4000).			%% Do not generate SIGPIPE.
-define(MSG_MORE,            16#8000).			%% Sender will send more.
-define(MSG_WAITFORONE,      16#10000).			%% Wait for at least one packet to return.*/
-define(MSG_FASTOPEN,        16#20000000).		%% Send data in TCP SYN.
-define(MSG_CMSG_CLOEXEC,    16#40000000).		%% Set close_on_exit for file
							%% descriptor received through
							%% SCM_RIGHTS.
-endif.
