-module(gen_socket_SUITE).

-include_lib("common_test/include/ct.hrl").
-compile(export_all).

%% -------------------------------------------------------------------------------------------------
%% -- Helper Macros
-define(ASSERT(Expr),
    case Expr of
        true  -> true;
        false ->
            ct:fail(" ASSERTION FAILED!~n"
                    "Expression: ~s~n",
                    [re:replace(??Expr, "\\s*(:|\\(|\\)|,)\\s*", "\\1", [global])])
    end).

-define(MATCH(Expect_Expr, Actual_Expr),
    (fun (Expect, Expect) -> true;
         (Expect, Actual) ->
             ct:fail(" MATCH FAILED!~n"
                     "Expected: ~p~n"
                     "Actual:   ~p~n",
                     [Expect, Actual])
     end)(Expect_Expr, Actual_Expr)).

wait_for_input(Socket, Timeout) ->
    ok = gen_socket:input_event(Socket, true),
    receive
        {Socket, input_ready} ->
            ok
    after
        Timeout -> ct:fail(didnt_receive_anything)
    end.

wait_for_output(Socket, Timeout) ->
    ok = gen_socket:output_event(Socket, true),
    receive
        {Socket, output_ready} ->
            ok
    after
        Timeout -> ct:fail(cant_send)
    end.

sync_connect(ClientSocket, ServerAddress, Timeout) ->
    {error,einprogress} = gen_socket:connect(ClientSocket, ServerAddress),
    ok = gen_socket:output_event(ClientSocket, true),
    receive
        {ClientSocket, output_ready} ->
            ok
    after
        Timeout -> ct:fail(didnt_receive_connected)
    end.

%% -------------------------------------------------------------------------------------------------
%% -- Common Test Callbacks
all() ->
    [address_encoding, getsocktype, getsockname,
     async_connect, async_connect_econnrefused,
     enotconn_errors, socket_options, getsockfd,
     client_tcp_recv, client_tcp_read, client_udp_recvfrom,
     client_tcp_send, client_tcp_write, client_udp_sendto,
     client_raw_udp_sendto].

%% -------------------------------------------------------------------------------------------------
%% -- Test Cases
address_encoding(_Config) ->
    Addresses = [{inet4, {0,0,0,0}, 0},
                 {inet4, {255,255,255,255}, 65535},
                 {inet4, {127,0,0,1}, 53409},
                 {unix, <<>>},
                 {unix, <<"/foo">>},
                 {unix, <<"./foo/bar/baz">>}],

    lists:foreach(fun (AddressTerm) ->
                      EncAddress = gen_socket:nif_encode_sockaddr(AddressTerm),
                      ?ASSERT(is_binary(EncAddress)),
                      ?MATCH(AddressTerm, gen_socket:nif_decode_sockaddr(EncAddress))
                  end, Addresses).

getsocktype(_Config) ->
    Sockets = [{inet, stream, ip},
               {inet, dgram, ip},
               {inet, stream, tcp},
               {inet, dgram, udp},
               {unix, stream, ip},
               {unix, dgram, ip}],

   lists:foreach(fun ({Family, Type, Protocol}) ->
                     {ok, Socket} = gen_socket:socket(Family, Type, Protocol),
                     ?MATCH({Family, Type, Protocol}, gen_socket:getsocktype(Socket))
                 end, Sockets).

getsockfd(_Config) ->
    Sockets = [{inet, stream, ip},
               {inet, dgram, ip},
               {inet, stream, tcp},
               {inet, dgram, udp},
               {unix, stream, ip},
               {unix, dgram, ip}],

    lists:foreach(fun ({Family, Type, Protocol}) ->
			  {ok, Socket} = gen_socket:socket(Family, Type, Protocol),
			  Fd = gen_socket:getfd(Socket),
			  ?ASSERT(is_integer(Fd) andalso Fd > 0)
		  end, Sockets).

getsockname(_Config) ->
    Sockets = [{inet, stream, tcp, {inet4, {127,0,0,1}, 8900}},
               {inet, dgram, udp, {inet4, {127,0,0,1}, 8900}},
               {unix, stream, ip, {unix, <<"./test.getsockname.stream">>}},
               {unix, dgram, ip, {unix, <<"./test.getsockname.dgram">>}}],

    lists:foreach(fun ({Family, Type, Protocol, Address}) ->
                      {ok, Socket} = gen_socket:socket(Family, Type, Protocol),
                      ok = gen_socket:bind(Socket, Address),
                      ?MATCH(Address, gen_socket:getsockname(Socket))
                  end, Sockets).

async_connect(_Config) ->
    {ok, ServerSocket} = gen_tcp:listen(0, [{ip, {127,0,0,1}}]),
    {ok, Port} = inet:port(ServerSocket),

    {ok, ClientSocket} = gen_socket:socket(inet, stream, tcp),
    ServerAddress = {inet4, {127,0,0,1}, Port},
    ?MATCH({error,einprogress}, gen_socket:connect(ClientSocket, ServerAddress)),
    ?MATCH(ok, gen_socket:output_event(ClientSocket, true)),

    {ok, _} = gen_tcp:accept(ServerSocket),

    receive
        {ClientSocket, output_ready} ->
            ok;
        Msg ->
            ct:fail("~nGot unexpected message: ~p~n", [Msg])
    after
        160 -> ct:fail(didnt_receive_connected)
    end.

async_connect_econnrefused(_Config) ->
    {ok, ServerSocket} = gen_socket:socket(inet, stream, tcp),
    gen_socket:bind(ServerSocket, {inet4, {127,0,0,1}, 0}),
    %% DO NOT LISTEN for this test
    %% -- gen_socket:listen(ServerSocket, 10),
    ServerAddress = gen_socket:getsockname(ServerSocket),

    {ok, ClientSocket} = gen_socket:socket(inet, stream, tcp),
    ?MATCH({error,einprogress}, gen_socket:connect(ClientSocket, ServerAddress)),
    ok = gen_socket:output_event(ClientSocket, true),
    
    receive
        {ClientSocket, output_ready} ->
            ok;
        Msg ->
            ct:fail("~nGot unexpected message: ~p~n", [Msg])
    after
        160 -> ct:fail(didnt_receive_connected)
    end,

    ?MATCH(econnrefused, gen_socket:getsockopt(ClientSocket, sol_socket, error)).

enotconn_errors(_Config) ->
    {ok, Socket} = gen_socket:socket(inet, stream, tcp),

    %% not connected
    ?MATCH({error, enotconn}, gen_socket:read(Socket)),
    ?MATCH({error, enotconn}, gen_socket:recv(Socket)),
    ?MATCH({error, epipe}, gen_socket:write(Socket, <<"data">>)),
    ?MATCH({error, epipe}, gen_socket:send(Socket, <<"data">>)),

    {ok, ServerAcceptSocket} = gen_tcp:listen(0, [{ip, {127,0,0,1}}]),
    {ok, ServerPort} = inet:port(ServerAcceptSocket),
    ServerAddress = {inet4, {127,0,0,1}, ServerPort},

    sync_connect(Socket, ServerAddress, 160),

    ok = gen_socket:shutdown(Socket, read_write),

    %% closed
    ?MATCH(eof, gen_socket:read(Socket)),
    ?MATCH(eof, gen_socket:recv(Socket)),
    ?MATCH({error, epipe}, gen_socket:write(Socket, <<"data">>)),
    ?MATCH({error, epipe}, gen_socket:send(Socket, <<"data">>)),

    ok = gen_socket:close(Socket),

    %% closed
    ?MATCH({error, ebadf}, gen_socket:read(Socket)),
    ?MATCH({error, ebadf}, gen_socket:recv(Socket)),
    ?MATCH({error, ebadf}, gen_socket:write(Socket, <<"data">>)),
    ?MATCH({error, ebadf}, gen_socket:send(Socket, <<"data">>)).

socket_options(_Config) ->
    {ok, Socket} = gen_socket:socket(inet, stream, tcp),
    ok = gen_socket:setsockopt(Socket, sol_socket, rcvbuf, 8192),
    (8192 * 2) = gen_socket:getsockopt(Socket, sol_socket, rcvbuf).

client_tcp_recv(_Config) ->
    TestStrings = [<<"test">>, <<"test test">>],

    %% open server socket
    {ok, ServerAcceptSocket} = gen_tcp:listen(0, [{ip, {127,0,0,1}}]),
    {ok, ServerPort} = inet:port(ServerAcceptSocket),
    ServerAddress = {inet4, {127,0,0,1}, ServerPort},

    %% send test strings to our client socket in a separate process once it connects
    _ServerProc = spawn_link(fun () ->
                                 {ok, ServerSocket} = gen_tcp:accept(ServerAcceptSocket),
                                 lists:foreach(fun (TestString) ->
                                                   ok = gen_tcp:send(ServerSocket, TestString)
                                               end, TestStrings)
                             end),

    %% open and connect client socket
    {ok, ClientSocket} = gen_socket:socket(inet, stream, tcp),
    ok = sync_connect(ClientSocket, ServerAddress, 160),

    ?MATCH(ServerAddress, gen_socket:getpeername(ClientSocket)),

    %% receive test strings using the client socket
    lists:foreach(fun (TestString) ->
			  wait_for_input(ClientSocket, 20),
			  ?MATCH({ok, TestString}, gen_socket:recv(ClientSocket, byte_size(TestString)))
                  end, TestStrings).

client_tcp_read(_Config) ->
    TestStrings = [<<"test">>, <<"test test">>],

    %% open server socket
    {ok, ServerAcceptSocket} = gen_tcp:listen(0, [{ip, {127,0,0,1}}]),
    {ok, ServerPort} = inet:port(ServerAcceptSocket),
    ServerAddress = {inet4, {127,0,0,1}, ServerPort},

    %% send test strings to our client socket in a separate process once it connects
    _ServerProc = spawn_link(fun () ->
                                 {ok, ServerSocket} = gen_tcp:accept(ServerAcceptSocket),
                                 lists:foreach(fun (TestString) ->
                                                   ok = gen_tcp:send(ServerSocket, TestString)
                                               end, TestStrings)
                             end),

    %% open and connect client socket
    {ok, ClientSocket} = gen_socket:socket(inet, stream, tcp),
    ok = sync_connect(ClientSocket, ServerAddress, 160),

    ?MATCH(ServerAddress, gen_socket:getpeername(ClientSocket)),

    %% receive test strings using the client socket
    lists:foreach(fun (TestString) ->
			  wait_for_input(ClientSocket, 20),
			  ?MATCH({ok, TestString}, gen_socket:read(ClientSocket, byte_size(TestString)))
                  end, TestStrings).

client_udp_recvfrom(_Config) ->
    TestStrings = [<<"test">>, <<"test test">>],

    %% open server socket
    {ok, ServerSocket} = gen_udp:open(0, [{ip, {127,0,0,1}}]),
    {ok, ServerPort} = inet:port(ServerSocket),
    ServerAddress = {inet4, {127,0,0,1}, ServerPort},

    %% open and connect client socket
    {ok, ClientSocket} = gen_socket:socket(inet, dgram, udp),
    ok = gen_socket:connect(ClientSocket, ServerAddress),
    ?MATCH(ServerAddress, gen_socket:getpeername(ClientSocket)),
    {inet4, _, ClientPort} = gen_socket:getsockname(ClientSocket),

    %% send test strings to our client socket in a separate process
    _ServerProc = spawn_link(fun () ->
                                 lists:foreach(fun (TestString) ->
                                                   ok = gen_udp:send(ServerSocket,
                                                                     {127,0,0,1},
                                                                     ClientPort,
                                                                     TestString)
                                               end, TestStrings)
                             end),

    %% receive test strings using the client socket
    lists:foreach(fun (TestString) ->
                      wait_for_input(ClientSocket, 20),
                      ?MATCH({ok, ServerAddress, TestString}, gen_socket:recvfrom(ClientSocket))
                  end, TestStrings).

client_tcp_send(_Config) ->
    TestStrings = [<<"test">>, <<"test test">>],

    %% open server socket
    {ok, ServerAcceptSocket} = gen_tcp:listen(0, [{ip, {127,0,0,1}}, {active, false}, binary]),
    {ok, ServerPort} = inet:port(ServerAcceptSocket),
    ServerAddress = {inet4, {127,0,0,1}, ServerPort},

    %% open and connnect client socket
    {ok, ClientSocket} = gen_socket:socket(inet, stream, tcp),
    sync_connect(ClientSocket, ServerAddress, 150),
    {ok, ServerSocket} = gen_tcp:accept(ServerAcceptSocket),
    ?MATCH(ServerAddress, gen_socket:getpeername(ClientSocket)),

    %% send test strings from the client to the server
    lists:foreach(fun (TestString) ->
			  wait_for_output(ClientSocket, 20),
			  ?MATCH({ok, <<>>}, gen_socket:send(ClientSocket, TestString)),
			  ?MATCH({ok, TestString},
				 gen_tcp:recv(ServerSocket, byte_size(TestString), 50))
                  end, TestStrings).

client_tcp_write(_Config) ->
    TestStrings = [<<"test">>, <<"test test">>],

    %% open server socket
    {ok, ServerAcceptSocket} = gen_tcp:listen(0, [{ip, {127,0,0,1}}, {active, false}, binary]),
    {ok, ServerPort} = inet:port(ServerAcceptSocket),
    ServerAddress = {inet4, {127,0,0,1}, ServerPort},

    %% open and connnect client socket
    {ok, ClientSocket} = gen_socket:socket(inet, stream, tcp),
    sync_connect(ClientSocket, ServerAddress, 150),
    {ok, ServerSocket} = gen_tcp:accept(ServerAcceptSocket),
    ?MATCH(ServerAddress, gen_socket:getpeername(ClientSocket)),

    %% send test strings from the client to the server
    lists:foreach(fun (TestString) ->
			  wait_for_output(ClientSocket, 20),
			  ?MATCH({ok, <<>>}, gen_socket:write(ClientSocket, TestString)),
			  ?MATCH({ok, TestString},
				 gen_tcp:recv(ServerSocket, byte_size(TestString), 50))
                  end, TestStrings).

client_udp_sendto(_Config) ->
    TestStrings = [<<"test">>, <<"test test">>],

    %% open server socket
    {ok, ServerSocket} = gen_udp:open(0, [{ip, {127,0,0,1}}, {active, false}, binary]),
    {ok, ServerPort} = inet:port(ServerSocket),
    ServerAddress = {inet4, {127,0,0,1}, ServerPort},

    %% open client socket
    {ok, ClientSocket} = gen_socket:socket(inet, dgram, udp),
    ok = gen_socket:bind(ClientSocket, {inet4, {127,0,0,1}, 0}),
    {inet4, ClientIP, ClientPort} = gen_socket:getsockname(ClientSocket),

    %% send test strings from the client to the server
    lists:foreach(fun (TestString) ->
                      wait_for_output(ClientSocket, 20),
                      ?MATCH({ok, <<>>}, gen_socket:sendto(ClientSocket, ServerAddress, TestString)),
                      ?MATCH({ok, {ClientIP, ClientPort, TestString}},
                             gen_udp:recv(ServerSocket, byte_size(TestString), 1000))
                  end, TestStrings).

client_raw_udp_sendto(_Config) ->
    TestStrings = [<<"test">>, <<"test test">>],

    %% open server socket
    ServerIP = {127,0,0,1},
    {ok, ServerSocket} = gen_udp:open(0, [{ip, ServerIP}, {active, false}, binary]),
    {ok, ServerPort} = inet:port(ServerSocket),
    ServerAddress = {inet4, ServerIP, ServerPort},
    
    %% open redirector server socket
    {ok, RedirectorServerSocket} = gen_socket:socket(inet, dgram, udp),
    ok = gen_socket:bind(RedirectorServerSocket, {inet4, {127,0,0,1}, 0}),
    {inet4, RedirectorServerIP, RedirectorServerPort} = gen_socket:getsockname(RedirectorServerSocket),

    %% open redirector sender socket
    {ok, RedirectorSenderSocket} = gen_socket:socket(inet, raw, udp),
    ok = gen_socket:setsockopt(RedirectorSenderSocket, sol_ip, hdrincl, true),
    ok = gen_socket:bind(RedirectorSenderSocket, {inet4, {127,0,0,1}, 0}),

    %% open server socket
    ClientIP = {127,0,0,1},
    {ok, ClientSocket} = gen_udp:open(0, [{ip, ClientIP}, {active, false}, binary]),
    {ok, ClientPort} = inet:port(ClientSocket),
    ClientAddress = {inet4, {127,0,0,1}, ClientPort},

    %% send test strings from the client to the server through redirector
    %% server should think that it gets packet directly from client
    %% redirector has two sockets: 
    %% 1) for reading udp
    %% 2) for sending raw ipv4
    lists:foreach(fun (TestString) ->
                      ?MATCH(ok, gen_udp:send(ClientSocket, RedirectorServerIP, RedirectorServerPort, TestString)),

                      wait_for_output(RedirectorServerSocket, 20),
                      ?MATCH({ok, ClientAddress, TestString}, gen_socket:recvfrom(RedirectorServerSocket)),

                      Packet = create_ipv4_udp_packet(ClientIP, ClientPort, ServerIP, ServerPort, TestString),

                      wait_for_output(RedirectorSenderSocket, 20),
                      ?MATCH({ok, <<>>}, gen_socket:sendto(RedirectorSenderSocket, ServerAddress, Packet)),

                      ?MATCH({ok, {ClientIP, ClientPort, TestString}},
                             gen_udp:recv(ServerSocket, byte_size(TestString), 1000))
                  end, TestStrings).

optlen(HL) -> (HL - 5) * 4.
create_ipv4_udp_packet({SA1, SA2, SA3, SA4}, SPort, {DA1, DA2, DA3, DA4}, DPort, Payload) ->
    % UDP
    ULen = 8 + byte_size(Payload),
    USum = 0,
    UDP = <<SPort:16, DPort:16, ULen:16, USum:16, Payload/binary>>,
    % IPv4
    HL = 5, DSCP = 0, ECN = 0, Len = 160 + optlen(HL) + byte_size(UDP),
    Id = 0, DF = 0, MF = 0, Off = 0,
    TTL = 64, Protocol = 17, Sum = 0,
    Opt = <<>>,
    % Packet
    <<4:4, HL:4, DSCP:6, ECN:2, Len:16, 
      Id:16, 0:1, DF:1, MF:1, Off:13, 
      TTL:8, Protocol:8, Sum:16,
      SA1:8, SA2:8, SA3:8, SA4:8, 
      DA1:8, DA2:8, DA3:8, DA4:8, 
      Opt:(optlen(HL))/binary, UDP/binary>>.
