/*
 * Copyright (c) 2010-2012, Travelping GmbH <info@travelping.com
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 *
 * Redistributions of source code must retain the above copyright
 * notice, this list of conditions and the following disclaimer.
 *
 * Redistributions in binary form must reproduce the above copyright
 * notice, this list of conditions and the following disclaimer in the
 * documentation and/or other materials provided with the distribution.
 *
 * Neither the name of the author nor the names of its contributors
 * may be used to endorse or promote products derived from this software
 * without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
 * "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
 * LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS
 * FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE
 * COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT,
 * INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING,
 * BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
 * LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER
 * CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN
 * ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
 * POSSIBILITY OF SUCH DAMAGE.
 */

#include <stdio.h>
#include <string.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <unistd.h>
#include <fcntl.h>
#include <limits.h>

// addresses
#include <sys/un.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netpacket/packet.h>

#ifdef AF_NETLINK
    #include <linux/netlink.h>
#endif

// driver
#include <erl_driver.h>
#include <ei.h>

#include "gen_socket_common.h"

// pre-R15B erl_driver.h doesn't have ErlDrvSizeT
#if ERL_DRV_EXTENDED_MAJOR_VERSION < 2
    typedef int DRV_SSIZE_T;
    typedef int DRV_SIZE_T;
#else
    typedef ErlDrvSSizeT DRV_SSIZE_T;
    typedef ErlDrvSizeT DRV_SIZE_T;
#endif

#define DRV_CALL_BADARG ((DRV_SSIZE_T) -1)

// http://stackoverflow.com/questions/3553296/c-sizeof-single-struct-member
#define member_size(type, member) sizeof(((type *)0)->member)

// -------------------------------------------------------------------------------------------------
// -- INTERNAL DATA STRUCTURES
typedef enum {
    GS_CALL_SETSOCKET  = 'S',
    GS_CALL_POLL_INPUT  = 'I',
    GS_CALL_POLL_OUTPUT = 'O'
} GsCall;

typedef struct {
	ErlDrvPort drv_port;
	int fd;
	int socket_len;
	char socket[128];
} GsState;

static ErlDrvTermData input_atom;
static ErlDrvTermData output_atom;

// -------------------------------------------------------------------------------------------------
// -- HELPER FUNCTIONS
inline static int
gs_alloc_rbuf_if_needed(GsState* state, int ei_idx, char** ei_rbuf, char** rbuf, DRV_SIZE_T rbuf_len)
{
    if (ei_idx > rbuf_len) {
        *ei_rbuf = driver_alloc(ei_idx);
        if (*ei_rbuf == NULL) {
            driver_failure_posix(state->drv_port, ENOMEM);
            return -1;
        }
    } else {
        *ei_rbuf = *rbuf;
    }
    return 0;
}


inline static DRV_SSIZE_T
gs_ei_errno_tuple(GsState* state, int error, char** rbuf, DRV_SIZE_T rlen)
{
    int ei_idx = 0;
    char* ei_rbuf = NULL;

    // first run computes size, second run does the encoding
    do {
        if (ei_idx > 0) {
            if (gs_alloc_rbuf_if_needed(state, ei_idx, &ei_rbuf, rbuf, rlen))
                return DRV_CALL_BADARG;
            ei_idx = 0;
        }

        ei_encode_version(ei_rbuf, &ei_idx);
        ei_encode_tuple_header(ei_rbuf, &ei_idx, 2);
        ei_encode_atom(ei_rbuf, &ei_idx, "error");
        ei_encode_atom(ei_rbuf, &ei_idx, erl_errno_id(error));
    } while (ei_rbuf == NULL);

    *rbuf = ei_rbuf;
    return (DRV_SSIZE_T) ei_idx;
}

inline static DRV_SSIZE_T
gs_ei_single_atom(GsState* state, const char* atom, char** rbuf, DRV_SIZE_T rlen)
{
    // first run computes size, second run does the encoding
    char* ei_rbuf = NULL;
    int ei_idx = 0;

    do {
        if (ei_idx > 0) {
            if (gs_alloc_rbuf_if_needed(state, ei_idx, &ei_rbuf, rbuf, rlen))
                return DRV_CALL_BADARG;
            ei_idx = 0;
        }

        ei_encode_version(ei_rbuf, &ei_idx);
        ei_encode_atom(ei_rbuf, &ei_idx, atom);
    } while (ei_rbuf == NULL);

    *rbuf = ei_rbuf;
    return (DRV_SSIZE_T) ei_idx;
}

static void
gs_send_single_atom(GsState* state, ErlDrvTermData atom)
{
	ErlDrvTermData output[] = {
		ERL_DRV_EXT2TERM, (ErlDrvTermData)state->socket, state->socket_len,
		ERL_DRV_ATOM, atom,
		ERL_DRV_TUPLE, 2
	};
#ifdef OLD_NIF
    driver_output_term(state->drv_port, output, sizeof(output) / sizeof(ErlDrvTermData));
#else
    erl_drv_output_term(driver_mk_port(state->drv_port), output, sizeof(output) / sizeof(ErlDrvTermData));
#endif
}

// -------------------------------------------------------------------------------------------------
// -- GS_CALL OPS
static DRV_SSIZE_T
gs_call_setsocket(GsState* state, char* buf, DRV_SIZE_T len, char** rbuf, DRV_SIZE_T rlen)
{
	if (len > sizeof(state->socket))
		return DRV_CALL_BADARG;

	memcpy(&state->socket, buf, len);
	state->socket_len = len;

	return gs_ei_single_atom(state, "ok", rbuf, rlen);
}

static DRV_SSIZE_T
gs_call_poll_input(GsState* state, char* buf, DRV_SIZE_T len, char** rbuf, DRV_SIZE_T rlen)
{
    // decode args from buf: Set::bool()
    int ei_version;
    int ei_idx = 0;
    int set;

    if (ei_decode_version(buf, &ei_idx, &ei_version)
	|| ei_decode_boolean(buf, &ei_idx, &set))
	    return DRV_CALL_BADARG;

    driver_select(state->drv_port, (ErlDrvEvent)(long) state->fd, ERL_DRV_READ, set);
    return gs_ei_single_atom(state, "ok", rbuf, rlen);
}

static DRV_SSIZE_T
gs_call_poll_output(GsState* state, char* buf, DRV_SIZE_T len, char** rbuf, DRV_SIZE_T rlen)
{
    // decode args from buf: Set::bool()
    int ei_version;
    int ei_idx = 0;
    int set;

    if (ei_decode_version(buf, &ei_idx, &ei_version)
	|| ei_decode_boolean(buf, &ei_idx, &set))
	    return DRV_CALL_BADARG;

    driver_select(state->drv_port, (ErlDrvEvent)(long) state->fd, ERL_DRV_WRITE, set);
    return gs_ei_single_atom(state, "ok", rbuf, rlen);
}

// -------------------------------------------------------------------------------------------------
// -- DRIVER CALLBACKS
static ErlDrvData
gs_start(ErlDrvPort port, char* command_str)
{
    // ensure the driver stays loaded even if
    // an error is returned from gs_start
    driver_lock_driver(port);

    GsState* state;

    state = driver_alloc(sizeof(GsState));
    if (state == NULL) {
        return ERL_DRV_ERROR_GENERAL;
    }
    state->drv_port = port;
    state->socket_len = 0;

    // parse domain, type, protocol from argument string
    if (sscanf(command_str, "gen_socket %d", &state->fd) == EOF) {
	    driver_free(state);
	    return ERL_DRV_ERROR_BADARG;
    }

    if (state->fd == -1) {
	    driver_free(state);
	    return ERL_DRV_ERROR_ERRNO;
    }

    driver_select(port, (ErlDrvEvent)(long) state->fd, ERL_DRV_USE, 1);
    return (ErlDrvData) state;
}

static void
gs_stop(ErlDrvData drv_data)
{
    GsState* state = (GsState*) drv_data;
    driver_select(state->drv_port, (ErlDrvEvent)(long) state->fd, ERL_DRV_READ | ERL_DRV_WRITE | ERL_DRV_USE, 0);

    driver_free(drv_data);
}

static DRV_SSIZE_T
gs_call(ErlDrvData drv_data,
        unsigned int command,
        char* buf,
        DRV_SIZE_T len,
        char** rbuf,
        DRV_SIZE_T rlen,
        unsigned int* flags)
{
    GsState* state = (GsState*) drv_data;

    switch ((GsCall) command) {
    case GS_CALL_SETSOCKET:
            return gs_call_setsocket(state, buf, len, rbuf, rlen);
    case GS_CALL_POLL_INPUT:
            return gs_call_poll_input(state, buf, len, rbuf, rlen);
    case GS_CALL_POLL_OUTPUT:
	    return gs_call_poll_output(state, buf, len, rbuf, rlen);
    default:
            return DRV_CALL_BADARG;
    }
}

static void
gs_ready_input(ErlDrvData drv_data, ErlDrvEvent event)
{
    GsState* state = (GsState*) drv_data;

    gs_send_single_atom(state, input_atom);

    // deselect
    driver_select(state->drv_port, (ErlDrvEvent)(long) state->fd, ERL_DRV_READ, 0);
}

static void
gs_ready_output(ErlDrvData drv_data, ErlDrvEvent event)
{
    GsState* state = (GsState*) drv_data;

    gs_send_single_atom(state, output_atom);

    // deselect
    driver_select(state->drv_port, (ErlDrvEvent)(long) state->fd, ERL_DRV_WRITE, 0);
}

static void
gs_stop_select(ErlDrvEvent event, void* reserved)
{
}

// -------------------------------------------------------------------------------------------------
// -- DRIVER ENTRY
static ErlDrvEntry gs_driver_entry = {
    NULL,                       // init
    gs_start,                   // start
    gs_stop,                    // stop
    NULL,                       // output
    gs_ready_input,             // ready_input
    gs_ready_output,            // ready_output
    "gen_socket",               // driver_name
    NULL,                       // finish
    NULL,                       // OTP INTERNAL: handle
    NULL,                       // control
    NULL,                       // timeout
    NULL,                       // outputv
    NULL,                       // ready_async
    NULL,                       // flush
    gs_call,                    // call
    NULL,                       // UNDOCUMENTED: event
    ERL_DRV_EXTENDED_MARKER,
    ERL_DRV_EXTENDED_MAJOR_VERSION,
    ERL_DRV_EXTENDED_MINOR_VERSION,
    ERL_DRV_FLAG_USE_PORT_LOCKING,
    NULL,                       // OTP INTERNAL: handle2
    NULL,                       // process_exit
    gs_stop_select              // stop_select
};

DRIVER_INIT(gen_socket)
{
	input_atom = driver_mk_atom("input_ready");
	output_atom = driver_mk_atom("output_ready");

	return &gs_driver_entry;
}
