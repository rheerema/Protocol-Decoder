//-----------------------------------------------------------------------
//   Copyright (c) <2009> by Netezza Corporation
//   All Rights Reserved.
//   Licensed Material - Property of Netezza Corporation.
//
//   File: sessionBuffer.hh
//
//   Component: Session Data Buffering between TCP and the Decoder
//
//-----------------------------------------------------------------------

#ifndef __SESSION_BUFFER_HH__
#define __SESSION_BUFFER_HH__

//-----------------------------------------------------------------------
// class SsnBuf
//-----------------------------------------------------------------------
#include <netmon/tzTlsSnoopApi.hh>
extern "C" {
#include <netmon/netmon_types.h>
}

typedef struct {
    tz_uint32 avail;
    tz_uint16 fragBlocks;
    tz_tls_api_error_code_t tlsError;
} sb_add_status_t;


class SsnBuf
{
public:

    // -- Public Functions --

    SsnBuf();
    ~SsnBuf();

    sb_add_status_t SbAddData ( u_char    *data,
                                tz_uint32  length,
                                bool       fromClient,
                                tz_uint32  tcpHole);

    tz_uint32 SbRecv( tz_int8   **buf,
                      tz_uint32   bufLen );

    tz_uint32 SbRecvBlock( tz_int8 **buf);

    void SbReturn( tz_int8   **buf,
                   tz_uint32   bufLen );

    tz_uint32 SbAvail();
    bool SbIsBuffering();

    tz_uint32 SbEnd(bool fromClient);

    tz_uint32 SbShowBlockSize();
    char      SbShowMode();
    void SbReset();
    void SbSslInit (SessionEntry *se);  // Initialize SSL processing.
    void SbInit();

    // -- Public Data --


private:

    // -- Private Functions --
    sb_add_status_t
    SbSslDecode (tz_uint8 *data, tz_uint16 length, bool fromClient);

    // -- Private Data --

    // common buffer descriptor
    typedef struct {
        tz_int8   *data;
        tz_uint32  len;         // length of data
        tz_uint32  idx;         // current offset of data
        tz_uint32  size;
        bool       client;      // direction of previous PDU
    } sb_buf_t;

    // Packet data - the current TCP segment
    sb_buf_t sbPkt;

    enum {
        inactive,
        active,
        sslActive,
        sslAborted
    } sbBufState;


    // Packet data stored in the data buffering mechanism
    // Note that when sbBufState == sslActive, sbBuf points to a buffer that
    // was allocated by the TLS/SSL layer, which is NOT quantized the same as
    // sessionBuffer allocated buffers.  TBD: move TLS/SSL into separate layer
    // between worker/TCP and decoders, and/or export heap management?
    sb_buf_t            sbBuf;        // assembly buffer
    sb_buf_t            sbCrypto;     // pending ssl-decode and decryption
    tz_uint32           sbSegIdx;     // start of current TCP segment data
    tz_uint16           sbSslSavedStateFlags;
    class TzTlsSession *sbTlsSession; // SSL crypto context

};  // class SsnBuf


#endif

