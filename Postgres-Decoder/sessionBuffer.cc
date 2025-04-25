//-----------------------------------------------------------------------
//   Copyright (c) <2009> by Netezza Corporation
//   All Rights Reserved.
//   Licensed Material - Property of Netezza Corporation.
//
//   File: sessionBuffer.cc
//
//   Component: Session Data Buffering between TCP and the Decoder
//
//-----------------------------------------------------------------------
//
// The Session Buffer is a service used by each decoder which provides a
// layer between incoming TCP segments and the decoder itself.  It provides
// a measure of insulation from TCP segment boundary fragmentation by
// offering to the decoder the ability to buffer received data so that
// it can digest the stream at its own pace.  Note that the decoder is
// still aware of the fact that data is being delivered in segment-sized
// buffers.  The Session Buffer does not try to emulate socket buffering.
//
// The decoder can use the Session Buffer to selectively look at the
// entire segment being served, to extract message-header-sized chunks or
// to process it segment by segment in a streaming fashion.  Each session
// that a decoder manages has its own SsnBuf which is stored as part of
// AppInfo.
//
// In a data flow sense, when a packet is served by the Worker the decoder
// immediately turns it over to SsnBuf to manage via SbAddData().  The
// decoder is then free to extract chunks back via SbRecv() or to
// examine the entire packet via SbRecvBlock().  The vast majority of times
// it calls the former.  The latter is used typically only for
// synchronizing to a header boundary or to process streaming data.
//
// Once requesting the data, the decoder now owns it and if there is a
// portion it cannot immediately use it gives it back by calling SbReturn()
// The decoder can test how much data SsnBuf still has for this
// packet interval by calling SbAvail().
//
// When the decoder is done processing a particular packet it calls SbEnd()
// to allow the SsnBuf to complete processing.  That may mean buffering
// any remaining data for the next packet which comes in on the session.
// In fact, when writing a decoder, if fragmentation is detected, the
// decoder intentionally returns the data via SbReturn() and stops
// decoding.  When it calls SbEnd() the SsnBuf knows that it has to preserve
// any remaining data and prepend it to whatever is received next on the
// session.
//
//-----------------------------------------------------------------------

#include <stdlib.h>
#include <string.h>
#include <tizor_types.h>
#include <limits.h>
#include <netmon/driver.hh>
#include <netmon/layerManager.hh>


extern "C"
{
// netmon_types.h is extern C for the benefit of tz_watch.h linkage
#include <netmon/netmon_types.h>

#include <util/tz_assert.h>
}

#include <netmon/sessionBuffer.hh>

#define SSNBUF_FRAG_BLOCK_LEN_LOG 11
#define SSNBUF_FRAG_BLOCK_LEN (1 << SSNBUF_FRAG_BLOCK_LEN_LOG)  // 2048


static tz_uint32 SizeToFragCount (tz_uint32 size)
{
    return (SSNBUF_FRAG_BLOCK_LEN - 1 + size) >> SSNBUF_FRAG_BLOCK_LEN_LOG;
}

//-----------------------------------------------------------------------
// SbSslDecode                                             Session Buffer
//     decode/decrypt SSL-encapsulated data.
//-----------------------------------------------------------------------

sb_add_status_t
SsnBuf::SbSslDecode (tz_uint8 *data, tz_uint16 length, bool fromClient)
{
    // decrypt locals
    tz_uint16            bytesExpected;
    tz_uint16            bytesLeft, cryptoFrags;
    tz_uint32            newBufSz;
    tz_uint8             *decryptData;
    tz_uint16            decryptLen;
    tz_tls_api_status_t  tlsStatus;
    sb_add_status_t      rtnStatus = (sb_add_status_t){0,0,TTAS_OK};

    bytesExpected = bytesLeft = cryptoFrags = 0;

    // First, decrypt new data just received from the endpoint.
    // Loop over "data" until it is exhausted, or bytesExpected != 0,
    // append the decryptData to sbBuf (if the latter is empty, free
    // it, and sbBuf = decryptData).  At the end, if bytesLeft != 0,
    // shift/copy (data==sbCrypto.data) bytesExpected to the front of
    // sbCrypto.data.  Optimization: if sbBuf.len == 0,
    // free(sbBuf.data) and set sbBuf =
    // {decryptData,decryptLen,0,decryptLen}.

    for (tlsStatus = (tz_tls_api_status_t){0, TTAS_OK, 0}, decryptData = NULL;
         (bytesExpected == 0) && (length > 0);) {
        
        tlsStatus
            = sbTlsSession->TzTlsPdu ((int)fromClient, data, length,  // in
                                      &decryptData, &decryptLen,      // out
                                      &bytesExpected, &bytesLeft);    // out
        // NzAccess sends an Alert:Close Notify in both directions, and
        // tls-snoop-api.c interprets the second as an error (as the first
        // should shut down the SSL connection).  Should this be fixed in
        // tls-snoop-api?
        if ((tlsStatus.errorCode != TTAS_FATAL)
            || ((sbSslSavedStateFlags & TTAS_TLS_CLOSED) == 0))
            rtnStatus.tlsError = tlsStatus.errorCode;
        else
            rtnStatus.tlsError = TTAS_OK;
        sbSslSavedStateFlags = tlsStatus.stateFlags;
        if (tlsStatus.errorCode != TTAS_OK) {
            if (decryptData) free (decryptData);
            decryptData = NULL;
            break;
        }
        if (decryptData && decryptLen) {
            if (sbBuf.len == 0) {
                // Optimization: No sbBuf so just use the SSL-allocated buffer
                if (sbBuf.data) free (sbBuf.data);
                sbBuf.data = (tz_int8*)decryptData;
                rtnStatus.avail = sbBuf.len = sbBuf.size = decryptLen;
                rtnStatus.fragBlocks = SizeToFragCount (decryptLen);
            }
            else {
                if (sbBuf.len + decryptLen > sbBuf.size) {
                    // There is existing sbBuf data, append to it
                    rtnStatus.fragBlocks
                        = SizeToFragCount (sbBuf.len + decryptLen);
                    newBufSz = rtnStatus.fragBlocks * SSNBUF_FRAG_BLOCK_LEN;
                    sbBuf.data = (tz_int8*)realloc (sbBuf.data, newBufSz);
                    if (!sbBuf.data) {
                        rtnStatus.tlsError = tlsStatus.errorCode = TTAS_HEAP;
                        sbBufState = sslAborted;
                        free (decryptData);
                        decryptData = NULL;
                        break;
                    }
                    sbBuf.size = newBufSz;
                }
                memcpy (sbBuf.data + sbBuf.len, decryptData, decryptLen);
                rtnStatus.avail = sbBuf.len += decryptLen;
                free (decryptData);
                decryptData = NULL;
            }
        }
        else if (decryptData) { // ssldecode returns  a %#$@ zero-length buffer?
            free (decryptData);
            decryptData = NULL;
        }
        data += (length - bytesLeft);
        length = bytesLeft;
    }
    if (tlsStatus.errorCode == TTAS_OK) {
        // There is leftover encrypted data and it is not already where
        // it needs to be so save it for next time
        if (bytesLeft   
            && (((tz_uint8*)sbCrypto.data != data)
                || (bytesLeft != sbCrypto.len))) {
            if ((sbCrypto.data == NULL) || (sbCrypto.size < bytesLeft)) {
                cryptoFrags = SizeToFragCount (bytesLeft);
                sbCrypto.size = cryptoFrags * SSNBUF_FRAG_BLOCK_LEN;
                sbCrypto.data =
                    (tz_int8*) realloc (sbCrypto.data, sbCrypto.size);
                if (sbCrypto.data == NULL) {
                    sbBufState = sslAborted;
                    rtnStatus.tlsError = tlsStatus.errorCode = TTAS_HEAP;
                    goto cleanup;
                }
            }
            sbCrypto.len = bytesLeft;
            memmove (sbCrypto.data, data, bytesLeft);
        }
    }
    // take care of error conditions:  for most, just increment a
    // counter, change state to sslAborted, and bail.  destructor
    // should clean up any buffers.
    else {
        sbBufState = sslAborted;
    }
cleanup:
    sbCrypto.client = fromClient;
    rtnStatus.fragBlocks += cryptoFrags;
    return rtnStatus;
}


//-----------------------------------------------------------------------
// SbAddData()                                           Session Buffer
//     The decoder adds a newly-received TCP segment to the SsnBuf
//
// Return:
//     current fragBlock count (of SSNBUF_FRAG_BLOCK_LEN blocks) or 0
//-----------------------------------------------------------------------
sb_add_status_t
SsnBuf::SbAddData( u_char *data,    tz_uint32 length, 
                   bool fromClient, tz_uint32 tcpHole)
{
    tz_uint32  cryptoFragBlocks = 0;
    tz_uint32  newBufSz;
    tz_int8   *newBuf;
    sb_add_status_t rtnStatus = (sb_add_status_t){0, 0, TTAS_OK};

    // FIX: should this care about whether byte or block mode?

    switch (sbBufState) {
    case inactive:
        // Nothing is currently buffered
        sbPkt.data = (tz_int8 *)data;
        sbPkt.len = length;
        sbPkt.idx = 0;

        // TCP segment at beginning of buffer
        sbSegIdx        = 0;
        rtnStatus.avail = length;
        rtnStatus.fragBlocks = 0;
        break;
    case active:
        // Data has been buffered.  Let's see if it can fit into available
        // buffer space
        if( (sbBuf.size - sbBuf.len) < length )
        {
            // It can't.  Boost the buffer by however many blocks necessary
            rtnStatus.fragBlocks = SizeToFragCount (sbBuf.len + length);

            // FIX: update maxFragBlocks stat

            newBufSz = rtnStatus.fragBlocks * SSNBUF_FRAG_BLOCK_LEN;
            newBuf   = (tz_int8 *)realloc(sbBuf.data, newBufSz);

            if(newBuf == NULL)
            {
                // error
                TZ_ASSERT(false,"SbAddData()");
                break;
            }
            else
            {
                sbBuf.data = newBuf;
                sbBuf.size = newBufSz;
            }
        }

        // The assembly buffer is (or was made to be) large enough so
        // copy the new packet data.
        memcpy( &sbBuf.data[sbBuf.len],
                data,
                length );

        // Rember where TCP segment starts
        sbSegIdx = sbBuf.len;

        // Now add in the segment data
        sbBuf.len        += length;
        rtnStatus.avail   = sbBuf.len;
        sbBuf.client      = fromClient;
        break;

    case sslActive:
        if (tcpHole) {  // not yet clear how to recover from gaps.
            sbBufState         = sslAborted;
            rtnStatus.tlsError = TTAS_SYNC;
            break;
        }
        cryptoFragBlocks = 0;

        // a change in direction and yet there is still some undecrypted data
        // this is awkward: NZ is supposed to be half-duplex, so all messages
        // ought to be completely consumed before the direction changes, which
        // means the encrypted data ought to be exhausted too.
        if ((fromClient != sbCrypto.client) && sbCrypto.len) {
            sbBufState         = sslAborted;
            rtnStatus.tlsError = TTAS_SYNC;
            break;
        }
        if (sbCrypto.data && sbCrypto.len) {
            if (sbCrypto.size < (sbCrypto.len + length)) {
                cryptoFragBlocks = SizeToFragCount (sbCrypto.len + length);
                newBufSz = cryptoFragBlocks * SSNBUF_FRAG_BLOCK_LEN;
                sbCrypto.data = (tz_int8 *)realloc (sbCrypto.data, newBufSz);
                if (sbCrypto.data == NULL) {
                    sbBufState = sslAborted;
                    rtnStatus.tlsError = TTAS_HEAP;
                    break;
                }
                sbCrypto.size = newBufSz;
            }
            memcpy (sbCrypto.data+sbCrypto.len, data, length);
            length = sbCrypto.len += length;
            data = (u_char *)sbCrypto.data;
        }
        sbSegIdx = sbBuf.len;

        TZ_ASSERT (length <= USHRT_MAX, "length too large for TzTlsPdu\n");
        rtnStatus = SbSslDecode (data, (tz_uint16)length, fromClient);
        rtnStatus.avail = sbBuf.len;
        // sbSslDecode may allocate sbCrypto *and* sbBuf, but would not
        // allocate sbCrypto if allocated above, and would not count same.
        rtnStatus.fragBlocks += cryptoFragBlocks;
        break;

    case sslAborted:
        break;
    }       //  switch (sbBufState)

    return rtnStatus;
}

//-----------------------------------------------------------------------
// SbRecv()                                              Session Buffer
//     The decoder requests bufLen bytes to work with.
//
// in:
//     buf    - pointer to the buffer pointer
//     bufLen - non-zero is requested length (byte mode)
//              zero is block mode
//
// return:
//     number of bytes actually read
//-----------------------------------------------------------------------
tz_uint32 SsnBuf::SbRecv( tz_int8    **buf,
                          tz_uint32    bufLen )
{
    tz_uint32 bytesRead = 0;

    switch (sbBufState) {
    case inactive:
        // Nothing is currently buffered
        if(bufLen <= (sbPkt.len - sbPkt.idx))
        {
            *buf = &sbPkt.data[sbPkt.idx];
            sbPkt.idx += bufLen;
            bytesRead = bufLen;
        }
        else if( sbPkt.idx < sbPkt.len)
        {
            *buf = &sbPkt.data[sbPkt.idx];
            bytesRead = sbPkt.len - sbPkt.idx;
            sbPkt.idx = sbPkt.len;
        }
        else
        {
            // There's no data
            *buf = NULL;
        }
        break;
    case active:
    case sslActive:
        // Data has been buffered
        if(bufLen <= (sbBuf.len - sbBuf.idx))
        {
            *buf = &sbBuf.data[sbBuf.idx];
            sbBuf.idx += bufLen;
            bytesRead = bufLen;
        }
        else if( sbBuf.idx < sbBuf.len)
        {
            *buf = &sbBuf.data[sbBuf.idx];
            bytesRead = sbBuf.len - sbBuf.idx;
            sbBuf.idx = sbBuf.len;
        }
        else
        {
            // There's no data
            *buf = NULL;
        }
        break;
    case sslAborted:
        bytesRead = 0;
    }                   //     switch (sbBufState)
    return bytesRead;
}

//-----------------------------------------------------------------------
// SbRecvBlock                                           Session Buffer
//     The decoder requests the SessBuf to provide the entire TCP
//     segment or appended buffer.
//
// in:
//     buf    - pointer to the buffer pointer
//
// return:
//     number of valid bytes
//-----------------------------------------------------------------------
tz_uint32 SsnBuf::SbRecvBlock( tz_int8 **buf)
{
    tz_uint32 bytesRead = 0;

    switch (sbBufState) {
    case inactive:
        // Nothing is currently buffered
        *buf = &sbPkt.data[sbPkt.idx];
        bytesRead = sbPkt.len - sbPkt.idx;
        sbPkt.idx = sbPkt.len;
        break;
    case active:
    case sslActive:
        // Data has been buffered
        *buf = &sbBuf.data[sbBuf.idx];
        bytesRead = sbBuf.len - sbBuf.idx;
        sbBuf.idx = sbBuf.len;
        break;
    case sslAborted:
        *buf      = NULL;
        bytesRead = 0;
        break;
    }
    return bytesRead;
}

//-----------------------------------------------------------------------
// SbAvail                                               Session Buffer
//     Decoder asks: "How many bytes are still available for processing?"
//-----------------------------------------------------------------------
tz_uint32 SsnBuf::SbAvail()
{
    tz_uint32 rv = 0;

    switch (sbBufState) {
    case inactive:
        // Nothing is currently buffered

        // assert sbPkt.idx <= sbPkt.len

        if(sbPkt.idx > sbPkt.len)
        {
            // An error
            TZ_ASSERT(false,"SbAvail() 1");
            rv = 0;
        }
        else
        {
            rv = sbPkt.len - sbPkt.idx;
        }
        break;
    case active:
    case sslActive:

        // Data has been buffered
        if(sbBuf.idx > sbBuf.len)
        {
            // An error
            TZ_ASSERT(false,"SbAvail() 2");
            rv = 0;
        }
        else
        {
            rv = sbBuf.len - sbBuf.idx;
        }
        break;
    case sslAborted:
        rv = 0;
        break;
    }
    return rv;
}

//-----------------------------------------------------------------------
// SbReturn                                              Session Buffer
//     The decoder returns unused bytes back to the SessBuf.  If these
//     bytes remain unused when the decoder completes processing and
//     calls SbEnd() then they will be buffered and prepended to the
//     data for the next segment received on the session.
//
// in:
//     buf    - pointer to the buffer pointer
//     bufLen - number of bytes to be returned
//
//-----------------------------------------------------------------------
void SsnBuf::SbReturn( tz_int8   **buf,
                       tz_uint32   bufLen )
{
    tz_uint32 calcLen;

    if( bufLen == 0 )
    {
        // Nothing to return...
        volatile tz_uint32 stalker;
        ++stalker;
    }
    else
        switch (sbBufState) {
        case inactive:
            // Nothing is currently buffered
            calcLen = &sbPkt.data[sbPkt.idx] - *buf;

            // assert calcLen == bufLen
            // i.e., what they're telling us the length is should match
            // up with their pointer relative to ours
            TZ_ASSERT( calcLen == bufLen, "SbReturn miscalc" );

            sbPkt.idx -= calcLen;
            break;
        case active:
        case sslActive:
            // Data has been buffered
            calcLen = &sbBuf.data[sbBuf.idx] - *buf;

            // assert calcLen == bufLen
            // see note above
            TZ_ASSERT( calcLen == bufLen, "SbReturn miscalc" );

            sbBuf.idx -= calcLen;
            break;
        case sslAborted:
            break;
        }
}

//-----------------------------------------------------------------------
// SbIsBuffering                                           Session Buffer
//-----------------------------------------------------------------------
bool SsnBuf::SbIsBuffering()
{
    bool isBuffering = false;

    switch (sbBufState)
    {
    case inactive:
        break;
    case active:
        isBuffering = true;
        break;
    case sslActive:
        isBuffering = (sbBuf.idx == sbBuf.len) ? false : true;
        break;
    case sslAborted:
        break;
    }
    return isBuffering;
}

//-----------------------------------------------------------------------
// SbEnd                                                 Session Buffer
//     The decoder indicates that it's at the end of processing
//     for this packet.  If there are remaining bytes they are buffered
//     for the session.
//
// Return:
//     current fragBlock count (of SSNBUF_FRAG_BLOCK_LEN blocks) or 0
//-----------------------------------------------------------------------
tz_uint32 SsnBuf::SbEnd(bool fromClient)
{
    tz_uint32  fragBlocks = 0;
    tz_uint32  remainSz;
    tz_uint32  newBufSz;
    tz_int8   *newBuf;

    switch (sbBufState) {
    case inactive:
        // Buffering NOT in effect.  Check for index overrun
        if( sbPkt.idx > sbPkt.len )
        {
            // error
            TZ_ASSERT(false,"SbEnd() 1");
            break;
        }

        // Check for remaining data
        remainSz = sbPkt.len - sbPkt.idx;

        // If there isn't, just quit
        if (remainSz == 0)
        {
            break;
        }

        // We're back to buffering mode
        sbBufState = active;
        sbBuf.client = fromClient;

        // The SsnBuf is still holding onto data, let's see if it can
        // fit into available buffer space
        if( (sbBuf.size - sbBuf.len) < remainSz )
        {
            // It can't.  Boost the buffer by however many blocks necessary
            fragBlocks = SizeToFragCount (sbBuf.len + remainSz);

            // FIX: update maxFragBlocks stat

            newBufSz = fragBlocks * SSNBUF_FRAG_BLOCK_LEN;
            newBuf = (tz_int8 *)realloc(sbBuf.data, newBufSz);

            // assert newBuf != NULL

            if(newBuf == NULL)
            {
                // error
                TZ_ASSERT(false,"SbEnd() 2");
                break;
            }
            else
            {
                sbBuf.data   = newBuf;
                sbBuf.size = newBufSz;
            }
        }

        // The assembly buffer is (or was made to be) large enough so
        // copy the remaining packet data.
        memcpy( &sbBuf.data[sbBuf.len],
                &sbPkt.data[sbPkt.idx],
                remainSz );
        sbBuf.len += remainSz;
        break;

    case active:
    case sslActive:

        // Buffering IS in effect

        // Check for index overrun
        if( sbBuf.idx > sbBuf.len )
        {
            // error
            TZ_ASSERT(false,"SbEnd() 3");
            break;
        }

        remainSz = sbBuf.len - sbBuf.idx;
        if( remainSz == 0 )
        {
            // Exit from buffering mode.  Note that we retain the
            // buffer sbBuf and hold onto its size, sbBuf.size.  We will
            // reuse it.  Once entering sslActive, you never leave it.
            if (sbBufState == active) sbBufState = inactive;
            sbBuf.len = sbBuf.idx = 0;
            break;
        }

        // Let's move the remaining bytes to the beginning of the buffer
        if( remainSz <= sbBuf.idx )
        {
            // We can move them directly within the current buffer
            memmove(sbBuf.data, &sbBuf.data[sbBuf.idx], remainSz);
            sbBuf.idx = 0;
            sbBuf.len = remainSz;
        }
        else
        {
            // We are going to normalize the data to the start of a new
            // buffer.  If we must grow the buffer then do so.
            fragBlocks = SizeToFragCount (sbBuf.len + remainSz);
            newBufSz = fragBlocks * SSNBUF_FRAG_BLOCK_LEN;
            newBuf = (tz_int8 *)malloc(newBufSz);

            if(newBuf == NULL)
            {
                // error
                TZ_ASSERT(false,"SbEnd() 4");
                break;
            }
            else
            {
                // Normalize the data to the beginning of the new buffer
                // and free the old buffer
                memcpy(newBuf, &sbBuf.data[sbBuf.idx], remainSz);
                free(sbBuf.data);

                sbBuf.data    = newBuf;
                sbBuf.size  = newBufSz;
                sbBuf.idx = 0;
                sbBuf.len = remainSz;
            }
        }
        break;

    case sslAborted:
        fragBlocks = 0;
        break;
    }
    return fragBlocks;
}
//-----------------------------------------------------------------------
// SbShowBlockSize()
//-----------------------------------------------------------------------
tz_uint32 SsnBuf::SbShowBlockSize()
{
    return SSNBUF_FRAG_BLOCK_LEN;
}

//-----------------------------------------------------------------------
// SbShowMode()
//-----------------------------------------------------------------------
char SsnBuf::SbShowMode()
{
    char rv;
    switch (sbBufState) {
    case inactive:
        rv = 'i';
        break;
    case active:
        rv = 'a';
        break;
    case sslActive:
        rv = 's';
        break;
    case sslAborted:
        rv = 'S';
        break;
    default:
        rv = '?';
        break;
    }
    return rv;
}

//-----------------------------------------------------------------------
// SbReset()                                             Session Buffer
//     The decoder informs the SessBuf to cancel any buffering activity.
//     This is typically called when a TCP gap is encountered.
//
//     The implementation tosses away any residual data we may have had
//     so that any new SbRecv() or SbRecvBlock() requests get data
//     that starts at the beginning of this TCP segment
//-----------------------------------------------------------------------
void SsnBuf::SbReset()
{
    switch (sbBufState)
    {
    case active:
    case sslActive:
        sbBuf.idx = sbSegIdx;

        // We stay in buffering state, however.  When SbEnd() runs
        // it will normalize the data if possible (or necessary).
    case sslAborted:
    case inactive:
        break;
    }
}

//-----------------------------------------------------------------------
// SbSslInit()                                           Session Buffer
//     turn on SSL/TLS de-capsulation and decryption.
//     This assumes that whatever data remains in the current packet/buffer
//     should be input to the SSL decoder.
//-----------------------------------------------------------------------
void SsnBuf:: SbSslInit (SessionEntry *se)
{
    tz_uint8  * dataPtr = NULL;
    tz_uint32  length = 0;
    bool       fromClient;

    switch (sbBufState) {
    case sslActive:
    case sslAborted:
        return;
    case inactive:
        dataPtr = (tz_uint8*)sbPkt.data + sbPkt.idx;
        length  = sbPkt.len - sbPkt.idx;
        sbPkt.idx = sbPkt.len = 0;
        memset (&sbCrypto, 0, sizeof (sbCrypto));
        break;
    case active:
        dataPtr = (tz_uint8*)sbBuf.data + sbBuf.idx;
        length  = sbBuf.len - sbBuf.idx;
        sbBuf.idx = sbBuf.len = 0;
        memcpy (&sbCrypto, &sbBuf, sizeof (sbBuf));
        memset (&sbBuf, 0, sizeof (sbBuf));
        break;
    }
    extern LayerManager *TZ_layerManager;
    NetMonDriver        *nmd = TZ_layerManager->netMonDriver;

    sbTlsSession = nmd->tlsSnoop->CreateSession (se);
    fromClient   = se->trafficDirection == TRAFFIC_FROM_CLIENT;
    if (sbTlsSession) {
        sbBufState = sslActive;
        SbSslDecode (dataPtr, (tz_uint16)length, fromClient);
    }
    else
        sbBufState = sslAborted;
    sbSegIdx     = 0;
}
//-----------------------------------------------------------------------
// SbInit()                                              Session Buffer
//     Initialize SessBuf service at the beginning of use
//-----------------------------------------------------------------------
void SsnBuf::SbInit()
{
    sbBufState    = inactive;
    memset (&sbPkt, 0, sizeof(sbPkt));
    memset (&sbBuf, 0, sizeof(sbBuf));
    memset (&sbCrypto, 0, sizeof(sbCrypto));

    sbSegIdx = 0;
}


//-----------------------------------------------------------------------
// SsnBuf()
//-----------------------------------------------------------------------
SsnBuf::SsnBuf()
{
    sbTlsSession = NULL;
    memset (&sbCrypto, 0, sizeof(sbCrypto));
}

//-----------------------------------------------------------------------
// ~SsnBuf()
//-----------------------------------------------------------------------
SsnBuf::~SsnBuf()
{
    if(sbBuf.data)  free(sbBuf.data);
    if (sbCrypto.data) free (sbCrypto.data);
    if (sbTlsSession) delete sbTlsSession;
}


