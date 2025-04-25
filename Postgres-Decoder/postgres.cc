//-----------------------------------------------------------------------
//   Copyright (c) <2009> by Netezza Corporation
//   All Rights Reserved.
//   Licensed Material - Property of Netezza Corporation.
//
//   File: postgres.cc
// 
//   Component: PostgreSQL Frontend/Backend message protocol
//
//-----------------------------------------------------------------------
//  Discussion
//  ----------
// This Postgres decoder is an implementation of the Netezza
// frontend/backend protocol.  In the future it may possibly also 
// accommodate generic Postgres client traffic auditing within this 
// decoder, should that become necessary.
// 
// As far as the design of this decoder goes, allow me to sketch the
// brief history of Tizor protocol adapter decoders.  The original 
// decoders simply accepted the entire TCP segment and acted upon it.
// Where buffering was necessary to bridge across a segment boundary
// those decoders implemented the buffering themselves (and in 
// multiple areas throughout the decoder).
// 
// The TDS II decoder (brought to you by Chuck) incorporated the bold
// new idea of looking for segment boundaries at each data access.  This
// allowed for graceful handling of arbitrary segment sizes.
// 
// This postgres decoder incorporates another idea. It inserts a
// layer between the Worker that contains it and the decoder itself, 
// that of the "session buffer".  The SsnBuf layer absorbs the 
// responsibility of buffering remainder bytes and allows the decoder
// to consume the byte stream in an organized manner and to quit 
// processing if there is a data underflow condition.  In that way it
// is not aware of the need for buffering.  It either gets what it 
// needs or waits until next time to try again.
// 
// So, upon receiving a packet, the decoder hands it over to the SsnBuf
// and then nibbles away at data by asking the SsnBuf for small amounts
// at a time.  Refer to the header comments in sessionBuffer.cc for a
// greater discription.  The SsnBuf interface also allows for a
// "streaming mode" where the decoder grabs the whole segment.  At
// certain times this is more efficient than nibbling.
//
//   Some General Programming Notes
//   ------------------------------
// The design is based on the state machine concept of processing that 
// advances through the stream of data.  Initially the state machine 
// looks for "header synchronization" which is the client's attempt
// to log into the backend.  This is necessary to establish the identity
// of the user on the session.  From there the state machine advances
// through the handshake and authentication stages and into the query
// execution state where it remains throughout the majority of the 
// session.
// 
// So when coding message handlers one must always be aware that data
// must be consumed in order to allow the statemachine to proceed.
// In the typical working case the decoder quits decoding when it
// cannot get all the data it needs for the current quantum of 
// processing.  It knows there are remaining bytes in the segment
// (i.e., SbAvail() is non-zero) but it trusts that they will reappear
// when the next segment is received on the session.
// 
// If unknown data is encountered, it must be consumed anyway or the
// SsnBuf will make the data reappear again and again in subsequent
// segments.  Data is consumed through calls to SbRecv() or 
// SbRecvBlock() without returning the data to the SsnBuf through
// SbReturn().  That way, when the decoder is done and it calls
// SbEnd() there is no remaing data to buffer.
//
//   A "Netmon 2 Ready" Decoder
//   --------------------------
// This decoder also implements some "Netmon 2" concepts.  Netmon2 
// utilizes a multi-threaded event stack versus the single threaded event
// stack in Netmon1 that is locked by IncomingTransaction() and unlocked
// when the event is issued to the conduit.  The current code base is
// still Netmon1, however.
// 
// Concept 1 - the decoder builds sessionDetail directly rather than
// having the encodingEngine build it when the first event on a
// session is received.
// 
// Concept 2 - the decoder calls InjectEvent() which will be the interface
// into the event stack in Netmon2
// 
// When the Netmon2 code base is ready the decoder will rely on an
// Event object for all the services necessary to build an event
// to be issued to the database.
//
//   Query Response Mechanisms
//   -------------------------
// To aid in evaluating Postgres decoder code a summary of message codepoint
// flows  is described here for quick reference.  All of these scenario
// mechanisms relate to the query phase which is entered when the client
// has authenticated with the backend.
//
// In the diagrams below, the client/frontend is shown on left and the 
// server/backend on the right.  Here is a summary of codepoints:
//
// * query/response codepoints
//     Q query
//     P portal (response data from server)
//     P parse (request from client)
//     C close
//
// * response data descriptor codepoints
//     T row descriptor
//     D ascii data row
//     B binary data row
//     X ascii data row
//     Y ascii data row
//
// * terminating codepoints
//     E error (if present it issues an event)
//     Z ready for query (Mantra event issued here)
//
//   Codepoint Flows
//   ---------------
// There are a few basic client-server interaction patterns.  Client is
// on the left side.
//
// Mechanism 1 (M1)
//     Q >
//       < P
//       < [T | D | B | X | Y ]   // optional data
//       < C Z                    // Z issues EVT
//
// Mechanism 2  (M2)
//     Q >
//       < C Z                    // Z issues EVT
//
// Mechanism 3  (M3)
//     P >
//       < [T | D | B | X | Y ]   // optional data
//       < C Z                    // Z issues EVT
//
// Mechanism 4  (M4)
//    P >
//      < P
//      < [T | D | B | X | Y ]    // optional data
//      < C Z                     // Z issues EVT
//
// Mechanism 5  (M5)            // Error trumps RdyQuery to issue events
//    P >
//      < N          // optional
//      < C C C E Z  // if E present it issues EVT, Z is then ignored
//
// Mechanism 6  (M6)            // Load/Unload
//     P >
//       < l                    // load/unload file name
//       >                      // load/unload data
//       < e                    // log file name
//       <                      // load statistics info message
//       < C INSERT 0 <num> Z   // <num> records loaded
//
//-----------------------------------------------------------------------

#include <tizor_types.h>

extern "C"
{
// netmon_types.h is extern C for the benefit of tz_watch.h linkage
#include <netmon/netmon_types.h>

#include <util/tz_assert.h>
}

#include <parser/nzSql.h>
#include <contentScanner/patternManager.hh>
#include <contentScanner/contentScanner.hh>
#include <netmon/layerManager.hh>
#include <netmon/postgres.hh>

extern LayerManager *TZ_layerManager;

//
// Simple crappy printf debug
//
// First Level Debug Print
#define Dprint(format, ...)  \
if(dbgLvl0) { printf(format, ## __VA_ARGS__); fflush(stdout); }

// Second Level Debug Print
#define Dprint1(format, ...)  \
if(dbgLvl1) { printf(format, ## __VA_ARGS__); fflush(stdout); }

// Static member allocations
bool PgDecode::dbgLvl0;
bool PgDecode::dbgLvl1;
bool PgDecode::dbgDump;

//
// -- Standard Postgres Data Access Functions --
//         (big endian representation)
//
// host-to-Postgres  and  Postgres-to-host
//     (htop)                 (ptoh)
tz_uint64 htopll( tz_uint64 val ) __attribute__((always_inline));
tz_uint32 htopl( tz_uint32 val ) __attribute__((always_inline));
tz_uint16 htops( tz_uint16 val ) __attribute__((always_inline));
tz_uint64 ptohll( tz_uint64 val ) __attribute__((always_inline));
tz_uint32 ptohl( tz_uint32 val ) __attribute__((always_inline));
tz_uint16 ptohs( tz_uint16 val ) __attribute__((always_inline));


tz_uint64 htopll( tz_uint64 val )
{
    return    ((val & 0xff00000000000000LL) >> 56)
            + ((val & 0x00ff000000000000LL) >> 40)
            + ((val & 0x0000ff0000000000LL) >> 24)
            + ((val & 0x000000ff00000000LL) >>  8)
            + ((val & 0x00000000ff000000LL) <<  8)
            + ((val & 0x0000000000ff0000LL) << 24)
            + ((val & 0x000000000000ff00LL) << 40)
            + ((val & 0x00000000000000ffLL) << 56);
}

tz_uint32 htopl( tz_uint32 val )
{
    return    ((val & 0xff000000) >> 24)
            + ((val & 0x00ff0000) >> 8)
            + ((val & 0x0000ff00) << 8)
            + ((val & 0x000000ff) << 24);
}

tz_uint16 htops( tz_uint16 val )
{
    return   ((val & 0xff00) >> 8)
           + ((val & 0x00ff) << 8);
}

tz_uint64 ptohll( tz_uint64 val )
{
    return    ((val & 0xff00000000000000LL) >> 56)
            + ((val & 0x00ff000000000000LL) >> 40)
            + ((val & 0x0000ff0000000000LL) >> 24)
            + ((val & 0x000000ff00000000LL) >>  8)
            + ((val & 0x00000000ff000000LL) <<  8)
            + ((val & 0x0000000000ff0000LL) << 24)
            + ((val & 0x000000000000ff00LL) << 40)
            + ((val & 0x00000000000000ffLL) << 56);
}

tz_uint32 ptohl( tz_uint32 val )
{
    return    ((val & 0xff000000) >> 24)
            + ((val & 0x00ff0000) >> 8)
            + ((val & 0x0000ff00) << 8)
            + ((val & 0x000000ff) << 24);
}

tz_uint16 ptohs( tz_uint16 val )
{
    return   ((val & 0xff00) >> 8)
           + ((val & 0x00ff) << 8);
}

//
// -- Netezza Postgres Data Access Functions --
//       (little endian representation)
//
// Little Endian was chosen because the majority of their clients and
// certainly the host machine are Intel-based.
//
// host-to-NZ  and  NZ-to-host
//     (hton)        (ntoh)
//
tz_uint64 htonzll( tz_uint64 val ) __attribute__((always_inline));
tz_uint32 htonzl( tz_uint32 val ) __attribute__((always_inline));
tz_uint16 htonzs( tz_uint16 val ) __attribute__((always_inline));
tz_uint64 nztohll( tz_uint64 val ) __attribute__((always_inline));
tz_uint32 nztohl( tz_uint32 val ) __attribute__((always_inline));
tz_uint16 nztohs( tz_uint16 val ) __attribute__((always_inline));

// null translation
tz_uint64 htonzll( tz_uint64 val ) {return val;}
tz_uint32 htonzl( tz_uint32 val )  {return val;}
tz_uint16 htonzs( tz_uint16 val )  {return val;}
tz_uint64 nztohll( tz_uint64 val ) {return val;}
tz_uint32 nztohl( tz_uint32 val )  {return val;}
tz_uint16 nztohs( tz_uint16 val )  {return val;}


// Macros for dereferencing a pointer to various data sizes
//
#define _U8(val)  (*((tz_uint8 *)(val)))
#define _U16(val) (*((tz_uint16 *)(val)))
#define _U32(val) (*((tz_uint32 *)(val)))
#define _U64(val) (*((tz_uint64 *)(val)))

#define _CASE_(x) case x: stg=#x;

//
// Unit Test
//
//#include "/user/rheerema/devel/proj/nz-adapter/rcv-from-phil-auth-seq.c"

//-----------------------------------------------------------------------
// PostgresProcess()
//-----------------------------------------------------------------------
tz_uint32 PgDecode::PostgresProcess( SessionEntry *se,
                                     const u_char *data, 
                                     tz_uint32     length,
                                     tz_uint32     tcpHole )
{
    tz_uint32  status     = IIMS_SUCCESS;
    bool       isDecoding = true;
    PgInfo    *pgInfo     = (PgInfo *)se->appInfo;
    sb_add_status_t       sbAddStatus;
    tz_uint32  fragBlocks;

    pgInfo->pktCount++;

    if (se->trafficDirection == TRAFFIC_FROM_CLIENT)
        pgClientPkts++;
    else
        pgServerPkts++;

    // We must check for an interrupt request from the client side
    // where they are trying to halt long-running server response data.
    if(   se->trafficDirection == TRAFFIC_FROM_CLIENT
       && pgInfo->ssnBuf->SbIsBuffering())
    {
        PgHandlerType currHnd = IdentifyHandler(se);
        if(currHnd == HndNzProcessQuery || currHnd == HndNzProcessQueryCont)
        {
            if(dbgDump)  DumpPkt(se, (tz_int8 *)data, length);

            // Just toss the data
            return status;
        }
    }

    // Typical case handling here.  Decoder hands the data over to the ssnBuf
    // so that the decoder can then request it piecemeal and nibble away at
    // it.  We keep tabs on how many blocks it is using to buffer and how
    // often certain SSL errors occur (note: sessionBuffer hides SSL/TLS 
    // encapsulation).
    sbAddStatus = pgInfo->ssnBuf->SbAddData( (u_char *)data,
                                             length,
                                             se->trafficDirection == TRAFFIC_FROM_CLIENT,
                                             tcpHole);
    if (sbAddStatus.tlsError < TTAS_ENUM_COUNT)
        decodeStats.sslErrors[sbAddStatus.tlsError]++;

    if(sbAddStatus.fragBlocks > decodeStats.ssnBufMaxBlocks)
    {
        decodeStats.ssnBufMaxBlocks = sbAddStatus.fragBlocks;
    }
    
    // Debug display of session:packet
    Dprint("- - %u : %u - - (%c, %u, %u) - - %c - - - - - - - - %s "
                     "- - - - - - - - - -\n",
                    (unsigned)pgInfo->sessionIdNum, (unsigned)pgInfo->pktCount,
                    (unsigned)pgInfo->ssnBuf->SbShowMode(),
                    (unsigned)length,
                    (unsigned)pgInfo->ssnBuf->SbAvail(),
                    tcpHole ? 'H' : '-',
                    State2String(se));

    // TLS may eat the entire packet, or it may encounter an error.
    if((sbAddStatus.avail == 0) || (sbAddStatus.tlsError != TTAS_OK))
    {
        if(   pgInfo->ssnIsSecured 
           && pgInfo->handler == &PgDecode::NzProcessHandshake
           && sbAddStatus.tlsError != TTAS_OK)
        {
            // If this session cannot be decrypted, on the first
            // failure we transition to the throwaway SSL state.
            // Note that this state is never invoked, it just marks
            // the transition
            pgInfo->handler = &PgDecode::NzProcessNullSsn;

            ++decodeStats.totSessionsIgnored;
        }

        // Create a filler pgbuf file
        if(dbgDump)  DumpPkt(se, (tz_int8 *)data, 0);

        return status;
    }

    // Dump the packet if enabled.  NULL pointer means "obtain it via 
    // SbRecvBlock()"
    if(dbgDump)  DumpPkt(se, (tz_int8 *)NULL, 0);

    // Special processing if a gap has been encountered
    if(tcpHole) 
    {
        // Bump the stats
        ++decodeStats.tcpHoles;
        ++decodeStats.syncLost;

        // Prepare for gap handling
        pgInfo->evtPrevHnd = IdentifyHandler(se);
        pgInfo->handler    = &PgDecode::NzProcessResync;
    }

    //------------------------------------------------------------------
    // Main decoder loop.  The current handler is called to nibble away
    // at data.  If the decoder underflows it sets isDecoding false and
    // quits to await the next packet which will hopefully provide the
    // remaining data
    //------------------------------------------------------------------
    while( isDecoding )
    {
        // Standard processing - restore the correct handler for this session
        // and execute the current state
        this->handler = pgInfo->handler;
        isDecoding = (this->*handler)(se);
    }

    Dprint("\n%u", (unsigned)pgInfo->ssnBuf->SbAvail());

    // The decoder declares to the sessionBuffer that it is done.  The ssnBuf
    // will preserve remaining data or cease buffering as necessary.
    fragBlocks = pgInfo->ssnBuf->SbEnd(se->trafficDirection == TRAFFIC_FROM_CLIENT);
    if(fragBlocks > decodeStats.ssnBufMaxBlocks)
    {
        decodeStats.ssnBufMaxBlocks = fragBlocks;
    }

    if(dbgLvl1 == false)  Dprint("\n");

  return status;
}

//-----------------------------------------------------------------------
// ProcessSync()
//     Search for a Message Header and synchronize processing to it
//
// return:
//     true  - more processing
//     false - processing completed
//-----------------------------------------------------------------------
bool PgDecode::ProcessSync(SessionEntry *se)
{
    tz_int8   *data, *rtnData;
    tz_uint32  dataIdx;
    tz_uint32  dataLen;
    tz_uint32  dataLenRead;
    bool       isDecoding = true;
    PgInfo    *pgInfo     = (PgInfo *)se->appInfo;

    do
    {
        // Grab the whole segment and start looking
        dataLenRead = pgInfo->ssnBuf->SbRecvBlock(&data);

        // We do not sync on server-side traffic
        if(se->trafficDirection == TRAFFIC_FROM_SERVER)
        {
            // Leave the traffic consumed
            isDecoding = false;
            break;
        }

        // Test for min size (works for Nz and Pg)
        if(dataLenRead < sizeof(NzVersion))
        {
            // If data isn't long enough to be a Version packet then leave
            // the data consumed
            isDecoding = false;
            break;
        }

        // -- Netezza --
        // Check first for the most common case of NZ PG,
        // NzVersion packet, opcode and version where they are aligned
        // at the beginning of the segment.

        // FIX: if something other than CP_VERSION_3 can be expected

        // ? why data in BE format?  Phil said it's LE

        NzVersion *nzMsg = (NzVersion *)data;
        if(   ptohs(nzMsg->opcode) == HSV2_CLIENT_BEGIN
           && VersionIsValid( ptohs(nzMsg->version) )
           && ptohl(nzMsg->length) == sizeof(NzVersion) )
        {
            pgInfo->sd = CreateSessionDetail(se);

            if(pgInfo->sd == NULL) {
                lc_log_basic(LOG_WARNING,"Postgres decoder error: "
                                         "failed sessionDetail create");
            }

            // We leave the data consumed because there is nothing
            // more in this message (i.e., no call to SbReturn())

            // Initialize the SQL buffer mechanism
            pgSqlBufMgrInit(se);

            // Client source port
            Dprint("Handshake version: %d on client port %d\n", 
                         ptohs(nzMsg->version),
                         se->clientIsDst ? ntohs(se->addressTuple.dport)
                                         : ntohs(se->addressTuple.sport) );

            // Advance to processing handshake messages
            pgInfo->handler = &PgDecode::NzProcessHandshake;
            ++decodeStats.sessionsHandshake;
            pgInfo->cpCount = 0;

            // There's nothing else in this packet
            isDecoding = false;
            break;
        }

        // -- Standard Postgres --
        // Check first for the most common standard Postgres case where
        // the StartupMsg is aligned at the beginning of a segment (protVer
        // just after length)
        dataIdx = 4;

        if( ptohl(_U32(&data[dataIdx])) == 0x00030000 )
        {
            // Return the data now that we know where we are!  For
            // standard Postgres this makes sense because there are
            // parameters in the Startup message
            pgInfo->ssnBuf->SbReturn(&data, dataLenRead);

            // Advance to message processing and continue decoding
            pgInfo->handler = &PgDecode::PgProcessStartupMsg;
            break;
        }

        // If we're here then we failed Nz and standard PG checks.
        // Begin searching through the entire segment for Nz version.
        // (If we decide to support standard Postgres, put test here too)
        for( dataIdx = 0; 
             dataIdx < (dataLenRead + 1 - sizeof(NzVersion));
             ++dataIdx )
        {
            NzVersion *nzMsg = (NzVersion *)&data[dataIdx];

            if(   ptohs(nzMsg->opcode) == HSV2_CLIENT_BEGIN
               && VersionIsValid( ptohs(nzMsg->version) )
               && ptohl(nzMsg->length) == sizeof(NzVersion) )
            {
                // Return anything that might be following
                rtnData = &data[dataIdx + sizeof(NzVersion)];
                pgInfo->ssnBuf->SbReturn(
                              &rtnData,
                              dataLenRead - dataIdx - sizeof(NzVersion));

                pgInfo->sd = CreateSessionDetail(se);

                if(pgInfo->sd == NULL) {
                    lc_log_basic(LOG_WARNING,"Postgres decoder error: "
                                             "failed sessionDetail create");
                }

                // Initialize the SQL buffer mechanism
                pgSqlBufMgrInit(se);

                Dprint("version: 3\n");

                // Advance to processing handshake messages
                pgInfo->handler = &PgDecode::NzProcessHandshake;
                ++decodeStats.sessionsHandshake;
                pgInfo->cpCount = 0;

                isDecoding = false;
                break;  // for loop
            }
        }

        // If the search was futile then return the few remaining bytes
        // so the search can continue later when this session receives the 
        // next packet on it
        if( dataIdx == (dataLenRead + 1 - sizeof(NzVersion)) )
        {
            rtnData = &data[dataIdx];
            pgInfo->ssnBuf->SbReturn( &rtnData,
                                      sizeof(NzVersion) - 1);
            isDecoding = false;
        }

    } while (0);

    return isDecoding;
}

//-----------------------------------------------------------------------
// NzProcessResync()
//     This session may or may not have been authenticated when it
//     encountered a TCP gap.  We need to get decoding back on track
//     by looking for the next query and we expect the command number
//     to be higher than what we've already processed
//
//
//-----------------------------------------------------------------------
bool PgDecode::NzProcessResync(SessionEntry *se)
{
    tz_int8   *data;
    tz_uint32  dataLenRead;
    bool       isDecoding = true;
    PgInfo    *pgInfo     = (PgInfo *)se->appInfo;
    DimValListEntry *thisDvle = NULL;
    DimValListEntry *nextDvle = NULL;

    switch(pgInfo->evtPrevHnd)
    {
    case HndProcessSync:
        // We were already searching for sync so turn control over
        // to Sync and continue looking
        pgInfo->handler = &PgDecode::ProcessSync;
        break;


    case HndNzProcessAuth:

        // There is nothing essential in Auth that the decoder needs.
        // We will just toss this data and try to resync

        // Discard any leftover data so that the decoder is working
        // with data from the start of the current TCP segment
        pgInfo->ssnBuf->SbReset();

        // Go into Resync Continuation until a 'P' or 'Q' req
        pgInfo->handler = &PgDecode::NzProcessResyncCont;
        break;

    case HndNzProcessHandshake:

        // Discard current segment data
        dataLenRead = pgInfo->ssnBuf->SbRecvBlock(&data);

        // Discard leftover data
        pgInfo->ssnBuf->SbReset();

        // Return control to ProcessHandshake
        pgInfo->handler = &PgDecode::NzProcessHandshake;

        // We're done processing the current segment
        isDecoding = false;
        break;

    case HndNzProcessNullSsn:
      // Return control to ProcessSsl
        pgInfo->handler = &PgDecode::NzProcessNullSsn;
        break;

    case HndNzProcessLoadUnload:
      // Return control to ProcessSsl
        pgInfo->handler = &PgDecode::NzProcessLoadUnload;
        break;

    // Query request or response in progress.  Issue a partial event
    // with req and rsp data received up to when the hole was encountered.
    // (Throw away the current segment, there's data missing between the
    // most recently received segment and it).  Next, go into resync mode.
    case HndNzProcessQuery:
    case HndNzProcessQueryCont:
    case HndNzProcessStreamMode:

        // Issue an event
        Dprint("Partial EVT");
        Dprint1("\n");

        pgInfo->evtStatus.evtRespStatus = FAILED_OPERATION;
        pgInfo->evtStatus.evtIsComplete = false;
        PrepareEvent(se);

        // Discard any leftover data so that the decoder is working
        // with data from the start of the current TCP segment
        pgInfo->ssnBuf->SbReset();

        // Stay in Resync Continuation
        pgInfo->handler = &PgDecode::NzProcessResyncCont;

        isDecoding = false;
        break;

    case HndNzProcessResyncCont:

        // Return control to ProcessResyncCont
        pgInfo->handler = &PgDecode::NzProcessResyncCont;
        break;


    case HndNzProcessResync:
    case HndOther:
        break;
    }

    return isDecoding;
}

//-----------------------------------------------------------------------
// NzProcessResyncCont()
//     Resync Continuation State.  Stay here until we find the beginning
//     of a new request then allow it to resume decoder operation
//-----------------------------------------------------------------------
bool PgDecode::NzProcessResyncCont(SessionEntry *se)
{
    tz_int8   *data;
    tz_uint32  dataLen;
    tz_uint32  dataLenRead;
    bool       isDecoding = true;
    PgInfo    *pgInfo     = (PgInfo *)se->appInfo;


    do
    {
        // We are looking specifically at client side traffic
        if(se->trafficDirection != TRAFFIC_FROM_CLIENT)
        {
            // Consume the server-side packet and end decoding of it
            dataLenRead = pgInfo->ssnBuf->SbRecvBlock(&data);
            isDecoding = false;
            break;
        }

        // We assume that SbReset() has been called so that the start
        // of data is the beginning of a TCP segment.  We assume that
        // the request will be located at the beginning of that segment

        dataLenRead = pgInfo->ssnBuf->SbRecv(&data, 1);
        //TZ_ASSERT(dataLenRead == 1,"NZProcessResyncCont opcode\n");
        if(dataLenRead != 1) {
            lc_log_basic(LOG_NOTICE,"NzProcessResyncCont opcode underflow");
            isDecoding = false;
            break;
        }

        tz_uint8 opcode = data[0];
        pgInfo->ssnBuf->SbReturn(&data, dataLenRead);

        if( opcode == 'P' || opcode == 'Q' )
        {
            // M1, M2 'Q' or M3, M4 'P'
            dataLen = sizeof(NzQuery);
            dataLenRead = pgInfo->ssnBuf->SbRecv(&data, dataLen);
            if(dataLenRead < dataLen)
            {
                pgInfo->ssnBuf->SbReturn(&data, dataLenRead);
                isDecoding = false;
                break;
            }
            else
            {
                NzQuery *msg = (NzQuery *)data;

                // If cmdNum is within a reasonable range, declare resync.
                // Note that we can't count on it linearly increasing.
                // Some client codepaths leave it fixed at 1 for successive
                // requests.  That's why it's greater than or equal to.
                if(   ptohl(msg->cmdNum) >= pgInfo->evtCmdNum
                   && ptohl(msg->cmdNum) <  pgInfo->evtCmdNum + 10)
                {
                    ++decodeStats.syncResyncSuccess;
                    Dprint("%c> resync\n", msg->opcode);

                    // Return the data
                    pgInfo->ssnBuf->SbReturn(&data, dataLenRead);

                    // Turn decoding over to Query processing
                    pgInfo->handler = &PgDecode::NzProcessQuery;
                }
                else
                {
                    // Consume what might be left of the client packet since
                    // we don't recognize it.  We end decoding for now and
                    // remain in NzProcessResyncCont
                    Dprint("resync miss\n");
                    dataLenRead = pgInfo->ssnBuf->SbRecvBlock(&data);
                    isDecoding = false;
                    break;
                }
            }
        }
        else if( opcode == 'X' )
        {
            // Client terminate request
            ++decodeStats.syncResyncSuccess;
            Dprint("resync\n");

            // Turn decoding over to Query processing
            pgInfo->handler = &PgDecode::NzProcessQuery;
        }
        else
        {
            // Consume the client packet since we don't recognize it.
            // We end decoding for now and remain in NzProcessResyncCont
            dataLenRead = pgInfo->ssnBuf->SbRecvBlock(&data);
            isDecoding = false;
            break;
        }

    } while (0);

    return isDecoding;
}

//-----------------------------------------------------------------------
// NzProcessStreamMode()
//     Process a TCP segment buffer received in while in streaming mode.
//     This will typically arise when data from a very large row is
//     returned for arow descriptor of type 'D', 'B', 'X', or 'Y'.
//
// return:
//     true  - more processing
//     false - processing completed
//-----------------------------------------------------------------------
bool PgDecode::NzProcessStreamMode(SessionEntry *se)
{
    tz_int8   *data;
    tz_uint32  dataLen;
    tz_uint32  dataLenRead;
    bool       isDecoding = true;
    PgInfo    *pgInfo     = (PgInfo *)se->appInfo;


    do
    {
        Dprint("stream: %lu/%lu ", pgInfo->ssnBuf->SbAvail(),
                                   pgInfo->streamModeTotRemaining);

        if(pgInfo->streamModeTotRemaining > pgInfo->ssnBuf->SbAvail())
        {
            // Grab the entire block
            dataLenRead = pgInfo->ssnBuf->SbRecvBlock(&data);
        }
        else
        {
            // Grab the remaining balance
            dataLen = pgInfo->streamModeTotRemaining;
            dataLenRead = pgInfo->ssnBuf->SbRecv(&data, dataLen);
        }

        if( pgInfo->streamModeTotRemaining > dataLenRead ) {
            pgInfo->streamModeTotRemaining -= dataLenRead;
        } else {

            if(pgInfo->streamModeTotRemaining != dataLenRead)
            lc_log_basic(LOG_NOTICE,"Postgres decoder error: NzProcessStreamMode"
                         "%lu mismatch %lu", pgInfo->streamModeTotRemaining,
                                             dataLenRead );

            // End of StreamMode
            pgInfo->streamModeTotExpected = pgInfo->streamModeTotRemaining = 0;
            pgInfo->streamModeCodepoint = 0;

            pgInfo->handler = &PgDecode::NzProcessQuery;
        }

        // Note: stream mode handles data for a very long row.  We already
        // counted the row when we entered stream mode.  So, don't count
        // it here

        pgInfo->evtRespBytes += dataLenRead;

        // Perform Content Scanning
        if( rspDataPatMgr->CSEnabled() == true )
        {
            // FIX - where necessary, convert data to ASCII 
            //       prior to scan

            pgInfo->serverCs->ScanData( 
                                  (const tz_uint8 *)&data[0],
                                   dataLenRead,
                                   se->workerIdx );
        }

        // If no more data, finish processing
        if( pgInfo->ssnBuf->SbAvail() == 0 )
        {
            isDecoding = false;
        }

    } while (0);

    return isDecoding;
}

//-----------------------------------------------------------------------
// NzProcessHandshake()
//     Process handshake messages
//
// return:
//     true  - more processing
//     false - processing completed
//-----------------------------------------------------------------------
bool PgDecode::NzProcessHandshake(SessionEntry *se)
{
    tz_int8   *data;
    tz_uint32  dataLen;
    tz_uint32  dataLenRead;
    tz_uint32  safeLen;
    bool       isDecoding = true;
    PgInfo    *pgInfo     = (PgInfo *)se->appInfo;

    do
    {

        // Formerly #ifdef NTZ_RUNTIME_TEST
        if(pgInfo->cpCount > 24 )
        {
            //TZ_ASSERT(false, "NzProcessHandshake state");

            // This session was not able to get off the ground
//          --decodeStats.sessionsSsl;
            ++decodeStats.totSessionsNull;
            pgInfo->handler = &PgDecode::NzProcessNullSsn;
            break;
        }

        // Check for single byte 'N', 'E', 'M' response to Handshake
        if( pgInfo->ssnBuf->SbAvail() == 1 )
        {
            dataLenRead = pgInfo->ssnBuf->SbRecv(&data, 1);
            ++pgInfo->cpCount;

            switch( data[0] )
            {
            // Notice
            case 'N':
                // Notice, successful ack of handshake message
                // or unsecured connection
                Dprint("Notice\n");
                break;
            case 'S':
                // Secured connection successful (from level 2 or 3)
                Dprint("Secured\n");
                break;
            case 'E':
                // Error on backend
                Dprint("Error\n");
                break;
            case 'M':
                // Mismatch
                Dprint("Mismatch\n");
                break;
            }

            // We're done processing here
            isDecoding = false;
            break;
        }

        // Redundancy to deal with gaps.  If HSV2_CLIENT_DONE is lost to
        // a gap then the following Auth codepoints will cause a proper
        // transition to the Auth state.  We start by obtaining the
        // first byte which is an opcode if this is an Auth codepoint.
        // If it's a Handshake codepoint the first byte is the MSB of
        // a length field and is unlikely to be such a large value
        dataLenRead = pgInfo->ssnBuf->SbRecv(&data, 1);
        tz_uint8 opcode = data[0];
        pgInfo->ssnBuf->SbReturn(&data, dataLenRead);

        if(opcode == 'R' || opcode == 'K' || opcode == 'Z' || opcode == 'E')
        {
            Dprint("Handshake -> Auth via codepoint\n");

            // Advance to auth processing
            pgInfo->handler = &PgDecode::NzProcessAuth;
            --decodeStats.sessionsHandshake;
            ++decodeStats.sessionsAuth;
            //printf("Handshake -> Auth cpCount %lu\n", pgInfo->cpCount);
            //fflush(stdout);
            pgInfo->cpCount = 0;

            // leave isDecoding true to continue processing
            break;
        }

        // Okay, we're back to processing Handshake codepoints


        // Read in an entire NzHsMsg
        tz_uint32 msgSize;
        dataLen = sizeof(NzHsMsg);
        dataLenRead = pgInfo->ssnBuf->SbRecv(&data, dataLen);

        if(dataLenRead < dataLen)
        {
            // Insufficient data to process, Return it
            pgInfo->ssnBuf->SbReturn(&data, dataLenRead);
            isDecoding = false;
            break;
        }
        else
        {
            msgSize = dataLenRead;
        }

        // Oh goody, we've got one.  Or what we think is one.  Data at
        // this point could be (a) a valid handshake message or (b)
        // query req or rsp data because gaps have obliterated enough
        // codepoints that this session never transitioned to Auth
        // and Query.
        NzHsMsg *msg = (NzHsMsg *)data;

        // Read the data portion of the message.  Or what we think is.
        dataLen = ptohl(msg->length);
        dataLen -= sizeof(NzHsMsg);
        dataLenRead = pgInfo->ssnBuf->SbRecv(&data, dataLen);

        if(dataLenRead < dataLen)
        {
            // This could be an underflow due to segmentation (less
            // likely) or a bad dataLen which was read from qurey req
            // or rsp data (more likely).  If the former then just
            // return the partial data.  If the latter then bump codepoint
            // count and wait for its overflow to drive the session into
            // NullSsn mode
            pgInfo->ssnBuf->SbReturn(&data, dataLenRead);

            // Return the message header
            pgInfo->ssnBuf->SbReturn((tz_int8 **)&msg, sizeof(NzHsMsg));

            ++pgInfo->cpCount;
            isDecoding = false;
            break;
        }
        else
        {
            msgSize += dataLenRead;
            ++pgInfo->cpCount;
        }

        switch(ptohs(msg->opcode))
        {
        case HSV2_CLIENT_BEGIN:
            Dprint("ClientBegin\n");
            break;

        case HSV2_DB:
            // DbName - "server.info"
            safeLen = MIN(TZX_512_STRING - 1,
                (ptohl(msg->length) - sizeof(msg->length) - sizeof(msg->opcode)));
            memcpy(pgInfo->sd->serverInfo,
                   msg->data,
                   safeLen );
            pgInfo->sd->serverInfo[safeLen] = '\0';

            NormalizeString(pgInfo->sd->serverInfo);
            pgInfo->sd->serverInfoLength = strlen(pgInfo->sd->serverInfo);
            Dprint("serverInfo: %s\n", pgInfo->sd->serverInfo);
            break;

        case HSV2_USER:
            // UserName - "user.serveruser"
            safeLen = MIN(TZX_512_STRING - 1,
                (ptohl(msg->length) - sizeof(msg->length) - sizeof(msg->opcode)));
            memcpy(pgInfo->sd->serverUser,
                   msg->data,
                   safeLen );
            pgInfo->sd->serverUser[safeLen] = '\0';

            NormalizeString(pgInfo->sd->serverUser);
            pgInfo->sd->serverUserLength = strlen(pgInfo->sd->serverUser);
            Dprint("serverUser: %s\n", pgInfo->sd->serverUser);

            NzSqlConnInit(&pgInfo->connState);
            break;

        case HSV2_OPTIONS:
            Dprint("Options\n");
            break;

        case HSV2_TTY:
            Dprint("Tty\n");
            break;

        case HSV2_REMOTE_PID:
            // RemotePid - "session.clientpid"
            // We have all the data already so just read it
            pgInfo->sd->clientPID = ptohl(_U32(&msg->data[0]));
            Dprint("RemotePid %lu\n", pgInfo->sd->clientPID);
            break;

        case HSV2_PRIOR_PID:
            // a 32-bit PID used by the backend/frontend to identify
            // active sessions (part of cleanup in the event of a DROP USER)
            Dprint("PriorPid\n");
            break;

        case HSV2_CLIENT_TYPE:
            pgInfo->nzClientType = ptohs(_U16(&msg->data[0]));
            strcpy(pgInfo->sd->hostUser, ClientType2String(pgInfo->nzClientType));
            pgInfo->sd->hostUserLength = strlen(pgInfo->sd->hostUser);
            Dprint("ClientType %s\n", pgInfo->sd->hostUser);
            break;

        case HSV2_PROTOCOL:
            // NzAccess protocol version "server.version"
            sprintf(pgInfo->sd->serverVersion,"%u.%u",
                   ptohs(_U16(&msg->data[0])), ptohs(_U16(&msg->data[2])));
            pgInfo->sd->serverVersionLength = strlen(pgInfo->sd->serverVersion);
            Dprint("serverVersion: %s\n", pgInfo->sd->serverVersion);
            break;

        case HSV2_HOSTCASE:
            Dprint("HostCase\n");
            break;

        case HSV2_SSL_NEGOTIATE:
            // Security Level
            Dprint("SslNegotiate\n");
            break;

        case HSV2_SSL_CONNECT:
            Dprint("SslConnect\n");
            pgInfo->ssnBuf->SbSslInit (se);

            // Formerly we went into a "Throwaway state"
            // pgInfo->handler = &PgDecode::NzProcessNullSsn;

            // Consider ourselves having transitioned from Handshake to SSL
            ++decodeStats.sessionsSsl;
            pgInfo->ssnIsSecured = true;
            break;

        case HSV2_CLIENT_DONE:
            // ClientDone - the client is done sending messages to 
            // the backend
            Dprint("ClientDone\n");

            // Advance to auth processing
            pgInfo->handler = &PgDecode::NzProcessAuth;
            --decodeStats.sessionsHandshake;
            ++decodeStats.sessionsAuth;
            //printf("Handshake -> Auth cpCount %lu\n", pgInfo->cpCount);
            //fflush(stdout);
            pgInfo->cpCount = 0;
            break;

        case HSV2_SERVER_BEGIN:
            Dprint("ServerBegin\n");
            break;

        case HSV2_PWD:
            Dprint("Pwd\n");
            break;

        case HSV2_SERVER_DONE:
            Dprint("ServerDone\n");
            break;

        case HSV2_INVALID_OPCODE:
        default:
            if( ptohl(msg->length) == msgSize )
            {
                // Assume it's an Auth request response and just ignore it.
                // I don't know why the're being sent so early.  There's no
                // way to definitively identify it since it's just length
                // followed by data.

                // The else case below may be dead code.  We need a way
                // to distinguish "opcode not present" from "opcode is
                // there but it's new and different."
            }
            else
            {
                // Assume it's a new Handshake Opcode we've never seen
                Dprint("InvalidOpcode\n");
                ++decodeStats.unknownCodepoints;
                TrapUnknown(ptohs(msg->opcode));
                lc_log_basic(LOG_NOTICE,"NzProcessHandshake Invalid Opcode %d",
                                                              msg->opcode);
#ifdef NTZ_RUNTIME_TEST
                TZ_ASSERT(false, "NzProcessHandshake invalid_op");
#endif
            }
            break;
        }

        // If no more data, finish processing
        if( pgInfo->ssnBuf->SbAvail() == 0 )
        {
            isDecoding = false;
        }

    } while (0);

    return isDecoding;
}

//-----------------------------------------------------------------------
// NzProcessAuth()
//     Process authentication messages
//
// return:
//     true  - more processing
//     false - processing completed
//-----------------------------------------------------------------------
bool PgDecode::NzProcessAuth(SessionEntry *se)
{
  tz_int8   *data, *rtnData;
    tz_uint32  dataLen;
    tz_uint32  dataLenRead;
    bool       isDecoding = true;
    PgInfo    *pgInfo     = (PgInfo *)se->appInfo;

    do
    {

#ifdef NTZ_RUNTIME_TEST
        if(pgInfo->cpCount > 10 )
        {
            TZ_ASSERT(false, "NzProcessAuth state");
        }
#endif

        // Accept 'R', 'K' from server
        if( se->trafficDirection == TRAFFIC_FROM_SERVER )
        {
            dataLenRead = pgInfo->ssnBuf->SbRecv(&data, 1);
            tz_uint8 opcode = data[0];
            pgInfo->ssnBuf->SbReturn(&data, dataLenRead);
            ++pgInfo->cpCount;

            switch( opcode )
            {
            // AuthenticationOk
            case 'R':
                dataLen = sizeof(NzAuth);
                dataLenRead = pgInfo->ssnBuf->SbRecv(&data, dataLen);
                if(dataLenRead < dataLen)
                {
                    // Insufficient data to process, Return it
                    pgInfo->ssnBuf->SbReturn(&data, dataLenRead);
                    isDecoding = false;
                }
                else
                {
                    // AUTH_REQ_XXX is now available
                    NzAuth *msg = (NzAuth *)data;

                    Dprint("AuthReq %s ", Auth2String(ptohl(msg->type)));

                    // There is no length in this message so just consume
                    // whatever is left (e.g., salt value) to prevent the
                    // statemachine from stalling
                    dataLen = pgInfo->ssnBuf->SbAvail();
                    dataLenRead = pgInfo->ssnBuf->SbRecv(&data, dataLen);

                }
                break;

             // BackendKeyData
            case 'K':
                Dprint("BackendKeyData\n");
                dataLen = sizeof(NzBackendKeyData);
                dataLenRead = pgInfo->ssnBuf->SbRecv(&data, dataLen);
                if(dataLenRead < dataLen)
                {
                    // Insufficient data to process, Return it
                    pgInfo->ssnBuf->SbReturn(&data, dataLenRead);
                    isDecoding = false;
                }
                else
                {
                    // Process this field, whatever it is...
                    Dprint("K< ");
                }
                break;

            // Error
            case 'E':
                dataLen = sizeof(NzError);
                dataLenRead = pgInfo->ssnBuf->SbRecv(&data, dataLen);
                if(dataLenRead < dataLen)
                {
                    // Insufficient data to process, Return it
                    pgInfo->ssnBuf->SbReturn(&data, dataLenRead);
                    isDecoding = false;
                }
                else
                {
                    NzError *msg = (NzError *)data;

                    // Process the Error message as a failed login
                    InjectEvent(se,
                                NULL,      // contentListEntry,
                                NULL,      // operationListEntry,
                                NULL,      // commandDataListEntry,
                                NULL,      // responseDataListEntry,
                                NULL,      // responseEntry,
                                NULL,      // sizeEntry,
                                msg->data, // commandStg,
                                true,      // isCompleteEvt,
                                false      // loginIsSuccess
                                );

                    // Return to search for a new session
                    pgInfo->handler = &PgDecode::ProcessSync;
                    --decodeStats.sessionsAuth;
                    //printf("Auth -> Sync cpCount      %lu\n", pgInfo->cpCount);
                    //fflush(stdout);
                    pgInfo->cpCount = 0;

                    // We leave decoding on here and we have Sync just
                    // look through bytes until it finds the header or
                    // depletes them.
                }
                break;

            // ReadyForQuery
            case 'Z':
                Dprint("ReadyForQuery\n");
                dataLen = sizeof(NzRdyQuery);

                Dprint1("Z< %u ", (unsigned)dataLen);
                dataLenRead = pgInfo->ssnBuf->SbRecv(&data, dataLen);
                if(dataLenRead < dataLen)
                {
                    // Insufficient data to process, Return it
                    Dprint1("U\n");
                    pgInfo->ssnBuf->SbReturn(&data, dataLenRead);
                    isDecoding = false;
                }
                else
                {
                    NzRdyQuery *msg = (NzRdyQuery *)data;
                    dataLen = ptohl(msg->length);
                    Dprint1("%u ", (unsigned)dataLen);

                    dataLenRead = pgInfo->ssnBuf->SbRecv(&data, dataLen);
                    if(dataLenRead < dataLen)
                    {
                        Dprint1("U\n");

                        // Insufficient data to process, Return it
                        pgInfo->ssnBuf->SbReturn(&data, dataLenRead);

                        // Return the message header
                        pgInfo->ssnBuf->SbReturn((tz_int8 **)&msg, sizeof(NzRdyQuery));

                        TrapUnderflow();
                        isDecoding = false;
                    }
                    else
                    {
                        // Final transition to Query execution (SSL or not)
                        pgInfo->handler = &PgDecode::NzProcessQuery;
                        --decodeStats.sessionsAuth;
                        pgInfo->ssnIsSecured 
                                        ? ++decodeStats.totSessionsSecured
                                        : ++decodeStats.totSessionsUnsecured;
                        //printf("Auth -> Query cpCount     %lu\n", pgInfo->cpCount);
                        //fflush(stdout);
                        pgInfo->cpCount = 0;
                    }
                }
                break;

            case 'N':
                if(pgInfo->ssnBuf->SbAvail() == 1)
                {
                    // Notice (1 byte) from server
                    Dprint("N< ");

                    // We know there's 1 byte so don't check underflow
                    dataLenRead = pgInfo->ssnBuf->SbRecv(&data, 1);

                }
                break;

            // We need to prove this is necessary
#if 0
            // Path for ClientDone, Auth request response then a server
            // response without the 'K', 'Z' sequence.  We therefore transition.
            case 'C':
                // Read in what is potentially a ('C' + cmdNum)
                dataLen = sizeof(tz_uint8) + sizeof(tz_uint32);
                dataLenRead = pgInfo->ssnBuf->SbRecv(&data, dataLen);

                if(dataLenRead < dataLen)
                {
                    // Insufficient data to process, Return it
                    pgInfo->ssnBuf->SbReturn(&data, dataLenRead);
                    isDecoding = false;
                    break;
                }
                else
                {
                    NzMsg *msg = (NzMsg *)data;

                    if( ptohl(msg->cmdNum) == 1 )
                    {
                        // The first query from the client
                        Dprint("/C\n");

                        // Return the block so that NzProces Query can pick it apart
                        pgInfo->ssnBuf->SbReturn(&data, dataLenRead);

                        // Go to the regular Query state
                        pgInfo->handler = &PgDecode::NzProcessQuery;
                        --decodeStats.sessionsAuth;
                        pgInfo->ssnIsSecured 
                                        ? ++decodeStats.totSessionsSecured
                                        : ++decodeStats.totSessionsUnsecured;
                        //printf("Auth -> Query cpCount     %lu\n", pgInfo->cpCount);
                        //fflush(stdout);
                        pgInfo->cpCount = 0;
                    }
                    else
                    {
                        //TZ_ASSERT(false,"NZProcessAuth 0\n");
                        lc_log_basic(LOG_NOTICE,"NzProcessAuth 0");
                    }
                }
                break;
#endif

            default:

                // Unimplemented opcode.  Make note of it and flush it to keep
                // the decoder from stalling
                lc_log_basic(LOG_NOTICE,"Postgres decoder error: NzProcessAuth "
                                               "Unknown opcode \'%c\'", opcode);
                ++decodeStats.unknownCodepoints;
                TrapUnknown(opcode);

#ifdef NTZ_RUNTIME_TEST
                TZ_ASSERT(false, "NzProcessAuth invalid_op");
#endif

                dataLen = sizeof(NzMsg);
                dataLenRead = pgInfo->ssnBuf->SbRecv(&data, dataLen);
                if(dataLenRead < dataLen)
                {
                    // Insufficient data to process, Return it
                    pgInfo->ssnBuf->SbReturn(&data, dataLenRead);
                    isDecoding = false;
                }
                else
                {
                    NzMsg *msg = (NzMsg *)data;
                    dataLen = ptohl(msg->length);
                    dataLenRead = pgInfo->ssnBuf->SbRecv(&data, dataLen);
                    if(dataLenRead < dataLen)
                    {
                        // Return the partial data
                        pgInfo->ssnBuf->SbReturn(&data, dataLenRead);

                        // Return the message header
                        pgInfo->ssnBuf->SbReturn((tz_int8 **)&msg, sizeof(NzMsg));

                        TrapUnderflow();
                        isDecoding = false;
                    }
                }
                break;
            }
        }

        // Accept traffic from client
        // * Auth request response (length, data)
        // * 'P' request due to absence of 'K', 'Z' sequence.
        if( se->trafficDirection == TRAFFIC_FROM_CLIENT )
        {
            // Read in what is potentially either a ('P' + cmdNum)
            // ('Q' + cmdNum) or a length for the Auth request response
            dataLen = sizeof(tz_uint8) + sizeof(tz_uint32);
            dataLenRead = pgInfo->ssnBuf->SbRecv(&data, dataLen);

            if(dataLenRead < dataLen)
            {
                // Insufficient data to process, Return it
                pgInfo->ssnBuf->SbReturn(&data, dataLenRead);
                isDecoding = false;
                break;
            }

            NzPortal *msg = (NzPortal *)data;
            ++pgInfo->cpCount;

            // Look for specific codepoints.  Why the heuristic tests?  To
            // lessen the chance we'll misinterpret an Auth Request Response
            // as one of these codepoints.  You'd expect cmdNum to be 1
            // since it's the first client request.  It may not be, though,
            // if gaps cause packet losses
            if(    msg->opcode == 'P'
                && ptohl(msg->cmdNum) < 255 )
            {
                // The first query from the client and cmdNum is small
                Dprint("/P\n");

                // Return the block so that NzProces Query can pick it apart
                pgInfo->ssnBuf->SbReturn(&data, dataLenRead);

                // Go to the regular Query state
                pgInfo->handler = &PgDecode::NzProcessQuery;
                --decodeStats.sessionsAuth;
                pgInfo->ssnIsSecured ? ++decodeStats.totSessionsSecured
                                     : ++decodeStats.totSessionsUnsecured;
                //printf("Auth -> Query cpCount     %lu\n", pgInfo->cpCount);
                //fflush(stdout);
                pgInfo->cpCount = 0;
            }
            else if(    msg->opcode == 'Q'
                     && ptohl(msg->cmdNum) < 255 )
            {
                // The first query from the client and cmdNum is small
                Dprint("/Q\n");

                // Return the block so that NzProces Query can pick it apart
                pgInfo->ssnBuf->SbReturn(&data, dataLenRead);

                // Go to the regular Query state
                pgInfo->handler = &PgDecode::NzProcessQuery;
                --decodeStats.sessionsAuth;
                pgInfo->ssnIsSecured ? ++decodeStats.totSessionsSecured
                                     : ++decodeStats.totSessionsUnsecured;
                //printf("Auth -> Query cpCount     %lu\n", pgInfo->cpCount);
                //fflush(stdout);
                pgInfo->cpCount = 0;
            }
            else if(    msg->opcode == 'N'
                     && ptohl(msg->cmdNum) < 65536 )
            {
                // Notice message with small length.  It has the format
                // {'N', length (inclusive), data} and we have the first two.
                // Note that it is not an NzPortal message but we pretend.

                // This field is not really cmdNum, it's length
                dataLen = ptohl(msg->cmdNum);
                dataLen - sizeof(tz_uint32);
                dataLenRead = pgInfo->ssnBuf->SbRecv(&data, dataLen);

                if(dataLenRead < dataLen)
                {
                    // Insufficient data to process, return 'N' data payload
                    pgInfo->ssnBuf->SbReturn(&data, dataLenRead);

                    // Now return "NzPortal"
                    pgInfo->ssnBuf->SbReturn((tz_int8 **)&msg, 
                                      sizeof(tz_uint8) + sizeof(tz_uint32));
                    isDecoding = false;
                    break;
                }
                else
                {
                    Dprint(">N %s\n", data);
                }

            }
            else
            {
                // Auth request response
                // We're now holding the 4-byte length plus the first byte
                // of the data payload.  Push that first byte back to make
                // the accounting easier
                rtnData = &data[4];
                pgInfo->ssnBuf->SbReturn(&rtnData, 1);

                // Capture the message length
                dataLen = ptohl(_U32(data));

                // remove the size of the length bytes themselves
                dataLen -= sizeof(tz_uint32);

                // Attempt to read in the payload data.  If we succeed, just
                // leave it digested and move on
                dataLenRead = pgInfo->ssnBuf->SbRecv(&data, dataLen);

                if(dataLenRead < dataLen)
                {
                    // Insufficient data to process, Return the data
                    // and the preceding length
                    pgInfo->ssnBuf->SbReturn(&data, dataLenRead 
                                                  + sizeof(tz_uint32));
                    isDecoding = false;
                    break;
                }
                else
                {
                    Dprint("client response: %lu bytes\n", dataLen);
                }
            }
        }

        // If no more data, finish processing
        if( pgInfo->ssnBuf->SbAvail() == 0 )
        {
            isDecoding = false;
        }

    } while (0);

    return isDecoding;
}

//-----------------------------------------------------------------------
// NzProcessNullSsn()
//     Process Null Session data.  This session was not able to
//     transition into normal operational mode (Query state).  Perhaps
//     it is an encrypted session and we don't have the cert.  Perhaps
//     there were so many gaps that the necessary codepoints to cause
//     Handshake to Auth to Query just never appeared.  What we do is
//     just toss the data until the session ends.  Sorry.  Clean up
//     your network traffic.
//
// return:
//     true  - more processing
//     false - processing completed
//-----------------------------------------------------------------------
bool PgDecode::NzProcessNullSsn(SessionEntry *se)
{
    tz_int8   *data;
    tz_uint32  dataLen;
    tz_uint32  dataLenRead;
    bool       isDecoding = false;
    PgInfo    *pgInfo     = (PgInfo *)se->appInfo;

    // We're not processing this session right now so just toss the data
    dataLenRead = pgInfo->ssnBuf->SbRecvBlock(&data);
    return isDecoding;
}

//-----------------------------------------------------------------------
// NzProcessLoadUnload()
//     Process Load/Unload sequence
//
// return:
//     true  - more processing
//     false - processing completed
//-----------------------------------------------------------------------
bool PgDecode::NzProcessLoadUnload(SessionEntry *se)
{
    tz_int8   *data, *rtnData;
    tz_uint32  dataLen;
    tz_uint32  dataLenRead;
    tz_uint32  dataBytes = 0;
    bool       isDecoding;
    PgInfo    *pgInfo     = (PgInfo *)se->appInfo;

    do
    {
        dataLenRead = pgInfo->ssnBuf->SbRecvBlock(&data);
        // Assume we're going to discard it
        isDecoding = false;

        // We look for "C INSERT 0 <num> Z" as the Load/Unload terminator
        NzClose *msgC = (NzClose *)data;

        if( msgC->opcode != 'C' )  break;  // It's not

        // If command number does not match (e.g. in binary data which has
        // matched so far) then quit
        if( pgInfo->evtCmdNum != ptohl(msgC->cmdNum) )  break;

        // Last check, look for an unreasonable dataLen value
        dataLen = ptohl(msgC->length);
        if( dataLen > 1460 )   break;

        // We've tried to improve the odds that we're fishing out a legitimate
        // "C INSERT 0 <num> Z" sequence which, hopefully, we have found here

        dataBytes = sizeof(NzClose) + dataLen;
        NzRdyQuery *msgZ = (NzRdyQuery *)(&msgC->data[0] + dataLen);

        if( msgZ->opcode != 'Z' )  break;  // It's not

        dataBytes += sizeof(NzRdyQuery);

        if( dataBytes == dataLenRead )
        {
            Dprint("C< (%lu) Z ", pgInfo->evtCmdNum);

            // We've digested the whole packet, issue an event
            Dprint("EVT");
            Dprint1("\n");

            // FIX: is it possible to read the actal status?

            // Record response.status
            pgInfo->evtStatus.evtRespStatus = SUCCESSFUL_OPERATION;
            pgInfo->evtStatus.evtIsComplete = true;
            pgInfo->evtStatus.evtIsIssued   = false;
            PrepareEvent(se);

            pgInfo->handler = &PgDecode::NzProcessQuery;
        }
        else if(dataLenRead > dataBytes)
        {
            Dprint("C< (%lu) Z ", pgInfo->evtCmdNum);

            // Return any remainder
            rtnData = &data[dataBytes];
            pgInfo->ssnBuf->SbReturn( &rtnData,
                                      dataLenRead - dataBytes);

            // Issue an event
            Dprint("EVT");
            Dprint1("\n");

            // FIX: is it possible to read the actal status?

            // Record response.status
            pgInfo->evtStatus.evtRespStatus = SUCCESSFUL_OPERATION;
            pgInfo->evtStatus.evtIsComplete = true;
            pgInfo->evtStatus.evtIsIssued   = false;
            PrepareEvent(se);

            pgInfo->handler = &PgDecode::NzProcessQuery;
            isDecoding = true;

        }
        else
        {
            //TZ_ASSERT(false,"NZProcessLoadUnload 0\n");
            lc_log_basic(LOG_NOTICE,"NzProcessLoadUnload error 0");
        }

    } while (0);

    return isDecoding;
}

//-----------------------------------------------------------------------
// NzProcessQuery()
//     Process query messages
//
// return:
//     true  - more processing
//     false - processing completed
//-----------------------------------------------------------------------
bool PgDecode::NzProcessQuery(SessionEntry *se)
{
    tz_int8   *data;
    tz_uint32  dataLen;
    tz_uint32  dataLenRead;
    bool       isDecoding = true;
    PgInfo    *pgInfo     = (PgInfo *)se->appInfo;

    do
    {
        // 'Z', 'C', 'Q', 'P'

        dataLenRead = pgInfo->ssnBuf->SbRecv(&data, 1);
        //TZ_ASSERT(dataLenRead == 1,"NZProcessQuery opcode\n");
        if(dataLenRead != 1) {
            lc_log_basic(LOG_NOTICE,"NzProcessQuery opcode underflow");
            isDecoding = false;
            break;
        }

        tz_uint8 opcode = data[0];
        pgInfo->ssnBuf->SbReturn(&data, dataLenRead);

        switch( opcode )
        {
        case 'Q':
            // Query (client request)
            // M1, M2 client side
            Dprint("Q ");

            dataLen = sizeof(NzQuery);
            Dprint1("%u ", (unsigned)dataLen);
            dataLenRead = pgInfo->ssnBuf->SbRecv(&data, dataLen);
            if(dataLenRead < dataLen)
            {
                // Insufficient data to process, Return it
                Dprint1("U1\n");
                pgInfo->ssnBuf->SbReturn(&data, dataLenRead);
                isDecoding = false;
            }
            else
            {
                // AUTH_REQ_XXX is now available
                NzQuery *msg = (NzQuery *)data;

                // Save the command number
                pgInfo->evtCmdNum = ptohl(msg->cmdNum);
                Dprint("(%lu) ", pgInfo->evtCmdNum);

                // The remaining part of the message is a null-terminated
                // query string
                tz_int8  *sqlStg;
                tz_uint32 sqlStgLen;
                sqlStgLen = pgInfo->ssnBuf->SbAvail();
                Dprint1("%u\n", (unsigned)sqlStgLen);

                dataLenRead = pgInfo->ssnBuf->SbRecv(&sqlStg, sqlStgLen);
                if(dataLenRead < sqlStgLen)
                {
                    // Insufficient data to process, Return it then header
                    Dprint1("U2\n");
                    pgInfo->ssnBuf->SbReturn(&sqlStg, dataLenRead);
                    pgInfo->ssnBuf->SbReturn(&data, dataLen);
                    isDecoding = false;
                }
                else
                {

                    // Initialize response counters, status
                    pgInfo->evtRespBytes   = 0;
                    pgInfo->evtRespRows    = 0;
                    pgInfo->evtStatus.evtRespStatus  = UNKNOWN_OPERATION;
                    pgInfo->evtStatus.evtIsComplete  = false;
                    pgInfo->evtStatus.evtIsIssued    = false;

                    // Clean up any lingering SQL buffers in case a lost
                    // response left them hanging
                    pgSqlBufMgrFree(se);

                    // Initialize the SQL buffer mechanism
                    pgSqlBufMgrInit(se);

                    tz_uint32 sbmLen, sbmIdx;
                    tz_uint32 rv = IIMS_SUCCESS;

                    sbmIdx = 0;

                    while( sbmIdx < sqlStgLen )
                    {
                        if(sqlStgLen - sbmIdx > PGSQL_BUFMGR_MAX_LEN)
                            sbmLen = PGSQL_BUFMGR_MAX_LEN;
                        else
                            sbmLen = sqlStgLen - sbmIdx;

                        // Create an SQL buffer for this new query
                        tz_int8 *newBuf;
                        rv = pgSqlBufMgrAlloc(se, sbmLen, &newBuf);
                        if( rv == IIMS_FAILURE )
                        {
                            Dprint1("U3\n");
                            pgInfo->ssnBuf->SbReturn(&sqlStg, dataLenRead);
                            pgInfo->ssnBuf->SbReturn(&data, dataLen);
                            isDecoding = false;
                            lc_log_basic(LOG_NOTICE,"Postgres decoder error: pgSqlBufMgrAlloc");
                            break;
                        }

                        // Store data in the SQL buffer
                        memcpy( newBuf,
                                &sqlStg[sbmIdx],
                                sbmLen);

                        // Perform Content Scanning on Client Side
                        if( cmdDataPatMgr->CSEnabled() == true )
                        {
                            pgInfo->clientCs->ScanData( 
                                           (const tz_uint8 *)&sqlStg[sbmIdx],
                                            sbmLen,
                                            se->workerIdx );
                        }

                        sbmIdx += PGSQL_BUFMGR_MAX_LEN;
                    }

                    if(rv == IIMS_FAILURE)  break;

                    // Enter TCP continuation state where we assume any
                    // subsequent traffic are segments containing query
                    // SQL text.
                    pgInfo->handler = &PgDecode::NzProcessQueryCont;
                }
            }
            break;

        case 'P':

            if(se->trafficDirection == TRAFFIC_FROM_CLIENT)
            {
                // Parse (issued by client)
                // M3, M4, M5, M6 client side
                Dprint("P> ");
                dataLen = sizeof(NzParse);

                Dprint1("%u ", (unsigned)dataLen);
                dataLenRead = pgInfo->ssnBuf->SbRecv(&data, dataLen);
                if(dataLenRead < dataLen)
                {
                    // Insufficient data to process, Return it
                    Dprint1("U\n");
                    pgInfo->ssnBuf->SbReturn(&data, dataLenRead);
                    isDecoding = false;
                }
                else
                {
                    NzParse *msg = (NzParse *)data;

                    // Save the command number
                    pgInfo->evtCmdNum = ptohl(msg->cmdNum);
                    Dprint("(%lu) ", pgInfo->evtCmdNum);

                    // The remaining part of the message is a null-
                    // terminated query string
                    tz_int8  *sqlStg;
                    tz_uint32 sqlStgLen;
                    sqlStgLen = pgInfo->ssnBuf->SbAvail();
                    Dprint1("%u\n", (unsigned)sqlStgLen);

                    dataLenRead = pgInfo->ssnBuf->SbRecv(&sqlStg, sqlStgLen);
                    if(dataLenRead < sqlStgLen)
                    {
                        Dprint1("U\n");

                        // Return the partial data
                        pgInfo->ssnBuf->SbReturn(&sqlStg, dataLenRead);

                        // Return the message header
                        pgInfo->ssnBuf->SbReturn((tz_int8 **)&msg, 
                                                  sizeof(NzParse));

                        TrapUnderflow();
                        isDecoding = false;
                    }
                    else
                    {
                        // Initialize response counters, status
                        pgInfo->evtRespBytes   = 0;
                        pgInfo->evtRespRows    = 0;
                        pgInfo->evtStatus.evtRespStatus  = UNKNOWN_OPERATION;
                        pgInfo->evtStatus.evtIsComplete  = false;
                        pgInfo->evtStatus.evtIsIssued    = false;

                        // Clean up any lingering SQL buffers in case a lost
                        // response left them hanging
                        pgSqlBufMgrFree(se);

                        // Initialize the SQL buffer mechanism
                        pgSqlBufMgrInit(se);

                        tz_uint32 sbmLen, sbmIdx;
                        tz_uint32 rv = IIMS_SUCCESS;

                        sbmIdx = 0;

                        while( sbmIdx < sqlStgLen )
                        {
                            if(sqlStgLen - sbmIdx > PGSQL_BUFMGR_MAX_LEN)
                                sbmLen = PGSQL_BUFMGR_MAX_LEN;
                            else
                                sbmLen = sqlStgLen - sbmIdx;

                            // Create an SQL buffer for this new query
                            tz_int8 *newBuf;
                            rv = pgSqlBufMgrAlloc(se, sbmLen, &newBuf);
                            if( rv == IIMS_FAILURE )
                            {
                                Dprint1("U3\n");
                                pgInfo->ssnBuf->SbReturn(&sqlStg, dataLenRead);
                                pgInfo->ssnBuf->SbReturn(&data, dataLen);
                                isDecoding = false;
                                lc_log_basic(LOG_NOTICE,"Postgres decoder error: pgSqlBufMgrAlloc");
                                break;
                            }

                            // Store data in the SQL buffer
                            memcpy( newBuf,
                                    &sqlStg[sbmIdx],
                                    sbmLen);

                            // Perform Content Scanning on Client Side
                            if( cmdDataPatMgr->CSEnabled() == true )
                            {
                                pgInfo->clientCs->ScanData( 
                                              (const tz_uint8 *)&sqlStg[sbmIdx],
                                               sbmLen,
                                               se->workerIdx );
                            }

                            sbmIdx += PGSQL_BUFMGR_MAX_LEN;
                        }

                        if(rv == IIMS_FAILURE)  break;

                        // Enter TCP continuation state where we assume any
                        // subsequent traffic are segments containing query
                        // SQL text.
                        pgInfo->handler = &PgDecode::NzProcessQueryCont;
                    }
                }
            }
            else
            {
                // Portal (from server, returned result set)
                // M4 server side
                Dprint("P< ");
                dataLen = sizeof(NzPortal);

                Dprint1("%u ", (unsigned)dataLen);
                dataLenRead = pgInfo->ssnBuf->SbRecv(&data, dataLen);
                if(dataLenRead < dataLen)
                {
                    // Insufficient data to process, Return it
                    Dprint1("U\n");
                    pgInfo->ssnBuf->SbReturn(&data, dataLenRead);
                    isDecoding = false;
                }
                else
                {
                    NzPortal *msg = (NzPortal *)data;
                    dataLen = ptohl(msg->length);
                    Dprint1("%u ", (unsigned)dataLen);

                    // Read and toss the string ("blank")
                    dataLenRead = pgInfo->ssnBuf->SbRecv(&data, dataLen);
                    if(dataLenRead < dataLen)
                    {
                        Dprint1("U\n");

                        // Return the partial data
                        pgInfo->ssnBuf->SbReturn(&data, dataLenRead);

                        // Return the message header
                        pgInfo->ssnBuf->SbReturn((tz_int8 **)&msg, sizeof(NzPortal));

                        TrapUnderflow();
                        isDecoding = false;
                    }
                    else
                    {
                        // Success, allow decoding to continue
                        Dprint("(%lu) ", ptohl(msg->cmdNum));

                        // response.status is set to SUCCESSFUL_OPERATION
                        // when 'Z' is received
                    }
                }
            }
            break;

        case 'I':
            // EmptyQuery response
            Dprint("I ");

            //   U N T E S T E D

            // I believe 'I' has a 1 byte payload that should be '\0'
            dataLen = sizeof(NzEmptyQueryResp);
            Dprint1("%u ", (unsigned)dataLen);
            dataLenRead = pgInfo->ssnBuf->SbRecv(&data, dataLen);
            if(dataLenRead < dataLen)
            {
                // Insufficient data to process, Return it
                Dprint1("U\n");
                pgInfo->ssnBuf->SbReturn(&data, dataLenRead);
                isDecoding = false;
            }
            else
            {
                NzEmptyQueryResp *msg = (NzEmptyQueryResp *)data;

                // we expect msg->code == '\0'.  Not sure what to do
                // if we don't get it

                // Record response.status
                pgInfo->evtStatus.evtRespStatus = FAILED_QUERY_DOESNT_EXIST;
                pgInfo->evtStatus.evtIsComplete = true;
                pgInfo->evtStatus.evtIsIssued   = false;

                Dprint("EVT");
                Dprint1("\n");

                PrepareEvent(se);
            }
            break;

        case 'E':
            // Error response
            Dprint("E ");
            dataLen = sizeof(NzError);

            Dprint1("%u ", (unsigned)dataLen);
            dataLenRead = pgInfo->ssnBuf->SbRecv(&data, dataLen);
            if(dataLenRead < dataLen)
            {
                // Insufficient data to process, Return it
                pgInfo->ssnBuf->SbReturn(&data, dataLenRead);
                isDecoding = false;
            }
            else
            {
                NzError *msg = (NzError *)data;

                // Save the command number
                pgInfo->evtCmdNum = ptohl(msg->cmdNum);
                Dprint("(%lu) ", pgInfo->evtCmdNum);

                // The remaining part of the message is a null-
                // terminated query string
                tz_int8  *errStg;
                tz_uint32 errStgLen = ptohl(msg->length);
                Dprint1("%u\n", (unsigned)errStgLen);

                // Read the error string
                dataLenRead = pgInfo->ssnBuf->SbRecv(&errStg, errStgLen);
                if(dataLenRead < errStgLen)
                {
                    Dprint1("U\n");

                    // Insufficient data to process, Return it
                    pgInfo->ssnBuf->SbReturn(&errStg, dataLenRead);

                    // Return the message header
                    pgInfo->ssnBuf->SbReturn((tz_int8 **)&msg, sizeof(NzError));

                    TrapUnderflow();
                    isDecoding = false;
                }
                else
                {
                    // Print the error message for debug
                    Dprint("\n%s\n", msg->data);

                    // Record response.status
                    pgInfo->evtStatus.evtRespStatus = FAILED_OPERATION;
                    pgInfo->evtStatus.evtIsComplete = true;
                    pgInfo->evtStatus.evtIsIssued   = false;

                    Dprint("EVT");
                    Dprint1("\n");

                    PrepareEvent(se);
                }
            }
            break;

        case 'T':
            // Row Descriptors
            Dprint("T ");

            dataLen = sizeof(NzRowDesc);
            Dprint1("%u ", (unsigned)dataLen);
            dataLenRead = pgInfo->ssnBuf->SbRecv(&data, dataLen);
            if(dataLenRead < dataLen)
            {
                // Insufficient data to process, Return it
                Dprint1("U\n");
                pgInfo->ssnBuf->SbReturn(&data, dataLenRead);
                isDecoding = false;
            }
            else
            {
                NzRowDesc *msg = (NzRowDesc *)data;
                dataLen = ptohl(msg->length);
                Dprint1("%u ", (unsigned)dataLen);

                // FIX: For now we read and toss.  Later we need to understand
                // the descriptor formats
                dataLenRead = pgInfo->ssnBuf->SbRecv(&data, dataLen);
                if(dataLenRead < dataLen)
                {
                    Dprint1("U\n");

                    // Return the partial data
                    pgInfo->ssnBuf->SbReturn(&data, dataLenRead);

                    // Return the message header
                    pgInfo->ssnBuf->SbReturn((tz_int8 **)&msg, sizeof(NzRowDesc));

                    TrapUnderflow();
                    isDecoding = false;
                }
            }
            break;

        case 'D':
            // ASCII Data Row
            Dprint("D ");

            dataLen = sizeof(NzDataRow);
            Dprint1("%u ", (unsigned)dataLen);
            dataLenRead = pgInfo->ssnBuf->SbRecv(&data, dataLen);
            if(dataLenRead < dataLen)
            {
                // Insufficient data to process, Return it
                Dprint1("U\n");
                pgInfo->ssnBuf->SbReturn(&data, dataLenRead);
                isDecoding = false;
            }
            else
            {
                // The following logic is common to 'D', 'B', 'X', and 'Y'
                NzDataRow *msg = (NzDataRow *)data;
                dataLen = ptohl(msg->length);
                Dprint1("%u ", (unsigned)dataLen);

                // FIX: Whether we handle the payload now or in stream mode
                //      we currently read and toss.  Later we may need to
                //      recover descriptor data

                dataLenRead = pgInfo->ssnBuf->SbRecv(&data, dataLen);

                if(    dataLen > dataLenRead
                    && dataLen < pgInfo->ssnBuf->SbShowBlockSize() )
                {
                    // Underflow but not by much, leave it for ssnBuf
                    Dprint1("U\n");

                    // Return the partial data
                    pgInfo->ssnBuf->SbReturn(&data, dataLenRead);

                    // Return the message header
                    pgInfo->ssnBuf->SbReturn((tz_int8 **)&msg, sizeof(NzDataRow));

                    TrapUnderflow();
                    isDecoding = false;

                    // Terminate processing and wait for next segment
                    break;
                }

                // Test for the start of stream mode
                if( dataLen > dataLenRead )
                {
                    // Underflow and by a significant amount.
                    // Stream this payload and subsequent ones
                    pgInfo->streamModeCodepoint = opcode;
                    pgInfo->streamModeTotRemaining = dataLen - dataLenRead;
                    pgInfo->streamModeTotExpected = dataLen;
                    pgInfo->handler = &PgDecode::NzProcessStreamMode;

                    Dprint("stream %u/%u/%u ",
                              (unsigned)dataLen,
                              (unsigned)dataLenRead, 
                              (unsigned)pgInfo->streamModeTotRemaining );
                }

                // Otherwise, dataLen == dataLenRead and the descriptor
                // is entirely contained in this segment

                // Whether entirely contained or the start of stream mode,
                // process the remaining data
                ++pgInfo->evtRespRows;
                pgInfo->evtRespBytes += dataLenRead;

                // Perform Content Scanning
                if( rspDataPatMgr->CSEnabled() == true )
                {
                    // FIX - where necessary, convert data to ASCII 
                    //       prior to scan

                    pgInfo->serverCs->ScanData( 
                                          (const tz_uint8 *)&data[0],
                                           dataLenRead,
                                           se->workerIdx );
                }
            }
            break;

        case 'B':

            //   U N T E S T E D
            volatile tz_uint32 whacko;
            ++whacko;


            // Binary Data Row
            Dprint("B ");

            dataLen = sizeof(NzBinDataRow);
            Dprint1("%u ", (unsigned)dataLen);
            dataLenRead = pgInfo->ssnBuf->SbRecv(&data, dataLen);
            if(dataLenRead < dataLen)
            {
                // Insufficient data to process, Return it
                Dprint1("U\n");
                pgInfo->ssnBuf->SbReturn(&data, dataLenRead);
                isDecoding = false;
            }
            else
            {
                // The following logic is common to 'D', 'B', 'X', and 'Y'
                NzBinDataRow *msg = (NzBinDataRow *)data;
                dataLen = ptohl(msg->length);
                Dprint1("%u ", (unsigned)dataLen);

                // FIX: Whether we handle the payload now or in stream mode
                //      we currently read and toss.  Later we may need to
                //      recover descriptor data

                dataLenRead = pgInfo->ssnBuf->SbRecv(&data, dataLen);

                if(    dataLen > dataLenRead
                    && dataLen < pgInfo->ssnBuf->SbShowBlockSize() )
                {
                    // Underflow but not by much, leave it for ssnBuf
                    Dprint1("U\n");

                    // Return the partial data
                    pgInfo->ssnBuf->SbReturn(&data, dataLenRead);

                    // Return the message header
                    pgInfo->ssnBuf->SbReturn((tz_int8 **)&msg, sizeof(NzBinDataRow));

                    TrapUnderflow();
                    isDecoding = false;

                    // Terminate processing and wait for next segment
                    break;
                }

                // Test for the start of stream mode
                if( dataLen > dataLenRead )
                {
                    // Underflow and by a significant amount.
                    // Stream this payload and subsequent ones
                    pgInfo->streamModeCodepoint = opcode;
                    pgInfo->streamModeTotRemaining = dataLen - dataLenRead;
                    pgInfo->streamModeTotExpected = dataLen;
                    pgInfo->handler = &PgDecode::NzProcessStreamMode;

                    Dprint("stream %u/%u/%u ",
                              (unsigned)dataLen,
                              (unsigned)dataLenRead, 
                              (unsigned)pgInfo->streamModeTotRemaining );
                }

                // Otherwise, dataLen == dataLenRead and the descriptor
                // is entirely contained in this segment

                // Whether entirely contained or the start of stream mode,
                // process the remaining data
                ++pgInfo->evtRespRows;
                pgInfo->evtRespBytes += dataLenRead;

                // Perform Content Scanning
                if( rspDataPatMgr->CSEnabled() == true )
                {
                    // FIX - where necessary, convert data to ASCII 
                    //       prior to scan

                    pgInfo->serverCs->ScanData( 
                                          (const tz_uint8 *)&data[0],
                                           dataLenRead,
                                           se->workerIdx );
                }
            }
            break;

        case 'X':
            // Terminate or DBOS Extended Tuple
            Dprint("X ");

            // Terminate (2 byte form)  'X' followed by NULL.
            if( pgInfo->ssnBuf->SbAvail() == 2 )
            {
                dataLenRead = pgInfo->ssnBuf->SbRecv(&data, 2);
                if(data[1] == 0) 
                {
                    // Nullable ?  What is this?
                    Dprint("2-byte ");

                    // Test for ssl mode here and adjust debug counter
                    if( 's' == pgInfo->ssnBuf->SbShowMode() ) {
                        --decodeStats.sessionsSsl;
                        Dprint("ssl ");
                    }
                    Dprint("\n");
                    break;
                }
                else
                {
                    // This may just be a fragment
                    pgInfo->ssnBuf->SbReturn(&data, 2);
                    Dprint1("U\n");
                    isDecoding = false;
                }
            }

            // Terminate (1 byte form)  Just the 'X'
            if( pgInfo->ssnBuf->SbAvail() == 1 )
            {
                dataLenRead = pgInfo->ssnBuf->SbRecv(&data, 1);

                // presume dataLenRead == 1
                Dprint("1-byte ");

                if( 's' == pgInfo->ssnBuf->SbShowMode() ) {
                    --decodeStats.sessionsSsl;
                    Dprint("ssl ");
                }
                Dprint("\n");
                break;
            }

            // Normal DBOS Extended Tuple processing
            dataLen = sizeof(NzDbosExtTup);
            Dprint1("%u ", (unsigned)dataLen);
            dataLenRead = pgInfo->ssnBuf->SbRecv(&data, dataLen);
            if(dataLenRead < dataLen)
            {
                // Insufficient data to process, Return it
                Dprint1("U\n");
                pgInfo->ssnBuf->SbReturn(&data, dataLenRead);
                isDecoding = false;
            }
            else
            {
                // The following logic is common to 'D', 'B', 'X', and 'Y'
                NzDbosExtTup *msg = (NzDbosExtTup *)data;
                dataLen = ptohl(msg->length);
                Dprint1("%u ", (unsigned)dataLen);

                // FIX: Whether we handle the payload now or in stream mode
                //      we currently read and toss.  Later we may need to
                //      recover descriptor data

                dataLenRead = pgInfo->ssnBuf->SbRecv(&data, dataLen);

                if(    dataLen > dataLenRead
                    && dataLen < pgInfo->ssnBuf->SbShowBlockSize() )
                {
                    // Underflow but not by much, leave it for ssnBuf
                    Dprint1("U\n");

                    // Return the partial data
                    pgInfo->ssnBuf->SbReturn(&data, dataLenRead);

                    // Return the message header
                    pgInfo->ssnBuf->SbReturn((tz_int8 **)&msg, sizeof(NzDbosExtTup));

                    TrapUnderflow();
                    isDecoding = false;

                    // Terminate processing and wait for next segment
                    break;
                }

                // Test for the start of stream mode
                if( dataLen > dataLenRead )
                {
                    // Underflow and by a significant amount.
                    // Stream this payload and subsequent ones
                    pgInfo->streamModeCodepoint = opcode;
                    pgInfo->streamModeTotRemaining = dataLen - dataLenRead;
                    pgInfo->streamModeTotExpected = dataLen;
                    pgInfo->handler = &PgDecode::NzProcessStreamMode;

                    Dprint("stream %u/%u/%u ",
                              (unsigned)dataLen,
                              (unsigned)dataLenRead, 
                              (unsigned)pgInfo->streamModeTotRemaining );
                }

                // Otherwise, dataLen == dataLenRead and the descriptor
                // is entirely contained in this segment

                // Whether entirely contained or the start of stream mode,
                // process the remaining data
                ++pgInfo->evtRespRows;
                pgInfo->evtRespBytes += dataLenRead;

                // Perform Content Scanning
                if( rspDataPatMgr->CSEnabled() == true )
                {
                    // FIX - where necessary, convert data to ASCII 
                    //       prior to scan

                    pgInfo->serverCs->ScanData( 
                                          (const tz_uint8 *)&data[0],
                                           dataLenRead,
                                           se->workerIdx );
                }
            }
            break;

        case 'Y':
            // DBOS Tuple
            Dprint("Y ");

            dataLen = sizeof(NzDbosTup);
            Dprint1("%u ", (unsigned)dataLen);
            dataLenRead = pgInfo->ssnBuf->SbRecv(&data, dataLen);
            if(dataLenRead < dataLen)
            {
                // Insufficient data to process, Return it
                Dprint1("U\n");
                pgInfo->ssnBuf->SbReturn(&data, dataLenRead);
                isDecoding = false;
            }
            else
            {
              // The following logic is common to 'D', 'B', 'X', and 'Y'
                NzDbosTup *msg = (NzDbosTup *)data;
                dataLen = ptohl(msg->length);
                Dprint1("%u ", (unsigned)dataLen);

                // FIX: Whether we handle the payload now or in stream mode
                //      we currently read and toss.  Later we may need to
                //      recover descriptor data

                dataLenRead = pgInfo->ssnBuf->SbRecv(&data, dataLen);

                if(    dataLen > dataLenRead
                    && dataLen < pgInfo->ssnBuf->SbShowBlockSize() )
                {
                    // Underflow but not by much, leave it for ssnBuf
                    Dprint1("U\n");

                    // Return the partial data
                    pgInfo->ssnBuf->SbReturn(&data, dataLenRead);

                    // Return the message header
                    pgInfo->ssnBuf->SbReturn((tz_int8 **)&msg, sizeof(NzDbosTup));

                    TrapUnderflow();
                    isDecoding = false;

                    // Terminate processing and wait for next segment
                    break;
                }

                // Test for the start of stream mode
                if( dataLen > dataLenRead )
                {
                    // Underflow and by a significant amount.
                    // Stream this payload and subsequent ones
                    pgInfo->streamModeCodepoint = opcode;
                    pgInfo->streamModeTotRemaining = dataLen - dataLenRead;
                    pgInfo->streamModeTotExpected = dataLen;
                    pgInfo->handler = &PgDecode::NzProcessStreamMode;

                    Dprint("stream %u/%u/%u ",
                              (unsigned)dataLen,
                              (unsigned)dataLenRead, 
                              (unsigned)pgInfo->streamModeTotRemaining );
                }

                // Otherwise, dataLen == dataLenRead and the descriptor
                // is entirely contained in this segment

                // Whether entirely contained or the start of stream mode,
                // process the remaining data
                ++pgInfo->evtRespRows;
                pgInfo->evtRespBytes += dataLenRead;

                // Perform Content Scanning
                if( rspDataPatMgr->CSEnabled() == true )
                {
                    // FIX - where necessary, convert data to ASCII 
                    //       prior to scan

                    pgInfo->serverCs->ScanData( 
                                          (const tz_uint8 *)&data[0],
                                           dataLenRead,
                                           se->workerIdx );
                }
            }
            break;

        case 'N':
            // Notice
            Dprint("N< ");
            dataLen = sizeof(NzNotice);

            // Notice is like an additional response from server
            // so stay in this state.  We don't care about content.
            Dprint1("%u ", (unsigned)dataLen);
            dataLenRead = pgInfo->ssnBuf->SbRecv(&data, dataLen);
            if(dataLenRead < dataLen)
            {
                // Insufficient data to process, Return it
                pgInfo->ssnBuf->SbReturn(&data, dataLenRead);
                isDecoding = false;
            }
            else
            {
                NzNotice *msg = (NzNotice *)data;

                // Print the command number
                Dprint("(%lu) ", ptohl(msg->cmdNum));

                // The remaining part of the message is a null-terminated
                // message string
                tz_int8  *msgStg;
                tz_uint32 msgStgLen = ptohl(msg->length);
                Dprint1("%u\n", (unsigned)msgStgLen);

                // Read the message string
                dataLenRead = pgInfo->ssnBuf->SbRecv(&msgStg, msgStgLen);
                if(dataLenRead < msgStgLen)
                {
                    Dprint1("U\n");

                    // Insufficient data to process, Return it
                    pgInfo->ssnBuf->SbReturn(&msgStg, dataLenRead);

                    // Return the message header
                    pgInfo->ssnBuf->SbReturn((tz_int8 **)&msg, sizeof(NzNotice));

                    TrapUnderflow();
                    isDecoding = false;
                }
                else
                {
                    // Print the message for debug
                    Dprint("\n%s\n", msg->data);
                }
            }
            break;

        case 'A':
            lc_log_basic(LOG_NOTICE,"Postgres decoder error: NzProcessQuery "
                                          "Unimplemented opcode %c", opcode);
            break;

        case 'C':
            // Close
            // all mechanisms
            Dprint("C ");

            dataLen = sizeof(NzClose);
            Dprint1("%u ", (unsigned)dataLen);
            dataLenRead = pgInfo->ssnBuf->SbRecv(&data, dataLen);
            if(dataLenRead < dataLen)
            {
                // Insufficient data to process, Return it
                Dprint1("U\n");
                pgInfo->ssnBuf->SbReturn(&data, dataLenRead);
                isDecoding = false;
            }
            else
            {
                NzClose *msg = (NzClose *)data;

                Dprint("(%lu) ", ptohl(msg->cmdNum));

                dataLen = ptohl(msg->length);
                Dprint1("%u ", (unsigned)dataLen);

                // FIX: For now we read and toss.  Later we need to understand
                // and use the Close codepoint
                dataLenRead = pgInfo->ssnBuf->SbRecv(&data, dataLen);
                if(dataLenRead < dataLen)
                {
                    Dprint1("%u ", (unsigned)dataLen);

                    // Return the partial data
                    pgInfo->ssnBuf->SbReturn(&data, dataLenRead);

                    // Return the message header
                    pgInfo->ssnBuf->SbReturn((tz_int8 **)&msg, sizeof(NzClose));

                    TrapUnderflow();
                    isDecoding = false;
                }
            }
            break;

        case 'Z':
          // Ready for Query (usually embedded with 'P' or 'C')
            Dprint("Z ");

            dataLen = sizeof(NzRdyQuery);
            Dprint1("%u ", (unsigned)dataLen);
            dataLenRead = pgInfo->ssnBuf->SbRecv(&data, dataLen);
            if(dataLenRead < dataLen)
            {
                // Insufficient data to process, Return it
                Dprint1("U\n");
                pgInfo->ssnBuf->SbReturn(&data, dataLenRead);
                TrapUnderflow();
                isDecoding = false;
            }
            else if( pgInfo->evtStatus.evtIsIssued == false )  // M5 enforcement
            {
                Dprint("EVT");
                Dprint1("\n");

                // Record response.status
                pgInfo->evtStatus.evtRespStatus = SUCCESSFUL_OPERATION;
                pgInfo->evtStatus.evtIsComplete = true;
                pgInfo->evtStatus.evtIsIssued   = false;

                PrepareEvent(se);
            }
            break;

        default:

            // Unimplemented opcode.  Make note of it and flush it to keep
            // the decoder from stalling
            lc_log_basic(LOG_NOTICE,"Postgres decoder error: NzProcessQuery "
                                           "Unknown opcode \'%c\'", opcode);
            ++decodeStats.unknownCodepoints;
            TrapUnknown(opcode);

            dataLen = sizeof(NzMsg);
            dataLenRead = pgInfo->ssnBuf->SbRecv(&data, dataLen);
            if(dataLenRead < dataLen)
            {
                // Insufficient data to process, Return it
                pgInfo->ssnBuf->SbReturn(&data, dataLenRead);
                isDecoding = false;
            }
            else
            {
                NzMsg *msg = (NzMsg *)data;
                dataLen = ptohl(msg->length);
                dataLenRead = pgInfo->ssnBuf->SbRecv(&data, dataLen);
                if(dataLenRead < dataLen)
                {
                    // Return the partial data
                    pgInfo->ssnBuf->SbReturn(&data, dataLenRead);

                    // Return the message header
                    pgInfo->ssnBuf->SbReturn((tz_int8 **)&msg, sizeof(NzMsg));

                    TrapUnderflow();
                    isDecoding = false;
                }
            }
            break;

        }

        // If no more data, finish processing
        if( pgInfo->ssnBuf->SbAvail() == 0 )
        {
            isDecoding = false;
        }

    } while (0);

    return isDecoding;
}

//-----------------------------------------------------------------------
// NzProcessQueryCont()
//     Process continuation query messages.  This handles the capture
//     of SQL statements which are potentially longer than what can fit
//     in a TCP segment on an Eth link (e.g. 1460 bytes or so).
//
//     This state is exited when a 'P' message (containing formatted
//     response data) is received.
//
// return:
//     true  - more processing
//     false - processing completed
//-----------------------------------------------------------------------
bool PgDecode::NzProcessQueryCont(SessionEntry *se)
{
    tz_int8   *data;
    tz_uint32  dataLen;
    tz_uint32  dataLenRead;
    bool       isDecoding = true;
    PgInfo    *pgInfo     = (PgInfo *)se->appInfo;

    do
    {
        // We assume here that if a 'P' response is received, that it
        // will be at the beginning of the segment.
        dataLenRead = pgInfo->ssnBuf->SbRecvBlock(&data);

        // Test to see if opcode and command number match
        NzMsg *msg     = (NzMsg *)data;
        NzNotice *msgN = (NzNotice *)data;

        // FIX - data could be shorter than sizeof(NzMsg).  Push back if so

        if(   dataLenRead >= sizeof(NzMsg)
           && ptohl(msg->cmdNum) == pgInfo->evtCmdNum )
        {
            // 'P', 'N', 'X', 'A', 'E', 'Z'
            switch( msg->opcode )
            {
            // Parse
            case 'P':
                if(se->trafficDirection == TRAFFIC_FROM_CLIENT)
                {
                    // Parse (issued by client)
                    // M3, M4 client side request
                    Dprint("/P>\n");
                }
                else
                {
                    // Portal (from server, returned result set)
                    // M1, M4 from server
                    Dprint("/P<\n");
                }
                // Return the block so that NzProces Query can pick it apart
                pgInfo->ssnBuf->SbReturn(&data, dataLenRead);

                // Return to the regular Query state
                pgInfo->handler = &PgDecode::NzProcessQuery;
                break;

            case 'C':
                // Close
                // all mechanisms
                Dprint("/C\n");

                // Return the block so that NzProces Query can pick it apart
                pgInfo->ssnBuf->SbReturn(&data, dataLenRead);

                // Return to the regular Query state
                pgInfo->handler = &PgDecode::NzProcessQuery;
                break;

            case 'I':
                // EmptyQuery response
                Dprint("/I\n");

                // Return the block so that NzProces Query can pick it apart
                pgInfo->ssnBuf->SbReturn(&data, dataLenRead);

                // Return to the regular Query state
                pgInfo->handler = &PgDecode::NzProcessQuery;
                break;

            case 'E':
                // Error response
                Dprint("/E\n");

                // Return the block so that NzProces Query can pick it apart
                pgInfo->ssnBuf->SbReturn(&data, dataLenRead);

                // Return to the regular Query state
                pgInfo->handler = &PgDecode::NzProcessQuery;
                break;


            case 'N':
                // Notice
                Dprint("N< ");

                // Notice is like an additional response from server
                // so stay in this state.  We don't care about content.
                dataLen = ptohl(msgN->length) + sizeof(NzNotice);
                Dprint1("%u ", (unsigned)dataLen);

                if( dataLenRead < dataLen )
                {
                    Dprint1("U\n");

                    // Insufficient data to process, Return it
                    pgInfo->ssnBuf->SbReturn(&data, dataLenRead);

                    TrapUnderflow();
                    isDecoding = false;
                }
                else
                {
                    Dprint("(%lu) ", ptohl(msgN->cmdNum));

                    // Print the error message for debug
                    Dprint("\n%s\n", msgN->data);
                    Dprint1("\n");
                }
                break;

            case 'A':
            case 'X':
            case 'Z':
            default:

#ifdef NTZ_RUNTIME_TEST
                TZ_ASSERT(false,"NzProcessQueryCont invalid_op\n");
#endif

                lc_log_basic(LOG_NOTICE,"NzProcessQueryCont error 0, opcode %c",
                                                                   msg->opcode);
                break;
            }
        }
        else if(    dataLenRead >= sizeof(NzMsg)
                 && ptohl(msg->cmdNum) > pgInfo->evtCmdNum
                 && msg->opcode == 'Q' )
        {
            // Query - error condition.  We're here because the 'P'
            // response to a previous 'Q' was not received by the
            // Mantra.  Now the client is issuing a new 'Q' request.
            Dprint("/Q\n");

            // I don't really like this test.  There could be a false
            // positive due to data in the cmdNum field and data that
            // just happens to match 'Q' in the opcode field.  
            // Unfortunately there's not much else to go on.

            // Return the block so that NzProces Query can pick it apart
            pgInfo->ssnBuf->SbReturn(&data, dataLenRead);

            // PrepareEvent for Partial event.  It will clean up any
            // SQL buffer chain elements
            pgInfo->evtStatus.evtIsComplete = false;

            Dprint("EVT");
            Dprint1("\n");

            PrepareEvent(se);

            // Return control back to the Query state
            pgInfo->handler = &PgDecode::NzProcessQuery;
        }
        else if(msg->opcode == 'l' && dataLenRead == 1)
        {
            // M6 Load/Unload (file name being presented)
            Dprint("l< ");

            // Set the handler
            pgInfo->handler = &PgDecode::NzProcessLoadUnload;

            // Consume this message
            isDecoding = false;
            break;
        }
        else
        {
            // We assume this is SQL text so create another buffer
            Dprint("Q\n");

            // FIX: more validation needed here
            //      dataLenRead could be < sizeof(NzMsg)

            tz_uint32 sbmLen, sbmIdx;
            tz_uint32 rv = IIMS_SUCCESS;

            sbmIdx = 0;

            while( sbmIdx < dataLenRead )
            {
                if(dataLenRead - sbmIdx > PGSQL_BUFMGR_MAX_LEN)
                    sbmLen = PGSQL_BUFMGR_MAX_LEN;
                else
                    sbmLen = dataLenRead - sbmIdx;

                // Create an SQL buffer for this new query
                tz_int8 *newBuf;
                rv = pgSqlBufMgrAlloc(se, sbmLen, &newBuf);
                if( rv == IIMS_FAILURE )
                {
                    // Return all the data
                    pgInfo->ssnBuf->SbReturn(&data, dataLenRead);
                    isDecoding = false;
                    lc_log_basic(LOG_NOTICE,"Postgres decoder error: pgSqlBufMgrAlloc");
                    break;
                }

                // Store data in the SQL buffer
                memcpy( newBuf,
                        &data[sbmIdx],
                        sbmLen);

                // Perform Content Scanning on Client Side
                if( cmdDataPatMgr->CSEnabled() == true )
                {
                    pgInfo->clientCs->ScanData( (const tz_uint8 *)&data[sbmIdx],
                                                 sbmLen,
                                                 se->workerIdx );
                }

                sbmIdx += PGSQL_BUFMGR_MAX_LEN;
            }

            if(rv == IIMS_FAILURE)  break;

            // Stay in this state...
        }

        // If no more data, finish processing
        if( pgInfo->ssnBuf->SbAvail() == 0 )
        {
            isDecoding = false;
        }

    } while (0);

    return isDecoding;
}

//-----------------------------------------------------------------------
// PgProcessStartupMsg()
//     Process a StartupMsg
//
// return:
//     true  - more processing
//     false - processing completed
//-----------------------------------------------------------------------
bool PgDecode::PgProcessStartupMsg(SessionEntry *se)
{
    tz_int8   *data;
    tz_uint32  dataLen;
    tz_uint32  dataLenRead;
    bool       isDecoding = true;
    PgInfo    *pgInfo     = (PgInfo *)se->appInfo;

    do
    {
        //Dprint("PgStartupMsg\n");

        dataLen = sizeof(PgStartupMsg);

        dataLenRead = pgInfo->ssnBuf->SbRecv(&data, dataLen);

        if(dataLenRead < dataLen)
        {
            // Insufficient data to process, Return it
            pgInfo->ssnBuf->SbReturn(&data, dataLenRead);
            isDecoding = false;
            break;
        }

        // Grab the message header length.  We need it to read the
        // entire PgStartupMsg since it has variable length strings
        tz_uint32 totMsgLen = ptohl(((PgStartupMsg *)data)->length);

        // Now we'll return what we have read and then read out the
        // entire message header
        pgInfo->ssnBuf->SbReturn( &data, dataLenRead );
        dataLenRead = pgInfo->ssnBuf->SbRecv( &data, totMsgLen );

        if(dataLenRead < totMsgLen)
        {
            // Insufficient data to process, Return it
            pgInfo->ssnBuf->SbReturn(&data, dataLenRead);
            isDecoding = false;
            break;
        }

        PgStartupMsg *msg = (PgStartupMsg *)data;

        tz_int8 * token = &msg->data[0];

        // parse type,value pairs
        // type is ("user", "database", "options")
        while( token[0] )
        {
            //Dprint( "%s\n", token );

            // find the NULL and advance beyond it
            token += strlen((const char *)token) + 1;
        }

        // If no more data, finish processing
        if( pgInfo->ssnBuf->SbAvail() == 0 )
        {
            isDecoding = false;

            // Advance to auth processing
            pgInfo->handler = &PgDecode::PgDispatchMsg;
        }

    } while (0);

    return isDecoding;
}

//-----------------------------------------------------------------------
// PgDispatchMsg()
// return:
//     true  - more processing
//     false - processing completed
//-----------------------------------------------------------------------
bool PgDecode::PgDispatchMsg(SessionEntry *se)
{
    tz_int8   *data;
    tz_uint32  dataLen;
    tz_uint32  dataLenRead;
    bool       isDecoding = true;
    PgInfo    *pgInfo     = (PgInfo *)se->appInfo;

    do
    {
        dataLen = sizeof(PgMsg);

        dataLenRead = pgInfo->ssnBuf->SbRecv(&data, dataLen);

        if(dataLenRead < dataLen)
        {
            // Insufficient data to process, Return it
            pgInfo->ssnBuf->SbReturn(&data, dataLenRead);
            isDecoding = false;
            break;
        }

        // Select which Auth from authType and length
        tz_uint8 opcode = ((PgMsg *)data)->opcode;

        // Get actual length, add in 1-byte opcode (not included)
        dataLen = ptohl(((PgMsg *)data)->length);
        ++dataLen;

        // Return what we have read so actual processing can read
        // out its entire message header
        pgInfo->ssnBuf->SbReturn( &data, dataLenRead );

        switch(opcode)
        {
        // -- backend key data --
        case 'K':
            // not implemented, read and flush
            //Dprint("PgBackendKeyData (<K)\n");
            dataLen = sizeof(PgBackendKeyData);
            dataLenRead = pgInfo->ssnBuf->SbRecv(&data, dataLen);

            if(dataLenRead < dataLen)
            {
                // Insufficient data to process, Return it
                pgInfo->ssnBuf->SbReturn(&data, dataLenRead);
                isDecoding = false;
            }
            break;

        // -- password message --
        case 'p':
            isDecoding = PgProcessPwdMsg(se, dataLen);
            break;

        // -- password message --
        case 'P':
            isDecoding = PgProcessParseMsg(se, dataLen);
            break;

        // -- auth --
        case 'R':
            isDecoding = PgProcessAuthMsg(se, dataLen);
            break;

        // -- parameter status --
        case 'S':
            isDecoding = PgProcessParmStatus(se, dataLen);
            break;

        // -- ready for query --
        case 'Z':
            // not implemented, read and flush
            //Dprint("PgReadyForQuery (<Z)\n");
            dataLen = sizeof(PgReadyForQuery);
            dataLenRead = pgInfo->ssnBuf->SbRecv(&data, dataLen);

            if(dataLenRead < dataLen)
            {
                // Insufficient data to process, Return it
                pgInfo->ssnBuf->SbReturn(&data, dataLenRead);
                isDecoding = false;
            }
            break;

        default:
            break;
        }


    } while (0);

    return isDecoding;
}

//-----------------------------------------------------------------------
// PgProcessAuthMsg()
//     Process an Authorization message
//
// return:
//     true  - more processing
//     false - processing completed
//-----------------------------------------------------------------------
bool PgDecode::PgProcessAuthMsg(SessionEntry *se, tz_uint32 msgLen)
{
    tz_int8   *data;
    tz_uint32  dataLen;
    tz_uint32  dataLenRead;
    bool       isDecoding = true;
    PgInfo    *pgInfo     = (PgInfo *)se->appInfo;

    do
    {
        dataLen = sizeof(PgAuth);

        dataLenRead = pgInfo->ssnBuf->SbRecv(&data, dataLen);

        if(dataLenRead < dataLen)
        {
            // Insufficient data to process, Return it
            pgInfo->ssnBuf->SbReturn(&data, dataLenRead);
            isDecoding = false;
            break;
        }

#if 0
        // Verify it's an 'R'
        if(((PgAuth *)data)->opcode != 'R')
        {
            lc_log_basic(LOG_WARNING,"Postgres decoder error: AuthMsg format");
            isDecoding = false;
            break;
        }
#endif

        // Select which Auth from authType and length
        tz_uint32 authType = ptohl(((PgAuth *)data)->authType);

        // Get actual length, add in 1-byte opcode (not included)
        dataLen = ptohl(((PgAuth *)data)->length);
        ++dataLen;

        // Return what we have read and then read out the entire 
        // message header based on authType
        pgInfo->ssnBuf->SbReturn( &data, dataLenRead );

        switch(authType)
        {
        // success
        case 0:
            //Dprint("PgAuthOk (<R)\n");
            dataLenRead = pgInfo->ssnBuf->SbRecv( &data, dataLen);
            if(dataLenRead == dataLen)
            {
                volatile PgAuthOk *msg = (PgAuthOk *)data;
            }
            break;

        // Krb
        case 2:
            //Dprint("PgAuthKrbV5 (<R)\n");
            dataLenRead = pgInfo->ssnBuf->SbRecv( &data, dataLen);
            if(dataLenRead == dataLen)
            {
                volatile PgAuthKrbV5 *msg = (PgAuthKrbV5 *)data;
            }
            break;

        // Cleartext
        case 3:
            //Dprint("PgAuthCleartextPwd (<R)\n");
            dataLenRead = pgInfo->ssnBuf->SbRecv( &data, dataLen);
            if(dataLenRead == dataLen)
            {
                volatile PgAuthCleartextPwd *msg = (PgAuthCleartextPwd *)data;
            }
            break;

        // MD5
        case 5:
            //Dprint("PgAuthMd5Pwd (<R)\n");
            dataLenRead = pgInfo->ssnBuf->SbRecv( &data, dataLen);
            if(dataLenRead == dataLen)
            {
                volatile PgAuthMd5Pwd *msg = (PgAuthMd5Pwd *)data;
            }
            break;

        // SCMCredential, GSS, GSSContinue, SSPI
        case 6:  case 7:  case 8:  case 9:
        default:
            //Dprint("PgAuth??? (<R)\n");
            dataLenRead = pgInfo->ssnBuf->SbRecv( &data, dataLen);
            if(dataLenRead == dataLen)
            {
                
            }
            break;
        }

        if(dataLenRead != dataLen)
        {
            // Processing not done above
            // FIX

            // is this correct ? ? ?
            pgInfo->ssnBuf->SbReturn(&data, dataLenRead);
            isDecoding = false;
        }

        // If no more data, finish processing
        if( pgInfo->ssnBuf->SbAvail() == 0 )
        {
            isDecoding = false;

            // Advance to auth processing
//          pgInfo->handler = &PgDecode::PgProcessAuthMsg;
        }

    } while (0);

    return isDecoding;
}

//-----------------------------------------------------------------------
// PgProcessPwdMsg()
//     Process a Password message
//
// return:
//     true  - more processing
//     false - processing completed
//-----------------------------------------------------------------------
bool PgDecode::PgProcessPwdMsg(SessionEntry *se, tz_uint32 msgLen)
{
    tz_int8   *data;
    tz_uint32  dataLen;
    tz_uint32  dataLenRead;
    bool       isDecoding = true;
    PgInfo    *pgInfo     = (PgInfo *)se->appInfo;

    do
    {
        //Dprint("PgPwdMsg (>p)\n");
        dataLenRead = pgInfo->ssnBuf->SbRecv(&data, msgLen);

        if(dataLenRead < msgLen)
        {
            // Insufficient data to process, Return it
            pgInfo->ssnBuf->SbReturn(&data, dataLenRead);
            isDecoding = false;
            break;
        }

#if 0
        // Verify it's a 'p'
        if(((PgAuth *)data)->opcode != 'p')
        {
            lc_log_basic(LOG_WARNING,"Postgres decoder error: PwdMsg");
            isDecoding = false;
            break;
        }
#endif

        volatile PgPwdMsg *msg = (PgPwdMsg *)data;

        // If no more data, finish processing
        if( pgInfo->ssnBuf->SbAvail() == 0 )
        {
            isDecoding = false;
        }

    } while (0);

    return isDecoding;
}

//-----------------------------------------------------------------------
// PgProcessParseMsg()
//     Process a Parse message
//
// return:
//     true  - more processing
//     false - processing completed
//-----------------------------------------------------------------------
bool PgDecode::PgProcessParseMsg(SessionEntry *se, tz_uint32 msgLen)
{
    tz_int8   *data;
    tz_uint32  dataLen;
    tz_uint32  dataLenRead;
    bool       isDecoding = true;
    PgInfo    *pgInfo     = (PgInfo *)se->appInfo;

    do
    {
        //Dprint("PgParseMsg (>P)\n");
        dataLenRead = pgInfo->ssnBuf->SbRecv(&data, msgLen);

        if(dataLenRead < msgLen)
        {
            // Insufficient data to process, Return it
            pgInfo->ssnBuf->SbReturn(&data, dataLenRead);
            isDecoding = false;
            break;
        }

#if 0
        // Verify it's a 'P'
        if(((PgAuth *)data)->opcode != 'P')
        {
            // FIX: error
        
            isDecoding = false;
            break;
        }
#endif

        volatile PgParse *msg = (PgParse *)data;

        // If no more data, finish processing
        if( pgInfo->ssnBuf->SbAvail() == 0 )
        {
            isDecoding = false;
        }

    } while (0);

    return isDecoding;
}

//-----------------------------------------------------------------------
// PgProcessParmStatus()
//     
//
// return:
//     true  - more processing
//     false - processing completed
//-----------------------------------------------------------------------
bool PgDecode::PgProcessParmStatus(SessionEntry *se, tz_uint32 msgLen)
{
    tz_int8   *data;
    tz_uint32  dataLen;
    tz_uint32  dataLenRead;
    bool       isDecoding = true;
    PgInfo    *pgInfo     = (PgInfo *)se->appInfo;

    do
    {
        //Dprint("PgParmStatus (>S)\n");
        dataLenRead = pgInfo->ssnBuf->SbRecv(&data, msgLen);

        if(dataLenRead < msgLen)
        {
            // Insufficient data to process, Return it
            pgInfo->ssnBuf->SbReturn(&data, dataLenRead);
            isDecoding = false;
            break;
        }

#if 0
        // Verify it's a 'S'
        if(((PgAuth *)data)->opcode != 'S')
        {
            // FIX: error

            isDecoding = false;
            break;
        }
#endif

        PgPwdMsg *msg = (PgPwdMsg *)data;

        tz_int8 *token = &msg->data[0];
        dataLen = msgLen - sizeof(PgPwdMsg);

        // parse type,value pairs
        // type is ("user", "database", "options")
        while( token < &msg->data[dataLen] )
        {
            //Dprint( "%s\n", token );

            // find the NULL and advance beyond it
            token += strlen((const char *)token) + 1;
        }

        // If no more data, finish processing
        if( pgInfo->ssnBuf->SbAvail() == 0 )
        {
            isDecoding = false;
        }

    } while (0);

    return isDecoding;
}

//-----------------------------------------------------------------------
// PgProcessMsgHeader()
//     Process a Postgres message
//
// return:
//     true  - more processing
//     false - processing completed
//-----------------------------------------------------------------------
bool PgDecode::PgProcessMsgHeader(SessionEntry *se, tz_uint32 msgLen)
{
    tz_int8   *data;
    tz_uint32  dataLen;
    tz_uint32  dataLenRead;
    bool       isDecoding = true;
    PgInfo    *pgInfo     = (PgInfo *)se->appInfo;

    do
    {
        isDecoding = false;

    } while (0);

    return isDecoding;
}

//-----------------------------------------------------------------------
// IdentifyHandler()
//     NOTES:
//     - you must cover all cases of PgHandlerType
//     - every new handler needs a corresponding entry here
//     - entries are ordered by likelihood
//
//-----------------------------------------------------------------------
PgHandlerType PgDecode::IdentifyHandler(SessionEntry *se)
{
    PgInfo        *pgInfo = (PgInfo *)se->appInfo;
    PgHandlerType  hnd    = HndOther;

    if(pgInfo->handler == &PgDecode::NzProcessQuery)
    {
        hnd = HndNzProcessQuery;
    }
    else if(pgInfo->handler == &PgDecode::NzProcessQueryCont)
    {
        hnd = HndNzProcessQueryCont;
    }
    else if(pgInfo->handler == &PgDecode::ProcessSync)
    {
        hnd = HndProcessSync;
    }
    else if(pgInfo->handler == &PgDecode::NzProcessLoadUnload)
    {
        hnd = HndNzProcessLoadUnload;
    }
    else if(pgInfo->handler == &PgDecode::NzProcessNullSsn)
    {
        hnd = HndNzProcessNullSsn;
    }
    else if(pgInfo->handler == &PgDecode::NzProcessAuth)
    {
        hnd = HndNzProcessAuth;
    }
    else if(pgInfo->handler == &PgDecode::NzProcessHandshake)
    {
        hnd = HndNzProcessHandshake;
    }
    else if(pgInfo->handler == &PgDecode::NzProcessResync)
    {
        hnd = HndNzProcessResync;
    }
    else if(pgInfo->handler == &PgDecode::NzProcessResyncCont)
    {
        hnd = HndNzProcessResyncCont;
    }
    else if(pgInfo->handler == &PgDecode::NzProcessStreamMode)
    {
        hnd = HndNzProcessStreamMode;
    }
    return hnd;
}

//-----------------------------------------------------------------------
// VersionIsValid()
//-----------------------------------------------------------------------
bool PgDecode::VersionIsValid(tz_uint16 ver)
{
    bool rv = false;

    if( ver == CP_VERSION_3 || ver == CP_VERSION_2 )
    {
        rv = true;
    }
    return rv;
}

//-----------------------------------------------------------------------
// Auth2String()
//-----------------------------------------------------------------------
char *PgDecode::Auth2String(tz_uint32 type)
{
    char * stg;

    switch( type )
    {
    _CASE_(AUTH_REQ_OK)
        break;
    _CASE_(AUTH_REQ_KRB4)
        break;
    _CASE_(AUTH_REQ_KRB5)
        break;
    _CASE_(AUTH_REQ_PASSWORD)
        break;
    _CASE_(AUTH_REQ_CRYPT)
        break;
    _CASE_(AUTH_REQ_MD5)
        break;
    default:
        stg = "AUTH_REQ_UNKNOWN";
        break;
    }
    return stg;
}

//-----------------------------------------------------------------------
// State2String()
//-----------------------------------------------------------------------
char *PgDecode::State2String(SessionEntry *se)
{
    PgHandlerType currHnd = IdentifyHandler(se);
    char * stg;

    switch(currHnd)
    {
    _CASE_(HndNzProcessQuery)
        break;
    _CASE_(HndNzProcessQueryCont)
        break;
    _CASE_(HndProcessSync)
        break;
    _CASE_(HndNzProcessLoadUnload)
        break;
    _CASE_(HndNzProcessNullSsn)
        break;
    _CASE_(HndNzProcessAuth)
        break;
    _CASE_(HndNzProcessHandshake)
        break;
    _CASE_(HndNzProcessResync)
        break;
    _CASE_(HndNzProcessResyncCont)
        break;
    _CASE_(HndNzProcessStreamMode)
        break;
    default:
        stg = "HndNzUnknown";
        break;
    }

    return stg;
}

//-----------------------------------------------------------------------
// ClientType2String()
//-----------------------------------------------------------------------
char *PgDecode::ClientType2String(tz_uint32 type)
{
    char * stg;

    switch( type )
    {
    _CASE_(CLIENT_TYPE_LIBPQ)
        break;
    _CASE_(CLIENT_TYPE_ODBC)
        break;
    _CASE_(CLIENT_TYPE_JDBC)
        break;
    _CASE_(CLIENT_TYPE_CLI)
        break;
    _CASE_(CLIENT_TYPE_NZLOAD)
        break;
    _CASE_(CLIENT_TYPE_NZBACKUP)
        break;
    _CASE_(CLIENT_TYPE_NZRESTORE)
        break;
    default:
        stg = "CLIENT_TYPE_UNKNOWN";
        break;
    }
    return stg;
}

//-----------------------------------------------------------------------
// DumpPkt()
//     Dump a packet buffer to a file whose name indicates which
//     session, packet number, and client/server direction
//-----------------------------------------------------------------------
void PgDecode::DumpPkt( SessionEntry *se, tz_int8 *data, tz_uint32 length )
{
    tz_int8   *dbgData;
    tz_uint32  dataLenRead;
    PgInfo    *pgInfo = (PgInfo *)se->appInfo;
    tz_int8    fname[32];

    sprintf( fname, "/var/log/pgbuf-%u.%u.%c",
                                    (unsigned)pgInfo->sessionIdNum,
                                    (unsigned)pgInfo->pktCount,
                                    se->trafficDirection == TRAFFIC_FROM_CLIENT 
                                        ? 'c' : 's');

    FILE      *logfile = fopen( fname, "w" );

    if(data == NULL) {
        dataLenRead = pgInfo->ssnBuf->SbRecvBlock(&dbgData);
    } else {
        dbgData     = data;
        dataLenRead = length;
    }

    fwrite( dbgData, sizeof(tz_int8), dataLenRead, logfile );

    if(data == NULL) {
        pgInfo->ssnBuf->SbReturn(&dbgData, dataLenRead);
    }

    fclose( logfile );
}


//-----------------------------------------------------------------------
// TrapUnknown()
//-----------------------------------------------------------------------
void PgDecode::TrapUnknown(tz_uint8 opcode)
{
    //TZ_ASSERT(false,"PgDecode UNKNOWN OPCODE 0x%x (%c)\n", 
    //                                              opcode, opcode);
}

//-----------------------------------------------------------------------
// TrapUnderflow()
//-----------------------------------------------------------------------
void PgDecode::TrapUnderflow()
{
    //TZ_ASSERT(false,"PgDecode UNDERFLOW\n");
}

//======================================================================
// SQL Buffer Manager
//======================================================================
//
// This is an interface to hide the details of how we store SQL strings
// when received.  This may be in a single packet or it may be in
// multiple TCP segments

//-----------------------------------------------------------------------
// pgSqlBufMgrInit()
//     Initialize the Buffer Manager.  Call this upon successful login.
//-----------------------------------------------------------------------
void PgDecode::pgSqlBufMgrInit( SessionEntry *se )
{
    PgInfo *pgInfo = (PgInfo *)se->appInfo;

    pgInfo->bufMgrBufCount = 0;
    pgInfo->bufMgrHead     = NULL;
    pgInfo->bufMgrTail     = NULL;
}

//-----------------------------------------------------------------------
// pgSqlBufMgrAlloc()
//   Allocate a buffer of size PGSQL_BUFMGR_BUFSIZE.  As this function
//   is called, buffers are linked together.
//
//   The client is responsible for filling in "buf" with data
//
// in:
//     sessionEntry, len
// out:
//     buf, ptr to allocated memory
// returns:
//     IIMS_SUCCESS - "buf" of length "len" is available
//     IIMS_FAILURE - allocation failed or length is invalid
//-----------------------------------------------------------------------
tz_uint32 PgDecode::pgSqlBufMgrAlloc( SessionEntry *se,
                                      tz_uint32     len,
                                      tz_int8     **buf )
{
    tz_uint32 status = IIMS_SUCCESS;
    PgInfo *pgInfo   = (PgInfo *)se->appInfo;
    PgSqlDataBuf  *pgSqlDataBuf;

    do
    {
        // Check if request is reasonable.
        if( len > PGSQL_BUFMGR_MAX_LEN ) {
            status = IIMS_FAILURE;
            *buf = NULL;
            break;
        }

        pgSqlDataBuf = (PgSqlDataBuf *)calloc( 1, PGSQL_BUFMGR_BUFSIZE);

        if( !pgSqlDataBuf ) {
            status = IIMS_FAILURE;
            *buf = NULL;
            break;
        }

        // Format the new buffer
        pgSqlDataBuf->len = len;
        pgSqlDataBuf->next = NULL;

        // D E B U G
        //volatile tz_uint32 whacko = sizeof(pgSqlDataBuf);

        if( pgInfo->bufMgrBufCount == 0 )
        {
            pgInfo->bufMgrHead = pgSqlDataBuf;
            pgInfo->bufMgrTail = pgInfo->bufMgrHead;
        } else {
            pgInfo->bufMgrTail->next = pgSqlDataBuf;
            pgInfo->bufMgrTail = pgSqlDataBuf;
        }
        ++pgInfo->bufMgrBufCount;

#ifdef NTZ_RUNTIME_TEST
        if(pgInfo->bufMgrBufCount > 100 )
        {
            TZ_ASSERT(false, "pgSqlBufMgrAlloc limit exceeded");
        }
#endif

        // D E B U G
        //printf("%lu \n", pgInfo->bufMgrBufCount);  fflush(stdout);

        if(pgInfo->bufMgrBufCount > decodeStats.sqlBufMaxBlocks)
        {
            decodeStats.sqlBufMaxBlocks = pgInfo->bufMgrBufCount;
        }

        // Here's the buffer
        *buf = pgSqlDataBuf->data;

    } while(0);

    return status;
}

//-----------------------------------------------------------------------
// pgSqlBufMgrFree()
//     Free buffers in the chain
//-----------------------------------------------------------------------
void PgDecode::pgSqlBufMgrFree( SessionEntry *se )
{
    PgInfo *pgInfo   = (PgInfo *)se->appInfo;
    PgSqlDataBuf  *thisBuf, *nextBuf;

    switch( pgInfo->bufMgrBufCount )
    {
    case 0:
        // There have been no allocations
        break;
    case 1:
        // Only the head has a buffer
        free( pgInfo->bufMgrHead );
        break;
    default:
        // There are a chain of buffers
        thisBuf = pgInfo->bufMgrHead;

        while( thisBuf )
        {
            nextBuf = thisBuf->next;
            free( thisBuf );
            thisBuf = nextBuf;
        }
        break;
    }
    pgInfo->bufMgrBufCount = 0;
}

//-----------------------------------------------------------------------
// SumDecodeStats()
//-----------------------------------------------------------------------
void PgDecode::SumDecodeStats( void *context)
{
    DecodeStats *stats = (DecodeStats *)context;
    int sslIndex;

    stats->sessionsNotLoggedIn  += decodeStats.sessionsNotLoggedIn;
    stats->sessionsLoggedIn     += decodeStats.sessionsLoggedIn;
    stats->sessionsHandshake    += decodeStats.sessionsHandshake;
    stats->sessionsAuth         += decodeStats.sessionsAuth;
    stats->sessionsSsl          += decodeStats.sessionsSsl;
    stats->totSessionsUnsecured += decodeStats.totSessionsUnsecured;
    stats->totSessionsSecured   += decodeStats.totSessionsSecured;
    stats->totSessionsIgnored   += decodeStats.totSessionsIgnored;
    stats->totSessionsNull      += decodeStats.totSessionsNull;
    stats->unknownCodepoints    += decodeStats.unknownCodepoints;
    stats->tcpHoles             += decodeStats.tcpHoles;
    stats->eventsPartial        += decodeStats.eventsPartial;
    stats->syncLost             += decodeStats.syncLost;
    stats->syncResyncSuccess    += decodeStats.syncResyncSuccess;
    for (sslIndex = 0; sslIndex < TTAS_ENUM_COUNT; sslIndex++)
        stats->sslErrors[sslIndex] += decodeStats.sslErrors[sslIndex];
    if( stats->ssnBufMaxBlocks < decodeStats.ssnBufMaxBlocks ) {
        stats->ssnBufMaxBlocks = decodeStats.ssnBufMaxBlocks;
    }
    if( stats->sqlBufMaxBlocks < decodeStats.sqlBufMaxBlocks ) {
        stats->sqlBufMaxBlocks = decodeStats.sqlBufMaxBlocks;
    }
}

//-----------------------------------------------------------------------
// PgIteratorSumStats()
//     Callback function to accumulate stats from each of the
//     PgDecode objects.
//-----------------------------------------------------------------------
void PgIteratorSumStats (void *object, void *context)
{
    PgDecode *pgDecode = (PgDecode *)object;

    pgDecode->SumDecodeStats (context);
}

//-----------------------------------------------------------------------
// GenerateDump()
//     Produce a text string which dumps the current state of 
//     interesting decoder variables
//-----------------------------------------------------------------------
tz_int8 *PgDecode::GenerateDump( void )
{
  tz_int8      *output;
  DecodeStats   decodeStatsSum;
  NetMonDriver *nmd = TZ_layerManager->netMonDriver;

  memset (&decodeStatsSum, 0, sizeof(DecodeStats));
  nmd->NetmonThreadIterate (PROTOCOL_NETEZZA,
                            PgIteratorSumStats, 
                            &decodeStatsSum);

  output = smprintf("Netezza Postgres Debug Stats\n"
                    "   sessionsNotLoggedIn:   %lu\n"
                    "   sessionsLoggedIn:      %lu\n"
                    "   sessionsHandshake:     %lu\n"
                    "   sessionsAuth:          %lu\n"
                    "   sessionsSsl:           %lu\n"
                    "   totSessionsUnsecured:  %lu\n"
                    "   totSessionsSecured:    %lu\n"
                    "   totSessionsIgnored:    %lu\n"
                    "   totSessionsNull:       %lu\n"
                    "   unknownCodepoints:     %lu\n"
                    "   tcpHoles:              %lu\n"
                    "   eventsPartial:         %lu\n"
                    "   ssnBufMaxBlocks:       %lu\n"
                    "   sqlBufMaxBlocks:       %lu\n"
                    "   syncLost:              %lu\n"
                    "   syncResyncSuccess:     %lu\n"
                    "   sslUnexpectedEoh:      %lu\n"
                    "   sslPubKeyMisMatch:     %lu\n"
                    "   sslRsaDecryptError:    %lu\n"
                    "   sslSymDecryptError:    %lu\n"
                    "   sslMACError:           %lu\n"
                    "   sslVersionUnsupported: %lu\n"
                    "   sslCipherUnsupported:  %lu\n"
                    "   sslCertDecode:         %lu\n"
                    "   sslCertUnmatched:      %lu\n"
                    "   sslFatal:              %lu\n"
                    "   sslHeapFailed:         %lu\n"
                    "   sslSyncFailure:        %lu\n",
                    decodeStatsSum.sessionsNotLoggedIn,
                    decodeStatsSum.sessionsLoggedIn,
                    decodeStatsSum.sessionsHandshake,
                    decodeStatsSum.sessionsAuth,
                    decodeStatsSum.sessionsSsl,
                    decodeStatsSum.totSessionsUnsecured,
                    decodeStatsSum.totSessionsSecured,
                    decodeStatsSum.totSessionsIgnored,
                    decodeStatsSum.totSessionsNull,
                    decodeStatsSum.unknownCodepoints,
                    decodeStatsSum.tcpHoles,
                    decodeStatsSum.eventsPartial,
                    decodeStatsSum.ssnBufMaxBlocks,
                    decodeStatsSum.sqlBufMaxBlocks,
                    decodeStatsSum.syncLost,
                    decodeStatsSum.syncResyncSuccess,
                    decodeStatsSum.sslErrors[TTAS_UNEXPECTED_EOH],
                    decodeStatsSum.sslErrors[TTAS_PUB_KEY_MISMATCH],
                    decodeStatsSum.sslErrors[TTAS_RSA_DECODE_ERROR],
                    decodeStatsSum.sslErrors[TTAS_SYM_DECODE_ERROR],
                    decodeStatsSum.sslErrors[TTAS_HASH_ERROR],
                    decodeStatsSum.sslErrors[TTAS_VERSION_UNSUPPORTED_ERROR],
                    decodeStatsSum.sslErrors[TTAS_CIPHERSPEC_UNSUPPORTED],
                    decodeStatsSum.sslErrors[TTAS_CERT_DECODE_ERROR],
                    decodeStatsSum.sslErrors[TTAS_CERT_NO_MATCH],
                    decodeStatsSum.sslErrors[TTAS_FATAL],
                    decodeStatsSum.sslErrors[TTAS_HEAP],
                    decodeStatsSum.sslErrors[TTAS_SYNC] );

  return output;
}

//-----------------------------------------------------------------------
// ShowNetmonDebugNz()
//     Debug command interface
//     show netmon debug "nz <cmd>"
//-----------------------------------------------------------------------
char *PgDecode::ShowNetmonDebugNz(const char *substring)
{
    const char *cmdPtr = substring;
    char *rsp = NULL;

    do
    {
        if( *cmdPtr == ' ' )  ++cmdPtr;

        // decode - print codepoint listing to stdout when enabled.
        //          This assumes that TZ_NETMON_THREAD_COUNT is set for
        //          1.  Otherwise, multi thread stdout gets intermixed.
        if( !strncmp(cmdPtr, "decode", strlen("decode")) )
        {
            cmdPtr += strlen("decode");
            if( *cmdPtr == ' ' )  ++cmdPtr;

            if( !strncmp(cmdPtr, "0", strlen("0")) )
            {
                rsp = strdup("nz decode off");
                dbgLvl0 = dbgLvl1 = false;
            }
            else if( !strncmp(cmdPtr, "1", strlen("1")) )
            {
                rsp = strdup("nz decode on (level 1)");
                dbgLvl0 = true;  dbgLvl1 = false;
            }
            else if( !strncmp(cmdPtr, "2", strlen("2")) )
            {
                rsp = strdup("nz decode on (level 2)");
                dbgLvl0 = true;  dbgLvl1 = true;
            }
            else
            {
                rsp = strdup("nz decode [0 | 1 | 2]");
                break;
            }
        }

        // dump - for each session, write packet contents as seen by the
        //        decoder to a file.  The pkt-convert utility can then
        //        be run to assemble a hex dump listing
        if( !strncmp(cmdPtr, "dump", strlen("dump")) )
        {
            cmdPtr += strlen("dump");
            if( *cmdPtr == ' ' )  ++cmdPtr;

            if( !strncmp(cmdPtr, "0", strlen("0")) )
            {
                rsp = strdup("nz dump off");
                dbgDump = false;
            }
            else if( !strncmp(cmdPtr, "1", strlen("1")) )
            {
                rsp = strdup("nz dump on");
                dbgDump = true;
            }
            else
            {
                rsp = strdup("nz dump [0 | 1]");
                break;
            }
        }

    } while (0);

    return rsp;
}

//-----------------------------------------------------------------------
// CreateProtocolData()
//     Currently the discipline is such that filter (the driver)
//     requests the protocol to allocate its own state data.  Filter
//     stores it in sessionEntry->appInfo.
//-----------------------------------------------------------------------
PgInfo *PgDecode::CreateProtocolData( SessionEntry *se )
{
    PgInfo *pgInfo;
    pgInfo = (PgInfo *)calloc( 1, sizeof(PgInfo) );

    if(pgInfo != NULL)
    {
        // FIX: Need all other initialization here...

        // SessionDetail will be allocated when it becomes clear that a
        // client connection is probable
        pgInfo->sd = NULL;

        pgInfo->ssnBuf = new SsnBuf();

        pgInfo->ssnBuf->SbInit();

        pgInfo->handler = &PgDecode::ProcessSync;
        pgInfo->sessionIdNum = sessionIdNum++;

        // Stats - not yet a session
        ++decodeStats.sessionsNotLoggedIn;

        // NzStreamMode counters
        pgInfo->streamModeTotExpected = pgInfo->streamModeTotRemaining = 0;
        pgInfo->streamModeCodepoint = 0;

        // Create the Content Scanners and start them
        pgInfo->clientCs = new ContentScanner( cmdDataPatMgr );
        pgInfo->serverCs = new ContentScanner( rspDataPatMgr );

        if( cmdDataPatMgr->CSEnabled() == true )
        {
            pgInfo->clientCs->StartScan(se->workerIdx);
        }
        if( rspDataPatMgr->CSEnabled() == true )
        {
            pgInfo->serverCs->StartScan(se->workerIdx);
        }
    }

    return pgInfo;
}

//-----------------------------------------------------------------------
// DeleteProtocolData()
//     The current discipline is for the filter (the driver) to call
//     in here so that the protocol can deallocate all data structures
//     it has privately been maintaining.  The filter will then itself
//     free appInfo (sessionEntry->appInfo)
//-----------------------------------------------------------------------
void PgDecode::DeleteProtocolData( SessionEntry *se )
{
    PgInfo *pgInfo = (PgInfo *)se->appInfo;

    // FIX: Need all other cleanup here...

    pgSqlBufMgrFree(se);

    delete pgInfo->ssnBuf;

    // Delete the Content Scanners
    if( pgInfo->clientCs )
    {
        if( pgInfo->clientCs->IsActive() )
        {
            pgInfo->clientCs->StopScan( CommandDataType,
                                        se->workerIdx );
        }
        delete pgInfo->clientCs;
    }

    if( pgInfo->serverCs )
    {
        if( pgInfo->serverCs->IsActive() )
        {
            pgInfo->serverCs->StopScan( ResponseDataType,
                                        se->workerIdx );
        }
        delete pgInfo->serverCs;
    }

    // Stats - account for session accordingly
    if(se->sessionDetail)
    {
        if(se->sessionDetail->loginEventIssued) {
            --decodeStats.sessionsLoggedIn;
        } else {
            --decodeStats.sessionsNotLoggedIn;
        }
    }
    else
    {
        // Never saw login (or even a version header) so just eliminate
        // the session from stats counters
        --decodeStats.sessionsNotLoggedIn;
    }

    // If this was a stuck-in-Handshake or stuck-in-Auth session, remove it
    if(pgInfo->handler == &PgDecode::NzProcessHandshake)
    {
        --decodeStats.sessionsHandshake;
    }
    if(pgInfo->handler == &PgDecode::NzProcessAuth)
    {
        --decodeStats.sessionsAuth;
    }

    // Note: Client frees pgInfo
}

//-----------------------------------------------------------------------
// CreateSessionDetail()
//     A decoder calls in here to allocate a new sessionDetail structure.
//     Typically it will do this when it acquires the first session
//     related data it needs to store.  (for example, when it discovers
//     serverUser, hostUser, programName, etc.)  It then builds the
//     sessionDetail structure in preparation for sending up the first
//     event on the session (at which time this data will all be latched).
//
// Note:  This code was lifted fron netmon2 development.  If/when the
//        threaded event stack is implemented, this function will be
//        offered by the Event class.
//-----------------------------------------------------------------------
SessionDetail *PgDecode::CreateSessionDetail(SessionEntry *sessionEntry)
{
    SessionDetail *sd = (SessionDetail *)calloc(1, sizeof(SessionDetail));

    if( sd == NULL )
    {
        sessionEntry->badSession = 1;
    }
    else
    {
        // FIX
        sd->serverApplication = PROTOCOL_NETEZZA;

        sd->serverType = SERVER_DATABASE;

        // (netmon2 note: loginEventIssued is initialized to false)
    }

    // Capture the new sessionDetail (or NULL)
    sessionEntry->sessionDetail = sd;

    return sd;
}

//------------------------------------------------------------------------
// CopyDimString()
//
// Note:  This code was lifted fron netmon2 development.  If/when the
//        threaded event stack is implemented, this function will be
//        offered by the Event class.
//------------------------------------------------------------------------
tz_uint32 PgDecode::CopyDimString(tz_int8 *dst, tz_int8 *src, tz_uint32 max)
{
    tz_uint32 safeLen = MIN(max - 1, strlen(src) + 1);
    memcpy(dst, src, safeLen);

    // Ensure termination (if necessary)
    if(safeLen == max - 1)
    {
        dst[safeLen] = '\0';
    }
    return safeLen;
}

//--------------------------------------------------------------------
// NormalizeString()
//     Transform a character string in-place with the following
//     changes:
//
//     - Convert a lower case ASCII characters to upper.
//     - If present, strip any double quotes surrounding the string.
//       If double quotes are present elsewhere in the string ignore
//       them.
//--------------------------------------------------------------------
void PgDecode::NormalizeString(tz_int8 *stg)
{
    tz_uint32 stgLen = strlen(stg);
    tz_uint32 oldIdx, newIdx;

    oldIdx = newIdx = 0;

    // Leading '"' is removed
    if( stg[oldIdx] == '"' )  ++oldIdx ;

    for( ; oldIdx < stgLen; ++oldIdx, ++newIdx)
    {
        if(    stg[oldIdx] == '"'
            && oldIdx == stgLen - 1 )
        {
            // Trailing '"' is nulled out
            stg[newIdx] = '\0';
        }
        else
        {
            stg[newIdx] = toupper(stg[oldIdx]);
        }
    }
}

//-----------------------------------------------------------------------
// PrepareEvent()
//-----------------------------------------------------------------------
void PgDecode::PrepareEvent( SessionEntry *sessionEntry )
{
    PgInfo          *pgInfo       = (PgInfo *)sessionEntry->appInfo;
    PgSqlDataBuf    *thisBuf, *nextBuf;
    tz_int8         *stmt         = NULL;
    tz_uint32        stmtLen      = 0;
    DimValListEntry *lastEntry, *newEntry;
    DimValListEntry *sizeDVLE     = NULL;
    DimValListEntry *respDVLE     = NULL;
    DimValListEntry *cmdDataDVLE  = NULL;
    DimValListEntry *respDataDVLE = NULL;

    // Parser call
    int                      parseStatus;
    sql_stmt_desc_t         *currSqlStmt, *nextSqlStmt;
    struct sql_batch_desc_t  sqlStmtEncaps;
    DimValListEntry         *contDVLE;
    DimValListEntry         *operDVLE;


    // Create the contiguous buffer for parser operations
    if( pgInfo->bufMgrBufCount == 0 )
    {
        // Codepoints with no SQL text.

        // FIX: what do we do here?
    }
    else if( pgInfo->bufMgrBufCount == 1 )
    {
        // Single buffer SQL text.  We will send the BufMgr buffer
        // directly into the parser
        stmt    = pgInfo->bufMgrHead->data;
        stmtLen = pgInfo->bufMgrHead->len;
        Dprint("\n%s\n", stmt);
    }
    else
    {
        // We have chained buffers so determine how large the buffer
        // should be and then allocate it.
        thisBuf = pgInfo->bufMgrHead;

        while( thisBuf ) {
            stmtLen += thisBuf->len;
            thisBuf = thisBuf->next;
        }

        stmt = (tz_int8 *)calloc(1, stmtLen + 1 );

        if(stmt == NULL)
        {
            stmtLen = 0;
            lc_log_basic(LOG_WARNING,"Postgres decoder error: PrepareEvent alloc 1");
        }
        else
        {
            // We will then copy in the contents of each buffer.  The 
            // contiguous string is presented to the parser.
            tz_uint32 bufIdx = 0;
            while( thisBuf )
            {
                memcpy( &stmt[bufIdx], thisBuf->data, thisBuf->len );
                bufIdx += thisBuf->len;
                thisBuf = thisBuf->next;
            }
            Dprint("\n%s\n", stmt);
        }
    }

    // Command.data (Content Scan)
    if( cmdDataPatMgr->CSEnabled() == true )
    {
        tz_uint32 cmdDataMatch = pgInfo->clientCs->GetTotalMatchCount();

        if( cmdDataMatch )
        {
            Dprint("cmdData %lu\n", cmdDataMatch);
        }

        // Stop the scan to acquire results then restart
        cmdDataDVLE = pgInfo->clientCs->StopScan( CommandDataType,
                                                  sessionEntry->workerIdx );
        pgInfo->clientCs->StartScan( sessionEntry->workerIdx );
    }

    // Response.data (Content Scan)
    if( rspDataPatMgr->CSEnabled() == true )
    {
        tz_uint32 rspDataMatch = pgInfo->serverCs->GetTotalMatchCount();

        if( rspDataMatch )
        {
            Dprint("rspData %lu\n", rspDataMatch);
        }

        // Stop the scan to acquire results then restart
        respDataDVLE = pgInfo->serverCs->StopScan( ResponseDataType,
                                                   sessionEntry->workerIdx );
        pgInfo->serverCs->StartScan( sessionEntry->workerIdx );
    }

    // If NULL Server.user, fill in something like "USER_192.168.1.1"
    if( pgInfo->sd->serverInfo[0] == '\0' )
    {
        struct in_addr srcAddr;
        srcAddr.s_addr = sessionEntry->clientIsDst ?
                         sessionEntry->addressTuple.dst :
                         sessionEntry->addressTuple.src;

        strcpy( pgInfo->sd->serverUser, "USER_" );
        strcat( pgInfo->sd->serverUser, inet_ntoa(srcAddr) );
    }

    // Here we go, call into the parser
    sqlStmtEncaps.listHead  = NULL;
    sqlStmtEncaps.stmtCount = 0;

    //NzSqlConnInit(&pgInfo->connState);

    parseStatus = NzSqlParse( &sqlStmtEncaps,      // output, linked list
                              &pgInfo->connState,  // state
                              (tz_uint8 *)stmt,    // input SQL text buffer
                              stmtLen);            // input SQL text bufLen

    if(parseStatus)
    {
        lc_log_basic(LOG_WARNING,"Postgres decoder error: Parse FAIL");
    }

    // The parser may return one event or more than one event if the
    // SQL string is a compound like this:
    // "select * from ad_event_1000 limit 100; select * from ad limit 100"
    // Since IncomingTransaction() frees all DVLEs that are allocated
    // here, care is taken to prevent a reused DVLE and a double free
    for( currSqlStmt = sqlStmtEncaps.listHead;
         currSqlStmt;
         currSqlStmt = currSqlStmt->next )
    {
        // Size.rows dimension
        sizeDVLE = NULL;

        if( pgInfo->evtRespRows )
        {
            newEntry = (DimValListEntry *)
                            calloc( 1, sizeof(DimValListEntry) );
            if(newEntry == NULL)
            {
                lc_log_basic(LOG_WARNING,"Postgres decoder error: PrepareEvent alloc 2");
            }
            else
            {
                newEntry->type = TZX_SIZE_ROWS;
                newEntry->numericalValue = pgInfo->evtRespRows;
                newEntry->next = NULL;

                // Append to end of list
                if( sizeDVLE == NULL ) {
                    sizeDVLE = newEntry;
                } else {
                    lastEntry = sizeDVLE;
                    while( lastEntry->next ) {
                        lastEntry = lastEntry->next;
                    }
                    lastEntry->next = newEntry;
                }
            }
        }

        // Size.bytes dimension
        if( pgInfo->evtRespBytes )
        {
            newEntry = (DimValListEntry *)
                            calloc( 1, sizeof(DimValListEntry) );
            if(newEntry == NULL)
            {
                lc_log_basic(LOG_WARNING,"Postgres decoder error: PrepareEvent alloc 3");
            }
            else
            {
                newEntry->type = TZX_SIZE_BYTES;
                newEntry->numericalValue = pgInfo->evtRespBytes;
                newEntry->next = NULL;

                // Append to end of list
                if( sizeDVLE == NULL ) {
                    sizeDVLE = newEntry;
                } else {
                    lastEntry = sizeDVLE;
                    while( lastEntry->next ) {
                        lastEntry = lastEntry->next;
                    }
                    lastEntry->next = newEntry;
                }
            }
        }

        // Response.status
        respDVLE = (DimValListEntry *)
                            calloc( 1, sizeof(DimValListEntry) );
        if(respDVLE == NULL)
        {
            lc_log_basic(LOG_WARNING,"Postgres decoder error: PrepareEvent alloc 4");
        }
        else
        {
            respDVLE->type = TZX_RESPONSE_STATUS;
            respDVLE->numericalValue = pgInfo->evtStatus.evtRespStatus;
            respDVLE->next = NULL;
        }

        // cmdData and rspData DVLEs are valid on the first event for
        // compound SQL statements.  For subsequent events we set them
        // NULL because IncomingTransaction() freed them on the first event.
        if(currSqlStmt != sqlStmtEncaps.listHead)
        {
            cmdDataDVLE = respDataDVLE = NULL;
        }

        // Note that InjectEvent() clones the commandStg parameter
        // because it is freed with each call to IncomingTransaction()

        // A complete event means both client SQL request and server
        // response were seen.  If that was the case but a parser error
        // was encountered then it's also considered "partial"
        bool isCompleteEvt =     pgInfo->evtStatus.evtIsComplete
                             && !currSqlStmt->parseError;

        InjectEvent(sessionEntry,
                    currSqlStmt->contentList,     // contentListEntry,
                    currSqlStmt->operationList,   // operationListEntry,
                    cmdDataDVLE,                  // commandDataListEntry,
                    respDataDVLE,                 // responseDataListEntry,
                    respDVLE,                     // responseEntry,
                    sizeDVLE,                     // sizeEntry,
                    (tz_int8 *)currSqlStmt->stmt, // commandStg,
                    isCompleteEvt,                // isCompleteEvt,
                    true                          // loginIsSuccess
                    );
    }

    // Clean up parser allocations where necessary.
    // Note - if the parser didn't parse anything, listHead will be NULL
    currSqlStmt = sqlStmtEncaps.listHead;

    while( currSqlStmt )
    {

#if 0
        // Ordinarily CleanEventDetail() does this cleanup but if it
        // was not called we must clean up here
        if( status == IIMS_FAILURE )
        {
            if( currSqlStmt->operationList )
            {
                freeVector( currSqlStmt->operationList );
            }
            if( currSqlStmt->contentList )
            {
                freeVector( currSqlStmt->contentList );
            }
        }
#endif

        // Always clean up parser allocations
        nextSqlStmt = currSqlStmt->next;
        free( currSqlStmt );
        currSqlStmt = nextSqlStmt;
    }

    // Free the parser contiguous memory (when bufMgrBufCount > 1)
    if( pgInfo->bufMgrBufCount > 1 && stmt )
    {
        free( stmt );
    }

    // Clean up the SQL buffer chain
    pgSqlBufMgrFree(sessionEntry);

    // Reinitialize the SQL buffer
    pgSqlBufMgrInit(sessionEntry);

    // Make note for multi termination sequences (e.g. 'E' then 'Z')
    pgInfo->evtStatus.evtIsIssued  = true;
}

//-----------------------------------------------------------------------
// InjectEvent()
//
//     ENCENGINE_EVENT_NORMAL events
//
// In:
//     All parameters are pointers to memory allocated by a decoder and
//     the memory will be freed by Event over the course of
//     the processing of this event
//
//     sessionDetail member of sessionEntry is allocated and properly
//     formatted
//
//     isCompleteEvt (versus Partial Event)
//
// Note:  This code was lifted fron netmon2 development.  If/when the
//        threaded event stack is implemented, this function will be
//        offered by the Event class.
//
//-----------------------------------------------------------------------
void PgDecode::InjectEvent ( SessionEntry    *sessionEntry,
                             DimValListEntry *contentListEntry,
                             DimValListEntry *operationListEntry,
                             DimValListEntry *commandDataListEntry,
                             DimValListEntry *responseDataListEntry,
                             DimValListEntry *responseEntry,
                             DimValListEntry *sizeEntry,
                             tz_int8         *commandStg,
                             tz_uint8         isCompleteEvt,
                             tz_uint8         loginIsSuccess)
{

    do
    {

        EncEngineEventType evtType;

        // Select the appropriate event type
        if(isCompleteEvt == false)
        {
            ++decodeStats.eventsPartial;
            evtType = ENCENGINE_EVENT_UNSUPPORTED;
        }
        else if(loginIsSuccess == false)
        {
            evtType = ENCENGINE_EVENT_FAILEDLOGIN;
        }
        else
        {
            evtType = ENCENGINE_EVENT_NORMAL;
        }

        // Clone the command string because the EncodingEngine takes the
        // liberty of freeing it.
        const char *cmdStg = (const char *)commandStg;
        tz_int8 *tmpCmdStg = (tz_int8 *)calloc(1, strlen(cmdStg) +1 );

        if( !tmpCmdStg )
        {
            lc_log_basic(LOG_WARNING,"Postgres decoder error: command string alloc");

            // The caller is counting on IncomingTransaction() to free 
            // DVLEs which is not going to happen so act now.
            // (For netmon.2 these will be freeVector() calls)
            encEng->CleanVector(&contentListEntry);
            encEng->CleanVector(&operationListEntry);
            encEng->CleanVector(&commandDataListEntry);
            encEng->CleanVector(&responseDataListEntry);
            encEng->CleanVector(&responseEntry);
            encEng->CleanVector(&sizeEntry);
            break;
        }

        memcpy( tmpCmdStg, cmdStg, strlen(cmdStg) +1 );

        bool loginStatePre = sessionEntry->sessionDetail->loginEventIssued;

        encEng->IncomingTransaction( sessionEntry,
                                     contentListEntry,      // content
                                     operationListEntry,    // operation
                                     commandDataListEntry,  // command.data content scan
                                     responseDataListEntry, // response.data content scan
                                     responseEntry,         // response
                                     sizeEntry,             // size
                                     evtType,
                                     tmpCmdStg );           // command (freed!)

        if(    !loginStatePre 
            && sessionEntry->sessionDetail
            && sessionEntry->sessionDetail->loginEventIssued )
        {
            // D E B U G
            //PgInfo *pgInfo     = (PgInfo *)sessionEntry->appInfo;
            //printf("ssn %lu\n", pgInfo->sessionIdNum);  fflush(stdout);

            // Stats - count this as a logged in session
            --decodeStats.sessionsNotLoggedIn;
            ++decodeStats.sessionsLoggedIn;
        }

    } while (0);
}

//------------------------------------------------------------------------
// InjectFailedLogin()
//
// In:
//     sessionDetail member of sessionEntry is allocated and properly
//     formatted
//
// Note:  This code was lifted fron netmon2 development.  If/when the
//        threaded event stack is implemented, this function will be
//        offered by the Event class.
//------------------------------------------------------------------------
void PgDecode::InjectFailedLogin( SessionEntry *sessionEntry,
                                  tz_int8      *command)
{
}

//-----------------------------------------------------------------------
// PgDecode()
//-----------------------------------------------------------------------
PgDecode::PgDecode(NetMonDriver *nmd, EncodingEngine *ee)
{
    netMonDriver = nmd;
    encEng       = ee;

    // SessionId for debugging
    sessionIdNum = 0;

    // Statistics counters
    memset( &decodeStats, 0, sizeof(struct DecodeStats) );

    // Obtain the Pattern Manager
    rspDataPatMgr = netMonDriver->rspDataPatMgr[PROTOCOL_NETEZZA];
    cmdDataPatMgr = netMonDriver->cmdDataPatMgr[PROTOCOL_NETEZZA];

    dbgLvl0 = dbgLvl1 = dbgDump = false;

    // For development, read shell variables to set debug options.
    // Yes this gets executed for each instance of of PgDecode but so what.
    // The answer will always be the same.
    char *envDecode = getenv( "TZ_NETMON_NZ_DECODE" );
    if( envDecode != NULL )
    {
        unsigned val;
        val = strtol( envDecode, NULL, 0 );
        if(val == 2) {
            dbgLvl0 = dbgLvl1 = true;
        } else if( val == 1) {
            dbgLvl0 = true;
        }
        // else, both retain false values set above
    }

    char *envDump = getenv( "TZ_NETMON_NZ_DUMP" );
    if( envDump != NULL )
    {
        unsigned val;
        val = strtol( envDump, NULL, 0 );
        if( val == 1) {
            dbgDump = true;
        }
        // else, dbgDump retains false value set above
    }
}

//-----------------------------------------------------------------------
// ~PgDecode()
//-----------------------------------------------------------------------
PgDecode::~PgDecode()
{

}


