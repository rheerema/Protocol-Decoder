//-----------------------------------------------------------------------
//   Copyright (c) <2005> by Tizor Systems. 
//   All Rights Reserved.
//   Licensed Material - Property of Tizor Systems.
//
//   File: smb.cc
// 
//   Component: SMB protocol processing
//
//-----------------------------------------------------------------------

#include <stddef.h>        // offsetof()
#include <tizor_types.h>
#include <consoleLogger.h>
#include <logging.h>       // syslog facility

extern "C"
{
// netmon_types.h is extern C for the benefit of tz_watch.h linkage
#include <netmon/netmon_types.h>

#include <util/tz_assert.h>
}
#include <netmon/packetLog.hh>
#include <netmon/layerManager.hh>

#include <arpa/inet.h>

#include <contentScanner/patternManager.hh>
#include <contentScanner/contentScanner.hh>

#include <util/tz_string.h>
#include <netmon/smb.h>
#include <netmon/smbNtStatus.h>
#include <netmon/smbEncEngFormat.hh>



// Note on SMB_DEBUG_MODE_2, output format is:
//
//    command                        uid   pid   mid   tid
//    -----------------------------  ----  ----  ----  ----


// SMB byte order is Little Endian.  x86 byte order is Little Endian
// Therefore, the translation is NULL.  In the interest of portability,
// however, a translation layer will be added so that, God forbid, we
// port this code to a BE machine, all we'll have to do is update this
// translation layer.  It is done in the style of htonl, htons, ntohl,
// ntohs, etc.
//

inline tz_uint64 htosll( tz_uint64 val )
{
  return val;
}

inline tz_uint32 htosl( tz_uint32 val )
{
  return val;
}

inline tz_uint16 htoss( tz_uint16 val )
{
  return val;
}

inline tz_uint64 stohll( tz_uint64 val )
{
  return val;
}

inline tz_uint32 stohl( tz_uint32 val )
{
  return val;
}

inline tz_uint16 stohs( tz_uint16 val )
{
  return val;
}

// Macros for dereferencing a pointer to various data sizes
//
#define _U8(val)  (*((tz_uint8 *)(val)))
#define _U16(val) (*((tz_uint16 *)(val)))
#define _U32(val) (*((tz_uint32 *)(val)))
#define _U64(val) (*((tz_uint64 *)(val)))


tz_uint32 targetPkt;


//-----------------------------------------------------------------------
// smbProcess()
//-----------------------------------------------------------------------
tz_uint32 SmbDecode::smbProcess( SessionEntry *sessionEntry,
                                 const u_char *data, 
                                 tz_uint32     length,
                                 tz_uint32     tcpHole )
{
  tz_uint32      status = IIMS_SUCCESS;
  tz_uint32      passCnt = 0;
  SmbInfo       *smbInfo = (SmbInfo *)sessionEntry->appInfo;
  LargeCmdState *lcs;

#ifdef SMB_VALGRIND_TEST
    const u_char *dbgData = NULL;
    if( length )
    {
        dbgData = (const u_char *)malloc( length );
        memcpy( (void *)dbgData, data, length );
        data = dbgData;
    }
#endif

  do
  {
      // Check for configuration changes
      LmCfgSmb * lmCfgSmb = (LmCfgSmb *)
                netMonDriver->layerManager->LmCfgGetCurrData( LMCFG_SMB );
      if( lmCfgSmb->chgSeqNum != myLmCfg.chgSeqNum )
      {
          // Process the LM config
          smbLmCfgProcess( lmCfgSmb ); 

          // Accept the update
          myLmCfg.chgSeqNum = lmCfgSmb->chgSeqNum;
      }

      // If this is a zero-length packet then we will quit.  The driver
      // does send 0-length packets up.  If we don't quit here then we
      // might end up processing stale SMB data from a previously received
      // packet.  Not very wholesome.

      if( length == 0 )
      {
          break;
      }

      if( SmbDebug::logIsEnabled )
      {
          // Processed packet ID number (command or TCP continuation)
          ++processedPktNum;

#if 0
          // Break on a specific trace packet
          volatile tz_uint32 foo;
          if( processedPktNum == targetPkt ) {
              // set breakpoint here!
              ++foo;
          }
#endif
      }

      SmbDcdLog( sessionEntry,
          "----------------------------------------------------------");

      if( tcpHole )
      {
          ++decodeStats.tcpHole;
          SmbDcdLog( sessionEntry, "START   len %4d  HOLE  ", length  );
      }
      else
      {
          SmbDcdLog( sessionEntry, "START   len %4d        ", length );
      }

      // Debug simulation of unidirectional client traffic
#ifdef SMB_UNI_CLIENT
      if( sessionEntry->trafficDirection == TRAFFIC_FROM_SERVER )
      {
          // Throw away server side packets!
          break;
      }
#endif

      // Most packets received by this adapter are SMB frames encapsulated
      // in either a NetBIOS Session Service "Session Message" (0x00) or, 
      // in raw TCP transport mode, an equivalent 4-byte header with an 
      // 8-bit opcode of 0 (equivalent to Session Message) and a 24-bit length
      //  field.  A small percentage of packets received (from clients using
      // NetBIOS) are NBSS session establishment and maintenance packets.  
      // These are not explicitly handled by the decoder since they contain no
      // information deemed relevant to Tizor and because the industry is 
      // moving away from NetBIOS encapsulation in general.


      // Actual Processing

      // Select the request or response Large Command State descriptor
      if( sessionEntry->trafficDirection == TRAFFIC_FROM_CLIENT ) {
          lcs = &smbInfo->reqLcs;
      } else {
          lcs = &smbInfo->rspLcs;
      }

      // If there was a fragmented nbHeader or smbHeader at end of previous
      // segment, aggregate it with this segment
      if( lcs->isActive == false && lcs->fs.isActive == true )
      {
          // Append current data to frag from previous segment
          handleFragCont( sessionEntry, data, length );

          // For this segment we will reassign data and length to match
          // the reconstructed segment
          data = (const u_char *)lcs->fs.data;
          length = lcs->fs.len;
          SmbDcdLog( sessionEntry, "RESTART len %4d        ", length );

          // Frag State is over
          lcs->fs.isActive = false;
          lcs->fs.len      = 0;
      }

      // Init the packet processing length
      lcs->remainInPkt = length;
      passCnt  = 0;

      // If a hole has been encountered, we drop out of Large Command State
      if( tcpHole )
      {
          lcs->isActive = false;
          lcs->tcpSegOffset = 0;
          lcs->totExpected = 0;
          lcs->totReceived = 0;

          // No fragmentation is in process
          lcs->fs.isActive = false;
          lcs->fs.len      = 0;
      }

      do
      {
          smbDecodeCommand( sessionEntry, data, length, tcpHole);
          ++passCnt;

          TZ_ASSERT(lcs->remainInPkt <= length, "SMB remainInPkt out of range");

      } while( lcs->remainInPkt && lcs->isActive == false );

#ifdef SMB_VALGRIND_TEST
    if( dbgData )
    {
        free( (void *)dbgData );
    }
#endif

#ifdef SMB_DECODE_LOG
      if( passCnt > 1)
      {
          SmbDcdLog( sessionEntry,"MULTI   %d", passCnt);
      }
#endif

  } while (0);

  return status;
}

//-----------------------------------------------------------------------
// smbDecodeCommand()
//     Decode a packet buffer containing an SMB command.
//-----------------------------------------------------------------------
void SmbDecode::smbDecodeCommand( SessionEntry *sessionEntry,
                                  const u_char *data, 
                                  tz_uint32     length,
                                  tz_uint32     tcpHole )
{
  NBHeader    *nbHeader;
  NBHeaderRaw *nbHeaderRaw;
  SmbHeader   *smbHeader;

  nbHeader = (NBHeader *)data;
  nbHeaderRaw = (NBHeaderRaw *)data;
  smbHeader = (SmbHeader *)(data + sizeof(NBHeader));

  SmbInfo       *smbInfo = (SmbInfo *)sessionEntry->appInfo;
  LargeCmdState *lcs;

#if 0
  // D E B U G
  NBHeader nbh = *nbHeader;
  SmbHeader sh = *smbHeader;
#endif

#if 0
  // D E B U G
  tz_uint8 peek[256];
  tz_uint32 cpLen;
  cpLen = length > 256 ? 256 : length;
  memcpy( peek, data, cpLen );
#endif


  do
  {
      // Select the request or response Large Command State descriptor
      if( sessionEntry->trafficDirection == TRAFFIC_FROM_CLIENT ) {
          lcs = &smbInfo->reqLcs;
      } else {
          lcs = &smbInfo->rspLcs;
      }

      //TZ_ASSERT(lcs != NULL, "Null LCS Descriptor");

#if 0
      // D E B U G  -  used for finding fragmented headers
      if(    lcs->isActive == false &&
             lcs->remainInPkt < sizeof(NBHeader) + sizeof(SmbHeader) )
      {
          nbHeaderRaw = (NBHeaderRaw *)data;
          if(   nbHeaderRaw->reserved == 0x00
             && nbHeaderRaw->length[0] == 0x00
             && nbHeaderRaw->length[1] == 0x00
             && nbHeaderRaw->length[2] == 0x00 )
          {
          }
          else if(   nbHeaderRaw->reserved == 0x85
                  && nbHeaderRaw->length[0] == 0x00
                  && nbHeaderRaw->length[1] == 0x00
                  && nbHeaderRaw->length[2] == 0x00 )
          {
          }
          else if(   nbHeaderRaw->reserved == 0x82
                  && nbHeaderRaw->length[0] == 0x00
                  && nbHeaderRaw->length[1] == 0x00
                  && nbHeaderRaw->length[2] == 0x00 )
          {
          }
          else
          {
              smbPktDump( (const u_char *)data, lcs->remainInPkt );

              volatile tz_uint32 batman;
              ++batman;
          }
      }
#endif

      // Test SMB magic number if we're at the start of a segment and
      // we're not in Large Command State
      if(   lcs->remainInPkt == length
         && lcs->isActive == false
         && length >= (sizeof(NBHeader) + sizeof(SmbHeader))
         && smbHeader->protocol == 0x424d53ff )
      {
          // NetBIOS header is contiguous to TCP header.  We can leave
          // nbHeader, smbHeader, etc. "as is".  There is no tcpSegOffset
          lcs->tcpSegOffset = 0;

#if 0
          // Debug - break on specific pkt
          if(   stohs(smbHeader->userId) == 0x3 
             && stohs(smbHeader->processId) == 0xa08
             && stohs(smbHeader->multiplexId) == 0x3301
             && stohs(smbHeader->treeId) == 0xa800 )
          {
              volatile tz_uint32 feedTheGoats;
              ++feedTheGoats;
          }
#endif

          // We have not yet determined what command is active
          lcs->smbCommand = SMB_COM_NULL_COMMAND;

          // At this point the NB and SMB headers have been located
          lcs->totExpected =    (nbHeaderRaw->length[0] << 16)
                              + (nbHeaderRaw->length[1] << 8 )
                              + (nbHeaderRaw->length[2]      );

          if( lcs->totExpected > (length - sizeof(NBHeader)) )
          {
              lcs->isActive = true;
              lcs->tdsEncaps = NULL;
              lcs->cs = NULL;
              lcs->totReceived = length - sizeof(NBHeader);

              // This packet's contribution is the SMB header and everything
              // after it.
              lcs->totRemaining =   lcs->totExpected 
                                  - lcs->totReceived;

              SmbDcdLog( sessionEntry, "SYNC    0  LCS" );
          }
          else
          {
              // Otherwise, ensure that we're not in large command mode
              lcs->isActive = false;
              SmbDcdLog( sessionEntry, "SYNC    0  NORM" );

              // No fragmentation is in process
              lcs->fs.isActive = false;
              lcs->fs.len      = 0;
          }
      }
      else  // NB and SMB headers not contiguous to TCP
      {
          // Large Command State
          if( lcs->isActive )
          {
              // This frame is probably a TCP continuation.  Update the
              // counts, process, and quit
              lcs->totReceived += length;

              // Check if this packet could possibly contain the rest of
              // what is remaining.  If it could then we're no longer in
              // large command mode

              if( lcs->totRemaining <= length )
              {
                  SmbDcdLog( sessionEntry, "LCS     END" );

                  // Last segment - Readjust lengths if necessary
                  if( lcs->totRemaining != length )
                  {
                      // The length included the beginning of another SMB
                      // command so remove that
                      lcs->totReceived -= (length - lcs->totRemaining);
                  }

                  // Large Command State and fragmentation in process
                  if( lcs->fs.isActive == true )
                  {
                      // Append the data to frag from previous segment
                      handleFragCont( sessionEntry, data, length );

                      // Init the Andx Command State variable
                      andxCmdState.cmd = lcs->smbCommand;
                      andxCmdState.offset = 0;
                      andxCmdState.chainCnt = 1;

                      // The command is now evaluated for the first time
                      smbProcessDataPacket( sessionEntry,
                                            lcs->smbCommand,
                                            (const u_char *)lcs->fs.data,
                                            lcs->fs.len,
                                            false );  // tcpHole
                      SmbIntLog("\n");

                      // Frag State is over
                      lcs->fs.isActive = false;
                      lcs->fs.len      = 0;
                  }
                  else
                  {
                      // No fragmentation in process
                      // Acquire the data and finish
                      handleTcpContComplete( sessionEntry, 
                                             (tz_uint8 *)data, 
                                             lcs->totRemaining, lcs );
                  }

                  lcs->isActive = false;

                  if( SmbDebug::logIsEnabled ) {
                      SmbIntLog("%s  ", smbUtilBlankString());
                      SmbIntLog("%c %4d  ", tcpHole ? 'H' : ' ',
                                                smbInfo->sessionIdNum );
                      SmbIntLog("%3d  ", processedPktNum );
                      SmbIntLog("totExp %08d  totRecd %08d  totRmn %08d  "
                                "tcpSegOffset 0x%04x",
                                lcs->totExpected,
                                lcs->totReceived, lcs->totRemaining,
                                lcs->tcpSegOffset );

                       // Display any Event Filtering debug info
                      if( encEngFmt->evtFiltDbgInfo[0] != '\0' )
                      {
                          SmbIntLog( "%s", encEngFmt->evtFiltDbgInfo );
                          // We're done with the debug info
                          encEngFmt->evtFiltDbgInfo[0] = '\0';
                      }

                      SmbIntLog( "\n" );
                      SmbDebug::logLinePut();
                  }

                  // The total remaining is the offset into the TCP segment
                  lcs->tcpSegOffset = lcs->totRemaining;

                  if( lcs->totRemaining == length )
                  {
                      lcs->remainInPkt = 0;
                      break;
                  }
                  else
                  {
                      lcs->remainInPkt -= lcs->totRemaining;
                  }
              }
              else
              {
                  // Intermediate Segment - Acquire the data
                  SmbDcdLog( sessionEntry, "LCS     INTER" );

                  // Large Command State and fragmentation in process
                  if( lcs->fs.isActive == true )
                  {
                      // Append the data to frag from previous segment
                      handleFragCont( sessionEntry, data, length );

                      // Init the Andx Command State variable
                      andxCmdState.cmd = lcs->smbCommand;
                      andxCmdState.offset = 0;
                      andxCmdState.chainCnt = 1;

                      // The command is now evaluated for the first time
                      smbProcessDataPacket( sessionEntry,
                                            lcs->smbCommand,
                                            (const u_char *)lcs->fs.data,
                                            lcs->fs.len,
                                            false );  // tcpHole

                      SmbIntLog("\n");

                      // Frag State is over
                      lcs->fs.isActive = false;
                      lcs->fs.len      = 0;
                  }
                  else
                  {
                      // No fragmentation in process
                      handleTcpContInProgress( sessionEntry,
                                               (tz_uint8 *)data,
                                               length, lcs );
                  }

                  // Account for this packet's bytes
                  lcs->totRemaining -= length;

                  if( SmbDebug::logIsEnabled ) {
                      SmbIntLog("%s  ", smbUtilTcpContinString());
                      SmbIntLog("%c %4d  ",  tcpHole ? 'H' : ' ',
                                             smbInfo->sessionIdNum );
                      SmbIntLog("%3d  ", processedPktNum );
                      SmbIntLog("totExp %08d  totRecd %08d  totRmn %08d  "
                                "tcpSegOffset 0x%04x",
                                lcs->totExpected,
                                lcs->totReceived, lcs->totRemaining,
                                lcs->tcpSegOffset );
                      SmbIntLog( "\n" );
                      SmbDebug::logLinePut();
                  }

                  //smbPktDump( data, length );

                  // No further processing for now
                  lcs->remainInPkt = 0;
                  break;
              }
          }

#if 0
          // D E B U G  -  used for finding fragmented headers
          if(    length == 4
              && lcs->remainInPkt == length )
          {
              // No SMB header found at start of TCP segment.  Ignore

          }
          else if( /* lcs->isActive == true && */
                 lcs->remainInPkt < sizeof(NBHeader) + sizeof(SmbHeader) )
          {
              nbHeaderRaw = (NBHeaderRaw *)(data + lcs->tcpSegOffset);
              if(   nbHeaderRaw->reserved == 0x00
                 && nbHeaderRaw->length[0] == 0x00
                 && nbHeaderRaw->length[1] == 0x00
                 && nbHeaderRaw->length[2] == 0x00 )
              {
              }
              else if(   nbHeaderRaw->reserved == 0x85
                      && nbHeaderRaw->length[0] == 0x00
                      && nbHeaderRaw->length[1] == 0x00
                      && nbHeaderRaw->length[2] == 0x00 )
              {
              }
              else if(   nbHeaderRaw->reserved == 0x82
                      && nbHeaderRaw->length[0] == 0x00
                      && nbHeaderRaw->length[1] == 0x00
                      && nbHeaderRaw->length[2] == 0x00 )
              {
              }
              else
              {
                  smbPktDump( (const u_char *)(data + lcs->tcpSegOffset),
                                                     lcs->remainInPkt );
                  volatile tz_uint32 batman;
                  ++batman;
              }
          }
#endif


          // Try and find the SMB header by applying the offset.  In
          // most cases this should succeed.
          nbHeader = (NBHeader *)(data + lcs->tcpSegOffset);
          nbHeaderRaw = (NBHeaderRaw *)(data + lcs->tcpSegOffset);
          smbHeader = (SmbHeader *)(data + lcs->tcpSegOffset
                                         + sizeof(NBHeader));

          // Test SMB magic number
          if(   lcs->remainInPkt >= sizeof(NBHeader) + sizeof(SmbHeader)
             && smbHeader->protocol == 0x424d53ff )
          {
              // Check if tcpSegOffset extends beyond length before we
              // use the calculated data pointer
              TZ_ASSERT(lcs->tcpSegOffset <= length, 
                                         "SMB tcpSegOffset out of range");

              // Good - We are synchronized.
              SmbDcdLog( sessionEntry, "SYNC    %lu", lcs->tcpSegOffset );

              // Protocol command handlers expect "data" to point to 
              // NBHeader.  Wave a wand and make it so
              data += lcs->tcpSegOffset;

              // We have not yet determined what command is active
              lcs->smbCommand = SMB_COM_NULL_COMMAND;

              // Extract NB_hdrlen and check if we're starting another
              // largeCmdState
              lcs->totExpected =   (nbHeaderRaw->length[0] << 16)
                                 + (nbHeaderRaw->length[1] << 8 )
                                 + (nbHeaderRaw->length[2]      );

              if( lcs->totExpected > length - lcs->tcpSegOffset 
                                            - sizeof(NBHeader) )
              {
                  lcs->isActive = true;
                  lcs->tdsEncaps = NULL;
                  lcs->cs = NULL;
                  lcs->totReceived = length - lcs->tcpSegOffset 
                                            - sizeof(NBHeader);

                  // This packet's contribution is the SMB header
                  //  and everything after it.
                  lcs->totRemaining =   lcs->totExpected 
                                      - lcs->totReceived;
              }
              else
              {
                  lcs->isActive = false;

                  // No fragmentation is in process (yet)
                  lcs->fs.isActive = false;
                  lcs->fs.len      = 0;
              }
          }

          else if(   lcs->remainInPkt < (sizeof(NBHeader) + sizeof(SmbHeader))
                  && length > (sizeof(NBHeader) + sizeof(SmbHeader)) )
          {
              // A LCS state has just ended.
              // It is reasonable to believe that the remaining data is the
              // beginning of another SMB command but the length of it is
              // insufficient to wholly contain both nbHeader and smbHeader.
              // That means we are unable to read the NetBIOS length from the
              // nbHeader and determine if we are going back into LCS again.
              // So, we initiate Frag state and process the aggregate when
              // the next segment comes in.  This case (header fragmentation)
              // is the only time that Frag is active when LCS is not.

              // D E B U G - remove
              //smbPktDump( (const u_char *)nbHeader, lcs->remainInPkt );

              handleFragBegin( sessionEntry,
                               (const u_char *)nbHeader,
                               lcs->remainInPkt );

              SmbDcdLog( sessionEntry,"FRAG    HEADER %u",
                                                      lcs->remainInPkt );
              lcs->smbCommand = SMB_COM_NULL_COMMAND;
              lcs->remainInPkt = 0;
              break;
          }
          else // SMB header not found at the offset
          {
              // Bad - We are NOT synchronized.

              // Verify nbHeader before going further.  It's influenced by
              // lcs->tcpSegOffset and holes can cause miscalculation
              if( (const u_char*)nbHeader > &data[length] )
              {
                  if( SmbDebug::logIsEnabled ) {
                      SmbIntLog("%s  ", smbUtilBlankString());
                      SmbIntLog("%c %4d  ", tcpHole ? 'H' : ' ',
                                                smbInfo->sessionIdNum );
                      SmbIntLog("%3d  ", processedPktNum );
                      SmbIntLog("not sync'd, nbHeader (tcpSegOffset %ld) "
                          "past &data[%ld]\n", lcs->tcpSegOffset,length );
                  }
 
                  lcs->remainInPkt = 0;
                  lcs->isActive = false;
                  lcs->tcpSegOffset = 0;
                  ++decodeStats.notSyncCount;

                  // No fragmentation
                  lcs->fs.isActive = false;
                  lcs->fs.len      = 0;
                  break;
              }

              // Evaluate if NetBIOS Session Service Empty Message
              if(   length >= 4
                 && nbHeader->type == 0x00
                 && nbHeader->flags == 0
                 && nbHeader->length == 0 )
              {
                  // NetBIOS Session Service Message (empty)
                  SmbDcdLog( sessionEntry, "NOSYNC  NB-SS-Empty" );
                  if( SmbDebug::logIsEnabled ) {
                      SmbIntLog("%s  ", smbUtilTcpContinString());
                      SmbIntLog("%c %4d  ",  tcpHole ? 'H' : ' ',
                                             smbInfo->sessionIdNum );
                      SmbIntLog("%3d  ", processedPktNum );
                      SmbIntLog("NBSS Session Empty Message\n");
                      SmbDebug::logLinePut();
                  }
                  lcs->remainInPkt = 0;
                  break;
              }

              // Evaluate if it is a possible NetBIOS Session Service
              if(   length >= 4
                 && nbHeader->type >= 0x81
                 && nbHeader->type <= 0x85 )
              {
                  if(   nbHeader->type == 0x85
                     && nbHeader->flags == 0
                     && nbHeader->length == 0 )
                  {
                      // NetBIOS Session Service Keep alive
                      SmbDcdLog( sessionEntry, "NOSYNC  NB-SS-KeepAlive" );
                      if( SmbDebug::logIsEnabled ) {
                          SmbIntLog("%s  ", smbUtilTcpContinString());
                          SmbIntLog("%c %4d  ",  tcpHole ? 'H' : ' ',
                                             smbInfo->sessionIdNum );
                          SmbIntLog("%3d  ", processedPktNum );
                          SmbIntLog("NBSS Session Keepalive\n");
                          SmbDebug::logLinePut();
                      }
                      lcs->remainInPkt = 0;
                      break;
                  }

                  // Otherwise, count it as another possible NBSS type
                  ++decodeStats.possibNbssCount;
              }

              // NetBios message length of 4 sets a minimum size to
              // attempt sync.  If the offset exceeds the buffer length,
              // don't sync.  If there's not enough room between the
              // offset and the end of the buffer then don't try to sync.
              if(   length < 4
                 || lcs->tcpSegOffset >= length
                 || length - lcs->tcpSegOffset < 4 )
              {
                  lcs->remainInPkt = 0;
                  lcs->isActive = false;
                  lcs->tcpSegOffset = 0;
                  ++decodeStats.notSyncCount;

                  // No fragmentation
                  lcs->fs.isActive = false;
                  lcs->fs.len      = 0;
                  break;
              }

              // Let's try to find SMB.  We factor in "-3" to prevent the
              // possibility of reading past the end of valid data
              tz_uint8 *currByte = (tz_uint8 *)(data + lcs->tcpSegOffset);
              tz_uint32 i;
              for( i = 0; i < (length - lcs->tcpSegOffset - 3 ); ++i )
              {
                  if(   *(currByte+0) == 0xff 
                     && *(currByte+1) == 0x53
                     && *(currByte+2) == 0x4d
                     && *(currByte+3) == 0x42 )
                  {
                      // We found the SMB header.  Rejoice

                      // If we are not in the packet deep enough to back
                      // up to the NBheader then we'll pretend as though
                      // we did not find sync at all.
                      if( lcs->tcpSegOffset + i < sizeof(NBHeader))
                      {
                          ++currByte;
                          continue;
                      }

                      // Count it as a resync success
                      ++decodeStats.reSyncSuccess;

                      // Establish tcpSegOffset which points to the NBheader
                      lcs->tcpSegOffset += i - sizeof(NBHeader);
                      SmbDcdLog( sessionEntry, "NOSYNC  %lu FOUND", 
                                                     lcs->tcpSegOffset );

                      nbHeader = (NBHeader *)(data 
                                        + lcs->tcpSegOffset );

                      nbHeaderRaw = (NBHeaderRaw *)(data 
                                        + lcs->tcpSegOffset );

                      smbHeader = (SmbHeader *)(data
                                          + lcs->tcpSegOffset
                                          + sizeof(NBHeader));
                      // Protocol command handlers expect "data" to point
                      // to NBHeader.
                      data = data + lcs->tcpSegOffset;

                      // Account for bytes skipped over
                      lcs->remainInPkt = length - lcs->tcpSegOffset;

                      break;
                  }
                  ++currByte;
              }

              // Test if we failed to find it.  (Factor "-3" is as above)
              if( i == length - lcs->tcpSegOffset - 3 )
              {
                  SmbDcdLog( sessionEntry, "NOSYNC  NOTFOUND" );

                  if( SmbDebug::logIsEnabled ) {
                      SmbIntLog("%s  ", smbUtilTcpContinString());
                      SmbIntLog("%c %4d  ",  tcpHole ? 'H' : ' ',
                                             smbInfo->sessionIdNum );
                      SmbIntLog("%3d  ", processedPktNum );
                      SmbIntLog("not sync'd  tcpSegOffset 0x%04x",
                                          lcs->tcpSegOffset );
                      SmbIntLog( "\n" );
                      SmbDebug::logLinePut();
                  }

                  //smbPktDump( data, length );

                  // We were unable to find the SMB header so quit
                  lcs->remainInPkt = 0;
                  lcs->isActive = false;
                  lcs->tcpSegOffset = 0;
                  ++decodeStats.notSyncCount;

                  // No fragmentation is in process
                  lcs->fs.isActive = false;
                  lcs->fs.len      = 0;
                  break;
              }

              // We succeeded in finding it
              if( SmbDebug::logIsEnabled ) {
                  SmbIntLog("%s  ", smbUtilTcpContinString());
                  SmbIntLog("%c %4d  ",  tcpHole ? 'H' : ' ',
                                         smbInfo->sessionIdNum );
                  SmbIntLog("%3d  ", processedPktNum );
                  SmbIntLog("resync success  tcpSegOffset 0x%04x",
                                          lcs->tcpSegOffset );
                  SmbIntLog( "\n" );
                  SmbDebug::logLinePut();
              }

              // We have not yet determined what command is active
              lcs->smbCommand = SMB_COM_NULL_COMMAND;

              // Check for largeCmdState
              lcs->totExpected =    (nbHeaderRaw->length[0] << 16)
                                  + (nbHeaderRaw->length[1] << 8 )
                                  + (nbHeaderRaw->length[2]      );

              if( lcs->totExpected > length - lcs->tcpSegOffset 
                                            - sizeof(NBHeader) )
              {
                  lcs->isActive = true;
                  lcs->tdsEncaps = NULL;
                  lcs->cs = NULL;
                  lcs->totReceived = length - lcs->tcpSegOffset 
                                            - sizeof(NBHeader);

                  // This packet's contribution is the SMB header and everything
                  // after it.
                  lcs->totRemaining =   lcs->totExpected
                                      - lcs->totReceived;
              }
              else
              {
                  lcs->isActive = false;

                  // No fragmentation is in process
                  lcs->fs.isActive = false;
                  lcs->fs.len      = 0;
              }

          } // SMB header not found at the offset

      } // NB and SMB headers not contiguous to TCP


      // Init the Andx Command State variable.  Since we're just starting
      // out with processing, chainCnt is 1 and offset is 0.
      andxCmdState.cmd = smbHeader->command;
      andxCmdState.offset = 0;
      andxCmdState.chainCnt = 1;

      // Process the command chain
      while( andxCmdState.cmd != 0xff )
      {
          if( smbIsLogonPacket(andxCmdState.cmd) )
          {
              smbProcessLogonPacket( sessionEntry,
                                     andxCmdState.cmd,
                                     (const u_char *)data,
                                     length - lcs->tcpSegOffset,
                                     tcpHole );

          } else {
              smbProcessDataPacket( sessionEntry,
                                    andxCmdState.cmd,
                                    (const u_char *)data,
                                    length - lcs->tcpSegOffset,
                                    tcpHole );
          }

#ifdef SMB_DEBUG_MODE_1
          smbCmdDump( andxCmdState.cmd, sessionEntry->trafficDirection,
                                                        data, length );
#endif
          if( SmbDebug::logIsEnabled )
          {
              // Display any Event Filtering debug info
              if( encEngFmt->evtFiltDbgInfo[0] != '\0' )
              {
                  SmbIntLog( "  %s", encEngFmt->evtFiltDbgInfo );
                  // We're done with the debug info
                  encEngFmt->evtFiltDbgInfo[0] = '\0';
              }

              // print the trailing CR
              SmbIntLog( "\n" );

              SmbDebug::logLinePut();
          }

          // A software bug may result in an Andx chain being
          // unterminated.  Detect that here and terminate to prevent a
          // runaway netmon
          if( andxCmdState.chainCnt > 15 + 1 )
          {
              SmbErrLog(LOG_NOTICE,"Unterminated Andx Chain, Cmd 0x%02x",
                                                     andxCmdState.cmd );
              // Terminate the chain
              andxCmdState.cmd = 0xff;
          }

      }

      // Count the bytes processed by this function
      if( lcs->isActive != true )
      {
          lcs->remainInPkt -= lcs->totExpected + sizeof(NBHeaderRaw);
          lcs->tcpSegOffset += lcs->totExpected + sizeof(NBHeaderRaw);
      }

  } while (0);

}

//-----------------------------------------------------------------------
// smbCmdDump()
//-----------------------------------------------------------------------
void SmbDecode::smbCmdDump( tz_uint8      cmd,
                            tz_uint32     dir,
                            const u_char *data, 
                            tz_uint32     length)
{
    tz_uint32 i, j, outCnt;

    char *pCmdStg = smbUtilCmd2String(cmd);
    tz_uint32 stgLen = strlen( pCmdStg );

    // Print the command string.  We assume a fixed column size of 30
    for( i=0; i < stgLen; ++i )
    {
        printf( "%c", pCmdStg[i] );
    }
    for( i=0; i<30-stgLen; ++i ) { printf( " " ); }


    if( dir == TRAFFIC_FROM_CLIENT )
    {
        printf( "*" );
    } else {
        printf( " " );
    } 

    // Now dump the smbHeader data and all that follows
    for( i=0, outCnt = 0; i < length; ++i )
    {
        printf( "%02x ", data[i] );
        ++outCnt;
        if( !(outCnt % 32) )
        {
            printf( "\n" );
            for( j=0; j<30+1; ++j ) { printf( " " ); }
        }
    }
    printf( "\n" );
}

//-----------------------------------------------------------------------
// smbPktDump()
//-----------------------------------------------------------------------
void SmbDecode::smbPktDump( const u_char *data, 
                            tz_uint32     length)
{
  tz_uint32 offset = 0;

  //if( SmbDebug::logIsEnabled )
  //{
      // Print the entire length if it's less than 12 lines of 32 bytes
      // each.  Otherwise, stop at (12 * 32)
      while(   offset < ((length < (12 * 32)) ? length : (12 * 32)) )
      {
          if( !(offset % 32) )
          {
              printf( "\n" );
              //SmbDebug::logLinePut();
              printf( "%04lx    ", offset );
          }

          printf( "%02x ", data[offset] );

          ++offset;
      }
      printf("\n");
      //SmbDebug::logLinePut();
  //}
}

//-----------------------------------------------------------------------
// smbPrintCmd()
//-----------------------------------------------------------------------
void SmbDecode::smbPrintCmd( char *pCmdStg )
{
    tz_uint32 i, j;
    tz_uint32 stgLen = strlen( pCmdStg );
    tz_uint8  outStg[32];

    // Print the command string.  We assume a fixed column size of 30
    for( i=0; i < stgLen; ++i )
    {
        outStg[i] = pCmdStg[i];
    }

    for( j=0; j<30-stgLen; ++j ) 
    { 
        outStg[i++] = ' ';
    }
    outStg[i] = '\0';
    SmbIntLog("%s", outStg);

}

//-----------------------------------------------------------------------
// smbIsLogonPacket()
//-----------------------------------------------------------------------
bool SmbDecode::smbIsLogonPacket( tz_uint8 command )
{
  bool isLogon;

  switch( command )
  {
  case SMB_COM_NEGOTIATE:
  case SMB_COM_SESSION_SETUP_ANDX:
  case SMB_COM_LOGOFF_ANDX:
      isLogon = true;
      break;
  default:
      isLogon = false;
      break;
  }
  return isLogon;
}

//-----------------------------------------------------------------------
// smbProcessLogonPacket()
//-----------------------------------------------------------------------
tz_uint32 SmbDecode::smbProcessLogonPacket( SessionEntry *sessionEntry,
                                            tz_uint8      command,
                                            const u_char *data,
                                            tz_uint32     length,
                                            tz_uint32     tcpHole )
{
  tz_uint32 status = IIMS_SUCCESS;
  SmbHeader *smbHeader;

  smbHeader = (SmbHeader *)(data + sizeof(NBHeader));


  if( SmbDebug::logIsEnabled )
  {
      tz_uint16 uid, pid, mid, tid;
      uid = stohs(smbHeader->userId);
      pid = stohs(smbHeader->processId);
      mid = stohs(smbHeader->multiplexId);
      tid = stohs(smbHeader->treeId);

      // Show all packets, even "unsuccessful" ones which typically happen
      // during NTLMSSP negotiation
      char *pCmdStg = smbUtilCmd2String(command);
      smbPrintCmd( pCmdStg );
      SmbIntLog("%c%04x  %04x  %04x  %04x", 
          sessionEntry->trafficDirection == TRAFFIC_FROM_SERVER ? ' ' : '*',
          uid, pid, mid,tid );

      SmbInfo *smbInfo = (SmbInfo *)sessionEntry->appInfo;
      SmbIntLog("  %c %4d", tcpHole ? 'H' : ' ', smbInfo->sessionIdNum );

      // Number the debug entries for easier debugging
      SmbIntLog("  %3d", processedPktNum );
  }

  switch( command )
  {
  case SMB_COM_NEGOTIATE:
      smbHandleNegotiate( sessionEntry, data, length );
      break;
  case SMB_COM_SESSION_SETUP_ANDX:
      smbHandleSessionSetupAndx( sessionEntry, data, length );
      break;
  case SMB_COM_LOGOFF_ANDX:
      smbHandleLogoffAndx( sessionEntry, data, length );
      break;
  default:
      break;
  }

  (sessionEntry->trafficDirection == TRAFFIC_FROM_CLIENT)
                                   ? ++smbClientPkts : ++smbServerPkts;

  return status;
}

//-----------------------------------------------------------------------
// smbProcessDataPacket()
//-----------------------------------------------------------------------
tz_uint32 SmbDecode::smbProcessDataPacket( SessionEntry *sessionEntry,
                                           tz_uint8      command,
                                           const u_char *data,
                                           tz_uint32    length,
                                           tz_uint32    tcpHole )
{
  tz_uint32 status = IIMS_SUCCESS;
  SmbHeader *smbHeader;

  smbHeader = (SmbHeader *)(data + sizeof(NBHeader));


  // General processing
  if( SmbDebug::logIsEnabled )
  {
      tz_uint16 uid, pid, mid, tid;

      // If we can see the entire smb header, display it
      if( length >= (sizeof(NBHeader) + sizeof(SmbHeader)))
      {
          // Regardless of ntStatus (success or a code), display the command
          char *pCmdStg = smbUtilCmd2String(command);
          uid = stohs(smbHeader->userId);
          pid = stohs(smbHeader->processId);
          mid = stohs(smbHeader->multiplexId);
          tid = stohs(smbHeader->treeId);
          smbPrintCmd( pCmdStg );
          SmbIntLog("%c%04x  %04x  %04x  %04x",
                 sessionEntry->trafficDirection == TRAFFIC_FROM_SERVER ? ' ' : '*',
                 uid, pid, mid, tid );
      }
      else
      {
          // Display unknowns, start with the NULL command
          char *pCmdStg = smbUtilCmd2String(0xff);
          smbPrintCmd( pCmdStg );

          // Unknown uid, pid, mid, tid
          SmbIntLog("%c----  ----  ----  ----",
                 sessionEntry->trafficDirection == TRAFFIC_FROM_SERVER ? ' ' : '*');
      }

      SmbInfo *smbInfo = (SmbInfo *)sessionEntry->appInfo;
      SmbIntLog("  %c %4d", tcpHole ? 'H' : ' ', smbInfo->sessionIdNum );

      // Number the debug entries for easier debugging
      SmbIntLog("  %3d", processedPktNum );
  }

  // Command-specific handlers
  switch( command )
  {
  case SMB_COM_CREATE:
      smbHandleCreate( sessionEntry, data, length );
      break;
  case SMB_COM_NT_CREATE_ANDX:
      smbHandleNtCreateAndx( sessionEntry, data, length );
      break;
  case SMB_COM_OPEN:
      smbHandleOpen( sessionEntry, data, length );
      break;
  case SMB_COM_OPEN_ANDX:
      smbHandleOpenAndx( sessionEntry, data, length );
      break;
  case SMB_COM_READ:
      smbHandleRead( sessionEntry, data, length );
      break;
  case SMB_COM_READ_ANDX:
      smbHandleReadAndx( sessionEntry, data, length );
      break;
  case SMB_COM_WRITE:
      smbHandleWrite( sessionEntry, data, length );
      break;
  case SMB_COM_WRITE_ANDX:
      smbHandleWriteAndx( sessionEntry, data, length );
      break;
  case SMB_COM_CLOSE:
      smbHandleClose( sessionEntry, data, length );
      break;
  case SMB_COM_TRANSACTION:
      smbHandleTransaction( sessionEntry, data, length );
      break;
  case SMB_COM_TRANSACTION2:
      smbHandleTransaction2( sessionEntry, data, length );
      break;
  case SMB_COM_DELETE:
      smbHandleDelete( sessionEntry, data, length );
      break;
  case SMB_COM_DELETE_DIRECTORY:
      smbHandleDeleteDirectory( sessionEntry, data, length );
      break;
  case SMB_COM_TREE_CONNECT_ANDX:
      smbHandleTreeConnectAndx( sessionEntry, data, length );
      break;
  case SMB_COM_TREE_DISCONNECT:
      smbHandleTreeDisconnect( sessionEntry, data, length );
      break;
  case SMB_COM_RENAME:
      smbHandleRename( sessionEntry, data, length );
      break;
  default:
      smbHandleDefaultCommand( sessionEntry, data, length );
      break;
  }

  (sessionEntry->trafficDirection == TRAFFIC_FROM_CLIENT)
                                   ? ++smbClientPkts : ++smbServerPkts;

  return status;
}

#ifdef SMB_DEBUG_MODE_3
void SmbAddrFormat ( SessionEntry *sessionEntry,
                     struct in_addr *clientAddr, struct in_addr *serverAddr,
                     uint16 *clientPort, uint16 *serverPort)
{
  if (sessionEntry->clientIsDst)
  {
      clientAddr->s_addr = sessionEntry->addressTuple.dst;
      serverAddr->s_addr = sessionEntry->addressTuple.src;
      *clientPort = htons(sessionEntry->addressTuple.dPort);
      *serverPort = htons(sessionEntry->addressTuple.sPort);
  }
  else
  {
      clientAddr->s_addr = sessionEntry->addressTuple.src;
      serverAddr->s_addr = sessionEntry->addressTuple.dst;
      *clientPort = htons(sessionEntry->addressTuple.sPort);
      *serverPort = htons(sessionEntry->addressTuple.dPort);
  }
}
#endif
//-----------------------------------------------------------------------
// CreateProtocolData()
//     Currently the discipline is such that filter (the driver)
//     requests the protocol to allocate its own state data.  Filter
//     stores it in sessionEntry->appInfo.
//     Note that both halves of a session each call in here.
//-----------------------------------------------------------------------
SmbInfo *SmbDecode::CreateProtocolData( SessionEntry *sessionEntry )
{
  SmbInfo *smbInfo;

#ifdef SMB_DEBUG_MODE_3
  char srcIp[32+1];  char dstIp[32+1];
  struct in_addr srcAddr;  struct in_addr dstAddr;
  uint16   clientPort, serverPort;

  SmbAddrFormat (sessionEntry, &srcAddr, &dstAddr, &clientPort, &serverPort);
  memset(srcIp, 0, 32);
  sprintf(srcIp, inet_ntoa(srcAddr));
  memset(dstIp, 0, 32);
  sprintf(dstIp, inet_ntoa(dstAddr));
  printf("SmbInfo CREATE: src: %s:%d  dst: %s:%d %s\n", 
         srcIp, clientPort,
         dstIp, serverPort,
         sessionEntry->trafficDirection == TRAFFIC_FROM_CLIENT ?
         "FROM_CLIENT" : "FROM_SERVER" );
#endif

  smbInfo = SmbSsnDataInit( sessionEntry );

  if( smbInfo != NULL )
  {
      // Create a new session ID number
      smbInfo->sessionIdNum = ++sessionIdNum;
  }

  return smbInfo;
}

//-----------------------------------------------------------------------
// DeleteProtocolData()
//     The current discipline is for the filter (the driver) to call
//     in here so that the protocol can deallocate all data structures
//     it has privately been maintaining.  The filter will then itself
//     free SmbInfo (held in sessionEntry->appInfo)
//     Note that both halves of the session each do this.
//-----------------------------------------------------------------------
void SmbDecode::DeleteProtocolData( SessionEntry *sessionEntry )
{
#ifdef SMB_DEBUG_MODE_3
  char srcIp[32+1];  char dstIp[32+1];
  struct in_addr srcAddr;  struct in_addr dstAddr;
  uint16 clientPort, serverPort;

  SmbAddrFormat(sessionEntry, &srcAddr, &dstAddr, &clientPort, &serverPort);
  memset(srcIp, 0, 32);
  sprintf(srcIp, inet_ntoa(srcAddr));
  memset(dstIp, 0, 32);
  sprintf(dstIp, inet_ntoa(dstAddr));
  printf("SmbInfo DELETE: src: %s:%d  dst: %s:%d %s\n", 
         srcIp, clientPort,
         dstIp, serverPort,
         sessionEntry->trafficDirection == TRAFFIC_FROM_CLIENT ?
         "FROM_CLIENT" : "FROM_SERVER" );
#endif

  SmbSsnDataDeInit( sessionEntry );
}

//-----------------------------------------------------------------------
// handleTcpContInProgress()
//     TCP Continuation In Progress.  This is one segment in a sequence
//     and others will follow
//-----------------------------------------------------------------------
void SmbDecode::handleTcpContInProgress( SessionEntry  *sessionEntry,
                                         tz_uint8      *data,
                                         tz_uint32      length,
                                         LargeCmdState *lcs )
{
  tz_uint32 status;

  do
  {

      if(   lcs->tdsEncaps
         && lcs->smbCommand == SMB_COM_READ_ANDX )
      {
          smbTdsEncapsServerRsp( sessionEntry,
                                 lcs->tdsEncaps,
                                 data,
                                 length );
          break;
      }

      // If Content Scanning is enabled, perform it
      if(   rspDataPatMgr->CSEnabled() == true
         && lcs->cs
         && lcs->smbCommand == SMB_COM_READ_ANDX )
      {
          lcs->cs->ScanData( data, length, sessionEntry->workerIdx );

          // Look up the PidMid to refresh its age
          SmbSsnUid        *ssnUid;
          SmbSsnPidMid     *ssnPidMid;
          status = smbCsFindSsnDescrs( sessionEntry, lcs, &ssnUid,
                                       &ssnPidMid, NULL, NULL );

          // We hope status is SMB_ERROR_NONE but, if not, we're not going
          // to do anything about it so ignore the return value

          // D E B U G
          //SmbIntLog("  CS_CONT_PROG");
      }

      if(   cmdDataPatMgr->CSEnabled() == true
         && lcs->cs
         && lcs->smbCommand == SMB_COM_WRITE_ANDX )
      {
          lcs->cs->ScanData( data, length, sessionEntry->workerIdx );

          // Look up the PidMid to refresh its age
          SmbSsnUid        *ssnUid;
          SmbSsnPidMid     *ssnPidMid;
          status = smbCsFindSsnDescrs( sessionEntry, lcs, &ssnUid,
                                       &ssnPidMid, NULL, NULL );

          // We hope status is SMB_ERROR_NONE but, if not, we're not going
          // to do anything about it so ignore the return value
      }

      if(   lcs->tdsEncaps
         && lcs->smbCommand == SMB_COM_WRITE_ANDX )
      {
          smbTdsEncapsClientReq( sessionEntry,
                                 lcs->tdsEncaps,
                                 data,
                                 length );
          break;
      }

  } while (0);
}

//-----------------------------------------------------------------------
// handleTcpContComplete()
//     TCP Continuation Complete.  This is the last segment of a multi-
//     segment sequence
//-----------------------------------------------------------------------
void SmbDecode::handleTcpContComplete( SessionEntry  *sessionEntry,
                                       tz_uint8      *data,
                                       tz_uint32      length,
                                       LargeCmdState *lcs )
{
  tz_uint32 status;


  do
  {

      if(   lcs->tdsEncaps
         && lcs->smbCommand == SMB_COM_READ_ANDX )
      {
          smbTdsEncapsServerRsp( sessionEntry,
                                 lcs->tdsEncaps,
                                 data,
                                 length );
          break;
      }

      // If Content Scanning is enabled, perform it
      if(   rspDataPatMgr->CSEnabled() == true
         && lcs->cs
         && lcs->smbCommand == SMB_COM_READ_ANDX )
      {
          DimValListEntry *respDataDVLE = NULL;

          SmbSsnUid        *ssnUid;
          SmbSsnPidMid     *ssnPidMid;
          SmbSsnFid        *ssnFid;
          SmbSsnTid        *ssnTid;

          status = smbCsFindSsnDescrs( sessionEntry, lcs, &ssnUid,
                                       &ssnPidMid,&ssnFid, &ssnTid );

          if( status != SMB_ERROR_NONE )  break;

          lcs->cs->ScanData( data, length, sessionEntry->workerIdx );

          // Take a peek at whether we are going to generate an event
          bool sendEvent;
          sendEvent = encEngFmt->evtFiltEvaluate( sessionEntry,
                                                  EVT_READ,
                                                  ssnUid,
                                                  ssnFid );

          if( sendEvent )
          {
              // We are so stop the scanner and get counts
              tz_uint32 matches = ssnFid->serverCs->GetTotalMatchCount();

              respDataDVLE = lcs->cs->StopScan(
                                ResponseDataType, sessionEntry->workerIdx);

              SmbIntLog("  %lu matches  CS_STOP", matches );
          }

          // Generate an event - create the command string
          sprintf( currCmdStg, "READ  %s", ssnFid->filename);

          // Format Content and Operation
          encEngFmt->resetEvent( sessionEntry );
          encEngFmt->setDimFileContent( sessionEntry,
                                        ssnFid->filename,
                                        NULL,
                                        ssnTid->sharename,
                                        0 );
          encEngFmt->setDimOperation( sessionEntry,
                                      EVT_READ, "READ", 
                                      strlen("READ") +1 );

          // Format Size and Response and generate the event
          encEngFmt->setDimSize( sessionEntry, 0 /* FIX stohs(rsp->dataLength)*/ );
          encEngFmt->setDimResponse( sessionEntry, SUCCESSFUL_OPERATION );
          encEngFmt->setDimResponseData( sessionEntry, respDataDVLE );
          encEngFmt->sendCOSREvent( encodingEngine,
                                    sessionEntry,
                                    ssnUid,
                                    ssnTid,
                                    currCmdStg );

          if( SmbSsnDataRemovePidMid(sessionEntry, ssnUid, lcs->csPid, lcs->csMid)
                                                        == IIMS_FAILURE )
          {
              ++decodeStats.failedRemove;

              SmbIntLog("  Descr ERROR - Failed Remove PidMId" );
          }

          //smbUtilCSPrintResults( lcs->cs, respDataDVLE );

          // D E B U G
          //SmbIntLog("  CS_CONT_COMPLETE");
      }

      if(   cmdDataPatMgr->CSEnabled() == true
         && lcs->cs
         && lcs->smbCommand == SMB_COM_WRITE_ANDX )
      {
          lcs->cs->ScanData( data, length, sessionEntry->workerIdx );

          // Look up the PidMid to refresh its age
          SmbSsnUid        *ssnUid;
          SmbSsnPidMid     *ssnPidMid;
          status = smbCsFindSsnDescrs( sessionEntry, lcs, &ssnUid,
                                       &ssnPidMid, NULL, NULL );

          // We hope status is SMB_ERROR_NONE but, if not, we're not going
          // to do anything about it so ignore the return value
      }

      if(   lcs->tdsEncaps
         && lcs->smbCommand == SMB_COM_WRITE_ANDX )
      {
          smbTdsEncapsClientReq( sessionEntry,
                                 lcs->tdsEncaps,
                                 data,
                                 length );
          break;
      }

  } while (0);
}


//-----------------------------------------------------------------------
// SendAppLogoutEvent()
//-----------------------------------------------------------------------
void SmbDecode::SendAppLogoutEvent( SessionEntry *sessionEntry,
                                    SmbSsnTid *ssnTid )
{
    // Prepare for an Application Logout
    encEngFmt->restoreSessionEntry(  sessionEntry,
                                    &ssnTid->seCtxt );

    // Generate an App Logout event
    if( encodingEngine->ApplicationIsLoggedIn(sessionEntry) )
    {
        encodingEngine->ApplicationLogout( sessionEntry );
        SmbIntLog("  APP_LOGOUT");

        // Application logout frees sessionDetail so we note
        // that in the TID
        ssnTid->ctxtIsEmpty = true;
        ssnTid->seCtxt.sessionDetail = NULL;
    }
}

//-----------------------------------------------------------------------
// smbHandleNegotiate()
//-----------------------------------------------------------------------
void SmbDecode::smbHandleNegotiate( SessionEntry *sessionEntry,
                                    const u_char *data,
                                    tz_uint32     length )
{
  SmbHeader        *smbHeader;
  tz_uint16         uid, pid, mid, tid;
  SmbInfo          *smbInfo = (SmbInfo *)sessionEntry->appInfo;

  smbHeader = (SmbHeader *)(data + sizeof(NBHeader));
  uid = stohs(smbHeader->userId);
  pid = stohs(smbHeader->processId);
  mid = stohs(smbHeader->multiplexId);
  tid = stohs(smbHeader->treeId);


  do
  {
      // == S E R V E R   S I D E ==
      if( sessionEntry->trafficDirection == TRAFFIC_FROM_SERVER )
      {
          // Assume it's an NTLM 0.12 dialect response
          SmbNegotiateNTLM012Response *rsp =
              (SmbNegotiateNTLM012Response *)(data + sizeof(NBHeader)
                                               + sizeof(SmbHeader) );

          // NOw verify that with the known byte count
          if( rsp->wordCount == 17 )
          {
              // It is NTLM 0.12
              smbInfo->capabilities = rsp->capabilities;

              // Save the server's max multiplex response
              smbInfo->srvMaxMpxCount = rsp->maxMpxCnt;

              // D E B U G
              //printf("  (%d)", rsp->maxMpxCnt );
              //fflush( stdout );
          }

      } 
      else   // == C L I E N T   S I D E ==    (TRAFFIC_FROM_CLIENT)
      {
          // Ignore client side for now...

      }
  }
  while (0);

  // This is a "non-Andx" command so terminate the chain
  andxCmdState.cmd = 0xff;
}

//-----------------------------------------------------------------------
// smbHandleSessionSetupAndx()
//     Handle user authentication for NTLMSSP
//
//-----------------------------------------------------------------------
void SmbDecode::smbHandleSessionSetupAndx( SessionEntry *sessionEntry,
                                           const u_char *data,
                                           tz_uint32 length )
{
  SmbHeader        *smbHeader;
  tz_uint32         ntStatus = 0;


  smbHeader = (SmbHeader *)(data + sizeof(NBHeader));

#if 0  // D E B U G
  printf("\n");
  smbCmdDump( smbHeader->command, sessionEntry->trafficDirection, data, length );
#endif

  do
  {
      // == S E R V E R   S I D E ==
      if( sessionEntry->trafficDirection == TRAFFIC_FROM_SERVER )
      {

          SmbInfo *smbInfo = (SmbInfo *)sessionEntry->appInfo;
          ntStatus = stohl(smbHeader->status.NTstatus);
          if( ntStatus == 0 )
          {
              // Successful user authentication

              void    *hdr;

              if( andxCmdState.chainCnt == 1 )
              {
                  hdr = (void *)
                         (data + sizeof(NBHeader) + sizeof(SmbHeader) );
              } else {
                  hdr = (void *)
                       (data + sizeof(NBHeader) + andxCmdState.offset );
              }

              // Dispatch to security/no-security processing
              if( smbInfo->authMode == SMB_AUTHMODE_NOEXTSEC )
              {
                  // ASSume "no extended security"
                  smbAuthNoExtSec( sessionEntry, smbHeader, hdr );
              } else {
                  // ASSume "extended security".
                  smbAuthExtSec( sessionEntry, smbHeader, hdr );
              }

              // Determine the negotiated max multiplex count
              if( smbInfo->srvMaxMpxCount )
              {
                  // The server has specified a max
                  tz_uint16 negMaxMpxCnt = MIN(smbInfo->cliMaxMpxCount,
                                               smbInfo->srvMaxMpxCount);

                  // Save result in server copy
                  smbInfo->srvMaxMpxCount = negMaxMpxCnt;
              } else {
                  // Use the client's request
                  smbInfo->srvMaxMpxCount = smbInfo->cliMaxMpxCount;
              }

              // D E B U G
              //printf("  <%d>", smbInfo->srvMaxMpxCount );
              //fflush( stdout );

          }
          else
          {
              // Put an end to any command chain processing
              andxCmdState.cmd = 0xff;

              // Check for Login Failure and declare if so
              if( ntStatus == STATUS_LOGON_FAILURE )
              {
                  sprintf( currCmdStg, "Login Failure %s", 
                                      smbUtilNtStatus2String(ntStatus));

                  // Consecutive failures on the same session
                  if( ++smbInfo->authFailCnt >= 1 )
                  {
                      if( myLmCfg.fileshareIsEnabled )
                      {
                          encEngFmt->sendLoginFailureEvent( encodingEngine,
                                                            sessionEntry,
                                                            currCmdStg );
                      }

                      // Reset the count
                      smbInfo->authFailCnt = 0;
                  }

                  // Consecutive failures on different sessions (for
                  // example, login in as an unknown user)
                  if( ++authFailCnt >= 3 )
                  {
                      if( myLmCfg.fileshareIsEnabled )
                      {
                          encEngFmt->sendLoginFailureEvent( encodingEngine,
                                                            sessionEntry,
                                                            currCmdStg );
                      }

                      // Reset the count
                      authFailCnt = 0;
                  }
              }

              SmbIntLog("  %s", smbUtilNtStatus2String(ntStatus) );
          }
      } 
      else  // == C L I E N T   S I D E ==    (TRAFFIC_FROM_CLIENT)
      {
          if( stohl(smbHeader->status.NTstatus) == 0 )
          {
              void    *hdr;

              if( andxCmdState.chainCnt == 1 )
              {
                  hdr = (void *)
                         (data + sizeof(NBHeader) + sizeof(SmbHeader) );
              } else {
                  hdr = (void *)
                       (data + sizeof(NBHeader) + andxCmdState.offset );
              }

              // Record the capfile name to the decode log
              SmbDcdLog( sessionEntry,"CAP     %s", 
                                     netMonDriver->markerPacketString );

              // Use wordCount to distinguish between Extended Security
              // or no Extended Security
              SmbInfo *smbInfo = (SmbInfo *)sessionEntry->appInfo;
              tz_uint8 wordCount = *((tz_uint8 *)hdr);
              switch( wordCount )
              {
              case 12:
                  // Set the generic EXTSEC mode.
                  smbInfo->authMode = SMB_AUTHMODE_EXTSEC;
                  smbAuthExtSec( sessionEntry, smbHeader, hdr );
                  break;
              case 13:
                  // No External Security
                  smbInfo->authMode = SMB_AUTHMODE_NOEXTSEC;
                  smbAuthNoExtSec( sessionEntry, smbHeader, hdr );
                  break;
              default:
                  SmbErrLog(LOG_NOTICE, "Unknown security wordcount %d",
                                                          wordCount );
                  break;
              }

          }
          else
          {
              // NT Status failure code
              // Put an end to any command chain processing
              andxCmdState.cmd = 0xff;
          }
      }
  } while (0);

  ++andxCmdState.chainCnt;
}

//-----------------------------------------------------------------------
// smbHandleLogoffAndx()
//-----------------------------------------------------------------------
void SmbDecode::smbHandleLogoffAndx( SessionEntry *sessionEntry,
                                     const u_char *data,
                                     tz_uint32 length )
{
  SmbHeader *smbHeader;
  tz_uint16 uid, pid, mid, tid;

  smbHeader = (SmbHeader *)(data + sizeof(NBHeader));
  uid = stohs(smbHeader->userId);
  pid = stohs(smbHeader->processId);
  mid = stohs(smbHeader->multiplexId);
  tid = stohs(smbHeader->treeId);


  do
  {
      // == S E R V E R   S I D E ==
      if( sessionEntry->trafficDirection == TRAFFIC_FROM_SERVER )
      {
          if( stohl(smbHeader->status.NTstatus) == 0 )
          {
              // Successful user logoff

              // Nothing currently to do here ...
          }

          // Regardless of success or failure, remove UID from list
          SmbSsnDataRemoveUid( sessionEntry, uid);

      } 
      else   // == C L I E N T   S I D E ==    (TRAFFIC_FROM_CLIENT)
      {
      }
  }
  while (0);

  // Even though this is an Andx command we are going to just 
  // terminate the chain
  andxCmdState.cmd = 0xff;
}

//-----------------------------------------------------------------------
// smbHandleTreeConnectAndx()
//    Mount a server resource.  From this transaction we recover
//    - ShareName
//    - ServerInfo (the server name)
//
//    A successful server response returns a TID which represents
//    access to a mount point on a server.  (The pathname and file
//    or directory are obtained through individual operations like
//    NtCreateAndx which pass the TID as the mount point).
//
//    There are many Tree Connects to IPC$.  The current way of handling
//    these is to just process them.  Shortly after the client finishes
//    using the IPC$ to get info about the share on the server it then
//    issues a Tree Disconnect which cleans things up.  We just allow
//    this all to happen.
//
//    The first TreeConnect which occurs after successful SessionSetup
//    and UID assignment is where the sessionDetail is filled out by
//    the Encoding Engine
//-----------------------------------------------------------------------
void SmbDecode::smbHandleTreeConnectAndx( SessionEntry *sessionEntry,
                                          const u_char *data,
                                          tz_uint32 length )
{
  tz_uint32         status;
  SmbHeader        *smbHeader;
  tz_uint16         uid, pid, mid, tid;
  SmbSsnUid        *ssnUid;
  SmbSsnUid        *ssnUidAndx;
  SmbSsnPidMid     *ssnPidMid;
  tz_uint32         ntStatus = 0;
  tz_uint32         safeLen = 0;

  smbHeader = (SmbHeader *)(data + sizeof(NBHeader));
  uid       = stohs(smbHeader->userId);
  pid       = stohs(smbHeader->processId);
  mid       = stohs(smbHeader->multiplexId);
  tid       = stohs(smbHeader->treeId);

#if 0  // D E B U G
  printf("\n");
  smbCmdDump( smbHeader->command, sessionEntry->trafficDirection, data, length );
#endif

  do
  {
      // == S E R V E R   S I D E ==
      //
      if( sessionEntry->trafficDirection == TRAFFIC_FROM_SERVER )
      {
          SmbInfo *smbInfo = (SmbInfo *)sessionEntry->appInfo;
          SmbTreeConnectAndxResponse *rsp;

          ntStatus = stohl(smbHeader->status.NTstatus);

          if( andxCmdState.chainCnt == 1 )
          {
              // Solo (Non-andx Chained Command)
              rsp = (SmbTreeConnectAndxResponse *)
                           (data + sizeof(NBHeader) + sizeof(SmbHeader) );

              // Update Andx State
              if( ntStatus == 0 )
              {
                  andxCmdState.cmd = rsp->andxCommand;
                  andxCmdState.offset = stohs(rsp->andxOffset);
              } else {
                  // Status returned, response payload is invalid
                  andxCmdState.cmd = 0xff;
              }

              // Look up PidMid
              status = SmbSsnFindSsnDescrsUid( sessionEntry, uid, smbHeader,
                                            &ssnUid, &ssnPidMid, NULL, NULL );
              if( status != SMB_ERROR_NONE )
              {
                  //SmbErrLog(LOG_NOTICE,"%04x  %04x  %04x  %04x %s", 
                  //         uid, pid, mid,tid, smbUtilError2String(status));
                  smbUtilErrorUpdateStats( status );

                  SmbIntLog("  Descr ERROR  %s", smbUtilError2String(status) );
                  break;
              }
          } else {
              rsp = (SmbTreeConnectAndxResponse *)
                         (data + sizeof(NBHeader) + andxCmdState.offset );

              // Update Andx State
              if( ntStatus == 0 )
              {
                  andxCmdState.cmd = rsp->andxCommand;
                  andxCmdState.offset = stohs(rsp->andxOffset);
              } else {
                  // Status returned, response payload is invalid
                  andxCmdState.cmd = 0xff;
              }

              // Look up PidMid based on the UID used in the request
              status = SmbSsnFindSsnDescrsUid( sessionEntry, 
                                               smbInfo->treeConnectReqUid,
                          smbHeader, &ssnUidAndx, &ssnPidMid, NULL, NULL );

              if( status != SMB_ERROR_NONE )
              {
                  //SmbErrLog(LOG_NOTICE,"%04x  %04x  %04x  %04x %s",
                  //         uid, pid, mid,tid, smbUtilError2String(status));
                  smbUtilErrorUpdateStats( status );

                  SmbIntLog("  Descr ERROR  %s", smbUtilError2String(status) );
                  break;
              }
          }

          if( ntStatus != 0 )
          {
              // Put an end to any command chain processing
              andxCmdState.cmd = 0xff;

              if( andxCmdState.chainCnt == 1 )
              {
                  // Remove the PidMid entry
                  if( SmbSsnDataRemovePidMid(sessionEntry, ssnUid, pid, mid) == IIMS_FAILURE )
                  {
                      //SmbErrLog(LOG_NOTICE,"Failed Remove pid %04x mid %04x "
                      //                   "on uid %04x", pid, mid, uid );
                      ++decodeStats.failedRemove;

                      SmbIntLog("  Descr ERROR - Failed Remove PidMid UID %04x",
                                                                             uid );
                  }
              } else {
                  // Remove the UID 0 PidMid entry
                  if( SmbSsnDataRemovePidMid(sessionEntry, ssnUidAndx, pid, mid) == IIMS_FAILURE )
                  {
                      //SmbErrLog(LOG_NOTICE,"Failed Remove pid %04x mid %04x "
                      //                   "on uid %04x", pid, mid, 0 );
                      ++decodeStats.failedRemove;

                      SmbIntLog("  Descr ERROR - Failed Remove PidMid UID 0" );
                  }
                  // Remove ssnUid for UID0
                  SmbSsnDataRemoveUid( sessionEntry, 0);
              }

              // Send up a Login Failure event
              sprintf( currCmdStg, "Login Failure %s", 
                                  smbUtilNtStatus2String(ntStatus));

              if( myLmCfg.fileshareIsEnabled )
              {
                  encEngFmt->sendLoginFailureEvent( encodingEngine,
                                                    sessionEntry,
                                                    currCmdStg );
              }

              SmbIntLog("  %s", smbUtilNtStatus2String(ntStatus) );
              break;
          }

          // Successful TreeConnectAndx means "no Login Failure"
          smbInfo->authFailCnt = 0;
          authFailCnt = 0;

          if( andxCmdState.chainCnt == 1 )
          {
              // Solo (Non-andx Chained Command) Processing

              // Add the new Tid
              if( SmbSsnDataAddTid( sessionEntry, ssnUid, tid ) == IIMS_FAILURE  )
              {
                  //SmbErrLog(LOG_NOTICE,"%04x  %04x  %04x  %04x %s", 
                  //    uid, pid, mid,tid, smbUtilError2String(SMB_ERROR_TID_CREATE));
                  smbUtilErrorUpdateStats( SMB_ERROR_TID_CREATE );

                  SmbIntLog("  Descr ERROR  %s", 
                               smbUtilError2String(SMB_ERROR_TID_CREATE) );
                  break;
              }
              SmbSsnTid *ssnTid = SmbSsnDataFindByTid( ssnUid, tid );
              if( ssnTid == NULL )
              {
                  //SmbErrLog(LOG_NOTICE,"%04x  %04x  %04x  %04x %s", 
                  //  uid, pid, mid,tid, smbUtilError2String(SMB_ERROR_NO_TID_DESCR));
                  smbUtilErrorUpdateStats( SMB_ERROR_NO_TID_DESCR );

                  SmbIntLog("  Descr ERROR  %s", 
                               smbUtilError2String(SMB_ERROR_NO_TID_DESCR) );

                  break;
              }

              // Parse this into servername and sharename
              encEngFmt->parseServerShare( ssnPidMid->filename,
                                           ssnTid->servername,
                                           ssnTid->sharename );

              if( SmbDebug::logIsEnabled )
              {
                  SmbIntLog("  server: %s share: %s ", ssnTid->servername, 
                                                       ssnTid->sharename );
                  if( smbInfo->domainName[0] != '\0' ) {
                      SmbIntLog("(%s)", smbInfo->domainName );
                  }
              }

              // Check for hidden share name
              if( smbUtilIsHiddenShare(ssnTid->sharename) )
              {
                  // Do not generate events
                  ssnTid->isEventSource = false;

                  SmbIntLog("  NO_EVTS" );
              }

              // Remove the PidMid entry
              if( SmbSsnDataRemovePidMid(sessionEntry, ssnUid, pid, mid) == IIMS_FAILURE )
              {
                  //SmbErrLog(LOG_NOTICE,"Failed Remove pid %04x mid %04x on uid %04x",
                  //                                      pid, mid, uid );
                  ++decodeStats.failedRemove;

                  SmbIntLog("  Descr ERROR - Failed Remove PidMid" );
              }
          }
          else
          {
              // Andx Chained Command Processing

              // Look up ssnUid based on new UID assigned by server
              status = SmbSsnFindSsnDescrsUid( sessionEntry, uid, smbHeader,
                                            &ssnUid, NULL, NULL, NULL );
              if( status != SMB_ERROR_NONE )
              {
                  //SmbErrLog(LOG_NOTICE,"%04x  %04x  %04x  %04x %s", 
                  //          uid, pid, mid,tid, smbUtilError2String(status));
                  smbUtilErrorUpdateStats( status );

                  SmbIntLog("  Descr ERROR  %s", smbUtilError2String(status) );
                  break;
              }

              // Save the new TID for chained commands
              //andxCmdState.tid = tid;

              // Add the new Tid on the new UID ssnUid
              if( SmbSsnDataAddTid( sessionEntry, ssnUid, tid ) == IIMS_FAILURE  )
              {
                  //SmbErrLog(LOG_NOTICE,"%04x  %04x  %04x  %04x %s", 
                  //  uid, pid, mid,tid, smbUtilError2String(SMB_ERROR_TID_CREATE));
                  smbUtilErrorUpdateStats( SMB_ERROR_TID_CREATE );

                  SmbIntLog("  Descr ERROR  %s",
                               smbUtilError2String(SMB_ERROR_TID_CREATE) );
                  break;
              }
              SmbSsnTid *ssnTid = SmbSsnDataFindByTid( ssnUid, tid );
              if( ssnTid == NULL )
              {
                  //SmbErrLog(LOG_NOTICE,"%04x  %04x  %04x  %04x %s", 
                  //  uid, pid, mid,tid, smbUtilError2String(SMB_ERROR_NO_TID_DESCR));
                  smbUtilErrorUpdateStats( SMB_ERROR_NO_TID_DESCR );

                  SmbIntLog("  Descr ERROR  %s",
                             smbUtilError2String(SMB_ERROR_NO_TID_DESCR) );
                  break;
              }

              // Parse this (from UID 0 ssnPidMid) into servername and
              // sharename
              encEngFmt->parseServerShare( ssnPidMid->filename,
                                           ssnTid->servername,
                                           ssnTid->sharename );

              if( SmbDebug::logIsEnabled )
              {
                  SmbIntLog("  server: %s  share: %s ", ssnTid->servername, 
                                                     ssnTid->sharename );
                  if( smbInfo->domainName[0] != '\0' ) {
                      SmbIntLog("(%s)", smbInfo->domainName );
                  }
              }

              // Check for hidden share name
              if( smbUtilIsHiddenShare(ssnTid->sharename) )
              {
                  // Do not generate events
                  ssnTid->isEventSource = false;

                  SmbIntLog("  NO_EVTS" );
              }

              // Remove the UID-Andx PidMid entry
              if( SmbSsnDataRemovePidMid(sessionEntry, ssnUidAndx, pid, mid) == IIMS_FAILURE )
              {
                  //SmbErrLog(LOG_NOTICE,"Failed Remove pid %04x mid %04x on uid %04x",
                  //                                      pid, mid, 0 );
                  ++decodeStats.failedRemove;

                  SmbIntLog("  Descr ERROR - Failed Remove PidMid" );
              }

              // Remove ssnUid for UID0
              SmbSsnDataRemoveUid( sessionEntry, 0);
          }

      } 
      else    // == C L I E N T   S I D E ==    (TRAFFIC_FROM_CLIENT)
      {
          SmbTreeConnectAndxRequest *req;

          if( andxCmdState.chainCnt == 1 )
          {
              req = (SmbTreeConnectAndxRequest *)
                         (data + sizeof(NBHeader) + sizeof(SmbHeader) );
          } else {
              req = (SmbTreeConnectAndxRequest *)
                       (data + sizeof(NBHeader) + andxCmdState.offset );
          }

          // Update Andx State
          andxCmdState.cmd = req->andxCommand;
          andxCmdState.offset = stohs(req->andxOffset);
#if 0
          if( stohl(smbHeader->status.NTstatus) != 0 )
          {
              // Put an end to any command chain processing
              andxCmdState.cmd = 0xff;
              break;
          }
#endif
          // If we're in Session jump-in mode then check to see if we
          // have a ssnUid for this UID and, if not, create it.
          // We also want to do this if we're using chained commands
          // in which case the UID will be 0 or some other temporary UID.
          if( !smbLoginIsRequired || andxCmdState.chainCnt > 1 )
          {
              // Session jump-in mode.  Check to see if we have a Uid
              // and, if not, create it
              SmbSsnUid *ssnUid = SmbSsnDataFindByUid( sessionEntry, uid );
              if( ssnUid == NULL )
              {
                  SmbSsnDataAddUid( sessionEntry, uid );
                  SmbMonLog("Fabricated UID %04x", uid);
              }
          }

          // Create a PidMid
          status = SmbSsnCreateSsnPidMid( sessionEntry,
                                          smbHeader,
                                          &ssnPidMid );
          if( status != SMB_ERROR_NONE )
          {
              //SmbErrLog(LOG_NOTICE,"%04x  %04x  %04x  %04x %s", 
              //             uid, pid, mid,tid, smbUtilError2String(status));
              smbUtilErrorUpdateStats( status );

              SmbIntLog("  Descr ERROR  %s", smbUtilError2String(status) );
              break;
          }

          // Calculate the start of the path info which is variable
          // depending on how long the password field is
          tz_int8 *path =  (tz_int8 *)( (tz_int8 *)&req->password
                                       + stohs(req->passwordLen));

          // Save the file or directory path and name
          memset( ssnPidMid->filename, 0, TZX_512_STRING );
          if( stohs(smbHeader->flags2) & SMB_FLAGS2_UNICODE )
          {
              // Unicode translation with even valued max length
              // to prevent scribbler behavior
              safeLen = (TZX_512_STRING - 1) * 2;
              smbUtilUnicodeToAscii( path, safeLen, ssnPidMid->filename );
          }
          else
          {
              safeLen = MIN( TZX_512_STRING - 1,
                             strlen(path) +1 );

              memcpy( ssnPidMid->filename, path, safeLen );
          }

          // Save the UID on which the request was made.  This matters in
          // the Andx request where the req UID is different than the rsp
          SmbInfo *smbInfo = (SmbInfo *)sessionEntry->appInfo;
          smbInfo->treeConnectReqUid = uid;
      }

  } while(0);

  ++andxCmdState.chainCnt;
}


//-----------------------------------------------------------------------
// smbHandleTreeDisconnect()
//     Free the Tid descriptor associated with the TID value passed
//     in the SmbHeader
//-----------------------------------------------------------------------
void SmbDecode::smbHandleTreeDisconnect( SessionEntry *sessionEntry,
                                         const u_char *data,
                                         tz_uint32 length )
{
  tz_uint32         status;
  SmbHeader        *smbHeader;
  tz_uint16         uid, pid, mid, tid;
  SmbSsnUid        *ssnUid;
  SmbSsnTid        *ssnTid;

  smbHeader = (SmbHeader *)(data + sizeof(NBHeader));
  uid       = stohs(smbHeader->userId);
  pid       = stohs(smbHeader->processId);
  mid       = stohs(smbHeader->multiplexId);
  tid       = stohs(smbHeader->treeId);

  do
  {
      // == S E R V E R   S I D E ==
      //
      if( sessionEntry->trafficDirection == TRAFFIC_FROM_SERVER )
      {
          //SmbTreeDisconnectResponse *rsp =
          //  (SmbTreeDisconnectResponse *)(data + sizeof(NBHeader)
          //                                   + sizeof(SmbHeader) );

          if( stohl(smbHeader->status.NTstatus) != 0 )
          {
              break;
          }

          status = SmbSsnFindSsnDescrs( sessionEntry, smbHeader,
                                        &ssnUid, NULL, NULL, &ssnTid );
          if( status != SMB_ERROR_NONE )
          {
              // We ignore this error because the client often does a
              // Logoff before a Disconnect so the UID is already gone
              // when Disconnect is executed
              if(   status != SMB_ERROR_NO_UID_DESCR
                 && status != SMB_ERROR_NO_TID_DESCR )
              {
                  //SmbErrLog(LOG_NOTICE,"%04x  %04x  %04x  %04x %s", 
                  //         uid, pid, mid,tid, smbUtilError2String(status));
                  smbUtilErrorUpdateStats( status );

                  SmbIntLog("  Descr ERROR  %s", smbUtilError2String(status) );
              }
              break;
          }

          // Remove the Tid descriptor
          if( SmbSsnDataRemoveTid(sessionEntry, ssnUid, ssnTid->tid)
                                                      == IIMS_FAILURE )
          {
              //SmbErrLog(LOG_NOTICE,"%04x  %04x  %04x  %04x %s", 
              //  uid, pid, mid,tid, smbUtilError2String(SMB_ERROR_NO_TID_DESCR));
              smbUtilErrorUpdateStats( SMB_ERROR_NO_TID_DESCR );

              SmbIntLog("  Descr ERROR  %s",
                             smbUtilError2String(SMB_ERROR_NO_TID_DESCR) );
          }

      } 
      else    // == C L I E N T   S I D E ==    (TRAFFIC_FROM_CLIENT)
      {
          //SmbTreeDisconnectRequest *req =
          //      (SmbTreeDisconnectRequest *)(data + sizeof(NBHeader)
          //                                      + sizeof(SmbHeader) );

          if( stohl(smbHeader->status.NTstatus) != 0 )
          {
              break;
          }

          // TreeDisconnect should not fabricate a UID descr
#if 0
          if( !smbLoginIsRequired )
          {
              // Session jump-in mode.  Check to see if we have a Uid
              // and, if not, create it
              SmbSsnUid *ssnUid = SmbSsnDataFindByUid( sessionEntry, uid );
              if( ssnUid == NULL )
              {
                  SmbSsnDataAddUid( sessionEntry, uid );
                  SmbMonLog("Fabricated UID %04x", uid);
              }
          }
#endif

      }

  } while(0);

  // This is a "non-Andx" command so terminate the chain
  andxCmdState.cmd = 0xff;
}

//-----------------------------------------------------------------------
// smbHandleCreate()
// 
//-----------------------------------------------------------------------
void SmbDecode::smbHandleCreate( SessionEntry *sessionEntry,
                                 const u_char *data,
                                 tz_uint32 length )
{
  tz_uint32         status;
  SmbHeader        *smbHeader;
  tz_uint16         uid, pid, mid, tid;
  SmbSsnUid        *ssnUid;
  SmbSsnPidMid     *ssnPidMid;
//SmbSsnFid        *ssnFid;
  SmbSsnTid        *ssnTid;
  tz_uint32         ntStatus = 0;
  tz_uint32         safeLen = 0;
  SmbInfo          *smbInfo = (SmbInfo *)sessionEntry->appInfo;

  smbHeader = (SmbHeader *)(data + sizeof(NBHeader));
  uid       = stohs(smbHeader->userId);
  pid       = stohs(smbHeader->processId);
  mid       = stohs(smbHeader->multiplexId);
  tid       = stohs(smbHeader->treeId);


  do
  {
      // == S E R V E R   S I D E ==
      //
      if( sessionEntry->trafficDirection == TRAFFIC_FROM_SERVER )
      {
          SmbCreateResponse *rsp =
              (SmbCreateResponse *)(data + sizeof(NBHeader)
                                               + sizeof(SmbHeader) );

          // Look up PidMid and Fid
          status = SmbSsnFindSsnDescrs( sessionEntry, smbHeader,
                                        &ssnUid, &ssnPidMid, NULL, &ssnTid );
          if( status != SMB_ERROR_NONE )
          {
              //SmbErrLog(LOG_NOTICE,"%04x  %04x  %04x  %04x %s", 
              //             uid, pid, mid,tid, smbUtilError2String(status));
              smbUtilErrorUpdateStats( status );

              SmbIntLog("  Descr ERROR  %s", smbUtilError2String(status) );
              break;
          }

          ntStatus = stohl(smbHeader->status.NTstatus);
          if( ntStatus != 0 )
          {
              // Remove the PidMid entry
              if( SmbSsnDataRemovePidMid(sessionEntry, ssnUid, pid, mid) == IIMS_FAILURE )
              {
                  //SmbErrLog(LOG_NOTICE,"Failed Remove pid %04x mid %04x on uid %04x",
                  //                                          pid, mid, uid );
                  ++decodeStats.failedRemove;

                  SmbIntLog("  Descr ERROR - Failed Remove PidMid" );
              }

              SmbIntLog("  %s", smbUtilNtStatus2String(ntStatus) );
              break;
          }

          // Before we actually generate an event let's check the filename
          // against a list of ones to be excluded.
          // 
          bool isEventSource = smbUtilIsEventSource( ssnPidMid->filename );

          // Content and Operation

          // Create the command string
          sprintf( currCmdStg, "CREATE  %s", ssnPidMid->filename);

          if( myLmCfg.fileshareIsEnabled &&
              isEventSource && ssnTid->isEventSource )
          {
              // Format Content and Operation
              encEngFmt->resetEvent( sessionEntry );
              encEngFmt->setDimFileContent( sessionEntry,
                                            ssnPidMid->filename,
                                            NULL,
                                            ssnTid->sharename,
                                            0 );
              encEngFmt->setDimOperation( sessionEntry,
                                          EVT_CREATE, "CREATE", 
                                          strlen("CREATE") +1 );
          }

          // Now on to server side stuff - obtain file size and FID
          tz_uint16 filesize = stohs(rsp->byteCount);
          tz_uint16 fid = stohs(rsp->fid);

          // Create a ssnFid and store the filename there.  We'll
          // need it when we CLOSE that fid
          if( SmbSsnDataAddFid(sessionEntry, ssnUid, fid) == IIMS_FAILURE )
          {
              //SmbErrLog(LOG_NOTICE,"%04x  %04x  %04x  %04x FID Create Failure",
              //                                         uid, pid, mid,tid );
              smbUtilErrorUpdateStats( SMB_ERROR_FID_CREATE );

              SmbIntLog("  Descr ERROR  %s", 
                               smbUtilError2String(SMB_ERROR_FID_CREATE) );
              break;
          }

          SmbSsnFid * ssnFid = SmbSsnDataFindByFid(ssnUid, fid);
          if( ssnFid == NULL )
          {
              //SmbErrLog(LOG_NOTICE,"%04x  %04x  %04x  %04x FID Find Failure",
              //                                         uid, pid, mid,tid );
              smbUtilErrorUpdateStats( SMB_ERROR_NO_FID_DESCR );

              SmbIntLog("  Descr ERROR  %s", 
                               smbUtilError2String(SMB_ERROR_NO_FID_DESCR) );
              break;
          }

          // Format the Fid entry
          memcpy( ssnFid->filename, ssnPidMid->filename,
                                    strlen(ssnPidMid->filename) +1 );
          ssnFid->tid = tid;
          if( !strcmp( ssnFid->filename, "\\spoolss") ) {
              ssnFid->mode = FID_MODE_NMD_PIPE_SPOOLSS;
              // FIX - for now we unconditionally create a content scanner
              ssnFid->serverCs = new ContentScanner( rspDataPatMgr );
              ssnFid->clientCs = new ContentScanner( cmdDataPatMgr );
          } else if(    myLmCfg.tdsNamedPipeIsEnabled
                     && smbTdsEncapsFidIsNP(sessionEntry, ssnFid->filename) )
          {
              ssnFid->mode = FID_MODE_NMD_PIPE_SQL;
          } else {
              ssnFid->mode = FID_MODE_FILESHARE;
              // FIX - for now we unconditionally create a content scanner
              ssnFid->serverCs = new ContentScanner( rspDataPatMgr );
              ssnFid->clientCs = new ContentScanner( cmdDataPatMgr );

              // D E B U G
              //SmbIntLog("  CS_NEW");
          }
          ssnFid->isEventSource = isEventSource;
          ssnFid->isDirectory = false;

          if( myLmCfg.fileshareIsEnabled &&
              isEventSource && ssnTid->isEventSource )
          {
              // Format Size and Response and generate the event
              encEngFmt->setDimSize( sessionEntry, filesize );
              encEngFmt->setDimResponse( sessionEntry, SUCCESSFUL_OPERATION );
              encEngFmt->sendCOSREvent( encodingEngine,
                                        sessionEntry,
                                        ssnUid,
                                        ssnTid,
                                        currCmdStg );
          }

          if( SmbDebug::logIsEnabled )
          {
              // Denote ignored events with '#'
              SmbIntLog(" %c%s  ", isEventSource && ssnTid->isEventSource
                                   ? ' ': '#', currCmdStg );
              SmbIntLog("(FID %04x) %d bytes", fid, filesize );
          }

          // We're done with the PidMid.  The Fid will live on until a
          // ClOSE is requested
          if( SmbSsnDataRemovePidMid(sessionEntry, ssnUid, pid, mid) == IIMS_FAILURE )
          {
              //SmbErrLog(LOG_NOTICE,"Failed Remove pid %04x mid %04x on uid %04x",
              //                                          pid, mid, uid );
              ++decodeStats.failedRemove;

              SmbIntLog("  Descr ERROR - Failed Remove PidMid" );
          }

      } 
      else    // == C L I E N T   S I D E ==    (TRAFFIC_FROM_CLIENT)
      {
          SmbCreateRequest *req =
                  (SmbCreateRequest *)(data + sizeof(NBHeader)
                                                  + sizeof(SmbHeader) );

#if 0
          if( stohl(smbHeader->status.NTstatus) != 0 )
          {
              break;
          }
#endif
          if( !smbLoginIsRequired )
          {
              // Session jump-in mode.  Check to see if we have a Uid
              // and, if not, create it
              SmbSsnUid *ssnUid = SmbSsnDataFindByUid( sessionEntry, uid );
              if( ssnUid == NULL )
              {
                  SmbSsnDataAddUid( sessionEntry, uid );
                  SmbMonLog("Fabricated UID %04x", uid);
              }
          }

          // Create a PidMid
          status = SmbSsnCreateSsnPidMid( sessionEntry,
                                          smbHeader,
                                          &ssnPidMid );
          if( status != SMB_ERROR_NONE )
          {
              //SmbErrLog(LOG_NOTICE,"%04x  %04x  %04x  %04x %s", 
              //             uid, pid, mid,tid, smbUtilError2String(status));
              smbUtilErrorUpdateStats( status );

              SmbIntLog("  Descr ERROR  %s", smbUtilError2String(status) );
              break;
          }

          // Save the pertinent info
          memset( ssnPidMid->filename, 0, TZX_512_STRING );
          if( stohs(smbHeader->flags2) & SMB_FLAGS2_UNICODE )
          {
              // Unicode translation with even valued max length
              // to prevent scribbler behavior
              safeLen = (TZX_512_STRING - 1) * 2;
              smbUtilUnicodeToAscii( req->filename, safeLen,
                                     ssnPidMid->filename );
          }
          else
          {
              safeLen = MIN( TZX_512_STRING - 1,
                             strlen(req->filename) +1 );

              memcpy( ssnPidMid->filename, req->filename, safeLen );
          }
          // we're done for now.  This info will be pushed up when the
          // server side response is received
      }
  } while(0);

  // This is a "non-Andx" command so terminate the chain
  andxCmdState.cmd = 0xff;
}



//-----------------------------------------------------------------------
// smbHandleNtCreateAndx()
//     Create or Open a file/directory.  From this transaction we recover
//     - FilePath (also valid if target is a directory)
//     - FolderName (if target is a directory)
//     - FileName, FileExtension, FileAttribute (when target is a file)
//     
//     A successful server response returns a FID.
//     Note that the PidMid context has to buffer the name of the file
//     until a FID is assigned.  From that point onward the Fid
//     context holds the filename.
//-----------------------------------------------------------------------
void SmbDecode::smbHandleNtCreateAndx( SessionEntry *sessionEntry,
                                       const u_char *data,
                                       tz_uint32 length )
{
  tz_uint32         status;
  SmbHeader        *smbHeader;
  tz_uint16         uid, pid, mid, tid;
  SmbSsnUid        *ssnUid;
  SmbSsnPidMid     *ssnPidMid;
  SmbSsnTid        *ssnTid;
  tz_uint32         ntStatus = 0;
  tz_uint32         safeLen = 0;
  SmbInfo          *smbInfo = (SmbInfo *)sessionEntry->appInfo;

  smbHeader = (SmbHeader *)(data + sizeof(NBHeader));
  uid       = stohs(smbHeader->userId);
  pid       = stohs(smbHeader->processId);
  mid       = stohs(smbHeader->multiplexId);
  tid       = stohs(smbHeader->treeId);

  do
  {
      // == S E R V E R   S I D E ==
      //
      if( sessionEntry->trafficDirection == TRAFFIC_FROM_SERVER )
      {
          SmbNTCreateAndXResponse *rsp;

          if( andxCmdState.chainCnt == 1 )
          {
              rsp = (SmbNTCreateAndXResponse *)
                         (data + sizeof(NBHeader) + sizeof(SmbHeader) );
          } else {
              rsp = (SmbNTCreateAndXResponse *)
                       (data + sizeof(NBHeader) + andxCmdState.offset );
          }

          // Update Andx State
          ntStatus = stohl(smbHeader->status.NTstatus);
          if( ntStatus == 0 )
          {
              andxCmdState.cmd = rsp->andxCommand;
              andxCmdState.offset = stohs(rsp->andxOffset);
          } else {
              // Status returned, response payload is invalid
              andxCmdState.cmd = 0xff;
          }

          // Look up the descriptors
          status = SmbSsnFindSsnDescrs( sessionEntry, smbHeader,
                                     &ssnUid, &ssnPidMid, NULL, &ssnTid );
          if( status != SMB_ERROR_NONE )
          {
              //SmbErrLog(LOG_NOTICE,"%04x  %04x  %04x  %04x %s", 
              //             uid, pid, mid,tid, smbUtilError2String(status));
              smbUtilErrorUpdateStats( status );

              SmbIntLog("  Descr ERROR  %s", smbUtilError2String(status) );
              break;
          }

          if( ntStatus != 0 )
          {
              // Put an end to any command chain processing
              andxCmdState.cmd = 0xff;

              sprintf( currCmdStg, "OPEN/CREATE failure: %s",
                                      smbUtilNtStatus2String(ntStatus));

              // Send up a failed event
              if(   myLmCfg.fileshareIsEnabled
                 && ntStatus != STATUS_OBJECT_NAME_NOT_FOUND
                 && ntStatus != STATUS_OBJECT_PATH_NOT_FOUND
                 && ssnTid->isEventSource )
              {
                  encEngFmt->resetEvent( sessionEntry );
                  encEngFmt->setDimFileContent( sessionEntry,
                                                ssnPidMid->filename,
                                                NULL,
                                                ssnTid->sharename,
                                                0 );
                  // We don't know what the OPERATION was going to be nor 
                  // what the SIZE dimension is because the server won't tell
                  // us when an error occurs.  To prevent filtering, handle
                  // it as EVT_UNKNOWN
                  encEngFmt->setDimOperation( sessionEntry,
                                              EVT_UNKNOWN, "", 1 );

                  // Operation dimension deliberately omitted

                  encEngFmt->setDimResponse( sessionEntry, FAILED_OPERATION );
                  encEngFmt->sendCOSREvent( encodingEngine,
                                            sessionEntry,
                                            ssnUid,
                                            ssnTid,
                                            currCmdStg );
              }

              SmbIntLog("  %s %s", ssnPidMid->filename,
                                       smbUtilNtStatus2String(ntStatus) );

              if( SmbSsnDataRemovePidMid(sessionEntry, ssnUid, pid, mid) == IIMS_FAILURE )
              {
                  //SmbErrLog(LOG_NOTICE,"Failed Remove pid %04x mid %04x "
                  //                       "on uid %04x", pid, mid, uid );
                  ++decodeStats.failedRemove;

                  SmbIntLog("  Descr ERROR - Failed Remove PidMid" );
              }
              break;
          }

          // Obtain the filename from the side session entry

          // Determine if action = OPEN (file existed) or CREATE 
          // (file did not exist)
          SmbEvtFiltEvent evt = EVT_UNKNOWN;
          switch ( stohl(rsp->createAction) )
          {
          case SMB_NT_CREATE_ANDX_CREATE_ACT_OPEN:
              strcpy( currCmdStg, "OPEN");
              evt = EVT_OPEN;
              break;
          case SMB_NT_CREATE_ANDX_CREATE_ACT_CREATE:
              strcpy( currCmdStg, "CREATE");
              evt = EVT_CREATE;
              break;
          case SMB_NT_CREATE_ANDX_CREATE_ACT_TRUNCATE:
              strcpy( currCmdStg, "TRUNCATE");
              evt = EVT_TRUNCATE;
              break;
          default:
              //SmbErrLog(LOG_NOTICE,"Unexpected Action %lx",
              //                                stohl(rsp->createAction));
              ++decodeStats.miscError;

              SmbIntLog("  Misc ERROR - Unexpected Action %lx ",
                                                stohl(rsp->createAction) );
              break;
          }

          // Before we actually generate an event let's check the filename
          // against a list of ones to be excluded.
          // 
          bool isEventSource = smbUtilIsEventSource( ssnPidMid->filename );

          // Content and Operation

          if( myLmCfg.fileshareIsEnabled &&
              isEventSource && ssnTid->isEventSource )
          {
              // Format Content and Operation
              encEngFmt->resetEvent( sessionEntry );
              if( rsp->isDirectory )
              {
                  encEngFmt->setDimFolderContent( sessionEntry,
                                                  ssnPidMid->filename,
                                                  NULL,
                                                  ssnTid->sharename,
                                                  0 );
              } else {
                  // file
                  encEngFmt->setDimFileContent( sessionEntry,
                                                ssnPidMid->filename,
                                                NULL,
                                                ssnTid->sharename,
                                                0 );
              }
              encEngFmt->setDimOperation( sessionEntry,
                                          evt, currCmdStg,
                                          strlen(currCmdStg) +1 );

              strcat( currCmdStg, "  ");
              strcat( currCmdStg, ssnPidMid->filename );
          }

          // Now on to server side stuff - obtain file size and FID
          tz_uint64 filesize = stohll(rsp->endOfFileOffset);
          tz_uint16 fid = stohs(rsp->fid);

          // Create a ssnFid and store the filename there.  We'll
          // need it when we CLOSE that fid
          if( SmbSsnDataAddFid(sessionEntry, ssnUid, fid) == IIMS_FAILURE )
          {
              //SmbErrLog(LOG_NOTICE,"%04x  %04x  %04x  %04x FID Create Failure",
              //                                         uid, pid, mid,tid );
              smbUtilErrorUpdateStats( SMB_ERROR_FID_CREATE );

              SmbIntLog("  Descr ERROR  %s", 
                               smbUtilError2String(SMB_ERROR_FID_CREATE) );
              break;
          }

          SmbSsnFid * ssnFid = SmbSsnDataFindByFid(ssnUid, fid);
          if( ssnFid == NULL )
          {
              //SmbErrLog(LOG_NOTICE,"%04x  %04x  %04x  %04x FID Find Failure",
              //                                         uid, pid, mid,tid );
              smbUtilErrorUpdateStats( SMB_ERROR_NO_FID_DESCR );

              SmbIntLog("  Descr ERROR  %s", 
                               smbUtilError2String(SMB_ERROR_NO_FID_DESCR) );
              break;
          }

          // Format the Fid entry
          memcpy( ssnFid->filename, ssnPidMid->filename,
                                    strlen(ssnPidMid->filename) +1 );
          ssnFid->tid = tid;
          if( !strcmp( ssnFid->filename, "\\spoolss") ) {
              ssnFid->mode = FID_MODE_NMD_PIPE_SPOOLSS;
              // FIX - for now we unconditionally create a content scanner
              ssnFid->serverCs = new ContentScanner( rspDataPatMgr );
              ssnFid->clientCs = new ContentScanner( cmdDataPatMgr );
          } else if(    myLmCfg.tdsNamedPipeIsEnabled
                     && smbTdsEncapsFidIsNP(sessionEntry, ssnFid->filename) )
          {
              ssnFid->mode = FID_MODE_NMD_PIPE_SQL;
          } else {
              ssnFid->mode = FID_MODE_FILESHARE;
              // FIX - for now we unconditionally create a content scanner
              ssnFid->serverCs = new ContentScanner( rspDataPatMgr );
              ssnFid->clientCs = new ContentScanner( cmdDataPatMgr );

              // D E B U G
              //SmbIntLog("  CS_NEW");
          }
          ssnFid->isEventSource = isEventSource;
          ssnFid->isDirectory = rsp->isDirectory ? true : false;

          // Size and Response, now generate the server side event

          if( myLmCfg.fileshareIsEnabled &&
              isEventSource && ssnTid->isEventSource )
          {
              encEngFmt->setDimSize( sessionEntry, filesize );
              encEngFmt->setDimResponse( sessionEntry, SUCCESSFUL_OPERATION );
              encEngFmt->sendCOSREvent( encodingEngine,
                                        sessionEntry,
                                        ssnUid,
                                        ssnTid,
                                        currCmdStg );
          }

          if( SmbDebug::logIsEnabled )
          {
              if( !isEventSource || !myLmCfg.fileshareIsEnabled) {
                  // We have to tack on the filename because it didn't
                  // happen as part of event generation
                  strcat( currCmdStg, "  ");
                  strcat( currCmdStg, ssnPidMid->filename );
              }
              // Denote ignored events with '#'
              SmbIntLog(" %c%s  ", isEventSource && ssnTid->isEventSource
                                   ? ' ': '#', currCmdStg );
              SmbIntLog("(FID %04x) %d bytes", fid, filesize );
          }

          // We're done with the PidMid.  The Fid will live on until a
          // ClOSE is requested
          if( SmbSsnDataRemovePidMid(sessionEntry, ssnUid, pid, mid) == IIMS_FAILURE )
          {
              //SmbErrLog(LOG_NOTICE,"Failed Remove pid %04x mid %04x on uid %04x",
              //                                          pid, mid, uid );
              ++decodeStats.failedRemove;

              SmbIntLog("  Descr ERROR - Failed Remove PidMid" );
          }

      } 
      else    // == C L I E N T   S I D E ==    (TRAFFIC_FROM_CLIENT)
      {
          SmbNTCreateAndXRequest *req;

          if( andxCmdState.chainCnt == 1 )
          {
              req = (SmbNTCreateAndXRequest *)
                         (data + sizeof(NBHeader) + sizeof(SmbHeader) );
          } else {
              req = (SmbNTCreateAndXRequest *)
                      (data + sizeof(NBHeader) + andxCmdState.offset );
          }

          // Update Andx State
          andxCmdState.cmd = req->andxCommand;
          andxCmdState.offset = stohs(req->andxOffset);
#if 0
          if( stohl(smbHeader->status.NTstatus) != 0 )
          {
              // Put an end to any command chain processing
              andxCmdState.cmd = 0xff;
              break;
          }
#endif
          if( !smbLoginIsRequired )
          {
              // Session jump-in mode.  Check to see if we have a Uid
              // and, if not, create it
              SmbSsnUid *ssnUid = SmbSsnDataFindByUid( sessionEntry, uid );
              if( ssnUid == NULL )
              {
                  SmbSsnDataAddUid( sessionEntry, uid );
                  SmbMonLog("Fabricated UID %04x", uid);
              }
          }

          // Create a PidMid and store the filename in it
          status = SmbSsnCreateSsnPidMid( sessionEntry,
                                          smbHeader,
                                          &ssnPidMid );
          if( status != SMB_ERROR_NONE )
          {
              //SmbErrLog(LOG_NOTICE,"%04x  %04x  %04x  %04x %s", 
              //             uid, pid, mid,tid, smbUtilError2String(status));
              smbUtilErrorUpdateStats( status );

              SmbIntLog("  Descr ERROR  %s", smbUtilError2String(status) );
              break;
          }

          // Save the pertinent info
          memset( ssnPidMid->filename, 0, TZX_512_STRING );
          if( stohs(smbHeader->flags2) & SMB_FLAGS2_UNICODE )
          {
              // For UNICODE, filenameLength excludes the null 00 00
              if( stohs(req->filenameLength) > 0 ) {
                  // Unicode translation with even valued max length
                  // to prevent scribbler behavior
                  safeLen = (TZX_512_STRING - 1) * 2;
                  smbUtilUnicodeToAscii( req->filename, safeLen,
                                                   ssnPidMid->filename );
              } else {
                  ssnPidMid->filename[0] = '\0';
              }
          }
          else
          {
              // For ASCII, filenameLength includes the null 00
              if( stohs(req->filenameLength) > 1 ) {
                  safeLen = MIN( TZX_512_STRING - 1,
                                 strlen(req->filename) +1 );

                  memcpy( ssnPidMid->filename, req->filename, safeLen );
              } else {
                  ssnPidMid->filename[0] = '\0';
              }
          }
          // we're done for now.  This info will be pushed up when the
          // server side response is received
      }

  } while(0);

  ++andxCmdState.chainCnt;
}

//-----------------------------------------------------------------------
// smbHandleOpen()                                            (Obsolete)
//     Open a file or directory.  From this transaction we recover
//     - FilePath (also valid if target is a directory)
//     - FolderName (if target is a directory)
//     - FileName, FileExtension, FileAttribute (when target is a file)
//     
//     A successful server response returns a FID.
//-----------------------------------------------------------------------
void SmbDecode::smbHandleOpen( SessionEntry *sessionEntry,
                               const u_char *data,
                               tz_uint32 length )
{
  tz_uint32         status;
  SmbHeader        *smbHeader;
  tz_uint16         uid, pid, mid, tid;
  SmbSsnUid        *ssnUid;
  SmbSsnPidMid     *ssnPidMid;
  SmbSsnTid        *ssnTid;
  tz_uint32         ntStatus = 0;
  tz_uint32         safeLen = 0;
  SmbInfo          *smbInfo = (SmbInfo *)sessionEntry->appInfo;

  smbHeader = (SmbHeader *)(data + sizeof(NBHeader));
  uid       = stohs(smbHeader->userId);
  pid       = stohs(smbHeader->processId);
  mid       = stohs(smbHeader->multiplexId);
  tid       = stohs(smbHeader->treeId);

  do
  {
      // == S E R V E R   S I D E ==
      //
      if( sessionEntry->trafficDirection == TRAFFIC_FROM_SERVER )
      {
          SmbOpenResponse *rsp =
              (SmbOpenResponse *)(data + sizeof(NBHeader)
                                               + sizeof(SmbHeader) );

          // Look up PidMid and Fid
          status = SmbSsnFindSsnDescrs( sessionEntry, smbHeader,
                                   &ssnUid, &ssnPidMid, NULL, &ssnTid );
          if( status != SMB_ERROR_NONE )
          {
              //SmbErrLog(LOG_NOTICE,"%04x  %04x  %04x  %04x %s", 
              //             uid, pid, mid,tid, smbUtilError2String(status));
              smbUtilErrorUpdateStats( status );

              SmbIntLog("  Descr ERROR  %s", smbUtilError2String(status) );
              break;
          }

          // F I X - check ErrorClass, could be a DOS error, if so, don't
          //         process like an NT status code
          ntStatus = stohl(smbHeader->status.NTstatus);
          if( ntStatus != 0 )
          {
              // Remove the PidMid entry
              if( SmbSsnDataRemovePidMid(sessionEntry, ssnUid, pid, mid) == IIMS_FAILURE )
              {
                  //SmbErrLog(LOG_NOTICE,"Failed Remove pid %04x mid %04x on uid %04x",
                  //                                          pid, mid, uid );
                  ++decodeStats.failedRemove;

                  SmbIntLog("  Descr ERROR - Failed Remove PidMid" );
              }

              SmbIntLog("  %s", smbUtilNtStatus2String(ntStatus) );
              break;
          }
          
          // Content and Operation

          // The operation is always OPEN
          strcpy( currCmdStg, "OPEN");

          if( myLmCfg.fileshareIsEnabled )
          {
              // Format Content and Operation
              encEngFmt->resetEvent( sessionEntry );
              if( stohs(rsp->fileAttrib) & SMB_OPEN_FILE_ATTRIB_IS_DIR )
              {
                  encEngFmt->setDimFolderContent( sessionEntry,
                                                  ssnPidMid->filename,
                                                  NULL,
                                                  ssnTid->sharename,
                                                  0 );
              } else {
                  // file
                  encEngFmt->setDimFileContent( sessionEntry,
                                                ssnPidMid->filename,
                                                NULL,
                                                ssnTid->sharename,
                                                0 );
              }
              encEngFmt->setDimOperation( sessionEntry,
                                          EVT_OPEN, currCmdStg, 
                                          strlen(currCmdStg) +1 );

              strcat( currCmdStg, "  ");
              strcat( currCmdStg, ssnPidMid->filename );
          }

          // Now on to server side stuff - obtain file size and FID
          tz_uint32 filesize = stohl(rsp->fileSize);
          tz_uint16 fid = stohs(rsp->fid);

          // Create a ssnFid and store the filename there.  We'll
          // need it when we CLOSE that fid
          if( SmbSsnDataAddFid(sessionEntry, ssnUid, fid) == IIMS_FAILURE )
          {
              //SmbErrLog(LOG_NOTICE,"%04x  %04x  %04x  %04x FID Create Failure",
              //                                         uid, pid, mid,tid );
              smbUtilErrorUpdateStats( SMB_ERROR_FID_CREATE );

              SmbIntLog("  Descr ERROR  %s", 
                               smbUtilError2String(SMB_ERROR_FID_CREATE) );
              break;
          }

          SmbSsnFid * ssnFid = SmbSsnDataFindByFid(ssnUid, fid);
          if( ssnFid == NULL )
          {
              //SmbErrLog(LOG_NOTICE,"%04x  %04x  %04x  %04x FID Find Failure",
              //                                         uid, pid, mid,tid );
              smbUtilErrorUpdateStats( SMB_ERROR_NO_FID_DESCR );

              SmbIntLog("  Descr ERROR  %s", 
                               smbUtilError2String(SMB_ERROR_NO_FID_DESCR) );
              break;
          }

          // Format the Fid entry
          memcpy( ssnFid->filename, ssnPidMid->filename,
                                    strlen(ssnPidMid->filename) +1 );
          ssnFid->tid = tid;
          if( !strcmp( ssnFid->filename, "\\spoolss") ) {
              ssnFid->mode = FID_MODE_NMD_PIPE_SPOOLSS;
              // FIX - for now we unconditionally create a content scanner
              ssnFid->serverCs = new ContentScanner( rspDataPatMgr );
              ssnFid->clientCs = new ContentScanner( cmdDataPatMgr );
          } else if(    myLmCfg.tdsNamedPipeIsEnabled
                     && smbTdsEncapsFidIsNP(sessionEntry, ssnFid->filename) )
          {
              ssnFid->mode = FID_MODE_NMD_PIPE_SQL;
          } else {
              ssnFid->mode = FID_MODE_FILESHARE;
              // FIX - for now we unconditionally create a content scanner
              ssnFid->serverCs = new ContentScanner( rspDataPatMgr );
              ssnFid->clientCs = new ContentScanner( cmdDataPatMgr );

              // D E B U G
              //SmbIntLog("  CS_NEW");
          }
          ssnFid->isEventSource = true;
          ssnFid->isDirectory = 
              (stohs(rsp->fileAttrib) & SMB_OPEN_FILE_ATTRIB_IS_DIR) ? true 
                                                                     : false;

          // Size and Response, now generate the server side event

          if( myLmCfg.fileshareIsEnabled )
          {
              encEngFmt->setDimSize( sessionEntry, filesize );
              encEngFmt->setDimResponse( sessionEntry, SUCCESSFUL_OPERATION );
              encEngFmt->sendCOSREvent( encodingEngine,
                                        sessionEntry,
                                        ssnUid,
                                        ssnTid,
                                        currCmdStg );
          }

          if( SmbDebug::logIsEnabled )
          {
              if( !myLmCfg.fileshareIsEnabled) {
                  // We have to tack on the filename because it didn't
                  // happen as part of event generation
                  strcat( currCmdStg, "  ");
                  strcat( currCmdStg, ssnPidMid->filename );
              }
              // Denote ignored events with '#'
              SmbIntLog(" %c%s  ", 1 ? ' ': '#', currCmdStg );
              SmbIntLog("(FID %04x %d bytes)", fid, filesize );
          }

          // We're done with the PidMid.  The Fid will live on until a
          // CLOSE is requested
          if( SmbSsnDataRemovePidMid(sessionEntry, ssnUid, pid, mid) == IIMS_FAILURE )
          {
              //SmbErrLog(LOG_NOTICE,"Failed Remove pid %04x mid %04x on uid %04x",
              //                                          pid, mid, uid );
              ++decodeStats.failedRemove;

              SmbIntLog("  Descr ERROR - Failed Remove PidMid" );
          }

      } 
      else    // == C L I E N T   S I D E ==    (TRAFFIC_FROM_CLIENT)
      {
          SmbOpenRequest *req =
                  (SmbOpenRequest *)(data + sizeof(NBHeader)
                                                  + sizeof(SmbHeader) );

          // F I X - check ErrorClass, could be a DOS error, if so, don't
          //         process like an NT status code
#if 0
          if( stohl(smbHeader->status.NTstatus) != 0 )
          {
              break;
          }
#endif
          if( !smbLoginIsRequired )
          {
              // Session jump-in mode.  Check to see if we have a Uid
              // and, if not, create it
              SmbSsnUid *ssnUid = SmbSsnDataFindByUid( sessionEntry, uid );
              if( ssnUid == NULL )
              {
                  SmbSsnDataAddUid( sessionEntry, uid );
                  SmbMonLog("Fabricated UID %04x", uid);
              }
          }

          // Create a PidMid and store the filename/dirname in it
          status = SmbSsnCreateSsnPidMid( sessionEntry,
                                          smbHeader,
                                          &ssnPidMid );
          if( status != SMB_ERROR_NONE )
          {
              //SmbErrLog(LOG_NOTICE,"%04x  %04x  %04x  %04x %s", 
              //            uid, pid, mid,tid, smbUtilError2String(status));
              smbUtilErrorUpdateStats( status );

              SmbIntLog("  Descr ERROR  %s", smbUtilError2String(status) );
              break;
          }

          // Copy the string
          memset( ssnPidMid->filename, 0, TZX_512_STRING );
          if( stohs(smbHeader->flags2) & SMB_FLAGS2_UNICODE )
          {
              // Unicode translation with even valued max length
              // to prevent scribbler behavior
              safeLen = (TZX_512_STRING - 1) * 2;
              smbUtilUnicodeToAscii( req->filename, safeLen,
                                     ssnPidMid->filename );
          }
          else
          {
              safeLen = MIN( TZX_512_STRING - 1,
                             strlen(req->filename) +1 );

              memcpy( ssnPidMid->filename, req->filename, safeLen );
          }

      }
  } while(0);

  // This is a "non-Andx" command so terminate the chain
  andxCmdState.cmd = 0xff;
}

//-----------------------------------------------------------------------
// smbHandleOpenAndx()                                         (Obsolete)
//     Open a file or directory.  From this transaction we recover
//     - FilePath (also valid if target is a directory)
//     - FolderName (if target is a directory)
//     - FileName, FileExtension, FileAttribute (when target is a file)
//     
//     A successful server response returns a FID.
//-----------------------------------------------------------------------
void SmbDecode::smbHandleOpenAndx( SessionEntry *sessionEntry,
                                   const u_char *data,
                                   tz_uint32 length )
{
  tz_uint32         status;
  SmbHeader        *smbHeader;
  tz_uint16         uid, pid, mid, tid;
  SmbSsnUid        *ssnUid;
  SmbSsnPidMid     *ssnPidMid;
  SmbSsnTid        *ssnTid;
  tz_uint32         ntStatus = 0;
  tz_uint32         safeLen = 0;
  SmbInfo          *smbInfo = (SmbInfo *)sessionEntry->appInfo;

  smbHeader = (SmbHeader *)(data + sizeof(NBHeader));
  uid       = stohs(smbHeader->userId);
  pid       = stohs(smbHeader->processId);
  mid       = stohs(smbHeader->multiplexId);
  tid       = stohs(smbHeader->treeId);

  do
  {
      // == S E R V E R   S I D E ==
      //
      if( sessionEntry->trafficDirection == TRAFFIC_FROM_SERVER )
      {
          SmbOpenAndxResponse *rsp;

          if( andxCmdState.chainCnt == 1 )
          {
              rsp = (SmbOpenAndxResponse *)
                         (data + sizeof(NBHeader) + sizeof(SmbHeader) );
          } else {
              rsp = (SmbOpenAndxResponse *)
                       (data + sizeof(NBHeader) + andxCmdState.offset );
          }

          // Update Andx State
          ntStatus = stohl(smbHeader->status.NTstatus);
          if( ntStatus == 0 )
          {
              andxCmdState.cmd = rsp->andxCommand;
              andxCmdState.offset = stohs(rsp->andxOffset);
          } else {
              // Status returned, response payload is invalid
              andxCmdState.cmd = 0xff;
          }

          // Look up PidMid and Fid
          status = SmbSsnFindSsnDescrs( sessionEntry, smbHeader,
                                  &ssnUid, &ssnPidMid, NULL, &ssnTid );
          if( status != SMB_ERROR_NONE )
          {
              //SmbErrLog(LOG_NOTICE,"%04x  %04x  %04x  %04x %s", 
              //             uid, pid, mid,tid, smbUtilError2String(status));
              smbUtilErrorUpdateStats( status );

              SmbIntLog("  Descr ERROR  %s", smbUtilError2String(status) );
              break;
          }

          if( ntStatus != 0 )
          {
              // Put an end to any command chain processing
              andxCmdState.cmd = 0xff;

              // Remove the PidMid entry
              if( SmbSsnDataRemovePidMid(sessionEntry, ssnUid, pid, mid) == IIMS_FAILURE )
              {
                  //SmbErrLog(LOG_NOTICE,"Failed Remove pid %04x mid %04x on uid %04x",
                  //                                          pid, mid, uid );
                  ++decodeStats.failedRemove;

                  SmbIntLog("  Descr ERROR - Failed Remove PidMid" );
              }

              SmbIntLog("  %s", smbUtilNtStatus2String(ntStatus) );
              break;
          }

          // Content and Operation

          // Create the command string
          strcpy( currCmdStg, "OPEN" );

          if( myLmCfg.fileshareIsEnabled )
          {
              // Format Content and Operation
              encEngFmt->resetEvent( sessionEntry );
              if( stohs(rsp->fileAttrib) & SMB_OPEN_FILE_ATTRIB_IS_DIR )
              {
                  encEngFmt->setDimFolderContent( sessionEntry,
                                                  ssnPidMid->filename,
                                                  NULL,
                                                  ssnTid->sharename,
                                                  0 );
              } else {
                  // file
                  encEngFmt->setDimFileContent( sessionEntry,
                                                ssnPidMid->filename,
                                                NULL,
                                                ssnTid->sharename,
                                                0 );
              }
              encEngFmt->setDimOperation( sessionEntry,
                                          EVT_OPEN, currCmdStg, 
                                          strlen(currCmdStg) +1 );

              strcat( currCmdStg, "  ");
              strcat( currCmdStg, ssnPidMid->filename );
          }

          // Now on to server side stuff - obtain file size and FID
          tz_uint32 filesize = stohl(rsp->fileSize);
          tz_uint16 fid = stohs(rsp->fid);

          // Create a ssnFid and store the filename there.  We'll
          // need it when we CLOSE that fid
          if( SmbSsnDataAddFid(sessionEntry, ssnUid, fid) == IIMS_FAILURE )
          {
              //SmbErrLog(LOG_NOTICE,"%04x  %04x  %04x  %04x FID Create Failure",
              //                                         uid, pid, mid,tid );
              smbUtilErrorUpdateStats( SMB_ERROR_FID_CREATE );

              SmbIntLog("  Descr ERROR  %s", 
                               smbUtilError2String(SMB_ERROR_FID_CREATE) );
              break;
          }

          SmbSsnFid * ssnFid = SmbSsnDataFindByFid(ssnUid, fid);
          if( ssnFid == NULL )
          {
              //SmbErrLog(LOG_NOTICE,"%04x  %04x  %04x  %04x FID Find Failure",
              //                                         uid, pid, mid,tid );
              smbUtilErrorUpdateStats( SMB_ERROR_NO_FID_DESCR );

              SmbIntLog("  Descr ERROR  %s", 
                               smbUtilError2String(SMB_ERROR_NO_FID_DESCR) );
              break;
          }

          // Format the Fid entry
          memcpy( ssnFid->filename, ssnPidMid->filename,
                                    strlen(ssnPidMid->filename) +1 );
          ssnFid->tid = tid;
          if( !strcmp( ssnFid->filename, "\\spoolss") ) {
              ssnFid->mode = FID_MODE_NMD_PIPE_SPOOLSS;
              // FIX - for now we unconditionally create a content scanner
              ssnFid->serverCs = new ContentScanner( rspDataPatMgr );
              ssnFid->clientCs = new ContentScanner( cmdDataPatMgr );
          } else if(    myLmCfg.tdsNamedPipeIsEnabled
                     && smbTdsEncapsFidIsNP(sessionEntry, ssnFid->filename) )
          {
              ssnFid->mode = FID_MODE_NMD_PIPE_SQL;
          } else {
              ssnFid->mode = FID_MODE_FILESHARE;
              // FIX - for now we unconditionally create a content scanner
              ssnFid->serverCs = new ContentScanner( rspDataPatMgr );
              ssnFid->clientCs = new ContentScanner( cmdDataPatMgr );

              // D E B U G
              //SmbIntLog("  CS_NEW");
          }
          ssnFid->isEventSource = true;
          ssnFid->isDirectory = 
              (stohs(rsp->fileAttrib) & SMB_OPEN_FILE_ATTRIB_IS_DIR) ? true 
                                                                     : false;

          // Size and Response, now generate the server side event

          if( myLmCfg.fileshareIsEnabled )
          {
              encEngFmt->setDimSize( sessionEntry, filesize );
              encEngFmt->setDimResponse( sessionEntry, SUCCESSFUL_OPERATION );
              encEngFmt->sendCOSREvent( encodingEngine,
                                        sessionEntry,
                                        ssnUid,
                                        ssnTid,
                                        currCmdStg );
          }

          if( SmbDebug::logIsEnabled ) {
              if( !myLmCfg.fileshareIsEnabled) {
                  // We have to tack on the filename because it didn't
                  // happen as part of event generation
                  strcat( currCmdStg, "  ");
                  strcat( currCmdStg, ssnPidMid->filename );
              }

              SmbIntLog(" %c%s  (FID %04x) %d bytes", 
                                     1 ? ' ': '#',
                                     currCmdStg, fid, filesize );
          }
          // We're done with the PidMid.  The Fid will live on until a
          // CLOSE is requested
          if( SmbSsnDataRemovePidMid(sessionEntry, ssnUid, pid, mid) == IIMS_FAILURE )
          {
              //SmbErrLog(LOG_NOTICE,"Failed Remove pid %04x mid %04x on uid %04x",
              //                                          pid, mid, uid );
              ++decodeStats.failedRemove;

              SmbIntLog("  Descr ERROR - Failed Remove PidMid" );
          }
      } 
      else    // == C L I E N T   S I D E ==    (TRAFFIC_FROM_CLIENT)
      {

          SmbOpenAndxRequest *req;

          if( andxCmdState.chainCnt == 1 )
          {
                req = (SmbOpenAndxRequest *)
                          (data + sizeof(NBHeader) + sizeof(SmbHeader));
          } else {
                req = (SmbOpenAndxRequest *)
                       (data + sizeof(NBHeader) + andxCmdState.offset );
          }

          // Update Andx State
          andxCmdState.cmd = req->andxCommand;
          andxCmdState.offset = stohs(req->andxOffset);
#if 0
          if( stohl(smbHeader->status.NTstatus) != 0 )
          {
              // Put an end to any command chain processing
              andxCmdState.cmd = 0xff;
              break;
          }
#endif
          if( !smbLoginIsRequired )
          {
              // Session jump-in mode.  Check to see if we have a Uid
              // and, if not, create it
              SmbSsnUid *ssnUid = SmbSsnDataFindByUid( sessionEntry, uid );
              if( ssnUid == NULL )
              {
                  SmbSsnDataAddUid( sessionEntry, uid );
                  SmbMonLog("Fabricated UID %04x", uid);
              }
          }

          // Create a PidMid
          status = SmbSsnCreateSsnPidMid( sessionEntry,
                                          smbHeader,
                                          &ssnPidMid );
          if( status != SMB_ERROR_NONE )
          {
              //SmbErrLog(LOG_NOTICE,"%04x  %04x  %04x  %04x %s", 
              //             uid, pid, mid,tid, smbUtilError2String(status));
              smbUtilErrorUpdateStats( status );

              SmbIntLog("  Descr ERROR  %s", smbUtilError2String(status) );
              break;
          }

          // Save the pertinent info
          memset( ssnPidMid->filename, 0, TZX_512_STRING );
          if( stohs(smbHeader->flags2) & SMB_FLAGS2_UNICODE )
          {
              // Unicode translation with even valued max length
              // to prevent scribbler behavior
              safeLen = (TZX_512_STRING - 1) * 2;
              smbUtilUnicodeToAscii( req->filename, safeLen,
                                     ssnPidMid->filename );
          }
          else
          {
              safeLen = MIN( TZX_512_STRING - 1,
                             strlen(req->filename) +1 );

              memcpy( ssnPidMid->filename, req->filename, safeLen );
          }
      }

  } while(0);

  ++andxCmdState.chainCnt;
}

//-----------------------------------------------------------------------
// smbHandleRead()
//     
//     - - U N T E S T E D - -
//-----------------------------------------------------------------------
void SmbDecode::smbHandleRead( SessionEntry *sessionEntry,
                               const u_char *data,
                               tz_uint32 length )
{
  tz_uint32         status;
  SmbHeader        *smbHeader;
  tz_uint16         uid, pid, mid, tid;
  SmbSsnUid        *ssnUid;
  SmbSsnPidMid     *ssnPidMid;
  SmbSsnFid        *ssnFid;
  SmbSsnTid        *ssnTid;
  tz_uint32         ntStatus = 0;

  smbHeader = (SmbHeader *)(data + sizeof(NBHeader));
  uid       = stohs(smbHeader->userId);
  pid       = stohs(smbHeader->processId);
  mid       = stohs(smbHeader->multiplexId);
  tid       = stohs(smbHeader->treeId);


  do
  {
      // == S E R V E R   S I D E ==
      //
      if( sessionEntry->trafficDirection == TRAFFIC_FROM_SERVER )
      {
          SmbReadResponse *rsp =
              (SmbReadResponse *)(data + sizeof(NBHeader)
                                               + sizeof(SmbHeader) );

          // Look up PidMid and Fid
          status = SmbSsnFindSsnDescrs( sessionEntry, smbHeader,
                                        &ssnUid, &ssnPidMid, &ssnFid, &ssnTid );
          if( status != SMB_ERROR_NONE )
          {
              //SmbErrLog(LOG_NOTICE,"%04x  %04x  %04x  %04x %s", 
              //             uid, pid, mid,tid, smbUtilError2String(status));
              smbUtilErrorUpdateStats( status );

              SmbIntLog("  Descr ERROR  %s", smbUtilError2String(status) );
              break;
          }

          ntStatus = stohl(smbHeader->status.NTstatus);
          if( ntStatus != 0 )
          {
              // Remove the PidMid entry
              if( SmbSsnDataRemovePidMid(sessionEntry, ssnUid, pid, mid) == IIMS_FAILURE )
              {
                  //SmbErrLog(LOG_NOTICE,"Failed Remove pid %04x mid %04x on uid %04x",
                  //                                          pid, mid, uid );
                  ++decodeStats.failedRemove;

                  SmbIntLog("  Descr ERROR - Failed Remove PidMid" );
              }

              SmbIntLog("  %s", smbUtilNtStatus2String(ntStatus) );
              break;
          }

          // Content and Operation

          // Create the command string
          sprintf( currCmdStg, "READ  %s", ssnFid->filename);

          if( myLmCfg.fileshareIsEnabled &&
              ssnFid->isEventSource && ssnTid->isEventSource )
          {
              // Format Content and Operation
              encEngFmt->resetEvent( sessionEntry );
              encEngFmt->setDimFileContent( sessionEntry,
                                            ssnFid->filename,
                                            NULL,
                                            ssnTid->sharename,
                                            0 );
              encEngFmt->setDimOperation( sessionEntry,
                                          EVT_READ, "READ", 
                                          strlen("READ") +1 );

              // Format Size and Response and generate the event
              encEngFmt->setDimSize( sessionEntry, stohs(rsp->count) );
              encEngFmt->setDimResponse( sessionEntry, SUCCESSFUL_OPERATION );
              encEngFmt->sendCOSREvent( encodingEngine,
                                        sessionEntry,
                                        ssnUid,
                                        ssnTid,
                                        currCmdStg );
          }

          SmbIntLog(" %c%s  (FID %04x)", 
                             ssnFid->isEventSource && ssnTid->isEventSource
                             ? ' ': '#', currCmdStg, ssnPidMid->fid );

          // Remove the PidMid entry
          if( SmbSsnDataRemovePidMid(sessionEntry, ssnUid, pid, mid) == IIMS_FAILURE )
          {
              //SmbErrLog(LOG_NOTICE,"Failed Remove pid %04x mid %04x on uid %04x",
              //                                          pid, mid, uid );
              ++decodeStats.failedRemove;

              SmbIntLog("  Descr ERROR - Failed Remove PidMid" );
          }

          SmbIntLog(" %d bytes", stohs(rsp->count));
      } 
      else    // == C L I E N T   S I D E ==    (TRAFFIC_FROM_CLIENT)
      {
          SmbReadRequest *req =
                  (SmbReadRequest *)(data + sizeof(NBHeader)
                                                  + sizeof(SmbHeader) );

#if 0
          if( stohl(smbHeader->status.NTstatus) != 0 )
          {
              break;
          }
#endif
          if( !smbLoginIsRequired )
          {
              // Session jump-in mode.  Check to see if we have a Uid
              // and, if not, create it
              SmbSsnUid *ssnUid = SmbSsnDataFindByUid( sessionEntry, uid );
              if( ssnUid == NULL )
              {
                  SmbSsnDataAddUid( sessionEntry, uid );
                  SmbMonLog("Fabricated UID %04x", uid);
              }
          }

          // Create a PidMid
          status = SmbSsnCreateSsnPidMid( sessionEntry,
                                          smbHeader,
                                          &ssnPidMid );
          if( status != SMB_ERROR_NONE )
          {
              //SmbErrLog(LOG_NOTICE,"%04x  %04x  %04x  %04x %s", 
              //             uid, pid, mid,tid, smbUtilError2String(status));
              smbUtilErrorUpdateStats( status );

              SmbIntLog("  Descr ERROR  %s", smbUtilError2String(status) );
              break;
          }

          // Save the pertinent info
          ssnPidMid->fid = stohs(req->fid);
      }
  } while(0);

  // This is a "non-Andx" command so terminate the chain
  andxCmdState.cmd = 0xff;
}



//-----------------------------------------------------------------------
// smbHandleReadAndx()
//-----------------------------------------------------------------------
void SmbDecode::smbHandleReadAndx( SessionEntry *sessionEntry,
                                   const u_char *data,
                                   tz_uint32 length )
{
  tz_uint32         status;
  SmbHeader        *smbHeader;
  tz_uint16         uid = 0, pid = 0, mid = 0, tid = 0;
  SmbSsnUid        *ssnUid;
  SmbSsnPidMid     *ssnPidMid;
  SmbSsnFid        *ssnFid;
  SmbSsnTid        *ssnTid;
  tz_uint32         ntStatus = 0;
  SmbInfo          *smbInfo = (SmbInfo *)sessionEntry->appInfo;
  bool              csEventIsEnabled = true;  // default if CS not active

  smbHeader = (SmbHeader *)(data + sizeof(NBHeader));

  if( length > (sizeof(NBHeader) + sizeof(SmbHeader)))
  {
      uid       = stohs(smbHeader->userId);
      pid       = stohs(smbHeader->processId);
      mid       = stohs(smbHeader->multiplexId);
      tid       = stohs(smbHeader->treeId);
  }

  do
  {
      // == S E R V E R   S I D E ==
      //
      if( sessionEntry->trafficDirection == TRAFFIC_FROM_SERVER )
      {
          SmbReadAndxResponse *rsp;
          LargeCmdState       *lcs            = &smbInfo->rspLcs;
          DimValListEntry     *respDataDVLE   = NULL;
          tz_uint8            *thisDataPtr    = NULL;
          tz_uint32            thisDataLen    = 0;
          tz_uint32            thisDataOffset = 0;

          // Handle fragmentation processing if necessary
          if( length < (  sizeof(NBHeader) 
                        + sizeof(SmbHeader)
                        + sizeof(SmbReadAndxResponse)) )
          {
              handleFragBegin( sessionEntry, data, length );
              lcs->smbCommand = SMB_COM_READ_ANDX;
              andxCmdState.cmd = 0xff;
              SmbDcdLog( sessionEntry,"FRAG    READ-ANDX-RSP" );
              break;
          }

          if( andxCmdState.chainCnt == 1 )
          {
              rsp = (SmbReadAndxResponse *)
                         (data + sizeof(NBHeader) + sizeof(SmbHeader) );
          } else {
              rsp = (SmbReadAndxResponse *)
                       (data + sizeof(NBHeader) + andxCmdState.offset );
          }

          // Update Andx State
          ntStatus = stohl(smbHeader->status.NTstatus);
          if( ntStatus == 0 )
          {
              andxCmdState.cmd = rsp->andxCommand;
              andxCmdState.offset = stohs(rsp->andxOffset);
          } else {
              // Status returned, response payload is invalid
              andxCmdState.cmd = 0xff;
          }

          // Look up PidMid and Fid
          status = SmbSsnFindSsnDescrs( sessionEntry, smbHeader,
                                  &ssnUid, &ssnPidMid, &ssnFid, &ssnTid );
          if( status != SMB_ERROR_NONE )
          {
              //SmbErrLog(LOG_NOTICE,"%04x  %04x  %04x  %04x %s", 
              //           uid, pid, mid,tid, smbUtilError2String(status));
              smbUtilErrorUpdateStats( status );

              SmbIntLog("  Descr ERROR  %s", smbUtilError2String(status) );
              break;
          }

          if(    ntStatus == STATUS_BUFFER_OVERFLOW
              && ssnFid->mode == FID_MODE_NMD_PIPE_SQL )
          {
              // The server is politely telling the client that he's
              // about to overflow the buffer the client specified at
              // the initial read request.  It's purely informational
              // and nondestructive so allow processing to continue
              // by ignoring it.
          }
          else if( ntStatus != 0 )
          {
              // Put an end to any command chain processing
              andxCmdState.cmd = 0xff;

              // Remove the PidMid entry
              if( SmbSsnDataRemovePidMid(sessionEntry, ssnUid, pid, mid) == IIMS_FAILURE )
              {
                  //SmbErrLog(LOG_NOTICE,"Failed Remove pid %04x mid %04x on uid %04x",
                  //                                          pid, mid, uid );
                  ++decodeStats.failedRemove;

                  SmbIntLog("  Descr ERROR - Failed Remove PidMid" );
              }

              SmbIntLog("  %s", smbUtilNtStatus2String(ntStatus) );
              break;
          }

          // Calculate the start address and length of the response payload
          thisDataOffset = stohs(rsp->dataOffset);

          thisDataLen = length 
                      - sizeof(NBHeader)
                      - thisDataOffset;

          thisDataPtr = (tz_uint8 *)data 
                      + sizeof(NBHeader)
                      + thisDataOffset;

          if (&thisDataPtr[thisDataLen] > &data[length])
          {
              SmbErrLog(LOG_NOTICE,
                        "Failed response payload calculation: thisDataPtr 0x%08x "
                        "thisDataLen 0x%08x, data 0x%08x length 0x%08x",
                        (unsigned int)thisDataPtr, (unsigned int)thisDataLen,
                        (unsigned int)data, (unsigned int)length);
              break; 
          }

          // Perform Content Scanning
          if(   rspDataPatMgr->CSEnabled() == true 
             && ssnFid->serverCs )
          {
              if( lcs->isActive == false )
              {
                  // No TCP Continuation data.  This packet has the entire
                  // response and we want the event to contain CS results
                  csEventIsEnabled = true;

                  if( ssnFid->serverCs->IsIdle() )
                  {
                      ssnFid->serverCs->StartScan( sessionEntry->workerIdx );
                      SmbIntLog("  CS_START");
                  }

                  ssnFid->serverCs->ScanData( thisDataPtr, thisDataLen,
                                              sessionEntry->workerIdx );

                  // Take a peek at whether we are going to generate an event
                  bool sendEvent;
                  sendEvent = encEngFmt->evtFiltEvaluate( sessionEntry,
                                                          EVT_READ,
                                                          ssnUid,
                                                          ssnFid );
                  if( sendEvent )
                  {
                      // We are so stop the scanner and get counts
                      tz_uint32 matches = ssnFid->serverCs->GetTotalMatchCount();

                      respDataDVLE = ssnFid->serverCs->StopScan(
                                ResponseDataType, sessionEntry->workerIdx);

                      SmbIntLog("  %lu matches  CS_STOP", matches );
                  }

                  //smbUtilCSPrintResults( ssnFid->serverCs, respDataDVLE );
              }
              else
              {
                  // TCP Continuation data will follow so defer the event
                  csEventIsEnabled = false;

                  // Save SMB parameters
                  smbCsSaveUidPidMidTid( lcs, uid, pid, mid, tid );
              }
          }

          // Content and Operation

          // Create the command string
          sprintf( currCmdStg, "READ  %s", ssnFid->filename);

          if(    myLmCfg.fileshareIsEnabled
              && ssnFid->isEventSource
              && ssnTid->isEventSource
              && csEventIsEnabled )
          {
              // Format Content and Operation
              encEngFmt->resetEvent( sessionEntry );
              encEngFmt->setDimFileContent( sessionEntry,
                                            ssnFid->filename,
                                            NULL,
                                            ssnTid->sharename,
                                            0 );
              encEngFmt->setDimOperation( sessionEntry,
                                          EVT_READ, "READ", 
                                          strlen("READ") +1 );

              // Format Size and Response and generate the event
              encEngFmt->setDimSize( sessionEntry, stohs(rsp->dataLength) );
              encEngFmt->setDimResponse( sessionEntry, SUCCESSFUL_OPERATION );

              if( rspDataPatMgr->CSEnabled() == true  && lcs->isActive == false ) {
                  encEngFmt->setDimResponseData( sessionEntry, respDataDVLE );
              }

              encEngFmt->sendCOSREvent( encodingEngine,
                                        sessionEntry,
                                        ssnUid,
                                        ssnTid,
                                        currCmdStg );
          }

          SmbIntLog(" %c%s  (FID %04x)", 
                            myLmCfg.fileshareIsEnabled && ssnFid->isEventSource
                            && ssnTid->isEventSource && csEventIsEnabled
                            ? ' ': '#', currCmdStg, ssnPidMid->fid );

          // Remove the PidMid entry if not deferring for content scan
          if(    csEventIsEnabled == true
                 && (SmbSsnDataRemovePidMid(sessionEntry, ssnUid, pid, mid) == IIMS_FAILURE ))
          {
              //SmbErrLog(LOG_NOTICE,"Failed Remove pid %04x mid %04x on uid %04x",
              //                                          pid, mid, uid );
              ++decodeStats.failedRemove;

              SmbIntLog("  Descr ERROR - Failed Remove PidMId" );
          }

          SmbIntLog(" %d bytes", stohs(rsp->dataLength));

          // If It's a large command, calculate remaining bytes
          if( lcs->isActive )
          {
              //lcs->cmdExpected = stohs(rsp->dataLength);
              //lcs->cmdReceived = thisDataLen;
              lcs->smbCommand = SMB_COM_READ_ANDX;

              // Begin Content Scanning for TCP Continuation data
              if( rspDataPatMgr->CSEnabled() == true && ssnFid->serverCs )
              {
                  // Store the Content Scanner
                  lcs->cs = ssnFid->serverCs;

                  if( ssnFid->serverCs->IsIdle() )
                  {
                      ssnFid->serverCs->StartScan(sessionEntry->workerIdx);
                      SmbIntLog("  CS_START");
                  }

                  // Scan the first segment of a sequence.  The TCP
                  // Continuation handler does the rest
                  ssnFid->serverCs->ScanData (thisDataPtr, thisDataLen, sessionEntry->workerIdx );

                  // D E B U G
                  //SmbIntLog("  CS_START");
              }
          }

          // Named pipe operation
          if( ssnFid->mode == FID_MODE_NMD_PIPE_SQL )
          {
              if( lcs->isActive )
              {
                  lcs->tdsEncaps = &ssnFid->tdsEncaps;
              }

              if( andxCmdState.chainCnt != 1 ) {
                  thisDataLen -= andxCmdState.offset;
              }

              smbTdsEncapsServerRsp( sessionEntry,
                                     &ssnFid->tdsEncaps,
                                     thisDataPtr,
                                     thisDataLen );

              SmbIntLog(" TDS_RSP" );
          }
      } 
      else    // == C L I E N T   S I D E ==    (TRAFFIC_FROM_CLIENT)
      {
          LargeCmdState      *lcs  = &smbInfo->reqLcs;
          bool isFragmented        = false;
          SmbReadAndxRequest *req;

          if( andxCmdState.chainCnt == 1 )
          {
                req = (SmbReadAndxRequest *)
                          (data + sizeof(NBHeader) + sizeof(SmbHeader));
          } else {
                req = (SmbReadAndxRequest *)
                       (data + sizeof(NBHeader) + andxCmdState.offset );
          }

          // Handle fragmentation processing if necessary.  First
          // determine the size of the response by reading wordCount
          if( length < (  sizeof(NBHeader) 
                        + sizeof(SmbHeader)
                        + sizeof(tz_uint8)) )
          {
              isFragmented = true;
          } else {
              // We can read wordCount
              if(   req->wordCount == 10
                 && length < (  sizeof(NBHeader) 
                              + sizeof(SmbHeader)
                              + sizeof(SmbReadAndxRequest)
                              - sizeof(tz_uint32)))
              {
                  // short response, no OffsetHigh field
                  isFragmented = true;
              }
              if(   req->wordCount == 12
                 && length < (  sizeof(NBHeader) 
                              + sizeof(SmbHeader)
                              + sizeof(SmbReadAndxRequest)))
              {
                  // long response
                  isFragmented = true;
              }
          }

          if( isFragmented )
          {
              handleFragBegin( sessionEntry, data, length );
              lcs->smbCommand = SMB_COM_READ_ANDX;
              andxCmdState.cmd = 0xff;
              SmbDcdLog( sessionEntry,"FRAG    READ-ANDX-REQ" );
              break;
          }

          // Update Andx State
          andxCmdState.cmd = req->andxCommand;
          andxCmdState.offset = stohs(req->andxOffset);
#if 0
          if( stohl(smbHeader->status.NTstatus) != 0 )
          {
              // Put an end to any command chain processing
              andxCmdState.cmd = 0xff;
              break;
          }
#endif
          if( !smbLoginIsRequired )
          {
              // Session jump-in mode.  Check to see if we have a Uid
              // and, if not, create it
              SmbSsnUid *ssnUid = SmbSsnDataFindByUid( sessionEntry, uid );
              if( ssnUid == NULL )
              {
                  SmbSsnDataAddUid( sessionEntry, uid );
                  SmbMonLog("Fabricated UID %04x", uid);
              }
          }

          // Create a PidMid
          status = SmbSsnCreateSsnPidMid( sessionEntry,
                                          smbHeader,
                                          &ssnPidMid );
          if( status != SMB_ERROR_NONE )
          {
              //SmbErrLog(LOG_NOTICE,"%04x  %04x  %04x  %04x %s", 
              //             uid, pid, mid,tid, smbUtilError2String(status));
              smbUtilErrorUpdateStats( status );

              SmbIntLog("  Descr ERROR  %s", smbUtilError2String(status) );
              break;
          }

          // Save the pertinent info
          ssnPidMid->fid = stohs(req->fid);

          // For debug purposes, log the file offset
          SmbIntLog("  offset %ld", stohl(req->offset));
      }

  } while(0);

  ++andxCmdState.chainCnt;
}

//-----------------------------------------------------------------------
// smbHandleWrite()
//     
//
//-----------------------------------------------------------------------
void SmbDecode::smbHandleWrite( SessionEntry *sessionEntry,
                                const u_char *data,
                                tz_uint32 length )
{
  tz_uint32         status;
  SmbHeader        *smbHeader;
  tz_uint16         uid, pid, mid, tid;
  SmbSsnUid        *ssnUid;
  SmbSsnPidMid     *ssnPidMid;
  SmbSsnFid        *ssnFid;
  SmbSsnTid        *ssnTid;
  tz_uint32         ntStatus = 0;

  smbHeader = (SmbHeader *)(data + sizeof(NBHeader));
  uid       = stohs(smbHeader->userId);
  pid       = stohs(smbHeader->processId);
  mid       = stohs(smbHeader->multiplexId);
  tid       = stohs(smbHeader->treeId);


  do
  {
      // == S E R V E R   S I D E ==
      //
      if( sessionEntry->trafficDirection == TRAFFIC_FROM_SERVER )
      {
          SmbWriteResponse *rsp =
              (SmbWriteResponse *)(data + sizeof(NBHeader)
                                               + sizeof(SmbHeader) );

          // Look up PidMid and Fid
          status = SmbSsnFindSsnDescrs( sessionEntry, smbHeader,
                                        &ssnUid, &ssnPidMid, &ssnFid, &ssnTid );
          if( status != SMB_ERROR_NONE )
          {
              //SmbErrLog(LOG_NOTICE,"%04x  %04x  %04x  %04x %s", 
              //             uid, pid, mid,tid, smbUtilError2String(status));
              smbUtilErrorUpdateStats( status );

              SmbIntLog("  Descr ERROR  %s", smbUtilError2String(status) );
              break;
          }

          ntStatus = stohl(smbHeader->status.NTstatus);
          if( ntStatus != 0 )
          {
              // Remove the PidMid entry
              if( SmbSsnDataRemovePidMid(sessionEntry, ssnUid, pid, mid) == IIMS_FAILURE )
              {
                  //SmbErrLog(LOG_NOTICE,"Failed Remove pid %04x mid %04x on uid %04x",
                  //                                          pid, mid, uid );
                  ++decodeStats.failedRemove;

                  SmbIntLog("  Descr ERROR - Failed Remove PidMid" );
              }

              SmbIntLog("  %s", smbUtilNtStatus2String(ntStatus) );
              break;
          }

          // Content and Operation

          // Create the command string
          sprintf( currCmdStg, "WRITE  %s", ssnFid->filename);

          if( myLmCfg.fileshareIsEnabled &&
              ssnFid->isEventSource && ssnTid->isEventSource )
          {
              // Format Content and Operation
              encEngFmt->resetEvent( sessionEntry );
              encEngFmt->setDimFileContent( sessionEntry,
                                            ssnFid->filename,
                                            NULL,
                                            ssnTid->sharename,
                                            0 );
              encEngFmt->setDimOperation( sessionEntry,
                                          EVT_WRITE, "WRITE", 
                                          strlen("WRITE") +1 );

              // Format Size and Response and generate the event
              encEngFmt->setDimSize( sessionEntry, stohs(rsp->count) );
              encEngFmt->setDimResponse( sessionEntry, SUCCESSFUL_OPERATION );
              encEngFmt->sendCOSREvent( encodingEngine,
                                        sessionEntry,
                                        ssnUid,
                                        ssnTid,
                                        currCmdStg );
          }

          SmbIntLog(" %c%s  (FID %04x)", 
                            ssnFid->isEventSource && ssnTid->isEventSource
                            ? ' ': '#', currCmdStg, ssnPidMid->fid );

          // Remove the PidMid entry
          if( SmbSsnDataRemovePidMid(sessionEntry, ssnUid, pid, mid) == IIMS_FAILURE )
          {
              //SmbErrLog(LOG_NOTICE,"Failed Remove pid %04x mid %04x on uid %04x",
              //                                          pid, mid, uid );
              ++decodeStats.failedRemove;

              SmbIntLog("  Descr ERROR - Failed Remove PidMid" );
          }

          SmbIntLog(" %d bytes", stohs(rsp->count));
      } 
      else    // == C L I E N T   S I D E ==    (TRAFFIC_FROM_CLIENT)
      {
          SmbWriteRequest *req =
                  (SmbWriteRequest *)(data + sizeof(NBHeader)
                                                  + sizeof(SmbHeader) );

#if 0
          if( stohl(smbHeader->status.NTstatus) != 0 )
          {
              break;
          }
#endif
          if( !smbLoginIsRequired )
          {
              // Session jump-in mode.  Check to see if we have a Uid
              // and, if not, create it
              SmbSsnUid *ssnUid = SmbSsnDataFindByUid( sessionEntry, uid );
              if( ssnUid == NULL )
              {
                  SmbSsnDataAddUid( sessionEntry, uid );
                  SmbMonLog("Fabricated UID %04x", uid);
              }
          }

          // Create a PidMid
          status = SmbSsnCreateSsnPidMid( sessionEntry,
                                          smbHeader,
                                          &ssnPidMid );
          if( status != SMB_ERROR_NONE )
          {
              //SmbErrLog(LOG_NOTICE,"%04x  %04x  %04x  %04x %s", 
              //             uid, pid, mid,tid, smbUtilError2String(status));
              smbUtilErrorUpdateStats( status );

              SmbIntLog("  Descr ERROR  %s", smbUtilError2String(status) );
              break;
          }

          // Save the pertinent info
          ssnPidMid->fid = stohs(req->fid);
      }
  } while(0);

  // This is a "non-Andx" command so terminate the chain
  andxCmdState.cmd = 0xff;
}

//-----------------------------------------------------------------------
// smbHandleWriteAndx()
//-----------------------------------------------------------------------
void SmbDecode::smbHandleWriteAndx( SessionEntry *sessionEntry,
                                    const u_char *data,
                                    tz_uint32 length )
{
  tz_uint32         status;
  SmbHeader        *smbHeader;
  tz_uint16         uid = 0, pid = 0, mid = 0, tid = 0;
  SmbSsnUid        *ssnUid;
  SmbSsnPidMid     *ssnPidMid;
  SmbSsnFid        *ssnFid;
  SmbSsnTid        *ssnTid;
  tz_uint32         ntStatus = 0;
  SmbInfo          *smbInfo = (SmbInfo *)sessionEntry->appInfo;

  smbHeader = (SmbHeader *)(data + sizeof(NBHeader));

  if( length > (sizeof(NBHeader) + sizeof(SmbHeader)))
  {
      uid       = stohs(smbHeader->userId);
      pid       = stohs(smbHeader->processId);
      mid       = stohs(smbHeader->multiplexId);
      tid       = stohs(smbHeader->treeId);
  }

  do
  {
      // == S E R V E R   S I D E ==
      //
      if( sessionEntry->trafficDirection == TRAFFIC_FROM_SERVER )
      {
          SmbWriteAndxResponse *rsp;
          LargeCmdState        *lcs  = &smbInfo->rspLcs;
          DimValListEntry      *cmdDataDVLE = NULL;

          // Handle fragmentation processing if necessary
          if( length < (  sizeof(NBHeader) 
                        + sizeof(SmbHeader)
                        + sizeof(SmbWriteAndxResponse)) )
          {
              handleFragBegin( sessionEntry, data, length );
              lcs->smbCommand = SMB_COM_WRITE_ANDX;
              andxCmdState.cmd = 0xff;
              SmbDcdLog( sessionEntry,"FRAG    WRITE-ANDX-RSP" );
              break;
          }

          if( andxCmdState.chainCnt == 1 )
          {
              rsp = (SmbWriteAndxResponse *)
                         (data + sizeof(NBHeader) + sizeof(SmbHeader) );
          } else {
              rsp = (SmbWriteAndxResponse *)
                       (data + sizeof(NBHeader) + andxCmdState.offset );
          }

          // Update Andx State
          ntStatus = stohl(smbHeader->status.NTstatus);
          if( ntStatus == 0 )
          {
              andxCmdState.cmd = rsp->andxCommand;
              andxCmdState.offset = stohs(rsp->andxOffset);
          } else {
              // Status returned, response payload is invalid
              andxCmdState.cmd = 0xff;
          }

          // Look up PidMid and Fid
          status = SmbSsnFindSsnDescrs( sessionEntry, smbHeader,
                                &ssnUid, &ssnPidMid, &ssnFid, &ssnTid );
          if( status != SMB_ERROR_NONE )
          {
              //SmbErrLog(LOG_NOTICE,"%04x  %04x  %04x  %04x %s", 
              //             uid, pid, mid,tid, smbUtilError2String(status));
              smbUtilErrorUpdateStats( status );

              SmbIntLog("  Descr ERROR  %s", smbUtilError2String(status) );
              break;
          }

          if( ntStatus != 0 )
          {
              // Put an end to any command chain processing
              andxCmdState.cmd = 0xff;

              // Remove the PidMid entry
              if( SmbSsnDataRemovePidMid(sessionEntry, ssnUid, pid, mid) == IIMS_FAILURE )
              {
                  //SmbErrLog(LOG_NOTICE,"Failed Remove pid %04x mid %04x on uid %04x",
                  //                                          pid, mid, uid );
                  ++decodeStats.failedRemove;

                  SmbIntLog("  Descr ERROR - Failed Remove PidMid" );
              }

              SmbIntLog("  %s", smbUtilNtStatus2String(ntStatus) );
              break;
          }

          // Perform Content Scanning.  Data has been scanned in the Req and
          // any TCP Continuation packets.  In the Rsp we just look for matches
          if(    cmdDataPatMgr->CSEnabled() == true
              && ssnFid->clientCs )
          {
              // Take a peek at whether we are going to generate an event
              bool sendEvent;
              sendEvent = encEngFmt->evtFiltEvaluate( sessionEntry,
                                                      EVT_WRITE,
                                                      ssnUid,
                                                      ssnFid );
              if( sendEvent )
              {
                  // We are so stop the scanner and get counts
                  tz_uint32 matches = ssnFid->clientCs->GetTotalMatchCount();

                  cmdDataDVLE = ssnFid->clientCs->StopScan(
                                CommandDataType, sessionEntry->workerIdx);

                  SmbIntLog("  %lu matches  CS_STOP", matches );
              }
          }

          // Content and Operation

          // Create the command string
          sprintf( currCmdStg, "WRITE  %s", ssnFid->filename);

          if( myLmCfg.fileshareIsEnabled &&
              ssnFid->isEventSource && ssnTid->isEventSource )
          {
              // Format Content and Operation
              encEngFmt->resetEvent( sessionEntry );
              encEngFmt->setDimFileContent( sessionEntry,
                                            ssnFid->filename,
                                            NULL,
                                            ssnTid->sharename,
                                            0 );
              encEngFmt->setDimOperation( sessionEntry,
                                          EVT_WRITE, "WRITE", 
                                          strlen("WRITE") +1 );

              // Format Size and Response and generate the event
              encEngFmt->setDimSize( sessionEntry, stohs(rsp->count) );
              encEngFmt->setDimResponse( sessionEntry, SUCCESSFUL_OPERATION );

              if( cmdDataPatMgr->CSEnabled() == true ) {
                  encEngFmt->setDimCommandData( sessionEntry, cmdDataDVLE );
              }

              encEngFmt->sendCOSREvent( encodingEngine,
                                        sessionEntry,
                                        ssnUid,
                                        ssnTid,
                                        currCmdStg );
          }

          SmbIntLog(" %c%s  (FID %04x)", 
                           ssnFid->isEventSource && ssnTid->isEventSource
                           ? ' ': '#', currCmdStg, ssnPidMid->fid );

          // Remove the PidMid entry
          if( SmbSsnDataRemovePidMid(sessionEntry, ssnUid, pid, mid) == IIMS_FAILURE )
          {
              //SmbErrLog(LOG_NOTICE,"Failed Remove pid %04x mid %04x on uid %04x",
              //                                          pid, mid, uid );
              ++decodeStats.failedRemove;

              if( SmbDebug::logIsEnabled ) {
                  SmbIntLog("  Descr ERROR - Failed Remove PidMid" );
              }
          }

          SmbIntLog(" %d bytes", stohs(rsp->count));
      } 
      else    // == C L I E N T   S I D E ==    (TRAFFIC_FROM_CLIENT)
      {
          SmbWriteAndxRequest *req;
          LargeCmdState       *lcs  = &smbInfo->reqLcs;
          bool isFragmented         = false;
          tz_uint8            *thisDataPtr    = NULL;
          tz_uint32            thisDataLen    = 0;

          if( andxCmdState.chainCnt == 1 )
          {
              req = (SmbWriteAndxRequest *)
                         (data + sizeof(NBHeader) + sizeof(SmbHeader) );
          } else {
              req = (SmbWriteAndxRequest *)
                       (data + sizeof(NBHeader) + andxCmdState.offset );
          }

          // Handle fragmentation processing if necessary.  First
          // determine the size of the response by reading wordCount
          if( length < (  sizeof(NBHeader) 
                        + sizeof(SmbHeader)
                        + sizeof(tz_uint8)) )
          {
              isFragmented = true;
          } else {
              // We can read wordCount
              if(   req->wordCount == 12
                 && length < (  sizeof(NBHeader) 
                              + sizeof(SmbHeader)
                              + sizeof(SmbWriteAndxRequest)
                              - sizeof(tz_uint32)))
              {
                  // short response, no OffsetHigh field
                  isFragmented = true;
              }
              if(   req->wordCount == 14
                 && length < (  sizeof(NBHeader) 
                              + sizeof(SmbHeader)
                              + sizeof(SmbWriteAndxRequest)))
              {
                  // long response
                  isFragmented = true;
              }
          }

          if( isFragmented )
          {
              handleFragBegin( sessionEntry, data, length );
              lcs->smbCommand = SMB_COM_WRITE_ANDX;
              andxCmdState.cmd = 0xff;
              SmbDcdLog( sessionEntry,"FRAG    WRITE-ANDX-REQ" );
              break;
          }

          // Update Andx State
          andxCmdState.cmd = req->andxCommand;
          andxCmdState.offset = stohs(req->andxOffset);
#if 0
          if( stohl(smbHeader->status.NTstatus) != 0 )
          {
              // Put an end to any command chain processing
              andxCmdState.cmd = 0xff;
              break;
          }
#endif
          if( !smbLoginIsRequired )
          {
              // Session jump-in mode.  Check to see if we have a Uid
              // and, if not, create it
              SmbSsnUid *ssnUid = SmbSsnDataFindByUid( sessionEntry, uid );
              if( ssnUid == NULL )
              {
                  SmbSsnDataAddUid( sessionEntry, uid );
                  SmbMonLog("Fabricated UID %04x", uid);
              }
          }

          // Create a PidMid
          status = SmbSsnCreateSsnPidMid( sessionEntry,
                                          smbHeader,
                                          &ssnPidMid );
          if( status != SMB_ERROR_NONE )
          {
              //SmbErrLog(LOG_NOTICE,"%04x  %04x  %04x  %04x %s", 
              //             uid, pid, mid,tid, smbUtilError2String(status));
              smbUtilErrorUpdateStats( status );

              SmbIntLog("  Descr ERROR  %s", smbUtilError2String(status) );
              break;
          }

          // Save the pertinent info
          ssnPidMid->fid = stohs(req->fid);

          // Calculate the start address and length of the response payload
          thisDataLen = length 
                      - sizeof(NBHeader)
                      - stohs(req->dataOffset);

          thisDataPtr = (tz_uint8 *)data 
                      + sizeof(NBHeader)
                      + stohs(req->dataOffset);

          if (&thisDataPtr[thisDataLen] > &data[length])
          {
              SmbErrLog(LOG_NOTICE,
                        "Failed response payload calculation: thisDataPtr 0x%08x "
                        "thisDataLen 0x%08x, data 0x%08x length 0x%08x",
                        (unsigned int)thisDataPtr, (unsigned int)thisDataLen,
                        (unsigned int)data, (unsigned int)length);
              break; 
          }

          // If it's a large command remember the SMB command
          if( lcs->isActive )
          {
              lcs->smbCommand = SMB_COM_WRITE_ANDX;

              // Save SMB parameters
              smbCsSaveUidPidMidTid( lcs, uid, pid, mid, tid );
          }

          // For debug purposes, log the file offset
          SmbIntLog("  offset %ld", stohl(req->offset));

          // Recover the FID descr so we can test for named pipes mode
          ssnUid = SmbSsnDataFindByUid( sessionEntry, stohs(smbHeader->userId) );
          if( ssnUid == NULL )
          {
              smbUtilErrorUpdateStats( SMB_ERROR_NO_UID_DESCR );

              SmbIntLog("  Descr ERROR  %s", 
                            smbUtilError2String(SMB_ERROR_NO_UID_DESCR) );
              break;
          }

          ssnFid = SmbSsnDataFindByFid( ssnUid, stohs(req->fid) );
          if( ssnFid == NULL )
          {
              smbUtilErrorUpdateStats( SMB_ERROR_NO_FID_DESCR );

              SmbIntLog("  Descr ERROR  %s", 
                               smbUtilError2String(SMB_ERROR_NO_FID_DESCR) );
              break;
          }

          // Perform Content Scanning
          if( cmdDataPatMgr->CSEnabled() == true && ssnFid->clientCs )
          {
              // Store the Content Scanner in case of LCS
              lcs->cs = ssnFid->clientCs;

              if( ssnFid->clientCs->IsIdle() )
              {
                  ssnFid->clientCs->StartScan(sessionEntry->workerIdx);
                  SmbIntLog("  CS_START");
              }

              // Scan the first segment of a sequence.  If LCS is active
              // then the TCP Continuation handler will do the rest
              ssnFid->clientCs->ScanData (thisDataPtr, thisDataLen,
                                          sessionEntry->workerIdx );
          }

          // Named pipe operation
          if( ssnFid->mode == FID_MODE_NMD_PIPE_SQL )
          {
              if( lcs->isActive )
              {
                  lcs->tdsEncaps = &ssnFid->tdsEncaps;
              }

              if( andxCmdState.chainCnt != 1 ) {
                  // NOTE: thisDataLen is modified
                  thisDataLen -= andxCmdState.offset;
              }

              smbTdsEncapsClientReq( sessionEntry,
                                     &ssnFid->tdsEncaps,
                                     thisDataPtr,
                                     thisDataLen );

              SmbIntLog(" TDS_REQ" );
          }

      }

  } while(0);

  ++andxCmdState.chainCnt;
}



//-----------------------------------------------------------------------
// smbHandleClose()
//     Close a file/directory specified by a FID
//-----------------------------------------------------------------------
void SmbDecode::smbHandleClose( SessionEntry *sessionEntry,
                                const u_char *data,
                                tz_uint32 length )
{
  tz_uint32         status;
  SmbHeader        *smbHeader;
  tz_uint16         uid, pid, mid, tid;
  SmbSsnUid        *ssnUid;
  SmbSsnPidMid     *ssnPidMid;
  SmbSsnFid        *ssnFid;
  SmbSsnTid        *ssnTid;
  tz_uint32         ntStatus = 0;

  smbHeader = (SmbHeader *)(data + sizeof(NBHeader));
  uid       = stohs(smbHeader->userId);
  pid       = stohs(smbHeader->processId);
  mid       = stohs(smbHeader->multiplexId);
  tid       = stohs(smbHeader->treeId);

  do
  {
      // == S E R V E R   S I D E ==
      //
      if( sessionEntry->trafficDirection == TRAFFIC_FROM_SERVER )
      {
          DimValListEntry *respDataDVLE = NULL;
          DimValListEntry *cmdDataDVLE = NULL;

          //SmbCloseResponse *rsp =
          //  (SmbCloseResponse *)(data + sizeof(NBHeader)
          //                            + sizeof(SmbHeader) );

          // Look up PidMid and Fid
          status = SmbSsnFindSsnDescrs( sessionEntry, smbHeader,
                                &ssnUid, &ssnPidMid, &ssnFid, &ssnTid );
          if( status != SMB_ERROR_NONE )
          {
              //SmbErrLog(LOG_NOTICE,"%04x  %04x  %04x  %04x %s", 
              //             uid, pid, mid,tid, smbUtilError2String(status));
              smbUtilErrorUpdateStats( status );

              SmbIntLog("  Descr ERROR  %s", smbUtilError2String(status) );
              break;
          }

          ntStatus = stohl(smbHeader->status.NTstatus);
          if( ntStatus != 0 )
          {
              // Remove the PidMid entry
              if( SmbSsnDataRemovePidMid(sessionEntry, ssnUid, pid, mid) == IIMS_FAILURE )
              {
                  //SmbErrLog(LOG_NOTICE,"Failed Remove pid %04x mid %04x on uid %04x",
                  //                                          pid, mid, uid );
                  ++decodeStats.failedRemove;

                  SmbIntLog("  Descr ERROR - Failed Remove PidMid" );
              }

              SmbIntLog("  %s", smbUtilNtStatus2String(ntStatus) );
              break;
          }

          // Perform Content Scanning
          if(   rspDataPatMgr->CSEnabled() == true
             && ssnFid->serverCs
             && ssnFid->serverCs->IsActive() )
          {
              // Test if there are pending match counts
              tz_uint32 matches = ssnFid->serverCs->GetTotalMatchCount();

              respDataDVLE = ssnFid->serverCs->StopScan(
                                ResponseDataType, sessionEntry->workerIdx);

              if( matches && respDataDVLE != NULL )
              {
                  // There are pending match counts
                  encEngFmt->evtFiltOverride( EVT_FILT_ACCEPT );
              }

              // Leave CS off
              SmbIntLog("  %lu resp matches  CS_STOP", matches );
          }

          if(   cmdDataPatMgr->CSEnabled() == true
             && ssnFid->clientCs
             && ssnFid->clientCs->IsActive() )
          {
              // Test if there are pending match counts
              tz_uint32 matches = ssnFid->clientCs->GetTotalMatchCount();

              cmdDataDVLE = ssnFid->clientCs->StopScan(
                                CommandDataType, sessionEntry->workerIdx);

              if( matches && cmdDataDVLE != NULL )
              {
                  // There are pending match counts
                  encEngFmt->evtFiltOverride( EVT_FILT_ACCEPT );
              }

              // Leave CS off
              SmbIntLog("  %lu cmd matches  CS_STOP", matches );
          }

          // Content and Operation

          // Create the command string
          sprintf( currCmdStg, "CLOSE  %s", ssnFid->filename);

          if( myLmCfg.fileshareIsEnabled &&
              ssnFid->isEventSource && ssnTid->isEventSource )
          {
              // Format Content and Operation
              encEngFmt->resetEvent( sessionEntry );

              if( ssnFid->isDirectory )
              {
                  encEngFmt->setDimFolderContent( sessionEntry,
                                                  ssnFid->filename,
                                                  NULL,
                                                  ssnTid->sharename,
                                                  0 );
              } else {

                  encEngFmt->setDimFileContent( sessionEntry,
                                                ssnFid->filename,
                                                NULL,
                                                ssnTid->sharename,
                                                0 );
              }

              encEngFmt->setDimOperation( sessionEntry,
                                          EVT_CLOSE, "CLOSE", 
                                          strlen("CLOSE") +1 );

              // Format Size and Response and generate the event
              // No size dimension for CLOSE
              //encEngFmt->setDimSize( sessionEntry, stohs(rsp->dataLength) );
              encEngFmt->setDimResponse( sessionEntry, SUCCESSFUL_OPERATION );

              if( rspDataPatMgr->CSEnabled() == true ) {
                  encEngFmt->setDimResponseData( sessionEntry, respDataDVLE );
              }
              if( cmdDataPatMgr->CSEnabled() == true ) {
                  encEngFmt->setDimCommandData( sessionEntry, cmdDataDVLE );
              }

              encEngFmt->sendCOSREvent( encodingEngine,
                                        sessionEntry,
                                        ssnUid,
                                        ssnTid,
                                        currCmdStg );
          }

          SmbIntLog(" %c%s  (FID %04x)", 
                           ssnFid->isEventSource && ssnTid->isEventSource
                           ? ' ': '#', currCmdStg, ssnPidMid->fid );

          // If the FID is named pipes cause a Logout event to occur
          if( ssnFid->mode == FID_MODE_NMD_PIPE_SQL )
          {
              smbTdsEncapsLogout( sessionEntry, &ssnFid->tdsEncaps );
          }

          // Remove the Fid entry
          SmbSsnDataRemoveFid( sessionEntry, ssnUid, ssnPidMid->fid );

          // Remove the PidMid entry
          if( SmbSsnDataRemovePidMid(sessionEntry, ssnUid, pid, mid) == IIMS_FAILURE )
          {
              //SmbErrLog(LOG_NOTICE,"Failed Remove pid %04x mid %04x on uid %04x",
              //                                          pid, mid, uid );
              ++decodeStats.failedRemove;

              SmbIntLog("  Descr ERROR - Failed Remove PidMid" );
          }

      } 
      else    // == C L I E N T   S I D E ==    (TRAFFIC_FROM_CLIENT)
      {
          SmbCloseRequest *req =
                  (SmbCloseRequest *)(data + sizeof(NBHeader)
                                           + sizeof(SmbHeader) );
#if 0
          if( stohl(smbHeader->status.NTstatus) != 0 )
          {
              break;
          }
#endif
          if( !smbLoginIsRequired )
          {
              // Session jump-in mode.  Check to see if we have a Uid
              // and, if not, create it
              SmbSsnUid *ssnUid = SmbSsnDataFindByUid( sessionEntry, uid );
              if( ssnUid == NULL )
              {
                  SmbSsnDataAddUid( sessionEntry, uid );
                  SmbMonLog("Fabricated UID %04x", uid);
              }
          }

          // Create a PidMid
          status = SmbSsnCreateSsnPidMid( sessionEntry,
                                          smbHeader,
                                          &ssnPidMid );
          if( status != SMB_ERROR_NONE )
          {
              //SmbErrLog(LOG_NOTICE,"%04x  %04x  %04x  %04x %s", 
              //             uid, pid, mid,tid, smbUtilError2String(status));
              smbUtilErrorUpdateStats( status );

              SmbIntLog("  Descr ERROR  %s", smbUtilError2String(status) );
              break;
          }

          // Save the pertinent info
          ssnPidMid->fid = stohs(req->fid);

          // We're done for now

#if 0
          printf("  (FID %04x)", ssnPidMid->fid );
#endif
      }

  } while(0);

  // This is a "non-Andx" command so terminate the chain
  andxCmdState.cmd = 0xff;
}

//-----------------------------------------------------------------------
// smbHandleDelete()
//     Delete the file specified (along with its path) using the
//     provided TID.
//
//-----------------------------------------------------------------------
void SmbDecode::smbHandleDelete( SessionEntry *sessionEntry,
                                 const u_char *data,
                                 tz_uint32 length )
{
  tz_uint32         status;
  SmbHeader        *smbHeader;
  tz_uint16         uid, pid, mid, tid;
  SmbSsnUid        *ssnUid;
  SmbSsnPidMid     *ssnPidMid;
  SmbSsnTid        *ssnTid;
  tz_uint32         ntStatus = 0;
  tz_uint32         safeLen = 0;

  smbHeader = (SmbHeader *)(data + sizeof(NBHeader));
  uid       = stohs(smbHeader->userId);
  pid       = stohs(smbHeader->processId);
  mid       = stohs(smbHeader->multiplexId);
  tid       = stohs(smbHeader->treeId);

  do
  {
      // == S E R V E R   S I D E ==
      //
      if( sessionEntry->trafficDirection == TRAFFIC_FROM_SERVER )
      {
          //SmbDeleteResponse *rsp =
          //    (SmbDeleteResponse *)(data + sizeof(NBHeader)
          //                               + sizeof(SmbHeader) );

          status = SmbSsnFindSsnDescrs( sessionEntry, smbHeader,
                                   &ssnUid, &ssnPidMid, NULL, &ssnTid );
          if( status != SMB_ERROR_NONE )
          {
              //SmbErrLog(LOG_NOTICE,"%04x  %04x  %04x  %04x %s", 
              //             uid, pid, mid,tid, smbUtilError2String(status));
              smbUtilErrorUpdateStats( status );

              SmbIntLog("  Descr ERROR  %s", smbUtilError2String(status) );
              break;
          }

          ntStatus = stohl(smbHeader->status.NTstatus);
          if( ntStatus != 0 )
          {
              // Delete the PidMid
              if( SmbSsnDataRemovePidMid(sessionEntry, ssnUid, pid, mid) == IIMS_FAILURE )
              {
                  //SmbErrLog(LOG_NOTICE,"Failed Remove pid %04x mid %04x "
                  //                   "on uid %04x", pid, mid, uid );
                  ++decodeStats.failedRemove;

                  SmbIntLog("  Descr ERROR - Failed Remove PidMid" );
              }

              SmbIntLog("  %s", smbUtilNtStatus2String(ntStatus) );
              break;
          }

          // Content and Operation

          // Create the command string
          sprintf( currCmdStg, "DELETE  %s", ssnPidMid->filename);

          if( myLmCfg.fileshareIsEnabled )  // Always generate an event for DELETE
          {
              // Format Content and Operation
              encEngFmt->resetEvent( sessionEntry );
              encEngFmt->setDimFileContent( sessionEntry,
                                            ssnPidMid->filename,
                                            NULL,
                                            ssnTid->sharename,
                                            0 );
              encEngFmt->setDimOperation( sessionEntry,
                                          EVT_DELETE, "DELETE", 
                                          strlen("DELETE") +1 );

              // Format Size and Response and generate the event

              // No size for DELETE operation
              //encEngFmt->setDimSize( sessionEntry, stohs(rsp->dataLength) );
              encEngFmt->setDimResponse( sessionEntry, SUCCESSFUL_OPERATION );
              encEngFmt->sendCOSREvent( encodingEngine,
                                        sessionEntry,
                                        ssnUid,
                                        ssnTid,
                                        currCmdStg );
          }

          SmbIntLog(" %c%s", 1 ? ' ': '#', currCmdStg );

          // Delete the PidMid
          if( SmbSsnDataRemovePidMid(sessionEntry, ssnUid, pid, mid) == IIMS_FAILURE )
          {
              //SmbErrLog(LOG_NOTICE,"Failed Remove pid %04x mid %04x on uid %04x",
              //                                          pid, mid, uid );
              ++decodeStats.failedRemove;

              SmbIntLog("  Descr ERROR - Failed Remove PidMid" );
          }

      } 
      else    // == C L I E N T   S I D E ==    (TRAFFIC_FROM_CLIENT)
      {
          SmbDeleteRequest *req =
                  (SmbDeleteRequest *)(data + sizeof(NBHeader)
                                                  + sizeof(SmbHeader) );
#if 0
          if( stohl(smbHeader->status.NTstatus) != 0 )
          {
              break;
          }
#endif
          if( !smbLoginIsRequired )
          {
              // Session jump-in mode.  Check to see if we have a Uid
              // and, if not, create it
              SmbSsnUid *ssnUid = SmbSsnDataFindByUid( sessionEntry, uid );
              if( ssnUid == NULL )
              {
                  SmbSsnDataAddUid( sessionEntry, uid );
                  SmbMonLog("Fabricated UID %04x", uid);
              }
          }

          // Create PidMid
          status = SmbSsnCreateSsnPidMid( sessionEntry,
                                          smbHeader,
                                          &ssnPidMid );
          if( status != SMB_ERROR_NONE )
          {
              //SmbErrLog(LOG_NOTICE,"%04x  %04x  %04x  %04x %s", 
              //             uid, pid, mid,tid, smbUtilError2String(status));
              smbUtilErrorUpdateStats( status );

              SmbIntLog("  Descr ERROR  %s", smbUtilError2String(status) );
              break;
          }

          // Save the pertinent info.  The server will echo TID back in
          // the response so we don't have to save it.
          memset( ssnPidMid->filename, 0, TZX_512_STRING );
          if( stohs(smbHeader->flags2) & SMB_FLAGS2_UNICODE )
          {
              // Unicode translation with even valued max length
              // to prevent scribbler behavior
              safeLen = (TZX_512_STRING - 1) * 2;
              smbUtilUnicodeToAscii( req->filename, safeLen,
                                     ssnPidMid->filename );
          }
          else
          {
              safeLen = MIN( TZX_512_STRING - 1,
                             strlen(req->filename) +1 );

              memcpy( ssnPidMid->filename, req->filename, safeLen );
          }

          // We're done for now
      }

  } while(0);

  // This is a "non-Andx" command so terminate the chain
  andxCmdState.cmd = 0xff;
}

//-----------------------------------------------------------------------
// smbHandleTransaction()
//-----------------------------------------------------------------------
void SmbDecode::smbHandleTransaction( SessionEntry *sessionEntry,
                                      const u_char *data,
                                      tz_uint32 length )
{
  tz_uint32         status;
  SmbHeader        *smbHeader;
  tz_uint16         uid, pid, mid, tid;
  SmbSsnUid        *ssnUid;
  SmbSsnPidMid     *ssnPidMid;
  SmbSsnFid        *ssnFid;
  SmbSsnTid        *ssnTid;
  tz_uint32         ntStatus = 0;
  tz_uint32         safeLen = 0;
  bool              pidMidIsToBeRemoved = true;

  smbHeader = (SmbHeader *)(data + sizeof(NBHeader));
  uid       = stohs(smbHeader->userId);
  pid       = stohs(smbHeader->processId);
  mid       = stohs(smbHeader->multiplexId);
  tid       = stohs(smbHeader->treeId);

  // D E B U G
  //SmbIntLog("\n");
  //smbPktDump( data, length );

  do
  {
      // == S E R V E R   S I D E ==
      //
      if( sessionEntry->trafficDirection == TRAFFIC_FROM_SERVER )
      {
          SmbTransactionResponse *rsp =
            (SmbTransactionResponse *)(data + sizeof(NBHeader)
                                            + sizeof(SmbHeader) );

      } 
      else    // == C L I E N T   S I D E ==    (TRAFFIC_FROM_CLIENT)
      {
          SmbTransactionRequest *req =
                  (SmbTransactionRequest *)(data + sizeof(NBHeader)
                                                 + sizeof(SmbHeader) );

          if( !smbLoginIsRequired )
          {
              // Session jump-in mode.  Check to see if we have a Uid
              // and, if not, create it
              SmbSsnUid *ssnUid = SmbSsnDataFindByUid( sessionEntry, uid );
              if( ssnUid == NULL )
              {
                  SmbSsnDataAddUid( sessionEntry, uid );
                  SmbMonLog("Fabricated UID %04x", uid);
              }
          }

          // Check function code here.  Go No Further if we don't care

          if( req->function != TRANS_FUNCT_NAMED_PIPE_DCERPCCMD ) {
              // D E B U G
              //SmbIntLog("  non DCE RPC");
              break;
          }

          // Recover the TID descr that was created when the client
          // connected to IPC$ to begin DCE RPC ops.  We're still
          // not sure yet if it's SPOOLSS or some other exchange.
          status = SmbSsnFindSsnDescrs( sessionEntry, smbHeader,
                                   &ssnUid, NULL, NULL, &ssnTid );
          if( status != SMB_ERROR_NONE )
          {
              smbUtilErrorUpdateStats( status );

              SmbIntLog("  Descr ERROR  %s", 
                                      smbUtilError2String(status) );
              break;
          }

          // Verify that this traffic is directed at SPOOLSS, quit if not
          ssnFid = SmbSsnDataFindByFid( ssnUid, stohs(req->fid) );
          if( ssnFid == NULL )
          {
              //SmbErrLog(LOG_NOTICE,"%04x  %04x  %04x  %04x FID Find Failure",
              //                                         uid, pid, mid,tid );
              smbUtilErrorUpdateStats( SMB_ERROR_NO_FID_DESCR );

              SmbIntLog("  Descr ERROR  %s", 
                               smbUtilError2String(SMB_ERROR_NO_FID_DESCR) );
              break;
          }

          if( ssnFid->mode != FID_MODE_NMD_PIPE_SPOOLSS ) {
              // This is traffic associated with the myriad of other named
              // pipe clients - \lsarpc, \samr, \winreg, the list goes on.
              break;
          }

          // DCE RPC header is determined by dataOffset parameter
          SmbDceRpc *dceRpc;
          dceRpc = (SmbDceRpc *)(data + sizeof(NBHeader) +
                                               stohs(req->dataOffset) );

          // When client code opens the printer, obtain the printer name
          if( dceRpc->parm[0] == SPOOLSS_OPEN_PRINTER_EX )
          {
              tz_uint32 offset;

              // Show the opnum
              SmbIntLog("  %s", smbUtilSpoolss2String(dceRpc->parm[0]) );

              tz_uint8 *data = (tz_uint8 *)( (tz_uint8 *)dceRpc 
                                                  + sizeof(SmbDceRpc) );

              // Printer name: referent ID
              data += 4;

              // Printer name: max count
              data += 4;

              // Printer name: offset
              data += 4;

              // Printer name: actual count
              offset = stohl(_U32(data));
              data += 4;

              // data is on top of \\<server>\<printer_name>
              // (Set even valued max length to prevent scribbler behavior)
              safeLen = (TZX_512_STRING - 1) * 2;
              smbUtilUnicodeToAscii( (tz_int8 *)data, safeLen, currCmdStg );

              // Parse into <server> and <printer_name> components
              encEngFmt->parseServerShare( currCmdStg,
                                           ssnTid->servername,
                                           ssnTid->sharename );

              SmbIntLog("  server: %s  printer: %s", ssnTid->servername,
                                                     ssnTid->sharename);

              // Further down in the packet, the User Level Container
              // holds the User which we could obtain for host.user.
              // I don't know if SPOOLSS is publicly documented and
              // I have used Ethereal's decode to write code so far.
              // At this point, though, it is very difficult to drill
              // down to the User Level Container and I am punting in the
              // interest of time.  Should specs become available or
              // should there be time to analyze Samba source code then
              // this feature can be implemented.
#if 0
              data += offset * 2;

              // Printer datatype
              if( stohl(_U32(data)) == 0 )
              {
                  // NULL Printer Datatype, do nothing
              }
              else
              {
                  // Printer datatype: unknown u16
                  //data +=2;

                  // Printer datatype: Referent ID
                  SmbIntLog("  RefId %08x", stohl(_U32(data)));
                  SmbDebug::logLinePut();
                  data += 4;

                  // Printer datatype, Datatype: Max count
                  data += 4;

                  // Printer datatype, Datatype: offset
                  data += 4;

                  // Printer datatype, Datatype: Actual Count
                  offset = stohl(_U32(data));
                  data += 4;

                  // Printer datatype, Datatype (string)
                  data += offset * 2;

                  // Devicemode container size
                  SmbIntLog("  CtrSz %08x", stohl(_U32(data)));
              }
#endif

          }

          // If the client is queueing a document for printing, grok it
          // and generate an event
          if( dceRpc->parm[0] == SPOOLSS_START_DOC_PRINTER )
          {
              // Show the opnum
              SmbIntLog("  %s (FID %04x)", smbUtilSpoolss2String(dceRpc->parm[0]),
                                           stohs(req->fid));

              tz_uint8 *data = (tz_uint8 *)( (tz_uint8 *)dceRpc 
                                                  + sizeof(SmbDceRpc) );

              // What you are about to see may offend you.  We are going to
              // step incrementally through the StartDocPrinter Req to get
              // to the area containing printer and file information

              // Policy Handle: Context handle (20 bytes)
              data += 20;

              // Document info container: Info level
              data += 4;

              // Document info level
              data += 4;

              // Document info Referent ID
              data += 4;

              // Document name Referent ID
              data += 4;

              // Output file: Referent ID
              data += 4;

              // Output file data type
              data += 4;

              // Document name max count
              data += 4;

              // Document name offset
              data += 4;

              // Document name actual count
              //SmbIntLog("  %08x", stohl( *((tz_uint32 *)data)));
              data += 4;

              // data is on top of document name/application here
              // (Set even valued max length to prevent scribbler behavior)
              safeLen = (TZX_512_STRING - 1) * 2;
              smbUtilUnicodeToAscii( (tz_int8 *)data, safeLen, ssnFid->filename );

#if 0         // Notepad appears after the '-' but Microsoft Word Viewer
              // appears before it.  Screw it, just display "as is"

              // Look for " - " separator indicating app doing the print
              char *app;
              app = strstr(ssnFid->filename, " - ");
              if( app ) {
                  *app = '\0';
                  app += 3;
                  sprintf( currCmdStg, "PRINT  %s  FROM  %s", 
                                              ssnFid->filename, app );
              } else {
                  sprintf( currCmdStg, "PRINT  %s", ssnFid->filename);
              }
#else
              sprintf( currCmdStg, "PRINT  %s", ssnFid->filename);
#endif

              SmbIntLog("  %s", ssnFid->filename );

              if( myLmCfg.fileshareIsEnabled )
              {
                  // Re-establish the context for this TID (the one for
                  // the printer)    We're setting up sessionDetail in
                  // sessionEntry here.
                  encEngFmt->restoreSessionEntry( sessionEntry,
                                                 &ssnTid->seCtxt );

                  // Ensure that this is a login event to guarantee that
                  // session.info is latched into the event.
                  if( encodingEngine->ApplicationIsLoggedIn(sessionEntry) )
                  {
                      encodingEngine->ApplicationLogout( sessionEntry );
                      SmbIntLog("  APP_LOGOUT");
                      // Application logout frees sessionDetail so we note
                      // that in the TID
                      ssnTid->ctxtIsEmpty = true;
                      ssnTid->seCtxt.sessionDetail = NULL;
                  }

                  // Format Content and Operation
                  encEngFmt->resetEvent( sessionEntry );
                  encEngFmt->setDimFileContent( sessionEntry,
                                                ssnFid->filename,
                                                NULL,
                                                NULL,
                                                0 );
                  encEngFmt->setDimOperation( sessionEntry,
                                              EVT_PRINT, "PRINT", 
                                              strlen("PRINT") +1 );

                  // Format Size and Response and generate the event
                  //encEngFmt->setDimSize( sessionEntry, stohs(rsp->dataLength) );
                  encEngFmt->setDimResponse( sessionEntry, SUCCESSFUL_OPERATION );
                  encEngFmt->sendCOSREvent( encodingEngine,
                                            sessionEntry,
                                            ssnUid,
                                            ssnTid,
                                            currCmdStg );
              }
          }

      }

  } while(0);

  // This is a "non-Andx" command so terminate the chain
  andxCmdState.cmd = 0xff;
}
//-----------------------------------------------------------------------
// smbHandleTransaction2()
//-----------------------------------------------------------------------
void SmbDecode::smbHandleTransaction2( SessionEntry *sessionEntry,
                                       const u_char *data,
                                       tz_uint32 length )
{
  tz_uint32         status;
  SmbHeader        *smbHeader;
  tz_uint16         uid = 0, pid = 0, mid = 0, tid = 0;
  SmbSsnUid        *ssnUid;
  SmbSsnPidMid     *ssnPidMid;
  SmbSsnTid        *ssnTid;
  tz_uint32         ntStatus = 0;
  tz_uint32         safeLen = 0;
  SmbInfo          *smbInfo = (SmbInfo *)sessionEntry->appInfo;
  bool              pidMidIsToBeRemoved = true;

  smbHeader = (SmbHeader *)(data + sizeof(NBHeader));

  if( length > (sizeof(NBHeader) + sizeof(SmbHeader)))
  {
      uid       = stohs(smbHeader->userId);
      pid       = stohs(smbHeader->processId);
      mid       = stohs(smbHeader->multiplexId);
      tid       = stohs(smbHeader->treeId);
  }

  do
  {
      // == S E R V E R   S I D E ==
      //
      if( sessionEntry->trafficDirection == TRAFFIC_FROM_SERVER )
      {
          LargeCmdState *lcs           = &smbInfo->rspLcs;
          bool isFragmented            = false;
          SmbTransaction2Response *rsp =
            (SmbTransaction2Response *)(data + sizeof(NBHeader)
                                             + sizeof(SmbHeader) );

          // Handle fragmentation processing if necessary.  First
          // determine the size of the response by reading wordCount
          if( length < (  sizeof(NBHeader) 
                        + sizeof(SmbHeader)
                        + sizeof(tz_uint8)) )
          {
              isFragmented = true;
          } else {
              // We can read wordCount
              if(   rsp->wordCount == 0
                 && length < (  sizeof(NBHeader) 
                              + sizeof(SmbHeader)
                              + 3))
              {
                  // short response
                  isFragmented = true;
              }
              if(   rsp->wordCount >= 10  
                 && length < (  sizeof(NBHeader) 
                              + sizeof(SmbHeader)
                              + sizeof(SmbTransaction2Response)))
              {
                  // long response
                  isFragmented = true;
              }
          }

          if( isFragmented )
          {
              handleFragBegin( sessionEntry, data, length );
              lcs->smbCommand = SMB_COM_TRANSACTION2;
              andxCmdState.cmd = 0xff;
              SmbDcdLog( sessionEntry,"FRAG    TRANS2-RSP" );
              break;
          }

          status = SmbSsnFindSsnDescrs( sessionEntry, smbHeader,
                                   &ssnUid, &ssnPidMid, NULL, NULL );
          if( status != SMB_ERROR_NONE )
          {
              //SmbErrLog(LOG_NOTICE,"%04x  %04x  %04x  %04x %s", 
              //             uid, pid, mid,tid, smbUtilError2String(status));
              smbUtilErrorUpdateStats( status );

              SmbIntLog("  Descr ERROR  %s", smbUtilError2String(status) );
              break;
          }

          ntStatus = stohl(smbHeader->status.NTstatus);
          if(    ntStatus != 0
              && ssnPidMid->trans2SubCmd != TRANS2_FIND_FIRST2 )
          {
              // Remove the PidMid entry
              if( SmbSsnDataRemovePidMid(sessionEntry, ssnUid, pid, mid) == IIMS_FAILURE )
              {
                  //SmbErrLog(LOG_NOTICE,"Failed Remove pid %04x mid %04x "
                  //                   "on uid %04x", pid, mid, uid );
                  ++decodeStats.failedRemove;

                  SmbIntLog("  Descr ERROR - Failed Remove PidMid" );
              }
              SmbIntLog("  %s", smbUtilNtStatus2String(ntStatus) );
              break;
          }

          // Rignt now we're only handling a few Trans2 subcommands.
          // We'll check for them individually

          // TRANS2_SET_FILE_INFORMATION is the hip way to delete a file
          bool isDispositionInfo =    ssnPidMid->trans2Parm == 0x3f5
                                   || ssnPidMid->trans2Parm == 0x102;
          if(    ssnPidMid->trans2SubCmd == TRANS2_SET_FILE_INFORMATION
              && isDispositionInfo
              && ssnPidMid->trans2Data == 0x01 )
          {
              // Look up the Tid context because it's needed here
              status = SmbSsnFindSsnDescrs( sessionEntry, smbHeader,
                                         &ssnUid, NULL, NULL, &ssnTid );
              if( status != SMB_ERROR_NONE )
              {
                  //SmbErrLog(LOG_NOTICE,"%04x  %04x  %04x  %04x %s", 
                  //             uid, pid, mid,tid, smbUtilError2String(status));
                  smbUtilErrorUpdateStats( status );

                  SmbIntLog("  Descr ERROR  %s", smbUtilError2String(status) );
                  break;
              }


              // Look up the Fid context
              SmbSsnFid * ssnFid = SmbSsnDataFindByFid(ssnUid, 
                                                       ssnPidMid->fid);
              if( ssnFid == NULL )
              {
                  //SmbErrLog(LOG_NOTICE,"%04x  %04x  %04x  %04x FID Find Failure",
                  //                                     uid, pid, mid,tid );
                  smbUtilErrorUpdateStats( SMB_ERROR_NO_FID_DESCR );

                  SmbIntLog("  Descr ERROR  %s", 
                                   smbUtilError2String(SMB_ERROR_NO_FID_DESCR) );
                  break;
              }

              // Create the command string
              sprintf( currCmdStg, "DELETE  %s", ssnFid->filename);

              if( myLmCfg.fileshareIsEnabled )
              {
                  // Content and Operation

                  // Format Content and Operation
                  encEngFmt->resetEvent( sessionEntry );
                  encEngFmt->setDimFileContent( sessionEntry,
                                                ssnFid->filename,
                                                NULL,
                                                ssnTid->sharename,
                                                0 );
                  encEngFmt->setDimOperation( sessionEntry,
                                              EVT_DELETE, "DELETE", 
                                              strlen("DELETE") +1 );

                 // Format Size and Response and generate the event

                  // No size for DELETE operation
                  //encEngFmt->setDimSize( sessionEntry, stohs(rsp->dataLength) );
                  encEngFmt->setDimResponse( sessionEntry, SUCCESSFUL_OPERATION );
                  encEngFmt->sendCOSREvent( encodingEngine,
                                            sessionEntry,
                                            ssnUid,
                                            ssnTid,
                                            currCmdStg );
              }

              SmbIntLog(" %c%s  (FID %04x)", 
                                  1 /*ssnFid->isEventSource*/ ? ' ': '#',
                                            currCmdStg, ssnPidMid->fid );
          }

          // TRANS_FIND_FIRST2 is a directory search that we use to
          // detect when someone is attempting to access a directory
          // area where they don't belong
          if(    ssnPidMid->trans2SubCmd == TRANS2_FIND_FIRST2
              && ntStatus != 0 )
          {
              // If it's not one of the excluded status codes, send up an 
              // event
              if( ntStatus == STATUS_NO_SUCH_FILE )
              {
                  // Ignore it
              }
              else if( ssnPidMid->filename[0] != '\0' )
              {
                  // Look up the Tid context because it's needed here
                  status = SmbSsnFindSsnDescrs( sessionEntry, smbHeader,
                                             &ssnUid, NULL, NULL, &ssnTid );
                  if( status != SMB_ERROR_NONE )
                  {
                      //SmbErrLog(LOG_NOTICE,"%04x  %04x  %04x  %04x %s", 
                      //      uid, pid, mid,tid, smbUtilError2String(status));
                      smbUtilErrorUpdateStats( status );

                      SmbIntLog("  Descr ERROR  %s", 
                                             smbUtilError2String(status) );
                      break;
                  }

                  sprintf( currCmdStg, "OPEN failure: %s",
                                      smbUtilNtStatus2String(ntStatus));

                  if( myLmCfg.fileshareIsEnabled )
                  {
                      encEngFmt->resetEvent( sessionEntry );
                      encEngFmt->setDimFolderContent( sessionEntry,
                                                      ssnPidMid->filename,
                                                      NULL,
                                                      ssnTid->sharename,
                                                      0 );

                      encEngFmt->setDimOperation( sessionEntry,
                                                  EVT_OPEN, "OPEN", 
                                                          strlen("OPEN") +1 );
                      encEngFmt->setDimResponse( sessionEntry, FAILED_OPERATION );
                      encEngFmt->sendCOSREvent( encodingEngine,
                                                sessionEntry,
                                                ssnUid,
                                                ssnTid,
                                                currCmdStg );
                  }

                  SmbIntLog("  %s", currCmdStg );
              }
          }

          if(    ssnPidMid->trans2SubCmd == TRANS2_FIND_FIRST2
              && ssnPidMid->trans2Parm == 0x0104 )
          {
              // 0x0104 - Find File Both Directory Info
  
              // If we can completely read it (i.e., up to the next one)
              // then access it
              if( (const u_char *)&rsp->dataOffset <= &data[length] )
              {
                  ssnPidMid->trans2DataCountRspTot += stohs(rsp->dataCount);
                  if(   ssnPidMid->trans2DataCountRspTot 
                      < stohs(rsp->totalDataCount) )
                  {
                      //  Multiple responses will be sent so preserve PidMid
                      pidMidIsToBeRemoved = false;
                  }
              }
          }

          if( ssnPidMid->trans2SubCmd == TRANS2_FIND_NEXT2 )
          {
              // All forms of FIND_NEXT2

              // If we can completely read it (i.e., up to the next one)
              // then access it
              if( (const u_char *)&rsp->dataOffset <= &data[length] )
              {

                  ssnPidMid->trans2DataCountRspTot += stohs(rsp->dataCount);
                  if(   ssnPidMid->trans2DataCountRspTot 
                      < stohs(rsp->totalDataCount) )
                  {
                      //  Multiple responses will be sent so preserve PidMid
                      pidMidIsToBeRemoved = false;
                  }
              }
          }

          // Remove the PidMid entry
          if( pidMidIsToBeRemoved )
          {
              if( SmbSsnDataRemovePidMid(sessionEntry, ssnUid, pid, mid) == IIMS_FAILURE )
              {
                  //SmbErrLog(LOG_NOTICE,"Failed Remove pid %04x mid %04x "
                  //                          "on uid %04x", pid, mid, uid );
                  ++decodeStats.failedRemove;

                  SmbIntLog("  Descr ERROR - Failed Remove PidMid" );
              }
          }

      } 
      else    // == C L I E N T   S I D E ==    (TRAFFIC_FROM_CLIENT)
      {
          SmbTransaction2Request *req =
                  (SmbTransaction2Request *)(data + sizeof(NBHeader)
                                                  + sizeof(SmbHeader) );
          LargeCmdState          *lcs = &smbInfo->reqLcs;
#if 0
          if( stohl(smbHeader->status.NTstatus) != 0 )
          {
              break;
          }
#endif

          // Handle fragmentation processing if necessary
          if( length < (  sizeof(NBHeader) 
                        + sizeof(SmbHeader)
                        + sizeof(SmbTransaction2Request)) )
          {
              handleFragBegin( sessionEntry, data, length );
              lcs->smbCommand = SMB_COM_TRANSACTION2;
              andxCmdState.cmd = 0xff;
              SmbDcdLog( sessionEntry,"FRAG    TRANS2-REQ" );
              break;
          }

          if( !smbLoginIsRequired )
          {
              // Session jump-in mode.  Check to see if we have a Uid
              // and, if not, create it
              SmbSsnUid *ssnUid = SmbSsnDataFindByUid( sessionEntry, uid );
              if( ssnUid == NULL )
              {
                  SmbSsnDataAddUid( sessionEntry, uid );
                  SmbMonLog("Fabricated UID %04x", uid);
              }
          }

          // Create a PidMid
          status = SmbSsnCreateSsnPidMid( sessionEntry,
                                          smbHeader,
                                          &ssnPidMid );
          if( status != SMB_ERROR_NONE )
          {
              //SmbErrLog(LOG_NOTICE,"%04x  %04x  %04x  %04x %s", 
              //             uid, pid, mid,tid, smbUtilError2String(status));
              smbUtilErrorUpdateStats( status );

              SmbIntLog("  Descr ERROR  %s", smbUtilError2String(status) );
              break;
          }


          // tid has servername and shareinfo - C O D E   H E R E


          SmbTrans2SetFileInfoParms *sfiReq;
          SmbTrans2QueryPathInfo *qpiReq;
          SmbTrans2QueryFSInfo *qfsiReq;
          SmbTrans2QueryFindFirst2 *ff2Req;
          SmbTrans2QueryGetDfsReferral *gdrReq;
          tz_uint8 *parmData;

          ssnPidMid->trans2SubCmd = stohs(req->setup);

          SmbIntLog("  %s ", smbUtilTrans2_2String(
                                             ssnPidMid->trans2SubCmd) );

          switch( ssnPidMid->trans2SubCmd )
          {
          case TRANS2_SET_FILE_INFORMATION:
              // Use parameterOffset and dataOffset to read the request
              sfiReq = (SmbTrans2SetFileInfoParms *)
                (data + sizeof(NBHeader) + stohs(req->parameterOffset) );

              // Save the fid which has the filename
              ssnPidMid->fid = stohs(sfiReq->fid);

              // If level of interest is 0x3f5 || 0x102 for
              // SMB_SET_FILE_DISPOSITION_INFO
              ssnPidMid->trans2Parm = stohs(sfiReq->infoLevel);

              // If data is 0x01 then file is marked for deletion
              // else it is marked for undeletion
              parmData = (tz_uint8 *)
                       (data + sizeof(NBHeader) + stohs(req->dataOffset) );
              ssnPidMid->trans2Data = *parmData;
              break;

          case TRANS2_OPEN2:
          case TRANS2_FIND_FIRST2:
              ff2Req = (SmbTrans2QueryFindFirst2 *)
                (data + sizeof(NBHeader) + stohs(req->parameterOffset) );

              ssnPidMid->trans2Parm = stohs(ff2Req->infoLevel);

              if( SmbDebug::logIsEnabled )
              {
                  SmbIntLog("%04x ", stohs(ff2Req->infoLevel) );
                  if( stohs(ff2Req->infoLevel) == 0x104 )
                  {
                      // SMB_FIND_FILE_BOTH_DIRECTORY_INFO
                      if( stohs(smbHeader->flags2) & SMB_FLAGS2_UNICODE )
                      {
                          safeLen = (TZX_512_STRING - 1) * 2;
                          smbUtilUnicodeToAscii( ff2Req->filename, safeLen,
                                                     ssnPidMid->filename );
                      }
                      else
                      {
                          safeLen = MIN( TZX_512_STRING - 1,
                                         strlen(ff2Req->filename) +1 );

                          memcpy( ssnPidMid->filename, ff2Req->filename, 
                                  safeLen);
                      }
                      SmbIntLog("%s", ssnPidMid->filename );
                  }
              }
              break;

          case TRANS2_FIND_NEXT2:
          case TRANS2_QUERY_FS_INFORMATION:
              qfsiReq = (SmbTrans2QueryFSInfo *)
                (data + sizeof(NBHeader) + stohs(req->parameterOffset) );

              // If the whole packet is there, read the data
              if( (const u_char *)qfsiReq + sizeof(SmbTrans2QueryFSInfo)
                    <= &data[length] )
              {
                  SmbIntLog("%04x", stohs(qfsiReq->infoLevel) );
              }
              break;

          case TRANS2_QUERY_PATH_INFORMATION:
              qpiReq = (SmbTrans2QueryPathInfo *)
                (data + sizeof(NBHeader) + stohs(req->parameterOffset) );

              if( SmbDebug::logIsEnabled )
              {
                  if( stohs(smbHeader->flags2) & SMB_FLAGS2_UNICODE )
                  {
                      safeLen = (TZX_512_STRING - 1) * 2;
                      smbUtilUnicodeToAscii( qpiReq->fileDirName, safeLen,
                                             currCmdStg );
                  }
                  else
                  {
                      safeLen = MIN( TZX_512_STRING - 1,
                                     strlen(qpiReq->fileDirName) +1 );
                      memcpy( currCmdStg, qpiReq->fileDirName, safeLen );
                  }
                  SmbIntLog("%s", currCmdStg );
              }
              break;

          case TRANS2_GET_DFS_REFERRAL:
              gdrReq = (SmbTrans2QueryGetDfsReferral *)
                    (data + sizeof(NBHeader) + stohs(req->parameterOffset) );

              if( SmbDebug::logIsEnabled )
              {
                  if( stohs(smbHeader->flags2) & SMB_FLAGS2_UNICODE )
                  {
                      safeLen = (TZX_512_STRING - 1) * 2;
                      smbUtilUnicodeToAscii( gdrReq->filename, safeLen,
                                             currCmdStg );
                  }
                  else
                  {
                      safeLen = MIN( TZX_512_STRING - 1,
                                     strlen(gdrReq->filename) +1 );
                      memcpy( currCmdStg, gdrReq->filename, safeLen );
                  }
                  SmbIntLog("%s", currCmdStg );
              }
              break;

          case TRANS2_REPORT_DFS_INCONSISTENCY:
              // No implementation yet

          case TRANS2_SET_PATH_INFORMATION:
          case TRANS2_QUERY_FILE_INFORMATION:
          case TRANS2_FSCTL:
          case TRANS2_IOCTL2:
          case TRANS2_FIND_NOTIFY_FIRST:
          case TRANS2_FIND_NOTIFY_NEXT:
          case TRANS2_CREATE_DIRECTORY:
          case TRANS2_SESSION_SETUP:
              // Log an unimplemented subcommand
              break;
          default:
              // Log an unknown subcommand
              break;
          }

      }

  } while(0);

  // This is a "non-Andx" command so terminate the chain
  andxCmdState.cmd = 0xff;
}

//-----------------------------------------------------------------------
// smbHandleDeleteDirectory()
//     Delete a directory with the expectation that it contains no
//     files.  The client specifies a TID and a directory path.
//-----------------------------------------------------------------------
void SmbDecode::smbHandleDeleteDirectory( SessionEntry *sessionEntry,
                                          const u_char *data,
                                          tz_uint32 length )
{
  tz_uint32         status;
  SmbHeader        *smbHeader;
  tz_uint16         uid, pid, mid, tid;
  SmbSsnUid        *ssnUid;
  SmbSsnPidMid     *ssnPidMid;
  SmbSsnTid        *ssnTid;
  tz_uint32         ntStatus = 0;
  tz_uint32         safeLen = 0;

  smbHeader = (SmbHeader *)(data + sizeof(NBHeader));
  uid       = stohs(smbHeader->userId);
  pid       = stohs(smbHeader->processId);
  mid       = stohs(smbHeader->multiplexId);
  tid       = stohs(smbHeader->treeId);

  do
  {
      // == S E R V E R   S I D E ==
      //
      if( sessionEntry->trafficDirection == TRAFFIC_FROM_SERVER )
      {
          //SmbDeleteDirResponse *rsp =
          //    (SmbDeleteDirResponse *)(data + sizeof(NBHeader)
          //                                     + sizeof(SmbHeader) );

          status = SmbSsnFindSsnDescrs( sessionEntry, smbHeader,
                                   &ssnUid, &ssnPidMid, NULL, &ssnTid );
          if( status != SMB_ERROR_NONE )
          {
              //SmbErrLog(LOG_NOTICE,"%04x  %04x  %04x  %04x %s", 
              //             uid, pid, mid,tid, smbUtilError2String(status));
              smbUtilErrorUpdateStats( status );

              SmbIntLog("  Descr ERROR  %s", smbUtilError2String(status) );
              break;
          }

          ntStatus = stohl(smbHeader->status.NTstatus);
          if( ntStatus != 0 )
          {
              // Remove the PidMid entry
              if( SmbSsnDataRemovePidMid(sessionEntry, ssnUid, pid, mid) == IIMS_FAILURE )
              {
                  //SmbErrLog(LOG_NOTICE,"Failed Remove pid %04x mid %04x "
                  //                       "on uid %04x", pid, mid, uid );
                  ++decodeStats.failedRemove;

                  SmbIntLog("  Descr ERROR - Failed Remove PidMid" );
              }

              SmbIntLog("  %s", smbUtilNtStatus2String(ntStatus) );
              break;
          }

          // Content and Operation

          // Create the command string
          sprintf( currCmdStg, "DELETE  %s", ssnPidMid->filename);

          if( myLmCfg.fileshareIsEnabled )
          {
              // Format Content and Operation
              encEngFmt->resetEvent( sessionEntry );
              encEngFmt->setDimFolderContent( sessionEntry, 
                                         ssnPidMid->filename,
                                         NULL,
                                         ssnTid->sharename,
                                         0 );
              encEngFmt->setDimOperation( sessionEntry,
                                          EVT_DELETE, "DELETE", 
                                          strlen("DELETE") +1 );

              // Format Size and Response and generate the event

              // No size for DELETE operation
              //encEngFmt->setDimSize( sessionEntry, stohs(rsp->dataLength) );
              encEngFmt->setDimResponse( sessionEntry, SUCCESSFUL_OPERATION );
              encEngFmt->sendCOSREvent( encodingEngine,
                                        sessionEntry,
                                        ssnUid,
                                        ssnTid,
                                        currCmdStg );
          }

          SmbIntLog("  %s", currCmdStg );

          // Remove the PidMid entry
          if( SmbSsnDataRemovePidMid(sessionEntry, ssnUid, pid, mid) == IIMS_FAILURE )
          {
              //SmbErrLog(LOG_NOTICE,"Failed Remove pid %04x mid %04x on uid %04x",
              //                                          pid, mid, uid );
              ++decodeStats.failedRemove;

              SmbIntLog("  Descr ERROR - Failed Remove PidMid" );
          }

      } 
      else    // == C L I E N T   S I D E ==    (TRAFFIC_FROM_CLIENT)
      {
          SmbDeleteDirRequest *req =
                  (SmbDeleteDirRequest *)(data + sizeof(NBHeader)
                                                  + sizeof(SmbHeader) );
#if 0
          if( stohl(smbHeader->status.NTstatus) != 0 )
          {
              break;
          }
#endif
          if( !smbLoginIsRequired )
          {
              // Session jump-in mode.  Check to see if we have a Uid
              // and, if not, create it
              SmbSsnUid *ssnUid = SmbSsnDataFindByUid( sessionEntry, uid );
              if( ssnUid == NULL )
              {
                  SmbSsnDataAddUid( sessionEntry, uid );
                  SmbMonLog("Fabricated UID %04x", uid);
              }
          }

          // Create a PidMid
          status = SmbSsnCreateSsnPidMid( sessionEntry,
                                          smbHeader,
                                          &ssnPidMid );
          if( status != SMB_ERROR_NONE )
          {
              //SmbErrLog(LOG_NOTICE,"%04x  %04x  %04x  %04x %s", 
              //              uid, pid, mid,tid, smbUtilError2String(status));
              smbUtilErrorUpdateStats( status );

              SmbIntLog("  Descr ERROR  %s", smbUtilError2String(status) );
              break;
          }

          // Save the directory pathname
          memset( ssnPidMid->filename, 0, TZX_512_STRING );
          if( stohs(smbHeader->flags2) & SMB_FLAGS2_UNICODE )
          {
              safeLen = (TZX_512_STRING - 1) * 2;
              smbUtilUnicodeToAscii( req->dirname, safeLen,
                                     ssnPidMid->filename );
          }
          else
          {
              safeLen = MIN( TZX_512_STRING - 1,
                             strlen(req->dirname) +1 );
              memcpy( ssnPidMid->filename, req->dirname, safeLen );
          }
      }

  } while(0);

  // This is a "non-Andx" command so terminate the chain
  andxCmdState.cmd = 0xff;
}

//-----------------------------------------------------------------------
// smbHandleRename()
//     
//
//-----------------------------------------------------------------------
void SmbDecode::smbHandleRename( SessionEntry *sessionEntry,
                                 const u_char *data,
                                 tz_uint32 length )
{
  tz_uint32         status;
  SmbHeader        *smbHeader;
  tz_uint16         uid, pid, mid, tid;
  SmbSsnUid        *ssnUid;
  SmbSsnPidMid     *ssnPidMid;
//SmbSsnFid        *ssnFid;
  SmbSsnTid        *ssnTid;
  tz_uint32         ntStatus = 0;
  tz_uint32         safeLen = 0;

  smbHeader = (SmbHeader *)(data + sizeof(NBHeader));
  uid       = stohs(smbHeader->userId);
  pid       = stohs(smbHeader->processId);
  mid       = stohs(smbHeader->multiplexId);
  tid       = stohs(smbHeader->treeId);


  do
  {
      // == S E R V E R   S I D E ==
      //
      if( sessionEntry->trafficDirection == TRAFFIC_FROM_SERVER )
      {
          //SmbRenameResponse *rsp =
          //  (SmbRenameResponse *)(data + sizeof(NBHeader)
          //                                   + sizeof(SmbHeader) );

          // Look up PidMid and Fid
          status = SmbSsnFindSsnDescrs( sessionEntry, smbHeader,
                                        &ssnUid, &ssnPidMid, NULL, &ssnTid );
          if( status != SMB_ERROR_NONE )
          {
              //SmbErrLog(LOG_NOTICE,"%04x  %04x  %04x  %04x %s", 
              //             uid, pid, mid,tid, smbUtilError2String(status));
              smbUtilErrorUpdateStats( status );

              SmbIntLog("  Descr ERROR  %s", smbUtilError2String(status) );
              break;
          }

          ntStatus = stohl(smbHeader->status.NTstatus);
          if( ntStatus != 0 )
          {
              // Remove the PidMid entry
              if( SmbSsnDataRemovePidMid(sessionEntry, ssnUid, pid, mid) == IIMS_FAILURE )
              {
                  //SmbErrLog(LOG_NOTICE,"Failed Remove pid %04x mid %04x on uid %04x",
                  //                                          pid, mid, uid );
                  ++decodeStats.failedRemove;

                  SmbIntLog("  Descr ERROR - Failed Remove PidMid" );
              }

              SmbIntLog("  %s", smbUtilNtStatus2String(ntStatus) );
              break;
          }

          // Content and Operation

          // Create the command string
          sprintf( currCmdStg, "RENAME  %s %s", ssnPidMid->filename,
                                                ssnPidMid->filename2);

          if( myLmCfg.fileshareIsEnabled )
          {
              // Format Content and Operation
              encEngFmt->resetEvent( sessionEntry );

              // We can't tell if these are dirs or files, we assume files
              // FIX - is it possible?
              encEngFmt->setDimFileContent( sessionEntry,
                                            ssnPidMid->filename,  // from
                                            ssnPidMid->filename2, // to
                                            NULL,  // sharename not used
                                            0 );

              encEngFmt->setDimOperation( sessionEntry,
                                          EVT_RENAME, "RENAME", 
                                          strlen("RENAME") +1 );

              // Format Size and Response and generate the event
              // No size dimension for RENAME
              //encEngFmt->setDimSize( sessionEntry, stohs(rsp->dataLength) );
              encEngFmt->setDimResponse( sessionEntry, SUCCESSFUL_OPERATION );
              encEngFmt->sendCOSREvent( encodingEngine,
                                        sessionEntry,
                                        ssnUid,
                                        ssnTid,
                                        currCmdStg );
          }

          SmbIntLog(" %cRENAME  from: %s  to: %s", 1 ? ' ': '#',
                                ssnPidMid->filename, ssnPidMid->filename2);

          // Remove the PidMid entry
          if( SmbSsnDataRemovePidMid(sessionEntry, ssnUid, pid, mid) == IIMS_FAILURE )
          {
              //SmbErrLog(LOG_NOTICE,"Failed Remove pid %04x mid %04x on uid %04x",
              //                                          pid, mid, uid );
              ++decodeStats.failedRemove;

              SmbIntLog("  Descr ERROR - Failed Remove PidMid" );
          }

      } 
      else    // == C L I E N T   S I D E ==    (TRAFFIC_FROM_CLIENT)
      {
          SmbRenameRequest *req =
                  (SmbRenameRequest *)(data + sizeof(NBHeader)
                                                  + sizeof(SmbHeader) );

#if 0
          if( stohl(smbHeader->status.NTstatus) != 0 )
          {
              break;
          }
#endif

          // Create a PidMid
          status = SmbSsnCreateSsnPidMid( sessionEntry,
                                          smbHeader,
                                          &ssnPidMid );
          if( status != SMB_ERROR_NONE )
          {
              //SmbErrLog(LOG_NOTICE,"%04x  %04x  %04x  %04x %s", 
              //             uid, pid, mid,tid, smbUtilError2String(status));
              smbUtilErrorUpdateStats( status );

              SmbIntLog("  Descr ERROR  %s", smbUtilError2String(status) );
              break;
          }

          // Recover the file/dir path and name strings which can be
          // either in UNICODE or ASCII format
          if( stohs(smbHeader->flags2) & SMB_FLAGS2_UNICODE )
          {
              safeLen = (TZX_512_STRING - 1) * 2;
              smbUtilUnicodeToAscii( req->oldFilename, safeLen,
                                     ssnPidMid->filename );

              tz_int8 *newFilename;
              newFilename = (tz_int8 *)((tz_int8 *)&req->oldFilename
                                  + 2 * (strlen(ssnPidMid->filename) +1) );

              // The byte after oldFilename should be 0x04
              if( newFilename[0] != 0x04 ) {
                  //SmbErrLog(LOG_NOTICE,"Unexpected bufferFormat2 value %02x",
                  //                                        newFilename[0] );

                  // We'll keep going but newFilename is going to be wrong
                  ++decodeStats.miscError;

                  SmbIntLog("  Misc ERROR - Unexpected bufferFormat2 "
                                               "value %02x", newFilename[0] );
              }
              ++newFilename;

              // There may be extra padding chars.  Adjust them out
              if( newFilename[0] == 0 || newFilename[1] != 0 )  ++newFilename;
              if( newFilename[0] == 0 || newFilename[1] != 0 )  ++newFilename;

              safeLen = (TZX_512_STRING - 1) * 2;
              smbUtilUnicodeToAscii( newFilename, safeLen,
                                     ssnPidMid->filename2 );
          }
          else
          {
              // ASCII strings

              safeLen = MIN( TZX_512_STRING - 1,
                             strlen(req->oldFilename) +1 );
              memcpy( ssnPidMid->filename, req->oldFilename, safeLen );

              tz_int8 *newFilename;
              newFilename = (tz_int8 *)((tz_int8 *)&req->oldFilename
                                        + strlen(ssnPidMid->filename) +1 );

              // The byte after oldFilename should be 0x04
              if( newFilename[0] != 0x04 ) {
                  //SmbErrLog(LOG_NOTICE,"Unexpected bufferFormat2 value %02x",
                  //                                        newFilename[0] );

                  // We'll keep going but newFilename is going to be wrong

                  ++decodeStats.miscError;

                  SmbIntLog("  Misc ERROR - Unexpected bufferFormat2 "
                                               "value %02x", newFilename[0] );
              }
              ++newFilename;

              // If extra padding chars, move past them
              if( newFilename[0] == 0 )  ++newFilename;
              if( newFilename[0] == 0 )  ++newFilename;

              memcpy( ssnPidMid->filename2, newFilename, 
                                                  strlen(newFilename) +1 );
          }
      }
  } while(0);

  // This is a "non-Andx" command so terminate the chain
  andxCmdState.cmd = 0xff;
}

//-----------------------------------------------------------------------
// smbHandleDefaultCommand()
//     This handler is for all SMB commands which are not explicitly
//     processed.
//-----------------------------------------------------------------------
void SmbDecode::smbHandleDefaultCommand( SessionEntry *sessionEntry,
                                         const u_char *data,
                                         tz_uint32 length )
{
  tz_uint32         status;
  SmbSsnUid        *ssnUid;
  SmbSsnTid        *ssnTid;

  SmbHeader        *smbHeader;
  smbHeader = (SmbHeader *)(data + sizeof(NBHeader));

  switch( andxCmdState.cmd )
  {
  // For these commands it's okay to leave them unimplemented
  case SMB_COM_LOCKING_ANDX:
  case SMB_COM_FLUSH:
  case SMB_COM_TRANSACTION:
  case SMB_COM_NT_TRANSACT:
  case SMB_COM_ECHO:
  case SMB_COM_NT_CANCEL:
  case SMB_COM_CHECK_DIRECTORY:
  case SMB_COM_QUERY_INFORMATION:
  case SMB_COM_FIND_CLOSE2:
  case SMB_COM_QUERY_INFORMATION_DISK:
  case SMB_COM_OPEN_PRINT_FILE:
  case SMB_COM_WRITE_PRINT_FILE:
  case SMB_COM_CLOSE_PRINT_FILE:
      break;

  // These commands need to be implemented
  case SMB_COM_READ_RAW:
      // If this is a request then the response will be returned without
      // a nbHeader and smbHeader so condition the rsp lcs
      if( sessionEntry->trafficDirection == TRAFFIC_FROM_CLIENT ) {
           SmbInfo *smbInfo = (SmbInfo *)sessionEntry->appInfo;
           smbInfo->rspLcs.isActive = false;
           smbInfo->rspLcs.tcpSegOffset = 0;

          // No fragmentation is in process
          smbInfo->rspLcs.fs.isActive = false;
          smbInfo->rspLcs.fs.len      = 0;
      }
  case SMB_COM_SEARCH:
  default:
      //SmbErrLog(LOG_NOTICE,"Unimplemented Cmd 0x%02x", andxCmdState.cmd );
      ++decodeStats.unimplCmdCount;

      status = SmbSsnFindSsnDescrs( sessionEntry, smbHeader,
                                    &ssnUid, NULL, NULL, &ssnTid );
      if( status != SMB_ERROR_NONE )
      {
          //SmbErrLog(LOG_NOTICE,"%04x  %04x  %04x  %04x %s", 
          //             uid, pid, mid,tid, smbUtilError2String(status));
          smbUtilErrorUpdateStats( status );

          SmbIntLog("  Descr ERROR  %s", smbUtilError2String(status) );
      }
      else if ( myLmCfg.fileshareIsEnabled )
      {
          char *pCmdStg = smbUtilCmd2String(andxCmdState.cmd);
          sprintf( currCmdStg, "%s", pCmdStg);

          encEngFmt->resetEvent( sessionEntry );
          encEngFmt->sendUnsuppEvent( encodingEngine,
                                      sessionEntry,
                                      ssnUid,
                                      ssnTid,
                                      currCmdStg );
      }
  }

  // Terminate the command chain
  andxCmdState.cmd = 0xff;
}

//-----------------------------------------------------------------------
// handleFragBegin()
//     Initiate the reassembly of fragments of a codepoint command 
//     byte sequence
//-----------------------------------------------------------------------
void SmbDecode::handleFragBegin( SessionEntry *sessionEntry,
                                 const u_char *data,
                                 tz_uint32     length )
{
    SmbInfo       *smbInfo = (SmbInfo *)sessionEntry->appInfo;
    tz_uint32      thisSz = length;
    tz_uint32      fragBlocks;
    tz_uint32      availSz;

    tz_uint32      newDataSz;
    tz_int8       *newData;
    LargeCmdState *lcs;

    // We expect to be in Large Command State
    sessionEntry->trafficDirection == TRAFFIC_FROM_CLIENT
                      ? lcs = &smbInfo->reqLcs : lcs = &smbInfo->rspLcs;
//    TZ_ASSERT(lcs->isActive == true, 
//                    "SMB fragmentation when NOT in Large Command State");

    do
    {
        // Is the size of the current reassembly buf large enough?
        availSz = lcs->fs.dataSz - lcs->fs.len;

        if( availSz < thisSz )
        {
            // It isn't so boost the size by one FRAG_BLOCK unit
            fragBlocks = 
                (((lcs->fs.len + thisSz) / SMB_FRAG_BLOCK_LEN) + 1);

            //if( decodeStats.maxFragBlocks < fragBlocks ) {
            //    decodeStats.maxFragBlocks = fragBlocks;
            //}

            newDataSz = fragBlocks * SMB_FRAG_BLOCK_LEN;
            newData = (tz_int8 *)realloc(lcs->fs.data, newDataSz);
            if( newData == NULL )
            {
                SmbErrLog(LOG_NOTICE,"SMB - Fragmentation Allocation Failure");
                break;
            }
            else
            {
                lcs->fs.data = newData;
                lcs->fs.dataSz = newDataSz;
            }
        } 

        // The reassembly buffer is now large enough
        lcs->fs.isActive = true;

        memcpy( lcs->fs.data + lcs->fs.len,
                data,
                thisSz );

        lcs->fs.len += thisSz;

        //SmbIntLog("  FRAG %d", lcs->fs.len );

#if 0
        // Fragmentation observation
        SmbIntLog("  FRAG %d", smbInfo->lcs.remainInPkt );
        lcs->fs.isActive = true;
#endif

    } while (0);
}

//-----------------------------------------------------------------------
// handleFragCont()
//     Continue the reassembly of fragments of a codepoint command 
//     byte sequence.  The Large Command Statemachine keeps track of
//     the bookkeeping.  When all fragments have been reassembled then
//     fs.data points to a complete codepoint byte sequence.  Parsing
//     it will never induce fragmentation because all the data is in
//     the buffer.  This is why only one fragment reassembly mechanism
//     is needed.
//-----------------------------------------------------------------------
void SmbDecode::handleFragCont( SessionEntry *sessionEntry,
                                const u_char *data, 
                                tz_uint32     length )
{
    SmbInfo       *smbInfo = (SmbInfo *)sessionEntry->appInfo;
    tz_uint32      thisSz = length;
    tz_uint32      fragBlocks;
    tz_uint32      availSz;

    tz_uint32      newDataSz;
    tz_int8       *newData;
    LargeCmdState *lcs;


    sessionEntry->trafficDirection == TRAFFIC_FROM_CLIENT
                      ? lcs = &smbInfo->reqLcs : lcs = &smbInfo->rspLcs;

    do
    {
        // Is current reassembly buf large enough?
        availSz =  lcs->fs.dataSz - lcs->fs.len;

        if( availSz < thisSz )
        {
            // It isn't so boost the size by one FRAG_BLOCK unit
            fragBlocks = 
                (((lcs->fs.len + thisSz) / SMB_FRAG_BLOCK_LEN) + 1);

            //if( decodeStats.maxFragBlocks < fragBlocks ) {
            //    decodeStats.maxFragBlocks = fragBlocks;
            //}

            newDataSz = fragBlocks * SMB_FRAG_BLOCK_LEN;
            newData = (tz_int8 *)realloc(lcs->fs.data, newDataSz);
            if( newData == NULL )
            {
                SmbErrLog(LOG_NOTICE,"SMB - Fragmentation Allocation Failure");
                break;
            }
            else
            {
                lcs->fs.data = newData;
                lcs->fs.dataSz = newDataSz;
            }
        }

        // The reassembly buffer is now large enough

        memcpy( lcs->fs.data + lcs->fs.len,
                data,
                thisSz );

        lcs->fs.len += thisSz;

    } while (0);
}

//-----------------------------------------------------------------------
// smbTdsEncapsClientReq()
//     Process client-side encapsulated TDS data.
//-----------------------------------------------------------------------
void SmbDecode::smbTdsEncapsClientReq( SessionEntry *sessionEntry,
                                       SmbTdsEncaps *tdsEncaps,
                                       tz_uint8     *data,
                                       tz_uint32     length )
{
    //SmbInfo      *smbInfo = (SmbInfo *)sessionEntry->appInfo;


    // Prepare for stacked TDS call by saving SMB state and
    // restoring TDS
    tdsEncaps->smbSsnDetail = sessionEntry->sessionDetail;
    tdsEncaps->smbInfo = (SmbInfo *)sessionEntry->appInfo;
    tdsEncaps->smbId = sessionEntry->id;

    sessionEntry->sessionDetail = tdsEncaps->tdsSsnDetail;
    sessionEntry->appInfo = tdsEncaps->tdsInfo;
    sessionEntry->id = tdsEncaps->tdsId;

    // Convince TDS that we're listening to SQL Server
    sessionEntry->application = PROTOCOL_TDS_MS_SS;

    // Traffic direction is already TRAFFIC_FROM_CLIENT so keep

    // FIX - a hack to placate the TDS decoder

    // (This is unfortunate, as TDS is very dependent on knowing that the
    // "first" packet on the "session" is a login.  LOGIN is a singular event
    // for TDS, as it defines the byte-sex of various fields, and the presence
    // or absence of attribute fields (particularly the version-8 "collate
    // sequence").
    sessionEntry->tcpState[TRAFFIC_FROM_CLIENT].flags |= SESS_SYN;

    if (sessionEntry->appInfo == NULL)
        sessionEntry->appInfo = tdsDecode->CreateProtocolData (sessionEntry);

    // Make the stacked call
    tdsDecode->processTDSPacket( sessionEntry,
                                 data,
                                 length,
                                 false );  // !tcpHole

    // Recover from stacked TDS call by saving TDS changes and
    // restoring SMB
    tdsEncaps->tdsSsnDetail = sessionEntry->sessionDetail;
    tdsEncaps->tdsInfo = (TdsInfo *)sessionEntry->appInfo;
    tdsEncaps->tdsId = sessionEntry->id;

    sessionEntry->sessionDetail = tdsEncaps->smbSsnDetail;
    sessionEntry->appInfo = tdsEncaps->smbInfo;
    sessionEntry->id = tdsEncaps->smbId;

    // We're back monitoring SMB
    sessionEntry->application = PROTOCOL_SMB;
}

//-----------------------------------------------------------------------
// smbTdsEncapsServerRsp()
//
//-----------------------------------------------------------------------
void SmbDecode::smbTdsEncapsServerRsp( SessionEntry *sessionEntry,
                                       SmbTdsEncaps *tdsEncaps,
                                       tz_uint8     *data,
                                       tz_uint32     length )
{
    //SmbInfo      *smbInfo = (SmbInfo *)sessionEntry->appInfo;


    // Prepare for stacked TDS call by saving SMB state and
    // restoring TDS
    tdsEncaps->smbSsnDetail = sessionEntry->sessionDetail;
    tdsEncaps->smbInfo = (SmbInfo *)sessionEntry->appInfo;
    tdsEncaps->smbId = sessionEntry->id;

    sessionEntry->sessionDetail = tdsEncaps->tdsSsnDetail;
    sessionEntry->appInfo = tdsEncaps->tdsInfo;
    sessionEntry->id = tdsEncaps->tdsId;

    // Convince TDS that we're listening to SQL Server
    sessionEntry->application = PROTOCOL_TDS_MS_SS;

    // Traffic direction is already TRAFFIC_FROM_CLIENT so keep

    // FIX - a hack to placate the TDS decoder
    sessionEntry->tcpState[TRAFFIC_FROM_CLIENT].flags |= SESS_SYN;

    // Make the stacked call
    // TBD: gap detection is extremely important for TDS,
    // as it controls various recovery actions.
    tdsDecode->processTDSPacket( sessionEntry,
                                 data,
                                 length,
                                 false );  // !tcpHole

    // Recover from stacked TDS call by saving TDS changes and
    // restoring SMB
    tdsEncaps->tdsSsnDetail = sessionEntry->sessionDetail;
    tdsEncaps->tdsInfo = (TdsInfo *)sessionEntry->appInfo;
    tdsEncaps->tdsId = sessionEntry->id;

    sessionEntry->sessionDetail = tdsEncaps->smbSsnDetail;
    sessionEntry->appInfo = tdsEncaps->smbInfo;
    sessionEntry->id = tdsEncaps->smbId;

    // We're back monitoring SMB
    sessionEntry->application = PROTOCOL_SMB;
}

//-----------------------------------------------------------------------
// smbTdsEncapsFidIsNP()
//     Test if FID filename is a configured Named Pipe
//-----------------------------------------------------------------------
bool SmbDecode::smbTdsEncapsFidIsNP( SessionEntry *sessionEntry,
                                     tz_int8      *fidName )
{
    bool         isNP = false;
    PipeStgData *thisPipe;


    thisPipe = myLmCfg.pipeStgList;

    while( thisPipe )
    {
        // Do a case insensitive search for the pipe name
        if( tz_stristr(fidName, thisPipe->pipeName) )
        {
            // F I X - this code may be unnecessary, the driver has
            // already determined that the SMB adapter should get
            // traffic for this server
#if 1
            tz_uint32 server =   sessionEntry->clientIsDst
                               ? sessionEntry->addressTuple.src 
                               : sessionEntry->addressTuple.dst;

            // Test server all or match on specified server
            if(   thisPipe->server == 0 
               || thisPipe->server == ntohl(server) )
            {
                isNP = true;
                break;
            }
#else
            isNP = true;
            break;
#endif
        }

        thisPipe = thisPipe->next;
    }

    return isNP;
}

//-----------------------------------------------------------------------
// smbTdsEncapsLogout()
//     Create a Named Pipe Logout Event
//-----------------------------------------------------------------------
void SmbDecode::smbTdsEncapsLogout( SessionEntry *sessionEntry,
                                    SmbTdsEncaps *tdsEncaps )
{
    // Restore TDS session data in preparation for Logout event
    tdsEncaps->smbSsnDetail = sessionEntry->sessionDetail;
    tdsEncaps->smbInfo = (SmbInfo *)sessionEntry->appInfo;
    tdsEncaps->smbId = sessionEntry->id;

    sessionEntry->sessionDetail = tdsEncaps->tdsSsnDetail;
    sessionEntry->appInfo = tdsEncaps->tdsInfo;
    sessionEntry->id = tdsEncaps->tdsId;

    // Generate the Logout
    encodingEngine->SessionLogout( sessionEntry, SESSION_CLOSE_CLEAN );

    // Restore SMB session data
    tdsEncaps->tdsSsnDetail = sessionEntry->sessionDetail;
    tdsEncaps->tdsInfo = (TdsInfo *)sessionEntry->appInfo;
    tdsEncaps->tdsId = sessionEntry->id;

    sessionEntry->sessionDetail = tdsEncaps->smbSsnDetail;
    sessionEntry->appInfo = tdsEncaps->smbInfo;
    sessionEntry->id = tdsEncaps->smbId;

    // FIX - unflag the session as being logged out as SessionLogout()
    //       has done
    sessionEntry->loggedOut = 0;

    // Free TDS sessionDetail
    if( tdsEncaps->tdsSsnDetail )
    {
        free( tdsEncaps->tdsSsnDetail );
    }

    // Free TDS appInfo (which also handles the NULL case).  Record this
    // session's appInfo in case it gets wiped by the call.
    void *smbInfo = sessionEntry->appInfo;
    tdsDecode->freeTDSSession((TdsInfo *)tdsEncaps->tdsInfo);

    // As a result of freeTDSSession() the TDS decoder may decide to
    // preemptively inhibit the use of the "parent session" for
    // further activity.  Undo it for named pipes operation and restore
    // appInfo
    if( sessionEntry->badSession == 1 )
    {
        sessionEntry->badSession = 0;
        sessionEntry->appInfo = smbInfo;
    }
}

//-----------------------------------------------------------------------
// smbLmCfgProcess()
//
// NOTE: This code mirrors NetMonDriver::UpdateNamedPipes()
//       Changes there require changes here.
//-----------------------------------------------------------------------
void SmbDecode::smbLmCfgProcess( LmCfgSmb * lmCfg )
{
    PipeStgData *newPipe;
    PipeStgData *thisPipe, *nextPipe;

    if( lmCfg->pipeStgListChgSeqNum != myLmCfg.pipeStgListChgSeqNum )
    {
        // The pipe string list has changed so reconstruct our copy.
        // Start by removing the list that we've had to this point.
        thisPipe = myLmCfg.pipeStgList;
        while( thisPipe )
        {
            nextPipe = thisPipe->next;

            // Deallocate memory
            free( thisPipe->interface );
            free( thisPipe->pipeName );

            free( thisPipe );
            thisPipe = nextPipe;
        }
        myLmCfg.pipeStgList = NULL;

        // Now copy the LM list
        PipeStgData *lmPipe;
        lmPipe = lmCfg->pipeStgList;

        while( lmPipe )
        {
             newPipe = (PipeStgData *)calloc(1, sizeof(PipeStgData));

            // Store the data
            newPipe->server      = lmPipe->server;
            newPipe->nullServer  = lmPipe->nullServer;
            newPipe->pipeName    = strndup((char *)lmPipe->pipeName,
                                      strlen((char *)lmPipe->pipeName));
            newPipe->nullPipe    = lmPipe->nullPipe;
            newPipe->interface   = strndup((char *)lmPipe->interface,
                                     strlen((char *)lmPipe->interface));
            newPipe->application = lmPipe->application;

            // Add it to the list
            if( myLmCfg.pipeStgList == NULL )
            {
                newPipe->next = NULL;
                myLmCfg.pipeStgList = newPipe;
            }
            else
            {
                newPipe->next = myLmCfg.pipeStgList;
                myLmCfg.pipeStgList = newPipe;
            }

            // D E B U G
            //printf("SMB pipe entry 0x%0lx %s\n", newPipe->server, 
            //                                     newPipe->pipeName);

            lmPipe = lmPipe->next;
        }

        // D E B U G
        //printf("- - - - - - - - - - - - - - -\n");

        // Accept the pipe string list update
        myLmCfg.pipeStgListChgSeqNum = lmCfg->pipeStgListChgSeqNum;
    }

    // Accept the mode variables
    if( myLmCfg.fileshareIsEnabled != lmCfg->fileshareIsEnabled )
    {
        myLmCfg.fileshareIsEnabled = lmCfg->fileshareIsEnabled;

        // D E B U G
        //printf("SMB fileshare %s\n", myLmCfg.fileshareIsEnabled ?
        //                                    "enabled" : "disabled");
    }

    if( myLmCfg.tdsNamedPipeIsEnabled != lmCfg->tdsNamedPipeIsEnabled )
    {
        myLmCfg.tdsNamedPipeIsEnabled = lmCfg->tdsNamedPipeIsEnabled;

        // D E B U G
        //printf("SMB named pipe %s\n", myLmCfg.tdsNamedPipeIsEnabled ?
        //                                    "enabled" : "disabled");
    }
}

//======================================================================
// Protocol Specific Authentication Functions
//======================================================================

//-----------------------------------------------------------------------
// smbAuthNoExtSec
//     Extended Security Disabled
//-----------------------------------------------------------------------
void SmbDecode::smbAuthNoExtSec( SessionEntry *sessionEntry,
                                 SmbHeader    *smbHeader,
                                 void         *hdr )
{
  SmbSsnSetupAndxNTLM012NoExtSecRequest  *req;
  SmbSsnSetupAndxNTLM012NoExtSecResponse *rsp;
  SmbInfo *smbInfo = (SmbInfo *)sessionEntry->appInfo;
  tz_uint16 uid;
  tz_uint32 safeLen = 0;

  uid = stohs(smbHeader->userId);

  do
  {
      // == S E R V E R   S I D E ==
      if( sessionEntry->trafficDirection == TRAFFIC_FROM_SERVER )
      {
          rsp = (SmbSsnSetupAndxNTLM012NoExtSecResponse *)hdr;

          // Update Andx State
          andxCmdState.cmd = rsp->andxCommand;
          andxCmdState.offset = stohs(rsp->andxOffset);

          // Create the UID descriptor if it hasn't already been done
          SmbSsnUid *ssnUid = SmbSsnDataFindByUid( 
                              sessionEntry, uid );
          if( ssnUid == NULL )
          {
              SmbSsnDataAddUid( sessionEntry, uid );

              // Look up the new Uid
              ssnUid = SmbSsnDataFindByUid( sessionEntry, uid );

              SmbMonLog("NoExtSec UID %04x  %s", uid, smbInfo->serverUser );
          }

          // The user is considered authenticated
          ssnUid->authIsCompleted = true;

          if( stohs(rsp->action) & 0x01 )
          {
              // Guest login
              strcpy( smbInfo->serverUser, "GUEST" );
          }

          SmbIntLog("  serverUser: %s", smbInfo->serverUser);

      } 
      else  // == C L I E N T   S I D E ==    (TRAFFIC_FROM_CLIENT)
      {
          req = (SmbSsnSetupAndxNTLM012NoExtSecRequest *)hdr;

          // Update Andx State
          andxCmdState.cmd = req->andxCommand;
          andxCmdState.offset = stohs(req->andxOffset);

          SmbInfo *smbInfo = (SmbInfo *)sessionEntry->appInfo;

          // Save the client's max multiplex count
          smbInfo->cliMaxMpxCount = req->maxMpxCount;

          // D E B U G
          //printf("  {%d}", req->maxMpxCount );
          //fflush( stdout );

          if(   stohs(req->ansiPasswdLen <= 1 ) 
             && stohs(req->unicodePasswdLen) <= 1 )
          {
              break;
          }

          tz_int8 *userName = (tz_int8 *)
                              ((tz_int8 *)&req->ansiPasswd
                             + stohs(req->ansiPasswdLen)
                             + stohs(req->unicodePasswdLen) );
          tz_int8 *hostName;

          if( stohs(smbHeader->flags2) & SMB_FLAGS2_UNICODE )
          {
              // There may be extra padding characters.  If they're
              // there then advance to the first valid unicode char
              if( userName[0] == 0 || userName[1] != 0 )  ++userName;
              if( userName[0] == 0 || userName[1] != 0 )  ++userName;

              safeLen = (TZX_512_STRING - 1) * 2;
              smbUtilUnicodeToAscii( userName, safeLen, smbInfo->serverUser );
              // hostName just after userName
              hostName = (tz_int8 *)(userName 
                                     + 2 * (strlen(smbInfo->serverUser) +1) );
              smbUtilUnicodeToAscii( hostName, safeLen, smbInfo->hostUser );
          }
          else
          {
              // ASCII strings

              // If extra padding chars, move past them
              if( userName[0] == 0 )  ++userName;
              if( userName[0] == 0 )  ++userName;

              // HostName from PrimaryDomain (just after userName)
              hostName = (tz_int8 *)
                          (userName
                         + strlen(userName) + 1 );

              // serverInfo not available

              safeLen = MIN( TZX_512_STRING - 1,
                             strlen(userName) +1 );
              memcpy( smbInfo->serverUser, userName, safeLen );
              safeLen = MIN( TZX_512_STRING - 1,
                             strlen(hostName) +1 );
              memcpy( smbInfo->hostUser, hostName, safeLen );
          }

          SmbIntLog("  serverUser: %s", smbInfo->serverUser);
      }
  } while (0);
}

//-----------------------------------------------------------------------
// smbAuthExtSec
//     Extended Security Enabled
//-----------------------------------------------------------------------
void SmbDecode::smbAuthExtSec( SessionEntry *sessionEntry,
                               SmbHeader    *smbHeader,
                               void         *hdr )
{
  SmbSsnSetupAndxNTLM012ExtSecRequest *req;
  SmbSsnSetupAndxNTLM012ExtSecResponse *rsp;
  SmbInfo *smbInfo = (SmbInfo *)sessionEntry->appInfo;
  tz_uint16 uid;
  bool      isNtlmRaw = false;
  tz_uint32 safeLen = 0;

  uid = stohs(smbHeader->userId);

  do
  {
      // == S E R V E R   S I D E ==
      if( sessionEntry->trafficDirection == TRAFFIC_FROM_SERVER )
      {
          rsp = (SmbSsnSetupAndxNTLM012ExtSecResponse *)hdr;

          // Update Andx State
          andxCmdState.cmd = rsp->andxCommand;
          andxCmdState.offset = stohs(rsp->andxOffset);

          if(    smbInfo->ntlmSspState == SMB_NTLMSSP_AUTH
              || smbInfo->krb5State == SMB_KRB5_AUTH )
          {
              // Save the new UID for chained commands
              //andxCmdState.uid = uid;

              // D E B U G
              tz_uint32 s = (tz_uint32)-1;
              if( smbInfo->ntlmSspState == SMB_NTLMSSP_AUTH ) {
                  s = SMB_NTLMSSP_AUTH;
              }
              if( smbInfo->krb5State == SMB_KRB5_AUTH ) {
                  s = SMB_KRB5_AUTH;
              }

              // Create the UID descriptor if it hasn't already been
              // done.  If we're in "session jump-in mode" 
              // (smbLoginIsRequired FALSE) we're still going to want
              //  the Uid descriptor to be created here.  The 
              // descriptor will live until it is deleted during a
              //  Logoff request by the client.
              SmbSsnUid *ssnUid = SmbSsnDataFindByUid( 
                                  sessionEntry, uid );
              if( ssnUid == NULL )
              {
                  SmbSsnDataAddUid( sessionEntry, uid );

                  // Look up the new Uid
                  ssnUid = SmbSsnDataFindByUid( sessionEntry, uid );

                  SmbMonLog("ExtSec %lx UID %04x  serverUser %s  "
                                        "hostUser %s",
                         s, uid, smbInfo->serverUser, smbInfo->hostUser );
              }

              // Check for special case of SMB_NTLMSSP_AUTH successful
              // but where user is actually logged in as GUEST
              if(    smbInfo->ntlmSspState == SMB_NTLMSSP_AUTH
                  && stohs(rsp->action) & 0x01 )
              {
                  // Guest login is in effect
                  strcpy( smbInfo->serverUser, "GUEST" );

                  SmbMonLog("ExtSec %lx UID %04x  changed to %s",
                                          s, uid, smbInfo->serverUser );

                  SmbIntLog("  serverUser changed to: %s",
                                                   smbInfo->serverUser);
              }

              // The user is considered authenticated
              ssnUid->authIsCompleted = true;

              // Reset the security states
              smbInfo->ntlmSspState = SMB_NTLMSSP_UNKNOWN;
              smbInfo->krb5State = SMB_KRB5_UNKNOWN;
          }
      } 
      else  // == C L I E N T   S I D E ==    (TRAFFIC_FROM_CLIENT)
      {
          SmbNtlmSsp *ntlmSspReq = NULL;
          req = (SmbSsnSetupAndxNTLM012ExtSecRequest *)hdr;

          // Update Andx State
          andxCmdState.cmd = req->andxCommand;
          andxCmdState.offset = stohs(req->andxOffset);

          // Save the client's max multiplex count
          smbInfo->cliMaxMpxCount = req->maxMpxCnt;

          // D E B U G
          //printf("  [%d]", req->maxMpxCnt );
          //fflush( stdout );

          // Identify which security is being used
          tz_uint32 spnegoToken;
          OidType   oidType;

          if( stohs(req->SecurityBlobLength) > 0 )
          {
              // There is a Security Blob attached so parse it
              spnegoToken = smbAuthParseSpnego( req->SecurityBlob,
                                                oidType);
          } else {
              // No Security Blob
              SmbErrLog(LOG_NOTICE,"Extended Security but "
                                                 "NO SECURITY BLOB");
              break;
          }

          if( spnegoToken == SMB_SPNEGO_ERROR )
          {
              // Check if the blob format is Raw NTLMSSP which will have
              // the string right at the beginning of the blob

              if( !memcmp(&req->SecurityBlob[0], "NTLMSSP", 8) )
              {
                  // I did.  I did.  I did tee a puttytat
                  // (interpretation: it's Raw NTLM)
                  isNtlmRaw = true;
              }
              else
              {
                  SmbErrLog(LOG_NOTICE,"NTLM ExtSec is neither GSS-API "
                                                             "nor Raw");
                  break;
              }
          }

          // Check for Kerberos
          if(   spnegoToken == SMB_SPNEGO_NEG_TOKEN_INIT
             && (   oidType == OID_MS_KRB5
                 || oidType == OID_MS_KRB5_LGCY ) )
          {
              // Kerberos, baby.  When the Rsp is received we expect
              // it to be AUTH.  We're "waiting for AUTH"
              smbInfo->krb5State = SMB_KRB5_AUTH;

              struct in_addr srcAddr;
              
              srcAddr.s_addr = sessionEntry->clientIsDst ?
                               sessionEntry->addressTuple.dst :
                               sessionEntry->addressTuple.src;

              strcpy( currCmdStg, "USER_" );
              strcat( currCmdStg, inet_ntoa(srcAddr) );

              // serverUser (a.k.a. UserName)
              memcpy( smbInfo->serverUser, currCmdStg, 
                                               strlen(currCmdStg) +1);

              SmbIntLog("  client: %s", currCmdStg );
              break;
          }

          // Check for NTLM Raw mode
          if( isNtlmRaw )
          {
              ntlmSspReq = (SmbNtlmSsp *)&req->SecurityBlob[0];

              // Quit because this is only the NTLMSSP_NEGOTIATE client
              // request
              if( SMB_NTLMSSP_NEGOTIATE == stohl(ntlmSspReq->ntlmSspType) )
              {
                  // Print the NTLMSSP type code
                  SmbIntLog("  %s NTLM-Raw", smbUtilNtlmssp2String(
                                                 SMB_NTLMSSP_NEGOTIATE ));
                  break;
              }
          }

          // Check for NTLM GSS-API mode
          if(   spnegoToken == SMB_SPNEGO_NEG_TOKEN_INIT
                  && oidType == OID_NTLMSSP )
          {
              // Quit because this is only the NTLMSSP_NEGOTIATE client 
              //request
              smbInfo->ntlmSspState = SMB_NTLMSSP_NEGOTIATE;

              // Print the NTLMSSP type code which we infer.
              SmbIntLog("  %s NTLM-GSS-API", smbUtilNtlmssp2String(
                                               SMB_NTLMSSP_NEGOTIATE ));
              break;
          }

          // We do NOT want this test in here.  It is only valid for
          // NTLMSSP.  It is invalid for the ntlm raw case because
          // spnegoToken will be ERROR (0) and ntlmSspState will be
          // UNKNOWN (0) because there is no SPNEGO content in the blob
#if 0
          if(   spnegoToken != SMB_SPNEGO_NEG_TOKEN_TARG
             || smbInfo->ntlmSspState != SMB_NTLMSSP_NEGOTIATE )
          {
              // D E B U G
              if( netMonDriver->pktLog->pktLogIsEnabled && isNtlmRaw )
              {
                  // This is for setting a breakpoint
                  volatile tz_uint32 baz;  ++baz;
                  // Dump a cap file
                  netMonDriver->pktLog->pktLogDump();
              }

              // This is NOT an NTLMSSP_AUTH client request so we cannot
              // proceed.
              SmbErrLog(LOG_NOTICE,"smbAuthExtSec() authentication ERROR: "
                                   "unexpected state");
              smbUtilDisplaySmbInfo( sessionEntry );
              lc_log_basic(LOG_NOTICE," spnegoToken: %02lx    ntlmSspState: %02lx",
                                     spnegoToken, smbInfo->ntlmSspState );
              lc_log_basic(LOG_NOTICE,"     oidType: %02lx       isNtlmRaw: %02lx",
                               (tz_uint32)oidType, (tz_uint32)isNtlmRaw );
              break;
          }
#endif

          // The remainder of code below is for processing an NTLMSSP_AUTH
          // client request whether we're in NTLM GSS-API mode or NTLM Raw
          // mode.  When the Rsp comes in we expect it to be AUTH.  We're
          // "waiting for AUTH"
          smbInfo->ntlmSspState = SMB_NTLMSSP_AUTH;

          //  Look for the NTLMSSP magic string to align the request 
          // structure.
          for( tz_uint32 i = 0; i < stohs(req->SecurityBlobLength); ++i )
          {
              if( req->SecurityBlob[i] == 'N')
              {
                  if(    req->SecurityBlob[i+1] == 'T' 
                      && req->SecurityBlob[i+2] == 'L'
                      && req->SecurityBlob[i+3] == 'M' 
                      && req->SecurityBlob[i+4] == 'S'
                      && req->SecurityBlob[i+5] == 'S'
                      && req->SecurityBlob[i+6] == 'P' )
                  {
                      ntlmSspReq = (SmbNtlmSsp *)&req->SecurityBlob[i];
                  }

              }
          }

          if( ntlmSspReq == NULL )
          {
              SmbErrLog(LOG_NOTICE,"smbAuthExtSec() authentication ERROR: "
                                   "magic string lookup failure");
              smbUtilDisplaySmbInfo( sessionEntry );
              lc_log_basic(LOG_NOTICE," spnegoToken: %02lx    ntlmSspState: %02lx",
                                     spnegoToken, smbInfo->ntlmSspState );
              lc_log_basic(LOG_NOTICE,"     oidType: %02lx       isNtlmRaw: %02lx",
                               (tz_uint32)oidType, (tz_uint32)isNtlmRaw );
              break;
          }

          // The NTLMSSP type code is right after the magic string
          SmbIntLog("  %s NTLM-%s", smbUtilNtlmssp2String(
                                    stohl(ntlmSspReq->ntlmSspType)),
                                    isNtlmRaw ? "Raw" : "GSS-API" );

          // For NTLMSSP where the request is AUTH we will latch
          // session parameters
          smbInfo->ntlmSspState = stohl(ntlmSspReq->ntlmSspType);


          // Establish pointers
          tz_int8 *userName = (tz_int8 *)
                               ((tz_int8 *)ntlmSspReq
                              + stohl(ntlmSspReq->userOffset) );
          tz_int8 *domainName = (tz_int8 *)
                               ((tz_int8 *)ntlmSspReq
                              + stohl(ntlmSspReq->domainOffset) );
          tz_int8 *hostName = (tz_int8 *)
                               ((tz_int8 *)ntlmSspReq
                              + stohl(ntlmSspReq->hostOffset) );

          tz_uint16 userLen = stohs(ntlmSspReq->userLen);
          if( userLen > TZX_512_STRING-1 ) { 
              SmbErrLog(LOG_NOTICE,"userLen %d out of range", userLen );
              break;
          }

          tz_uint16 domainLen = stohs(ntlmSspReq->domainLen);
          if( domainLen > TZX_64_STRING-1 ) { 
              SmbErrLog(LOG_NOTICE,"domainLen %d out of range", domainLen );
              break;
          }

          tz_uint16 hostLen = stohs(ntlmSspReq->hostLen);
          if( hostLen > TZX_512_STRING-1 ) { 
              SmbErrLog(LOG_NOTICE,"hostLen %d out of range", hostLen );
              break;
          }

          if( stohs(smbHeader->flags2) & SMB_FLAGS2_UNICODE )
          {
              // ServerInfo
              if( domainLen )
              {
                  safeLen = MIN( (TZX_512_STRING - 1) * 2,
                                 stohs(ntlmSspReq->domainLen) );
                  smbUtilUnicodeToAscii( domainName, 
                                         safeLen,
                                         smbInfo->domainName );
              } else {
                  smbInfo->domainName[0] = '\0';
              }

              // UserName
              if( userLen )
              {
                  safeLen = MIN( (TZX_512_STRING - 1) * 2,
                                 stohs(ntlmSspReq->userLen) );
                  smbUtilUnicodeToAscii( userName, 
                                         safeLen,
                                         smbInfo->serverUser );
              } else {
                  smbInfo->serverUser[0] = '\0';
              }

              // HostName
              if( hostLen )
              {
                  safeLen = MIN( (TZX_512_STRING - 1) * 2,
                                 stohs(ntlmSspReq->hostLen) );
                  smbUtilUnicodeToAscii( hostName, 
                                         safeLen,
                                         smbInfo->hostUser );
              } else {
                  smbInfo->hostUser[0] = '\0';
              }
          }
          else
          {
              // ASCII strings
              if( domainLen )
              {
                  safeLen = MIN( TZX_512_STRING - 1,
                                 strlen(domainName) +1 );

                  memcpy( smbInfo->domainName, domainName, safeLen );
              } else {
                  smbInfo->domainName[0] = '\0';
              }

              if( userLen )
              {
                  safeLen = MIN( TZX_512_STRING - 1,
                                 strlen(userName) +1 );
                  memcpy( smbInfo->serverUser, userName, safeLen );
              } else {
                  smbInfo->serverUser[0] = '\0';
              }

              if( hostLen )
              {
                  safeLen = MIN( TZX_512_STRING - 1,
                                 strlen(hostName) +1 );
                  memcpy( smbInfo->hostUser, hostName, safeLen );
              } else {
                  smbInfo->hostUser[0] = '\0';
              }
          }

          SmbIntLog("  domainName: %s", smbInfo->domainName);
          SmbIntLog("  serverUser: %s", smbInfo->serverUser);
          SmbIntLog("  hostUser: %s", smbInfo->hostUser);

      }
  } while (0);
}

//-----------------------------------------------------------------------
// smbAuthParseSpnego
//     Parse the SPNEGO security blob in the GSS-API payload.  For the
//     Kerberos case there is only one request coming from the client
//     and it's NegTokenInit.  For the NTLMSSP case the client sends
//     two requests.  The first is NegTokenInit and it's for 
//     NTLMSSP_NEGOTIATE.  The second is NegTokenTarg and it's for
//     NTLMSSP_AUTH.
//
// returns:
//     SMB_SPNEGO_NEG_TOKEN_INIT
//     SMB_SPNEGO_NEG_TOKEN_TARG
//     SMB_SPNEGO_ERROR
//-----------------------------------------------------------------------
tz_uint32 SmbDecode::smbAuthParseSpnego( tz_uint8 *data, OidType &oidType )
{
  tz_uint32 ret = SMB_SPNEGO_ERROR;
  tz_uint32 idx = 0;
  tz_uint32 len;
  tz_uint32 bytes;

  do
  {
      // Not sure what the oidType is yet
      oidType = OID_UNKNOWN;

     // Test if the first byte is a NegTokenTarg.  If so then this is an
     // NTLMSSP_AUTH packet from the client and our work here is done.
     if( data[idx] == SMB_SPNEGO_NEGTARG_TOKEN_IDENTIFIER )
     {
         // We're done - NegTokenTarg
         ret = SMB_SPNEGO_NEG_TOKEN_TARG;
         break;
     }

     // If first byte was not a NegTokenTarg then we expect that it is the
     // Application Constructed Object from RFC 2078.
     if( data[idx] != SMB_SPNEGO_NEGINIT_APP_CONSTRUCT )
     {
         // We're done - It's NOT NegTokenInit, that's bad
         ret = SMB_SPNEGO_ERROR;
         break;
     }

     // Advance idx to length field
     ++idx;
     if( smbUtilAsnDerGetLength( &data[idx], &len, &bytes ) == IIMS_FAILURE )
     {
         //SmbErrLog(LOG_NOTICE,"smbUtilAsnDerGetLength FAILED");
         ++decodeStats.miscError;

         SmbIntLog("  Misc ERROR - smbUtilAsnDerGetLength FAILED" );
         ret = SMB_SPNEGO_ERROR;
         break;
     }

     // Application Constructed Object has type and length but no value
     idx += bytes;

     // We expect that the SPNEGO OID is next
     if( IIMS_FAILURE == smbUtilAsnDerCheckOid(&data[idx], OID_SPNEGO, &bytes) )
     {
         //SmbErrLog(LOG_NOTICE,"smbUtilAsnDerCheckOid NO MATCH");
         ++decodeStats.miscError;

         SmbIntLog("  Misc ERROR - smbUtilAsnDerCheckOid NO MATCH" );
         ret = SMB_SPNEGO_ERROR;
         break;
     }

     // SPNEGO OID tlv
     idx += bytes;

     // We expect that NegTokenInit is next.    Advance idx to length.
     if( data[idx++] != SMB_SPNEGO_NEGINIT_TOKEN_IDENTIFIER )
     {
         //SmbErrLog(LOG_NOTICE,"SMB_SPNEGO_NEGINIT_TOKEN_IDENTIFIER NOT FOUND");
         ++decodeStats.miscError;

         SmbIntLog("  Misc ERROR - SMB_SPNEGO_NEGINIT_TOKEN_IDENTIFIER NOT FOUND" );
         ret = SMB_SPNEGO_ERROR;
         break;
     }
     if( smbUtilAsnDerGetLength( &data[idx], &len, &bytes ) == IIMS_FAILURE )
     {
         //SmbErrLog(LOG_NOTICE,"smbUtilAsnDerGetLength FAILED");
         ++decodeStats.miscError;

         SmbIntLog("  Misc ERROR - smbUtilAsnDerGetLength FAILED" );
         ret = SMB_SPNEGO_ERROR;
         break;
     }

     // NegTokenInit has type and length but no value
     idx += bytes;

     // We expect the Constructed Sequence.  Advance idx to length
     if( data[idx++] != SMB_SPNEGO_CONSTRUCTED_SEQ )
     {
         //SmbErrLog(LOG_NOTICE,"SMB_SPNEGO_CONSTRUCTED_SEQ NOT FOUND");
         ++decodeStats.miscError;

         SmbIntLog("  Misc ERROR - SMB_SPNEGO_CONSTRUCTED_SEQ NOT FOUND" );
         ret = SMB_SPNEGO_ERROR;
         break;
     }
     if( smbUtilAsnDerGetLength( &data[idx], &len, &bytes ) == IIMS_FAILURE )
     {
         //SmbErrLog(LOG_NOTICE,"smbUtilAsnDerGetLength FAILED");
         ++decodeStats.miscError;

         SmbIntLog("  Misc ERROR - smbUtilAsnDerGetLength FAILED" );
         ret = SMB_SPNEGO_ERROR;
         break;
     }

     // Constructed Sequence has type and length but no value
     idx += bytes;

     // We expect Sequence element 0 (0xa0), mechType list.  Advance idx 
     // to length
     if( data[idx++] != SMB_SPNEGO_NEGINIT_ELEMENT_MECHTYPES )
     {
         //SmbErrLog(LOG_NOTICE,"SMB_SPNEGO_NEGINIT_ELEMENT_MECHTYPES NOT FOUND");
         ++decodeStats.miscError;

         SmbIntLog("  Misc ERROR - SMB_SPNEGO_NEGINIT_ELEMENT_MECHTYPES NOT FOUND" );
         ret = SMB_SPNEGO_ERROR;
         break;
     }
     if( smbUtilAsnDerGetLength( &data[idx], &len, &bytes ) == IIMS_FAILURE )
     {
         //SmbErrLog(LOG_NOTICE,"smbUtilAsnDerGetLength FAILED");
         ++decodeStats.miscError;

         SmbIntLog("  Misc ERROR - smbUtilAsnDerGetLength FAILED" );
         ret = SMB_SPNEGO_ERROR;
         break;
     }
     // Sequence element bytes
     idx += bytes;

     // Sequence length (0x30).  Advance idx to length
     if( data[idx++] != 0x30 )
     {
         //SmbErrLog(LOG_NOTICE,"Sequence Length INCORRECT");
         ++decodeStats.miscError;

         SmbIntLog("  Misc ERROR - Sequence Length INCORRECT" );
         ret = SMB_SPNEGO_ERROR;
         break;
     }
     if( smbUtilAsnDerGetLength( &data[idx], &len, &bytes ) == IIMS_FAILURE )
     {
         //SmbErrLog(LOG_NOTICE,"smbUtilAsnDerGetLength FAILED");
         ++decodeStats.miscError;

         SmbIntLog("  Misc ERROR - smbUtilAsnDerGetLength FAILED" );
         ret = SMB_SPNEGO_ERROR;
         break;
     }
     // Sequence length bytes
     idx += bytes;

     // And now the big payoff.  We've advanced to the first OID which will
     // tell us the type of security in effect.  We'll start with MS KRB5
     // which, most of the time, in a modern world, is the right answer.
     // The next most likely anser, NTLMSSP, is next in the list.  And so on. 
     OidType ot = OID_MS_KRB5;
     tz_uint32 rv;
     rv = smbUtilAsnDerCheckOid( &data[idx], ot, &bytes );
     while( rv == IIMS_FAILURE && ot != OID_UNKNOWN )
     {
         // Advance to the next OID
         ot = (OidType)((int)ot + 1);
         rv = smbUtilAsnDerCheckOid( &data[idx], ot, &bytes );
     }

     oidType = ot;
     ret = SMB_SPNEGO_NEG_TOKEN_INIT;

  } while (0);

  return ret;
}

//======================================================================
// Utility Functions
//======================================================================

//-----------------------------------------------------------------------
// smbUtilEvtFilterMode()
//-----------------------------------------------------------------------
void SmbDecode::smbUtilEvtFilterMode( bool isOn )
{
  encEngFmt->evtFiltIsEnabled = isOn;
}

//-----------------------------------------------------------------------
// smbUtilEvtFilterModeIsEnab()
//-----------------------------------------------------------------------
bool SmbDecode::smbUtilEvtFilterModeIsEnab( void )
{
  return encEngFmt->evtFiltIsEnabled;
}

//-----------------------------------------------------------------------
// smbUtilGetPidMidConfig()
//-----------------------------------------------------------------------
void SmbDecode::smbUtilGetPidMidConfig( tz_uint64 *var )
{
    var[0] = pidMidPerSsnLimit;
    var[1] = pidMidAgeTimeout;
}

//-----------------------------------------------------------------------
// smbUtilSetPidMidConfig()
//-----------------------------------------------------------------------
void SmbDecode::smbUtilSetPidMidConfig( tz_uint64 *var )
{
    // -1 indicates "no change to current value"

  if( var[0] != (tz_uint64)-1 ) {
        pidMidPerSsnLimit = var[0];
    }

    if( var[1] != (tz_uint64)-1 ) {
        pidMidAgeTimeout = var[1];
    }
}

//-----------------------------------------------------------------------
// smbUtilUnicodeToAscii()
//     Parse Unicode strings in Little Endian format
//
// In:  in,    ptr to string
//      inLen,     0 means "in" is NULL terminated
//             non-0 means conversion length is being specified
//             (we assume inLen is even)
//
// Out: out, the ASCII string
//-----------------------------------------------------------------------
tz_int8 *SmbDecode::smbUtilUnicodeToAscii(tz_int8 *in, tz_uint32 inLen,
                                                       tz_int8 *out)
{
  tz_int8 *inP;

  //tz_int8 chIn, chOut;  // D E B U G

  inP = in;
  while( *inP || *(inP+1))
  {
      //chIn = *(inP);  // D E B U G
      *out = *(inP);
      //chOut = *out; // D E B U G

      ++out;
      inP += 2;

      if( inLen )
      {
          inLen -= 2;
          if( !inLen )  break;
      }
  }
  *out = '\0';
  return (inP+2);
}

//-----------------------------------------------------------------------
// smbUtilFreeVector()
//     this should be available for all protocols
//-----------------------------------------------------------------------
void SmbDecode::smbUtilFreeVector(DimValListEntry *vector)
{
DimValListEntry *tmp;

    while (vector)
    {
        tmp = vector->next;
        free(vector);
        vector = tmp;  
    }
}

//-----------------------------------------------------------------------
// smbUtilAsnDerGetLength()
//
// in:
//     data - ptr to asn.1
// out:
//     len - decoded length value
//     bytes - number of length bytes
// returns:
//     IIMS_SUCCESS
//     IIMS_FAILURE
//-----------------------------------------------------------------------
tz_uint32 SmbDecode::smbUtilAsnDerGetLength( tz_uint8 *data, tz_uint32 *len,
                                             tz_uint32 *bytes )
{
  tz_uint32 status = IIMS_SUCCESS;
  tz_uint8 numLenBytes;

  do
  {
      if( *data & LEN_XTND )
      {
          // Extended bit is set
          numLenBytes = *data & LEN_MASK;

          // Initial zero of length
          *len = 0;

          ++data;

          // Do little-endian conversion while extracting length
          switch( numLenBytes )
          {
          case 1:
              *((tz_int8 *)len +0) = *(data+0);
              break;
          case 2:
              *((tz_int8 *)len +0) = *(data+1);
              *((tz_int8 *)len +1) = *(data+0);
              break;
          case 3:
              *((tz_int8 *)len +0) = *(data+2);
              *((tz_int8 *)len +1) = *(data+1);
              *((tz_int8 *)len +2) = *(data+0);
              break;
          case 4:
              *((tz_int8 *)len +0) = *(data+3);
              *((tz_int8 *)len +1) = *(data+2);
              *((tz_int8 *)len +2) = *(data+1);
              *((tz_int8 *)len +3) = *(data+0);
              break;
          default:
              status = IIMS_FAILURE;
              break;
          }

          // Set the length (including the first byte)
          *bytes = numLenBytes + 1;
      }
      else
      {
          // Extended bit is not set so the length is in the value
          // and the one byte describes the length
          *len = *data & LEN_MASK;
          *bytes = 1;
      }

  } while(0);

  return status;
}

// The expected OID list, ordered by OidType values (see smb.h).
// WARNING: Correspondence between the two must be maintained
mechOID oidList[] = 
{
  { OID_SPNEGO,        8,  6, 
                                   "\x06\x06\x2b\x06\x01\x05\x05\x02" },
  { OID_MS_KRB5,      11,  9, 
                       "\x06\x09\x2a\x86\x48\x86\xf7\x12\x01\x02\x02" },
  { OID_MS_KRB5_LGCY, 11,  9,
                       "\x06\x09\x2a\x86\x48\x82\xf7\x12\x01\x02\x02" },
  { OID_NTLMSSP,      12, 10, 
                    "\x06\x0a\x2b\x06\x01\x04\x01\x82\x37\x02\x02\x0a"},
  { OID_UNKNOWN,       0,  0,
                                                                   "" },
};

//-----------------------------------------------------------------------
// smbUtilAsnDerCheckOid()
//     Check the oid parameter against a list of expected ones
//
// out:
//     bytes - total number of OID bytes
// returns:
//     IIMS_SUCCESS, OID matches
//     IIMS_FAILURE, no match
//-----------------------------------------------------------------------
tz_uint32 SmbDecode::smbUtilAsnDerCheckOid( tz_uint8 *data, OidType oid, 
                                            tz_uint32 *bytes )
{
  tz_uint32 status = IIMS_SUCCESS;
  tz_uint32 oidLen, totLen = 0;
  tz_uint32 lenBytes;

  do
  {
      // Do a length check
      if( smbUtilAsnDerGetLength(data+1, &oidLen, &lenBytes) == IIMS_FAILURE ) {
          break;
      }

      // Add the type byte and the length byte(s) to the oid length
      totLen = 1 + lenBytes + oidLen;

      if( oidLen != oidList[oid].oidLen || totLen != oidList[oid].totalLen  ) {
          // OID length or total length mismatch
          status = IIMS_FAILURE;
          break;
      }

      if( memcmp(data, oidList[oid].stg, oidList[oid].totalLen) != 0 ) {
          // OID byte compare mismatch
          status = IIMS_FAILURE;
          break;
      }

  } while(0);

  if( status == IIMS_SUCCESS ) {
      *bytes = totLen;
  } else {
      *bytes = 0;
  }

  return status;
}

//-----------------------------------------------------------------------
// smbUtilIsEventSource()
//     Determine if the presented filename should generate an event
//     or not.  Events are not generated for standard Windows
//     hard coded named pipes such as "srvsvc", "wkssvc", "samr", etc.
//-----------------------------------------------------------------------
bool SmbDecode::smbUtilIsEventSource( tz_int8 *filename )
{
  bool isEvent = true;

  if(    filename[0] == '\0'
      || strstr(filename, "srvsvc")
      || strstr(filename, "wkssvc")
      || strstr(filename, "lsarpc")
      || strstr(filename, "samr")
      || strstr(filename, "winreg")
      || strstr(filename, "spoolss")
      || strstr(filename, "\\sql\\query") )
  {
      isEvent = false;
  }

  return isEvent;
}

//-----------------------------------------------------------------------
// smbUtilIsHiddenShare()
//     Certain shares (e.g. PRINT$, IPC$) are the target of Windows
//     IPC traffic.  These are said to be "hidden" in the sense that they
//     don't represent ordinary fileshares.  We don't want file accesses
//      on these hidden shares to generate events.
//-----------------------------------------------------------------------
bool SmbDecode::smbUtilIsHiddenShare( tz_int8 *share )
{
  bool isHidden = false;

  if(    strstr(share, "PRINT$") )
  {
      isHidden = true;
  }
  return isHidden;
}

//-----------------------------------------------------------------------
// smbUtilCSPrintResults()
//     Content Scanner, Print Results
//     Ken's code, completely lifted from csCli.c PrintResults()
//-----------------------------------------------------------------------
void SmbDecode::smbUtilCSPrintResults( ContentScanner  *cs, 
                                       DimValListEntry *curEntry )
{
    DimValListEntry * nxtEntry;

    if( curEntry == NULL )  return;

#if 0
    if (optMatches)
    {
        fprintf (stdout, "\n");
    }
#endif

    fprintf (stdout, "Matched Pattern Counters\n");

    while (curEntry)
    {
        fprintf (stdout, "patternName = %s\n", curEntry->stringValue);
        fprintf (stdout, "matchCount  = %lld\n", (unsigned long long int)curEntry->numericalValue);
        nxtEntry = curEntry->next;
        free (curEntry);
        curEntry = nxtEntry;
    }

    if ( 1 /*optPerf*/ )
    {
//      long double duration = tz_watch_read_seconds (watch);
//      long double bitRate  = (long double)bytesScanned * 8.0 / duration / 1000000.0;
        ContentScanner::diag_counters_t  counters;

        cs->GetDiagCounters (&counters);

        fprintf (stdout, "\nPerformance Counters\n");
//      fprintf (stdout, "byte count        = %Ld\n",  bytesScanned);
//      fprintf (stdout, "scan time (secs)  = %LF\n",  duration);
//      fprintf (stdout, "scan rate (Mbps)  = %LF\n",  bitRate);
        fprintf (stdout, "\nDiagnostic Counters\n");
        fprintf (stdout, "scannedCharCount  = %lld\n", (unsigned long long int)counters.scannedCharCount);
        fprintf (stdout, "backupCharCount   = %lld\n", (unsigned long long int)counters.backupCharCount);
        fprintf (stdout, "nullCharCount     = %lld\n", (unsigned long long int)counters.nullCharCount);
        fprintf (stdout, "backupFailedCount = %lld\n", (unsigned long long int)counters.backupFailedCount);
        fprintf (stdout, "fatalErrorCount   = %lld\n", (unsigned long long int)counters.fatalErrorCount);
    }
}

//-----------------------------------------------------------------------
// smbCsSaveUidPidMidTid()
//     Save identifying SMB parameters into lcs for later retrieval
//     of descriptors during tcpCont processing
//-----------------------------------------------------------------------
void SmbDecode::smbCsSaveUidPidMidTid( LargeCmdState *lcs, 
                                       tz_uint16 uid, tz_uint16 pid,
                                       tz_uint16 mid, tz_uint16 tid )
{
  lcs->csUid = uid;
  lcs->csPid = pid;
  lcs->csMid = mid;
  lcs->csTid = tid;
}

//-----------------------------------------------------------------------
// smbCsFindSsnDescrs()
//     Restore descirptors during a tcpCont sequence
//
//     in: sessionEntry, smbHeader
//    out: ssnUid, ssnPidMid, ssnFid, ssnTid
//         (by passing a NULL the client indicates "do not search")
// return: SMB_ERROR code
//-----------------------------------------------------------------------
tz_uint32 SmbDecode::smbCsFindSsnDescrs( SessionEntry   *sessionEntry,
                                         LargeCmdState  *lcs, 
                                         SmbSsnUid     **ssnUid,
                                         SmbSsnPidMid  **ssnPidMid,
                                         SmbSsnFid     **ssnFid,
                                         SmbSsnTid     **ssnTid )
{
  tz_uint32      status;
  SmbHeader      smbHdr;

  // Populate smbHdr with parameters necessary for descriptor lookup
  smbHdr.userId      = lcs->csUid;
  smbHdr.processId   = lcs->csPid;
  smbHdr.multiplexId = lcs->csMid;
  smbHdr.treeId      = lcs->csTid;

  status = SmbSsnFindSsnDescrs( sessionEntry, &smbHdr, ssnUid, ssnPidMid,
                                ssnFid, ssnTid );

  if( status != SMB_ERROR_NONE )
  {
      smbUtilErrorUpdateStats( status );

      SmbIntLog("  Descr ERROR  %s", smbUtilError2String(status) );
  }

  return status;
}

//-----------------------------------------------------------------------
// smbServerCsSendEvent()
//     Unconditionally issue a Content Scanning event only if there are
//     any pending matches on the Server side.
//-----------------------------------------------------------------------
void SmbDecode::smbServerCsSendEvent( SessionEntry  *sessionEntry,
                                      SmbSsnUid     *ssnUid,
                                      SmbSsnFid     *ssnFid )
{
    DimValListEntry *respDataDVLE = NULL;
    tz_uint32        matches;
    SmbSsnTid       *ssnTid;

    do
    {
        if( rspDataPatMgr->CSEnabled() == false )  break;

        if( !ssnUid || !ssnFid ) {
            SmbErrLog(LOG_NOTICE,"smbServerCsSendEvent() - Null UID or FID Descriptor" );
            break;
        }

        ssnTid = SmbSsnDataFindByTid( ssnUid, ssnFid->tid );
        if( ssnTid == NULL )
        {
            SmbErrLog(LOG_NOTICE,"smbServerCsSendEvent() - Null TID Descriptor" );
            break;
        }

        matches = ssnFid->serverCs->GetTotalMatchCount();

        respDataDVLE = ssnFid->serverCs->StopScan( ResponseDataType,
                                             sessionEntry->workerIdx);

        if( matches == 0 || respDataDVLE == NULL )
        {
            break;
        }

        // There are pending match counts
        encEngFmt->evtFiltOverride( EVT_FILT_ACCEPT );

        SmbIntLog("  %lu matches  CS_STOP", matches );

        // Generate an event - create the command string
        sprintf( currCmdStg, "READ  %s", ssnFid->filename);

        // Format Content and Operation
        encEngFmt->resetEvent( sessionEntry );
        encEngFmt->setDimFileContent( sessionEntry,
                                      ssnFid->filename,
                                      NULL,
                                      ssnTid->sharename,
                                      0 );
        encEngFmt->setDimOperation( sessionEntry,
                                    EVT_READ, "READ", 
                                    strlen("READ") +1 );

        // Format Size and Response and generate the event
        encEngFmt->setDimSize( sessionEntry, 0 );
        encEngFmt->setDimResponse( sessionEntry, SUCCESSFUL_OPERATION );
        encEngFmt->setDimResponseData( sessionEntry, respDataDVLE );
        encEngFmt->sendCOSREvent( encodingEngine,
                                  sessionEntry,
                                  ssnUid,
                                  ssnTid,
                                  currCmdStg );

    } while (0);
}

//-----------------------------------------------------------------------
// smbClientCsSendEvent()
//     Unconditionally issue a Content Scanning event only if there are
//     any pending matches on the Client side
//-----------------------------------------------------------------------
void SmbDecode::smbClientCsSendEvent( SessionEntry  *sessionEntry,
                                      SmbSsnUid     *ssnUid,
                                      SmbSsnFid     *ssnFid )
{
    DimValListEntry *cmdDataDVLE = NULL;
    tz_uint32        matches;
    SmbSsnTid       *ssnTid;

    do
    {
        if( cmdDataPatMgr->CSEnabled() == false )  break;

        if( !ssnUid || !ssnFid ) {
            SmbErrLog(LOG_NOTICE,"smbClientCsSendEvent() - Null UID or FID Descriptor" );
            break;
        }

        ssnTid = SmbSsnDataFindByTid( ssnUid, ssnFid->tid );
        if( ssnTid == NULL )
        {
            SmbErrLog(LOG_NOTICE,"smbClientCsSendEvent() - Null TID Descriptor" );
            break;
        }

        matches = ssnFid->clientCs->GetTotalMatchCount();

        cmdDataDVLE = ssnFid->clientCs->StopScan( CommandDataType,
                                                  sessionEntry->workerIdx);

        if( matches == 0 || cmdDataDVLE == NULL )
        {
            break;
        }

        // There are pending match counts
        encEngFmt->evtFiltOverride( EVT_FILT_ACCEPT );

        SmbIntLog("  %lu matches  CS_STOP", matches );

        // Generate an event - create the command string
        sprintf( currCmdStg, "WRITE  %s", ssnFid->filename);

        // Format Content and Operation
        encEngFmt->resetEvent( sessionEntry );
        encEngFmt->setDimFileContent( sessionEntry,
                                      ssnFid->filename,
                                      NULL,
                                      ssnTid->sharename,
                                      0 );
        encEngFmt->setDimOperation( sessionEntry,
                                    EVT_WRITE, "WRITE", 
                                    strlen("WRITE") +1 );

        // Format Size and Response and generate the event
        encEngFmt->setDimSize( sessionEntry, 0 );
        encEngFmt->setDimResponse( sessionEntry, SUCCESSFUL_OPERATION );
        encEngFmt->setDimResponseData( sessionEntry, cmdDataDVLE );
        encEngFmt->sendCOSREvent( encodingEngine,
                                  sessionEntry,
                                  ssnUid,
                                  ssnTid,
                                  currCmdStg );

    } while (0);
}

//-----------------------------------------------------------------------
// smbUtilDecodeLog
//-----------------------------------------------------------------------
void SmbDecode::smbUtilDecodeLog( SessionEntry *sessionEntry,
                                  const char * format, ...)
{
    va_list    ap;
    SmbInfo   *smbInfo = (SmbInfo *)sessionEntry->appInfo;

    va_start (ap, format);

    fprintf(dlFile, "%4d  %3d  ", (int)smbInfo->sessionIdNum,
                                  (int)processedPktNum );
    vfprintf( dlFile, format, ap );
    fputc('\n', dlFile);

    fflush( dlFile );

    va_end (ap);
}

//-----------------------------------------------------------------------
// ClearDecodeStats()
//-----------------------------------------------------------------------
void SmbDecode::ClearDecodeStats( void )
{
  memset( &decodeStats, 0, sizeof(struct DecodeStats) );
}

//-----------------------------------------------------------------------
// SumDecodeStats()
//     Add this SMB Decoder's counts to the running total of all
//     SMB decoders (worker threads) in the system.  Also, look for this
//     SMB decoder's maximums and factor them into those of all SMB
//     decoders.
//-----------------------------------------------------------------------
void SmbDecode::SumDecodeStats( void *context)
{
    DecodeStats *stats = (DecodeStats *)context;

    stats->tcpHole              += decodeStats.tcpHole;
    stats->unimplCmdCount       += decodeStats.unimplCmdCount;
    stats->notSyncCount         += decodeStats.notSyncCount;
    stats->reSyncSuccess        += decodeStats.reSyncSuccess;
    stats->possibNbssCount      += decodeStats.possibNbssCount;
    stats->noSession            += decodeStats.noSession;
    stats->noSmbInfoDescr       += decodeStats.noSmbInfoDescr;
    stats->noUidDescr           += decodeStats.noUidDescr;
    stats->uidCreateError       += decodeStats.uidCreateError;
    stats->noPidMidDescr        += decodeStats.noPidMidDescr;
    stats->pidMidCreateError    += decodeStats.pidMidCreateError;
    stats->pidMidAgedDescr      += decodeStats.pidMidAgedDescr;
    stats->noFidDescr           += decodeStats.noFidDescr;
    stats->fidCreateError       += decodeStats.fidCreateError;
    stats->noTidDescr           += decodeStats.noTidDescr;
    stats->tidCreateError       += decodeStats.tidCreateError;
    stats->failedRemove         += decodeStats.failedRemove;
    stats->miscError            += decodeStats.miscError;

    // Roll in maximum allocations from departed sessions
    if( stats->oldSsnMaxUidCount < decodeStats.oldSsnMaxUidCount)
    {
        stats->oldSsnMaxUidCount = decodeStats.oldSsnMaxUidCount;
    }
    if( stats->oldSsnMaxPidMidCount < decodeStats.oldSsnMaxPidMidCount)
    {
        stats->oldSsnMaxPidMidCount = decodeStats.oldSsnMaxPidMidCount;
    }
    if( stats->oldSsnMaxTidCount < decodeStats.oldSsnMaxTidCount)
    {
        stats->oldSsnMaxTidCount = decodeStats.oldSsnMaxTidCount;
    }
    if( stats->oldSsnMaxFidCount < decodeStats.oldSsnMaxFidCount)
    {
        stats->oldSsnMaxFidCount = decodeStats.oldSsnMaxFidCount;
    }
    if( stats->oldSsnMaxPidMidLife < decodeStats.oldSsnMaxPidMidLife)
    {
        stats->oldSsnMaxPidMidLife = decodeStats.oldSsnMaxPidMidLife;
    }
}

//-----------------------------------------------------------------------
// CsEnab()
//-----------------------------------------------------------------------
void SmbDecode::CsEnab( void *context)
{
    bool *csEnab = (bool *)context;
    *csEnab = rspDataPatMgr->CSEnabled();
}

//-----------------------------------------------------------------------
// SmbDecode()
//-----------------------------------------------------------------------
SmbDecode::SmbDecode(NetMonDriver *nmd, EncodingEngine *ee, TDSDecode *tds)
{
  netMonDriver    = nmd;
  encodingEngine  = ee;
  tdsDecode       = tds;

  smbDebugLevel = LOG_NOTICE;
  smbDebugMode = 2;

  //SmbErrLog(LOG_NOTICE, "SMB Protocol Decode created\n");
  //SmbDbgLog(LOG_NOTICE, "SMB test %lx\n", smbDebugLevel );

  smbLoginIsRequired = false;

  // Init the debug logger and enable it
  SmbDebug::logInit();

  // Set debug defaults but override them if smb.ini exists
  //SmbDebug::utilReadIni();        M O V E D   T O   LayerManager::Run()

  // Init the packet counters
  smbClientPkts = smbServerPkts = 0;

  // Statistics counters
  ClearDecodeStats();

  // Processed packet ID number (for debugging)
  processedPktNum = 0;

  // Session ID number (for debugging)
  sessionIdNum = 0;

  // Create the Encoding Engine Formatter
  encEngFmt = new smbEncEngFormatter( this );

  // Obtain the Pattern Manager
  rspDataPatMgr = nmd->rspDataPatMgr[PROTOCOL_SMB];
  cmdDataPatMgr = nmd->cmdDataPatMgr[PROTOCOL_SMB];

  // layer manager config
  memset( &myLmCfg, 0, sizeof(LmCfgSmb) );

  // PID/MID descriptor management (possibly overridden by smb.ini)
  // - 10 per session max
  // - descriptors live 6.0 sec
  pidMidPerSsnLimit = 10;
  pidMidAgeTimeout = 6 * netMonDriver->cyclesPerSecond;

#ifdef SMB_DECODE_LOG
  // Decode log is meant for only one worker thread
  dlFile = fopen( "./decode_log.txt", "w" );
#endif
}

//-----------------------------------------------------------------------
// ~SmbDecode()
//-----------------------------------------------------------------------
SmbDecode::~SmbDecode()
{
}


//======================================================================
// Session Entry  - protocol specific session data management
//======================================================================


//-----------------------------------------------------------------------
// SmbSsnFindSsnDescrs()
//     For a server side response, extract the reverse sessionEntry
//     then find the Uid, PidMid, Fid, and Tid descriptors as directed
//     by the caller.
//
//     The caller expects the UID to be what's in the SMBHeader.
//     Nearly all command handlers want this functionality.
//
//     in: sessionEntry, smbHeader
//    out: ssnUid, ssnPidMid, ssnFid, ssnTid
//         (by passing a NULL the client indicates "do not search")
// return: SMB_ERROR code
//-----------------------------------------------------------------------
tz_uint32 SmbDecode::SmbSsnFindSsnDescrs( SessionEntry   *sessionEntry,
                                          SmbHeader      *smbHeader,
                                          SmbSsnUid     **ssnUid,
                                          SmbSsnPidMid  **ssnPidMid,
                                          SmbSsnFid     **ssnFid,
                                          SmbSsnTid     **ssnTid )
{
  return SmbSsnFindSsnDescrsUid( sessionEntry,
                                 stohs(smbHeader->userId),
                                 smbHeader,
                                 ssnUid,
                                 ssnPidMid,
                                 ssnFid,
                                 ssnTid );
}


//-----------------------------------------------------------------------
// SmbSsnFindSsnDescrsUid()
//     For a server side response, extract the reverse sessionEntry
//     then find the Uid, PidMid, Fid, and Tid descriptors as directed
//     by the caller.  The UID key is a passed parameter.
//
//     in: sessionEntry, smbHeader, uid
//    out: ssnUid, ssnPidMid, ssnFid, ssnTid
//         (by passing a NULL the client indicates "do not search")
// return: SMB_ERROR code
//-----------------------------------------------------------------------
tz_uint32 SmbDecode::SmbSsnFindSsnDescrsUid( SessionEntry   *sessionEntry,
                                             tz_uint16       uid,
                                             SmbHeader      *smbHeader,
                                             SmbSsnUid     **ssnUid,
                                             SmbSsnPidMid  **ssnPidMid,
                                             SmbSsnFid     **ssnFid,
                                             SmbSsnTid     **ssnTid )
{
  tz_uint32 status = SMB_ERROR_NONE;

  do
  {
      if( sessionEntry == NULL )
      {
          status = SMB_ERROR_NO_SESSION;
          break;
      }

      SmbInfo *smbInfo = (SmbInfo *)sessionEntry->appInfo;
      if( smbInfo == NULL )
      {
          status = SMB_ERROR_NO_SMB_INFO_DESCR;
          break;
      }

      if( ssnUid )
      {
          *ssnUid = SmbSsnDataFindByUid( sessionEntry, 
                                         uid );
          if( *ssnUid == NULL )
          {
              status = SMB_ERROR_NO_UID_DESCR;
              break;
          }
      }

      if( ssnPidMid )
      {
          *ssnPidMid = SmbSsnDataFindByPidMid( sessionEntry, *ssnUid, 
                                          stohs(smbHeader->processId),
                                          stohs(smbHeader->multiplexId));
          if( *ssnPidMid == NULL )
          {
              status = SMB_ERROR_NO_PID_MID_DESCR;
              break;
          }
      }

      if( ssnFid && ssnPidMid )
      {
          tz_uint16 fid = (*ssnPidMid)->fid;
          *ssnFid = SmbSsnDataFindByFid( *ssnUid, fid );
          if( *ssnFid == NULL )
          {
              if( (*ssnUid)->authIsCompleted ) {
                  // We have received session setup so this is unexpected
                  status = SMB_ERROR_NO_FID_DESCR;
                  break;
              } else {
#if 0
                  // Session jump-in, use the unknown Fid
                  *ssnFid = &smbInfo->ssnFidUnknown;
#else
                  // Session jump-in, create a Fid
                  if( SmbSsnDataAddFid(sessionEntry, *ssnUid, fid) == IIMS_FAILURE )
                  {
                      status = SMB_ERROR_FID_CREATE;
                      SmbIntLog("  SJI_FID_FAIL");
                      break;
                  } else {
                      *ssnFid = SmbSsnDataFindByFid( *ssnUid, fid );
                      // We don't have a filename so suppress any events
                      (*ssnFid)->isEventSource = false;
                      SmbIntLog("  SJI_FID");
                  }
#endif
              }
          }
      }

      if( ssnTid )
      {
          tz_uint16 tid = stohs(smbHeader->treeId);
          *ssnTid = SmbSsnDataFindByTid( *ssnUid, tid );
          if( *ssnTid == NULL )
          {
              if( (*ssnUid)->authIsCompleted ) {
                  // We have received session setup so this is unexpected
                  status = SMB_ERROR_NO_TID_DESCR;
                  break;
              } else {
#if 0
                  // Session jump-in, use the unknown Tid
                  *ssnTid = &smbInfo->ssnTidUnknown;
#else
                  // Session jump-in, create a Tid
                  if( SmbSsnDataAddTid(sessionEntry, *ssnUid, tid) == IIMS_FAILURE )
                  {
                      status = SMB_ERROR_TID_CREATE;
                      SmbIntLog("  SJI_TID_FAIL");
                      break;
                  } else {
                      *ssnTid = SmbSsnDataFindByTid( *ssnUid, tid );
                      SmbIntLog("  SJI_TID");
                  }

#endif
              }
          }
      }

  } while (0);

  return status;
}

//-----------------------------------------------------------------------
// SmbSsnCreatePidMid()
//     For a client side request, find the SmbInfo, create a PidMid
//     and add it to that SmbInfo's Uid (or recycle an old PidMid if
//     appropriate).
//
// out:
//     *ssnPidMid - the new or recycled PidMid
//
// return: 
//     SMB_ERROR_NONE - success
//     SMB_ERROR_XXX  - failure indication
//-----------------------------------------------------------------------
tz_uint32 SmbDecode::SmbSsnCreateSsnPidMid( SessionEntry   *sessionEntry,
                                            SmbHeader      *smbHeader,
                                            SmbSsnPidMid  **ssnPidMid )
{
  tz_uint32     status = SMB_ERROR_NONE;
  SmbInfo      *smbInfo = (SmbInfo *)sessionEntry->appInfo;
  SmbSsnUid    *ssnUid;
  SmbSsnPidMid *agedPidMid, *newPidMid;

  do
  {
      ssnUid = SmbSsnDataFindByUid( sessionEntry, stohs(smbHeader->userId) );
      if( ssnUid == NULL )
      {
          status = SMB_ERROR_NO_UID_DESCR;
          break;
      }

      // Check if there are any stale descriptors to recycle
      agedPidMid = SmbSsnDataFindAgedPidMid( sessionEntry, ssnUid );

      if( agedPidMid )
      {
          // We will reuse the stranded PidMid.  Start by clearing it
          // except for its place in the list and its tz_watch
          tz_watch_t   *age  = agedPidMid->age;
          SmbSsnPidMid *next = agedPidMid->next;
          memset( agedPidMid, 0, sizeof(SmbSsnPidMid) );
          agedPidMid->age = age;
          agedPidMid->next = next;

          // Update its identity
          agedPidMid->pid = stohs(smbHeader->processId);
          agedPidMid->mid = stohs(smbHeader->multiplexId);

          // Refresh its age, count it as recycled and give it to client
          tz_watch_reset( agedPidMid->age );
          ++decodeStats.pidMidAgedDescr;
          *ssnPidMid = agedPidMid;
      }
      else if(   smbInfo->thisSsnStats.currPidMidCount 
              >= MAX(pidMidPerSsnLimit, smbInfo->srvMaxMpxCount) )
      {
          // We're at the limit for this session.
          status = SMB_ERROR_PID_MID_CREATE;
      }
      else
      {
          // Create a brand new PidMid
          if( SmbSsnDataAddPidMid(ssnUid, 
                                  stohs(smbHeader->processId),
                                  stohs(smbHeader->multiplexId),
                                  &newPidMid)             == IIMS_FAILURE )
          {
              status = SMB_ERROR_PID_MID_CREATE;
              break;
          }

          // Give to client and count it
          *ssnPidMid = newPidMid;
          currPidMidCountInc( sessionEntry );
      }

  } while (0);

  return status;
}

//-----------------------------------------------------------------------
// SmbSsnDataInit()
//     Create a new SMB protocol specific data structure
//-----------------------------------------------------------------------
SmbInfo *SmbDecode::SmbSsnDataInit( SessionEntry *sessionEntry )
{
  SmbInfo *ssnData;
  ssnData = (SmbInfo *)calloc( 1, sizeof(SmbInfo) );

  do
  {
      if( ssnData == NULL )
      {
          SmbErrLog(LOG_NOTICE,"SmbInfo allocation FAILED");
          break;
      }

      // Filter (driver) records that the create has occurred
      // by setting sessionEntry->appInfo = ssnData;

      // No UIDs yet
      ssnData->uidList = NULL;
      ssnData->uidListCnt = 0;

      ssnData->ntlmSspState = SMB_NTLMSSP_UNKNOWN;
      ssnData->krb5State = SMB_KRB5_UNKNOWN;

#if 0
      // Establish the special unknown Fid and Tid descriptors
      memset( &ssnData->ssnFidUnknown, 0, sizeof(SmbSsnFid) );
      ssnData->ssnFidUnknown.isEventSource = true;

      memset( &ssnData->ssnTidUnknown, 0, sizeof(SmbSsnTid) );
      ssnData->ssnTidUnknown.ctxtIsEmpty = true;
#endif

      // Establish a default serverUser
      ssnData->serverUser[0] = '\0';

      // Large SMB command multipacket byte counters
      ssnData->reqLcs.isActive     = false;
      ssnData->reqLcs.totExpected  = 0;
      ssnData->reqLcs.totReceived  = 0;
      ssnData->reqLcs.tcpSegOffset = 0;
      ssnData->reqLcs.remainInPkt  = 0;

      ssnData->rspLcs.isActive     = false;
      ssnData->rspLcs.totExpected  = 0;
      ssnData->rspLcs.totReceived  = 0;
      ssnData->rspLcs.tcpSegOffset = 0;
      ssnData->rspLcs.remainInPkt  = 0;

      // Clear thisSsnStats
      // (we're relying on calloc to zero)

  } while(0);

  return ssnData;
}

//-----------------------------------------------------------------------
// SmbSsnDataDeInit()
//-----------------------------------------------------------------------
void SmbDecode::SmbSsnDataDeInit(SessionEntry *sessionEntry)
{
  SmbInfo   *ssnData = (SmbInfo *)sessionEntry->appInfo;
  SmbSsnUid *nextSsnUid, *thisSsnUid;

  // Before the session is removed, update maximum allocation stats
  // for all sessions departed
  if( decodeStats.oldSsnMaxUidCount < ssnData->thisSsnStats.maxUidCount)
  {
      decodeStats.oldSsnMaxUidCount = ssnData->thisSsnStats.maxUidCount;
  }
  if( decodeStats.oldSsnMaxPidMidCount < ssnData->thisSsnStats.maxPidMidCount)
  {
      decodeStats.oldSsnMaxPidMidCount = ssnData->thisSsnStats.maxPidMidCount;
  }
  if( decodeStats.oldSsnMaxTidCount < ssnData->thisSsnStats.maxTidCount)
  {
      decodeStats.oldSsnMaxTidCount = ssnData->thisSsnStats.maxTidCount;
  }
  if( decodeStats.oldSsnMaxFidCount < ssnData->thisSsnStats.maxFidCount)
  {
      decodeStats.oldSsnMaxFidCount = ssnData->thisSsnStats.maxFidCount;
  }
  if( decodeStats.oldSsnMaxPidMidLife < ssnData->thisSsnStats.maxPidMidLife)
  {
      decodeStats.oldSsnMaxPidMidLife = ssnData->thisSsnStats.maxPidMidLife;
  }

  // If there's a list, deallocate them all

  thisSsnUid = ssnData->uidList;
  while( thisSsnUid )
  {
      // Grab the next right now because RemoveUid() will free this
      nextSsnUid = thisSsnUid->next;

      // Remove this Uid freeing any contained lists and itself
      SmbSsnDataRemoveUid( sessionEntry, thisSsnUid->uid );

      thisSsnUid = nextSsnUid;
  }

  // Ensure that there's no longer a list
  ssnData->uidList = NULL;

  // Remove the Fragmentation buffers
  if( ssnData->reqLcs.fs.data )
  {
      free( ssnData->reqLcs.fs.data );
  }
  if( ssnData->rspLcs.fs.data )
  {
      free( ssnData->rspLcs.fs.data );
  }
}

//-----------------------------------------------------------------------
// SmbSsnDataAddUid()
//     The UID is the result of a successfully completed authentication.
//     It's valid until logoff.  It is not necessarily the same as the
//     user's real UNIX UID.  There can be multiple pending server
//     replies for a given UID.  They are differentiated on the basis
//     of PID:MID.  It is required that there is only one outstanding
//     request per PID:MID per connection.
//
// sideeffect:
//     Check to see if serverInfo has been initialized and init if
//     necessary.  If we don't then no events will be received for this
//     session.  This is here for two reasons:
//     - When authentication failed for some reason to acquire serverInfo
//     - In session jump-in mode where login and authentication have
//       already happened.
//
// returns:
//     IIMS_SUCCESS
//     IIMS_FAILURE - unable to add
//-----------------------------------------------------------------------
tz_uint32 SmbDecode::SmbSsnDataAddUid(SessionEntry *sessionEntry, tz_uint16 uid)
{
  tz_uint32 status = IIMS_SUCCESS;
  SmbInfo *ssnData = (SmbInfo *)sessionEntry->appInfo;

  SmbSsnUid *ssnUid;

  do
  {
      if( !ssnData )
      {
          //printf( "FAILURE %s:%d", __FILE__, __LINE__ );
          status = IIMS_FAILURE;
          break;
      }

      ssnUid = (SmbSsnUid *)calloc( 1, sizeof(SmbSsnUid));
      if( !ssnUid )
      {
          //printf( "FAILURE %s:%d", __FILE__, __LINE__ );
          status = IIMS_FAILURE;
          break;
      }

      // Format the content of the new entry
      ssnUid->uid  = uid;
      ssnUid->fidList = NULL;
      ssnUid->pidMidList = NULL;
      ssnUid->tidList = NULL;
      ssnUid->fileInfoTree = NULL;
      ssnUid->authIsCompleted = false;

      // Check to see if serverUser has been initialized and, if not,
      // do so now.
      if( ssnData->serverUser[0] == '\0' )
      {
          struct in_addr srcAddr;
          srcAddr.s_addr = sessionEntry->clientIsDst ?
                           sessionEntry->addressTuple.dst :
                           sessionEntry->addressTuple.src;

          strcpy( ssnData->serverUser, "USER_" );
          strcat( ssnData->serverUser, inet_ntoa(srcAddr) );
      }

      if( ssnData->uidList == NULL )
      {
          // No entries yet - format the new Uid entry
          ssnUid->next = NULL;

          // Add to head of list
          ssnData->uidList = ssnUid;
      }
      else
      {
          // Add to head of existing list
          ssnUid->next = ssnData->uidList;
          ssnData->uidList = ssnUid;
      }

      ++ssnData->uidListCnt;
      currUidCountInc( sessionEntry );

  } while(0);

  return status;
}

//-----------------------------------------------------------------------
// SmbSsnDataRemoveUid()
//
// returns:
//     IIMS_SUCCESS
//     IIMS_FAILURE - UID not found
//-----------------------------------------------------------------------
tz_uint32 SmbDecode::SmbSsnDataRemoveUid(SessionEntry *sessionEntry, 
                                         tz_uint16    uid)
{
  tz_uint32 status;
  SmbInfo *ssnData = (SmbInfo *)sessionEntry->appInfo;
  SmbSsnUid *thisSsnUid, *prevSsnUid, *nextSsnUid;
  SmbSsnFid *nextSsnFid, *thisSsnFid;
  SmbSsnPidMid *nextSsnPidMid, *thisSsnPidMid;
  SmbSsnTid *nextSsnTid, *thisSsnTid;

  do
  {
      if( ssnData->uidList == NULL )
      {
          // Removing from an empty list
          status = IIMS_FAILURE;
          break;
      }
      else
      {
          // Do a linear search and remove
          status = IIMS_FAILURE;

          prevSsnUid = NULL;
          thisSsnUid = ssnData->uidList;
          while( thisSsnUid )
          {
              if( thisSsnUid->uid == uid )
              {
                  // remove the entry
                  if( prevSsnUid == NULL )
                  {
                      // It's the first in the chain
                      nextSsnUid = thisSsnUid->next;
                      ssnData->uidList = nextSsnUid;

                  } else {
                      nextSsnUid = thisSsnUid->next;
                      prevSsnUid->next = nextSsnUid;
                  }

                  // Remove any lists it contains
                  // Fid
                  thisSsnFid = thisSsnUid->fidList;
                  while( thisSsnFid )
                  {
                      nextSsnFid = thisSsnFid->next;
                      if( thisSsnFid->serverCs )
                      {
                          // Issue CS event if there is one.  We can do
                          // this here because the tid list is not yet
                          // deleted (until later, below)
                          smbServerCsSendEvent( sessionEntry,
                                                thisSsnUid, thisSsnFid );
                          delete thisSsnFid->serverCs;
                      }
                      if( thisSsnFid->clientCs )
                      {
                          smbClientCsSendEvent( sessionEntry,
                                                thisSsnUid, thisSsnFid );
                          delete thisSsnFid->clientCs;
                      }
                      free( thisSsnFid );
                      currFidCountDec( sessionEntry );
                      thisSsnFid = nextSsnFid;
                  }
                  thisSsnUid->fidList = NULL;
                  // PidMid
                  thisSsnPidMid = thisSsnUid->pidMidList;
                  while( thisSsnPidMid )
                  {
                      // Note that we are deliberately NOT capturing PidMid
                      // age becuase PidMids still alive here are forgotten
                      // and stranded and would skew the results.

                      nextSsnPidMid = thisSsnPidMid->next;
                      free( thisSsnPidMid->age );
                      free( thisSsnPidMid );
                      currPidMidCountDec( sessionEntry );
                      thisSsnPidMid = nextSsnPidMid;
                  }
                  thisSsnUid->pidMidList = NULL;
                  // Tid
                  thisSsnTid = thisSsnUid->tidList;
                  while( thisSsnTid )
                  {
                      // Application Logout
                      SendAppLogoutEvent( sessionEntry, thisSsnTid );

                      // If this TID has a sessionDetail pointer then free it
                      // unconditionally.  If sessionEntry also has that same
                      // pointer, then NULL it out
                      if( thisSsnTid->seCtxt.sessionDetail )
                      {
                          if(   sessionEntry->sessionDetail 
                             == thisSsnTid->seCtxt.sessionDetail )
                          {
                              sessionEntry->sessionDetail = NULL;
                          }
                          free(thisSsnTid->seCtxt.sessionDetail);
                      }

                      nextSsnTid = thisSsnTid->next;
                      free( thisSsnTid );
                      currTidCountDec( sessionEntry );
                      thisSsnTid = nextSsnTid;
                  }
                  thisSsnUid->tidList = NULL;

                  // Free the FileInfo tree if one has been created
                  if( thisSsnUid->fileInfoTree )
                  {
                      evtFiltRemoveTree( thisSsnUid->fileInfoTree );
                  }

                  // Now free the Uid itself
                  free( thisSsnUid );
                  --ssnData->uidListCnt;
                  currUidCountDec( sessionEntry );
                  status = IIMS_SUCCESS;
                  break;
              }
              prevSsnUid = thisSsnUid;
              thisSsnUid = thisSsnUid->next;
          }
          break;
      }
  } while(0);

  return status;
}

//-----------------------------------------------------------------------
// SmbSsnDataFindByUid()
//-----------------------------------------------------------------------
SmbSsnUid *SmbDecode::SmbSsnDataFindByUid(SessionEntry *sessionEntry, 
                                          tz_uint16     uid)
{
  SmbInfo *ssnData = (SmbInfo *)sessionEntry->appInfo;
  SmbSsnUid *thisSsnUid;
  SmbSsnUid *matchSsnUid = NULL;

  do
  {
      if( ssnData->uidList == NULL )
      {
          // Finding Uid on an empty list
          break;
      }
      else
      {
          // Do a linear search

          thisSsnUid = ssnData->uidList;
          while( thisSsnUid )
          {
              if( thisSsnUid->uid == uid )
              {
                  matchSsnUid = thisSsnUid;
                  break;
              }
              thisSsnUid = thisSsnUid->next;
          }
          break;
      }
  } while(0);

  return matchSsnUid;
}

//-----------------------------------------------------------------------
// SmbSsnDataAddFid()
//
// returns:
//     IIMS_SUCCESS
//     IIMS_FAILURE - unable to add
//-----------------------------------------------------------------------
tz_uint32 SmbDecode::SmbSsnDataAddFid( SessionEntry   *sessionEntry,
                                       SmbSsnUid      *ssnUid,
                                       tz_uint16       fid )
{
  tz_uint32 status = IIMS_SUCCESS;

  SmbSsnFid *ssnFid;

  do
  {
      if( !ssnUid )
      {
          //printf( "FAILURE %s:%d", __FILE__, __LINE__ );
          status = IIMS_FAILURE;
          break;
      }

      ssnFid = (SmbSsnFid *)calloc( 1, sizeof(SmbSsnFid));
      if( !ssnFid )
      {
          //printf( "FAILURE %s:%d", __FILE__, __LINE__ );
          status = IIMS_FAILURE;
          break;
      }

      // Format the content of the new entry
      ssnFid->fid  = fid;
      ssnFid->isEventSource = true;

      if( ssnUid->fidList == NULL )
      {
          // No entries yet - format the new Fid entry
          ssnFid->next = NULL;

          // Add to head of list
          ssnUid->fidList = ssnFid;
      }
      else
      {
          // Add to head of existing list
          ssnFid->next = ssnUid->fidList;
          ssnUid->fidList = ssnFid;
      }
      currFidCountInc( sessionEntry );

  } while(0);

  return status;
}

//-----------------------------------------------------------------------
// SmbSsnDataRemoveFid()
//
// returns:
//     IIMS_SUCCESS
//     IIMS_FAILURE - unable to add
//-----------------------------------------------------------------------
tz_uint32 SmbDecode::SmbSsnDataRemoveFid( SessionEntry   *sessionEntry,
                                          SmbSsnUid      *ssnUid, 
                                          tz_uint16       fid )
{
  tz_uint32 status;
  SmbSsnFid *thisSsnFid, *prevSsnFid, *nextSsnFid;

  do
  {
      if( ssnUid->fidList == NULL )
      {
          // Removing from an empty list
          status = IIMS_FAILURE;
          break;
      }
      else
      {
          // Do a linear search and remove
          status = IIMS_FAILURE;

          prevSsnFid = NULL;
          thisSsnFid = ssnUid->fidList;
          while( thisSsnFid )
          {
              if( thisSsnFid->fid == fid )
              {
                  if( thisSsnFid->serverCs )
                  {
                      delete thisSsnFid->serverCs;
                  }

                  if( thisSsnFid->clientCs )
                  {
                      delete thisSsnFid->clientCs;
                  }

                  // remove the entry
                  if( prevSsnFid == NULL )
                  {
                      // It's the first in the chain
                      nextSsnFid = thisSsnFid->next;
                      free( thisSsnFid );
                      ssnUid->fidList = nextSsnFid;

                  } else {
                      nextSsnFid = thisSsnFid->next;
                      free( thisSsnFid );
                      prevSsnFid->next = nextSsnFid;
                  }
                  currFidCountDec( sessionEntry );
                  status = IIMS_SUCCESS;
                  break;
              }
              prevSsnFid = thisSsnFid;
              thisSsnFid = thisSsnFid->next;
          }
          break;
      }
  } while(0);

  return status;
}

//-----------------------------------------------------------------------
// SmbSsnDataFindByFid()
//-----------------------------------------------------------------------
SmbSsnFid *SmbDecode::SmbSsnDataFindByFid( SmbSsnUid *ssnUid, 
                                           tz_uint16 fid )
{
  SmbSsnFid *thisSsnFid;
  SmbSsnFid *matchSsnFid = NULL;

  do
  {
      if( ssnUid->fidList == NULL )
      {
          // Finding Fid on an empty list
          break;
      }
      else
      {
          // Do a linear search

          thisSsnFid = ssnUid->fidList;
          while( thisSsnFid )
          {
              if( thisSsnFid->fid == fid )
              {
                  matchSsnFid = thisSsnFid;
                  break;
              }
              thisSsnFid = thisSsnFid->next;
          }
          break;
      }
  } while(0);

  return matchSsnFid;
}


//-----------------------------------------------------------------------
// SmbSsnDataAddPidMid()
//
// out:
//     *ssnPidMid - valid_ptr or NULL
//
// returns:
//     IIMS_SUCCESS
//     IIMS_FAILURE - unable to add
//-----------------------------------------------------------------------
tz_uint32 SmbDecode::SmbSsnDataAddPidMid( SmbSsnUid      *ssnUid, 
                                          tz_uint16       pid,
                                          tz_uint16       mid,
                                          SmbSsnPidMid  **ssnPidMid )
{
  tz_uint32 status = IIMS_SUCCESS;

  do
  {
      if( !ssnUid )
      {
          //printf( "FAILURE %s:%d", __FILE__, __LINE__ );
          status = IIMS_FAILURE;
          break;
      }

      *ssnPidMid = (SmbSsnPidMid *)calloc( 1, sizeof(SmbSsnPidMid));
      if( *ssnPidMid == NULL )
      {
          status = IIMS_FAILURE;
          break;
      }

      // Format the content of the new entry
      (*ssnPidMid)->pid  = pid;
      (*ssnPidMid)->mid  = mid;

      if( ssnUid->pidMidList == NULL )
      {
          // No entries yet - format the new PidMid entry
          (*ssnPidMid)->next = NULL;

          // Add to head of list
          ssnUid->pidMidList = *ssnPidMid;
      }
      else
      {
          // Add to head of existing list
          (*ssnPidMid)->next = ssnUid->pidMidList;
          ssnUid->pidMidList = *ssnPidMid;
      }

      // Start the age timer
      (*ssnPidMid)->age = tz_watch_new();
      tz_watch_start( (*ssnPidMid)->age );

  } while(0);

  return status;
}

//-----------------------------------------------------------------------
// SmbSsnDataRemovePidMid()
//
// returns:
//     IIMS_SUCCESS
//     IIMS_FAILURE - unable to remove
//-----------------------------------------------------------------------
tz_uint32 SmbDecode::SmbSsnDataRemovePidMid( SessionEntry *sessionEntry,
                                             SmbSsnUid    *ssnUid, 
                                             tz_uint16     pid,
                                             tz_uint16     mid )
{
  tz_uint32 status;
  SmbSsnPidMid *thisSsnPidMid, *prevSsnPidMid, *nextSsnPidMid;
  SmbInfo      *smbInfo = (SmbInfo *)sessionEntry->appInfo;
  tz_uint64     thisAge;

  do
  {
      if( ssnUid->pidMidList == NULL )
      {
          // Removing from an empty list
          status = IIMS_FAILURE;
          break;
      }
      else
      {
          // Do a linear search and remove
          status = IIMS_FAILURE;

          prevSsnPidMid = NULL;
          thisSsnPidMid = ssnUid->pidMidList;
          while( thisSsnPidMid )
          {
              if(   thisSsnPidMid->pid == pid
                 && thisSsnPidMid->mid == mid )
              {
                  // Evaluate age
                  tz_watch_stop( thisSsnPidMid->age );
                  thisAge = tz_watch_read_cycles( thisSsnPidMid->age );
                  if( smbInfo->thisSsnStats.maxPidMidLife < thisAge ) {
                      smbInfo->thisSsnStats.maxPidMidLife = thisAge;
                  }
                  free( thisSsnPidMid->age );

                  // remove the entry
                  if( prevSsnPidMid == NULL )
                  {
                      // It's the first in the chain
                      nextSsnPidMid = thisSsnPidMid->next;
                      free( thisSsnPidMid );
                      ssnUid->pidMidList = nextSsnPidMid;

                  } else {
                      nextSsnPidMid = thisSsnPidMid->next;
                      free( thisSsnPidMid );
                      prevSsnPidMid->next = nextSsnPidMid;
                  }
                  status = IIMS_SUCCESS;
                  currPidMidCountDec( sessionEntry );
                  break;
              }
              prevSsnPidMid = thisSsnPidMid;
              thisSsnPidMid = thisSsnPidMid->next;
          }
          break;
      }
  } while(0);

  return status;
}

//-----------------------------------------------------------------------
// SmbSsnDataFindByPidMid()
//
// return:
//     valid_ptr
//     NULL
//-----------------------------------------------------------------------
SmbSsnPidMid *SmbDecode::SmbSsnDataFindByPidMid( SessionEntry *sessionEntry,
                                                 SmbSsnUid    *ssnUid, 
                                                 tz_uint16     pid,
                                                 tz_uint16     mid )
{
  SmbSsnPidMid *thisSsnPidMid;
  SmbSsnPidMid *matchSsnPidMid = NULL;
  SmbInfo      *smbInfo = (SmbInfo *)sessionEntry->appInfo;
  tz_uint64     thisAge;

  do
  {
      if( ssnUid->pidMidList == NULL )
      {
          // Finding PID:MID on an empty list
          break;
      }
      else
      {
          // Do a linear search

          thisSsnPidMid = ssnUid->pidMidList;
          while( thisSsnPidMid )
          {
              if(   thisSsnPidMid->pid == pid
                 && thisSsnPidMid->mid == mid )
              {
                  matchSsnPidMid = thisSsnPidMid;

                  // Evaluate lifetime then refresh the age timer
                  thisAge = tz_watch_read_cycles( thisSsnPidMid->age );
                  if( smbInfo->thisSsnStats.maxPidMidLife < thisAge ) {
                      smbInfo->thisSsnStats.maxPidMidLife = thisAge;
                  }

                  tz_watch_reset( thisSsnPidMid->age );
                  break;
              }
              thisSsnPidMid = thisSsnPidMid->next;
          }
          break;
      }
  } while(0);

  return matchSsnPidMid;
}

//-----------------------------------------------------------------------
// SmbSsnDataFindAgedPidMid()
//     Search the set of PidMid descriptors on this session and attempt
//     to find one whose age exceeds the timeout limit
//
// return:
//     valid_ptr
//     NULL
//-----------------------------------------------------------------------
SmbSsnPidMid *SmbDecode::SmbSsnDataFindAgedPidMid( SessionEntry *sessionEntry,
                                                   SmbSsnUid    *ssnUid )
{
  SmbSsnPidMid *thisSsnPidMid;
  SmbSsnPidMid *matchSsnPidMid = NULL;
  SmbInfo      *smbInfo = (SmbInfo *)sessionEntry->appInfo;
  tz_uint64     thisAge;

  do
  {
      if( ssnUid->pidMidList == NULL )
      {
          // Finding PID:MID on an empty list
          break;
      }
      else
      {
          // Do a linear search
          thisSsnPidMid = ssnUid->pidMidList;
          while( thisSsnPidMid )
          {
              thisAge = tz_watch_read_cycles( thisSsnPidMid->age );

              if( thisAge > pidMidAgeTimeout )
              {
                  matchSsnPidMid = thisSsnPidMid;
                  break;
              }
              thisSsnPidMid = thisSsnPidMid->next;
          }
      }

  } while(0);

  return matchSsnPidMid;
}

//-----------------------------------------------------------------------
// SmbSsnDataAddTid()
//
// returns:
//     IIMS_SUCCESS
//     IIMS_FAILURE - unable to add
//-----------------------------------------------------------------------
tz_uint32 SmbDecode::SmbSsnDataAddTid( SessionEntry   *sessionEntry,
                                       SmbSsnUid      *ssnUid,
                                       tz_uint16       tid )
{
  tz_uint32 status = IIMS_SUCCESS;

  SmbSsnTid *ssnTid;

  do
  {
      if( !ssnUid )
      {
          //printf( "FAILURE %s:%d", __FILE__, __LINE__ );
          status = IIMS_FAILURE;
          break;
      }

      ssnTid = (SmbSsnTid *)calloc( 1, sizeof(SmbSsnTid));
      if( !ssnTid )
      {
          //printf( "FAILURE %s:%d", __FILE__, __LINE__ );
          status = IIMS_FAILURE;
          break;
      }

      // Format the content of the new entry
      ssnTid->tid  = tid;
      ssnTid->ctxtIsEmpty = true;
      ssnTid->isEventSource = true;

      if( ssnUid->tidList == NULL )
      {
          // No entries yet - format the new Tid entry
          ssnTid->next = NULL;

          // Add to head of list
          ssnUid->tidList = ssnTid;
      }
      else
      {
          // Add to head of existing list
          ssnTid->next = ssnUid->tidList;
          ssnUid->tidList = ssnTid;
      }
      currTidCountInc( sessionEntry );

  } while(0);

  return status;
}

//-----------------------------------------------------------------------
// SmbSsnDataRemoveTid()
//
// returns:
//     IIMS_SUCCESS
//     IIMS_FAILURE - unable to add
//-----------------------------------------------------------------------
tz_uint32 SmbDecode::SmbSsnDataRemoveTid( SessionEntry  *sessionEntry,
                                          SmbSsnUid     *ssnUid, 
                                          tz_uint16      tid )
{
  tz_uint32 status;
  SmbSsnTid *thisSsnTid, *prevSsnTid, *nextSsnTid;

  do
  {
      if( ssnUid->tidList == NULL )
      {
          // Removing from an empty list
          status = IIMS_FAILURE;
          break;
      }
      else
      {
          // Do a linear search and remove
          status = IIMS_FAILURE;

          prevSsnTid = NULL;
          thisSsnTid = ssnUid->tidList;
          while( thisSsnTid )
          {
              if( thisSsnTid->tid == tid )
              {
                  // Application Logout
                  SendAppLogoutEvent( sessionEntry, thisSsnTid );

                  // If this TID has a sessionDetail pointer then free it
                  // unconditionally.  If sessionEntry also has that same
                  // pointer, then NULL it out
                  if( thisSsnTid->seCtxt.sessionDetail )
                  {
                      if(   sessionEntry->sessionDetail 
                         == thisSsnTid->seCtxt.sessionDetail )
                      {
                          sessionEntry->sessionDetail = NULL;
                      }
                      free(thisSsnTid->seCtxt.sessionDetail);
                  }

                  // remove the entry
                  if( prevSsnTid == NULL )
                  {
                      // It's the first in the chain
                      nextSsnTid = thisSsnTid->next;
                      free( thisSsnTid );
                      ssnUid->tidList = nextSsnTid;

                  } else {
                      nextSsnTid = thisSsnTid->next;
                      free( thisSsnTid );
                      prevSsnTid->next = nextSsnTid;
                  }

                  currTidCountDec( sessionEntry );
                  status = IIMS_SUCCESS;
                  break;
              }
              prevSsnTid = thisSsnTid;
              thisSsnTid = thisSsnTid->next;
          }
          break;
      }
  } while(0);

  return status;
}

//-----------------------------------------------------------------------
// SmbSsnDataFindByTid()
//-----------------------------------------------------------------------
SmbSsnTid *SmbDecode::SmbSsnDataFindByTid( SmbSsnUid *ssnUid, 
                                           tz_uint16 tid )
{
  SmbSsnTid *thisSsnTid;
  SmbSsnTid *matchSsnTid = NULL;

  do
  {
      if( ssnUid->tidList == NULL )
      {
          // Finding Tid on an empty list
          break;
      }
      else
      {
          // Do a linear search

          thisSsnTid = ssnUid->tidList;
          while( thisSsnTid )
          {
              if( thisSsnTid->tid == tid )
              {
                  matchSsnTid = thisSsnTid;
                  break;
              }
              thisSsnTid = thisSsnTid->next;
          }
          break;
      }
  } while(0);

  return matchSsnTid;
}
