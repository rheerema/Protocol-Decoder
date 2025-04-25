//-----------------------------------------------------------------------
//   Copyright (c) <2005> by Tizor Systems. 
//   All Rights Reserved.
//   Licensed Material - Property of Tizor Systems.
//
//   File: smbDebug.cc
// 
//   Component: SMB Protocol Debug Facility
//
//-----------------------------------------------------------------------

#include <logging.h>      // syslog facility

#include <arpa/inet.h>
#include <net/ethernet.h> // ethernet header
#include <fcntl.h>        // open(), read()

#include <netmon/layerManager.hh>

#include <netmon/smbDebug.hh>
#include <netmon/packetLog.hh>
#include <netmon/loginEvtCtrl.hh>

extern LayerManager *TZ_layerManager;


// Smb Debug Log static member allocations
//
tz_int8  *SmbDebug::appendPtr;
tz_uint32 SmbDebug::appendCnt;
tz_uint32 SmbDebug::logHead;
tz_uint32 SmbDebug::logIsEnabled;
tz_uint32 SmbDebug::monIsEnabled;
tz_uint32 SmbDebug::logTail;
tz_int8   SmbDebug::logBuf[SMB_DEBUG_LOG_ENTRIES]
                          [SMB_DEBUG_LOG_LINESIZE];
tz_uint32 SmbDebug::logToStdout;
tz_uint32 SmbDebug::logToFile;
FILE     *SmbDebug::logFile;


// Command line processing
tz_int8 SmbDebug::intCmdStg[TZX_512_STRING];
int     SmbDebug::argc;
char    SmbDebug::argv[SMB_DEBUG_CMDPARMS][SMB_DEBUG_CMDPARMSIZE];

// Debug config init file
tz_int8 SmbDebug::utilReadToken[TZX_64_STRING];
tz_int8 SmbDebug::utilReadEquals[TZX_64_STRING];
tz_int8 SmbDebug::utilReadValue[TZX_64_STRING];
tz_int8 SmbDebug::utilRead2Value[TZX_64_STRING];

// Pipe command file
FILE     *SmbDebug::pipeCmdFile = (FILE *)NULL;
int       SmbDebug::pipeCap1File;
int       SmbDebug::pipeCap2File;
tz_uint8 *SmbDebug::pipePktData;

//----------------------------------------------------------------------
// Currently Supported Debug Commands
//----------------------------------------------------------------------
static char *helpInfo[] = 
{
  "SMB debug -- available commands --",
  "\n",
  "help",
  "\n",
  "cap {on | off}",
  "cap du",
  "coredump",
  "def-login {on | off}",
  "fileshare {on | off}",
  "filt {on | off}",
  "\n",
  "log {on | off}",
  "log stdout {on | off}",
  "log file on <file>",
  "log file off",
  "\n",
  "mon {on | off}",
  "\n",
  "pipe open <file>",
  "pipe step",
  "pipe go",
  "pipe close",
  "\n",
  "show config",
  "show stats",
  "show def-login",
  "show data",
  "\n",
  "stats cl",
};

//-----------------------------------------------------------------------
// SmbIteratorClearStats()
//     Callback function to clear stats in each of the
//     smbDecode objects.
//-----------------------------------------------------------------------
void SmbIteratorClearStats (void *object, void *context)
{
    SmbDecode *smbDecode = (SmbDecode *)object;

    smbDecode->ClearDecodeStats();
}

//-----------------------------------------------------------------------
// SmbIteratorSetFilterMode()
//     Callback function to set the filter mode in each of the
//     smbDecode objects.
//-----------------------------------------------------------------------
void SmbIteratorSetFilterMode (void *object, void *context)
{
    SmbDecode *smbDecode = (SmbDecode *)object;

    smbDecode->smbUtilEvtFilterMode((bool) context);
}

//-----------------------------------------------------------------------
// SmbIteratorGetFilterMode()
//     Callback function to get the filter mode.
//-----------------------------------------------------------------------
void SmbIteratorGetFilterMode (void *object, void *context)
{
    SmbDecode   *smbDecode = (SmbDecode *)object;
    bool        *isEnab    = (bool *)context;

    *isEnab = smbDecode->smbUtilEvtFilterModeIsEnab();
}

//-----------------------------------------------------------------------
// SmbIteratorGetPidMidConfig
//-----------------------------------------------------------------------
void SmbIteratorGetPidMidVars ( void *object, void *context)
{
    SmbDecode   *smbDecode = (SmbDecode *)object;
    tz_uint64   *var       = (tz_uint64 *)context;

    smbDecode->smbUtilGetPidMidConfig( var );
}

//-----------------------------------------------------------------------
// SmbIteratorSetPidMidConfig
//-----------------------------------------------------------------------
void SmbIteratorSetPidMidVars ( void *object, void *context)
{
    SmbDecode   *smbDecode = (SmbDecode *)object;
    tz_uint64   *var       = (tz_uint64 *)context;

    smbDecode->smbUtilSetPidMidConfig( var );
}

//-----------------------------------------------------------------------
// process()
//     Process an SMB debug command
//
//     Note that the last argument passed is always ignored.  It is 
//     currently used to spoof the management code into believing
//     a unique "configuration change" is being requested so it will
//     therefore pass the command string into this function.
//-----------------------------------------------------------------------
void SmbDebug::process( char *cmdStg )
{
  size_t cmdStgLen = strlen(cmdStg) +1;
  char  *cmdWord;

  do
  {
//    lc_log_basic(LOG_NOTICE, "SMB debug command %s", cmdStg);

      if( cmdStgLen > TZX_512_STRING )  break;

      // Copy the passed command string to our internal command
      // string memory so strtok can poke NULLs into it
      memcpy( intCmdStg, cmdStg, cmdStgLen );
      argc = 0;

      cmdWord = strtok( intCmdStg, " ");
      while( cmdWord != NULL )
      {
          memcpy( argv[argc], cmdWord, strlen(cmdWord) +1 );
          ++argc;
          cmdWord = strtok( NULL, " " );
      }

      // Dispatch to the command handler
      if( !strcmp( argv[0], "help" ) )
      {
          tz_uint32 helpIdx;
          for( helpIdx=0; helpIdx < (sizeof(helpInfo) / sizeof(char *));
                                                             ++helpIdx )
          {
              lc_log_basic(LOG_NOTICE,"%s\n", helpInfo[helpIdx]);
          }
      }
      else if( !strcmp( argv[0], "show" ) )
      {
          dbgHandleShow();
      }
      else if( !strcmp( argv[0], "log" ) )
      {
          dbgHandleLog();
      }
      else if( !strcmp( argv[0], "filt" ) )
      {
          dbgHandleFilt();
      }
      else if( !strcmp( argv[0], "mon" ) )
      {
          dbgHandleMon();
      }
      else if( !strcmp( argv[0], "def-login" ) )
      {
          dbgHandleDefLogin();
      }
      else if( !strcmp( argv[0], "fileshare" ) )
      {
          dbgHandleFileshare();
      }
      else if( !strcmp( argv[0], "stats" ) )
      {
          if( !strcmp( argv[1], "cl" ) )
          {
              // Clear stats counters
              NetMonDriver *nmd = TZ_layerManager->netMonDriver;

              nmd->NetmonThreadIterate (PROTOCOL_SMB, 
                                        SmbIteratorClearStats, 
                                        NULL);
              lc_log_basic(LOG_NOTICE, "SMB stats CLEARED" );
          }
      }
      else if( !strcmp( argv[0], "pipe" ) )
      {
          dbgHandlePipe();
      }
      else if( !strcmp( argv[0], "cap" ) )
      {
          dbgHandleCap();
      }
      else if( !strcmp( argv[0], "coredump" ) )
      {
          tz_uint32 *pBad = NULL;
          ++(*pBad);
      }

  } while (0);

}

//-----------------------------------------------------------------------
// dbgHandleShow()
//     Show various aspects of the SMB adapber
//
//     argc and argv[][] passed implicitly as data members
//     argv[0] == "show"
//-----------------------------------------------------------------------
bool SmbDebug::dbgHandleShow( void )
{
  bool          ret = IIMS_SUCCESS;

  if( !strcmp( argv[1], "data" ) )
  {
      lc_log_basic(LOG_NOTICE, "SMB debug -- show data --" );
      dbgHandleShowData();
  }
  else if( !strcmp( argv[1], "stats" ) )
  {
      lc_log_basic(LOG_NOTICE, "SMB debug -- show stats --" );
      SmbDecode::smbUtilErrorDisplayStats();
  }
  else if( !strcmp( argv[1], "config" ) )
  {
      lc_log_basic(LOG_NOTICE, "SMB debug -- show config --" );
      dbgHandleShowConfig();
  }
  else if( !strcmp( argv[1], "def-login" ) )
  {
      lc_log_basic(LOG_NOTICE, "LEC debug -- show def-login --" );
      dbgHandleShowDefLogin();
  }

  return ret;
}


//-----------------------------------------------------------------------
// dbgHandleShowData()
//     Dump SMB internal data structures
//
//     argc and argv[][] passed implicitly as data members
//     argv[0] == "data"
//-----------------------------------------------------------------------
bool SmbDebug::dbgHandleShowData( void )
{
  bool      ret = IIMS_SUCCESS;
  char      direction;
  tz_int8   clientAddr[64];
  tz_int8   serverAddr[64];
  uint16    clientPort, serverPort;
  struct in_addr srcAddress;
  struct in_addr dstAddress;
  SessionEntry  *sessionEntry;


  do
  {
      NetMonDriver *nmd = TZ_layerManager->netMonDriver;
      if( nmd->DbgSmbGetFirstSession(&sessionEntry) != IIMS_SUCCESS )
      {
          break;
      }

      // Process first SessionEntry
      if( sessionEntry->trafficDirection == TRAFFIC_FROM_CLIENT )
      {
          direction = '*';
      } else {
          direction = ' ';
      }
      if (sessionEntry->clientIsDst)
      {
          srcAddress.s_addr = sessionEntry->addressTuple.dst;
          dstAddress.s_addr = sessionEntry->addressTuple.src;
          clientPort = htons(sessionEntry->addressTuple.dport);
          serverPort = htons(sessionEntry->addressTuple.sport);
      }
      else
      {
          srcAddress.s_addr = sessionEntry->addressTuple.src;
          dstAddress.s_addr = sessionEntry->addressTuple.dst;
          clientPort = htons(sessionEntry->addressTuple.sport);
          serverPort = htons(sessionEntry->addressTuple.dport);
      }
      strcpy(&clientAddr[0], inet_ntoa(srcAddress));
      strcpy(&serverAddr[0], inet_ntoa(dstAddress));
      // Session indent 2 (where dir is part of indent field)
      lc_log_basic(LOG_NOTICE, "%c %s  %d  %s  %d", direction,
                                   clientAddr, clientPort,
                                   serverAddr, serverPort);

      if( sessionEntry->trafficDirection == TRAFFIC_FROM_CLIENT )
      {
          displaySmbInfo( *sessionEntry );
      }

      while( nmd->DbgSmbGetNextSession(&sessionEntry) == IIMS_SUCCESS )
      {
          // Process next SessionEntry
          if( sessionEntry->trafficDirection == TRAFFIC_FROM_CLIENT )
          {
              direction = '*';
          } else {
              direction = ' ';
          }
          if (sessionEntry->clientIsDst)
          {
              srcAddress.s_addr = sessionEntry->addressTuple.dst;
              dstAddress.s_addr = sessionEntry->addressTuple.src;
              clientPort = htons(sessionEntry->addressTuple.dport);
              serverPort = htons(sessionEntry->addressTuple.sport);
          }
          else
          {
              srcAddress.s_addr = sessionEntry->addressTuple.src;
              dstAddress.s_addr = sessionEntry->addressTuple.dst;
              clientPort = htons(sessionEntry->addressTuple.sport);
              serverPort = htons(sessionEntry->addressTuple.dport);
          }
          strcpy(&clientAddr[0], inet_ntoa(srcAddress));
          strcpy(&serverAddr[0], inet_ntoa(dstAddress));
          // Session indent 2  (where dir is part of indent field)
          lc_log_basic(LOG_NOTICE, "%c %s  %d  %s  %d", direction,
                                   clientAddr, clientPort,
                                   serverAddr, serverPort);

          if( sessionEntry->trafficDirection == TRAFFIC_FROM_CLIENT )
          {
              displaySmbInfo( *sessionEntry );
          }
      }

  } while (0);

  return ret;
}


const char onStg[] = "on";
const char offStg[] = "off";
//-----------------------------------------------------------------------
// dbgHandleShowConfig()
//-----------------------------------------------------------------------
bool SmbDebug::dbgHandleShowConfig( void )
{
  bool          ret = IIMS_SUCCESS;
  bool          filterModeIsEnab;
  bool          fileshareModeIsEnab;
  tz_uint64     var[2];
  NetMonDriver *nmd = TZ_layerManager->netMonDriver;

  nmd->NetmonThreadIterate (PROTOCOL_SMB, 
                            SmbIteratorGetFilterMode, 
                            &filterModeIsEnab);

  nmd->NetmonThreadIterate (PROTOCOL_SMB,
                            SmbIteratorGetPidMidVars,
                            var );

  lc_log_basic(LOG_NOTICE,"        fileshare : %s", 
              TZ_layerManager->lmCfgSmb.fileshareIsEnabled ? onStg : offStg );
  lc_log_basic(LOG_NOTICE,"pidMidPerSsnLimit : %llu", var[0] );
  lc_log_basic(LOG_NOTICE," pidMidAgeTimeout : %0.3Lf", (long double)
                                                var[1] / nmd->cyclesPerSecond );
  lc_log_basic(LOG_NOTICE,"          logging : %s", logIsEnabled ? onStg : offStg );
  lc_log_basic(LOG_NOTICE,"    log to stdout : %s", logToStdout ? onStg : offStg );
  lc_log_basic(LOG_NOTICE,"      log to file : %s", logToFile ? onStg : offStg );
  lc_log_basic(LOG_NOTICE,"           filter : %s", filterModeIsEnab 
                                                              ? onStg : offStg );
  lc_log_basic(LOG_NOTICE,"          monitor : %s", monIsEnabled ? onStg : offStg );
  lc_log_basic(LOG_NOTICE,"         def-login: %s", nmd->encodingEngine->lec->GetMode()
                                                               ? onStg : offStg);

  return ret;
}

//-----------------------------------------------------------------------
// displaySmbInfo()
//-----------------------------------------------------------------------
void SmbDebug::displaySmbInfo( SessionEntry &sessionEntry )
{
  SmbInfo *ssnData = (SmbInfo *)sessionEntry.appInfo;
  SmbSsnUid    *thisSsnUid;
  SmbSsnPidMid *thisSsnPidMid;
  SmbSsnTid    *thisSsnTid;
  SmbSsnFid    *thisSsnFid;

  do
  {
      if( sessionEntry.application != PROTOCOL_SMB )
      {
          break;
      }

      if( ssnData->uidList != NULL )
      {
          thisSsnUid = ssnData->uidList;
          while( thisSsnUid )
          {
              // Uid indent 4
              lc_log_basic(LOG_NOTICE,"    uid %04x  %s",
                           thisSsnUid->uid, 
                           ((SmbInfo *)sessionEntry.appInfo)->serverUser );

              // PidMid  (indent 6)
              thisSsnPidMid = thisSsnUid->pidMidList;
              while( thisSsnPidMid )
              {
                  lc_log_basic(LOG_NOTICE,"      pid %04x mid %04x",
                                thisSsnPidMid->pid, thisSsnPidMid->mid );
                  thisSsnPidMid = thisSsnPidMid->next;
              }

              // Tid  (indent 6)
              thisSsnTid = thisSsnUid->tidList;
              while( thisSsnTid )
              {
                  lc_log_basic(LOG_NOTICE,"      tid %04x %s %s",
                                thisSsnTid->tid, thisSsnTid->servername,
                                                 thisSsnTid->sharename );
                  thisSsnTid = thisSsnTid->next;
              }

              // Fid  (indent 6)
              thisSsnFid = thisSsnUid->fidList;
              while( thisSsnFid )
              {
                  lc_log_basic(LOG_NOTICE,"      fid %04x %s",
                                thisSsnFid->fid, thisSsnFid->filename );
                  thisSsnFid = thisSsnFid->next;
              }

              thisSsnUid = thisSsnUid->next;
          }
      }

  } while (0);

}

//-----------------------------------------------------------------------
// dbgHandleLog()
//     Operations on the debug log
//
//     argc and argv[][] passed implicitly as data members
//     argv[0] == "log"
//-----------------------------------------------------------------------
bool SmbDebug::dbgHandleLog( void )
{
  bool      ret;
  tz_int8  *line;

  if( !strcmp( argv[1], "du" ) )
  {
     // Dump the log
     ret = SmbDebug::logLineGet( &line );
     while( ret == IIMS_SUCCESS )
     {
         lc_log_basic(LOG_NOTICE, "%s", line );
         ret = SmbDebug::logLineGet( &line );
     }
  }
  else if( !strcmp( argv[1], "on" ) )
  {
      // Enable log collection
      lc_log_basic(LOG_NOTICE, "SMB Debug Log is ENABLED" );
      SmbDebug::logIsEnabled = true;
  }
  else if( !strcmp( argv[1], "off" ) )
  {
      // Disable log collection
      lc_log_basic(LOG_NOTICE, "SMB Debug Log is DISABLED" );
      SmbDebug::logIsEnabled = false;
  }
  else if( !strcmp( argv[1], "cl" ) )
  {
      // Clear the log
      lc_log_basic(LOG_NOTICE, "SMB Debug Log is CLEARED" );
      logTail = logHead;
  }
  else if( !strcmp( argv[1], "stdout" ) )
  {
      if( !strcmp( argv[2], "on" ) ) {
          lc_log_basic(LOG_NOTICE, "SMB Debug output to Stdout is ON" );
          SmbDebug::logToStdout = true;

          // Enable logging if it is not already so
          SmbDebug::logIsEnabled = true;
      } else {
          lc_log_basic(LOG_NOTICE, "SMB Debug output to Stdout is OFF" );
          SmbDebug::logToStdout = false;
          SmbDebug::logIsEnabled = false;
      }
  }
  else if( !strcmp( argv[1], "file" ) )
  {
      if( !strcmp( argv[2], "on" )) {
          SmbDebug::logFile = fopen( argv[3], "w" );
          if( SmbDebug::logFile != (FILE *)NULL ) {
              lc_log_basic(LOG_NOTICE, "SMB Debug Log to file \"%s\" is ON",
                                                               argv[3] );
          }
          SmbDebug::logToFile = true;

          // Enable logging if it is not already so
          SmbDebug::logIsEnabled = true;
      }
      if( !strcmp( argv[2], "off" )) {
          lc_log_basic(LOG_NOTICE, "SMB Debug Log to file is OFF" );

          SmbDebug::logToFile = false;
          SmbDebug::logIsEnabled = false;

          if( SmbDebug::logFile != (FILE *)NULL ) {
              fclose( SmbDebug::logFile );
          }
          SmbDebug::logFile = NULL;
      }
  }

  ret = IIMS_SUCCESS;
  return ret;
}

//----------------------------------------------------------------------
// logInit()
//----------------------------------------------------------------------
void SmbDebug::logInit( void )
{
  logHead = logTail = 0;

  appendPtr = logBuf[logHead];
  appendCnt = 0;
}

//----------------------------------------------------------------------
// logLineAppend()
//     Append text to the current line.  When the client calls
//     logLinePut() the line is closed and the current line advances
//     to the next in the buffer (wrapping if necessary)
//----------------------------------------------------------------------
void SmbDebug::logLineAppend( const tz_int8 *format, ... )
{
  va_list  ap;
  int      numChars;
  int      avail;

  va_start( ap, format );

  // Calculate the remaining size available on the line.
  avail = SMB_DEBUG_LOG_LINESIZE - appendCnt;

  numChars = vsnprintf( &appendPtr[appendCnt], avail, format, ap );

  if( numChars < avail )
  {
      // No overflow
      appendCnt += numChars;
  }
  else
  {
      // Overflow occurred
      appendCnt += avail;
  }

  va_end( ap );
}

//----------------------------------------------------------------------
// logLinePut()
//     Insert a debug line into the logger.  If we wrap then we move
//     the tail to maintain the most recent events.
//
// Note: this design allows the storage of SMB_DEBUG_LOG_ENTRIES - 2
//----------------------------------------------------------------------
void SmbDebug::logLinePut( void )
{
  tz_int32 depth;  // signed

  // Check if optional "print to stdout" is enabled and tee output
  // to it if so
  if( logToStdout )
  {
      printf( "%s", logBuf[logHead] );
  }

  // Check if we are to log to a file
  if( logToFile )
  {
      fputs( logBuf[logHead], logFile );
  }

  // Move to the next slot and wrap if necessary
  logHead++;
  logHead %= SMB_DEBUG_LOG_ENTRIES;
  depth = logHead - logTail;

  if( depth < 0 )  depth += SMB_DEBUG_LOG_ENTRIES;

  // Check to see if we're exceeding the size if the log.  If so
  // move the tail to discard oldest line
  if( depth >= SMB_DEBUG_LOG_ENTRIES - 1 )
  {
      logTail++;
      logTail %= SMB_DEBUG_LOG_ENTRIES;
  }

  // Establish the new line
  appendPtr = logBuf[logHead];
  appendCnt = 0;

}

//----------------------------------------------------------------------
// logLineGet()
//     Remove a debug line from the logger.  If put() has wrapped
//     then tail is advanced.  This ensures that get() will display
//     the most recent events if the log has filled up
// returns:
//     IIMS_SUCCESS : "line" points to a log line
//     IIMS_FAILURE : no log line to return
//----------------------------------------------------------------------
bool SmbDebug::logLineGet( tz_int8 **line )
{
  tz_int32 depth;  // signed

  depth = logHead - logTail;
  if( depth < 0 )  depth += SMB_DEBUG_LOG_ENTRIES;

  if( depth > 0 )
  {
      *line = logBuf[logTail];
      logTail++;
      logTail %= SMB_DEBUG_LOG_ENTRIES;
      return IIMS_SUCCESS;
  } else {
      *line = NULL;
      return IIMS_FAILURE;
  }
}


//-----------------------------------------------------------------------
// dbgHandleFilt()
//     Operations affecting filtering
//
//     argc and argv[][] passed implicitly as data members
//     argv[0] == "filt"
//-----------------------------------------------------------------------
bool SmbDebug::dbgHandleFilt( void )
{
  bool         ret;
  NetMonDriver *nmd = TZ_layerManager->netMonDriver;

  if( !strcmp( argv[1], "on" ) )
  {
      // Enable log collection
      lc_log_basic(LOG_NOTICE, "%s", "SMB Event Filtering is ENABLED" );
      nmd->NetmonThreadIterate (PROTOCOL_SMB, 
                                SmbIteratorSetFilterMode, 
                                (void *) true);
  }
  else if( !strcmp( argv[1], "off" ) )
  {
      // Disable log collection
      lc_log_basic(LOG_NOTICE, "%s", "SMB Event Filtering is DISABLED" );
      nmd->NetmonThreadIterate (PROTOCOL_SMB, 
                                SmbIteratorSetFilterMode, 
                                (void *) false);
  }
  else
  {
      lc_log_basic(LOG_NOTICE,"tizor sys net smb filt - INVALID MODE %s",
                                                                 argv[1]);
  }

  ret = IIMS_SUCCESS;
  return ret;
}

//-----------------------------------------------------------------------
// dbgHandleMon()
//     Enable or disable "monitor" of SMB decoder operation.  When
//     enabled, SmbMonLog() directives are sent to syslog
//
//     argc and argv[][] passed implicitly as data members
//     argv[0] == "mon"
//-----------------------------------------------------------------------
bool SmbDebug::dbgHandleMon( void )
{
  bool         ret;
  NetMonDriver *nmd = TZ_layerManager->netMonDriver;

  if( !strcmp( argv[1], "on" ) )
  {
      // Enable monitor
      lc_log_basic(LOG_NOTICE, "%s", "SMB monitor output is ENABLED" );
      monIsEnabled = true;
  }
  else if( !strcmp( argv[1], "off" ) )
  {
      // Disable monitor
      lc_log_basic(LOG_NOTICE, "%s", "SMB monitor output is DISABLED" );
      monIsEnabled = false;
  }
  else
  {
      lc_log_basic(LOG_NOTICE,"tizor sys net smb mon - INVALID MODE %s",
                                                                 argv[1]);
  }

  ret = IIMS_SUCCESS;
  return ret;
}

//-----------------------------------------------------------------------
// dbgHandleFileshare()
//     Operations affecting fileshare mode.  Normally we want this to be
//     controlled by the monitor command and whether SMB is configured
//     or not.  Here we update Layer Manager config just like the monitor
//     command does.
//
//     argc and argv[][] passed implicitly as data members
//     argv[0] == "fileshare"
//-----------------------------------------------------------------------
bool SmbDebug::dbgHandleFileshare( void )
{
  bool         ret;
  //NetMonDriver *nmd = TZ_layerManager->netMonDriver;

  if( !strcmp( argv[1], "on" ) )
  {
      // Enable fileshare mode
      lc_log_basic(LOG_NOTICE, "%s", "SMB Fileshare Mode is ENABLED" );
      TZ_layerManager->lmCfgSmb.fileshareIsEnabled = true;
      ++TZ_layerManager->lmCfgSmb.chgSeqNum;
  }
  else if( !strcmp( argv[1], "off" ) )
  {
      // Disable fileshare mode
      lc_log_basic(LOG_NOTICE, "%s", "SMB Fileshare Mode is DISABLED" );
      TZ_layerManager->lmCfgSmb.fileshareIsEnabled = false;
      ++TZ_layerManager->lmCfgSmb.chgSeqNum;
  }
  else
  {
      lc_log_basic(LOG_NOTICE,"tizor sys net smb fileshare - INVALID MODE %s",
                                                                 argv[1]);
  }

  ret = IIMS_SUCCESS;
  return ret;
}

//-----------------------------------------------------------------------
// dbgHandleCap()
//     Operations affecting the tcpdump capture file output feature
//
//     argc and argv[][] passed implicitly as data members
//     argv[0] == "cap"
//-----------------------------------------------------------------------
bool SmbDebug::dbgHandleCap( void )
{
    // NOTE: Deprecated. Use "netmon tizor keep" to set the pktLog size.
    //       Use "show netmon debug dumppktlog" to create cap files.
  return IIMS_SUCCESS;
}

// Frame Header for a cap file packet entry
//
typedef struct FrameHdr
{
    tz_uint32 sec;           // since 1-1-1970
    tz_uint32 uSec;          // into the above sec
    tz_uint32 capturedBytes; // 
    tz_uint32 actualLen;     // possibly > capturedBytes
} FrameHdr;

//-----------------------------------------------------------------------
// dbgHandlePipe()
//     Named Pipe Debug Facility
//
//     argv[0] == "pipe"
//
//     NOTE: cap file manipulations herein assumes that the data is
//     stored in little endian format.  There should be endianness
//     transparency bulit in but, what the heck, this is just debug code.
//-----------------------------------------------------------------------
bool SmbDebug::dbgHandlePipe( void )
{
  bool    ret = IIMS_SUCCESS;
  bool    cleanup = false;
  bool    formatIsValid = false;
  int     num;

  do
  {
      if( !strcmp( argv[1], "open" ) )
      {
          pipeCmdFile = (FILE *)NULL;
          pipeCap1File = pipeCap2File = 0;

          pipeCmdFile = fopen( argv[2], "r" );
          if( pipeCmdFile == (FILE *)NULL )
          {
              lc_log_basic(LOG_NOTICE,"pipe: error opening %s", argv[2]);
              ret = IIMS_FAILURE;
              break;
          }

          // We expect the first two lines to specify capfiles
          num = fscanf( pipeCmdFile, "%s %s %s", utilReadToken,
                                                 utilReadEquals,
                                                 utilReadValue );
          // First expect "cap1"
          if( strcmp(utilReadToken, "cap1") ) {
              ret = IIMS_FAILURE;
              lc_log_basic(LOG_NOTICE,"pipe: format problem 1" );
              break;
          }
          pipeCap1File = open( utilReadValue, O_RDONLY );
          if( pipeCap1File == -1 ) {
              lc_log_basic(LOG_NOTICE,"pipe: format problem 2" );
              ret = IIMS_FAILURE;
              break;
          }

          num = fscanf( pipeCmdFile, "%s %s %s", utilReadToken,
                                                 utilReadEquals,
                                                 utilReadValue );
          // Second expect "cap2"
          if( strcmp(utilReadToken, "cap2") ) {
              lc_log_basic(LOG_NOTICE,"pipe: format problem 3" );
              ret = IIMS_FAILURE;
              break;
          }
          pipeCap2File = open( utilReadValue, O_RDONLY );
          if( pipeCap2File == -1 ) {
              lc_log_basic(LOG_NOTICE,"pipe: format problem 4" );
              ret = IIMS_FAILURE;
              break;
          }

          // Allocate storage for packet data
          pipePktData = (tz_uint8 *)malloc( 2048 );

          // D E B U G
          //lc_log_basic(LOG_NOTICE,"pipe: SUCCESS !" );

          break;
      }

      if( !strcmp( argv[1], "close" ) )
      {
          free( pipePktData );
          cleanup = true;
          break;
      }

      while(    !strcmp(argv[1], "step")
             || !strcmp(argv[1], "go") )
      {
          num = fscanf( pipeCmdFile, "%s %s %s %s", utilReadToken,
                                                    utilReadEquals,
                                                    utilReadValue,
                                                    utilRead2Value );
          if( num == EOF )  break;

          formatIsValid =    num == 4 
                         && !strcmp(utilReadToken, "pkt")
                         && utilReadEquals[0] == '=';

          if( !formatIsValid )
          {
              lc_log_basic(LOG_NOTICE,"pipe: format problem 5" );
              break;
          }

          // D E B U G
          //lc_log_basic(LOG_NOTICE,"pipe: %s %s", utilReadValue, utilRead2Value );

          // Select the specified cap file
          int cap;
          if( !strcmp(utilReadValue, "cap1") ) {
              cap = pipeCap1File;
          } else if( !strcmp(utilReadValue, "cap2") ) {
              cap = pipeCap2File;
          } else {
              lc_log_basic(LOG_NOTICE,"pipe: format problem 6" );
              break;
          }

          // Convert the desired packet number
          tz_uint32 thePkt = strtoul( utilRead2Value, NULL, 0 );

          // Go to the first packet past the 24-byte file header
          int rv;
          tz_uint32 currPkt = 1;
          FrameHdr fh;

          rv = lseek( cap, 24, SEEK_SET );
          if( rv == -1 ) {
              lc_log_basic(LOG_NOTICE,"pipe: problem 7" );
              break;
          }

          // Merrily skip packet to packet from the beginning until we
          // get to the packet we want.
          while( currPkt != thePkt )
          {
              rv = read( cap, (char *)&fh, sizeof(FrameHdr));

              if( rv == 0 ) {
                  // End of file
                  break;
              }
              if( rv == -1 || rv != sizeof(FrameHdr) ) {
                  lc_log_basic(LOG_NOTICE,"pipe: problem 8" );
                  break;
              }

              // Move past currPkt packet data
              rv = lseek( cap, fh.capturedBytes, SEEK_CUR );
              if( rv == -1 ) {
                  lc_log_basic(LOG_NOTICE,"pipe: problem 9" );
                  break;
              }

              ++currPkt;
          }

          if( currPkt == thePkt )
          {
              // We're positioned on the frame header of the desired pkt.
              // Read the header to obtain the packet data length and to
              // seek up to the packet data itself
              rv = read( cap, (char *)&fh, sizeof(FrameHdr));

              if( rv == 0 ) {
                  // End of file
                  break;
              }
              if( rv == -1 || rv != sizeof(FrameHdr) ) {
                  lc_log_basic(LOG_NOTICE,"pipe: problem 10" );
                  break;
              }

              // Here is where we inject the packet ! ! !
              NetMonDriver *nmd = TZ_layerManager->netMonDriver;
              read( cap, pipePktData, fh.capturedBytes );

#if 1
              nmd->InjectPacket(PACKET_SRC_FILE, FILE_SOURCE_ID, 
                                &nmd->interfaceTable[FILE_SOURCE_ID].driverCounters,
                                pipePktData, fh.capturedBytes);

#else
              // D E B U G
              lc_log_basic(LOG_NOTICE,"pkt %u (len %u) %02x %02x %02x %02x %02x %02x %02x %02x",
                  (unsigned)currPkt, (unsigned)fh.capturedBytes,
                  pipePktData[0], pipePktData[1], pipePktData[2], pipePktData[3], 
                  pipePktData[4], pipePktData[5], pipePktData[6], pipePktData[7] );
#endif
          }

          if( !strcmp(argv[1], "step") )
          {
              break;
          }
      }


  } while (0);

  if( ret == IIMS_FAILURE || cleanup )
  {
      if( pipeCmdFile != (FILE *)NULL ) {
          fclose( pipeCmdFile );
      }
      if( pipeCap1File != 0 ) {
          close( pipeCap1File );
      }
      if( pipeCap2File != 0 ) {
          close( pipeCap2File );
      }
  }

  return ret;
}

//-----------------------------------------------------------------------
// dbgHandleDefLogin()
//     Enable or disable "def-login" capability.  This doesn't belong
//     here as an SMB debug capability because it relates to all of
//     network traffic auditing.  But here is where I put it.
//
//     argc and argv[][] passed implicitly as data members
//     argv[0] == "mon"
//-----------------------------------------------------------------------
bool SmbDebug::dbgHandleDefLogin( void )
{
  bool         ret;
  NetMonDriver *nmd = TZ_layerManager->netMonDriver;

  if( !strcmp( argv[1], "on" ) )
  {
      // Enable Deferred Login
      lc_log_basic(LOG_NOTICE, "%s", "Deferred Login is ENABLED" );
      nmd->encodingEngine->lec->SetMode(true);
  }
  else if( !strcmp( argv[1], "off" ) )
  {
      // Disable Deferred Login
      lc_log_basic(LOG_NOTICE, "%s", "Deferred Login is DISABLED" );
      nmd->encodingEngine->lec->SetMode(false);
  }
  else
  {
      lc_log_basic(LOG_NOTICE,"tizor sys net smb def-login - INVALID MODE %s",
                                                                 argv[1]);
  }

  ret = IIMS_SUCCESS;
  return ret;
}

//-----------------------------------------------------------------------
// dbgHandleShowDefLogin()
//     Display Deferred Login stats
//-----------------------------------------------------------------------
bool SmbDebug::dbgHandleShowDefLogin( void )
{
  NetMonDriver *nmd = TZ_layerManager->netMonDriver;
  nmd->encodingEngine->lec->ShowStatsSyslog();
  return IIMS_SUCCESS;
}

//--------------------------------------------------------------------
// utilReadIni()
//     Attempt to read debug config from "smb.ini".  If the file 
//     exists and its format is correct, use its contents to override
//     debug options.
//
//     Tokens are identical to SmbDebug variables that control debug
//     operation.  Not all variables must be specified.  Everything
//     defaults to production values except where overridden by
//     the ini file.  Examples of valid formats:
//
//         logIsEnabled = true
//         logToStdout = true
//     or
//         logIsEnabled = 1
//         logToStdout = 0
//--------------------------------------------------------------------
void SmbDebug::utilReadIni( void )
{
    NetMonDriver *nmd = TZ_layerManager->netMonDriver;
    FILE     *configFile;
    bool      formatIsValid = false;
    int       num;
    tz_uint64 var[2];


    // Unconditionally default to hardcoded production values.
    // If init file doesn't exist or has a bad format then these stand.
    logIsEnabled = false;
    monIsEnabled = false;
    logToStdout = false;
    logToFile = false;
    logFile = NULL;


    do
    {
        // should be /opt/tizor/bin
        configFile = fopen( "/opt/tizor/bin/smb.ini", "r" );

        if( configFile == (FILE *)NULL )
        {
            // Normal production startup should be quiet.  No log entry
            // if SMB debug file is not found

            //printf( "SMB config smb.ini not found, using defaults\n" );
            break;
        }

        // Valid format for the file means tree tokens pre read, '='
        // is the middle token, and EOF not received
        num = fscanf( configFile, "%s %s %s", utilReadToken,
                                              utilReadEquals,
                                              utilReadValue );
        formatIsValid = num == 3 && utilReadEquals[0] == '=';

        while( num != EOF && formatIsValid )
        {
            // logIsEnabled
            if( !strcmp( utilReadToken, "logIsEnabled") )
            {
                if(    !strcmp(utilReadValue, "true")
                    || !strcmp(utilReadValue, "1") )
                {
                    //printf("setting true\n");
                    logIsEnabled = true;
                }
                else if(    !strcmp(utilReadValue, "false")
                         || !strcmp(utilReadValue, "0") )
                {
                    //printf("setting false\n");
                    logIsEnabled = false;
                }
                else
                {
                    formatIsValid = false;
                    break;
                }
            }

            // logToStdout
            if( !strcmp( utilReadToken, "logToStdout") )
            {
                if(    !strcmp(utilReadValue, "true")
                    || !strcmp(utilReadValue, "1") )
                {
                    //printf("setting true\n");
                    logToStdout = true;
                }
                else if(    !strcmp(utilReadValue, "false")
                         || !strcmp(utilReadValue, "0") )
                {
                    //printf("setting false\n");
                    logToStdout = false;
                }
                else
                {
                    formatIsValid = false;
                    break;
                }
            }

            // pidMidPerSsnLimit
            if( !strcmp( utilReadToken, "pidMidPerSsnLimit") )
            {
                tz_uint32 lim = strtoul( utilReadValue, NULL, 0 );

                var[0] = lim;
                var[1] = (tz_uint64)-1;  // no change
                nmd->NetmonThreadIterate( PROTOCOL_SMB,
                                          SmbIteratorSetPidMidVars,
                                          var );
            }

            // pidMidAgeTimeout (float value, specified in sec.)
            if( !strcmp( utilReadToken, "pidMidAgeTimeout") )
            {
                double to = strtod( utilReadValue, NULL );

                var[0] = (tz_uint64)-1;  // no change
                var[1] = (tz_uint64)(to * nmd->cyclesPerSecond);
                nmd->NetmonThreadIterate( PROTOCOL_SMB,
                                          SmbIteratorSetPidMidVars,
                                          var );
            }

            num = fscanf( configFile, "%s %s %s", utilReadToken,
                                                  utilReadEquals,
                                                  utilReadValue );
            if( num == EOF )
            {
                lc_log_basic(LOG_NOTICE,"SMB config smb.ini found and "
                         "is valid, setting debug parameters\n");
                break;
            }
            formatIsValid = num == 3 && utilReadEquals[0] == '=';
        }

    } while (0);

    if( configFile != (FILE *)NULL )
    {
        fclose( configFile );
    }
}


