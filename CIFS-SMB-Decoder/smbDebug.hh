//-----------------------------------------------------------------------
//   Copyright (c) <2005> by Tizor Systems. 
//   All Rights Reserved.
//   Licensed Material - Property of Tizor Systems.
//
//   File: smbEncEngFormat.cc
// 
//   Component: SMB Protocol Encoding Engine Formatter
//
//              The Encoding Engine Formatter provides a service to
//              the SMB protocol decoder.  It creates dimensions to be
//              passed up to the Encoding Engine and offers formatting
//              functions to allow SMB to create events and a push
//              function to actually send the event up.  All the gory
//              and necessary details to make this happen are hidden
//              inside this class.
//-----------------------------------------------------------------------

#ifndef _SMB_DEBUG_H
#define _SMB_DEBUG_H

#define SMB_DEBUG_LOG_ENTRIES   (1 + 2)  // was 4096 + 2
#define SMB_DEBUG_LOG_LINESIZE     512

#define SMB_DEBUG_CMDPARMS         16
#define SMB_DEBUG_CMDPARMSIZE      64

//
// SMB Internal Log, used for looking at traces of decoded SMB when
// enabled.  The output can go to either stdout, a file, or both.
//
#define SmbIntLog(format, ...)                                          \
    do                                                                  \
    {                                                                   \
        if( SmbDebug::logIsEnabled )                                    \
        {                                                               \
            SmbDebug::logLineAppend(format, ## __VA_ARGS__);            \
        }                                                               \
    } while (0)


class SmbDebug
{
public:

  // -- Public Functions --
  static void process( char *cmdStg );
  static void utilReadIni( void );

  // Debug log access/control
  static void logInit( void );
  static void logLineAppend( const tz_int8 *format, ... );
  static void logLinePut( void );
  static bool logLineGet( tz_int8 **line );

  // -- Public Data --
  static tz_uint32 logIsEnabled;
  static tz_uint32 monIsEnabled;
  static tz_uint32 logToStdout;

  static tz_uint32 logToFile;
  static FILE     *logFile;


private:

  // -- Private Functions --
  static void displaySmbInfo( SessionEntry &sessionEntry );

  // Debug command handlers
  static bool dbgHandleLog( void );
  static bool dbgHandleShow( void );
  static bool dbgHandleShowData( void );
  static bool dbgHandleShowConfig( void );
  static bool dbgHandleFilt( void );
  static bool dbgHandleMon( void );
  static bool dbgHandleDefLogin( void );
  static bool dbgHandleShowDefLogin( void );
  static bool dbgHandleFileshare( void );
  static bool dbgHandleCap( void );
  static bool dbgHandlePipe( void );

  // -- Private Data --
  tz_int8 outStg[TZX_512_STRING];

  // Command line parameters
  static tz_int8 intCmdStg[TZX_512_STRING];
  static int     argc;
  static char    argv[][SMB_DEBUG_CMDPARMSIZE];

  // Debug log data storage
  static tz_int8 logBuf[][SMB_DEBUG_LOG_LINESIZE];

  static tz_uint32  logHead;   // insert here
  static tz_uint32  logTail;   // remove here

  static tz_int8   *appendPtr;
  static tz_uint32  appendCnt;

  // Debug config init file
  static tz_int8 utilReadToken[TZX_64_STRING];
  static tz_int8 utilReadEquals[TZX_64_STRING];
  static tz_int8 utilReadValue[TZX_64_STRING];
  static tz_int8 utilRead2Value[TZX_64_STRING];

  // Pipe command file
  static FILE     *pipeCmdFile;
  static int       pipeCap1File;
  static int       pipeCap2File;
  static tz_uint8 *pipePktData;

};

#endif /* _SMB_DEBUG_H */

