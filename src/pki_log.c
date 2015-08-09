/* OpenCA libpki package
* (c) 2000-2007 by Massimiliano Pala and OpenCA Group
* All Rights Reserved
*
* ===================================================================
* Released under OpenCA LICENSE
*/

#include <syslog.h>
#include <stdarg.h>

#include <pki.h>

#pragma GCC diagnostic ignored "-Wunused-function"

/* Log Configuration Mutex */
static pthread_mutex_t log_mutex = PTHREAD_MUTEX_INITIALIZER;
static pthread_cond_t log_cond;

/* Log resource usage Mutex */
static pthread_mutex_t log_res_mutex = PTHREAD_MUTEX_INITIALIZER;
static pthread_cond_t log_res_cond;

/* Local function prototypes */
static int _pki_syslog_init( PKI_LOG *l );
static int _pki_stdout_init( PKI_LOG *l );
static int _pki_stderr_init( PKI_LOG *l );
static int _pki_file_init( PKI_LOG *l );

static void _pki_syslog_add( int, const char *fmt, va_list ap );
static void _pki_stdout_add( int, const char *fmt, va_list ap );
static void _pki_stderr_add( int, const char *fmt, va_list ap );
static void _pki_file_add( int, const char *fmt, va_list ap );

static int _pki_syslog_finalize( PKI_LOG *l );
static int _pki_stdout_finalize( PKI_LOG *l );
static int _pki_stderr_finalize( PKI_LOG *l );
static int _pki_file_finalize( PKI_LOG *l );

static int _pki_syslog_entry_sign( PKI_LOG *l, char *entry );
static int _pki_stdout_entry_sign( PKI_LOG *l, char *entry );
static int _pki_file_entry_sign( PKI_LOG *l, char *entry );

/* Log Static Variable */
static PKI_LOG _log_st = {
	/* Keep track if the LOG subsystem has undergone initialization */
	0,

	/* Type of PKI_LOG - PKI_LOG_TYPE */
	PKI_LOG_TYPE_SYSLOG,

	/* Identifier of the resource */
	NULL,

	/* Log Level - one of PKI_LOG_LEVEL */
	PKI_LOG_ERR,

	/* Enable Debuging Infos in the Log */
	0,

	/* PKI_TOKEN - if present it enables Signed Logging */
	NULL,

	/* Init Callback Pointer */
	_pki_syslog_init,

	/* Add Callback Pointer */
	_pki_syslog_add,

	/* Finalize Callback Pointer */
	_pki_syslog_finalize,

	/* Sign Callback Pointer */
	_pki_syslog_entry_sign,
};

/*!
 * \brief Initialize the log subsystem 
*/

int PKI_log_init ( PKI_LOG_TYPE type, PKI_LOG_LEVEL level, char *resource,
				PKI_LOG_FLAGS flags, PKI_TOKEN *tk ) {
	
	int ret = PKI_OK;

	PKI_init_all();

	/* We should acquire both the log and log_res mutex to
	   prevent bad programmers to mess with threads and logging */
	pthread_mutex_lock( &log_res_mutex );
	pthread_mutex_lock( &log_mutex );

	_log_st.type  = type;
	_log_st.level = level;

	if( _log_st.resource != NULL ) {
		PKI_Free( _log_st.resource );
		_log_st.resource = NULL;
	}

	if( resource ) {
		_log_st.resource = strdup( resource );
	} else {
		_log_st.resource = NULL;
	}

	_log_st.flags = flags;

	/* Check consistency between the token and the signature flag */
	if( tk ) {
		_log_st.tk = tk;

		/* It does not make sense not enabling the signature
		   when passing the token! */
		if( ! (flags & PKI_LOG_FLAGS_ENABLE_SIGNATURE )) {
			PKI_log_err ( "Token configured for logs but no "
					"signature flag set in init!");
			ret = PKI_ERR;
			goto err;
		}
	} else {
		/* Again, no sense enabling signatures without passing
		   the token! */
		if( flags & PKI_LOG_FLAGS_ENABLE_SIGNATURE ) {
			PKI_log_err ( "Log signing enabled but no token is "
					"configured for signing logs in init!");
			ret = PKI_ERR;
			goto err;
		}
	}

	/* Let's use different functions for different log types */
	switch ( type ) {
		case PKI_LOG_TYPE_SYSLOG:
			_log_st.init = _pki_syslog_init;
			_log_st.add = _pki_syslog_add;
			_log_st.finalize = _pki_syslog_finalize;
			break;
		case PKI_LOG_TYPE_STDOUT:
			_log_st.init = _pki_stdout_init;
			_log_st.add = _pki_stdout_add;
			_log_st.finalize = _pki_stdout_finalize;
			break;
		case PKI_LOG_TYPE_STDERR:
			_log_st.init = _pki_stderr_init;
			_log_st.add = _pki_stderr_add;
			_log_st.finalize = _pki_stderr_finalize;
			break;
		case PKI_LOG_TYPE_FILE:
			_log_st.init = _pki_file_init;
			_log_st.add = _pki_file_add;
			_log_st.finalize = _pki_file_finalize;
			break;
		case PKI_LOG_TYPE_FILE_XML:
		default:
			ret = PKI_ERR;
			goto err;
	}

	if ( _log_st.init ) {
		ret = _log_st.init( & _log_st );
	}

err:
	pthread_cond_signal ( &log_cond );
	pthread_mutex_unlock( &log_mutex );

	pthread_cond_signal ( &log_res_cond );
	pthread_mutex_unlock( &log_res_mutex );

	return (ret);
}

/*!
 * \brief Finalize the log subsystem
 */

int PKI_log_end( void )
{
	int ret = PKI_OK;

	/* We should acquire both the log and log_res mutex */
	pthread_mutex_lock( &log_res_mutex );

	/* Let's wait for the log_mutex */
	pthread_mutex_lock( &log_mutex );

	if ( _log_st.finalize) 
		ret = _log_st.finalize ( & _log_st );
	else
		ret = PKI_OK;

	pthread_cond_signal ( &log_cond );
	pthread_mutex_unlock( &log_mutex );

	pthread_cond_signal ( &log_res_cond );
	pthread_mutex_unlock( &log_res_mutex );

	return ret;
}

/*! \brief Add an entry in the log */

void PKI_log( int level, const char *fmt, ... ) {

	va_list ap;

	if( (_log_st.add) && ((level == PKI_LOG_ALWAYS) ||
			((level > PKI_LOG_NONE) && (level <= _log_st.level))) ) {

		pthread_mutex_lock( &log_res_mutex );
		va_start (ap, fmt);
			_log_st.add( level, fmt, ap );
		va_end (ap);

		pthread_mutex_unlock( &log_res_mutex );
		pthread_cond_signal ( &log_res_cond );
	}

	return;
}

/*! \brief Add an hex dump in the Debug log */

void PKI_log_hexdump(int level, char *p_txt, int len, void *p_data)
{
    int     a;
    char    *x;
    char    *dt;
    int     adr=0;
    char    buff1[40];
    char    buff2[20];
    static  char    hex[]="0123456789abcdef";


    if(level == PKI_LOG_DEBUG && (_log_st.flags & PKI_LOG_FLAGS_ENABLE_DEBUG) == 0 )
      return;

    if(p_txt != NULL) PKI_log(level, "%s:\n", p_txt);
    dt=(char *)p_data;
    while(len>0) {
        x=buff1;
        for(a=0;a<16 && a<len;a++) {
            if((a&3)==0) *x++ = ' ';
            if((a&7)==0) *x++ = ' ';
            *x++ = hex[(dt[a]>>4)&15];
            *x++ = hex[dt[a]&15];
        }
        *x=0;
        x=buff2;
        for(a=0;a<16 && a<len;a++) {
          if(dt[a]>' ' && dt[a]<0x7f)
            *x++ = dt[a];
          else
            *x++ = ' ';
        }
        *x=0;
        PKI_log(level, "%6x%-38s |%-16s|\n", adr, buff1, buff2);
        len-=16;
        dt+=16;
        adr+=16;
    }
}

/*! \brief Add an entry in the Debug log */

void PKI_log_debug_simple( const char *fmt, ... ) {

	va_list ap;
	unsigned int rv = 0;

	if((rv = _log_st.flags & PKI_LOG_FLAGS_ENABLE_DEBUG) == 0 ) {
		return;
	}

	pthread_mutex_lock( &log_res_mutex );

	va_start (ap, fmt);
	if( _log_st.add ) _log_st.add ( PKI_LOG_DEBUG, fmt, ap );
	va_end (ap);

	pthread_mutex_unlock( &log_res_mutex );
	pthread_cond_signal ( &log_res_cond );

	return;
}

/*! \brief Add an entry in the Debug log */

void PKI_log_err_simple( const char *fmt, ... ) {

	va_list ap;

	pthread_mutex_lock( &log_res_mutex );

	va_start (ap, fmt);
	if( _log_st.add ) _log_st.add ( PKI_LOG_ERR, fmt, ap );
	va_end (ap);

	pthread_mutex_unlock( &log_res_mutex );
	pthread_cond_signal ( &log_res_cond );

	return;
}

/* ===================== Init Callbacks Functions ===================== */

static int _pki_syslog_init( PKI_LOG *l ) {

	int ret = PKI_OK;

	openlog( l->resource, LOG_PID, LOG_USER );

	if( !l ) return ( PKI_ERR );

	return ( ret );
}

static int _pki_stdout_init( PKI_LOG *l ) {

	int ret = PKI_OK;

	if( !l ) return ( PKI_ERR );

	/* Actually not much to do here... */

	return ( ret );
}

static int _pki_stderr_init( PKI_LOG *l ) {

	int ret = PKI_OK;

	if( !l ) return ( PKI_ERR );

	/* Actually not much to do here... */

	return ( ret );
}

static int _pki_file_init( PKI_LOG *l ) {

	int ret = PKI_OK;
	int fd = 0;

	if( !l ) return ( PKI_ERR );

	if( !l->resource ) return ( PKI_ERR );

	if(( fd = open( l->resource, O_RDWR | O_APPEND | O_CREAT, 
					S_IRUSR | S_IWUSR )) == -1 ) {
		/* Error! */
		return( PKI_ERR );
	}

	close ( fd );

	return ( ret );
}

/* ===================== LogAdd Callbacks Functions ===================== */

/* Internal Usage Only! */

static char *_get_info_string( int level ) {

	char *info = NULL;

	switch ( level ) {
		case PKI_LOG_MSG:
			info = "MSG";
			break;
		case PKI_LOG_ERR:
			info = "ERROR";
			break;
		case PKI_LOG_WARNING:
			info = "WARNING";
			break;
		case PKI_LOG_NOTICE:
			info = "NOTICE";
			break;
		case PKI_LOG_INFO:
			info = "INFO";
			break;
		case PKI_LOG_DEBUG:
			info = "DEBUG";
			break;
		default:
			info = "GENERAL";
	}

	return( info );
}

/*! \brief Add an entry in the log 
*/

static void _pki_syslog_add( int level, const char *fmt, va_list ap ) {

	int syslog_level = LOG_WARNING;

	switch ( level ) {
		case PKI_LOG_ERR:
			syslog_level = LOG_ERR;
			break;
		case PKI_LOG_WARNING:
			syslog_level = LOG_WARNING;
			break;
		case PKI_LOG_NOTICE:
			syslog_level = LOG_NOTICE;
			break;
		case PKI_LOG_INFO:
			syslog_level = LOG_INFO;
			break;
		case PKI_LOG_DEBUG:
			syslog_level = LOG_DEBUG;
			break;
		case PKI_LOG_ALWAYS:
			syslog_level = LOG_INFO;
			break;
		default:
			syslog_level = LOG_USER;
	}
	vsyslog( syslog_level, fmt, ap );

	return;
}

static void _pki_stdout_add( int level, const char *fmt, va_list ap ) {

	PKI_TIME *now = NULL;

	now = PKI_TIME_new(0);

	/* Let's print the log entry */
	fprintf ( stdout, "%s [%d] %s: ", 
		PKI_TIME_get_parsed( (PKI_TIME *) now ), 
					getpid(), _get_info_string( level ));
	vfprintf( stdout, fmt, ap );
	fprintf ( stdout, "\n" );

	PKI_TIME_free( now );

	return;
}

static void _pki_stderr_add( int level, const char *fmt, va_list ap ) {

	PKI_TIME *now = NULL;

	now = PKI_TIME_new(0);

	/* Let's print the log entry */
	fprintf ( stderr, "%s [%d] %s: ", 
		PKI_TIME_get_parsed( (PKI_TIME *) now ), 
					getpid(), _get_info_string( level ));
	vfprintf( stderr, fmt, ap );
	fprintf ( stderr, "\n" );

	PKI_TIME_free( now );

	return;
}

static void _pki_file_add( int level, const char *fmt, va_list ap ) {

	int fd = 0;
	FILE *file = NULL;

	PKI_TIME *now = NULL;

	if( ! _log_st.resource ) return;

	if(( fd = open( _log_st.resource, O_RDWR|O_APPEND|O_CREAT,
						S_IRUSR | S_IWUSR )) == -1 ) {
		/* Error! */
		return;
	}

	if(( file = fdopen( fd, "a+")) == NULL ) {
		/* Error!!! */
		fprintf( stderr, "DEBUG::ERROR, can not open log file!\n");
		return;
	}

	now = PKI_TIME_new(0);
	/* Let's print the log entry */
	fprintf ( file, "%s [%d]: %s: ", 
		PKI_TIME_get_parsed( (PKI_TIME *) now ), 
					getpid(), _get_info_string( level ));
	vfprintf( file, fmt, ap );
	fprintf ( file, "\n");
	PKI_TIME_free( now );

	/* Now close the file stream */
	fclose( file );

	/* Do we need to also close the fd ? */
	close ( fd );

	return;
}

/* ===================== Finalize Callbacks Functions =================== */

static int _pki_syslog_finalize( PKI_LOG *l ) {

	closelog();

	return ( PKI_OK );
}

static int _pki_stdout_finalize( PKI_LOG *l ) {

	/* No need to do anything here */
	return ( PKI_ERR );
}

static int _pki_stderr_finalize( PKI_LOG *l ) {

	/* No need to do anything here */
	return ( PKI_ERR );
}

static int _pki_file_finalize ( PKI_LOG *l ) {

	/* Also here, no need for anything special */
	return (PKI_ERR);
}

/* ===================== Entry Sign Callback Functions ================== */

static int _pki_syslog_entry_sign( PKI_LOG *l, char *entry ) {

	/* Function not really implemented */
	return ( PKI_ERR );

}

static int _pki_stdout_entry_sign( PKI_LOG *l, char *entry ) {

	/* Function not really implemented */
	return ( PKI_ERR );

}

static int _pki_stderr_entry_sign( PKI_LOG *l, char *entry ) {

	/* Function not really implemented */
	return ( PKI_ERR );

}

static int _pki_file_entry_sign( PKI_LOG *l, char *entry ) {

	/* Function not really implemented */
	return ( PKI_ERR );

}
