/* PKI ERR Management Functions */

#define __LIBPKI_ERR__

#include <libpki/pki.h>

/* Private variables */
// static int pki_err = PKI_OK;
// static char *pki_errval;

/* Externally accessible variable */
// char ext_pki_errval[1024];

/* ERR Stack Mutex */
// static pthread_mutex_t err_mutex = PTHREAD_MUTEX_INITIALIZER;
// static pthread_cond_t err_cond;

/* Pointer to the Error Stack */
PKI_STACK *pki_err_stack = NULL;

// static int _set_pki_errval (int err);
// static char * _get_pki_errval (int err);

/*!
 * \brief Set and logs library errors
 */
#pragma GCC diagnostic ignored "-Wuninitialized"
int __pki_error ( const char *file, int line, int err, const char *info, ... ) {
 
	int i, found;
	PKI_ERR_ST *curr = NULL;
	//char fmt[2048];

	//va_list ap;

	found = -1;
	for ( i = 0; i < __libpki_err_size ; i++ ) 
	{
		curr = (PKI_ERR_ST *) &__libpki_errors_st[i];

		if ( ( curr ) && ( curr->code == err ) ) 
		{
			found = i;
			if ( !curr->descr ) break;

			if ( info == NULL )
			{
				PKI_log_err_simple( "[%s:%d] %s", file, line, curr->descr );
			} 
			else 
			{
				// remove comment: why don't leave it as it was in the previous release?
				// <ap> is used uninitialized here!!!
				PKI_log_err_simple( "[%s:%d] %s => %s", file, line, curr->descr, info );
				//snprintf(fmt, sizeof(fmt), "[%s:%d] %s => %s", file, line, curr->descr, info );
				//PKI_log_err_simple( fmt, ap);
			}

			break;
		}
	}

	if ( found < 0 ) err = PKI_ERR_UNKNOWN;

	return ( PKI_ERR );
}

#ifdef HAVE_GCC_PRAGMA_POP
# pragma GCC diagnostic pop
#endif

void PKI_strerror(int errnum, char *buf, size_t buflen)
{
	if(!buf || buflen <= 0)
		return;

#if (_POSIX_C_SOURCE >= 200112L || _XOPEN_SOURCE >= 600) && ! _GNU_SOURCE
	{
		int _errno = errno;

		/* POSIX variant */
		if (strerror_r(errnum, buf, buflen) != 0)
		{
			errno = _errno;
			if(buflen >= 4)
				strncpy(buf, "n/a", buflen);
			else
				buf[0] = '\0';
		}
	}
#else
	{
		char *err_str;

		/* GNU libc strerror_r is non-portable. */
		err_str = strerror_r(errnum, buf, buflen);
		if (err_str != buf)
		{
			strncpy(buf, err_str, buflen);
			buf[buflen - 1] = '\0';
		}
	}
#endif
}

