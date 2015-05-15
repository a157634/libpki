/* Socket Wrapping functions */
/* OpenCA libpki package
 * Copyright (c) 2000-2009 by Massimiliano Pala and OpenCA Group
 * All Rights Reserved
 *
 * ===================================================================
 * Released under OpenCA LICENSE
 */

#include <libpki/pki.h>

#define	LISTENQ		30

extern int h_errno;

/* ---------------------------- Internal Functions ---------------------- */

int _Socket (int family, int type, int protocol) {
	int n;
	char err_str[128];

	if ( (n = socket(family,type,protocol)) < 0)
	{
		PKI_strerror ( errno, err_str, sizeof(err_str));
		PKI_log( PKI_LOG_ERR, "Can not initialize socket: [%d] %s", errno, err_str);
	}

	return n;
}

#pragma GCC diagnostic ignored "-Wconversion" 
int _Listen (char *hostname, int port, PKI_NET_SOCK_TYPE type) {

	int fd = 0;
	int reuse_addr = 1;
	int ret = 0;
	char err_str[128];

	struct addrinfo *res, *rp;
	struct addrinfo hints;

	// struct sockaddr_storage servaddr;

	char service[10];

	/* create socket */
	memset(&hints, 0, sizeof(struct addrinfo));
	hints.ai_family = AF_UNSPEC;
	hints.ai_flags = AI_PASSIVE;
	hints.ai_socktype = type;
	hints.ai_canonname = NULL;
	hints.ai_addr = NULL;
	hints.ai_next = NULL;

	/* If we want a datagram listener, we switch to UDP */
	switch (hints.ai_socktype)
	{
		case PKI_NET_SOCK_DGRAM:
			hints.ai_protocol = IPPROTO_UDP;
			break;
		
		default:
			hints.ai_protocol = 0;
	}

	snprintf( service, sizeof(service)-1, "%d", port );

	if((ret = getaddrinfo( hostname, service, &hints, &res)) != 0 ) {
		PKI_log_err("Can not parse hostname (err: %d)", ret);
		return ( -1 );
	}

	for ( rp = res; rp != NULL; rp = rp->ai_next ) {
		if((fd = _Socket( rp->ai_family, rp->ai_socktype, 
				rp->ai_protocol)) == -1 ) {
			continue;
		}

		if(setsockopt(fd, SOL_SOCKET,  SO_REUSEADDR,  &reuse_addr, 
					sizeof(reuse_addr)) == -1 ) {
			PKI_strerror ( errno, err_str, sizeof(err_str));
			PKI_log( PKI_LOG_ERR, "Can not set socket option (SO_REUSEADDR): [%d] %s", errno, err_str);
			close(fd);
			continue;
		}

		// Successfully Binded
		break;
	}

	if ( rp == NULL ) {
		freeaddrinfo ( res );
		close ( fd );
		return ( -1 );
	}

	if (bind(fd, rp->ai_addr, rp->ai_addrlen) == -1 )
	{
		PKI_strerror ( errno, err_str, sizeof(err_str));
		PKI_log_err("Can not bind to %s:%d [%d] %s", hostname, port, errno, err_str);
		close ( fd );
		freeaddrinfo ( res );
		return ( -1 );
	};

	freeaddrinfo ( res );

	/* If a DGRAM is used, no need to listen */
	if (type == PKI_NET_SOCK_DGRAM) return fd;

	/* Here we listen on the fd */
	if (listen(fd, LISTENQ) == -1)
	{
		PKI_strerror ( errno, err_str, sizeof(err_str));
		PKI_log_err("Can not listen to socket: [%d] %s", errno, err_str);
		close ( fd );
		return(-1);
	}

	return ( fd );

}
#ifdef HAVE_GCC_PRAGMA_POP
# pragma GCC diagnostic pop
#endif

/*
#pragma GCC diagnostic error "-Wconversion" 

int _Accept (int listen_sockfd, struct sockaddr * cliaddr,
					socklen_t *addrlenp) {

	int n;
	struct sockaddr addr;
	socklen_t len;

again:

	if( !cliaddr || !addrlenp ) {
		len=sizeof(addr);
		n = accept(listen_sockfd, &addr, &len);
	} else {
		n = accept(listen_sockfd, cliaddr, addrlenp);
	}
		
	if ( n < 0) {
		if (INTERRUPTED_BY_SIGNAL)
			goto again;

		PKI_strerror ( errno, err_str, sizeof(err_str));
		PKI_log(PKI_LOG_ERR,"Error while (ACCEPT): [%d] %s]", errno, err_str);
	}
	return(n);
}
*/

ssize_t _Read (int fd, void *bufptr, size_t nbytes) {

	ssize_t n;
	char err_str[128];

again:
	if ((n = read(fd,bufptr,nbytes)) < 0)
	{
		if (INTERRUPTED_BY_SIGNAL)
		{
			goto again;
		}
		else
		{
			PKI_strerror ( errno, err_str, sizeof(err_str));
			PKI_log(PKI_LOG_ERR, "Socket read failed [%d:%s]", errno, err_str);
		}
	}
	return(n);
}

ssize_t _Write (int fd, void *bufptr, size_t nbytes) {

	ssize_t n;
	char err_str[128];

again:
	if ((n = write(fd,bufptr,nbytes)) < 0)
	{
		if (INTERRUPTED_BY_SIGNAL)
		{
			goto again;
		}
		else
		{
			PKI_strerror ( errno, err_str, sizeof(err_str));
			PKI_log_err( "Socket write failed [%d:%s]!", errno, err_str);
		}
	}
	return(n);
}

int _Select (int maxfdp1, fd_set *readset, fd_set *writeset, 
			fd_set *exceptset, struct timeval *timeout)
{
	int n;
	char err_str[128];

again:
	if ( (n = select (maxfdp1, readset, writeset, 
				exceptset, timeout)) < 0)
	{
		if (INTERRUPTED_BY_SIGNAL)
			goto again;
		PKI_strerror ( errno, err_str, sizeof(err_str));
		PKI_log( PKI_LOG_ERR, "Select failed: [%d] %s", errno, err_str);
	}
	return(n);
}

int _Connect (int sockfd, const SA *srvaddr, socklen_t addrlen)
{
	char err_str[128];

	if (connect(sockfd, srvaddr, addrlen) != 0)
	{
		PKI_strerror ( errno, err_str, sizeof(err_str));
		PKI_log(PKI_LOG_ERR, "Socket connect failed: [%d] %s", errno, err_str);
		return(PKI_ERR);
	}
	return ( PKI_OK );
}


int _Close (int fd)
{
	char err_str[128];

	if (close(fd) != 0)
	{
		PKI_strerror ( errno, err_str, sizeof(err_str));
		PKI_log(PKI_LOG_ERR, "Socket close failed: [%d] %s", errno, err_str);
		return(0);
	}
	return( 1 );
}


void _Shutdown (int fd, int howto)
{
	char err_str[128];

	if (shutdown(fd,howto) != 0)
	{
		PKI_strerror ( errno, err_str, sizeof(err_str));
		PKI_log(PKI_LOG_ERR, "Socket Shutdown failed: [%d] %s)", errno, err_str);
	}

	return;
}

struct hostent *Gethostbyname (const char *hostname) {

	struct hostent *hp = NULL;

	if( !hostname ) return NULL;
	if ((hp = gethostbyname(hostname)) == NULL)
		PKI_log( PKI_LOG_ERR, "Socket gethostbyname() failed for "
			"[%s]: %s", hostname, hstrerror(h_errno));
	return hp;
}

#pragma GCC diagnostic ignored "-Wconversion" 
int inet_connect ( URL *url ) {

	int sockfd;
	int ret = 0;
	char err_str[128];

	struct addrinfo *res, *rp;
	struct addrinfo hints;

	char service[10];

	/* create socket */
	memset(&hints, 0, sizeof( struct addrinfo ));
	hints.ai_family = AF_UNSPEC;
	hints.ai_flags = AI_PASSIVE;
	hints.ai_protocol = IPPROTO_TCP;
	hints.ai_canonname = NULL;
	hints.ai_addr = NULL;
	hints.ai_next = NULL;

	snprintf( service, sizeof(service)-1, "%d", url->port );

	if((ret = getaddrinfo( url->addr, service, &hints, &res)) != 0 ) {
		PKI_log_err("Can not parse hostname (err: %d)", ret);
		return ( -1 );
	}

	for ( rp = res; rp != NULL; rp = rp->ai_next ) {
		if((sockfd = _Socket( rp->ai_family, rp->ai_socktype, 
				rp->ai_protocol)) == -1 ) {
			continue;
		}
		break;
	}

	if ( rp == NULL ) {
		PKI_log_err ( "Can not create socket");
		freeaddrinfo ( res );
		return ( -1 );
	}

	/* try to connect */
	if(( ret = _Connect(sockfd, rp->ai_addr, rp->ai_addrlen )) == PKI_ERR ) {
		PKI_strerror ( errno, err_str, sizeof(err_str));
		PKI_log( PKI_LOG_ERR, "Socket _Connect failed: [%d] %s", errno, err_str);

		_Close ( sockfd );
		freeaddrinfo ( res );
		return(-1);
	}

	freeaddrinfo( res );

	PKI_log_debug( "Connection Successful to %s:%d", 
					url->addr, url->port );

	return ( sockfd );
}
#ifdef HAVE_GCC_PRAGMA_POP
# pragma GCC diagnostic pop
#endif


#pragma GCC diagnostic error "-Wconversion" 
int inet_close ( int fd )
{
	return _Close( fd );
}
#ifdef HAVE_GCC_PRAGMA_POP
# pragma GCC diagnostic pop
#endif

/* ----------------------------- Public Functions ----------------------- */

/*! \brief Returns a reference to a new socket (int) */

int PKI_NET_socket ( int family, int type, int protocol ) {
	return _Socket( family, type, protocol );
}

/*! \brief Returns a reference to a listen socket */
int PKI_NET_listen ( char *host, int port, PKI_NET_SOCK_TYPE type ) {
	int sock = -1;

	sock = _Listen ( host, port, type );
	if ( sock < 0 )
	{
		return PKI_ERR;
	};

	return sock;
}

#pragma GCC diagnostic ignored "-Wsign-conversion"
/*! \brief Returns the connected socket as a result of an Accept */
int PKI_NET_accept ( int sock, int timeout ) {

	int n;
	struct sockaddr addr;
	socklen_t len;

	// Timeout Support Values
	struct timeval  time_out;
	struct timeval *time_out_pnt = NULL;
	fd_set          readset;
	int             sel_ret;
	char            err_str[128];

	// Initialization
	len=sizeof( struct sockaddr );

	// Set the nonblocking status
	if (fcntl(sock, F_SETFL, O_NONBLOCK) < 0) {
		PKI_strerror ( errno, err_str, sizeof(err_str));
		PKI_log_err("PKI_NET_accept()::Cannot set non-blocking socket: [%d] %s", errno, err_str);
		return -1;
	}

	// Loop on the Accept
	for (;;) {

		/* Add the socket to the read set */
		FD_ZERO( &readset );
		FD_SET ( sock, &readset);

		// We need to update the values every time as select can
		// change them
		if ( timeout <= 0 ) {
			time_out_pnt = NULL;
		} else {
			time_out_pnt = &time_out;
			time_out.tv_sec = timeout;
        		time_out.tv_usec = 0;
		};

		sel_ret = select(sock+1, &readset, NULL, NULL, time_out_pnt);

		if (sel_ret < 0) {
			PKI_strerror ( errno, err_str, sizeof(err_str));
			if(errno == EINTR) {
				PKI_log_debug("Select failed (recoverable): [%d] %s", errno, err_str);
				continue;
			} else {
				PKI_log_debug("Select failed: [%d] %s", errno, err_str);
				return -1;
			}
		}

		if( (timeout > 0 ) && ( sel_ret == 0 ) ) {
			PKI_log_err("socket connection timed out after %d seconds", timeout);
			return -1;
		};
 
		if (FD_ISSET (sock, &readset))
		{
			n = accept(sock, &addr, &len);
		
			if ( n < 0) {
				if (INTERRUPTED_BY_SIGNAL) {
					continue;
				};

				PKI_strerror ( errno, err_str, sizeof(err_str));
				PKI_log(PKI_LOG_ERR, "Error while (ACCEPT): [%d] %s]", errno, err_str);
			}
			break;
		}
  	}
	return(n);
}
#ifdef HAVE_GCC_PRAGMA_POP
# pragma GCC diagnostic pop
#endif

/*! \brief Connects to an host and returns the connected socket */
int PKI_NET_open ( URL *url, int timeout ) {
	return inet_connect ( url );
}

/*! \brief Closes the connection to an open connection to an host */
int PKI_NET_close ( int sock ) {
	return inet_close ( sock );
}

/*! \brief Writes n bytes of data to a socket */
ssize_t PKI_NET_write (int fd, void *bufptr, size_t nbytes) {
	return _Write( fd, bufptr, nbytes );
}

/*! \brief Reads n-bytes of data from a socket */
#pragma GCC diagnostic ignored "-Wsign-conversion"
ssize_t PKI_NET_read (int fd, void *bufptr, size_t nbytes, int timeout ) {

	ssize_t n = 0;

	// Timeout Support Values
	struct timeval  time_out;
	struct timeval *time_out_pnt = NULL;
	fd_set          readset;
	int             sel_ret;
	char            err_str[128];
	
	if (fcntl( fd, F_SETFL, O_NONBLOCK) < 0) {
		PKI_strerror ( errno, err_str, sizeof(err_str));
		PKI_log_err("PKI_NET_read()::Cannot set non-blocking socket: [%d] %s", errno, err_str);
		return -1;
	}

	for (;; ) {
		/* Add the socket to the read set */
		FD_ZERO( &readset );
		FD_SET ( fd, &readset);

		// We need to update the values every time as select can
		// change them
		if ( timeout <= 0 ) {
			time_out_pnt = NULL;
		} else {
			time_out_pnt = &time_out;
			time_out.tv_sec = timeout;
        		time_out.tv_usec = 0;
		};

		sel_ret = select(fd+1, &readset, NULL, NULL, time_out_pnt);

		if (sel_ret < 0) {
			PKI_strerror ( errno, err_str, sizeof(err_str));
			if(errno == EINTR) {
				PKI_log_debug("Select failed (recoverable): [%d] %s", errno, err_str);
				continue;
			} else {
				PKI_log_debug("Select failed: [%d] %s", errno, err_str);
				return -1;
			}
		}

		if( (timeout > 0 ) && (sel_ret == 0) ) {
			PKI_log_err("PKI_NET_read::socket connection timed out after %d seconds", timeout);
			return -1;
		}

		if (FD_ISSET (fd, &readset)) {
			if((n = recv(fd, bufptr, nbytes, 0 )) == 0 ) {
				break;
			};

			if (n < 0) {
				if( errno == EWOULDBLOCK ) {
					PKI_log_debug("Network error, EWOULDBLOCK");
					continue;
				}
				PKI_strerror ( errno, err_str, sizeof(err_str));
				PKI_log_err("PKI_NET_read::recv() failed: [%d] %s", errno, err_str);
				break;
			} else {
				//PKI_log_debug("Read %d bytes from socket", n);
			};

			break;
		}
	}

	return n;
}

#ifdef HAVE_GCC_PRAGMA_POP
# pragma GCC diagnostic pop
#endif

/*! \brief Returns data read from a socket */
PKI_MEM *PKI_NET_get_data ( int fd, int timeout, size_t max_size ) {

	PKI_MEM *buf = NULL;

	char tmp_buff[BUFF_MAX_SIZE];
	ssize_t newsize  = 0;

	if( fd < 1 ) {
		PKI_log_err("Attempted to retrieve data from sock %d", fd );
		return NULL;
	}

	/* get subject name from bio using recommended OpenSSL template */
	if((buf = PKI_MEM_new_null()) == NULL ) {
		PKI_log_err( "Memory Failure" );
		return ( NULL );
	}

	while( (newsize = PKI_NET_read( fd, tmp_buff, sizeof(tmp_buff), 
							timeout )) != 0 ) {

		if( newsize < 0 ) {
			PKI_log_err("Network Error: %s", strerror(errno));
			break;
		}

		if( (max_size > 0) && 
				((ssize_t)(buf->size) + newsize > max_size) ) {
			newsize = (ssize_t) (max_size - buf->size);
			PKI_MEM_add( buf, tmp_buff, (size_t) newsize);
			break;
		};

		PKI_MEM_add ( buf, tmp_buff, (size_t) newsize );

	};

	if( buf->size <= 0 ) {
		PKI_log_debug("WARNING::No HTTP data retrieved.");

		if( buf ) PKI_MEM_free ( buf );
		buf = NULL;
	}

	return ( buf );
}

/*! \brief Gets a DGRAM packet */
ssize_t PKI_NET_recvfrom (int fd, void *bufptr, size_t nbytes, 
	struct sockaddr_in *cli, socklen_t cli_len)
{
	ssize_t rv = 0;
	struct sockaddr_in cli_addr;
	socklen_t slen = sizeof(cli_addr);

	if (!bufptr || nbytes <= 0) return 0;

	if (cli && cli_len > 0)
	{
		rv = recvfrom(fd, bufptr, nbytes, 0, (struct sockaddr *)cli, &cli_len);
		PKI_log_debug("[DNS] Packet from %s:%d", 
			inet_ntoa(cli->sin_addr), ntohl(cli->sin_port));
	}
	else
	{
		rv = recvfrom(fd, bufptr, nbytes, 0, (struct sockaddr *)&cli_addr, &slen);
		PKI_log_debug("[DNS] Packet from %s:%d", 
			inet_ntoa(cli_addr.sin_addr), ntohl(cli_addr.sin_port));
	}

	if (rv == -1)
	{
		PKI_log_debug("[DNS] Error getting the packet!");
		return -1;
	}

	return rv;
}

/*!\brief Sends a datagram to a host */
ssize_t PKI_NET_sendto (int sock, char *host, int port, void *data, size_t len)
{
	ssize_t ret = 0;

	// Check the input
	if (!host || port < 0 || port > 65535) return -1;

	// Create a new datagram socket
	if (sock < 0)
	{
		if ((sock = PKI_NET_socket(PF_INET, PKI_NET_SOCK_DGRAM, 0)) <= 0)
			return -1;
	}

	// Setup the Server socket
	struct sockaddr_in serv;
	socklen_t slen = sizeof(serv);
	memset(&serv, 0, sizeof(struct sockaddr_in));
	serv.sin_family = AF_INET;

	/*
	// Set the origin
	if (from || from_port > 0)
	{
		if (from)
		{
			if (inet_aton(from, &serv.sin_addr) == -1)
			{
				PKI_log_err("ERROR: Can not convert address (%s)", from);
				return -1;
			}
		}
		else
		{
			serv.sin_addr.s_addr = INADDR_ANY;
		}
		serv.sin_port = htons(from_port);
		if (bind(sock, (struct sockaddr *) &serv, sizeof(struct sockaddr_in)) == -1 )
		{
			PKI_log_err("ERROR: Can not bind to port %d", from_port);
			return -1;
		}
	}
	*/

	// Set the destination
	serv.sin_port = (in_port_t) htonl((uint32_t) port);
	if (inet_aton(host, &serv.sin_addr) == -1)
	{
		PKI_log_err("ERROR: Can not convert destination address (%s)", host);
		return -1;
	}

	// Sends the data
	ret = sendto(sock, data, len, 0, (struct sockaddr*) &serv, slen);

	// Check the return value
	if (ret == -1) PKI_log_debug("ERROR: Can not send DGRAM packet (%d)", h_errno);

	return ret;
}
