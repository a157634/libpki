/* PKI_X509 object management */

#include <libpki/pki.h>

typedef struct parsed_datatypes_st {
	const char *descr;
	int nid;
} LIBPKI_PARSED_DATATYPES;

struct parsed_datatypes_st __parsed_datatypes[] = {
	/* X509 types */
	{ "Unknown",						PKI_DATATYPE_UNKNOWN },
	{ "Public KeyPair", 				PKI_DATATYPE_X509_KEYPAIR },
	{ "X509 Public Key Certificate", 	PKI_DATATYPE_X509_CERT },
	{ "X509 CRL", 						PKI_DATATYPE_X509_CRL },
	{ "PKCS#10 Certificate Request", 	PKI_DATATYPE_X509_REQ },
	{ "PKCS#7 Message", 				PKI_DATATYPE_X509_PKCS7 },
	{ "PKCS#12 PMI Object", 			PKI_DATATYPE_X509_PKCS12 },
	{ "OCSP Request", 					PKI_DATATYPE_X509_OCSP_REQ },
	{ "OCSP Response", 					PKI_DATATYPE_X509_OCSP_RESP },
	{ "PRQP Request", 					PKI_DATATYPE_X509_PRQP_REQ },
	{ "PRQP Response", 					PKI_DATATYPE_X509_PRQP_RESP },
	{ "Cross Certificate Pair", 		PKI_DATATYPE_X509_XPAIR },
	{ "CMS Message", 					PKI_DATATYPE_X509_CMS_MSG },
	{ NULL, -1 }
};

/*! \brief Returns the callbacks for a specific PKI_DATATYPE */

const PKI_X509_CALLBACKS *PKI_X509_CALLBACKS_get (PKI_DATATYPE type, 
						struct hsm_st *hsm) {

	if ( !hsm ) hsm = (HSM *) HSM_get_default();

	if ( !hsm || !hsm->callbacks || !hsm->callbacks->x509_get_cb )
		return NULL;

	return hsm->callbacks->x509_get_cb ( type );

}

/*! \brief Allocs the memory associated with an empty PKI_X509 object */

PKI_X509 *PKI_X509_new ( PKI_DATATYPE type, struct hsm_st *hsm ) {

	PKI_X509 *ret = NULL;
	const PKI_X509_CALLBACKS *cb = NULL;

	// If no hsm, let's get the default
	if ( !hsm ) hsm = (HSM *) HSM_get_default();

	// Now we need the callbacks for object creation and handling
	if (( cb = PKI_X509_CALLBACKS_get ( type, hsm )) == NULL ) {
		PKI_ERROR(PKI_ERR_CALLBACK_NULL, NULL);
		return NULL;
	}

	// Let's allocate the required memory
	if((ret = PKI_Malloc (sizeof( PKI_X509 ))) == NULL ) {
		PKI_ERROR(PKI_ERR_MEMORY_ALLOC, NULL);
		return NULL;
	}

	// Object Type
	ret->type = type;

	// X509_Callbacks
	ret->cb = cb;

	// URL Reference
	ret->ref = NULL;

	// HSM to use
	ret->hsm = hsm;

	// Crypto provider's specific data structure
	ret->value = NULL;

	return ret;
}

/*! \brief Frees the memory associated with a PKI_X509 object */

void PKI_X509_free_void ( void *x ) {
	PKI_X509_free ( (PKI_X509 *) x );
	return;
}

void PKI_X509_free ( PKI_X509 *x ) {

	if (!x ) return;

	if (x->value)
	{
		if (x->cb->free)
		{
			if (x->type == PKI_DATATYPE_X509_KEYPAIR)
			{
				switch(EVP_PKEY_type(((EVP_PKEY *)x->value)->type))
				{
					case EVP_PKEY_RSA:
					{
						CK_OBJECT_HANDLE *pubKey = NULL;
						CK_OBJECT_HANDLE *privKey = NULL;
						RSA *rsa = EVP_PKEY_get1_RSA( (EVP_PKEY *) x->value );

						if(rsa == NULL )
							break;

						/* Retrieves the privkey object handler */
						if((privKey = (CK_OBJECT_HANDLE *) RSA_get_ex_data (rsa, KEYPAIR_PRIVKEY_HANDLER_IDX)) == NULL )
							PKI_log_debug ("PKI_X509_free()::Can't get privKey Handle");
						else
							PKI_Free(privKey);

						/* Retrieves the pubkey object handler */
						if((pubKey = (CK_OBJECT_HANDLE *) RSA_get_ex_data (rsa, KEYPAIR_PUBKEY_HANDLER_IDX)) == NULL )
							PKI_log_debug ("PKI_X509_free()::Can't get pubKey Handle");
						else
							PKI_Free(pubKey);
						RSA_free(rsa);
					}
					default:
						break;
				}
			}
			x->cb->free(x->value);
		}
		else
			PKI_Free(x->value);
	}

	if (x->cred) PKI_CRED_free(x->cred);

	if (x->ref ) URL_free(x->ref);

	PKI_ZFree ( x, sizeof(PKI_X509) );

	return;
}

/*! \brief Allocates the memory for a new PKI_X509 and sets the data */

PKI_X509 *PKI_X509_new_value (PKI_DATATYPE type, void *value, 
						struct hsm_st *hsm){

	PKI_X509 *ret = NULL;

	if (!value) return NULL;

	if (( ret = PKI_X509_new ( type, hsm )) == NULL ) {
		PKI_log_debug ( "Can not initialized a new PKI_X509 object.");
		return NULL;
	}

	if((PKI_X509_set_value ( ret, value )) == PKI_ERR ) {
		PKI_log_debug ( "Can not set the value in the PKI_X509 object");
		PKI_X509_free ( ret );
		return NULL;
	}

	return ret;
}

/*! \brief Allocates the memory for a new PKI_X509 and duplicates the data */

PKI_X509 *PKI_X509_new_dup_value (PKI_DATATYPE type, void *value, 
						struct hsm_st *hsm ) {

	PKI_X509 *ret = NULL;

	if( !value ) return NULL;

	if (( ret = PKI_X509_new ( type, hsm )) == NULL ) {
		PKI_log_debug ( "Can not initialized a new PKI_X509 object.");
		return NULL;
	}

	if ( !ret->cb || !ret->cb->dup )  {
		PKI_log_debug ( "ERROR, no 'dup' callback!");
		PKI_X509_free ( ret );
		return NULL;
	}

	ret->value = ret->cb->dup ( value );

	return ret;
}

/*!
 * \brief Sets the Modified bit (required in some crypto lib to force re-encoding)
 */

int PKI_X509_set_modified ( PKI_X509 *x ) {

#if ( OPENSSL_VERSION_NUMBER >= 0x0090900f )
	PKI_X509_CERT_VALUE *cVal = NULL;
	PKI_X509_CRL_VALUE *cRLVal = NULL;
#endif
	int type;
	
	if ( !x || !x->value ) return PKI_ERR;

	type = PKI_X509_get_type ( x );

	// This should be implemented via callbacks!!!
	switch ( type )
	{
		case PKI_DATATYPE_X509_CERT:
#if ( OPENSSL_VERSION_NUMBER >= 0x0090900f )
				cVal = (PKI_X509_CERT_VALUE *) x->value;
				// cVal->cert_info->enc.modified = 1;
				if (cVal && cVal->cert_info) {
					PKI_X509_CINF_FULL *cFull = NULL;
					cFull = (PKI_X509_CINF_FULL *) cVal->cert_info;
					cFull->enc.modified = 1;
				}
#endif
				break;

		case PKI_DATATYPE_X509_CRL:
#if ( OPENSSL_VERSION_NUMBER >= 0x0090900f )
				cRLVal = (PKI_X509_CRL_VALUE *) x->value;
				cRLVal->crl->enc.modified = 1;
#endif
				break;
	};

	return PKI_OK;

};

/*! \brief Returns the type of a PKI_X509 object */

PKI_DATATYPE PKI_X509_get_type ( PKI_X509 *x ) {

	if (!x) return PKI_DATATYPE_UNKNOWN;

	return x->type;
}

/*!
 * \brief Returns a TXT description of the Object Type
 */

const char * PKI_X509_get_type_parsed ( PKI_X509 *obj ) {
	int i = 0;
	int type = 0;

	type = PKI_X509_get_type( obj );
	while( __parsed_datatypes[i].descr != NULL ) {
		if ( __parsed_datatypes[i].nid == type ) {
			return __parsed_datatypes[i].descr;
		};
		i++;
	};
	return __parsed_datatypes[0].descr;
};

/*! \brief Sets the HSM reference in a PKI_X509 object */

int PKI_X509_set_hsm ( PKI_X509 *x, struct hsm_st *hsm ) {

	if ( !x || !hsm ) return PKI_ERR;

	if ( hsm ) HSM_free ( hsm );

	x->hsm = hsm;

	return PKI_OK;
}

/*! \brief Retrieves the HSM reference from a PKI_X509 object */

struct hsm_st *PKI_X509_get_hsm ( PKI_X509 *x ) {

	if (!x) return NULL;

	return x->hsm;
}

/*! \brief Sets (duplicates) the reference URL of a PKI_X509 object */
int PKI_X509_set_reference ( PKI_X509 *x, URL *url ) {
	if ( !x || !url ) return PKI_ERR;

	if ( x->ref ) URL_free ( x->ref );

	x->ref = URL_new ( url->url_s );

	return PKI_OK;
}

/*! \brief Retrieves the reference URL from a PKI_X509 object */

URL *PKI_X509_get_reference ( PKI_X509 *x ) {
	if ( !x ) return NULL;

	return x->ref;
}


/*! \brief Returns the reference to the PKI_X509_XXX_VALUE withing a PKI_X509
	   object */

void * PKI_X509_get_value ( PKI_X509 *x ) {

	if ( !x ) return NULL;

	return x->value;
}


/*! \brief Sets the pointer to the internal value in a PKI_X509 */

int PKI_X509_set_value ( PKI_X509 *x, void *data ) {

	if ( !x || !data ) return PKI_ERR;

	if ( x->value && x->cb ) {
		if ( !x->cb || !x->cb->free ) {
			PKI_log_debug ("ERROR, no 'free' callback!");
			return PKI_ERR;
		}
		x->cb->free ( x->value );
	}

	x->value = data;

	return PKI_OK;
}

/*! \brief Duplicates the PKI_X509_XXX_VALUE from the passed PKI_X509 object */

void * PKI_X509_dup_value ( PKI_X509 *x ) {

	void *ret = NULL;

	if (!x || !x->cb || !x->cb->dup || !x->value ) 
		return NULL;

	ret = x->cb->dup ( x->value );

	return ret;
}

/*! \brief Duplicates a PKI_X509 object */

PKI_X509 * PKI_X509_dup ( PKI_X509 *x ) {

	PKI_X509 *ret = NULL;

	if (!x ) return NULL;

	if(( ret = PKI_Malloc(sizeof(PKI_X509))) == NULL)
	{
		PKI_ERROR(PKI_ERR_MEMORY_ALLOC, NULL);
		return NULL;
	}

	memcpy ( ret, x, sizeof ( PKI_X509 ));

	if( x->value )
	{
		ret->value = PKI_X509_dup_value(x);
		if ( ret->value == NULL )
		{
			PKI_ERROR(PKI_ERR_MEMORY_ALLOC, NULL);
			PKI_ZFree(ret, sizeof(PKI_X509));
			return NULL;
		}
	}

	if (x->ref)
	{
		// The origin of this new object is memory, so the ref
		// should be set to NULL
		ret->ref = NULL;	
	}

	if (x->hsm)
	{
		ret->hsm = x->hsm;
	}

	if (x->cb) {
		ret->cb = x->cb;
	}

	return ret;
}

/*! \brief Returns a ref to the X509 data (e.g., SUBJECT) within the passed PKI_X509 object */

void * PKI_X509_get_data ( PKI_X509 *x, PKI_X509_DATA type ) {


	if ( !x || !x->cb || !x->cb->get_data ) {
		PKI_log_debug ( "ERROR, no x, cb or get_data!");
	}

	if( !x || !x->cb || !x->cb->get_data || !x->value ) return NULL;

	return x->cb->get_data ( x, type );
}

/*! \brief Returns PKI_OK if the PKI_X509 object is signed */

int PKI_X509_is_signed( PKI_X509 *obj ) {

	if ( !obj || !obj->value ) return PKI_ERR;

	if ( PKI_X509_get_data ( obj, PKI_X509_DATA_SIGNATURE ) == NULL ) {
		return PKI_ERR;
	}

	return PKI_OK;
}

/*! \brief Returns the parsed (char *, int *, etc.) version of the data in
           a PKI_X509 object */

void * PKI_X509_get_parsed ( PKI_X509 *x, PKI_X509_DATA type ) {

	if ( !x || !x->cb || !x->cb->get_parsed || !x->value ) return NULL;

	return x->cb->get_parsed ( x, type );
}


/*! \brief Prints the parsed data from a PKI_X509 object to a file descriptor */

int PKI_X509_print_parsed ( PKI_X509 *x, PKI_X509_DATA type, int fd ) {

	if ( !x || !x->cb->print_parsed || !x->value ) return PKI_ERR;

	return x->cb->print_parsed ( x, type, fd );
}

/*! \brief Deletes the hard copy (eg., file, hsm file, etc.) of the PKI_X509
 *         object. */

int PKI_X509_delete ( PKI_X509 *x )
{
	int ret = PKI_OK;
	PKI_X509_STACK *sk = NULL;

	if (!x || !x->ref) return PKI_ERR;

	if (x->hsm && x->hsm->callbacks)
	{
		sk = PKI_STACK_new_type( x->type );
		PKI_STACK_X509_push ( sk, x );

		ret = HSM_X509_STACK_del ( sk );
		x = PKI_STACK_X509_pop ( sk );

		PKI_STACK_X509_free ( sk );
		return ret;
	}

	switch ( x->ref->proto )
	{
		case URI_PROTO_FILE:
			ret = unlink ( x->ref->url_s );
			break;
		default:
			ret = PKI_ERR;
			break;
	}

	return ret;
}

