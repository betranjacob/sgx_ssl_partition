static int
aead_aes_gcm_init(EVP_AEAD_CTX *ctx, const unsigned char *key, size_t key_len,
    size_t tag_len)
{
	struct aead_aes_gcm_ctx *gcm_ctx;
	const size_t key_bits = key_len * 8;

	/* EVP_AEAD_CTX_init should catch this. */
	if (key_bits != 128 && key_bits != 256) {
		EVPerr(EVP_F_AEAD_AES_GCM_INIT, EVP_R_BAD_KEY_LENGTH);
		return 0;
	}

	if (tag_len == EVP_AEAD_DEFAULT_TAG_LENGTH)
		tag_len = EVP_AEAD_AES_GCM_TAG_LEN;

	if (tag_len > EVP_AEAD_AES_GCM_TAG_LEN) {
		EVPerr(EVP_F_AEAD_AES_GCM_INIT, EVP_R_TAG_TOO_LARGE);
		return 0;
	}

	gcm_ctx = malloc(sizeof(struct aead_aes_gcm_ctx));
	if (gcm_ctx == NULL)
		return 0;

#ifdef AESNI_CAPABLE
	if (AESNI_CAPABLE) {
		aesni_set_encrypt_key(key, key_bits, &gcm_ctx->ks.ks);
		CRYPTO_gcm128_init(&gcm_ctx->gcm, &gcm_ctx->ks.ks,
		    (block128_f)aesni_encrypt);
		gcm_ctx->ctr = (ctr128_f) aesni_ctr32_encrypt_blocks;
	} else
#endif
	{
		gcm_ctx->ctr = aes_gcm_set_key(&gcm_ctx->ks.ks, &gcm_ctx->gcm,
		    key, key_len);
	}
	gcm_ctx->tag_len = tag_len;
	ctx->aead_state = gcm_ctx;

	return 1;
}


static int
aead_aes_gcm_open(const EVP_AEAD_CTX *ctx, unsigned char *out, size_t *out_len,
    size_t max_out_len, const unsigned char *nonce, size_t nonce_len,
    const unsigned char *in, size_t in_len, const unsigned char *ad,
    size_t ad_len)
{
	const struct aead_aes_gcm_ctx *gcm_ctx = ctx->aead_state;
	unsigned char tag[EVP_AEAD_AES_GCM_TAG_LEN];
	GCM128_CONTEXT gcm;
	size_t plaintext_len;
	size_t bulk = 0;

	if (in_len < gcm_ctx->tag_len) {
		EVPerr(EVP_F_AEAD_AES_GCM_OPEN, EVP_R_BAD_DECRYPT);
		return 0;
	}

	plaintext_len = in_len - gcm_ctx->tag_len;

	if (max_out_len < plaintext_len) {
		EVPerr(EVP_F_AEAD_AES_GCM_OPEN, EVP_R_BUFFER_TOO_SMALL);
		return 0;
	}

	memcpy(&gcm, &gcm_ctx->gcm, sizeof(gcm));
	CRYPTO_gcm128_setiv(&gcm, nonce, nonce_len);

	if (CRYPTO_gcm128_aad(&gcm, ad, ad_len))
		return 0;

	if (gcm_ctx->ctr) {
		if (CRYPTO_gcm128_decrypt_ctr32(&gcm, in + bulk, out + bulk,
		    in_len - bulk - gcm_ctx->tag_len, gcm_ctx->ctr))
			return 0;
	} else {
		if (CRYPTO_gcm128_decrypt(&gcm, in + bulk, out + bulk,
		    in_len - bulk - gcm_ctx->tag_len))
			return 0;
	}

	CRYPTO_gcm128_tag(&gcm, tag, gcm_ctx->tag_len);
	if (timingsafe_memcmp(tag, in + plaintext_len, gcm_ctx->tag_len) != 0) {
		EVPerr(EVP_F_AEAD_AES_GCM_OPEN, EVP_R_BAD_DECRYPT);
		return 0;
	}

	*out_len = plaintext_len;

	return 1;
}


static int
aead_aes_gcm_seal(const EVP_AEAD_CTX *ctx, unsigned char *out, size_t *out_len,
    size_t max_out_len, const unsigned char *nonce, size_t nonce_len,
    const unsigned char *in, size_t in_len, const unsigned char *ad,
    size_t ad_len)
{
	const struct aead_aes_gcm_ctx *gcm_ctx = ctx->aead_state;
	GCM128_CONTEXT gcm;
	size_t bulk = 0;

	if (max_out_len < in_len + gcm_ctx->tag_len) {
		EVPerr(EVP_F_AEAD_AES_GCM_SEAL, EVP_R_BUFFER_TOO_SMALL);
		return 0;
	}

	memcpy(&gcm, &gcm_ctx->gcm, sizeof(gcm));
	CRYPTO_gcm128_setiv(&gcm, nonce, nonce_len);

	if (ad_len > 0 && CRYPTO_gcm128_aad(&gcm, ad, ad_len))
		return 0;

	if (gcm_ctx->ctr) {
		if (CRYPTO_gcm128_encrypt_ctr32(&gcm, in + bulk, out + bulk,
		    in_len - bulk, gcm_ctx->ctr))
			return 0;
	} else {
		if (CRYPTO_gcm128_encrypt(&gcm, in + bulk, out + bulk,
		    in_len - bulk))
			return 0;
	}

	CRYPTO_gcm128_tag(&gcm, out + in_len, gcm_ctx->tag_len);
	*out_len = in_len + gcm_ctx->tag_len;

	return 1;
}


static int
ameth_cmp(const EVP_PKEY_ASN1_METHOD * const *a,
    const EVP_PKEY_ASN1_METHOD * const *b)
{
	return ((*a)->pkey_id - (*b)->pkey_id);
}


void
arc4random_buf(void *buf, size_t n)
{
	_ARC4_LOCK();
	_rs_random_buf(buf, n);
	_ARC4_UNLOCK();
}


static int
asn1_check_eoc(const unsigned char **in, long len)
{
	const unsigned char *p;

	if (len < 2)
		return 0;
	p = *in;
	if (!p[0] && !p[1]) {
		*in += 2;
		return 1;
	}
	return 0;
}


static int
asn1_check_tlen(long *olen, int *otag, unsigned char *oclass, char *inf,
    char *cst, const unsigned char **in, long len, int exptag, int expclass,
    char opt, ASN1_TLC *ctx)
{
	int i;
	int ptag, pclass;
	long plen;
	const unsigned char *p, *q;

	p = *in;
	q = p;

	if (ctx && ctx->valid) {
		i = ctx->ret;
		plen = ctx->plen;
		pclass = ctx->pclass;
		ptag = ctx->ptag;
		p += ctx->hdrlen;
	} else {
		i = ASN1_get_object(&p, &plen, &ptag, &pclass, len);
		if (ctx) {
			ctx->ret = i;
			ctx->plen = plen;
			ctx->pclass = pclass;
			ctx->ptag = ptag;
			ctx->hdrlen = p - q;
			ctx->valid = 1;
			/* If definite length, and no error, length +
			 * header can't exceed total amount of data available.
			 */
			if (!(i & 0x81) && ((plen + ctx->hdrlen) > len)) {
				ASN1err(ASN1_F_ASN1_CHECK_TLEN,
				    ASN1_R_TOO_LONG);
				asn1_tlc_clear(ctx);
				return 0;
			}
		}
	}

	if (i & 0x80) {
		ASN1err(ASN1_F_ASN1_CHECK_TLEN, ASN1_R_BAD_OBJECT_HEADER);
		asn1_tlc_clear(ctx);
		return 0;
	}
	if (exptag >= 0) {
		if ((exptag != ptag) || (expclass != pclass)) {
			/* If type is OPTIONAL, not an error:
			 * indicate missing type.
			 */
			if (opt)
				return -1;
			asn1_tlc_clear(ctx);
			ASN1err(ASN1_F_ASN1_CHECK_TLEN, ASN1_R_WRONG_TAG);
			return 0;
		}
		/* We have a tag and class match:
		 * assume we are going to do something with it */
		asn1_tlc_clear(ctx);
	}

	if (i & 1)
		plen = len - (p - q);
	if (inf)
		*inf = i & 1;
	if (cst)
		*cst = i & V_ASN1_CONSTRUCTED;
	if (olen)
		*olen = plen;
	if (oclass)
		*oclass = pclass;
	if (otag)
		*otag = ptag;

	*in = p;
	return 1;
}


static int
asn1_d2i_ex_primitive(ASN1_VALUE **pval, const unsigned char **in, long inlen,
    const ASN1_ITEM *it, int tag, int aclass, char opt, ASN1_TLC *ctx)
{
	int ret = 0, utype;
	long plen;
	char cst, inf, free_cont = 0;
	const unsigned char *p;
	BUF_MEM buf;
	const unsigned char *cont = NULL;
	long len;

	buf.length = 0;
	buf.max = 0;
	buf.data = NULL;

	if (!pval) {
		ASN1err(ASN1_F_ASN1_D2I_EX_PRIMITIVE, ASN1_R_ILLEGAL_NULL);
		return 0; /* Should never happen */
	}

	if (it->itype == ASN1_ITYPE_MSTRING) {
		utype = tag;
		tag = -1;
	} else
		utype = it->utype;

	if (utype == V_ASN1_ANY) {
		/* If type is ANY need to figure out type from tag */
		unsigned char oclass;
		if (tag >= 0) {
			ASN1err(ASN1_F_ASN1_D2I_EX_PRIMITIVE,
			    ASN1_R_ILLEGAL_TAGGED_ANY);
			return 0;
		}
		if (opt) {
			ASN1err(ASN1_F_ASN1_D2I_EX_PRIMITIVE,
			    ASN1_R_ILLEGAL_OPTIONAL_ANY);
			return 0;
		}
		p = *in;
		ret = asn1_check_tlen(NULL, &utype, &oclass, NULL, NULL,
		    &p, inlen, -1, 0, 0, ctx);
		if (!ret) {
			ASN1err(ASN1_F_ASN1_D2I_EX_PRIMITIVE,
			    ERR_R_NESTED_ASN1_ERROR);
			return 0;
		}
		if (oclass != V_ASN1_UNIVERSAL)
			utype = V_ASN1_OTHER;
	}
	if (tag == -1) {
		tag = utype;
		aclass = V_ASN1_UNIVERSAL;
	}
	p = *in;
	/* Check header */
	ret = asn1_check_tlen(&plen, NULL, NULL, &inf, &cst,
	    &p, inlen, tag, aclass, opt, ctx);
	if (!ret) {
		ASN1err(ASN1_F_ASN1_D2I_EX_PRIMITIVE, ERR_R_NESTED_ASN1_ERROR);
		return 0;
	} else if (ret == -1)
		return -1;
	ret = 0;
	/* SEQUENCE, SET and "OTHER" are left in encoded form */
	if ((utype == V_ASN1_SEQUENCE) || (utype == V_ASN1_SET) ||
	    (utype == V_ASN1_OTHER)) {
		/* Clear context cache for type OTHER because the auto clear
		 * when we have a exact match wont work
		 */
		if (utype == V_ASN1_OTHER) {
			asn1_tlc_clear(ctx);
		}
		/* SEQUENCE and SET must be constructed */
		else if (!cst) {
			ASN1err(ASN1_F_ASN1_D2I_EX_PRIMITIVE,
			    ASN1_R_TYPE_NOT_CONSTRUCTED);
			return 0;
		}

		cont = *in;
		/* If indefinite length constructed find the real end */
		if (inf) {
			if (!asn1_find_end(&p, plen, inf))
				goto err;
			len = p - cont;
		} else {
			len = p - cont + plen;
			p += plen;
			buf.data = NULL;
		}
	} else if (cst) {
		/* Should really check the internal tags are correct but
		 * some things may get this wrong. The relevant specs
		 * say that constructed string types should be OCTET STRINGs
		 * internally irrespective of the type. So instead just check
		 * for UNIVERSAL class and ignore the tag.
		 */
		if (!asn1_collect(&buf, &p, plen, inf, -1, V_ASN1_UNIVERSAL, 0)) {
			free_cont = 1;
			goto err;
		}
		len = buf.length;
		/* Append a final null to string */
		if (!BUF_MEM_grow_clean(&buf, len + 1)) {
			ASN1err(ASN1_F_ASN1_D2I_EX_PRIMITIVE,
			    ERR_R_MALLOC_FAILURE);
			return 0;
		}
		buf.data[len] = 0;
		cont = (const unsigned char *)buf.data;
		free_cont = 1;
	} else {
		cont = p;
		len = plen;
		p += plen;
	}

	/* We now have content length and type: translate into a structure */
	if (!asn1_ex_c2i(pval, cont, len, utype, &free_cont, it))
		goto err;

	*in = p;
	ret = 1;

err:
	if (free_cont && buf.data)
		free(buf.data);
	return ret;
}


const ASN1_TEMPLATE *
asn1_do_adb(ASN1_VALUE **pval, const ASN1_TEMPLATE *tt, int nullerr)
{
	const ASN1_ADB *adb;
	const ASN1_ADB_TABLE *atbl;
	long selector;
	ASN1_VALUE **sfld;
	int i;

	if (!(tt->flags & ASN1_TFLG_ADB_MASK))
		return tt;

	/* Else ANY DEFINED BY ... get the table */
	adb = (const ASN1_ADB *)tt->item;

	/* Get the selector field */
	sfld = offset2ptr(*pval, adb->offset);

	/* Check if NULL */
	if (!sfld) {
		if (!adb->null_tt)
			goto err;
		return adb->null_tt;
	}

	/* Convert type to a long:
	 * NB: don't check for NID_undef here because it
	 * might be a legitimate value in the table
	 */
	if (tt->flags & ASN1_TFLG_ADB_OID)
		selector = OBJ_obj2nid((ASN1_OBJECT *)*sfld);
	else
		selector = ASN1_INTEGER_get((ASN1_INTEGER *)*sfld);

	/* Try to find matching entry in table
	 * Maybe should check application types first to
	 * allow application override? Might also be useful
	 * to have a flag which indicates table is sorted and
	 * we can do a binary search. For now stick to a
	 * linear search.
	 */

	for (atbl = adb->tbl, i = 0; i < adb->tblcount; i++, atbl++)
		if (atbl->value == selector)
			return &atbl->tt;

	/* FIXME: need to search application table too */

	/* No match, return default type */
	if (!adb->default_tt)
		goto err;
	return adb->default_tt;

err:
	/* FIXME: should log the value or OID of unsupported type */
	if (nullerr)
		ASN1err(ASN1_F_ASN1_DO_ADB,
		    ASN1_R_UNSUPPORTED_ANY_DEFINED_BY_TYPE);
	return NULL;
}


int
asn1_do_lock(ASN1_VALUE **pval, int op, const ASN1_ITEM *it)
{
	const ASN1_AUX *aux;
	int *lck, ret;

	if ((it->itype != ASN1_ITYPE_SEQUENCE) &&
	    (it->itype != ASN1_ITYPE_NDEF_SEQUENCE))
		return 0;
	aux = it->funcs;
	if (!aux || !(aux->flags & ASN1_AFLG_REFCOUNT))
		return 0;
	lck = offset2ptr(*pval, aux->ref_offset);
	if (op == 0) {
		*lck = 1;
		return 1;
	}
	ret = CRYPTO_add(lck, op, aux->ref_lock);
	return ret;
}


void
asn1_enc_free(ASN1_VALUE **pval, const ASN1_ITEM *it)
{
	ASN1_ENCODING *enc;

	enc = asn1_get_enc_ptr(pval, it);
	if (enc) {
		free(enc->enc);
		enc->enc = NULL;
		enc->len = 0;
		enc->modified = 1;
	}
}


void
asn1_enc_init(ASN1_VALUE **pval, const ASN1_ITEM *it)
{
	ASN1_ENCODING *enc;

	enc = asn1_get_enc_ptr(pval, it);
	if (enc) {
		enc->enc = NULL;
		enc->len = 0;
		enc->modified = 1;
	}
}


int
asn1_enc_restore(int *len, unsigned char **out, ASN1_VALUE **pval,
    const ASN1_ITEM *it)
{
	ASN1_ENCODING *enc;

	enc = asn1_get_enc_ptr(pval, it);
	if (!enc || enc->modified)
		return 0;
	if (out) {
		memcpy(*out, enc->enc, enc->len);
		*out += enc->len;
	}
	if (len)
		*len = enc->len;
	return 1;
}


int
asn1_enc_save(ASN1_VALUE **pval, const unsigned char *in, int inlen,
    const ASN1_ITEM *it)
{
	ASN1_ENCODING *enc;

	enc = asn1_get_enc_ptr(pval, it);
	if (!enc)
		return 1;

	free(enc->enc);
	enc->enc = malloc(inlen);
	if (!enc->enc)
		return 0;
	memcpy(enc->enc, in, inlen);
	enc->len = inlen;
	enc->modified = 0;

	return 1;
}


int
asn1_ex_c2i(ASN1_VALUE **pval, const unsigned char *cont, int len, int utype,
    char *free_cont, const ASN1_ITEM *it)
{
	ASN1_VALUE **opval = NULL;
	ASN1_STRING *stmp;
	ASN1_TYPE *typ = NULL;
	int ret = 0;
	const ASN1_PRIMITIVE_FUNCS *pf;
	ASN1_INTEGER **tint;

	pf = it->funcs;

	if (pf && pf->prim_c2i)
		return pf->prim_c2i(pval, cont, len, utype, free_cont, it);
	/* If ANY type clear type and set pointer to internal value */
	if (it->utype == V_ASN1_ANY) {
		if (!*pval) {
			typ = ASN1_TYPE_new();
			if (typ == NULL)
				goto err;
			*pval = (ASN1_VALUE *)typ;
		} else
			typ = (ASN1_TYPE *)*pval;

		if (utype != typ->type)
			ASN1_TYPE_set(typ, utype, NULL);
		opval = pval;
		pval = &typ->value.asn1_value;
	}
	switch (utype) {
	case V_ASN1_OBJECT:
		if (!c2i_ASN1_OBJECT((ASN1_OBJECT **)pval, &cont, len))
			goto err;
		break;

	case V_ASN1_NULL:
		if (len) {
			ASN1err(ASN1_F_ASN1_EX_C2I,
			    ASN1_R_NULL_IS_WRONG_LENGTH);
			goto err;
		}
		*pval = (ASN1_VALUE *)1;
		break;

	case V_ASN1_BOOLEAN:
		if (len != 1) {
			ASN1err(ASN1_F_ASN1_EX_C2I,
			    ASN1_R_BOOLEAN_IS_WRONG_LENGTH);
			goto err;
		} else {
			ASN1_BOOLEAN *tbool;
			tbool = (ASN1_BOOLEAN *)pval;
			*tbool = *cont;
		}
		break;

	case V_ASN1_BIT_STRING:
		if (!c2i_ASN1_BIT_STRING((ASN1_BIT_STRING **)pval, &cont, len))
			goto err;
		break;

	case V_ASN1_INTEGER:
	case V_ASN1_ENUMERATED:
		tint = (ASN1_INTEGER **)pval;
		if (!c2i_ASN1_INTEGER(tint, &cont, len))
			goto err;
		/* Fixup type to match the expected form */
		(*tint)->type = utype | ((*tint)->type & V_ASN1_NEG);
		break;

	case V_ASN1_OCTET_STRING:
	case V_ASN1_NUMERICSTRING:
	case V_ASN1_PRINTABLESTRING:
	case V_ASN1_T61STRING:
	case V_ASN1_VIDEOTEXSTRING:
	case V_ASN1_IA5STRING:
	case V_ASN1_UTCTIME:
	case V_ASN1_GENERALIZEDTIME:
	case V_ASN1_GRAPHICSTRING:
	case V_ASN1_VISIBLESTRING:
	case V_ASN1_GENERALSTRING:
	case V_ASN1_UNIVERSALSTRING:
	case V_ASN1_BMPSTRING:
	case V_ASN1_UTF8STRING:
	case V_ASN1_OTHER:
	case V_ASN1_SET:
	case V_ASN1_SEQUENCE:
	default:
		if (utype == V_ASN1_BMPSTRING && (len & 1)) {
			ASN1err(ASN1_F_ASN1_EX_C2I,
			    ASN1_R_BMPSTRING_IS_WRONG_LENGTH);
			goto err;
		}
		if (utype == V_ASN1_UNIVERSALSTRING && (len & 3)) {
			ASN1err(ASN1_F_ASN1_EX_C2I,
			    ASN1_R_UNIVERSALSTRING_IS_WRONG_LENGTH);
			goto err;
		}
		/* All based on ASN1_STRING and handled the same */
		if (!*pval) {
			stmp = ASN1_STRING_type_new(utype);
			if (!stmp) {
				ASN1err(ASN1_F_ASN1_EX_C2I,
				    ERR_R_MALLOC_FAILURE);
				goto err;
			}
			*pval = (ASN1_VALUE *)stmp;
		} else {
			stmp = (ASN1_STRING *)*pval;
			stmp->type = utype;
		}
		/* If we've already allocated a buffer use it */
		if (*free_cont) {
			free(stmp->data);
			stmp->data = (unsigned char *)cont; /* UGLY CAST! RL */
			stmp->length = len;
			*free_cont = 0;
		} else {
			if (!ASN1_STRING_set(stmp, cont, len)) {
				ASN1err(ASN1_F_ASN1_EX_C2I,
				    ERR_R_MALLOC_FAILURE);
				ASN1_STRING_free(stmp);
				*pval = NULL;
				goto err;
			}
		}
		break;
	}
	/* If ASN1_ANY and NULL type fix up value */
	if (typ && (utype == V_ASN1_NULL))
		typ->value.ptr = NULL;

	ret = 1;

err:
	if (!ret) {
		ASN1_TYPE_free(typ);
		if (opval)
			*opval = NULL;
	}
	return ret;
}


static int
asn1_ex_i2c(ASN1_VALUE **pval, unsigned char *cout, int *putype,
    const ASN1_ITEM *it)
{
	ASN1_BOOLEAN *tbool = NULL;
	ASN1_STRING *strtmp;
	ASN1_OBJECT *otmp;
	int utype;
	const unsigned char *cont;
	unsigned char c;
	int len;
	const ASN1_PRIMITIVE_FUNCS *pf;

	pf = it->funcs;
	if (pf && pf->prim_i2c)
		return pf->prim_i2c(pval, cout, putype, it);

	/* Should type be omitted? */
	if ((it->itype != ASN1_ITYPE_PRIMITIVE) ||
	    (it->utype != V_ASN1_BOOLEAN)) {
		if (!*pval)
			return -1;
	}

	if (it->itype == ASN1_ITYPE_MSTRING) {
		/* If MSTRING type set the underlying type */
		strtmp = (ASN1_STRING *)*pval;
		utype = strtmp->type;
		*putype = utype;
	} else if (it->utype == V_ASN1_ANY) {
		/* If ANY set type and pointer to value */
		ASN1_TYPE *typ;
		typ = (ASN1_TYPE *)*pval;
		utype = typ->type;
		*putype = utype;
		pval = &typ->value.asn1_value;
	} else
		utype = *putype;

	switch (utype) {
	case V_ASN1_OBJECT:
		otmp = (ASN1_OBJECT *)*pval;
		cont = otmp->data;
		len = otmp->length;
		break;

	case V_ASN1_NULL:
		cont = NULL;
		len = 0;
		break;

	case V_ASN1_BOOLEAN:
		tbool = (ASN1_BOOLEAN *)pval;
		if (*tbool == -1)
			return -1;
		if (it->utype != V_ASN1_ANY) {
			/* Default handling if value == size field then omit */
			if (*tbool && (it->size > 0))
				return -1;
			if (!*tbool && !it->size)
				return -1;
		}
		c = (unsigned char)*tbool;
		cont = &c;
		len = 1;
		break;

	case V_ASN1_BIT_STRING:
		return i2c_ASN1_BIT_STRING((ASN1_BIT_STRING *)*pval,
		    cout ? &cout : NULL);
		break;

	case V_ASN1_INTEGER:
	case V_ASN1_ENUMERATED:
		/* These are all have the same content format
		 * as ASN1_INTEGER
		 */
		return i2c_ASN1_INTEGER((ASN1_INTEGER *)*pval,
		    cout ? &cout : NULL);
		break;

	case V_ASN1_OCTET_STRING:
	case V_ASN1_NUMERICSTRING:
	case V_ASN1_PRINTABLESTRING:
	case V_ASN1_T61STRING:
	case V_ASN1_VIDEOTEXSTRING:
	case V_ASN1_IA5STRING:
	case V_ASN1_UTCTIME:
	case V_ASN1_GENERALIZEDTIME:
	case V_ASN1_GRAPHICSTRING:
	case V_ASN1_VISIBLESTRING:
	case V_ASN1_GENERALSTRING:
	case V_ASN1_UNIVERSALSTRING:
	case V_ASN1_BMPSTRING:
	case V_ASN1_UTF8STRING:
	case V_ASN1_SEQUENCE:
	case V_ASN1_SET:
	default:
		/* All based on ASN1_STRING and handled the same */
		strtmp = (ASN1_STRING *)*pval;
		/* Special handling for NDEF */
		if ((it->size == ASN1_TFLG_NDEF) &&
		    (strtmp->flags & ASN1_STRING_FLAG_NDEF)) {
			if (cout) {
				strtmp->data = cout;
				strtmp->length = 0;
			}
			/* Special return code */
			return -2;
		}
		cont = strtmp->data;
		len = strtmp->length;

		break;

	}
	if (cout && len)
		memcpy(cout, cont, len);
	return len;
}


static ASN1_ENCODING *
asn1_get_enc_ptr(ASN1_VALUE **pval, const ASN1_ITEM *it)
{
	const ASN1_AUX *aux;

	if (!pval || !*pval)
		return NULL;
	aux = it->funcs;
	if (!aux || !(aux->flags & ASN1_AFLG_ENCODING))
		return NULL;
	return offset2ptr(*pval, aux->enc_offset);
}


ASN1_VALUE **
asn1_get_field_ptr(ASN1_VALUE **pval, const ASN1_TEMPLATE *tt)
{
	ASN1_VALUE **pvaltmp;

	if (tt->flags & ASN1_TFLG_COMBINE)
		return pval;
	pvaltmp = offset2ptr(*pval, tt->offset);
	/* NOTE for BOOLEAN types the field is just a plain
 	 * int so we can't return int **, so settle for
	 * (int *).
	 */
	return pvaltmp;
}


static int
asn1_get_length(const unsigned char **pp, int *inf, long *rl, int max)
{
	const unsigned char *p= *pp;
	unsigned long ret = 0;
	unsigned int i;

	if (max-- < 1)
		return (0);
	if (*p == 0x80) {
		*inf = 1;
		ret = 0;
		p++;
	} else {
		*inf = 0;
		i= *p & 0x7f;
		if (*(p++) & 0x80) {
			if (max < (int)i)
				return (0);
			/* skip leading zeroes */
			while (i && *p == 0) {
				p++;
				i--;
			}
			if (i > sizeof(long))
				return 0;
			while (i-- > 0) {
				ret <<= 8L;
				ret |= *(p++);
			}
		} else
			ret = i;
	}
	if (ret > LONG_MAX)
		return 0;
	*pp = p;
	*rl = (long)ret;
	return (1);
}


int
ASN1_get_object(const unsigned char **pp, long *plength, int *ptag,
    int *pclass, long omax)
{
	int i, ret;
	long l;
	const unsigned char *p= *pp;
	int tag, xclass, inf;
	long max = omax;

	if (!max)
		goto err;
	ret = (*p & V_ASN1_CONSTRUCTED);
	xclass = (*p & V_ASN1_PRIVATE);
	i= *p & V_ASN1_PRIMITIVE_TAG;
	if (i == V_ASN1_PRIMITIVE_TAG) {		/* high-tag */
		p++;
		if (--max == 0)
			goto err;
		l = 0;
		while (*p & 0x80) {
			l <<= 7L;
			l |= *(p++) & 0x7f;
			if (--max == 0)
				goto err;
			if (l > (INT_MAX >> 7L))
				goto err;
		}
		l <<= 7L;
		l |= *(p++) & 0x7f;
		tag = (int)l;
		if (--max == 0)
			goto err;
	} else {
		tag = i;
		p++;
		if (--max == 0)
			goto err;
	}
	*ptag = tag;
	*pclass = xclass;
	if (!asn1_get_length(&p, &inf, plength, (int)max))
		goto err;

	if (inf && !(ret & V_ASN1_CONSTRUCTED))
		goto err;

	if (*plength > (omax - (p - *pp))) {
		ASN1err(ASN1_F_ASN1_GET_OBJECT, ASN1_R_TOO_LONG);
		/* Set this so that even if things are not long enough
		 * the values are set correctly */
		ret |= 0x80;
	}
	*pp = p;
	return (ret | inf);

err:
	ASN1err(ASN1_F_ASN1_GET_OBJECT, ASN1_R_HEADER_TOO_LONG);
	return (0x80);
}


static int
asn1_i2d_ex_primitive(ASN1_VALUE **pval, unsigned char **out,
    const ASN1_ITEM *it, int tag, int aclass)
{
	int len;
	int utype;
	int usetag;
	int ndef = 0;

	utype = it->utype;

	/* Get length of content octets and maybe find
	 * out the underlying type.
	 */

	len = asn1_ex_i2c(pval, NULL, &utype, it);

	/* If SEQUENCE, SET or OTHER then header is
	 * included in pseudo content octets so don't
	 * include tag+length. We need to check here
	 * because the call to asn1_ex_i2c() could change
	 * utype.
	 */
	if ((utype == V_ASN1_SEQUENCE) || (utype == V_ASN1_SET) ||
	    (utype == V_ASN1_OTHER))
		usetag = 0;
	else
		usetag = 1;

	/* -1 means omit type */
	if (len == -1)
		return 0;

	/* -2 return is special meaning use ndef */
	if (len == -2) {
		ndef = 2;
		len = 0;
	}

	/* If not implicitly tagged get tag from underlying type */
	if (tag == -1)
		tag = utype;

	/* Output tag+length followed by content octets */
	if (out) {
		if (usetag)
			ASN1_put_object(out, ndef, len, tag, aclass);
		asn1_ex_i2c(pval, *out, &utype, it);
		if (ndef)
			ASN1_put_eoc(out);
		else
			*out += len;
	}

	if (usetag)
		return ASN1_object_size(ndef, len, tag);
	return len;
}


ASN1_INTEGER *
ASN1_INTEGER_new(void)
{
	return (ASN1_INTEGER *)ASN1_item_new(&ASN1_INTEGER_it);
}


static void
asn1_item_clear(ASN1_VALUE **pval, const ASN1_ITEM *it)
{
	const ASN1_EXTERN_FUNCS *ef;

	switch (it->itype) {
	case ASN1_ITYPE_EXTERN:
		ef = it->funcs;
		if (ef && ef->asn1_ex_clear)
			ef->asn1_ex_clear(pval, it);
		else
			*pval = NULL;
		break;

	case ASN1_ITYPE_PRIMITIVE:
		if (it->templates)
			asn1_template_clear(pval, it->templates);
		else
			asn1_primitive_clear(pval, it);
		break;

	case ASN1_ITYPE_MSTRING:
		asn1_primitive_clear(pval, it);
		break;

	case ASN1_ITYPE_CHOICE:
	case ASN1_ITYPE_SEQUENCE:
	case ASN1_ITYPE_NDEF_SEQUENCE:
		*pval = NULL;
		break;
	}
}


static void
asn1_item_combine_free(ASN1_VALUE **pval, const ASN1_ITEM *it, int combine)
{
	const ASN1_TEMPLATE *tt = NULL, *seqtt;
	const ASN1_EXTERN_FUNCS *ef;
	const ASN1_AUX *aux = it->funcs;
	ASN1_aux_cb *asn1_cb = NULL;
	int i;

	if (pval == NULL || *pval == NULL)
		return;

	if (aux != NULL && aux->asn1_cb != NULL)
		asn1_cb = aux->asn1_cb;

	switch (it->itype) {
	case ASN1_ITYPE_PRIMITIVE:
		if (it->templates)
			ASN1_template_free(pval, it->templates);
		else
			ASN1_primitive_free(pval, it);
		break;

	case ASN1_ITYPE_MSTRING:
		ASN1_primitive_free(pval, it);
		break;

	case ASN1_ITYPE_CHOICE:
		if (asn1_cb) {
			i = asn1_cb(ASN1_OP_FREE_PRE, pval, it, NULL);
			if (i == 2)
				return;
		}
		i = asn1_get_choice_selector(pval, it);
		if ((i >= 0) && (i < it->tcount)) {
			ASN1_VALUE **pchval;
			tt = it->templates + i;
			pchval = asn1_get_field_ptr(pval, tt);
			ASN1_template_free(pchval, tt);
		}
		if (asn1_cb)
			asn1_cb(ASN1_OP_FREE_POST, pval, it, NULL);
		if (!combine) {
			free(*pval);
			*pval = NULL;
		}
		break;

	case ASN1_ITYPE_EXTERN:
		ef = it->funcs;
		if (ef && ef->asn1_ex_free)
			ef->asn1_ex_free(pval, it);
		break;

	case ASN1_ITYPE_NDEF_SEQUENCE:
	case ASN1_ITYPE_SEQUENCE:
		if (asn1_do_lock(pval, -1, it) > 0)
			return;
		if (asn1_cb) {
			i = asn1_cb(ASN1_OP_FREE_PRE, pval, it, NULL);
			if (i == 2)
				return;
		}
		asn1_enc_free(pval, it);
		/* If we free up as normal we will invalidate any
		 * ANY DEFINED BY field and we wont be able to
		 * determine the type of the field it defines. So
		 * free up in reverse order.
		 */
		tt = it->templates + it->tcount - 1;
		for (i = 0; i < it->tcount; tt--, i++) {
			ASN1_VALUE **pseqval;
			seqtt = asn1_do_adb(pval, tt, 0);
			if (!seqtt)
				continue;
			pseqval = asn1_get_field_ptr(pval, seqtt);
			ASN1_template_free(pseqval, seqtt);
		}
		if (asn1_cb)
			asn1_cb(ASN1_OP_FREE_POST, pval, it, NULL);
		if (!combine) {
			free(*pval);
			*pval = NULL;
		}
		break;
	}
}


ASN1_VALUE *
ASN1_item_d2i(ASN1_VALUE **pval, const unsigned char **in, long len,
    const ASN1_ITEM *it)
{
	ASN1_TLC c;
	ASN1_VALUE *ptmpval = NULL;

	if (!pval)
		pval = &ptmpval;
	asn1_tlc_clear_nc(&c);
	if (ASN1_item_ex_d2i(pval, in, len, it, -1, 0, 0, &c) > 0)
		return *pval;
	return NULL;
}


static int
asn1_item_ex_combine_new(ASN1_VALUE **pval, const ASN1_ITEM *it, int combine)
{
	const ASN1_TEMPLATE *tt = NULL;
	const ASN1_EXTERN_FUNCS *ef;
	const ASN1_AUX *aux = it->funcs;
	ASN1_aux_cb *asn1_cb = NULL;
	ASN1_VALUE **pseqval;
	int i;

	if (aux != NULL && aux->asn1_cb != NULL)
		asn1_cb = aux->asn1_cb;

	if (!combine)
		*pval = NULL;

#ifdef CRYPTO_MDEBUG
	if (it->sname)
		CRYPTO_push_info(it->sname);
#endif

	switch (it->itype) {
	case ASN1_ITYPE_EXTERN:
		ef = it->funcs;
		if (ef && ef->asn1_ex_new) {
			if (!ef->asn1_ex_new(pval, it))
				goto memerr;
		}
		break;

	case ASN1_ITYPE_PRIMITIVE:
		if (it->templates) {
			if (!ASN1_template_new(pval, it->templates))
				goto memerr;
		} else if (!ASN1_primitive_new(pval, it))
			goto memerr;
		break;

	case ASN1_ITYPE_MSTRING:
		if (!ASN1_primitive_new(pval, it))
			goto memerr;
		break;

	case ASN1_ITYPE_CHOICE:
		if (asn1_cb) {
			i = asn1_cb(ASN1_OP_NEW_PRE, pval, it, NULL);
			if (!i)
				goto auxerr;
			if (i == 2) {
#ifdef CRYPTO_MDEBUG
				if (it->sname)
					CRYPTO_pop_info();
#endif
				return 1;
			}
		}
		if (!combine) {
			*pval = calloc(1, it->size);
			if (!*pval)
				goto memerr;
		}
		asn1_set_choice_selector(pval, -1, it);
		if (asn1_cb && !asn1_cb(ASN1_OP_NEW_POST, pval, it, NULL))
			goto auxerr;
		break;

	case ASN1_ITYPE_NDEF_SEQUENCE:
	case ASN1_ITYPE_SEQUENCE:
		if (asn1_cb) {
			i = asn1_cb(ASN1_OP_NEW_PRE, pval, it, NULL);
			if (!i)
				goto auxerr;
			if (i == 2) {
#ifdef CRYPTO_MDEBUG
				if (it->sname)
					CRYPTO_pop_info();
#endif
				return 1;
			}
		}
		if (!combine) {
			*pval = calloc(1, it->size);
			if (!*pval)
				goto memerr;
			asn1_do_lock(pval, 0, it);
			asn1_enc_init(pval, it);
		}
		for (i = 0, tt = it->templates; i < it->tcount; tt++, i++) {
			pseqval = asn1_get_field_ptr(pval, tt);
			if (!ASN1_template_new(pseqval, tt))
				goto memerr;
		}
		if (asn1_cb && !asn1_cb(ASN1_OP_NEW_POST, pval, it, NULL))
			goto auxerr;
		break;
	}
#ifdef CRYPTO_MDEBUG
	if (it->sname)
		CRYPTO_pop_info();
#endif
	return 1;

memerr:
	ASN1err(ASN1_F_ASN1_ITEM_EX_COMBINE_NEW, ERR_R_MALLOC_FAILURE);
#ifdef CRYPTO_MDEBUG
	if (it->sname)
		CRYPTO_pop_info();
#endif
	return 0;

auxerr:
	ASN1err(ASN1_F_ASN1_ITEM_EX_COMBINE_NEW, ASN1_R_AUX_ERROR);
	ASN1_item_ex_free(pval, it);
#ifdef CRYPTO_MDEBUG
	if (it->sname)
		CRYPTO_pop_info();
#endif
	return 0;

}


int
ASN1_item_ex_d2i(ASN1_VALUE **pval, const unsigned char **in, long len,
    const ASN1_ITEM *it, int tag, int aclass, char opt, ASN1_TLC *ctx)
{
	const ASN1_TEMPLATE *tt, *errtt = NULL;
	const ASN1_EXTERN_FUNCS *ef;
	const ASN1_AUX *aux = it->funcs;
	ASN1_aux_cb *asn1_cb;
	const unsigned char *p = NULL, *q;
	unsigned char oclass;
	char seq_eoc, seq_nolen, cst, isopt;
	long tmplen;
	int i;
	int otag;
	int ret = 0;
	ASN1_VALUE **pchptr;
	int combine;

	combine = aclass & ASN1_TFLG_COMBINE;
	aclass &= ~ASN1_TFLG_COMBINE;

	if (!pval)
		return 0;

	if (aux && aux->asn1_cb)
		asn1_cb = aux->asn1_cb;
	else
		asn1_cb = 0;

	switch (it->itype) {
	case ASN1_ITYPE_PRIMITIVE:
		if (it->templates) {
			/* tagging or OPTIONAL is currently illegal on an item
			 * template because the flags can't get passed down.
			 * In practice this isn't a problem: we include the
			 * relevant flags from the item template in the
			 * template itself.
			 */
			if ((tag != -1) || opt) {
				ASN1err(ASN1_F_ASN1_ITEM_EX_D2I,
				    ASN1_R_ILLEGAL_OPTIONS_ON_ITEM_TEMPLATE);
				goto err;
			}
			return asn1_template_ex_d2i(pval, in, len,
			    it->templates, opt, ctx);
		}
		return asn1_d2i_ex_primitive(pval, in, len, it,
		    tag, aclass, opt, ctx);
		break;

	case ASN1_ITYPE_MSTRING:
		p = *in;
		/* Just read in tag and class */
		ret = asn1_check_tlen(NULL, &otag, &oclass, NULL, NULL,
		    &p, len, -1, 0, 1, ctx);
		if (!ret) {
			ASN1err(ASN1_F_ASN1_ITEM_EX_D2I,
			    ERR_R_NESTED_ASN1_ERROR);
			goto err;
		}

		/* Must be UNIVERSAL class */
		if (oclass != V_ASN1_UNIVERSAL) {
			/* If OPTIONAL, assume this is OK */
			if (opt)
				return -1;
			ASN1err(ASN1_F_ASN1_ITEM_EX_D2I,
			    ASN1_R_MSTRING_NOT_UNIVERSAL);
			goto err;
		}
		/* Check tag matches bit map */
		if (!(ASN1_tag2bit(otag) & it->utype)) {
			/* If OPTIONAL, assume this is OK */
			if (opt)
				return -1;
			ASN1err(ASN1_F_ASN1_ITEM_EX_D2I,
			    ASN1_R_MSTRING_WRONG_TAG);
			goto err;
		}
		return asn1_d2i_ex_primitive(pval, in, len,
		    it, otag, 0, 0, ctx);

	case ASN1_ITYPE_EXTERN:
		/* Use new style d2i */
		ef = it->funcs;
		return ef->asn1_ex_d2i(pval, in, len,
		    it, tag, aclass, opt, ctx);

	case ASN1_ITYPE_CHOICE:
		if (asn1_cb && !asn1_cb(ASN1_OP_D2I_PRE, pval, it, NULL))
			goto auxerr;

		if (*pval) {
			/* Free up and zero CHOICE value if initialised */
			i = asn1_get_choice_selector(pval, it);
			if ((i >= 0) && (i < it->tcount)) {
				tt = it->templates + i;
				pchptr = asn1_get_field_ptr(pval, tt);
				ASN1_template_free(pchptr, tt);
				asn1_set_choice_selector(pval, -1, it);
			}
		} else if (!ASN1_item_ex_new(pval, it)) {
			ASN1err(ASN1_F_ASN1_ITEM_EX_D2I,
			    ERR_R_NESTED_ASN1_ERROR);
			goto err;
		}
		/* CHOICE type, try each possibility in turn */
		p = *in;
		for (i = 0, tt = it->templates; i < it->tcount; i++, tt++) {
			pchptr = asn1_get_field_ptr(pval, tt);
			/* We mark field as OPTIONAL so its absence
			 * can be recognised.
			 */
			ret = asn1_template_ex_d2i(pchptr, &p, len, tt, 1, ctx);
			/* If field not present, try the next one */
			if (ret == -1)
				continue;
			/* If positive return, read OK, break loop */
			if (ret > 0)
				break;
			/* Otherwise must be an ASN1 parsing error */
			errtt = tt;
			ASN1err(ASN1_F_ASN1_ITEM_EX_D2I,
			    ERR_R_NESTED_ASN1_ERROR);
			goto err;
		}

		/* Did we fall off the end without reading anything? */
		if (i == it->tcount) {
			/* If OPTIONAL, this is OK */
			if (opt) {
				/* Free and zero it */
				ASN1_item_ex_free(pval, it);
				return -1;
			}
			ASN1err(ASN1_F_ASN1_ITEM_EX_D2I,
			    ASN1_R_NO_MATCHING_CHOICE_TYPE);
			goto err;
		}

		asn1_set_choice_selector(pval, i, it);
		*in = p;
		if (asn1_cb && !asn1_cb(ASN1_OP_D2I_POST, pval, it, NULL))
			goto auxerr;
		return 1;

	case ASN1_ITYPE_NDEF_SEQUENCE:
	case ASN1_ITYPE_SEQUENCE:
		p = *in;
		tmplen = len;

		/* If no IMPLICIT tagging set to SEQUENCE, UNIVERSAL */
		if (tag == -1) {
			tag = V_ASN1_SEQUENCE;
			aclass = V_ASN1_UNIVERSAL;
		}
		/* Get SEQUENCE length and update len, p */
		ret = asn1_check_tlen(&len, NULL, NULL, &seq_eoc, &cst,
		    &p, len, tag, aclass, opt, ctx);
		if (!ret) {
			ASN1err(ASN1_F_ASN1_ITEM_EX_D2I,
			    ERR_R_NESTED_ASN1_ERROR);
			goto err;
		} else if (ret == -1)
			return -1;
		if (aux && (aux->flags & ASN1_AFLG_BROKEN)) {
			len = tmplen - (p - *in);
			seq_nolen = 1;
		}
		/* If indefinite we don't do a length check */
		else
			seq_nolen = seq_eoc;
		if (!cst) {
			ASN1err(ASN1_F_ASN1_ITEM_EX_D2I,
			    ASN1_R_SEQUENCE_NOT_CONSTRUCTED);
			goto err;
		}

		if (!*pval && !ASN1_item_ex_new(pval, it)) {
			ASN1err(ASN1_F_ASN1_ITEM_EX_D2I,
			    ERR_R_NESTED_ASN1_ERROR);
			goto err;
		}

		if (asn1_cb && !asn1_cb(ASN1_OP_D2I_PRE, pval, it, NULL))
			goto auxerr;

		/* Free up and zero any ADB found */
		for (i = 0, tt = it->templates; i < it->tcount; i++, tt++) {
			if (tt->flags & ASN1_TFLG_ADB_MASK) {
				const ASN1_TEMPLATE *seqtt;
				ASN1_VALUE **pseqval;
				seqtt = asn1_do_adb(pval, tt, 1);
				if (!seqtt)
					goto err;
				pseqval = asn1_get_field_ptr(pval, seqtt);
				ASN1_template_free(pseqval, seqtt);
			}
		}

		/* Get each field entry */
		for (i = 0, tt = it->templates; i < it->tcount; i++, tt++) {
			const ASN1_TEMPLATE *seqtt;
			ASN1_VALUE **pseqval;
			seqtt = asn1_do_adb(pval, tt, 1);
			if (!seqtt)
				goto err;
			pseqval = asn1_get_field_ptr(pval, seqtt);
			/* Have we ran out of data? */
			if (!len)
				break;
			q = p;
			if (asn1_check_eoc(&p, len)) {
				if (!seq_eoc) {
					ASN1err(ASN1_F_ASN1_ITEM_EX_D2I,
					    ASN1_R_UNEXPECTED_EOC);
					goto err;
				}
				len -= p - q;
				seq_eoc = 0;
				q = p;
				break;
			}
			/* This determines the OPTIONAL flag value. The field
			 * cannot be omitted if it is the last of a SEQUENCE
			 * and there is still data to be read. This isn't
			 * strictly necessary but it increases efficiency in
			 * some cases.
			 */
			if (i == (it->tcount - 1))
				isopt = 0;
			else
				isopt = (char)(seqtt->flags & ASN1_TFLG_OPTIONAL);
			/* attempt to read in field, allowing each to be
			 * OPTIONAL */

			ret = asn1_template_ex_d2i(pseqval, &p, len,
			    seqtt, isopt, ctx);
			if (!ret) {
				errtt = seqtt;
				goto err;
			} else if (ret == -1) {
				/* OPTIONAL component absent.
				 * Free and zero the field.
				 */
				ASN1_template_free(pseqval, seqtt);
				continue;
			}
			/* Update length */
			len -= p - q;
		}

		/* Check for EOC if expecting one */
		if (seq_eoc && !asn1_check_eoc(&p, len)) {
			ASN1err(ASN1_F_ASN1_ITEM_EX_D2I, ASN1_R_MISSING_EOC);
			goto err;
		}
		/* Check all data read */
		if (!seq_nolen && len) {
			ASN1err(ASN1_F_ASN1_ITEM_EX_D2I,
			    ASN1_R_SEQUENCE_LENGTH_MISMATCH);
			goto err;
		}

		/* If we get here we've got no more data in the SEQUENCE,
		 * however we may not have read all fields so check all
		 * remaining are OPTIONAL and clear any that are.
		 */
		for (; i < it->tcount; tt++, i++) {
			const ASN1_TEMPLATE *seqtt;
			seqtt = asn1_do_adb(pval, tt, 1);
			if (!seqtt)
				goto err;
			if (seqtt->flags & ASN1_TFLG_OPTIONAL) {
				ASN1_VALUE **pseqval;
				pseqval = asn1_get_field_ptr(pval, seqtt);
				ASN1_template_free(pseqval, seqtt);
			} else {
				errtt = seqtt;
				ASN1err(ASN1_F_ASN1_ITEM_EX_D2I,
				    ASN1_R_FIELD_MISSING);
				goto err;
			}
		}
		/* Save encoding */
		if (!asn1_enc_save(pval, *in, p - *in, it)) {
			ASN1err(ASN1_F_ASN1_ITEM_EX_D2I, ERR_R_MALLOC_FAILURE);
			goto auxerr;
		}
		*in = p;
		if (asn1_cb && !asn1_cb(ASN1_OP_D2I_POST, pval, it, NULL))
			goto auxerr;
		return 1;

	default:
		return 0;
	}

auxerr:
	ASN1err(ASN1_F_ASN1_ITEM_EX_D2I, ASN1_R_AUX_ERROR);
err:
	if (combine == 0)
		ASN1_item_ex_free(pval, it);
	if (errtt)
		ERR_asprintf_error_data("Field=%s, Type=%s", errtt->field_name,
		    it->sname);
	else
		ERR_asprintf_error_data("Type=%s", it->sname);
	return 0;
}


int
ASN1_item_ex_i2d(ASN1_VALUE **pval, unsigned char **out, const ASN1_ITEM *it,
    int tag, int aclass)
{
	const ASN1_TEMPLATE *tt = NULL;
	int i, seqcontlen, seqlen, ndef = 1;
	const ASN1_EXTERN_FUNCS *ef;
	const ASN1_AUX *aux = it->funcs;
	ASN1_aux_cb *asn1_cb = NULL;

	if ((it->itype != ASN1_ITYPE_PRIMITIVE) && !*pval)
		return 0;

	if (aux && aux->asn1_cb)
		asn1_cb = aux->asn1_cb;

	switch (it->itype) {

	case ASN1_ITYPE_PRIMITIVE:
		if (it->templates)
			return asn1_template_ex_i2d(pval, out, it->templates,
			    tag, aclass);
		return asn1_i2d_ex_primitive(pval, out, it, tag, aclass);
		break;

	case ASN1_ITYPE_MSTRING:
		return asn1_i2d_ex_primitive(pval, out, it, -1, aclass);

	case ASN1_ITYPE_CHOICE:
		if (asn1_cb && !asn1_cb(ASN1_OP_I2D_PRE, pval, it, NULL))
			return 0;
		i = asn1_get_choice_selector(pval, it);
		if ((i >= 0) && (i < it->tcount)) {
			ASN1_VALUE **pchval;
			const ASN1_TEMPLATE *chtt;
			chtt = it->templates + i;
			pchval = asn1_get_field_ptr(pval, chtt);
			return asn1_template_ex_i2d(pchval, out, chtt,
			    -1, aclass);
		}
		/* Fixme: error condition if selector out of range */
		if (asn1_cb && !asn1_cb(ASN1_OP_I2D_POST, pval, it, NULL))
			return 0;
		break;

	case ASN1_ITYPE_EXTERN:
		/* If new style i2d it does all the work */
		ef = it->funcs;
		return ef->asn1_ex_i2d(pval, out, it, tag, aclass);

	case ASN1_ITYPE_NDEF_SEQUENCE:
		/* Use indefinite length constructed if requested */
		if (aclass & ASN1_TFLG_NDEF)
			ndef = 2;
		/* fall through */

	case ASN1_ITYPE_SEQUENCE:
		i = asn1_enc_restore(&seqcontlen, out, pval, it);
		/* An error occurred */
		if (i < 0)
			return 0;
		/* We have a valid cached encoding... */
		if (i > 0)
			return seqcontlen;
		/* Otherwise carry on */
		seqcontlen = 0;
		/* If no IMPLICIT tagging set to SEQUENCE, UNIVERSAL */
		if (tag == -1) {
			tag = V_ASN1_SEQUENCE;
			/* Retain any other flags in aclass */
			aclass = (aclass & ~ASN1_TFLG_TAG_CLASS) |
			    V_ASN1_UNIVERSAL;
		}
		if (asn1_cb && !asn1_cb(ASN1_OP_I2D_PRE, pval, it, NULL))
			return 0;
		/* First work out sequence content length */
		for (i = 0, tt = it->templates; i < it->tcount; tt++, i++) {
			const ASN1_TEMPLATE *seqtt;
			ASN1_VALUE **pseqval;
			seqtt = asn1_do_adb(pval, tt, 1);
			if (!seqtt)
				return 0;
			pseqval = asn1_get_field_ptr(pval, seqtt);
			/* FIXME: check for errors in enhanced version */
			seqcontlen += asn1_template_ex_i2d(pseqval, NULL, seqtt,
			    -1, aclass);
		}

		seqlen = ASN1_object_size(ndef, seqcontlen, tag);
		if (!out)
			return seqlen;
		/* Output SEQUENCE header */
		ASN1_put_object(out, ndef, seqcontlen, tag, aclass);
		for (i = 0, tt = it->templates; i < it->tcount; tt++, i++) {
			const ASN1_TEMPLATE *seqtt;
			ASN1_VALUE **pseqval;
			seqtt = asn1_do_adb(pval, tt, 1);
			if (!seqtt)
				return 0;
			pseqval = asn1_get_field_ptr(pval, seqtt);
			/* FIXME: check for errors in enhanced version */
			asn1_template_ex_i2d(pseqval, out, seqtt, -1, aclass);
		}
		if (ndef == 2)
			ASN1_put_eoc(out);
		if (asn1_cb && !asn1_cb(ASN1_OP_I2D_POST, pval, it, NULL))
			return 0;
		return seqlen;

	default:
		return 0;

	}
	return 0;
}


int
ASN1_item_ex_new(ASN1_VALUE **pval, const ASN1_ITEM *it)
{
	return asn1_item_ex_combine_new(pval, it, 0);
}


static int
asn1_item_flags_i2d(ASN1_VALUE *val, unsigned char **out, const ASN1_ITEM *it,
    int flags)
{
	if (out && !*out) {
		unsigned char *p, *buf;
		int len;
		len = ASN1_item_ex_i2d(&val, NULL, it, -1, flags);
		if (len <= 0)
			return len;
		buf = malloc(len);
		if (!buf)
			return -1;
		p = buf;
		ASN1_item_ex_i2d(&val, &p, it, -1, flags);
		*out = buf;
		return len;
	}

	return ASN1_item_ex_i2d(&val, out, it, -1, flags);
}


void
ASN1_item_free(ASN1_VALUE *val, const ASN1_ITEM *it)
{
	asn1_item_combine_free(&val, it, 0);
}


int
ASN1_item_i2d(ASN1_VALUE *val, unsigned char **out, const ASN1_ITEM *it)
{
	return asn1_item_flags_i2d(val, out, it, 0);
}


ASN1_VALUE *
ASN1_item_new(const ASN1_ITEM *it)
{
	ASN1_VALUE *ret = NULL;
	if (ASN1_item_ex_new(&ret, it) > 0)
		return ret;
	return NULL;
}


int
ASN1_mbstring_copy(ASN1_STRING **out, const unsigned char *in, int len,
    int inform, unsigned long mask)
{
	return ASN1_mbstring_ncopy(out, in, len, inform, mask, 0, 0);
}


int
ASN1_mbstring_ncopy(ASN1_STRING **out, const unsigned char *in, int len,
    int inform, unsigned long mask, long minsize, long maxsize)
{
	int str_type;
	int ret;
	char free_out;
	int outform, outlen = 0;
	ASN1_STRING *dest;
	unsigned char *p;
	int nchar;
	int (*cpyfunc)(unsigned long, void *) = NULL;

	if (len < 0)
		len = strlen((const char *)in);
	if (!mask)
		mask = DIRSTRING_TYPE;

	/* First do a string check and work out the number of characters */
	switch (inform) {
	case MBSTRING_BMP:
		if (len & 1) {
			ASN1err(ASN1_F_ASN1_MBSTRING_NCOPY,
			    ASN1_R_INVALID_BMPSTRING_LENGTH);
			return -1;
		}
		nchar = len >> 1;
		break;

	case MBSTRING_UNIV:
		if (len & 3) {
			ASN1err(ASN1_F_ASN1_MBSTRING_NCOPY,
			    ASN1_R_INVALID_UNIVERSALSTRING_LENGTH);
			return -1;
		}
		nchar = len >> 2;
		break;

	case MBSTRING_UTF8:
		nchar = 0;
		/* This counts the characters and does utf8 syntax checking */
		ret = traverse_string(in, len, MBSTRING_UTF8, in_utf8, &nchar);
		if (ret < 0) {
			ASN1err(ASN1_F_ASN1_MBSTRING_NCOPY,
			    ASN1_R_INVALID_UTF8STRING);
			return -1;
		}
		break;

	case MBSTRING_ASC:
		nchar = len;
		break;

	default:
		ASN1err(ASN1_F_ASN1_MBSTRING_NCOPY, ASN1_R_UNKNOWN_FORMAT);
		return -1;
	}

	if ((minsize > 0) && (nchar < minsize)) {
		ASN1err(ASN1_F_ASN1_MBSTRING_NCOPY, ASN1_R_STRING_TOO_SHORT);
		ERR_asprintf_error_data("minsize=%ld", minsize);
		return -1;
	}

	if ((maxsize > 0) && (nchar > maxsize)) {
		ASN1err(ASN1_F_ASN1_MBSTRING_NCOPY, ASN1_R_STRING_TOO_LONG);
		ERR_asprintf_error_data("maxsize=%ld", maxsize);
		return -1;
	}

	/* Now work out minimal type (if any) */
	if (traverse_string(in, len, inform, type_str, &mask) < 0) {
		ASN1err(ASN1_F_ASN1_MBSTRING_NCOPY, ASN1_R_ILLEGAL_CHARACTERS);
		return -1;
	}


	/* Now work out output format and string type */
	outform = MBSTRING_ASC;
	if (mask & B_ASN1_PRINTABLESTRING)
		str_type = V_ASN1_PRINTABLESTRING;
	else if (mask & B_ASN1_IA5STRING)
		str_type = V_ASN1_IA5STRING;
	else if (mask & B_ASN1_T61STRING)
		str_type = V_ASN1_T61STRING;
	else if (mask & B_ASN1_BMPSTRING) {
		str_type = V_ASN1_BMPSTRING;
		outform = MBSTRING_BMP;
	} else if (mask & B_ASN1_UNIVERSALSTRING) {
		str_type = V_ASN1_UNIVERSALSTRING;
		outform = MBSTRING_UNIV;
	} else {
		str_type = V_ASN1_UTF8STRING;
		outform = MBSTRING_UTF8;
	}
	if (!out)
		return str_type;
	if (*out) {
		free_out = 0;
		dest = *out;
		if (dest->data) {
			dest->length = 0;
			free(dest->data);
			dest->data = NULL;
		}
		dest->type = str_type;
	} else {
		free_out = 1;
		dest = ASN1_STRING_type_new(str_type);
		if (!dest) {
			ASN1err(ASN1_F_ASN1_MBSTRING_NCOPY,
			    ERR_R_MALLOC_FAILURE);
			return -1;
		}
		*out = dest;
	}
	/* If both the same type just copy across */
	if (inform == outform) {
		if (!ASN1_STRING_set(dest, in, len)) {
			ASN1err(ASN1_F_ASN1_MBSTRING_NCOPY,
			    ERR_R_MALLOC_FAILURE);
			goto err;
		}
		return str_type;
	}

	/* Work out how much space the destination will need */
	switch (outform) {
	case MBSTRING_ASC:
		outlen = nchar;
		cpyfunc = cpy_asc;
		break;

	case MBSTRING_BMP:
		outlen = nchar << 1;
		cpyfunc = cpy_bmp;
		break;

	case MBSTRING_UNIV:
		outlen = nchar << 2;
		cpyfunc = cpy_univ;
		break;

	case MBSTRING_UTF8:
		outlen = 0;
		if (traverse_string(in, len, inform, out_utf8, &outlen) < 0) {
			ASN1err(ASN1_F_ASN1_MBSTRING_NCOPY,
			    ASN1_R_ILLEGAL_CHARACTERS);
			goto err;
		}
		cpyfunc = cpy_utf8;
		break;
	}
	if (!(p = malloc(outlen + 1))) {
		ASN1err(ASN1_F_ASN1_MBSTRING_NCOPY, ERR_R_MALLOC_FAILURE);
		goto err;
	}
	dest->length = outlen;
	dest->data = p;
	p[outlen] = 0;
	traverse_string(in, len, inform, cpyfunc, &p);
	return str_type;

err:
	if (free_out) {
		ASN1_STRING_free(dest);
		*out = NULL;
	}
	return -1;
}


void
ASN1_OBJECT_free(ASN1_OBJECT *a)
{
	if (a == NULL)
		return;
	if (a->flags & ASN1_OBJECT_FLAG_DYNAMIC_STRINGS) {
		free((void *)a->sn);
		free((void *)a->ln);
		a->sn = a->ln = NULL;
	}
	if (a->flags & ASN1_OBJECT_FLAG_DYNAMIC_DATA) {
		if (a->data != NULL)
			explicit_bzero((void *)a->data, a->length);
		free((void *)a->data);
		a->data = NULL;
		a->length = 0;
	}
	if (a->flags & ASN1_OBJECT_FLAG_DYNAMIC)
		free(a);
}


ASN1_OBJECT *
ASN1_OBJECT_new(void)
{
	ASN1_OBJECT *ret;

	ret = malloc(sizeof(ASN1_OBJECT));
	if (ret == NULL) {
		ASN1err(ASN1_F_ASN1_OBJECT_NEW, ERR_R_MALLOC_FAILURE);
		return (NULL);
	}
	ret->length = 0;
	ret->data = NULL;
	ret->nid = 0;
	ret->sn = NULL;
	ret->ln = NULL;
	ret->flags = ASN1_OBJECT_FLAG_DYNAMIC;
	return (ret);
}


int
ASN1_object_size(int constructed, int length, int tag)
{
	int ret;

	ret = length;
	ret++;
	if (tag >= 31) {
		while (tag > 0) {
			tag >>= 7;
			ret++;
		}
	}
	if (constructed == 2)
		return ret + 3;
	ret++;
	if (length > 127) {
		while (length > 0) {
			length >>= 8;
			ret++;
		}
	}
	return (ret);
}


ASN1_OCTET_STRING *
ASN1_OCTET_STRING_dup(const ASN1_OCTET_STRING *x)
{
	return ASN1_STRING_dup(x);
}


void
ASN1_OCTET_STRING_free(ASN1_OCTET_STRING *a)
{
	ASN1_item_free((ASN1_VALUE *)a, &ASN1_OCTET_STRING_it);
}


int
ASN1_OCTET_STRING_set(ASN1_OCTET_STRING *x, const unsigned char *d, int len)
{
	return ASN1_STRING_set(x, d, len);
}


static void
asn1_primitive_clear(ASN1_VALUE **pval, const ASN1_ITEM *it)
{
	int utype;
	if (it && it->funcs) {
		const ASN1_PRIMITIVE_FUNCS *pf = it->funcs;
		if (pf->prim_clear)
			pf->prim_clear(pval, it);
		else
			*pval = NULL;
		return;
	}
	if (!it || (it->itype == ASN1_ITYPE_MSTRING))
		utype = V_ASN1_UNDEF;
	else
		utype = it->utype;
	if (utype == V_ASN1_BOOLEAN)
		*(ASN1_BOOLEAN *)pval = it->size;
	else
		*pval = NULL;
}


void
ASN1_primitive_free(ASN1_VALUE **pval, const ASN1_ITEM *it)
{
	int utype;
	if (it) {
		const ASN1_PRIMITIVE_FUNCS *pf;
		pf = it->funcs;
		if (pf && pf->prim_free) {
			pf->prim_free(pval, it);
			return;
		}
	}
	/* Special case: if 'it' is NULL free contents of ASN1_TYPE */
	if (!it) {
		ASN1_TYPE *typ = (ASN1_TYPE *)*pval;
		utype = typ->type;
		pval = &typ->value.asn1_value;
		if (!*pval)
			return;
	} else if (it->itype == ASN1_ITYPE_MSTRING) {
		utype = -1;
		if (!*pval)
			return;
	} else {
		utype = it->utype;
		if ((utype != V_ASN1_BOOLEAN) && !*pval)
			return;
	}

	switch (utype) {
	case V_ASN1_OBJECT:
		ASN1_OBJECT_free((ASN1_OBJECT *)*pval);
		break;

	case V_ASN1_BOOLEAN:
		if (it)
			*(ASN1_BOOLEAN *)pval = it->size;
		else
			*(ASN1_BOOLEAN *)pval = -1;
		return;

	case V_ASN1_NULL:
		break;

	case V_ASN1_ANY:
		ASN1_primitive_free(pval, NULL);
		free(*pval);
		break;

	default:
		ASN1_STRING_free((ASN1_STRING *)*pval);
		break;
	}
	*pval = NULL;
}


int
ASN1_primitive_new(ASN1_VALUE **pval, const ASN1_ITEM *it)
{
	ASN1_TYPE *typ;
	ASN1_STRING *str;
	int utype;

	if (it && it->funcs) {
		const ASN1_PRIMITIVE_FUNCS *pf = it->funcs;
		if (pf->prim_new)
			return pf->prim_new(pval, it);
	}

	if (!it || (it->itype == ASN1_ITYPE_MSTRING))
		utype = V_ASN1_UNDEF;
	else
		utype = it->utype;
	switch (utype) {
	case V_ASN1_OBJECT:
		*pval = (ASN1_VALUE *)OBJ_nid2obj(NID_undef);
		return 1;

	case V_ASN1_BOOLEAN:
		*(ASN1_BOOLEAN *)pval = it->size;
		return 1;

	case V_ASN1_NULL:
		*pval = (ASN1_VALUE *)1;
		return 1;

	case V_ASN1_ANY:
		typ = malloc(sizeof(ASN1_TYPE));
		if (typ != NULL) {
			typ->value.ptr = NULL;
			typ->type = V_ASN1_UNDEF;
		}
		*pval = (ASN1_VALUE *)typ;
		break;

	default:
		str = ASN1_STRING_type_new(utype);
		if (it != NULL && it->itype == ASN1_ITYPE_MSTRING &&
		    str != NULL)
			str->flags |= ASN1_STRING_FLAG_MSTRING;
		*pval = (ASN1_VALUE *)str;
		break;
	}
	if (*pval)
		return 1;
	return 0;
}


static void
asn1_put_length(unsigned char **pp, int length)
{
	unsigned char *p= *pp;

	int i, l;
	if (length <= 127)
		*(p++) = (unsigned char)length;
	else {
		l = length;
		for (i = 0; l > 0; i++)
			l >>= 8;
		*(p++) = i | 0x80;
		l = i;
		while (i-- > 0) {
			p[i] = length & 0xff;
			length >>= 8;
		}
		p += l;
	}
	*pp = p;
}


void
ASN1_put_object(unsigned char **pp, int constructed, int length, int tag,
    int xclass)
{
	unsigned char *p= *pp;
	int i, ttag;

	i = (constructed) ? V_ASN1_CONSTRUCTED : 0;
	i |= (xclass & V_ASN1_PRIVATE);
	if (tag < 31)
		*(p++) = i | (tag & V_ASN1_PRIMITIVE_TAG);
	else {
		*(p++) = i | V_ASN1_PRIMITIVE_TAG;
		for(i = 0, ttag = tag; ttag > 0; i++)
			ttag >>= 7;
		ttag = i;
		while (i-- > 0) {
			p[i] = tag & 0x7f;
			if (i != (ttag - 1))
				p[i] |= 0x80;
			tag >>= 7;
		}
		p += ttag;
	}
	if (constructed == 2)
		*(p++) = 0x80;
	else
		asn1_put_length(&p, length);
	*pp = p;
}


static int
asn1_set_seq_out(STACK_OF(ASN1_VALUE) *sk, unsigned char **out, int skcontlen,
    const ASN1_ITEM *item, int do_sort, int iclass)
{
	int i;
	ASN1_VALUE *skitem;
	unsigned char *tmpdat = NULL, *p = NULL;
	DER_ENC *derlst = NULL, *tder;

	if (do_sort) {
		/* Don't need to sort less than 2 items */
		if (sk_ASN1_VALUE_num(sk) < 2)
			do_sort = 0;
		else {
			derlst = reallocarray(NULL, sk_ASN1_VALUE_num(sk),
			    sizeof(*derlst));
			tmpdat = malloc(skcontlen);
			if (!derlst || !tmpdat) {
				free(derlst);
				free(tmpdat);
				return 0;
			}
		}
	}
	/* If not sorting just output each item */
	if (!do_sort) {
		for (i = 0; i < sk_ASN1_VALUE_num(sk); i++) {
			skitem = sk_ASN1_VALUE_value(sk, i);
			ASN1_item_ex_i2d(&skitem, out, item, -1, iclass);
		}
		return 1;
	}
	p = tmpdat;

	/* Doing sort: build up a list of each member's DER encoding */
	for (i = 0, tder = derlst; i < sk_ASN1_VALUE_num(sk); i++, tder++) {
		skitem = sk_ASN1_VALUE_value(sk, i);
		tder->data = p;
		tder->length = ASN1_item_ex_i2d(&skitem, &p, item, -1, iclass);
		tder->field = skitem;
	}

	/* Now sort them */
	qsort(derlst, sk_ASN1_VALUE_num(sk), sizeof(*derlst), der_cmp);
	/* Output sorted DER encoding */
	p = *out;
	for (i = 0, tder = derlst; i < sk_ASN1_VALUE_num(sk); i++, tder++) {
		memcpy(p, tder->data, tder->length);
		p += tder->length;
	}
	*out = p;
	/* If do_sort is 2 then reorder the STACK */
	if (do_sort == 2) {
		for (i = 0, tder = derlst; i < sk_ASN1_VALUE_num(sk); i++, tder++)
			(void)sk_ASN1_VALUE_set(sk, i, tder->field);
	}
	free(derlst);
	free(tmpdat);
	return 1;
}


static int
asn1_string_canon(ASN1_STRING *out, ASN1_STRING *in)
{
	unsigned char *to, *from;
	int len, i;

	/* If type not in bitmask just copy string across */
	if (!(ASN1_tag2bit(in->type) & ASN1_MASK_CANON)) {
		if (!ASN1_STRING_copy(out, in))
			return 0;
		return 1;
	}

	out->type = V_ASN1_UTF8STRING;
	out->length = ASN1_STRING_to_UTF8(&out->data, in);
	if (out->length == -1)
		return 0;

	to = out->data;
	from = to;

	len = out->length;

	/* Convert string in place to canonical form.
	 * Ultimately we may need to handle a wider range of characters
	 * but for now ignore anything with MSB set and rely on the
	 * isspace() and tolower() functions.
	 */

	/* Ignore leading spaces */
	while ((len > 0) && !(*from & 0x80) && isspace(*from)) {
		from++;
		len--;
	}

	to = from + len - 1;

	/* Ignore trailing spaces */
	while ((len > 0) && !(*to & 0x80) && isspace(*to)) {
		to--;
		len--;
	}

	to = out->data;

	i = 0;
	while (i < len) {
		/* If MSB set just copy across */
		if (*from & 0x80) {
			*to++ = *from++;
			i++;
		}
		/* Collapse multiple spaces */
		else if (isspace(*from)) {
			/* Copy one space across */
			*to++ = ' ';
			/* Ignore subsequent spaces. Note: don't need to
			 * check len here because we know the last
			 * character is a non-space so we can't overflow.
			 */
			do {
				from++;
				i++;
			} while (!(*from & 0x80) && isspace(*from));
		} else {
			*to++ = tolower(*from);
			from++;
			i++;
		}
	}

	out->length = to - out->data;

	return 1;
}


int
ASN1_STRING_copy(ASN1_STRING *dst, const ASN1_STRING *str)
{
	if (str == NULL)
		return 0;
	dst->type = str->type;
	if (!ASN1_STRING_set(dst, str->data, str->length))
		return 0;
	dst->flags = str->flags;
	return 1;
}


ASN1_STRING *
ASN1_STRING_dup(const ASN1_STRING *str)
{
	ASN1_STRING *ret;

	if (!str)
		return NULL;
	ret = ASN1_STRING_new();
	if (!ret)
		return NULL;
	if (!ASN1_STRING_copy(ret, str)) {
		ASN1_STRING_free(ret);
		return NULL;
	}
	return ret;
}


void
ASN1_STRING_free(ASN1_STRING *a)
{
	if (a == NULL)
		return;
	if (a->data != NULL && !(a->flags & ASN1_STRING_FLAG_NDEF)) {
		explicit_bzero(a->data, a->length);
		free(a->data);
	}
	free(a);
}


ASN1_STRING *
ASN1_STRING_new(void)
{
	return (ASN1_STRING_type_new(V_ASN1_OCTET_STRING));
}


int
ASN1_STRING_set(ASN1_STRING *str, const void *_data, int len)
{
	const char *data = _data;

	if (len < 0) {
		if (data == NULL)
			return (0);
		else
			len = strlen(data);
	}
	if ((str->length < len) || (str->data == NULL)) {
		unsigned char *tmp;
		tmp = realloc(str->data, len + 1);
		if (tmp == NULL) {
			ASN1err(ASN1_F_ASN1_STRING_SET, ERR_R_MALLOC_FAILURE);
			return (0);
		}
		str->data = tmp;
	}
	str->length = len;
	if (data != NULL) {
		memmove(str->data, data, len);
	}
	str->data[str->length]='\0';
	return (1);
}
ASN1_STRING_set0(ASN1_STRING *str, void *data, int len)
{
	if (str->data != NULL)
		explicit_bzero(str->data, str->length);
	free(str->data);
	str->data = data;
	str->length = len;
}


int
ASN1_STRING_to_UTF8(unsigned char **out, ASN1_STRING *in)
{
	ASN1_STRING stmp, *str = &stmp;
	int mbflag, type, ret;

	if (!in)
		return -1;
	type = in->type;
	if ((type < 0) || (type > 30))
		return -1;
	mbflag = tag2nbyte[type];
	if (mbflag == -1)
		return -1;
	mbflag |= MBSTRING_FLAG;
	stmp.data = NULL;
	stmp.length = 0;
	ret = ASN1_mbstring_copy(&str, in->data, in->length, mbflag,
	    B_ASN1_UTF8STRING);
	if (ret < 0)
		return ret;
	*out = stmp.data;
	return stmp.length;
}


ASN1_STRING *
ASN1_STRING_type_new(int type)
{
	ASN1_STRING *ret;

	ret = malloc(sizeof(ASN1_STRING));
	if (ret == NULL) {
		ASN1err(ASN1_F_ASN1_STRING_TYPE_NEW, ERR_R_MALLOC_FAILURE);
		return (NULL);
	}
	ret->length = 0;
	ret->type = type;
	ret->data = NULL;
	ret->flags = 0;
	return (ret);
}


unsigned long
ASN1_tag2bit(int tag)
{
	if ((tag < 0) || (tag > 30))
		return 0;
	return tag2bit[tag];
}


static void
asn1_template_clear(ASN1_VALUE **pval, const ASN1_TEMPLATE *tt)
{
	/* If ADB or STACK just NULL the field */
	if (tt->flags & (ASN1_TFLG_ADB_MASK|ASN1_TFLG_SK_MASK))
		*pval = NULL;
	else
		asn1_item_clear(pval, ASN1_ITEM_ptr(tt->item));
}


static int
asn1_template_ex_d2i(ASN1_VALUE **val, const unsigned char **in, long inlen,
    const ASN1_TEMPLATE *tt, char opt, ASN1_TLC *ctx)
{
	int flags, aclass;
	int ret;
	long len;
	const unsigned char *p, *q;
	char exp_eoc;

	if (!val)
		return 0;
	flags = tt->flags;
	aclass = flags & ASN1_TFLG_TAG_CLASS;

	p = *in;

	/* Check if EXPLICIT tag expected */
	if (flags & ASN1_TFLG_EXPTAG) {
		char cst;
		/* Need to work out amount of data available to the inner
		 * content and where it starts: so read in EXPLICIT header to
		 * get the info.
		 */
		ret = asn1_check_tlen(&len, NULL, NULL, &exp_eoc, &cst,
		    &p, inlen, tt->tag, aclass, opt, ctx);
		q = p;
		if (!ret) {
			ASN1err(ASN1_F_ASN1_TEMPLATE_EX_D2I,
			    ERR_R_NESTED_ASN1_ERROR);
			return 0;
		} else if (ret == -1)
			return -1;
		if (!cst) {
			ASN1err(ASN1_F_ASN1_TEMPLATE_EX_D2I,
			    ASN1_R_EXPLICIT_TAG_NOT_CONSTRUCTED);
			return 0;
		}
		/* We've found the field so it can't be OPTIONAL now */
		ret = asn1_template_noexp_d2i(val, &p, len, tt, 0, ctx);
		if (!ret) {
			ASN1err(ASN1_F_ASN1_TEMPLATE_EX_D2I,
			    ERR_R_NESTED_ASN1_ERROR);
			return 0;
		}
		/* We read the field in OK so update length */
		len -= p - q;
		if (exp_eoc) {
			/* If NDEF we must have an EOC here */
			if (!asn1_check_eoc(&p, len)) {
				ASN1err(ASN1_F_ASN1_TEMPLATE_EX_D2I,
				    ASN1_R_MISSING_EOC);
				goto err;
			}
		} else {
			/* Otherwise we must hit the EXPLICIT tag end or its
			 * an error */
			if (len) {
				ASN1err(ASN1_F_ASN1_TEMPLATE_EX_D2I,
				    ASN1_R_EXPLICIT_LENGTH_MISMATCH);
				goto err;
			}
		}
	} else
		return asn1_template_noexp_d2i(val, in, inlen, tt, opt, ctx);

	*in = p;
	return 1;

err:
	ASN1_template_free(val, tt);
	return 0;
}


static int
asn1_template_ex_i2d(ASN1_VALUE **pval, unsigned char **out,
    const ASN1_TEMPLATE *tt, int tag, int iclass)
{
	int i, ret, flags, ttag, tclass, ndef;
	flags = tt->flags;
	/* Work out tag and class to use: tagging may come
	 * either from the template or the arguments, not both
	 * because this would create ambiguity. Additionally
	 * the iclass argument may contain some additional flags
	 * which should be noted and passed down to other levels.
	 */
	if (flags & ASN1_TFLG_TAG_MASK) {
		/* Error if argument and template tagging */
		if (tag != -1)
			/* FIXME: error code here */
			return -1;
		/* Get tagging from template */
		ttag = tt->tag;
		tclass = flags & ASN1_TFLG_TAG_CLASS;
	} else if (tag != -1) {
		/* No template tagging, get from arguments */
		ttag = tag;
		tclass = iclass & ASN1_TFLG_TAG_CLASS;
	} else {
		ttag = -1;
		tclass = 0;
	}
	/*
	 * Remove any class mask from iflag.
	 */
	iclass &= ~ASN1_TFLG_TAG_CLASS;

	/* At this point 'ttag' contains the outer tag to use,
	 * 'tclass' is the class and iclass is any flags passed
	 * to this function.
	 */

	/* if template and arguments require ndef, use it */
	if ((flags & ASN1_TFLG_NDEF) && (iclass & ASN1_TFLG_NDEF))
		ndef = 2;
	else
		ndef = 1;

	if (flags & ASN1_TFLG_SK_MASK) {
		/* SET OF, SEQUENCE OF */
		STACK_OF(ASN1_VALUE) *sk = (STACK_OF(ASN1_VALUE) *)*pval;
		int isset, sktag, skaclass;
		int skcontlen, sklen;
		ASN1_VALUE *skitem;

		if (!*pval)
			return 0;

		if (flags & ASN1_TFLG_SET_OF) {
			isset = 1;
			/* 2 means we reorder */
			if (flags & ASN1_TFLG_SEQUENCE_OF)
				isset = 2;
		} else
			isset = 0;

		/* Work out inner tag value: if EXPLICIT
		 * or no tagging use underlying type.
		 */
		if ((ttag != -1) && !(flags & ASN1_TFLG_EXPTAG)) {
			sktag = ttag;
			skaclass = tclass;
		} else {
			skaclass = V_ASN1_UNIVERSAL;
			if (isset)
				sktag = V_ASN1_SET;
			else
				sktag = V_ASN1_SEQUENCE;
		}

		/* Determine total length of items */
		skcontlen = 0;
		for (i = 0; i < sk_ASN1_VALUE_num(sk); i++) {
			skitem = sk_ASN1_VALUE_value(sk, i);
			skcontlen += ASN1_item_ex_i2d(&skitem, NULL,
			    ASN1_ITEM_ptr(tt->item), -1, iclass);
		}
		sklen = ASN1_object_size(ndef, skcontlen, sktag);
		/* If EXPLICIT need length of surrounding tag */
		if (flags & ASN1_TFLG_EXPTAG)
			ret = ASN1_object_size(ndef, sklen, ttag);
		else
			ret = sklen;

		if (!out)
			return ret;

		/* Now encode this lot... */
		/* EXPLICIT tag */
		if (flags & ASN1_TFLG_EXPTAG)
			ASN1_put_object(out, ndef, sklen, ttag, tclass);
		/* SET or SEQUENCE and IMPLICIT tag */
		ASN1_put_object(out, ndef, skcontlen, sktag, skaclass);
		/* And the stuff itself */
		asn1_set_seq_out(sk, out, skcontlen, ASN1_ITEM_ptr(tt->item),
		    isset, iclass);
		if (ndef == 2) {
			ASN1_put_eoc(out);
			if (flags & ASN1_TFLG_EXPTAG)
				ASN1_put_eoc(out);
		}

		return ret;
	}

	if (flags & ASN1_TFLG_EXPTAG) {
		/* EXPLICIT tagging */
		/* Find length of tagged item */
		i = ASN1_item_ex_i2d(pval, NULL, ASN1_ITEM_ptr(tt->item),
		    -1, iclass);
		if (!i)
			return 0;
		/* Find length of EXPLICIT tag */
		ret = ASN1_object_size(ndef, i, ttag);
		if (out) {
			/* Output tag and item */
			ASN1_put_object(out, ndef, i, ttag, tclass);
			ASN1_item_ex_i2d(pval, out, ASN1_ITEM_ptr(tt->item),
			    -1, iclass);
			if (ndef == 2)
				ASN1_put_eoc(out);
		}
		return ret;
	}

	/* Either normal or IMPLICIT tagging: combine class and flags */
	return ASN1_item_ex_i2d(pval, out, ASN1_ITEM_ptr(tt->item),
	    ttag, tclass | iclass);
}


void
ASN1_template_free(ASN1_VALUE **pval, const ASN1_TEMPLATE *tt)
{
	int i;
	if (tt->flags & ASN1_TFLG_SK_MASK) {
		STACK_OF(ASN1_VALUE) *sk = (STACK_OF(ASN1_VALUE) *)*pval;
		for (i = 0; i < sk_ASN1_VALUE_num(sk); i++) {
			ASN1_VALUE *vtmp;
			vtmp = sk_ASN1_VALUE_value(sk, i);
			asn1_item_combine_free(&vtmp, ASN1_ITEM_ptr(tt->item),
			    0);
		}
		sk_ASN1_VALUE_free(sk);
		*pval = NULL;
	} else
		asn1_item_combine_free(pval, ASN1_ITEM_ptr(tt->item),
		    tt->flags & ASN1_TFLG_COMBINE);
}


int
ASN1_template_new(ASN1_VALUE **pval, const ASN1_TEMPLATE *tt)
{
	const ASN1_ITEM *it = ASN1_ITEM_ptr(tt->item);
	int ret;

	if (tt->flags & ASN1_TFLG_OPTIONAL) {
		asn1_template_clear(pval, tt);
		return 1;
	}
	/* If ANY DEFINED BY nothing to do */

	if (tt->flags & ASN1_TFLG_ADB_MASK) {
		*pval = NULL;
		return 1;
	}
#ifdef CRYPTO_MDEBUG
	if (tt->field_name)
		CRYPTO_push_info(tt->field_name);
#endif
	/* If SET OF or SEQUENCE OF, its a STACK */
	if (tt->flags & ASN1_TFLG_SK_MASK) {
		STACK_OF(ASN1_VALUE) *skval;
		skval = sk_ASN1_VALUE_new_null();
		if (!skval) {
			ASN1err(ASN1_F_ASN1_TEMPLATE_NEW, ERR_R_MALLOC_FAILURE);
			ret = 0;
			goto done;
		}
		*pval = (ASN1_VALUE *)skval;
		ret = 1;
		goto done;
	}
	/* Otherwise pass it back to the item routine */
	ret = asn1_item_ex_combine_new(pval, it, tt->flags & ASN1_TFLG_COMBINE);
done:
#ifdef CRYPTO_MDEBUG
	if (it->sname)
		CRYPTO_pop_info();
#endif
	return ret;
}


static int
asn1_template_noexp_d2i(ASN1_VALUE **val, const unsigned char **in, long len,
    const ASN1_TEMPLATE *tt, char opt, ASN1_TLC *ctx)
{
	int flags, aclass;
	int ret;
	const unsigned char *p, *q;

	if (!val)
		return 0;
	flags = tt->flags;
	aclass = flags & ASN1_TFLG_TAG_CLASS;

	p = *in;
	q = p;

	if (flags & ASN1_TFLG_SK_MASK) {
		/* SET OF, SEQUENCE OF */
		int sktag, skaclass;
		char sk_eoc;
		/* First work out expected inner tag value */
		if (flags & ASN1_TFLG_IMPTAG) {
			sktag = tt->tag;
			skaclass = aclass;
		} else {
			skaclass = V_ASN1_UNIVERSAL;
			if (flags & ASN1_TFLG_SET_OF)
				sktag = V_ASN1_SET;
			else
				sktag = V_ASN1_SEQUENCE;
		}
		/* Get the tag */
		ret = asn1_check_tlen(&len, NULL, NULL, &sk_eoc, NULL,
		    &p, len, sktag, skaclass, opt, ctx);
		if (!ret) {
			ASN1err(ASN1_F_ASN1_TEMPLATE_NOEXP_D2I,
			    ERR_R_NESTED_ASN1_ERROR);
			return 0;
		} else if (ret == -1)
			return -1;
		if (!*val)
			*val = (ASN1_VALUE *)sk_new_null();
		else {
			/* We've got a valid STACK: free up any items present */
			STACK_OF(ASN1_VALUE) *sktmp =
			    (STACK_OF(ASN1_VALUE) *)*val;
			ASN1_VALUE *vtmp;
			while (sk_ASN1_VALUE_num(sktmp) > 0) {
				vtmp = sk_ASN1_VALUE_pop(sktmp);
				ASN1_item_ex_free(&vtmp,
				    ASN1_ITEM_ptr(tt->item));
			}
		}

		if (!*val) {
			ASN1err(ASN1_F_ASN1_TEMPLATE_NOEXP_D2I,
			    ERR_R_MALLOC_FAILURE);
			goto err;
		}

		/* Read as many items as we can */
		while (len > 0) {
			ASN1_VALUE *skfield;
			q = p;
			/* See if EOC found */
			if (asn1_check_eoc(&p, len)) {
				if (!sk_eoc) {
					ASN1err(ASN1_F_ASN1_TEMPLATE_NOEXP_D2I,
					    ASN1_R_UNEXPECTED_EOC);
					goto err;
				}
				len -= p - q;
				sk_eoc = 0;
				break;
			}
			skfield = NULL;
			if (!ASN1_item_ex_d2i(&skfield, &p, len,
			    ASN1_ITEM_ptr(tt->item), -1, 0, 0, ctx)) {
				ASN1err(ASN1_F_ASN1_TEMPLATE_NOEXP_D2I,
				    ERR_R_NESTED_ASN1_ERROR);
				goto err;
			}
			len -= p - q;
			if (!sk_ASN1_VALUE_push((STACK_OF(ASN1_VALUE) *)*val,
			    skfield)) {
				ASN1err(ASN1_F_ASN1_TEMPLATE_NOEXP_D2I,
				    ERR_R_MALLOC_FAILURE);
				goto err;
			}
		}
		if (sk_eoc) {
			ASN1err(ASN1_F_ASN1_TEMPLATE_NOEXP_D2I,
			    ASN1_R_MISSING_EOC);
			goto err;
		}
	} else if (flags & ASN1_TFLG_IMPTAG) {
		/* IMPLICIT tagging */
		ret = ASN1_item_ex_d2i(val, &p, len,
		    ASN1_ITEM_ptr(tt->item), tt->tag, aclass, opt, ctx);
		if (!ret) {
			ASN1err(ASN1_F_ASN1_TEMPLATE_NOEXP_D2I,
			    ERR_R_NESTED_ASN1_ERROR);
			goto err;
		} else if (ret == -1)
			return -1;
	} else {
		/* Nothing special */
		ret = ASN1_item_ex_d2i(val, &p, len, ASN1_ITEM_ptr(tt->item),
		    -1, tt->flags & ASN1_TFLG_COMBINE, opt, ctx);
		if (!ret) {
			ASN1err(ASN1_F_ASN1_TEMPLATE_NOEXP_D2I,
			    ERR_R_NESTED_ASN1_ERROR);
			goto err;
		} else if (ret == -1)
			return -1;
	}

	*in = p;
	return 1;

err:
	ASN1_template_free(val, tt);
	return 0;
}


ASN1_TYPE *
ASN1_TYPE_new(void)
{
	return (ASN1_TYPE *)ASN1_item_new(&ASN1_ANY_it);
}


void
ASN1_TYPE_set(ASN1_TYPE *a, int type, void *value)
{
	if (a->value.ptr != NULL) {
		ASN1_TYPE **tmp_a = &a;
		ASN1_primitive_free((ASN1_VALUE **)tmp_a, NULL);
	}
	a->type = type;
	if (type == V_ASN1_BOOLEAN)
		a->value.boolean = value ? 0xff : 0;
	else
		a->value.ptr = value;
}
ASN1_TYPE_set1(ASN1_TYPE *a, int type, const void *value)
{
	if (!value || (type == V_ASN1_BOOLEAN)) {
		void *p = (void *)value;
		ASN1_TYPE_set(a, type, p);
	} else if (type == V_ASN1_OBJECT) {
		ASN1_OBJECT *odup;
		odup = OBJ_dup(value);
		if (!odup)
			return 0;
		ASN1_TYPE_set(a, type, odup);
	} else {
		ASN1_STRING *sdup;
		sdup = ASN1_STRING_dup(value);
		if (!sdup)
			return 0;
		ASN1_TYPE_set(a, type, sdup);
	}
	return 1;
}


long
BIO_ctrl(BIO *b, int cmd, long larg, void *parg)
{
	long ret;
	long (*cb)(BIO *, int, const char *, int, long, long);

	if (b == NULL)
		return (0);

	if ((b->method == NULL) || (b->method->ctrl == NULL)) {
		BIOerr(BIO_F_BIO_CTRL, BIO_R_UNSUPPORTED_METHOD);
		return (-2);
	}

	cb = b->callback;

	if ((cb != NULL) &&
	    ((ret = cb(b, BIO_CB_CTRL, parg, cmd, larg, 1L)) <= 0))
		return (ret);

	ret = b->method->ctrl(b, cmd, larg, parg);

	if (cb != NULL)
		ret = cb(b, BIO_CB_CTRL|BIO_CB_RETURN, parg, cmd, larg, ret);
	return (ret);
}
BIO_ctrl_pending(BIO *bio)
{
	return BIO_ctrl(bio, BIO_CTRL_PENDING, 0, NULL);
}
BIO_ctrl_wpending(BIO *bio)
{
	return BIO_ctrl(bio, BIO_CTRL_WPENDING, 0, NULL);
}


int
BIO_free(BIO *a)
{
	int i;

	if (a == NULL)
		return (0);

	i = CRYPTO_add(&a->references, -1, CRYPTO_LOCK_BIO);
	if (i > 0)
		return (1);
	if ((a->callback != NULL) &&
	    ((i = (int)a->callback(a, BIO_CB_FREE, NULL, 0, 0L, 1L)) <= 0))
		return (i);

	CRYPTO_free_ex_data(CRYPTO_EX_INDEX_BIO, a, &a->ex_data);

	if (a->method != NULL && a->method->destroy != NULL)
		a->method->destroy(a);
	free(a);
	return (1);
}
BIO_free_all(BIO *bio)
{
	BIO *b;
	int ref;

	while (bio != NULL) {
		b = bio;
		ref = b->references;
		bio = bio->next_bio;
		BIO_free(b);
		/* Since ref count > 1, don't free anyone else. */
		if (ref > 1)
			break;
	}
}


int
BIO_gets(BIO *b, char *in, int inl)
{
	int i;
	long (*cb)(BIO *, int, const char *, int, long, long);

	if ((b == NULL) || (b->method == NULL) || (b->method->bgets == NULL)) {
		BIOerr(BIO_F_BIO_GETS, BIO_R_UNSUPPORTED_METHOD);
		return (-2);
	}

	cb = b->callback;

	if ((cb != NULL) &&
	    ((i = (int)cb(b, BIO_CB_GETS, in, inl, 0L, 1L)) <= 0))
		return (i);

	if (!b->init) {
		BIOerr(BIO_F_BIO_GETS, BIO_R_UNINITIALIZED);
		return (-2);
	}

	i = b->method->bgets(b, in, inl);

	if (cb != NULL)
		i = (int)cb(b, BIO_CB_GETS|BIO_CB_RETURN, in, inl, 0L, (long)i);
	return (i);
}


BIO *
BIO_new(BIO_METHOD *method)
{
	BIO *ret = NULL;

	ret = malloc(sizeof(BIO));
	if (ret == NULL) {
		BIOerr(BIO_F_BIO_NEW, ERR_R_MALLOC_FAILURE);
		return (NULL);
	}
	if (!BIO_set(ret, method)) {
		free(ret);
		ret = NULL;
	}
	return (ret);
}


int
BIO_set(BIO *bio, BIO_METHOD *method)
{
	bio->method = method;
	bio->callback = NULL;
	bio->cb_arg = NULL;
	bio->init = 0;
	bio->shutdown = 1;
	bio->flags = 0;
	bio->retry_reason = 0;
	bio->num = 0;
	bio->ptr = NULL;
	bio->prev_bio = NULL;
	bio->next_bio = NULL;
	bio->references = 1;
	bio->num_read = 0L;
	bio->num_write = 0L;
	CRYPTO_new_ex_data(CRYPTO_EX_INDEX_BIO, bio, &bio->ex_data);
	if (method->create != NULL)
		if (!method->create(bio)) {
			CRYPTO_free_ex_data(CRYPTO_EX_INDEX_BIO, bio,
			    &bio->ex_data);
			return (0);
		}
	return (1);
}
BIO_set_flags(BIO *b, int flags)
{
	b->flags |= flags;
}
BIO_set_callback(BIO *b, long (*cb)(struct bio_st *, int, const char *, int,
    long, long))
{
	b->callback = cb;
}
BIO_set_callback_arg(BIO *b, char *arg)
{
	b->cb_arg = arg;
}
BIO_set_ex_data(BIO *bio, int idx, void *data)
{
	return (CRYPTO_set_ex_data(&(bio->ex_data), idx, data));
}


BIO_METHOD *
BIO_s_file(void)
{
	return (&methods_filep);
}


int
BN_add(BIGNUM *r, const BIGNUM *a, const BIGNUM *b)
{
	const BIGNUM *tmp;
	int a_neg = a->neg, ret;

	bn_check_top(a);
	bn_check_top(b);

	/*  a +  b	a+b
	 *  a + -b	a-b
	 * -a +  b	b-a
	 * -a + -b	-(a+b)
	 */
	if (a_neg ^ b->neg) {
		/* only one is negative */
		if (a_neg)
				{ tmp = a;
			a = b;
			b = tmp;
		}

		/* we are now a - b */

		if (BN_ucmp(a, b) < 0) {
			if (!BN_usub(r, b, a))
				return (0);
			r->neg = 1;
		} else {
			if (!BN_usub(r, a, b))
				return (0);
			r->neg = 0;
		}
		return (1);
	}

	ret = BN_uadd(r, a, b);
	r->neg = a_neg;
	bn_check_top(r);
	return ret;
}


int
BN_add_word(BIGNUM *a, BN_ULONG w)
{
	BN_ULONG l;
	int i;

	bn_check_top(a);
	w &= BN_MASK2;

	/* degenerate case: w is zero */
	if (!w)
		return 1;
	/* degenerate case: a is zero */
	if (BN_is_zero(a))
		return BN_set_word(a, w);
	/* handle 'a' when negative */
	if (a->neg) {
		a->neg = 0;
		i = BN_sub_word(a, w);
		if (!BN_is_zero(a))
			a->neg=!(a->neg);
		return (i);
	}
	for (i = 0; w != 0 && i < a->top; i++) {
		a->d[i] = l = (a->d[i] + w) & BN_MASK2;
		w = (w > l) ? 1 : 0;
	}
	if (w && i == a->top) {
		if (bn_wexpand(a, a->top + 1) == NULL)
			return 0;
		a->top++;
		a->d[i] = w;
	}
	bn_check_top(a);
	return (1);
}


BN_ULONG
bn_add_words(BN_ULONG *r, const BN_ULONG *a, const BN_ULONG *b, int n)
{
	BN_ULLONG ll = 0;

	assert(n >= 0);
	if (n <= 0)
		return ((BN_ULONG)0);

#ifndef OPENSSL_SMALL_FOOTPRINT
	while (n & ~3) {
		ll += (BN_ULLONG)a[0] + b[0];
		r[0] = (BN_ULONG)ll & BN_MASK2;
		ll >>= BN_BITS2;
		ll += (BN_ULLONG)a[1] + b[1];
		r[1] = (BN_ULONG)ll & BN_MASK2;
		ll >>= BN_BITS2;
		ll += (BN_ULLONG)a[2] + b[2];
		r[2] = (BN_ULONG)ll & BN_MASK2;
		ll >>= BN_BITS2;
		ll += (BN_ULLONG)a[3] + b[3];
		r[3] = (BN_ULONG)ll & BN_MASK2;
		ll >>= BN_BITS2;
		a += 4;
		b += 4;
		r += 4;
		n -= 4;
	}
#endif
	while (n) {
		ll += (BN_ULLONG)a[0] + b[0];
		r[0] = (BN_ULONG)ll & BN_MASK2;
		ll >>= BN_BITS2;
		a++;
		b++;
		r++;
		n--;
	}
	return ((BN_ULONG)ll);
}
bn_add_words(BN_ULONG *r, const BN_ULONG *a, const BN_ULONG *b, int n)
{
	BN_ULONG c, l, t;

	assert(n >= 0);
	if (n <= 0)
		return ((BN_ULONG)0);

	c = 0;
#ifndef OPENSSL_SMALL_FOOTPRINT
	while (n & ~3) {
		t = a[0];
		t = (t + c) & BN_MASK2;
		c = (t < c);
		l = (t + b[0]) & BN_MASK2;
		c += (l < t);
		r[0] = l;
		t = a[1];
		t = (t + c) & BN_MASK2;
		c = (t < c);
		l = (t + b[1]) & BN_MASK2;
		c += (l < t);
		r[1] = l;
		t = a[2];
		t = (t + c) & BN_MASK2;
		c = (t < c);
		l = (t + b[2]) & BN_MASK2;
		c += (l < t);
		r[2] = l;
		t = a[3];
		t = (t + c) & BN_MASK2;
		c = (t < c);
		l = (t + b[3]) & BN_MASK2;
		c += (l < t);
		r[3] = l;
		a += 4;
		b += 4;
		r += 4;
		n -= 4;
	}
#endif
	while (n) {
		t = a[0];
		t = (t + c) & BN_MASK2;
		c = (t < c);
		l = (t + b[0]) & BN_MASK2;
		c += (l < t);
		r[0] = l;
		a++;
		b++;
		r++;
		n--;
	}
	return ((BN_ULONG)c);
}


BIGNUM *
BN_bin2bn(const unsigned char *s, int len, BIGNUM *ret)
{
	unsigned int i, m;
	unsigned int n;
	BN_ULONG l;
	BIGNUM *bn = NULL;

	if (ret == NULL)
		ret = bn = BN_new();
	if (ret == NULL)
		return (NULL);
	bn_check_top(ret);
	l = 0;
	n = len;
	if (n == 0) {
		ret->top = 0;
		return (ret);
	}
	i = ((n - 1) / BN_BYTES) + 1;
	m = ((n - 1) % (BN_BYTES));
	if (bn_wexpand(ret, (int)i) == NULL) {
		BN_free(bn);
		return NULL;
	}
	ret->top = i;
	ret->neg = 0;
	while (n--) {
		l = (l << 8L) | *(s++);
		if (m-- == 0) {
			ret->d[--i] = l;
			l = 0;
			m = BN_BYTES - 1;
		}
	}
	/* need to call this due to clear byte at top if avoiding
	 * having the top bit set (-ve number) */
	bn_correct_top(ret);
	return (ret);
}


int
BN_BLINDING_convert_ex(BIGNUM *n, BIGNUM *r, BN_BLINDING *b, BN_CTX *ctx)
{
	int ret = 1;

	bn_check_top(n);

	if ((b->A == NULL) || (b->Ai == NULL)) {
		BNerr(BN_F_BN_BLINDING_CONVERT_EX, BN_R_NOT_INITIALIZED);
		return (0);
	}

	if (b->counter == -1)
		/* Fresh blinding, doesn't need updating. */
		b->counter = 0;
	else if (!BN_BLINDING_update(b, ctx))
		return (0);

	if (r != NULL) {
		if (!BN_copy(r, b->Ai))
			ret = 0;
	}

	if (!BN_mod_mul(n, n,b->A, b->mod, ctx))
		ret = 0;

	return ret;
}


BN_BLINDING *
BN_BLINDING_create_param(BN_BLINDING *b, const BIGNUM *e, BIGNUM *m,
    BN_CTX *ctx, int (*bn_mod_exp)(BIGNUM *r, const BIGNUM *a, const BIGNUM *p,
    const BIGNUM *m, BN_CTX *ctx, BN_MONT_CTX *m_ctx), BN_MONT_CTX *m_ctx)
{
	int    retry_counter = 32;
	BN_BLINDING *ret = NULL;

	if (b == NULL)
		ret = BN_BLINDING_new(NULL, NULL, m);
	else
		ret = b;

	if (ret == NULL)
		goto err;

	if (ret->A  == NULL && (ret->A = BN_new()) == NULL)
		goto err;
	if (ret->Ai == NULL && (ret->Ai = BN_new()) == NULL)
		goto err;

	if (e != NULL) {
		BN_free(ret->e);
		ret->e = BN_dup(e);
	}
	if (ret->e == NULL)
		goto err;

	if (bn_mod_exp != NULL)
		ret->bn_mod_exp = bn_mod_exp;
	if (m_ctx != NULL)
		ret->m_ctx = m_ctx;

	do {
		if (!BN_rand_range(ret->A, ret->mod))
			goto err;
		if (BN_mod_inverse(ret->Ai, ret->A, ret->mod, ctx) == NULL) {
			/* this should almost never happen for good RSA keys */
			unsigned long error = ERR_peek_last_error();
			if (ERR_GET_REASON(error) == BN_R_NO_INVERSE) {
				if (retry_counter-- == 0) {
					BNerr(BN_F_BN_BLINDING_CREATE_PARAM,
					    BN_R_TOO_MANY_ITERATIONS);
					goto err;
				}
				ERR_clear_error();
			} else
				goto err;
		} else
			break;
	} while (1);

	if (ret->bn_mod_exp != NULL && ret->m_ctx != NULL) {
		if (!ret->bn_mod_exp(ret->A, ret->A, ret->e, ret->mod,
		    ctx, ret->m_ctx))
			goto err;
	} else {
		if (!BN_mod_exp(ret->A, ret->A, ret->e, ret->mod, ctx))
			goto err;
	}

	return ret;

err:
	if (b == NULL && ret != NULL) {
		BN_BLINDING_free(ret);
		ret = NULL;
	}

	return ret;
}


int
BN_BLINDING_invert_ex(BIGNUM *n, const BIGNUM *r, BN_BLINDING *b, BN_CTX *ctx)
{
	int ret;

	bn_check_top(n);

	if (r != NULL)
		ret = BN_mod_mul(n, n, r, b->mod, ctx);
	else {
		if (b->Ai == NULL) {
			BNerr(BN_F_BN_BLINDING_INVERT_EX, BN_R_NOT_INITIALIZED);
			return (0);
		}
		ret = BN_mod_mul(n, n, b->Ai, b->mod, ctx);
	}

	bn_check_top(n);
	return (ret);
}


BN_BLINDING *
BN_BLINDING_new(const BIGNUM *A, const BIGNUM *Ai, BIGNUM *mod)
{
	BN_BLINDING *ret = NULL;

	bn_check_top(mod);

	if ((ret = calloc(1, sizeof(BN_BLINDING))) == NULL) {
		BNerr(BN_F_BN_BLINDING_NEW, ERR_R_MALLOC_FAILURE);
		return (NULL);
	}
	if (A != NULL) {
		if ((ret->A = BN_dup(A))  == NULL)
			goto err;
	}
	if (Ai != NULL) {
		if ((ret->Ai = BN_dup(Ai)) == NULL)
			goto err;
	}

	/* save a copy of mod in the BN_BLINDING structure */
	if ((ret->mod = BN_dup(mod)) == NULL)
		goto err;
	if (BN_get_flags(mod, BN_FLG_CONSTTIME) != 0)
		BN_set_flags(ret->mod, BN_FLG_CONSTTIME);

	/* Set the counter to the special value -1
	 * to indicate that this is never-used fresh blinding
	 * that does not need updating before first use. */
	ret->counter = -1;
	CRYPTO_THREADID_current(&ret->tid);
	return (ret);

err:
	if (ret != NULL)
		BN_BLINDING_free(ret);
	return (NULL);
}


CRYPTO_THREADID *
BN_BLINDING_thread_id(BN_BLINDING *b)
{
	return &b->tid;
}


int
BN_BLINDING_update(BN_BLINDING *b, BN_CTX *ctx)
{
	int ret = 0;

	if ((b->A == NULL) || (b->Ai == NULL)) {
		BNerr(BN_F_BN_BLINDING_UPDATE, BN_R_NOT_INITIALIZED);
		goto err;
	}

	if (b->counter == -1)
		b->counter = 0;

	if (++b->counter == BN_BLINDING_COUNTER && b->e != NULL &&
	    !(b->flags & BN_BLINDING_NO_RECREATE)) {
		/* re-create blinding parameters */
		if (!BN_BLINDING_create_param(b, NULL, NULL, ctx, NULL, NULL))
			goto err;
	} else if (!(b->flags & BN_BLINDING_NO_UPDATE)) {
		if (!BN_mod_mul(b->A, b->A, b->A, b->mod, ctx))
			goto err;
		if (!BN_mod_mul(b->Ai, b->Ai, b->Ai, b->mod, ctx))
			goto err;
	}

	ret = 1;

err:
	if (b->counter == BN_BLINDING_COUNTER)
		b->counter = 0;
	return (ret);
}


int
BN_bn2bin(const BIGNUM *a, unsigned char *to)
{
	int n, i;
	BN_ULONG l;

	bn_check_top(a);
	n = i=BN_num_bytes(a);
	while (i--) {
		l = a->d[i / BN_BYTES];
		*(to++) = (unsigned char)(l >> (8 * (i % BN_BYTES))) & 0xff;
	}
	return (n);
}


static int
bn_c2i(ASN1_VALUE **pval, const unsigned char *cont, int len, int utype,
    char *free_cont, const ASN1_ITEM *it)
{
	BIGNUM *bn;

	if (*pval == NULL) {
		if (bn_new(pval, it) == 0)
			return 0;
	}
	bn = (BIGNUM *)*pval;
	if (!BN_bin2bn(cont, len, bn)) {
		bn_free(pval, it);
		return 0;
	}
	return 1;
}


void
BN_clear_free(BIGNUM *a)
{
	int i;

	if (a == NULL)
		return;
	bn_check_top(a);
	if (a->d != NULL && !(BN_get_flags(a, BN_FLG_STATIC_DATA))) {
		explicit_bzero(a->d, a->dmax * sizeof(a->d[0]));
		free(a->d);
	}
	i = BN_get_flags(a, BN_FLG_MALLOCED);
	explicit_bzero(a, sizeof(BIGNUM));
	if (i)
		free(a);
}


int
BN_cmp(const BIGNUM *a, const BIGNUM *b)
{
	int i;
	int gt, lt;
	BN_ULONG t1, t2;

	if ((a == NULL) || (b == NULL)) {
		if (a != NULL)
			return (-1);
		else if (b != NULL)
			return (1);
		else
			return (0);
	}

	bn_check_top(a);
	bn_check_top(b);

	if (a->neg != b->neg) {
		if (a->neg)
			return (-1);
		else
			return (1);
	}
	if (a->neg == 0) {
		gt = 1;
		lt = -1;
	} else {
		gt = -1;
		lt = 1;
	}

	if (a->top > b->top)
		return (gt);
	if (a->top < b->top)
		return (lt);
	for (i = a->top - 1; i >= 0; i--) {
		t1 = a->d[i];
		t2 = b->d[i];
		if (t1 > t2)
			return (gt);
		if (t1 < t2)
			return (lt);
	}
	return (0);
}


int
bn_cmp_part_words(const BN_ULONG *a, const BN_ULONG *b, int cl, int dl)
{
	int n, i;

	n = cl - 1;

	if (dl < 0) {
		for (i = dl; i < 0; i++) {
			if (b[n - i] != 0)
				return -1; /* a < b */
		}
	}
	if (dl > 0) {
		for (i = dl; i > 0; i--) {
			if (a[n + i] != 0)
				return 1; /* a > b */
		}
	}
	return bn_cmp_words(a, b, cl);
}


int
bn_cmp_words(const BN_ULONG *a, const BN_ULONG *b, int n)
{
	int i;
	BN_ULONG aa, bb;

	aa = a[n - 1];
	bb = b[n - 1];
	if (aa != bb)
		return ((aa > bb) ? 1 : -1);
	for (i = n - 2; i >= 0; i--) {
		aa = a[i];
		bb = b[i];
		if (aa != bb)
			return ((aa > bb) ? 1 : -1);
	}
	return (0);
}


BIGNUM *
BN_copy(BIGNUM *a, const BIGNUM *b)
{
	int i;
	BN_ULONG *A;
	const BN_ULONG *B;

	bn_check_top(b);

	if (a == b)
		return (a);
	if (bn_wexpand(a, b->top) == NULL)
		return (NULL);

#if 1
	A = a->d;
	B = b->d;
	for (i = b->top >> 2; i > 0; i--, A += 4, B += 4) {
		BN_ULONG a0, a1, a2, a3;
		a0 = B[0];
		a1 = B[1];
		a2 = B[2];
		a3 = B[3];
		A[0] = a0;
		A[1] = a1;
		A[2] = a2;
		A[3] = a3;
	}
	switch (b->top & 3) {
	case 3:
		A[2] = B[2];
	case 2:
		A[1] = B[1];
	case 1:
		A[0] = B[0];
	}
#else
	memcpy(a->d, b->d, sizeof(b->d[0]) * b->top);
#endif

	a->top = b->top;
	a->neg = b->neg;
	bn_check_top(a);
	return (a);
}


void
BN_CTX_end(BN_CTX *ctx)
{
	CTXDBG_ENTRY("BN_CTX_end", ctx);

	if (ctx->err_stack)
		ctx->err_stack--;
	else {
		unsigned int fp = BN_STACK_pop(&ctx->stack);
		/* Does this stack frame have anything to release? */
		if (fp < ctx->used)
			BN_POOL_release(&ctx->pool, ctx->used - fp);
		ctx->used = fp;
		/* Unjam "too_many" in case "get" had failed */
		ctx->too_many = 0;
	}
	CTXDBG_EXIT(ctx);
}


void
BN_CTX_free(BN_CTX *ctx)
{
	if (ctx == NULL)
		return;
#ifdef BN_CTX_DEBUG
	{
		BN_POOL_ITEM *pool = ctx->pool.head;
		fprintf(stderr, "BN_CTX_free, stack-size=%d, pool-bignums=%d\n",
		    ctx->stack.size, ctx->pool.size);
		fprintf(stderr, "dmaxs: ");
		while (pool) {
			unsigned loop = 0;
			while (loop < BN_CTX_POOL_SIZE)
				fprintf(stderr, "%02x ",
				    pool->vals[loop++].dmax);
			pool = pool->next;
		}
		fprintf(stderr, "\n");
	}
#endif
	BN_STACK_finish(&ctx->stack);
	BN_POOL_finish(&ctx->pool);
	free(ctx);
}


BIGNUM *
BN_CTX_get(BN_CTX *ctx)
{
	BIGNUM *ret;

	CTXDBG_ENTRY("BN_CTX_get", ctx);

	if (ctx->err_stack || ctx->too_many)
		return NULL;
	if ((ret = BN_POOL_get(&ctx->pool)) == NULL) {
		/* Setting too_many prevents repeated "get" attempts from
		 * cluttering the error stack. */
		ctx->too_many = 1;
		BNerr(BN_F_BN_CTX_GET, BN_R_TOO_MANY_TEMPORARY_VARIABLES);
		return NULL;
	}
	/* OK, make sure the returned bignum is "zero" */
	BN_zero(ret);
	ctx->used++;
	CTXDBG_RET(ctx, ret);
	return ret;
}


BN_CTX *
BN_CTX_new(void)
{
	BN_CTX *ret = malloc(sizeof(BN_CTX));
	if (!ret) {
		BNerr(BN_F_BN_CTX_NEW, ERR_R_MALLOC_FAILURE);
		return NULL;
	}

	/* Initialise the structure */
	BN_POOL_init(&ret->pool);
	BN_STACK_init(&ret->stack);
	ret->used = 0;
	ret->err_stack = 0;
	ret->too_many = 0;
	return ret;
}


void
BN_CTX_start(BN_CTX *ctx)
{
	CTXDBG_ENTRY("BN_CTX_start", ctx);

	/* If we're already overflowing ... */
	if (ctx->err_stack || ctx->too_many)
		ctx->err_stack++;
	/* (Try to) get a new frame pointer */
	else if (!BN_STACK_push(&ctx->stack, ctx->used)) {
		BNerr(BN_F_BN_CTX_START, BN_R_TOO_MANY_TEMPORARY_VARIABLES);
		ctx->err_stack++;
	}
	CTXDBG_EXIT(ctx);
}


int
BN_div(BIGNUM *dv, BIGNUM *rm, const BIGNUM *num, const BIGNUM *divisor,
    BN_CTX *ctx)
{
	int norm_shift, i, loop;
	BIGNUM *tmp, wnum, *snum, *sdiv, *res;
	BN_ULONG *resp, *wnump;
	BN_ULONG d0, d1;
	int num_n, div_n;
	int no_branch = 0;

	/* Invalid zero-padding would have particularly bad consequences
	 * in the case of 'num', so don't just rely on bn_check_top() for this one
	 * (bn_check_top() works only for BN_DEBUG builds) */
	if (num->top > 0 && num->d[num->top - 1] == 0) {
		BNerr(BN_F_BN_DIV, BN_R_NOT_INITIALIZED);
		return 0;
	}

	bn_check_top(num);

	if ((BN_get_flags(num, BN_FLG_CONSTTIME) != 0) ||
	    (BN_get_flags(divisor, BN_FLG_CONSTTIME) != 0)) {
		no_branch = 1;
	}

	bn_check_top(dv);
	bn_check_top(rm);
	/* bn_check_top(num); */ /* 'num' has been checked already */
	bn_check_top(divisor);

	if (BN_is_zero(divisor)) {
		BNerr(BN_F_BN_DIV, BN_R_DIV_BY_ZERO);
		return (0);
	}

	if (!no_branch && BN_ucmp(num, divisor) < 0) {
		if (rm != NULL) {
			if (BN_copy(rm, num) == NULL)
				return (0);
		}
		if (dv != NULL)
			BN_zero(dv);
		return (1);
	}

	BN_CTX_start(ctx);
	tmp = BN_CTX_get(ctx);
	snum = BN_CTX_get(ctx);
	sdiv = BN_CTX_get(ctx);
	if (dv == NULL)
		res = BN_CTX_get(ctx);
	else
		res = dv;
	if (tmp == NULL || snum == NULL || sdiv == NULL || res == NULL)
		goto err;

	/* First we normalise the numbers */
	norm_shift = BN_BITS2 - ((BN_num_bits(divisor)) % BN_BITS2);
	if (!(BN_lshift(sdiv, divisor, norm_shift)))
		goto err;
	sdiv->neg = 0;
	norm_shift += BN_BITS2;
	if (!(BN_lshift(snum, num, norm_shift)))
		goto err;
	snum->neg = 0;

	if (no_branch) {
		/* Since we don't know whether snum is larger than sdiv,
		 * we pad snum with enough zeroes without changing its
		 * value.
		 */
		if (snum->top <= sdiv->top + 1) {
			if (bn_wexpand(snum, sdiv->top + 2) == NULL)
				goto err;
			for (i = snum->top; i < sdiv->top + 2; i++)
				snum->d[i] = 0;
			snum->top = sdiv->top + 2;
		} else {
			if (bn_wexpand(snum, snum->top + 1) == NULL)
				goto err;
			snum->d[snum->top] = 0;
			snum->top ++;
		}
	}

	div_n = sdiv->top;
	num_n = snum->top;
	loop = num_n - div_n;
	/* Lets setup a 'window' into snum
	 * This is the part that corresponds to the current
	 * 'area' being divided */
	wnum.neg = 0;
	wnum.d = &(snum->d[loop]);
	wnum.top = div_n;
	/* only needed when BN_ucmp messes up the values between top and max */
	wnum.dmax  = snum->dmax - loop; /* so we don't step out of bounds */
	wnum.flags = snum->flags | BN_FLG_STATIC_DATA;

	/* Get the top 2 words of sdiv */
	/* div_n=sdiv->top; */
	d0 = sdiv->d[div_n - 1];
	d1 = (div_n == 1) ? 0 : sdiv->d[div_n - 2];

	/* pointer to the 'top' of snum */
	wnump = &(snum->d[num_n - 1]);

	/* Setup to 'res' */
	res->neg = (num->neg ^ divisor->neg);
	if (!bn_wexpand(res, (loop + 1)))
		goto err;
	res->top = loop - no_branch;
	resp = &(res->d[loop - 1]);

	/* space for temp */
	if (!bn_wexpand(tmp, (div_n + 1)))
		goto err;

	if (!no_branch) {
		if (BN_ucmp(&wnum, sdiv) >= 0) {
			/* If BN_DEBUG_RAND is defined BN_ucmp changes (via
			 * bn_pollute) the const bignum arguments =>
			 * clean the values between top and max again */
			bn_clear_top2max(&wnum);
			bn_sub_words(wnum.d, wnum.d, sdiv->d, div_n);
			*resp = 1;
		} else
			res->top--;
	}

	/* if res->top == 0 then clear the neg value otherwise decrease
	 * the resp pointer */
	if (res->top == 0)
		res->neg = 0;
	else
		resp--;

	for (i = 0; i < loop - 1; i++, wnump--, resp--) {
		BN_ULONG q, l0;
		/* the first part of the loop uses the top two words of
		 * snum and sdiv to calculate a BN_ULONG q such that
		 * | wnum - sdiv * q | < sdiv */
#if defined(BN_DIV3W) && !defined(OPENSSL_NO_ASM)
		BN_ULONG bn_div_3_words(BN_ULONG*, BN_ULONG, BN_ULONG);
		q = bn_div_3_words(wnump, d1, d0);
#else
		BN_ULONG n0, n1, rem = 0;

		n0 = wnump[0];
		n1 = wnump[-1];
		if (n0 == d0)
			q = BN_MASK2;
		else 			/* n0 < d0 */
		{
#ifdef BN_LLONG
			BN_ULLONG t2;

#if defined(BN_DIV2W) && !defined(bn_div_words)
			q = (BN_ULONG)(((((BN_ULLONG)n0) << BN_BITS2)|n1)/d0);
#else
			q = bn_div_words(n0, n1, d0);
#endif

#ifndef REMAINDER_IS_ALREADY_CALCULATED
			/*
			 * rem doesn't have to be BN_ULLONG. The least we
			 * know it's less that d0, isn't it?
			 */
			rem = (n1 - q * d0) & BN_MASK2;
#endif
			t2 = (BN_ULLONG)d1*q;

			for (;;) {
				if (t2 <= ((((BN_ULLONG)rem) << BN_BITS2) |
				    wnump[-2]))
					break;
				q--;
				rem += d0;
				if (rem < d0) break; /* don't let rem overflow */
					t2 -= d1;
			}
#else /* !BN_LLONG */
			BN_ULONG t2l, t2h;

			q = bn_div_words(n0, n1, d0);
#ifndef REMAINDER_IS_ALREADY_CALCULATED
			rem = (n1 - q*d0)&BN_MASK2;
#endif

#if defined(BN_UMULT_LOHI)
			BN_UMULT_LOHI(t2l, t2h, d1, q);
#elif defined(BN_UMULT_HIGH)
			t2l = d1 * q;
			t2h = BN_UMULT_HIGH(d1, q);
#else
			{
				BN_ULONG ql, qh;
				t2l = LBITS(d1);
				t2h = HBITS(d1);
				ql = LBITS(q);
				qh = HBITS(q);
				mul64(t2l, t2h, ql, qh); /* t2=(BN_ULLONG)d1*q; */
			}
#endif

			for (;;) {
				if ((t2h < rem) ||
				    ((t2h == rem) && (t2l <= wnump[-2])))
					break;
				q--;
				rem += d0;
				if (rem < d0)
					break; /* don't let rem overflow */
				if (t2l < d1)
					t2h--;
				t2l -= d1;
			}
#endif /* !BN_LLONG */
		}
#endif /* !BN_DIV3W */

		l0 = bn_mul_words(tmp->d, sdiv->d, div_n, q);
		tmp->d[div_n] = l0;
		wnum.d--;
		/* ingore top values of the bignums just sub the two
		 * BN_ULONG arrays with bn_sub_words */
		if (bn_sub_words(wnum.d, wnum.d, tmp->d, div_n + 1)) {
			/* Note: As we have considered only the leading
			 * two BN_ULONGs in the calculation of q, sdiv * q
			 * might be greater than wnum (but then (q-1) * sdiv
			 * is less or equal than wnum)
			 */
			q--;
			if (bn_add_words(wnum.d, wnum.d, sdiv->d, div_n))
				/* we can't have an overflow here (assuming
				 * that q != 0, but if q == 0 then tmp is
				 * zero anyway) */
				(*wnump)++;
		}
		/* store part of the result */
		*resp = q;
	}
	bn_correct_top(snum);
	if (rm != NULL) {
		/* Keep a copy of the neg flag in num because if rm==num
		 * BN_rshift() will overwrite it.
		 */
		int neg = num->neg;
		BN_rshift(rm, snum, norm_shift);
		if (!BN_is_zero(rm))
			rm->neg = neg;
		bn_check_top(rm);
	}
	if (no_branch)
		bn_correct_top(res);
	BN_CTX_end(ctx);
	return (1);

err:
	bn_check_top(rm);
	BN_CTX_end(ctx);
	return (0);
}


BIGNUM *
BN_dup(const BIGNUM *a)
{
	BIGNUM *t;

	if (a == NULL)
		return NULL;
	bn_check_top(a);

	t = BN_new();
	if (t == NULL)
		return NULL;
	if (!BN_copy(t, a)) {
		BN_free(t);
		return NULL;
	}
	bn_check_top(t);
	return t;
}


BIGNUM *
bn_expand_internal(const BIGNUM *b, int words)
{
	BN_ULONG *A, *a = NULL;
	const BN_ULONG *B;
	int i;

	bn_check_top(b);

	if (words > (INT_MAX/(4*BN_BITS2))) {
		BNerr(BN_F_BN_EXPAND_INTERNAL, BN_R_BIGNUM_TOO_LONG);
		return NULL;
	}
	if (BN_get_flags(b, BN_FLG_STATIC_DATA)) {
		BNerr(BN_F_BN_EXPAND_INTERNAL,
		    BN_R_EXPAND_ON_STATIC_BIGNUM_DATA);
		return (NULL);
	}
	a = A = reallocarray(NULL, words, sizeof(BN_ULONG));
	if (A == NULL) {
		BNerr(BN_F_BN_EXPAND_INTERNAL, ERR_R_MALLOC_FAILURE);
		return (NULL);
	}
#if 1
	B = b->d;
	/* Check if the previous number needs to be copied */
	if (B != NULL) {
		for (i = b->top >> 2; i > 0; i--, A += 4, B += 4) {
			/*
			 * The fact that the loop is unrolled
			 * 4-wise is a tribute to Intel. It's
			 * the one that doesn't have enough
			 * registers to accommodate more data.
			 * I'd unroll it 8-wise otherwise:-)
			 *
			 *		<appro@fy.chalmers.se>
			 */
			BN_ULONG a0, a1, a2, a3;
			a0 = B[0];
			a1 = B[1];
			a2 = B[2];
			a3 = B[3];
			A[0] = a0;
			A[1] = a1;
			A[2] = a2;
			A[3] = a3;
		}
		switch (b->top & 3) {
		case 3:
			A[2] = B[2];
		case 2:
			A[1] = B[1];
		case 1:
			A[0] = B[0];
		}
	}

#else
	memset(A, 0, sizeof(BN_ULONG) * words);
	memcpy(A, b->d, sizeof(b->d[0]) * b->top);
#endif

	return (a);
}
bn_expand2(BIGNUM *b, int words)
{
	bn_check_top(b);

	if (words > b->dmax) {
		BN_ULONG *a = bn_expand_internal(b, words);
		if (!a)
			return NULL;
		if (b->d) {
			explicit_bzero(b->d, b->dmax * sizeof(b->d[0]));
			free(b->d);
		}
		b->d = a;
		b->dmax = words;
	}

/* None of this should be necessary because of what b->top means! */
#if 0
	/* NB: bn_wexpand() calls this only if the BIGNUM really has to grow */
	if (b->top < b->dmax) {
		int i;
		BN_ULONG *A = &(b->d[b->top]);
		for (i = (b->dmax - b->top) >> 3; i > 0; i--, A += 8) {
			A[0] = 0;
			A[1] = 0;
			A[2] = 0;
			A[3] = 0;
			A[4] = 0;
			A[5] = 0;
			A[6] = 0;
			A[7] = 0;
		}
		for (i = (b->dmax - b->top)&7; i > 0; i--, A++)
			A[0] = 0;
		assert(A == &(b->d[b->dmax]));
	}
#endif
	bn_check_top(b);
	return b;
}
bn_expand(BIGNUM *a, int bits)
{
	if (bits > (INT_MAX - BN_BITS2 + 1))
		return (NULL);

	if (((bits + BN_BITS2 - 1) / BN_BITS2) <= a->dmax)
		return (a);

	return bn_expand2(a, (bits + BN_BITS2 - 1) / BN_BITS2);
}


BIGNUM *
bn_expand2(BIGNUM *b, int words)
{
	bn_check_top(b);

	if (words > b->dmax) {
		BN_ULONG *a = bn_expand_internal(b, words);
		if (!a)
			return NULL;
		if (b->d) {
			explicit_bzero(b->d, b->dmax * sizeof(b->d[0]));
			free(b->d);
		}
		b->d = a;
		b->dmax = words;
	}

/* None of this should be necessary because of what b->top means! */
#if 0
	/* NB: bn_wexpand() calls this only if the BIGNUM really has to grow */
	if (b->top < b->dmax) {
		int i;
		BN_ULONG *A = &(b->d[b->top]);
		for (i = (b->dmax - b->top) >> 3; i > 0; i--, A += 8) {
			A[0] = 0;
			A[1] = 0;
			A[2] = 0;
			A[3] = 0;
			A[4] = 0;
			A[5] = 0;
			A[6] = 0;
			A[7] = 0;
		}
		for (i = (b->dmax - b->top)&7; i > 0; i--, A++)
			A[0] = 0;
		assert(A == &(b->d[b->dmax]));
	}
#endif
	bn_check_top(b);
	return b;
}


static BN_ULONG *
bn_expand_internal(const BIGNUM *b, int words)
{
	BN_ULONG *A, *a = NULL;
	const BN_ULONG *B;
	int i;

	bn_check_top(b);

	if (words > (INT_MAX/(4*BN_BITS2))) {
		BNerr(BN_F_BN_EXPAND_INTERNAL, BN_R_BIGNUM_TOO_LONG);
		return NULL;
	}
	if (BN_get_flags(b, BN_FLG_STATIC_DATA)) {
		BNerr(BN_F_BN_EXPAND_INTERNAL,
		    BN_R_EXPAND_ON_STATIC_BIGNUM_DATA);
		return (NULL);
	}
	a = A = reallocarray(NULL, words, sizeof(BN_ULONG));
	if (A == NULL) {
		BNerr(BN_F_BN_EXPAND_INTERNAL, ERR_R_MALLOC_FAILURE);
		return (NULL);
	}
#if 1
	B = b->d;
	/* Check if the previous number needs to be copied */
	if (B != NULL) {
		for (i = b->top >> 2; i > 0; i--, A += 4, B += 4) {
			/*
			 * The fact that the loop is unrolled
			 * 4-wise is a tribute to Intel. It's
			 * the one that doesn't have enough
			 * registers to accommodate more data.
			 * I'd unroll it 8-wise otherwise:-)
			 *
			 *		<appro@fy.chalmers.se>
			 */
			BN_ULONG a0, a1, a2, a3;
			a0 = B[0];
			a1 = B[1];
			a2 = B[2];
			a3 = B[3];
			A[0] = a0;
			A[1] = a1;
			A[2] = a2;
			A[3] = a3;
		}
		switch (b->top & 3) {
		case 3:
			A[2] = B[2];
		case 2:
			A[1] = B[1];
		case 1:
			A[0] = B[0];
		}
	}

#else
	memset(A, 0, sizeof(BN_ULONG) * words);
	memcpy(A, b->d, sizeof(b->d[0]) * b->top);
#endif

	return (a);
}


void
BN_free(BIGNUM *a)
{
	BN_clear_free(a);
}


int
BN_from_montgomery_word(BIGNUM *ret, BIGNUM *r, BN_MONT_CTX *mont)
{
	BIGNUM *n;
	BN_ULONG *ap, *np, *rp, n0, v, carry;
	int nl, max, i;

	n = &(mont->N);
	nl = n->top;
	if (nl == 0) {
		ret->top = 0;
		return (1);
	}

	max = (2 * nl); /* carry is stored separately */
	if (bn_wexpand(r, max) == NULL)
		return (0);

	r->neg ^= n->neg;
	np = n->d;
	rp = r->d;

	/* clear the top words of T */
#if 1
	for (i=r->top; i<max; i++) /* memset? XXX */
		rp[i] = 0;
#else
	memset(&(rp[r->top]), 0, (max - r->top) * sizeof(BN_ULONG));
#endif

	r->top = max;
	n0 = mont->n0[0];

#ifdef BN_COUNT
	fprintf(stderr, "word BN_from_montgomery_word %d * %d\n", nl, nl);
#endif
	for (carry = 0, i = 0; i < nl; i++, rp++) {
		v = bn_mul_add_words(rp, np, nl, (rp[0] * n0) & BN_MASK2);
		v = (v + carry + rp[nl]) & BN_MASK2;
		carry |= (v != rp[nl]);
		carry &= (v <= rp[nl]);
		rp[nl] = v;
	}

	if (bn_wexpand(ret, nl) == NULL)
		return (0);
	ret->top = nl;
	ret->neg = r->neg;

	rp = ret->d;
	ap = &(r->d[nl]);

#define BRANCH_FREE 1
#if BRANCH_FREE
	{
		BN_ULONG *nrp;
		size_t m;

		v = bn_sub_words(rp, ap, np, nl) - carry;
		/* if subtraction result is real, then
		 * trick unconditional memcpy below to perform in-place
		 * "refresh" instead of actual copy. */
		m = (0 - (size_t)v);
		nrp = (BN_ULONG *)(((uintptr_t)rp & ~m)|((uintptr_t)ap & m));

		for (i = 0, nl -= 4; i < nl; i += 4) {
			BN_ULONG t1, t2, t3, t4;

			t1 = nrp[i + 0];
			t2 = nrp[i + 1];
			t3 = nrp[i + 2];
			ap[i + 0] = 0;
			t4 = nrp[i + 3];
			ap[i + 1] = 0;
			rp[i + 0] = t1;
			ap[i + 2] = 0;
			rp[i + 1] = t2;
			ap[i + 3] = 0;
			rp[i + 2] = t3;
			rp[i + 3] = t4;
		}
		for (nl += 4; i < nl; i++)
			rp[i] = nrp[i], ap[i] = 0;
	}
#else
	if (bn_sub_words (rp, ap, np, nl) - carry)
		memcpy(rp, ap, nl*sizeof(BN_ULONG));
#endif
	bn_correct_top(r);
	bn_correct_top(ret);
	bn_check_top(ret);

	return (1);
}
BN_from_montgomery(BIGNUM *ret, const BIGNUM *a, BN_MONT_CTX *mont, BN_CTX *ctx)
{
	int retn = 0;
#ifdef MONT_WORD
	BIGNUM *t;

	BN_CTX_start(ctx);
	if ((t = BN_CTX_get(ctx)) && BN_copy(t, a))
		retn = BN_from_montgomery_word(ret, t, mont);
	BN_CTX_end(ctx);
#else /* !MONT_WORD */
	BIGNUM *t1, *t2;

	BN_CTX_start(ctx);
	if ((t1 = BN_CTX_get(ctx)) == NULL)
		goto err;
	if ((t2 = BN_CTX_get(ctx)) == NULL)
		goto err;

	if (!BN_copy(t1, a))
		goto err;
	BN_mask_bits(t1, mont->ri);

	if (!BN_mul(t2, t1, &mont->Ni, ctx))
		goto err;
	BN_mask_bits(t2, mont->ri);

	if (!BN_mul(t1, t2, &mont->N, ctx))
		goto err;
	if (!BN_add(t2, a, t1))
		goto err;
	if (!BN_rshift(ret, t2, mont->ri))
		goto err;

	if (BN_ucmp(ret, &(mont->N)) >= 0) {
		if (!BN_usub(ret, ret, &(mont->N)))
			goto err;
	}
	retn = 1;
	bn_check_top(ret);

err:
	BN_CTX_end(ctx);
#endif /* MONT_WORD */
	return (retn);
}


static int
BN_from_montgomery_word(BIGNUM *ret, BIGNUM *r, BN_MONT_CTX *mont)
{
	BIGNUM *n;
	BN_ULONG *ap, *np, *rp, n0, v, carry;
	int nl, max, i;

	n = &(mont->N);
	nl = n->top;
	if (nl == 0) {
		ret->top = 0;
		return (1);
	}

	max = (2 * nl); /* carry is stored separately */
	if (bn_wexpand(r, max) == NULL)
		return (0);

	r->neg ^= n->neg;
	np = n->d;
	rp = r->d;

	/* clear the top words of T */
#if 1
	for (i=r->top; i<max; i++) /* memset? XXX */
		rp[i] = 0;
#else
	memset(&(rp[r->top]), 0, (max - r->top) * sizeof(BN_ULONG));
#endif

	r->top = max;
	n0 = mont->n0[0];

#ifdef BN_COUNT
	fprintf(stderr, "word BN_from_montgomery_word %d * %d\n", nl, nl);
#endif
	for (carry = 0, i = 0; i < nl; i++, rp++) {
		v = bn_mul_add_words(rp, np, nl, (rp[0] * n0) & BN_MASK2);
		v = (v + carry + rp[nl]) & BN_MASK2;
		carry |= (v != rp[nl]);
		carry &= (v <= rp[nl]);
		rp[nl] = v;
	}

	if (bn_wexpand(ret, nl) == NULL)
		return (0);
	ret->top = nl;
	ret->neg = r->neg;

	rp = ret->d;
	ap = &(r->d[nl]);

#define BRANCH_FREE 1
#if BRANCH_FREE
	{
		BN_ULONG *nrp;
		size_t m;

		v = bn_sub_words(rp, ap, np, nl) - carry;
		/* if subtraction result is real, then
		 * trick unconditional memcpy below to perform in-place
		 * "refresh" instead of actual copy. */
		m = (0 - (size_t)v);
		nrp = (BN_ULONG *)(((uintptr_t)rp & ~m)|((uintptr_t)ap & m));

		for (i = 0, nl -= 4; i < nl; i += 4) {
			BN_ULONG t1, t2, t3, t4;

			t1 = nrp[i + 0];
			t2 = nrp[i + 1];
			t3 = nrp[i + 2];
			ap[i + 0] = 0;
			t4 = nrp[i + 3];
			ap[i + 1] = 0;
			rp[i + 0] = t1;
			ap[i + 2] = 0;
			rp[i + 1] = t2;
			ap[i + 3] = 0;
			rp[i + 2] = t3;
			rp[i + 3] = t4;
		}
		for (nl += 4; i < nl; i++)
			rp[i] = nrp[i], ap[i] = 0;
	}
#else
	if (bn_sub_words (rp, ap, np, nl) - carry)
		memcpy(rp, ap, nl*sizeof(BN_ULONG));
#endif
	bn_correct_top(r);
	bn_correct_top(ret);
	bn_check_top(ret);

	return (1);
}


void
BN_init(BIGNUM *a)
{
	memset(a, 0, sizeof(BIGNUM));
	bn_check_top(a);
}


int
BN_is_bit_set(const BIGNUM *a, int n)
{
	int i, j;

	bn_check_top(a);
	if (n < 0)
		return 0;
	i = n / BN_BITS2;
	j = n % BN_BITS2;
	if (a->top <= i)
		return 0;
	return (int)(((a->d[i]) >> j) & ((BN_ULONG)1));
}


int
BN_lshift1(BIGNUM *r, const BIGNUM *a)
{
	BN_ULONG *ap, *rp, t, c;
	int i;

	bn_check_top(r);
	bn_check_top(a);

	if (r != a) {
		r->neg = a->neg;
		if (bn_wexpand(r, a->top + 1) == NULL)
			return (0);
		r->top = a->top;
	} else {
		if (bn_wexpand(r, a->top + 1) == NULL)
			return (0);
	}
	ap = a->d;
	rp = r->d;
	c = 0;
	for (i = 0; i < a->top; i++) {
		t= *(ap++);
		*(rp++) = ((t << 1) | c) & BN_MASK2;
		c = (t & BN_TBIT) ? 1 : 0;
	}
	if (c) {
		*rp = 1;
		r->top++;
	}
	bn_check_top(r);
	return (1);
}
BN_lshift(BIGNUM *r, const BIGNUM *a, int n)
{
	int i, nw, lb, rb;
	BN_ULONG *t, *f;
	BN_ULONG l;

	bn_check_top(r);
	bn_check_top(a);

	r->neg = a->neg;
	nw = n / BN_BITS2;
	if (bn_wexpand(r, a->top + nw + 1) == NULL)
		return (0);
	lb = n % BN_BITS2;
	rb = BN_BITS2 - lb;
	f = a->d;
	t = r->d;
	t[a->top + nw] = 0;
	if (lb == 0)
		for (i = a->top - 1; i >= 0; i--)
			t[nw + i] = f[i];
	else
		for (i = a->top - 1; i >= 0; i--) {
			l = f[i];
			t[nw + i + 1] |= (l >> rb) & BN_MASK2;
			t[nw + i] = (l << lb) & BN_MASK2;
		}
	memset(t, 0, nw * sizeof(t[0]));
/*	for (i=0; i<nw; i++)
		t[i]=0;*/
	r->top = a->top + nw + 1;
	bn_correct_top(r);
	bn_check_top(r);
	return (1);
}


int
BN_lshift1(BIGNUM *r, const BIGNUM *a)
{
	BN_ULONG *ap, *rp, t, c;
	int i;

	bn_check_top(r);
	bn_check_top(a);

	if (r != a) {
		r->neg = a->neg;
		if (bn_wexpand(r, a->top + 1) == NULL)
			return (0);
		r->top = a->top;
	} else {
		if (bn_wexpand(r, a->top + 1) == NULL)
			return (0);
	}
	ap = a->d;
	rp = r->d;
	c = 0;
	for (i = 0; i < a->top; i++) {
		t= *(ap++);
		*(rp++) = ((t << 1) | c) & BN_MASK2;
		c = (t & BN_TBIT) ? 1 : 0;
	}
	if (c) {
		*rp = 1;
		r->top++;
	}
	bn_check_top(r);
	return (1);
}


int
BN_mod_add_quick(BIGNUM *r, const BIGNUM *a, const BIGNUM *b, const BIGNUM *m)
{
	if (!BN_uadd(r, a, b))
		return 0;
	if (BN_ucmp(r, m) >= 0)
		return BN_usub(r, r, m);
	return 1;
}


int
BN_mod_exp(BIGNUM *r, const BIGNUM *a, const BIGNUM *p, const BIGNUM *m,
    BN_CTX *ctx)
{
	int ret;

	bn_check_top(a);
	bn_check_top(p);
	bn_check_top(m);

	/* For even modulus  m = 2^k*m_odd,  it might make sense to compute
	 * a^p mod m_odd  and  a^p mod 2^k  separately (with Montgomery
	 * exponentiation for the odd part), using appropriate exponent
	 * reductions, and combine the results using the CRT.
	 *
	 * For now, we use Montgomery only if the modulus is odd; otherwise,
	 * exponentiation using the reciprocal-based quick remaindering
	 * algorithm is used.
	 *
	 * (Timing obtained with expspeed.c [computations  a^p mod m
	 * where  a, p, m  are of the same length: 256, 512, 1024, 2048,
	 * 4096, 8192 bits], compared to the running time of the
	 * standard algorithm:
	 *
	 *   BN_mod_exp_mont   33 .. 40 %  [AMD K6-2, Linux, debug configuration]
         *                     55 .. 77 %  [UltraSparc processor, but
	 *                                  debug-solaris-sparcv8-gcc conf.]
	 *
	 *   BN_mod_exp_recp   50 .. 70 %  [AMD K6-2, Linux, debug configuration]
	 *                     62 .. 118 % [UltraSparc, debug-solaris-sparcv8-gcc]
	 *
	 * On the Sparc, BN_mod_exp_recp was faster than BN_mod_exp_mont
	 * at 2048 and more bits, but at 512 and 1024 bits, it was
	 * slower even than the standard algorithm!
	 *
	 * "Real" timings [linux-elf, solaris-sparcv9-gcc configurations]
	 * should be obtained when the new Montgomery reduction code
	 * has been integrated into OpenSSL.)
	 */

#define MONT_MUL_MOD
#define MONT_EXP_WORD
#define RECP_MUL_MOD

#ifdef MONT_MUL_MOD
	/* I have finally been able to take out this pre-condition of
	 * the top bit being set.  It was caused by an error in BN_div
	 * with negatives.  There was also another problem when for a^b%m
	 * a >= m.  eay 07-May-97 */
/*	if ((m->d[m->top-1]&BN_TBIT) && BN_is_odd(m)) */

	if (BN_is_odd(m)) {
#  ifdef MONT_EXP_WORD
		if (a->top == 1 && !a->neg &&
		    (BN_get_flags(p, BN_FLG_CONSTTIME) == 0)) {
			BN_ULONG A = a->d[0];
			ret = BN_mod_exp_mont_word(r, A,p, m,ctx, NULL);
		} else
#  endif
			ret = BN_mod_exp_mont(r, a,p, m,ctx, NULL);
	} else
#endif
#ifdef RECP_MUL_MOD
	{
		ret = BN_mod_exp_recp(r, a,p, m, ctx);
	}
#else
	{
		ret = BN_mod_exp_simple(r, a,p, m, ctx);
	}
#endif

	bn_check_top(r);
	return (ret);
}
BN_mod_exp_recp(BIGNUM *r, const BIGNUM *a, const BIGNUM *p, const BIGNUM *m,
    BN_CTX *ctx)
{
	int i, j, bits, ret = 0, wstart, wend, window, wvalue;
	int start = 1;
	BIGNUM *aa;
	/* Table of variables obtained from 'ctx' */
	BIGNUM *val[TABLE_SIZE];
	BN_RECP_CTX recp;

	if (BN_get_flags(p, BN_FLG_CONSTTIME) != 0) {
		/* BN_FLG_CONSTTIME only supported by BN_mod_exp_mont() */
		BNerr(BN_F_BN_MOD_EXP_RECP, ERR_R_SHOULD_NOT_HAVE_BEEN_CALLED);
		return -1;
	}

	bits = BN_num_bits(p);

	if (bits == 0) {
		ret = BN_one(r);
		return ret;
	}

	BN_CTX_start(ctx);
	if ((aa = BN_CTX_get(ctx)) == NULL)
		goto err;
	if ((val[0] = BN_CTX_get(ctx)) == NULL)
		goto err;

	BN_RECP_CTX_init(&recp);
	if (m->neg) {
		/* ignore sign of 'm' */
		if (!BN_copy(aa, m))
			goto err;
		aa->neg = 0;
		if (BN_RECP_CTX_set(&recp, aa, ctx) <= 0)
			goto err;
	} else {
		if (BN_RECP_CTX_set(&recp, m, ctx) <= 0)
			goto err;
	}

	if (!BN_nnmod(val[0], a, m, ctx))
		goto err;		/* 1 */
	if (BN_is_zero(val[0])) {
		BN_zero(r);
		ret = 1;
		goto err;
	}

	window = BN_window_bits_for_exponent_size(bits);
	if (window > 1) {
		if (!BN_mod_mul_reciprocal(aa, val[0], val[0], &recp, ctx))
			goto err;				/* 2 */
		j = 1 << (window - 1);
		for (i = 1; i < j; i++) {
			if (((val[i] = BN_CTX_get(ctx)) == NULL) ||
			    !BN_mod_mul_reciprocal(val[i], val[i - 1],
			    aa, &recp, ctx))
				goto err;
		}
	}

	start = 1;		/* This is used to avoid multiplication etc
				 * when there is only the value '1' in the
				 * buffer. */
	wvalue = 0;		/* The 'value' of the window */
	wstart = bits - 1;	/* The top bit of the window */
	wend = 0;		/* The bottom bit of the window */

	if (!BN_one(r))
		goto err;

	for (;;) {
		if (BN_is_bit_set(p, wstart) == 0) {
			if (!start)
				if (!BN_mod_mul_reciprocal(r, r,r, &recp, ctx))
					goto err;
			if (wstart == 0)
				break;
			wstart--;
			continue;
		}
		/* We now have wstart on a 'set' bit, we now need to work out
		 * how bit a window to do.  To do this we need to scan
		 * forward until the last set bit before the end of the
		 * window */
		j = wstart;
		wvalue = 1;
		wend = 0;
		for (i = 1; i < window; i++) {
			if (wstart - i < 0)
				break;
			if (BN_is_bit_set(p, wstart - i)) {
				wvalue <<= (i - wend);
				wvalue |= 1;
				wend = i;
			}
		}

		/* wend is the size of the current window */
		j = wend + 1;
		/* add the 'bytes above' */
		if (!start)
			for (i = 0; i < j; i++) {
				if (!BN_mod_mul_reciprocal(r, r,r, &recp, ctx))
					goto err;
			}

		/* wvalue will be an odd number < 2^window */
		if (!BN_mod_mul_reciprocal(r, r,val[wvalue >> 1], &recp, ctx))
			goto err;

		/* move the 'window' down further */
		wstart -= wend + 1;
		wvalue = 0;
		start = 0;
		if (wstart < 0)
			break;
	}
	ret = 1;

err:
	BN_CTX_end(ctx);
	BN_RECP_CTX_free(&recp);
	bn_check_top(r);
	return (ret);
}
BN_mod_exp_mont(BIGNUM *rr, const BIGNUM *a, const BIGNUM *p, const BIGNUM *m,
    BN_CTX *ctx, BN_MONT_CTX *in_mont)
{
	int i, j, bits, ret = 0, wstart, wend, window, wvalue;
	int start = 1;
	BIGNUM *d, *r;
	const BIGNUM *aa;
	/* Table of variables obtained from 'ctx' */
	BIGNUM *val[TABLE_SIZE];
	BN_MONT_CTX *mont = NULL;

	if (BN_get_flags(p, BN_FLG_CONSTTIME) != 0) {
		return BN_mod_exp_mont_consttime(rr, a, p, m, ctx, in_mont);
	}

	bn_check_top(a);
	bn_check_top(p);
	bn_check_top(m);

	if (!BN_is_odd(m)) {
		BNerr(BN_F_BN_MOD_EXP_MONT, BN_R_CALLED_WITH_EVEN_MODULUS);
		return (0);
	}
	bits = BN_num_bits(p);
	if (bits == 0) {
		ret = BN_one(rr);
		return ret;
	}

	BN_CTX_start(ctx);
	if ((d = BN_CTX_get(ctx)) == NULL)
		goto err;
	if ((r = BN_CTX_get(ctx)) == NULL)
		goto err;
	if ((val[0] = BN_CTX_get(ctx)) == NULL)
		goto err;

	/* If this is not done, things will break in the montgomery
	 * part */

	if (in_mont != NULL)
		mont = in_mont;
	else {
		if ((mont = BN_MONT_CTX_new()) == NULL)
			goto err;
		if (!BN_MONT_CTX_set(mont, m, ctx))
			goto err;
	}

	if (a->neg || BN_ucmp(a, m) >= 0) {
		if (!BN_nnmod(val[0], a,m, ctx))
			goto err;
		aa = val[0];
	} else
		aa = a;
	if (BN_is_zero(aa)) {
		BN_zero(rr);
		ret = 1;
		goto err;
	}
	if (!BN_to_montgomery(val[0], aa, mont, ctx))
		goto err; /* 1 */

	window = BN_window_bits_for_exponent_size(bits);
	if (window > 1) {
		if (!BN_mod_mul_montgomery(d, val[0], val[0], mont, ctx))
			goto err; /* 2 */
		j = 1 << (window - 1);
		for (i = 1; i < j; i++) {
			if (((val[i] = BN_CTX_get(ctx)) == NULL) ||
			    !BN_mod_mul_montgomery(val[i], val[i - 1],
			    d, mont, ctx))
				goto err;
		}
	}

	start = 1;		/* This is used to avoid multiplication etc
				 * when there is only the value '1' in the
				 * buffer. */
	wvalue = 0;		/* The 'value' of the window */
	wstart = bits - 1;	/* The top bit of the window */
	wend = 0;		/* The bottom bit of the window */

	if (!BN_to_montgomery(r, BN_value_one(), mont, ctx))
		goto err;
	for (;;) {
		if (BN_is_bit_set(p, wstart) == 0) {
			if (!start) {
				if (!BN_mod_mul_montgomery(r, r, r, mont, ctx))
					goto err;
			}
			if (wstart == 0)
				break;
			wstart--;
			continue;
		}
		/* We now have wstart on a 'set' bit, we now need to work out
		 * how bit a window to do.  To do this we need to scan
		 * forward until the last set bit before the end of the
		 * window */
		j = wstart;
		wvalue = 1;
		wend = 0;
		for (i = 1; i < window; i++) {
			if (wstart - i < 0)
				break;
			if (BN_is_bit_set(p, wstart - i)) {
				wvalue <<= (i - wend);
				wvalue |= 1;
				wend = i;
			}
		}

		/* wend is the size of the current window */
		j = wend + 1;
		/* add the 'bytes above' */
		if (!start)
			for (i = 0; i < j; i++) {
				if (!BN_mod_mul_montgomery(r, r, r, mont, ctx))
					goto err;
			}

		/* wvalue will be an odd number < 2^window */
		if (!BN_mod_mul_montgomery(r, r, val[wvalue >> 1], mont, ctx))
			goto err;

		/* move the 'window' down further */
		wstart -= wend + 1;
		wvalue = 0;
		start = 0;
		if (wstart < 0)
			break;
	}
	if (!BN_from_montgomery(rr, r,mont, ctx))
		goto err;
	ret = 1;

err:
	if ((in_mont == NULL) && (mont != NULL))
		BN_MONT_CTX_free(mont);
	BN_CTX_end(ctx);
	bn_check_top(rr);
	return (ret);
}
BN_mod_exp_mont_consttime(BIGNUM *rr, const BIGNUM *a, const BIGNUM *p,
    const BIGNUM *m, BN_CTX *ctx, BN_MONT_CTX *in_mont)
{
	int i, bits, ret = 0, window, wvalue;
	int top;
	BN_MONT_CTX *mont = NULL;
	int numPowers;
	unsigned char *powerbufFree = NULL;
	int powerbufLen = 0;
	unsigned char *powerbuf = NULL;
	BIGNUM tmp, am;

	bn_check_top(a);
	bn_check_top(p);
	bn_check_top(m);

	top = m->top;

	if (!(m->d[0] & 1)) {
		BNerr(BN_F_BN_MOD_EXP_MONT_CONSTTIME,
		    BN_R_CALLED_WITH_EVEN_MODULUS);
		return (0);
	}
	bits = BN_num_bits(p);
	if (bits == 0) {
		ret = BN_one(rr);
		return ret;
	}

	BN_CTX_start(ctx);

	/* Allocate a montgomery context if it was not supplied by the caller.
	 * If this is not done, things will break in the montgomery part.
 	 */
	if (in_mont != NULL)
		mont = in_mont;
	else {
		if ((mont = BN_MONT_CTX_new()) == NULL)
			goto err;
		if (!BN_MONT_CTX_set(mont, m, ctx))
			goto err;
	}

	/* Get the window size to use with size of p. */
	window = BN_window_bits_for_ctime_exponent_size(bits);
#if defined(OPENSSL_BN_ASM_MONT5)
	if (window == 6 && bits <= 1024)
		window = 5;	/* ~5% improvement of 2048-bit RSA sign */
#endif

	/* Allocate a buffer large enough to hold all of the pre-computed
	 * powers of am, am itself and tmp.
	 */
	numPowers = 1 << window;
	powerbufLen = sizeof(m->d[0]) * (top * numPowers +
	    ((2*top) > numPowers ? (2*top) : numPowers));
	if ((powerbufFree = malloc(powerbufLen +
	    MOD_EXP_CTIME_MIN_CACHE_LINE_WIDTH)) == NULL)
		goto err;

	powerbuf = MOD_EXP_CTIME_ALIGN(powerbufFree);
	memset(powerbuf, 0, powerbufLen);

	/* lay down tmp and am right after powers table */
	tmp.d = (BN_ULONG *)(powerbuf + sizeof(m->d[0]) * top * numPowers);
	am.d = tmp.d + top;
	tmp.top = am.top = 0;
	tmp.dmax = am.dmax = top;
	tmp.neg = am.neg = 0;
	tmp.flags = am.flags = BN_FLG_STATIC_DATA;

	/* prepare a^0 in Montgomery domain */
#if 1
	if (!BN_to_montgomery(&tmp, BN_value_one(), mont, ctx))
		goto err;
#else
	tmp.d[0] = (0 - m - >d[0]) & BN_MASK2;	/* 2^(top*BN_BITS2) - m */
	for (i = 1; i < top; i++)
		tmp.d[i] = (~m->d[i]) & BN_MASK2;
	tmp.top = top;
#endif

	/* prepare a^1 in Montgomery domain */
	if (a->neg || BN_ucmp(a, m) >= 0) {
		if (!BN_mod(&am, a,m, ctx))
			goto err;
		if (!BN_to_montgomery(&am, &am, mont, ctx))
			goto err;
	} else if (!BN_to_montgomery(&am, a,mont, ctx))
		goto err;

#if defined(OPENSSL_BN_ASM_MONT5)
	/* This optimization uses ideas from http://eprint.iacr.org/2011/239,
	 * specifically optimization of cache-timing attack countermeasures
	 * and pre-computation optimization. */

	/* Dedicated window==4 case improves 512-bit RSA sign by ~15%, but as
	 * 512-bit RSA is hardly relevant, we omit it to spare size... */
	if (window == 5 && top > 1) {
		void bn_mul_mont_gather5(BN_ULONG *rp, const BN_ULONG *ap,
		    const void *table, const BN_ULONG *np,
		    const BN_ULONG *n0, int num, int power);
		void bn_scatter5(const BN_ULONG *inp, size_t num,
		    void *table, size_t power);
		void bn_gather5(BN_ULONG *out, size_t num,
		    void *table, size_t power);

		BN_ULONG *np = mont->N.d, *n0 = mont->n0;

		/* BN_to_montgomery can contaminate words above .top
		 * [in BN_DEBUG[_DEBUG] build]... */
		for (i = am.top; i < top; i++)
			am.d[i] = 0;
		for (i = tmp.top; i < top; i++)
			tmp.d[i] = 0;

		bn_scatter5(tmp.d, top, powerbuf, 0);
		bn_scatter5(am.d, am.top, powerbuf, 1);
		bn_mul_mont(tmp.d, am.d, am.d, np, n0, top);
		bn_scatter5(tmp.d, top, powerbuf, 2);

#if 0
		for (i = 3; i < 32; i++) {
			/* Calculate a^i = a^(i-1) * a */
			bn_mul_mont_gather5(tmp.d, am.d, powerbuf, np,
			    n0, top, i - 1);
			bn_scatter5(tmp.d, top, powerbuf, i);
		}
#else
		/* same as above, but uses squaring for 1/2 of operations */
		for (i = 4; i < 32; i*=2) {
			bn_mul_mont(tmp.d, tmp.d, tmp.d, np, n0, top);
			bn_scatter5(tmp.d, top, powerbuf, i);
		}
		for (i = 3; i < 8; i += 2) {
			int j;
			bn_mul_mont_gather5(tmp.d, am.d, powerbuf, np,
			    n0, top, i - 1);
			bn_scatter5(tmp.d, top, powerbuf, i);
			for (j = 2 * i; j < 32; j *= 2) {
				bn_mul_mont(tmp.d, tmp.d, tmp.d, np, n0, top);
				bn_scatter5(tmp.d, top, powerbuf, j);
			}
		}
		for (; i < 16; i += 2) {
			bn_mul_mont_gather5(tmp.d, am.d, powerbuf, np,
			    n0, top, i - 1);
			bn_scatter5(tmp.d, top, powerbuf, i);
			bn_mul_mont(tmp.d, tmp.d, tmp.d, np, n0, top);
			bn_scatter5(tmp.d, top, powerbuf, 2*i);
		}
		for (; i < 32; i += 2) {
			bn_mul_mont_gather5(tmp.d, am.d, powerbuf, np,
			    n0, top, i - 1);
			bn_scatter5(tmp.d, top, powerbuf, i);
		}
#endif
		bits--;
		for (wvalue = 0, i = bits % 5; i >= 0; i--, bits--)
			wvalue = (wvalue << 1) + BN_is_bit_set(p, bits);
		bn_gather5(tmp.d, top, powerbuf, wvalue);

		/* Scan the exponent one window at a time starting from the most
		 * significant bits.
		 */
		while (bits >= 0) {
			for (wvalue = 0, i = 0; i < 5; i++, bits--)
				wvalue = (wvalue << 1) + BN_is_bit_set(p, bits);

			bn_mul_mont(tmp.d, tmp.d, tmp.d, np, n0, top);
			bn_mul_mont(tmp.d, tmp.d, tmp.d, np, n0, top);
			bn_mul_mont(tmp.d, tmp.d, tmp.d, np, n0, top);
			bn_mul_mont(tmp.d, tmp.d, tmp.d, np, n0, top);
			bn_mul_mont(tmp.d, tmp.d, tmp.d, np, n0, top);
			bn_mul_mont_gather5(tmp.d, tmp.d, powerbuf, np, n0, top, wvalue);
		}

		tmp.top = top;
		bn_correct_top(&tmp);
	} else
#endif
	{
		if (!MOD_EXP_CTIME_COPY_TO_PREBUF(&tmp, top, powerbuf, 0,
		    numPowers))
			goto err;
		if (!MOD_EXP_CTIME_COPY_TO_PREBUF(&am,  top, powerbuf, 1,
		    numPowers))
			goto err;

		/* If the window size is greater than 1, then calculate
		 * val[i=2..2^winsize-1]. Powers are computed as a*a^(i-1)
		 * (even powers could instead be computed as (a^(i/2))^2
		 * to use the slight performance advantage of sqr over mul).
		 */
		if (window > 1) {
			if (!BN_mod_mul_montgomery(&tmp, &am, &am, mont, ctx))
				goto err;
			if (!MOD_EXP_CTIME_COPY_TO_PREBUF(&tmp, top, powerbuf,
			    2, numPowers))
				goto err;
			for (i = 3; i < numPowers; i++) {
				/* Calculate a^i = a^(i-1) * a */
				if (!BN_mod_mul_montgomery(&tmp, &am, &tmp,
				    mont, ctx))
					goto err;
				if (!MOD_EXP_CTIME_COPY_TO_PREBUF(&tmp, top,
				    powerbuf, i, numPowers))
					goto err;
			}
		}

		bits--;
		for (wvalue = 0, i = bits % window; i >= 0; i--, bits--)
			wvalue = (wvalue << 1) + BN_is_bit_set(p, bits);
		if (!MOD_EXP_CTIME_COPY_FROM_PREBUF(&tmp, top, powerbuf,
		    wvalue, numPowers))
			goto err;

		/* Scan the exponent one window at a time starting from the most
		 * significant bits.
		 */
		while (bits >= 0) {
			wvalue = 0; /* The 'value' of the window */

			/* Scan the window, squaring the result as we go */
			for (i = 0; i < window; i++, bits--) {
				if (!BN_mod_mul_montgomery(&tmp, &tmp, &tmp,
				    mont, ctx))
					goto err;
				wvalue = (wvalue << 1) + BN_is_bit_set(p, bits);
			}

			/* Fetch the appropriate pre-computed value from the pre-buf */
			if (!MOD_EXP_CTIME_COPY_FROM_PREBUF(&am, top, powerbuf,
			    wvalue, numPowers))
				goto err;

			/* Multiply the result into the intermediate result */
			if (!BN_mod_mul_montgomery(&tmp, &tmp, &am, mont, ctx))
				goto err;
		}
	}

	/* Convert the final result from montgomery to standard format */
	if (!BN_from_montgomery(rr, &tmp, mont, ctx))
		goto err;
	ret = 1;

err:
	if ((in_mont == NULL) && (mont != NULL))
		BN_MONT_CTX_free(mont);
	if (powerbuf != NULL) {
		explicit_bzero(powerbuf, powerbufLen);
		free(powerbufFree);
	}
	BN_CTX_end(ctx);
	return (ret);
}
BN_mod_exp_mont_word(BIGNUM *rr, BN_ULONG a, const BIGNUM *p, const BIGNUM *m,
    BN_CTX *ctx, BN_MONT_CTX *in_mont)
{
	BN_MONT_CTX *mont = NULL;
	int b, bits, ret = 0;
	int r_is_one;
	BN_ULONG w, next_w;
	BIGNUM *d, *r, *t;
	BIGNUM *swap_tmp;

#define BN_MOD_MUL_WORD(r, w, m) \
		(BN_mul_word(r, (w)) && \
		(/* BN_ucmp(r, (m)) < 0 ? 1 :*/  \
			(BN_mod(t, r, m, ctx) && (swap_tmp = r, r = t, t = swap_tmp, 1))))
		/* BN_MOD_MUL_WORD is only used with 'w' large,
		 * so the BN_ucmp test is probably more overhead
		 * than always using BN_mod (which uses BN_copy if
		 * a similar test returns true). */
		/* We can use BN_mod and do not need BN_nnmod because our
		 * accumulator is never negative (the result of BN_mod does
		 * not depend on the sign of the modulus).
		 */
#define BN_TO_MONTGOMERY_WORD(r, w, mont) \
		(BN_set_word(r, (w)) && BN_to_montgomery(r, r, (mont), ctx))

	if (BN_get_flags(p, BN_FLG_CONSTTIME) != 0) {
		/* BN_FLG_CONSTTIME only supported by BN_mod_exp_mont() */
		BNerr(BN_F_BN_MOD_EXP_MONT_WORD,
		    ERR_R_SHOULD_NOT_HAVE_BEEN_CALLED);
		return -1;
	}

	bn_check_top(p);
	bn_check_top(m);

	if (!BN_is_odd(m)) {
		BNerr(BN_F_BN_MOD_EXP_MONT_WORD, BN_R_CALLED_WITH_EVEN_MODULUS);
		return (0);
	}
	if (m->top == 1)
		a %= m->d[0]; /* make sure that 'a' is reduced */

	bits = BN_num_bits(p);
	if (bits == 0) {
		ret = BN_one(rr);
		return ret;
	}
	if (a == 0) {
		BN_zero(rr);
		ret = 1;
		return ret;
	}

	BN_CTX_start(ctx);
	if ((d = BN_CTX_get(ctx)) == NULL)
		goto err;
	if ((r = BN_CTX_get(ctx)) == NULL)
		goto err;
	if ((t = BN_CTX_get(ctx)) == NULL)
		goto err;

	if (in_mont != NULL)
		mont = in_mont;
	else {
		if ((mont = BN_MONT_CTX_new()) == NULL)
			goto err;
		if (!BN_MONT_CTX_set(mont, m, ctx))
			goto err;
	}

	r_is_one = 1; /* except for Montgomery factor */

	/* bits-1 >= 0 */

	/* The result is accumulated in the product r*w. */
	w = a; /* bit 'bits-1' of 'p' is always set */
	for (b = bits - 2; b >= 0; b--) {
		/* First, square r*w. */
		next_w = w * w;
		if ((next_w / w) != w) /* overflow */
		{
			if (r_is_one) {
				if (!BN_TO_MONTGOMERY_WORD(r, w, mont))
					goto err;
				r_is_one = 0;
			} else {
				if (!BN_MOD_MUL_WORD(r, w, m))
					goto err;
			}
			next_w = 1;
		}
		w = next_w;
		if (!r_is_one) {
			if (!BN_mod_mul_montgomery(r, r, r, mont, ctx))
				goto err;
		}

		/* Second, multiply r*w by 'a' if exponent bit is set. */
		if (BN_is_bit_set(p, b)) {
			next_w = w * a;
			if ((next_w / a) != w) /* overflow */
			{
				if (r_is_one) {
					if (!BN_TO_MONTGOMERY_WORD(r, w, mont))
						goto err;
					r_is_one = 0;
				} else {
					if (!BN_MOD_MUL_WORD(r, w, m))
						goto err;
				}
				next_w = a;
			}
			w = next_w;
		}
	}

	/* Finally, set r:=r*w. */
	if (w != 1) {
		if (r_is_one) {
			if (!BN_TO_MONTGOMERY_WORD(r, w, mont))
				goto err;
			r_is_one = 0;
		} else {
			if (!BN_MOD_MUL_WORD(r, w, m))
				goto err;
		}
	}

	if (r_is_one) /* can happen only if a == 1*/
	{
		if (!BN_one(rr))
			goto err;
	} else {
		if (!BN_from_montgomery(rr, r, mont, ctx))
			goto err;
	}
	ret = 1;

err:
	if ((in_mont == NULL) && (mont != NULL))
		BN_MONT_CTX_free(mont);
	BN_CTX_end(ctx);
	bn_check_top(rr);
	return (ret);
}
BN_mod_exp_simple(BIGNUM *r, const BIGNUM *a, const BIGNUM *p, const BIGNUM *m,
    BN_CTX *ctx)
{
	int i, j,bits, ret = 0, wstart, wend, window, wvalue;
	int start = 1;
	BIGNUM *d;
	/* Table of variables obtained from 'ctx' */
	BIGNUM *val[TABLE_SIZE];

	if (BN_get_flags(p, BN_FLG_CONSTTIME) != 0) {
		/* BN_FLG_CONSTTIME only supported by BN_mod_exp_mont() */
		BNerr(BN_F_BN_MOD_EXP_SIMPLE,
		    ERR_R_SHOULD_NOT_HAVE_BEEN_CALLED);
		return -1;
	}

	bits = BN_num_bits(p);

	if (bits == 0) {
		ret = BN_one(r);
		return ret;
	}

	BN_CTX_start(ctx);
	if ((d = BN_CTX_get(ctx)) == NULL)
		goto err;
	if ((val[0] = BN_CTX_get(ctx)) == NULL)
		goto err;

	if (!BN_nnmod(val[0],a,m,ctx))
		goto err;		/* 1 */
	if (BN_is_zero(val[0])) {
		BN_zero(r);
		ret = 1;
		goto err;
	}

	window = BN_window_bits_for_exponent_size(bits);
	if (window > 1) {
		if (!BN_mod_mul(d, val[0], val[0], m, ctx))
			goto err;				/* 2 */
		j = 1 << (window - 1);
		for (i = 1; i < j; i++) {
			if (((val[i] = BN_CTX_get(ctx)) == NULL) ||
			    !BN_mod_mul(val[i], val[i - 1], d,m, ctx))
				goto err;
		}
	}

	start = 1;		/* This is used to avoid multiplication etc
				 * when there is only the value '1' in the
				 * buffer. */
	wvalue = 0;		/* The 'value' of the window */
	wstart = bits - 1;	/* The top bit of the window */
	wend = 0;		/* The bottom bit of the window */

	if (!BN_one(r))
		goto err;

	for (;;) {
		if (BN_is_bit_set(p, wstart) == 0) {
			if (!start)
				if (!BN_mod_mul(r, r, r, m, ctx))
					goto err;
			if (wstart == 0)
				break;
			wstart--;
			continue;
		}
		/* We now have wstart on a 'set' bit, we now need to work out
		 * how bit a window to do.  To do this we need to scan
		 * forward until the last set bit before the end of the
		 * window */
		j = wstart;
		wvalue = 1;
		wend = 0;
		for (i = 1; i < window; i++) {
			if (wstart - i < 0)
				break;
			if (BN_is_bit_set(p, wstart - i)) {
				wvalue <<= (i - wend);
				wvalue |= 1;
				wend = i;
			}
		}

		/* wend is the size of the current window */
		j = wend + 1;
		/* add the 'bytes above' */
		if (!start)
			for (i = 0; i < j; i++) {
				if (!BN_mod_mul(r, r, r, m, ctx))
					goto err;
			}

		/* wvalue will be an odd number < 2^window */
		if (!BN_mod_mul(r, r, val[wvalue >> 1], m, ctx))
			goto err;

		/* move the 'window' down further */
		wstart -= wend + 1;
		wvalue = 0;
		start = 0;
		if (wstart < 0)
			break;
	}
	ret = 1;

err:
	BN_CTX_end(ctx);
	bn_check_top(r);
	return (ret);
}


int
BN_mod_exp_mont(BIGNUM *rr, const BIGNUM *a, const BIGNUM *p, const BIGNUM *m,
    BN_CTX *ctx, BN_MONT_CTX *in_mont)
{
	int i, j, bits, ret = 0, wstart, wend, window, wvalue;
	int start = 1;
	BIGNUM *d, *r;
	const BIGNUM *aa;
	/* Table of variables obtained from 'ctx' */
	BIGNUM *val[TABLE_SIZE];
	BN_MONT_CTX *mont = NULL;

	if (BN_get_flags(p, BN_FLG_CONSTTIME) != 0) {
		return BN_mod_exp_mont_consttime(rr, a, p, m, ctx, in_mont);
	}

	bn_check_top(a);
	bn_check_top(p);
	bn_check_top(m);

	if (!BN_is_odd(m)) {
		BNerr(BN_F_BN_MOD_EXP_MONT, BN_R_CALLED_WITH_EVEN_MODULUS);
		return (0);
	}
	bits = BN_num_bits(p);
	if (bits == 0) {
		ret = BN_one(rr);
		return ret;
	}

	BN_CTX_start(ctx);
	if ((d = BN_CTX_get(ctx)) == NULL)
		goto err;
	if ((r = BN_CTX_get(ctx)) == NULL)
		goto err;
	if ((val[0] = BN_CTX_get(ctx)) == NULL)
		goto err;

	/* If this is not done, things will break in the montgomery
	 * part */

	if (in_mont != NULL)
		mont = in_mont;
	else {
		if ((mont = BN_MONT_CTX_new()) == NULL)
			goto err;
		if (!BN_MONT_CTX_set(mont, m, ctx))
			goto err;
	}

	if (a->neg || BN_ucmp(a, m) >= 0) {
		if (!BN_nnmod(val[0], a,m, ctx))
			goto err;
		aa = val[0];
	} else
		aa = a;
	if (BN_is_zero(aa)) {
		BN_zero(rr);
		ret = 1;
		goto err;
	}
	if (!BN_to_montgomery(val[0], aa, mont, ctx))
		goto err; /* 1 */

	window = BN_window_bits_for_exponent_size(bits);
	if (window > 1) {
		if (!BN_mod_mul_montgomery(d, val[0], val[0], mont, ctx))
			goto err; /* 2 */
		j = 1 << (window - 1);
		for (i = 1; i < j; i++) {
			if (((val[i] = BN_CTX_get(ctx)) == NULL) ||
			    !BN_mod_mul_montgomery(val[i], val[i - 1],
			    d, mont, ctx))
				goto err;
		}
	}

	start = 1;		/* This is used to avoid multiplication etc
				 * when there is only the value '1' in the
				 * buffer. */
	wvalue = 0;		/* The 'value' of the window */
	wstart = bits - 1;	/* The top bit of the window */
	wend = 0;		/* The bottom bit of the window */

	if (!BN_to_montgomery(r, BN_value_one(), mont, ctx))
		goto err;
	for (;;) {
		if (BN_is_bit_set(p, wstart) == 0) {
			if (!start) {
				if (!BN_mod_mul_montgomery(r, r, r, mont, ctx))
					goto err;
			}
			if (wstart == 0)
				break;
			wstart--;
			continue;
		}
		/* We now have wstart on a 'set' bit, we now need to work out
		 * how bit a window to do.  To do this we need to scan
		 * forward until the last set bit before the end of the
		 * window */
		j = wstart;
		wvalue = 1;
		wend = 0;
		for (i = 1; i < window; i++) {
			if (wstart - i < 0)
				break;
			if (BN_is_bit_set(p, wstart - i)) {
				wvalue <<= (i - wend);
				wvalue |= 1;
				wend = i;
			}
		}

		/* wend is the size of the current window */
		j = wend + 1;
		/* add the 'bytes above' */
		if (!start)
			for (i = 0; i < j; i++) {
				if (!BN_mod_mul_montgomery(r, r, r, mont, ctx))
					goto err;
			}

		/* wvalue will be an odd number < 2^window */
		if (!BN_mod_mul_montgomery(r, r, val[wvalue >> 1], mont, ctx))
			goto err;

		/* move the 'window' down further */
		wstart -= wend + 1;
		wvalue = 0;
		start = 0;
		if (wstart < 0)
			break;
	}
	if (!BN_from_montgomery(rr, r,mont, ctx))
		goto err;
	ret = 1;

err:
	if ((in_mont == NULL) && (mont != NULL))
		BN_MONT_CTX_free(mont);
	BN_CTX_end(ctx);
	bn_check_top(rr);
	return (ret);
}
BN_mod_exp_mont_consttime(BIGNUM *rr, const BIGNUM *a, const BIGNUM *p,
    const BIGNUM *m, BN_CTX *ctx, BN_MONT_CTX *in_mont)
{
	int i, bits, ret = 0, window, wvalue;
	int top;
	BN_MONT_CTX *mont = NULL;
	int numPowers;
	unsigned char *powerbufFree = NULL;
	int powerbufLen = 0;
	unsigned char *powerbuf = NULL;
	BIGNUM tmp, am;

	bn_check_top(a);
	bn_check_top(p);
	bn_check_top(m);

	top = m->top;

	if (!(m->d[0] & 1)) {
		BNerr(BN_F_BN_MOD_EXP_MONT_CONSTTIME,
		    BN_R_CALLED_WITH_EVEN_MODULUS);
		return (0);
	}
	bits = BN_num_bits(p);
	if (bits == 0) {
		ret = BN_one(rr);
		return ret;
	}

	BN_CTX_start(ctx);

	/* Allocate a montgomery context if it was not supplied by the caller.
	 * If this is not done, things will break in the montgomery part.
 	 */
	if (in_mont != NULL)
		mont = in_mont;
	else {
		if ((mont = BN_MONT_CTX_new()) == NULL)
			goto err;
		if (!BN_MONT_CTX_set(mont, m, ctx))
			goto err;
	}

	/* Get the window size to use with size of p. */
	window = BN_window_bits_for_ctime_exponent_size(bits);
#if defined(OPENSSL_BN_ASM_MONT5)
	if (window == 6 && bits <= 1024)
		window = 5;	/* ~5% improvement of 2048-bit RSA sign */
#endif

	/* Allocate a buffer large enough to hold all of the pre-computed
	 * powers of am, am itself and tmp.
	 */
	numPowers = 1 << window;
	powerbufLen = sizeof(m->d[0]) * (top * numPowers +
	    ((2*top) > numPowers ? (2*top) : numPowers));
	if ((powerbufFree = malloc(powerbufLen +
	    MOD_EXP_CTIME_MIN_CACHE_LINE_WIDTH)) == NULL)
		goto err;

	powerbuf = MOD_EXP_CTIME_ALIGN(powerbufFree);
	memset(powerbuf, 0, powerbufLen);

	/* lay down tmp and am right after powers table */
	tmp.d = (BN_ULONG *)(powerbuf + sizeof(m->d[0]) * top * numPowers);
	am.d = tmp.d + top;
	tmp.top = am.top = 0;
	tmp.dmax = am.dmax = top;
	tmp.neg = am.neg = 0;
	tmp.flags = am.flags = BN_FLG_STATIC_DATA;

	/* prepare a^0 in Montgomery domain */
#if 1
	if (!BN_to_montgomery(&tmp, BN_value_one(), mont, ctx))
		goto err;
#else
	tmp.d[0] = (0 - m - >d[0]) & BN_MASK2;	/* 2^(top*BN_BITS2) - m */
	for (i = 1; i < top; i++)
		tmp.d[i] = (~m->d[i]) & BN_MASK2;
	tmp.top = top;
#endif

	/* prepare a^1 in Montgomery domain */
	if (a->neg || BN_ucmp(a, m) >= 0) {
		if (!BN_mod(&am, a,m, ctx))
			goto err;
		if (!BN_to_montgomery(&am, &am, mont, ctx))
			goto err;
	} else if (!BN_to_montgomery(&am, a,mont, ctx))
		goto err;

#if defined(OPENSSL_BN_ASM_MONT5)
	/* This optimization uses ideas from http://eprint.iacr.org/2011/239,
	 * specifically optimization of cache-timing attack countermeasures
	 * and pre-computation optimization. */

	/* Dedicated window==4 case improves 512-bit RSA sign by ~15%, but as
	 * 512-bit RSA is hardly relevant, we omit it to spare size... */
	if (window == 5 && top > 1) {
		void bn_mul_mont_gather5(BN_ULONG *rp, const BN_ULONG *ap,
		    const void *table, const BN_ULONG *np,
		    const BN_ULONG *n0, int num, int power);
		void bn_scatter5(const BN_ULONG *inp, size_t num,
		    void *table, size_t power);
		void bn_gather5(BN_ULONG *out, size_t num,
		    void *table, size_t power);

		BN_ULONG *np = mont->N.d, *n0 = mont->n0;

		/* BN_to_montgomery can contaminate words above .top
		 * [in BN_DEBUG[_DEBUG] build]... */
		for (i = am.top; i < top; i++)
			am.d[i] = 0;
		for (i = tmp.top; i < top; i++)
			tmp.d[i] = 0;

		bn_scatter5(tmp.d, top, powerbuf, 0);
		bn_scatter5(am.d, am.top, powerbuf, 1);
		bn_mul_mont(tmp.d, am.d, am.d, np, n0, top);
		bn_scatter5(tmp.d, top, powerbuf, 2);

#if 0
		for (i = 3; i < 32; i++) {
			/* Calculate a^i = a^(i-1) * a */
			bn_mul_mont_gather5(tmp.d, am.d, powerbuf, np,
			    n0, top, i - 1);
			bn_scatter5(tmp.d, top, powerbuf, i);
		}
#else
		/* same as above, but uses squaring for 1/2 of operations */
		for (i = 4; i < 32; i*=2) {
			bn_mul_mont(tmp.d, tmp.d, tmp.d, np, n0, top);
			bn_scatter5(tmp.d, top, powerbuf, i);
		}
		for (i = 3; i < 8; i += 2) {
			int j;
			bn_mul_mont_gather5(tmp.d, am.d, powerbuf, np,
			    n0, top, i - 1);
			bn_scatter5(tmp.d, top, powerbuf, i);
			for (j = 2 * i; j < 32; j *= 2) {
				bn_mul_mont(tmp.d, tmp.d, tmp.d, np, n0, top);
				bn_scatter5(tmp.d, top, powerbuf, j);
			}
		}
		for (; i < 16; i += 2) {
			bn_mul_mont_gather5(tmp.d, am.d, powerbuf, np,
			    n0, top, i - 1);
			bn_scatter5(tmp.d, top, powerbuf, i);
			bn_mul_mont(tmp.d, tmp.d, tmp.d, np, n0, top);
			bn_scatter5(tmp.d, top, powerbuf, 2*i);
		}
		for (; i < 32; i += 2) {
			bn_mul_mont_gather5(tmp.d, am.d, powerbuf, np,
			    n0, top, i - 1);
			bn_scatter5(tmp.d, top, powerbuf, i);
		}
#endif
		bits--;
		for (wvalue = 0, i = bits % 5; i >= 0; i--, bits--)
			wvalue = (wvalue << 1) + BN_is_bit_set(p, bits);
		bn_gather5(tmp.d, top, powerbuf, wvalue);

		/* Scan the exponent one window at a time starting from the most
		 * significant bits.
		 */
		while (bits >= 0) {
			for (wvalue = 0, i = 0; i < 5; i++, bits--)
				wvalue = (wvalue << 1) + BN_is_bit_set(p, bits);

			bn_mul_mont(tmp.d, tmp.d, tmp.d, np, n0, top);
			bn_mul_mont(tmp.d, tmp.d, tmp.d, np, n0, top);
			bn_mul_mont(tmp.d, tmp.d, tmp.d, np, n0, top);
			bn_mul_mont(tmp.d, tmp.d, tmp.d, np, n0, top);
			bn_mul_mont(tmp.d, tmp.d, tmp.d, np, n0, top);
			bn_mul_mont_gather5(tmp.d, tmp.d, powerbuf, np, n0, top, wvalue);
		}

		tmp.top = top;
		bn_correct_top(&tmp);
	} else
#endif
	{
		if (!MOD_EXP_CTIME_COPY_TO_PREBUF(&tmp, top, powerbuf, 0,
		    numPowers))
			goto err;
		if (!MOD_EXP_CTIME_COPY_TO_PREBUF(&am,  top, powerbuf, 1,
		    numPowers))
			goto err;

		/* If the window size is greater than 1, then calculate
		 * val[i=2..2^winsize-1]. Powers are computed as a*a^(i-1)
		 * (even powers could instead be computed as (a^(i/2))^2
		 * to use the slight performance advantage of sqr over mul).
		 */
		if (window > 1) {
			if (!BN_mod_mul_montgomery(&tmp, &am, &am, mont, ctx))
				goto err;
			if (!MOD_EXP_CTIME_COPY_TO_PREBUF(&tmp, top, powerbuf,
			    2, numPowers))
				goto err;
			for (i = 3; i < numPowers; i++) {
				/* Calculate a^i = a^(i-1) * a */
				if (!BN_mod_mul_montgomery(&tmp, &am, &tmp,
				    mont, ctx))
					goto err;
				if (!MOD_EXP_CTIME_COPY_TO_PREBUF(&tmp, top,
				    powerbuf, i, numPowers))
					goto err;
			}
		}

		bits--;
		for (wvalue = 0, i = bits % window; i >= 0; i--, bits--)
			wvalue = (wvalue << 1) + BN_is_bit_set(p, bits);
		if (!MOD_EXP_CTIME_COPY_FROM_PREBUF(&tmp, top, powerbuf,
		    wvalue, numPowers))
			goto err;

		/* Scan the exponent one window at a time starting from the most
		 * significant bits.
		 */
		while (bits >= 0) {
			wvalue = 0; /* The 'value' of the window */

			/* Scan the window, squaring the result as we go */
			for (i = 0; i < window; i++, bits--) {
				if (!BN_mod_mul_montgomery(&tmp, &tmp, &tmp,
				    mont, ctx))
					goto err;
				wvalue = (wvalue << 1) + BN_is_bit_set(p, bits);
			}

			/* Fetch the appropriate pre-computed value from the pre-buf */
			if (!MOD_EXP_CTIME_COPY_FROM_PREBUF(&am, top, powerbuf,
			    wvalue, numPowers))
				goto err;

			/* Multiply the result into the intermediate result */
			if (!BN_mod_mul_montgomery(&tmp, &tmp, &am, mont, ctx))
				goto err;
		}
	}

	/* Convert the final result from montgomery to standard format */
	if (!BN_from_montgomery(rr, &tmp, mont, ctx))
		goto err;
	ret = 1;

err:
	if ((in_mont == NULL) && (mont != NULL))
		BN_MONT_CTX_free(mont);
	if (powerbuf != NULL) {
		explicit_bzero(powerbuf, powerbufLen);
		free(powerbufFree);
	}
	BN_CTX_end(ctx);
	return (ret);
}
BN_mod_exp_mont_word(BIGNUM *rr, BN_ULONG a, const BIGNUM *p, const BIGNUM *m,
    BN_CTX *ctx, BN_MONT_CTX *in_mont)
{
	BN_MONT_CTX *mont = NULL;
	int b, bits, ret = 0;
	int r_is_one;
	BN_ULONG w, next_w;
	BIGNUM *d, *r, *t;
	BIGNUM *swap_tmp;

#define BN_MOD_MUL_WORD(r, w, m) \
		(BN_mul_word(r, (w)) && \
		(/* BN_ucmp(r, (m)) < 0 ? 1 :*/  \
			(BN_mod(t, r, m, ctx) && (swap_tmp = r, r = t, t = swap_tmp, 1))))
		/* BN_MOD_MUL_WORD is only used with 'w' large,
		 * so the BN_ucmp test is probably more overhead
		 * than always using BN_mod (which uses BN_copy if
		 * a similar test returns true). */
		/* We can use BN_mod and do not need BN_nnmod because our
		 * accumulator is never negative (the result of BN_mod does
		 * not depend on the sign of the modulus).
		 */
#define BN_TO_MONTGOMERY_WORD(r, w, mont) \
		(BN_set_word(r, (w)) && BN_to_montgomery(r, r, (mont), ctx))

	if (BN_get_flags(p, BN_FLG_CONSTTIME) != 0) {
		/* BN_FLG_CONSTTIME only supported by BN_mod_exp_mont() */
		BNerr(BN_F_BN_MOD_EXP_MONT_WORD,
		    ERR_R_SHOULD_NOT_HAVE_BEEN_CALLED);
		return -1;
	}

	bn_check_top(p);
	bn_check_top(m);

	if (!BN_is_odd(m)) {
		BNerr(BN_F_BN_MOD_EXP_MONT_WORD, BN_R_CALLED_WITH_EVEN_MODULUS);
		return (0);
	}
	if (m->top == 1)
		a %= m->d[0]; /* make sure that 'a' is reduced */

	bits = BN_num_bits(p);
	if (bits == 0) {
		ret = BN_one(rr);
		return ret;
	}
	if (a == 0) {
		BN_zero(rr);
		ret = 1;
		return ret;
	}

	BN_CTX_start(ctx);
	if ((d = BN_CTX_get(ctx)) == NULL)
		goto err;
	if ((r = BN_CTX_get(ctx)) == NULL)
		goto err;
	if ((t = BN_CTX_get(ctx)) == NULL)
		goto err;

	if (in_mont != NULL)
		mont = in_mont;
	else {
		if ((mont = BN_MONT_CTX_new()) == NULL)
			goto err;
		if (!BN_MONT_CTX_set(mont, m, ctx))
			goto err;
	}

	r_is_one = 1; /* except for Montgomery factor */

	/* bits-1 >= 0 */

	/* The result is accumulated in the product r*w. */
	w = a; /* bit 'bits-1' of 'p' is always set */
	for (b = bits - 2; b >= 0; b--) {
		/* First, square r*w. */
		next_w = w * w;
		if ((next_w / w) != w) /* overflow */
		{
			if (r_is_one) {
				if (!BN_TO_MONTGOMERY_WORD(r, w, mont))
					goto err;
				r_is_one = 0;
			} else {
				if (!BN_MOD_MUL_WORD(r, w, m))
					goto err;
			}
			next_w = 1;
		}
		w = next_w;
		if (!r_is_one) {
			if (!BN_mod_mul_montgomery(r, r, r, mont, ctx))
				goto err;
		}

		/* Second, multiply r*w by 'a' if exponent bit is set. */
		if (BN_is_bit_set(p, b)) {
			next_w = w * a;
			if ((next_w / a) != w) /* overflow */
			{
				if (r_is_one) {
					if (!BN_TO_MONTGOMERY_WORD(r, w, mont))
						goto err;
					r_is_one = 0;
				} else {
					if (!BN_MOD_MUL_WORD(r, w, m))
						goto err;
				}
				next_w = a;
			}
			w = next_w;
		}
	}

	/* Finally, set r:=r*w. */
	if (w != 1) {
		if (r_is_one) {
			if (!BN_TO_MONTGOMERY_WORD(r, w, mont))
				goto err;
			r_is_one = 0;
		} else {
			if (!BN_MOD_MUL_WORD(r, w, m))
				goto err;
		}
	}

	if (r_is_one) /* can happen only if a == 1*/
	{
		if (!BN_one(rr))
			goto err;
	} else {
		if (!BN_from_montgomery(rr, r, mont, ctx))
			goto err;
	}
	ret = 1;

err:
	if ((in_mont == NULL) && (mont != NULL))
		BN_MONT_CTX_free(mont);
	BN_CTX_end(ctx);
	bn_check_top(rr);
	return (ret);
}


int
BN_mod_exp_mont_consttime(BIGNUM *rr, const BIGNUM *a, const BIGNUM *p,
    const BIGNUM *m, BN_CTX *ctx, BN_MONT_CTX *in_mont)
{
	int i, bits, ret = 0, window, wvalue;
	int top;
	BN_MONT_CTX *mont = NULL;
	int numPowers;
	unsigned char *powerbufFree = NULL;
	int powerbufLen = 0;
	unsigned char *powerbuf = NULL;
	BIGNUM tmp, am;

	bn_check_top(a);
	bn_check_top(p);
	bn_check_top(m);

	top = m->top;

	if (!(m->d[0] & 1)) {
		BNerr(BN_F_BN_MOD_EXP_MONT_CONSTTIME,
		    BN_R_CALLED_WITH_EVEN_MODULUS);
		return (0);
	}
	bits = BN_num_bits(p);
	if (bits == 0) {
		ret = BN_one(rr);
		return ret;
	}

	BN_CTX_start(ctx);

	/* Allocate a montgomery context if it was not supplied by the caller.
	 * If this is not done, things will break in the montgomery part.
 	 */
	if (in_mont != NULL)
		mont = in_mont;
	else {
		if ((mont = BN_MONT_CTX_new()) == NULL)
			goto err;
		if (!BN_MONT_CTX_set(mont, m, ctx))
			goto err;
	}

	/* Get the window size to use with size of p. */
	window = BN_window_bits_for_ctime_exponent_size(bits);
#if defined(OPENSSL_BN_ASM_MONT5)
	if (window == 6 && bits <= 1024)
		window = 5;	/* ~5% improvement of 2048-bit RSA sign */
#endif

	/* Allocate a buffer large enough to hold all of the pre-computed
	 * powers of am, am itself and tmp.
	 */
	numPowers = 1 << window;
	powerbufLen = sizeof(m->d[0]) * (top * numPowers +
	    ((2*top) > numPowers ? (2*top) : numPowers));
	if ((powerbufFree = malloc(powerbufLen +
	    MOD_EXP_CTIME_MIN_CACHE_LINE_WIDTH)) == NULL)
		goto err;

	powerbuf = MOD_EXP_CTIME_ALIGN(powerbufFree);
	memset(powerbuf, 0, powerbufLen);

	/* lay down tmp and am right after powers table */
	tmp.d = (BN_ULONG *)(powerbuf + sizeof(m->d[0]) * top * numPowers);
	am.d = tmp.d + top;
	tmp.top = am.top = 0;
	tmp.dmax = am.dmax = top;
	tmp.neg = am.neg = 0;
	tmp.flags = am.flags = BN_FLG_STATIC_DATA;

	/* prepare a^0 in Montgomery domain */
#if 1
	if (!BN_to_montgomery(&tmp, BN_value_one(), mont, ctx))
		goto err;
#else
	tmp.d[0] = (0 - m - >d[0]) & BN_MASK2;	/* 2^(top*BN_BITS2) - m */
	for (i = 1; i < top; i++)
		tmp.d[i] = (~m->d[i]) & BN_MASK2;
	tmp.top = top;
#endif

	/* prepare a^1 in Montgomery domain */
	if (a->neg || BN_ucmp(a, m) >= 0) {
		if (!BN_mod(&am, a,m, ctx))
			goto err;
		if (!BN_to_montgomery(&am, &am, mont, ctx))
			goto err;
	} else if (!BN_to_montgomery(&am, a,mont, ctx))
		goto err;

#if defined(OPENSSL_BN_ASM_MONT5)
	/* This optimization uses ideas from http://eprint.iacr.org/2011/239,
	 * specifically optimization of cache-timing attack countermeasures
	 * and pre-computation optimization. */

	/* Dedicated window==4 case improves 512-bit RSA sign by ~15%, but as
	 * 512-bit RSA is hardly relevant, we omit it to spare size... */
	if (window == 5 && top > 1) {
		void bn_mul_mont_gather5(BN_ULONG *rp, const BN_ULONG *ap,
		    const void *table, const BN_ULONG *np,
		    const BN_ULONG *n0, int num, int power);
		void bn_scatter5(const BN_ULONG *inp, size_t num,
		    void *table, size_t power);
		void bn_gather5(BN_ULONG *out, size_t num,
		    void *table, size_t power);

		BN_ULONG *np = mont->N.d, *n0 = mont->n0;

		/* BN_to_montgomery can contaminate words above .top
		 * [in BN_DEBUG[_DEBUG] build]... */
		for (i = am.top; i < top; i++)
			am.d[i] = 0;
		for (i = tmp.top; i < top; i++)
			tmp.d[i] = 0;

		bn_scatter5(tmp.d, top, powerbuf, 0);
		bn_scatter5(am.d, am.top, powerbuf, 1);
		bn_mul_mont(tmp.d, am.d, am.d, np, n0, top);
		bn_scatter5(tmp.d, top, powerbuf, 2);

#if 0
		for (i = 3; i < 32; i++) {
			/* Calculate a^i = a^(i-1) * a */
			bn_mul_mont_gather5(tmp.d, am.d, powerbuf, np,
			    n0, top, i - 1);
			bn_scatter5(tmp.d, top, powerbuf, i);
		}
#else
		/* same as above, but uses squaring for 1/2 of operations */
		for (i = 4; i < 32; i*=2) {
			bn_mul_mont(tmp.d, tmp.d, tmp.d, np, n0, top);
			bn_scatter5(tmp.d, top, powerbuf, i);
		}
		for (i = 3; i < 8; i += 2) {
			int j;
			bn_mul_mont_gather5(tmp.d, am.d, powerbuf, np,
			    n0, top, i - 1);
			bn_scatter5(tmp.d, top, powerbuf, i);
			for (j = 2 * i; j < 32; j *= 2) {
				bn_mul_mont(tmp.d, tmp.d, tmp.d, np, n0, top);
				bn_scatter5(tmp.d, top, powerbuf, j);
			}
		}
		for (; i < 16; i += 2) {
			bn_mul_mont_gather5(tmp.d, am.d, powerbuf, np,
			    n0, top, i - 1);
			bn_scatter5(tmp.d, top, powerbuf, i);
			bn_mul_mont(tmp.d, tmp.d, tmp.d, np, n0, top);
			bn_scatter5(tmp.d, top, powerbuf, 2*i);
		}
		for (; i < 32; i += 2) {
			bn_mul_mont_gather5(tmp.d, am.d, powerbuf, np,
			    n0, top, i - 1);
			bn_scatter5(tmp.d, top, powerbuf, i);
		}
#endif
		bits--;
		for (wvalue = 0, i = bits % 5; i >= 0; i--, bits--)
			wvalue = (wvalue << 1) + BN_is_bit_set(p, bits);
		bn_gather5(tmp.d, top, powerbuf, wvalue);

		/* Scan the exponent one window at a time starting from the most
		 * significant bits.
		 */
		while (bits >= 0) {
			for (wvalue = 0, i = 0; i < 5; i++, bits--)
				wvalue = (wvalue << 1) + BN_is_bit_set(p, bits);

			bn_mul_mont(tmp.d, tmp.d, tmp.d, np, n0, top);
			bn_mul_mont(tmp.d, tmp.d, tmp.d, np, n0, top);
			bn_mul_mont(tmp.d, tmp.d, tmp.d, np, n0, top);
			bn_mul_mont(tmp.d, tmp.d, tmp.d, np, n0, top);
			bn_mul_mont(tmp.d, tmp.d, tmp.d, np, n0, top);
			bn_mul_mont_gather5(tmp.d, tmp.d, powerbuf, np, n0, top, wvalue);
		}

		tmp.top = top;
		bn_correct_top(&tmp);
	} else
#endif
	{
		if (!MOD_EXP_CTIME_COPY_TO_PREBUF(&tmp, top, powerbuf, 0,
		    numPowers))
			goto err;
		if (!MOD_EXP_CTIME_COPY_TO_PREBUF(&am,  top, powerbuf, 1,
		    numPowers))
			goto err;

		/* If the window size is greater than 1, then calculate
		 * val[i=2..2^winsize-1]. Powers are computed as a*a^(i-1)
		 * (even powers could instead be computed as (a^(i/2))^2
		 * to use the slight performance advantage of sqr over mul).
		 */
		if (window > 1) {
			if (!BN_mod_mul_montgomery(&tmp, &am, &am, mont, ctx))
				goto err;
			if (!MOD_EXP_CTIME_COPY_TO_PREBUF(&tmp, top, powerbuf,
			    2, numPowers))
				goto err;
			for (i = 3; i < numPowers; i++) {
				/* Calculate a^i = a^(i-1) * a */
				if (!BN_mod_mul_montgomery(&tmp, &am, &tmp,
				    mont, ctx))
					goto err;
				if (!MOD_EXP_CTIME_COPY_TO_PREBUF(&tmp, top,
				    powerbuf, i, numPowers))
					goto err;
			}
		}

		bits--;
		for (wvalue = 0, i = bits % window; i >= 0; i--, bits--)
			wvalue = (wvalue << 1) + BN_is_bit_set(p, bits);
		if (!MOD_EXP_CTIME_COPY_FROM_PREBUF(&tmp, top, powerbuf,
		    wvalue, numPowers))
			goto err;

		/* Scan the exponent one window at a time starting from the most
		 * significant bits.
		 */
		while (bits >= 0) {
			wvalue = 0; /* The 'value' of the window */

			/* Scan the window, squaring the result as we go */
			for (i = 0; i < window; i++, bits--) {
				if (!BN_mod_mul_montgomery(&tmp, &tmp, &tmp,
				    mont, ctx))
					goto err;
				wvalue = (wvalue << 1) + BN_is_bit_set(p, bits);
			}

			/* Fetch the appropriate pre-computed value from the pre-buf */
			if (!MOD_EXP_CTIME_COPY_FROM_PREBUF(&am, top, powerbuf,
			    wvalue, numPowers))
				goto err;

			/* Multiply the result into the intermediate result */
			if (!BN_mod_mul_montgomery(&tmp, &tmp, &am, mont, ctx))
				goto err;
		}
	}

	/* Convert the final result from montgomery to standard format */
	if (!BN_from_montgomery(rr, &tmp, mont, ctx))
		goto err;
	ret = 1;

err:
	if ((in_mont == NULL) && (mont != NULL))
		BN_MONT_CTX_free(mont);
	if (powerbuf != NULL) {
		explicit_bzero(powerbuf, powerbufLen);
		free(powerbufFree);
	}
	BN_CTX_end(ctx);
	return (ret);
}


BIGNUM *
BN_mod_inverse(BIGNUM *in, const BIGNUM *a, const BIGNUM *n, BN_CTX *ctx)
{
	BIGNUM *A, *B, *X, *Y, *M, *D, *T, *R = NULL;
	BIGNUM *ret = NULL;
	int sign;

	if ((BN_get_flags(a, BN_FLG_CONSTTIME) != 0) ||
	    (BN_get_flags(n, BN_FLG_CONSTTIME) != 0)) {
		return BN_mod_inverse_no_branch(in, a, n, ctx);
	}

	bn_check_top(a);
	bn_check_top(n);

	BN_CTX_start(ctx);
	if ((A = BN_CTX_get(ctx)) == NULL)
		goto err;
	if ((B = BN_CTX_get(ctx)) == NULL)
		goto err;
	if ((X = BN_CTX_get(ctx)) == NULL)
		goto err;
	if ((D = BN_CTX_get(ctx)) == NULL)
		goto err;
	if ((M = BN_CTX_get(ctx)) == NULL)
		goto err;
	if ((Y = BN_CTX_get(ctx)) == NULL)
		goto err;
	if ((T = BN_CTX_get(ctx)) == NULL)
		goto err;

	if (in == NULL)
		R = BN_new();
	else
		R = in;
	if (R == NULL)
		goto err;

	BN_one(X);
	BN_zero(Y);
	if (BN_copy(B, a) == NULL)
		goto err;
	if (BN_copy(A, n) == NULL)
		goto err;
	A->neg = 0;
	if (B->neg || (BN_ucmp(B, A) >= 0)) {
		if (!BN_nnmod(B, B, A, ctx))
			goto err;
	}
	sign = -1;
	/* From  B = a mod |n|,  A = |n|  it follows that
	 *
	 *      0 <= B < A,
	 *     -sign*X*a  ==  B   (mod |n|),
	 *      sign*Y*a  ==  A   (mod |n|).
	 */

	if (BN_is_odd(n) && (BN_num_bits(n) <= (BN_BITS <= 32 ? 450 : 2048))) {
		/* Binary inversion algorithm; requires odd modulus.
		 * This is faster than the general algorithm if the modulus
		 * is sufficiently small (about 400 .. 500 bits on 32-bit
		 * sytems, but much more on 64-bit systems) */
		int shift;

		while (!BN_is_zero(B)) {
			/*
			 *      0 < B < |n|,
			 *      0 < A <= |n|,
			 * (1) -sign*X*a  ==  B   (mod |n|),
			 * (2)  sign*Y*a  ==  A   (mod |n|)
			 */

			/* Now divide  B  by the maximum possible power of two in the integers,
			 * and divide  X  by the same value mod |n|.
			 * When we're done, (1) still holds. */
			shift = 0;
			while (!BN_is_bit_set(B, shift)) /* note that 0 < B */
			{
				shift++;

				if (BN_is_odd(X)) {
					if (!BN_uadd(X, X, n))
						goto err;
				}
				/* now X is even, so we can easily divide it by two */
				if (!BN_rshift1(X, X))
					goto err;
			}
			if (shift > 0) {
				if (!BN_rshift(B, B, shift))
					goto err;
			}


			/* Same for  A  and  Y.  Afterwards, (2) still holds. */
			shift = 0;
			while (!BN_is_bit_set(A, shift)) /* note that 0 < A */
			{
				shift++;

				if (BN_is_odd(Y)) {
					if (!BN_uadd(Y, Y, n))
						goto err;
				}
				/* now Y is even */
				if (!BN_rshift1(Y, Y))
					goto err;
			}
			if (shift > 0) {
				if (!BN_rshift(A, A, shift))
					goto err;
			}


			/* We still have (1) and (2).
			 * Both  A  and  B  are odd.
			 * The following computations ensure that
			 *
			 *     0 <= B < |n|,
			 *      0 < A < |n|,
			 * (1) -sign*X*a  ==  B   (mod |n|),
			 * (2)  sign*Y*a  ==  A   (mod |n|),
			 *
			 * and that either  A  or  B  is even in the next iteration.
			 */
			if (BN_ucmp(B, A) >= 0) {
				/* -sign*(X + Y)*a == B - A  (mod |n|) */
				if (!BN_uadd(X, X, Y))
					goto err;
				/* NB: we could use BN_mod_add_quick(X, X, Y, n), but that
				 * actually makes the algorithm slower */
				if (!BN_usub(B, B, A))
					goto err;
			} else {
				/*  sign*(X + Y)*a == A - B  (mod |n|) */
				if (!BN_uadd(Y, Y, X))
					goto err;
				/* as above, BN_mod_add_quick(Y, Y, X, n) would slow things down */
				if (!BN_usub(A, A, B))
					goto err;
			}
		}
	} else {
		/* general inversion algorithm */

		while (!BN_is_zero(B)) {
			BIGNUM *tmp;

			/*
			 *      0 < B < A,
			 * (*) -sign*X*a  ==  B   (mod |n|),
			 *      sign*Y*a  ==  A   (mod |n|)
			 */

			/* (D, M) := (A/B, A%B) ... */
			if (BN_num_bits(A) == BN_num_bits(B)) {
				if (!BN_one(D))
					goto err;
				if (!BN_sub(M, A, B))
					goto err;
			} else if (BN_num_bits(A) == BN_num_bits(B) + 1) {
				/* A/B is 1, 2, or 3 */
				if (!BN_lshift1(T, B))
					goto err;
				if (BN_ucmp(A, T) < 0) {
					/* A < 2*B, so D=1 */
					if (!BN_one(D))
						goto err;
					if (!BN_sub(M, A, B))
						goto err;
				} else {
					/* A >= 2*B, so D=2 or D=3 */
					if (!BN_sub(M, A, T))
						goto err;
					if (!BN_add(D,T,B)) goto err; /* use D (:= 3*B) as temp */
						if (BN_ucmp(A, D) < 0) {
						/* A < 3*B, so D=2 */
						if (!BN_set_word(D, 2))
							goto err;
						/* M (= A - 2*B) already has the correct value */
					} else {
						/* only D=3 remains */
						if (!BN_set_word(D, 3))
							goto err;
						/* currently  M = A - 2*B,  but we need  M = A - 3*B */
						if (!BN_sub(M, M, B))
							goto err;
					}
				}
			} else {
				if (!BN_div(D, M, A, B, ctx))
					goto err;
			}

			/* Now
			 *      A = D*B + M;
			 * thus we have
			 * (**)  sign*Y*a  ==  D*B + M   (mod |n|).
			 */
			tmp = A; /* keep the BIGNUM object, the value does not matter */

			/* (A, B) := (B, A mod B) ... */
			A = B;
			B = M;
			/* ... so we have  0 <= B < A  again */

			/* Since the former  M  is now  B  and the former  B  is now  A,
			 * (**) translates into
			 *       sign*Y*a  ==  D*A + B    (mod |n|),
			 * i.e.
			 *       sign*Y*a - D*A  ==  B    (mod |n|).
			 * Similarly, (*) translates into
			 *      -sign*X*a  ==  A          (mod |n|).
			 *
			 * Thus,
			 *   sign*Y*a + D*sign*X*a  ==  B  (mod |n|),
			 * i.e.
			 *        sign*(Y + D*X)*a  ==  B  (mod |n|).
			 *
			 * So if we set  (X, Y, sign) := (Y + D*X, X, -sign),  we arrive back at
			 *      -sign*X*a  ==  B   (mod |n|),
			 *       sign*Y*a  ==  A   (mod |n|).
			 * Note that  X  and  Y  stay non-negative all the time.
			 */

			/* most of the time D is very small, so we can optimize tmp := D*X+Y */
			if (BN_is_one(D)) {
				if (!BN_add(tmp, X, Y))
					goto err;
			} else {
				if (BN_is_word(D, 2)) {
					if (!BN_lshift1(tmp, X))
						goto err;
				} else if (BN_is_word(D, 4)) {
					if (!BN_lshift(tmp, X, 2))
						goto err;
				} else if (D->top == 1) {
					if (!BN_copy(tmp, X))
						goto err;
					if (!BN_mul_word(tmp, D->d[0]))
						goto err;
				} else {
					if (!BN_mul(tmp, D,X, ctx))
						goto err;
				}
				if (!BN_add(tmp, tmp, Y))
					goto err;
			}

			M = Y; /* keep the BIGNUM object, the value does not matter */
			Y = X;
			X = tmp;
			sign = -sign;
		}
	}

	/*
	 * The while loop (Euclid's algorithm) ends when
	 *      A == gcd(a,n);
	 * we have
	 *       sign*Y*a  ==  A  (mod |n|),
	 * where  Y  is non-negative.
	 */

	if (sign < 0) {
		if (!BN_sub(Y, n, Y))
			goto err;
	}
	/* Now  Y*a  ==  A  (mod |n|).  */

	if (BN_is_one(A)) {
		/* Y*a == 1  (mod |n|) */
		if (!Y->neg && BN_ucmp(Y, n) < 0) {
			if (!BN_copy(R, Y))
				goto err;
		} else {
			if (!BN_nnmod(R, Y,n, ctx))
				goto err;
		}
	} else {
		BNerr(BN_F_BN_MOD_INVERSE, BN_R_NO_INVERSE);
		goto err;
	}
	ret = R;

err:
	if ((ret == NULL) && (in == NULL))
		BN_free(R);
	BN_CTX_end(ctx);
	bn_check_top(ret);
	return (ret);
}
BN_mod_inverse_no_branch(BIGNUM *in, const BIGNUM *a, const BIGNUM *n,
    BN_CTX *ctx)
{
	BIGNUM *A, *B, *X, *Y, *M, *D, *T, *R = NULL;
	BIGNUM local_A, local_B;
	BIGNUM *pA, *pB;
	BIGNUM *ret = NULL;
	int sign;

	bn_check_top(a);
	bn_check_top(n);

	BN_CTX_start(ctx);
	if ((A = BN_CTX_get(ctx)) == NULL)
		goto err;
	if ((B = BN_CTX_get(ctx)) == NULL)
		goto err;
	if ((X = BN_CTX_get(ctx)) == NULL)
		goto err;
	if ((D = BN_CTX_get(ctx)) == NULL)
		goto err;
	if ((M = BN_CTX_get(ctx)) == NULL)
		goto err;
	if ((Y = BN_CTX_get(ctx)) == NULL)
		goto err;
	if ((T = BN_CTX_get(ctx)) == NULL)
		goto err;

	if (in == NULL)
		R = BN_new();
	else
		R = in;
	if (R == NULL)
		goto err;

	BN_one(X);
	BN_zero(Y);
	if (BN_copy(B, a) == NULL)
		goto err;
	if (BN_copy(A, n) == NULL)
		goto err;
	A->neg = 0;

	if (B->neg || (BN_ucmp(B, A) >= 0)) {
		/* Turn BN_FLG_CONSTTIME flag on, so that when BN_div is invoked,
	 	 * BN_div_no_branch will be called eventually.
	 	 */
		pB = &local_B;
		BN_with_flags(pB, B, BN_FLG_CONSTTIME);
		if (!BN_nnmod(B, pB, A, ctx))
			goto err;
	}
	sign = -1;
	/* From  B = a mod |n|,  A = |n|  it follows that
	 *
	 *      0 <= B < A,
	 *     -sign*X*a  ==  B   (mod |n|),
	 *      sign*Y*a  ==  A   (mod |n|).
	 */

	while (!BN_is_zero(B)) {
		BIGNUM *tmp;

		/*
		 *      0 < B < A,
		 * (*) -sign*X*a  ==  B   (mod |n|),
		 *      sign*Y*a  ==  A   (mod |n|)
		 */

		/* Turn BN_FLG_CONSTTIME flag on, so that when BN_div is invoked,
	 	 * BN_div_no_branch will be called eventually.
	 	 */
		pA = &local_A;
		BN_with_flags(pA, A, BN_FLG_CONSTTIME);

		/* (D, M) := (A/B, A%B) ... */
		if (!BN_div(D, M, pA, B, ctx))
			goto err;

		/* Now
		 *      A = D*B + M;
		 * thus we have
		 * (**)  sign*Y*a  ==  D*B + M   (mod |n|).
		 */
		tmp = A; /* keep the BIGNUM object, the value does not matter */

		/* (A, B) := (B, A mod B) ... */
		A = B;
		B = M;
		/* ... so we have  0 <= B < A  again */

		/* Since the former  M  is now  B  and the former  B  is now  A,
		 * (**) translates into
		 *       sign*Y*a  ==  D*A + B    (mod |n|),
		 * i.e.
		 *       sign*Y*a - D*A  ==  B    (mod |n|).
		 * Similarly, (*) translates into
		 *      -sign*X*a  ==  A          (mod |n|).
		 *
		 * Thus,
		 *   sign*Y*a + D*sign*X*a  ==  B  (mod |n|),
		 * i.e.
		 *        sign*(Y + D*X)*a  ==  B  (mod |n|).
		 *
		 * So if we set  (X, Y, sign) := (Y + D*X, X, -sign),  we arrive back at
		 *      -sign*X*a  ==  B   (mod |n|),
		 *       sign*Y*a  ==  A   (mod |n|).
		 * Note that  X  and  Y  stay non-negative all the time.
		 */

		if (!BN_mul(tmp, D, X, ctx))
			goto err;
		if (!BN_add(tmp, tmp, Y))
			goto err;

		M = Y; /* keep the BIGNUM object, the value does not matter */
		Y = X;
		X = tmp;
		sign = -sign;
	}

	/*
	 * The while loop (Euclid's algorithm) ends when
	 *      A == gcd(a,n);
	 * we have
	 *       sign*Y*a  ==  A  (mod |n|),
	 * where  Y  is non-negative.
	 */

	if (sign < 0) {
		if (!BN_sub(Y, n, Y))
			goto err;
	}
	/* Now  Y*a  ==  A  (mod |n|).  */

	if (BN_is_one(A)) {
		/* Y*a == 1  (mod |n|) */
		if (!Y->neg && BN_ucmp(Y, n) < 0) {
			if (!BN_copy(R, Y))
				goto err;
		} else {
			if (!BN_nnmod(R, Y, n, ctx))
				goto err;
		}
	} else {
		BNerr(BN_F_BN_MOD_INVERSE_NO_BRANCH, BN_R_NO_INVERSE);
		goto err;
	}
	ret = R;

err:
	if ((ret == NULL) && (in == NULL))
		BN_free(R);
	BN_CTX_end(ctx);
	bn_check_top(ret);
	return (ret);
}


static BIGNUM *
BN_mod_inverse_no_branch(BIGNUM *in, const BIGNUM *a, const BIGNUM *n,
    BN_CTX *ctx)
{
	BIGNUM *A, *B, *X, *Y, *M, *D, *T, *R = NULL;
	BIGNUM local_A, local_B;
	BIGNUM *pA, *pB;
	BIGNUM *ret = NULL;
	int sign;

	bn_check_top(a);
	bn_check_top(n);

	BN_CTX_start(ctx);
	if ((A = BN_CTX_get(ctx)) == NULL)
		goto err;
	if ((B = BN_CTX_get(ctx)) == NULL)
		goto err;
	if ((X = BN_CTX_get(ctx)) == NULL)
		goto err;
	if ((D = BN_CTX_get(ctx)) == NULL)
		goto err;
	if ((M = BN_CTX_get(ctx)) == NULL)
		goto err;
	if ((Y = BN_CTX_get(ctx)) == NULL)
		goto err;
	if ((T = BN_CTX_get(ctx)) == NULL)
		goto err;

	if (in == NULL)
		R = BN_new();
	else
		R = in;
	if (R == NULL)
		goto err;

	BN_one(X);
	BN_zero(Y);
	if (BN_copy(B, a) == NULL)
		goto err;
	if (BN_copy(A, n) == NULL)
		goto err;
	A->neg = 0;

	if (B->neg || (BN_ucmp(B, A) >= 0)) {
		/* Turn BN_FLG_CONSTTIME flag on, so that when BN_div is invoked,
	 	 * BN_div_no_branch will be called eventually.
	 	 */
		pB = &local_B;
		BN_with_flags(pB, B, BN_FLG_CONSTTIME);
		if (!BN_nnmod(B, pB, A, ctx))
			goto err;
	}
	sign = -1;
	/* From  B = a mod |n|,  A = |n|  it follows that
	 *
	 *      0 <= B < A,
	 *     -sign*X*a  ==  B   (mod |n|),
	 *      sign*Y*a  ==  A   (mod |n|).
	 */

	while (!BN_is_zero(B)) {
		BIGNUM *tmp;

		/*
		 *      0 < B < A,
		 * (*) -sign*X*a  ==  B   (mod |n|),
		 *      sign*Y*a  ==  A   (mod |n|)
		 */

		/* Turn BN_FLG_CONSTTIME flag on, so that when BN_div is invoked,
	 	 * BN_div_no_branch will be called eventually.
	 	 */
		pA = &local_A;
		BN_with_flags(pA, A, BN_FLG_CONSTTIME);

		/* (D, M) := (A/B, A%B) ... */
		if (!BN_div(D, M, pA, B, ctx))
			goto err;

		/* Now
		 *      A = D*B + M;
		 * thus we have
		 * (**)  sign*Y*a  ==  D*B + M   (mod |n|).
		 */
		tmp = A; /* keep the BIGNUM object, the value does not matter */

		/* (A, B) := (B, A mod B) ... */
		A = B;
		B = M;
		/* ... so we have  0 <= B < A  again */

		/* Since the former  M  is now  B  and the former  B  is now  A,
		 * (**) translates into
		 *       sign*Y*a  ==  D*A + B    (mod |n|),
		 * i.e.
		 *       sign*Y*a - D*A  ==  B    (mod |n|).
		 * Similarly, (*) translates into
		 *      -sign*X*a  ==  A          (mod |n|).
		 *
		 * Thus,
		 *   sign*Y*a + D*sign*X*a  ==  B  (mod |n|),
		 * i.e.
		 *        sign*(Y + D*X)*a  ==  B  (mod |n|).
		 *
		 * So if we set  (X, Y, sign) := (Y + D*X, X, -sign),  we arrive back at
		 *      -sign*X*a  ==  B   (mod |n|),
		 *       sign*Y*a  ==  A   (mod |n|).
		 * Note that  X  and  Y  stay non-negative all the time.
		 */

		if (!BN_mul(tmp, D, X, ctx))
			goto err;
		if (!BN_add(tmp, tmp, Y))
			goto err;

		M = Y; /* keep the BIGNUM object, the value does not matter */
		Y = X;
		X = tmp;
		sign = -sign;
	}

	/*
	 * The while loop (Euclid's algorithm) ends when
	 *      A == gcd(a,n);
	 * we have
	 *       sign*Y*a  ==  A  (mod |n|),
	 * where  Y  is non-negative.
	 */

	if (sign < 0) {
		if (!BN_sub(Y, n, Y))
			goto err;
	}
	/* Now  Y*a  ==  A  (mod |n|).  */

	if (BN_is_one(A)) {
		/* Y*a == 1  (mod |n|) */
		if (!Y->neg && BN_ucmp(Y, n) < 0) {
			if (!BN_copy(R, Y))
				goto err;
		} else {
			if (!BN_nnmod(R, Y, n, ctx))
				goto err;
		}
	} else {
		BNerr(BN_F_BN_MOD_INVERSE_NO_BRANCH, BN_R_NO_INVERSE);
		goto err;
	}
	ret = R;

err:
	if ((ret == NULL) && (in == NULL))
		BN_free(R);
	BN_CTX_end(ctx);
	bn_check_top(ret);
	return (ret);
}


int
BN_mod_lshift1_quick(BIGNUM *r, const BIGNUM *a, const BIGNUM *m)
{
	if (!BN_lshift1(r, a))
		return 0;
	bn_check_top(r);
	if (BN_cmp(r, m) >= 0)
		return BN_sub(r, r, m);
	return 1;
}


int
BN_mod_lshift_quick(BIGNUM *r, const BIGNUM *a, int n, const BIGNUM *m)
{
	if (r != a) {
		if (BN_copy(r, a) == NULL)
			return 0;
	}

	while (n > 0) {
		int max_shift;

		/* 0 < r < m */
		max_shift = BN_num_bits(m) - BN_num_bits(r);
		/* max_shift >= 0 */

		if (max_shift < 0) {
			BNerr(BN_F_BN_MOD_LSHIFT_QUICK, BN_R_INPUT_NOT_REDUCED);
			return 0;
		}

		if (max_shift > n)
			max_shift = n;

		if (max_shift) {
			if (!BN_lshift(r, r, max_shift))
				return 0;
			n -= max_shift;
		} else {
			if (!BN_lshift1(r, r))
				return 0;
			--n;
		}

		/* BN_num_bits(r) <= BN_num_bits(m) */

		if (BN_cmp(r, m) >= 0) {
			if (!BN_sub(r, r, m))
				return 0;
		}
	}
	bn_check_top(r);

	return 1;
}


int
BN_mod_mul(BIGNUM *r, const BIGNUM *a, const BIGNUM *b, const BIGNUM *m,
    BN_CTX *ctx)
{
	BIGNUM *t;
	int ret = 0;

	bn_check_top(a);
	bn_check_top(b);
	bn_check_top(m);

	BN_CTX_start(ctx);
	if ((t = BN_CTX_get(ctx)) == NULL)
		goto err;
	if (a == b) {
		if (!BN_sqr(t, a, ctx))
			goto err;
	} else {
		if (!BN_mul(t, a,b, ctx))
			goto err;
	}
	if (!BN_nnmod(r, t,m, ctx))
		goto err;
	bn_check_top(r);
	ret = 1;

err:
	BN_CTX_end(ctx);
	return (ret);
}


int
BN_mod_mul_montgomery(BIGNUM *r, const BIGNUM *a, const BIGNUM *b,
    BN_MONT_CTX *mont, BN_CTX *ctx)
{
	BIGNUM *tmp;
	int ret = 0;
#if defined(OPENSSL_BN_ASM_MONT) && defined(MONT_WORD)
	int num = mont->N.top;

	if (num > 1 && a->top == num && b->top == num) {
		if (bn_wexpand(r, num) == NULL)
			return (0);
		if (bn_mul_mont(r->d, a->d, b->d, mont->N.d, mont->n0, num)) {
			r->neg = a->neg^b->neg;
			r->top = num;
			bn_correct_top(r);
			return (1);
		}
	}
#endif

	BN_CTX_start(ctx);
	if ((tmp = BN_CTX_get(ctx)) == NULL)
		goto err;

	bn_check_top(tmp);
	if (a == b) {
		if (!BN_sqr(tmp, a, ctx))
			goto err;
	} else {
		if (!BN_mul(tmp, a,b, ctx))
			goto err;
	}
	/* reduce from aRR to aR */
#ifdef MONT_WORD
	if (!BN_from_montgomery_word(r, tmp, mont))
		goto err;
#else
	if (!BN_from_montgomery(r, tmp, mont, ctx))
		goto err;
#endif
	bn_check_top(r);
	ret = 1;
err:
	BN_CTX_end(ctx);
	return (ret);
}


int
BN_mod_sqr(BIGNUM *r, const BIGNUM *a, const BIGNUM *m, BN_CTX *ctx)
{
	if (!BN_sqr(r, a, ctx))
		return 0;
	/* r->neg == 0,  thus we don't need BN_nnmod */
	return BN_mod(r, r, m, ctx);
}


int
BN_mod_sub_quick(BIGNUM *r, const BIGNUM *a, const BIGNUM *b, const BIGNUM *m)
{
	if (!BN_sub(r, a, b))
		return 0;
	if (r->neg)
		return BN_add(r, r, m);
	return 1;
}


void
BN_MONT_CTX_free(BN_MONT_CTX *mont)
{
	if (mont == NULL)
		return;

	BN_clear_free(&(mont->RR));
	BN_clear_free(&(mont->N));
	BN_clear_free(&(mont->Ni));
	if (mont->flags & BN_FLG_MALLOCED)
		free(mont);
}


void
BN_MONT_CTX_init(BN_MONT_CTX *ctx)
{
	ctx->ri = 0;
	BN_init(&(ctx->RR));
	BN_init(&(ctx->N));
	BN_init(&(ctx->Ni));
	ctx->n0[0] = ctx->n0[1] = 0;
	ctx->flags = 0;
}


BN_MONT_CTX *
BN_MONT_CTX_new(void)
{
	BN_MONT_CTX *ret;

	if ((ret = malloc(sizeof(BN_MONT_CTX))) == NULL)
		return (NULL);

	BN_MONT_CTX_init(ret);
	ret->flags = BN_FLG_MALLOCED;
	return (ret);
}


int
BN_MONT_CTX_set(BN_MONT_CTX *mont, const BIGNUM *mod, BN_CTX *ctx)
{
	int ret = 0;
	BIGNUM *Ri, *R;

	BN_CTX_start(ctx);
	if ((Ri = BN_CTX_get(ctx)) == NULL)
		goto err;
	R = &(mont->RR);				/* grab RR as a temp */
	if (!BN_copy(&(mont->N), mod))
		 goto err;				/* Set N */
	mont->N.neg = 0;

#ifdef MONT_WORD
	{
		BIGNUM tmod;
		BN_ULONG buf[2];

		BN_init(&tmod);
		tmod.d = buf;
		tmod.dmax = 2;
		tmod.neg = 0;

		mont->ri = (BN_num_bits(mod) +
		    (BN_BITS2 - 1)) / BN_BITS2 * BN_BITS2;

#if defined(OPENSSL_BN_ASM_MONT) && (BN_BITS2<=32)
		/* Only certain BN_BITS2<=32 platforms actually make use of
		 * n0[1], and we could use the #else case (with a shorter R
		 * value) for the others.  However, currently only the assembler
		 * files do know which is which. */

		BN_zero(R);
		if (!(BN_set_bit(R, 2 * BN_BITS2)))
			goto err;

		tmod.top = 0;
		if ((buf[0] = mod->d[0]))
			tmod.top = 1;
		if ((buf[1] = mod->top > 1 ? mod->d[1] : 0))
			tmod.top = 2;

		if ((BN_mod_inverse(Ri, R, &tmod, ctx)) == NULL)
			goto err;
		if (!BN_lshift(Ri, Ri, 2 * BN_BITS2))
			goto err; /* R*Ri */
		if (!BN_is_zero(Ri)) {
			if (!BN_sub_word(Ri, 1))
				goto err;
		}
		else /* if N mod word size == 1 */
		{
			if (bn_expand(Ri, (int)sizeof(BN_ULONG) * 2) == NULL)
				goto err;
			/* Ri-- (mod double word size) */
			Ri->neg = 0;
			Ri->d[0] = BN_MASK2;
			Ri->d[1] = BN_MASK2;
			Ri->top = 2;
		}
		if (!BN_div(Ri, NULL, Ri, &tmod, ctx))
			goto err;
		/* Ni = (R*Ri-1)/N,
		 * keep only couple of least significant words: */
		mont->n0[0] = (Ri->top > 0) ? Ri->d[0] : 0;
		mont->n0[1] = (Ri->top > 1) ? Ri->d[1] : 0;
#else
		BN_zero(R);
		if (!(BN_set_bit(R, BN_BITS2)))
			goto err;	/* R */

		buf[0] = mod->d[0]; /* tmod = N mod word size */
		buf[1] = 0;
		tmod.top = buf[0] != 0 ? 1 : 0;
		/* Ri = R^-1 mod N*/
		if ((BN_mod_inverse(Ri, R, &tmod, ctx)) == NULL)
			goto err;
		if (!BN_lshift(Ri, Ri, BN_BITS2))
			goto err; /* R*Ri */
		if (!BN_is_zero(Ri)) {
			if (!BN_sub_word(Ri, 1))
				goto err;
		}
		else /* if N mod word size == 1 */
		{
			if (!BN_set_word(Ri, BN_MASK2))
				goto err;  /* Ri-- (mod word size) */
		}
		if (!BN_div(Ri, NULL, Ri, &tmod, ctx))
			goto err;
		/* Ni = (R*Ri-1)/N,
		 * keep only least significant word: */
		mont->n0[0] = (Ri->top > 0) ? Ri->d[0] : 0;
		mont->n0[1] = 0;
#endif
	}
#else /* !MONT_WORD */
	{ /* bignum version */
		mont->ri = BN_num_bits(&mont->N);
		BN_zero(R);
		if (!BN_set_bit(R, mont->ri))
			goto err;  /* R = 2^ri */
		/* Ri = R^-1 mod N*/
		if ((BN_mod_inverse(Ri, R, &mont->N, ctx)) == NULL)
			goto err;
		if (!BN_lshift(Ri, Ri, mont->ri))
			goto err; /* R*Ri */
		if (!BN_sub_word(Ri, 1))
			goto err;
		/* Ni = (R*Ri-1) / N */
		if (!BN_div(&(mont->Ni), NULL, Ri, &mont->N, ctx))
			goto err;
	}
#endif

	/* setup RR for conversions */
	BN_zero(&(mont->RR));
	if (!BN_set_bit(&(mont->RR), mont->ri*2))
		goto err;
	if (!BN_mod(&(mont->RR), &(mont->RR), &(mont->N), ctx))
		goto err;

	ret = 1;

err:
	BN_CTX_end(ctx);
	return ret;
}
BN_MONT_CTX_set_locked(BN_MONT_CTX **pmont, int lock, const BIGNUM *mod,
    BN_CTX *ctx)
{
	int got_write_lock = 0;
	BN_MONT_CTX *ret;

	CRYPTO_r_lock(lock);
	if (!*pmont) {
		CRYPTO_r_unlock(lock);
		CRYPTO_w_lock(lock);
		got_write_lock = 1;

		if (!*pmont) {
			ret = BN_MONT_CTX_new();
			if (ret && !BN_MONT_CTX_set(ret, mod, ctx))
				BN_MONT_CTX_free(ret);
			else
				*pmont = ret;
		}
	}

	ret = *pmont;

	if (got_write_lock)
		CRYPTO_w_unlock(lock);
	else
		CRYPTO_r_unlock(lock);

	return ret;
}


BN_MONT_CTX *
BN_MONT_CTX_set_locked(BN_MONT_CTX **pmont, int lock, const BIGNUM *mod,
    BN_CTX *ctx)
{
	int got_write_lock = 0;
	BN_MONT_CTX *ret;

	CRYPTO_r_lock(lock);
	if (!*pmont) {
		CRYPTO_r_unlock(lock);
		CRYPTO_w_lock(lock);
		got_write_lock = 1;

		if (!*pmont) {
			ret = BN_MONT_CTX_new();
			if (ret && !BN_MONT_CTX_set(ret, mod, ctx))
				BN_MONT_CTX_free(ret);
			else
				*pmont = ret;
		}
	}

	ret = *pmont;

	if (got_write_lock)
		CRYPTO_w_unlock(lock);
	else
		CRYPTO_r_unlock(lock);

	return ret;
}


int
BN_mul(BIGNUM *r, const BIGNUM *a, const BIGNUM *b, BN_CTX *ctx)
{
	int ret = 0;
	int top, al, bl;
	BIGNUM *rr;
#if defined(BN_MUL_COMBA) || defined(BN_RECURSION)
	int i;
#endif
#ifdef BN_RECURSION
	BIGNUM *t = NULL;
	int j = 0, k;
#endif

#ifdef BN_COUNT
	fprintf(stderr, "BN_mul %d * %d\n",a->top,b->top);
#endif

	bn_check_top(a);
	bn_check_top(b);
	bn_check_top(r);

	al = a->top;
	bl = b->top;

	if ((al == 0) || (bl == 0)) {
		BN_zero(r);
		return (1);
	}
	top = al + bl;

	BN_CTX_start(ctx);
	if ((r == a) || (r == b)) {
		if ((rr = BN_CTX_get(ctx)) == NULL)
			goto err;
	} else
		rr = r;
	rr->neg = a->neg ^ b->neg;

#if defined(BN_MUL_COMBA) || defined(BN_RECURSION)
	i = al - bl;
#endif
#ifdef BN_MUL_COMBA
	if (i == 0) {
# if 0
		if (al == 4) {
			if (bn_wexpand(rr, 8) == NULL)
				goto err;
			rr->top = 8;
			bn_mul_comba4(rr->d, a->d, b->d);
			goto end;
		}
# endif
		if (al == 8) {
			if (bn_wexpand(rr, 16) == NULL)
				goto err;
			rr->top = 16;
			bn_mul_comba8(rr->d, a->d, b->d);
			goto end;
		}
	}
#endif /* BN_MUL_COMBA */
#ifdef BN_RECURSION
	if ((al >= BN_MULL_SIZE_NORMAL) && (bl >= BN_MULL_SIZE_NORMAL)) {
		if (i >= -1 && i <= 1) {
			/* Find out the power of two lower or equal
			   to the longest of the two numbers */
			if (i >= 0) {
				j = BN_num_bits_word((BN_ULONG)al);
			}
			if (i == -1) {
				j = BN_num_bits_word((BN_ULONG)bl);
			}
			j = 1 << (j - 1);
			assert(j <= al || j <= bl);
			k = j + j;
			if ((t = BN_CTX_get(ctx)) == NULL)
				goto err;
			if (al > j || bl > j) {
				if (bn_wexpand(t, k * 4) == NULL)
					goto err;
				if (bn_wexpand(rr, k * 4) == NULL)
					goto err;
				bn_mul_part_recursive(rr->d, a->d, b->d,
				    j, al - j, bl - j, t->d);
			}
			else	/* al <= j || bl <= j */
			{
				if (bn_wexpand(t, k * 2) == NULL)
					goto err;
				if (bn_wexpand(rr, k * 2) == NULL)
					goto err;
				bn_mul_recursive(rr->d, a->d, b->d,
				    j, al - j, bl - j, t->d);
			}
			rr->top = top;
			goto end;
		}
#if 0
		if (i == 1 && !BN_get_flags(b, BN_FLG_STATIC_DATA)) {
			BIGNUM *tmp_bn = (BIGNUM *)b;
			if (bn_wexpand(tmp_bn, al) == NULL)
				goto err;
			tmp_bn->d[bl] = 0;
			bl++;
			i--;
		} else if (i == -1 && !BN_get_flags(a, BN_FLG_STATIC_DATA)) {
			BIGNUM *tmp_bn = (BIGNUM *)a;
			if (bn_wexpand(tmp_bn, bl) == NULL)
				goto err;
			tmp_bn->d[al] = 0;
			al++;
			i++;
		}
		if (i == 0) {
			/* symmetric and > 4 */
			/* 16 or larger */
			j = BN_num_bits_word((BN_ULONG)al);
			j = 1 << (j - 1);
			k = j + j;
			if ((t = BN_CTX_get(ctx)) == NULL)
				goto err;
			if (al == j) /* exact multiple */
			{
				if (bn_wexpand(t, k * 2) == NULL)
					goto err;
				if (bn_wexpand(rr, k * 2) == NULL)
					goto err;
				bn_mul_recursive(rr->d, a->d, b->d, al, t->d);
			} else {
				if (bn_wexpand(t, k * 4) == NULL)
					goto err;
				if (bn_wexpand(rr, k * 4) == NULL)
					goto err;
				bn_mul_part_recursive(rr->d, a->d, b->d,
				    al - j, j, t->d);
			}
			rr->top = top;
			goto end;
		}
#endif
	}
#endif /* BN_RECURSION */
	if (bn_wexpand(rr, top) == NULL)
		goto err;
	rr->top = top;
	bn_mul_normal(rr->d, a->d, al, b->d, bl);

#if defined(BN_MUL_COMBA) || defined(BN_RECURSION)
end:
#endif
	bn_correct_top(rr);
	if (r != rr)
		BN_copy(r, rr);
	ret = 1;
err:
	bn_check_top(r);
	BN_CTX_end(ctx);
	return (ret);
}


BN_ULONG
bn_mul_add_words(BN_ULONG *rp, const BN_ULONG *ap, int num, BN_ULONG w)
{
	BN_ULONG c1 = 0;

	assert(num >= 0);
	if (num <= 0)
		return (c1);

#ifndef OPENSSL_SMALL_FOOTPRINT
	while (num & ~3) {
		mul_add(rp[0], ap[0], w, c1);
		mul_add(rp[1], ap[1], w, c1);
		mul_add(rp[2], ap[2], w, c1);
		mul_add(rp[3], ap[3], w, c1);
		ap += 4;
		rp += 4;
		num -= 4;
	}
#endif
	while (num) {
		mul_add(rp[0], ap[0], w, c1);
		ap++;
		rp++;
		num--;
	}

	return (c1);
}
bn_mul_add_words(BN_ULONG *rp, const BN_ULONG *ap, int num, BN_ULONG w)
{
	BN_ULONG c = 0;
	BN_ULONG bl, bh;

	assert(num >= 0);
	if (num <= 0)
		return ((BN_ULONG)0);

	bl = LBITS(w);
	bh = HBITS(w);

#ifndef OPENSSL_SMALL_FOOTPRINT
	while (num & ~3) {
		mul_add(rp[0], ap[0], bl, bh, c);
		mul_add(rp[1], ap[1], bl, bh, c);
		mul_add(rp[2], ap[2], bl, bh, c);
		mul_add(rp[3], ap[3], bl, bh, c);
		ap += 4;
		rp += 4;
		num -= 4;
	}
#endif
	while (num) {
		mul_add(rp[0], ap[0], bl, bh, c);
		ap++;
		rp++;
		num--;
	}
	return (c);
}


void
bn_mul_comba8(BN_ULONG *r, BN_ULONG *a, BN_ULONG *b)
{
	BN_ULONG c1, c2, c3;

	c1 = 0;
	c2 = 0;
	c3 = 0;
	mul_add_c(a[0], b[0], c1, c2, c3);
	r[0] = c1;
	c1 = 0;
	mul_add_c(a[0], b[1], c2, c3, c1);
	mul_add_c(a[1], b[0], c2, c3, c1);
	r[1] = c2;
	c2 = 0;
	mul_add_c(a[2], b[0], c3, c1, c2);
	mul_add_c(a[1], b[1], c3, c1, c2);
	mul_add_c(a[0], b[2], c3, c1, c2);
	r[2] = c3;
	c3 = 0;
	mul_add_c(a[0], b[3], c1, c2, c3);
	mul_add_c(a[1], b[2], c1, c2, c3);
	mul_add_c(a[2], b[1], c1, c2, c3);
	mul_add_c(a[3], b[0], c1, c2, c3);
	r[3] = c1;
	c1 = 0;
	mul_add_c(a[4], b[0], c2, c3, c1);
	mul_add_c(a[3], b[1], c2, c3, c1);
	mul_add_c(a[2], b[2], c2, c3, c1);
	mul_add_c(a[1], b[3], c2, c3, c1);
	mul_add_c(a[0], b[4], c2, c3, c1);
	r[4] = c2;
	c2 = 0;
	mul_add_c(a[0], b[5], c3, c1, c2);
	mul_add_c(a[1], b[4], c3, c1, c2);
	mul_add_c(a[2], b[3], c3, c1, c2);
	mul_add_c(a[3], b[2], c3, c1, c2);
	mul_add_c(a[4], b[1], c3, c1, c2);
	mul_add_c(a[5], b[0], c3, c1, c2);
	r[5] = c3;
	c3 = 0;
	mul_add_c(a[6], b[0], c1, c2, c3);
	mul_add_c(a[5], b[1], c1, c2, c3);
	mul_add_c(a[4], b[2], c1, c2, c3);
	mul_add_c(a[3], b[3], c1, c2, c3);
	mul_add_c(a[2], b[4], c1, c2, c3);
	mul_add_c(a[1], b[5], c1, c2, c3);
	mul_add_c(a[0], b[6], c1, c2, c3);
	r[6] = c1;
	c1 = 0;
	mul_add_c(a[0], b[7], c2, c3, c1);
	mul_add_c(a[1], b[6], c2, c3, c1);
	mul_add_c(a[2], b[5], c2, c3, c1);
	mul_add_c(a[3], b[4], c2, c3, c1);
	mul_add_c(a[4], b[3], c2, c3, c1);
	mul_add_c(a[5], b[2], c2, c3, c1);
	mul_add_c(a[6], b[1], c2, c3, c1);
	mul_add_c(a[7], b[0], c2, c3, c1);
	r[7] = c2;
	c2 = 0;
	mul_add_c(a[7], b[1], c3, c1, c2);
	mul_add_c(a[6], b[2], c3, c1, c2);
	mul_add_c(a[5], b[3], c3, c1, c2);
	mul_add_c(a[4], b[4], c3, c1, c2);
	mul_add_c(a[3], b[5], c3, c1, c2);
	mul_add_c(a[2], b[6], c3, c1, c2);
	mul_add_c(a[1], b[7], c3, c1, c2);
	r[8] = c3;
	c3 = 0;
	mul_add_c(a[2], b[7], c1, c2, c3);
	mul_add_c(a[3], b[6], c1, c2, c3);
	mul_add_c(a[4], b[5], c1, c2, c3);
	mul_add_c(a[5], b[4], c1, c2, c3);
	mul_add_c(a[6], b[3], c1, c2, c3);
	mul_add_c(a[7], b[2], c1, c2, c3);
	r[9] = c1;
	c1 = 0;
	mul_add_c(a[7], b[3], c2, c3, c1);
	mul_add_c(a[6], b[4], c2, c3, c1);
	mul_add_c(a[5], b[5], c2, c3, c1);
	mul_add_c(a[4], b[6], c2, c3, c1);
	mul_add_c(a[3], b[7], c2, c3, c1);
	r[10] = c2;
	c2 = 0;
	mul_add_c(a[4], b[7], c3, c1, c2);
	mul_add_c(a[5], b[6], c3, c1, c2);
	mul_add_c(a[6], b[5], c3, c1, c2);
	mul_add_c(a[7], b[4], c3, c1, c2);
	r[11] = c3;
	c3 = 0;
	mul_add_c(a[7], b[5], c1, c2, c3);
	mul_add_c(a[6], b[6], c1, c2, c3);
	mul_add_c(a[5], b[7], c1, c2, c3);
	r[12] = c1;
	c1 = 0;
	mul_add_c(a[6], b[7], c2, c3, c1);
	mul_add_c(a[7], b[6], c2, c3, c1);
	r[13] = c2;
	c2 = 0;
	mul_add_c(a[7], b[7], c3, c1, c2);
	r[14] = c3;
	r[15] = c1;
}
bn_mul_comba8(BN_ULONG *r, BN_ULONG *a, BN_ULONG *b)
{
	r[8] = bn_mul_words(&(r[0]), a, 8, b[0]);
	r[9] = bn_mul_add_words(&(r[1]), a, 8, b[1]);
	r[10] = bn_mul_add_words(&(r[2]), a, 8, b[2]);
	r[11] = bn_mul_add_words(&(r[3]), a, 8, b[3]);
	r[12] = bn_mul_add_words(&(r[4]), a, 8, b[4]);
	r[13] = bn_mul_add_words(&(r[5]), a, 8, b[5]);
	r[14] = bn_mul_add_words(&(r[6]), a, 8, b[6]);
	r[15] = bn_mul_add_words(&(r[7]), a, 8, b[7]);
}


int
bn_mul_mont(BN_ULONG *rp, const BN_ULONG *ap, const BN_ULONG *bp, const BN_ULONG *np, const BN_ULONG *n0p, int num)
{
	BN_ULONG c0, c1, ml, *tp, n0;
#ifdef mul64
	BN_ULONG mh;
#endif
	int i = 0, j;

#if 0	/* template for platform-specific implementation */
	if (ap == bp)
		return bn_sqr_mont(rp, ap, np, n0p, num);
#endif
	tp = reallocarray(NULL, num + 2, sizeof(BN_ULONG));
	if (tp == NULL)
		return 0;

	n0 = *n0p;

	c0 = 0;
	ml = bp[0];
#ifdef mul64
	mh = HBITS(ml);
	ml = LBITS(ml);
	for (j = 0; j < num; ++j)
		mul(tp[j], ap[j], ml, mh, c0);
#else
	for (j = 0; j < num; ++j)
		mul(tp[j], ap[j], ml, c0);
#endif

	tp[num] = c0;
	tp[num + 1] = 0;
	goto enter;

	for (i = 0; i < num; i++) {
		c0 = 0;
		ml = bp[i];
#ifdef mul64
		mh = HBITS(ml);
		ml = LBITS(ml);
		for (j = 0; j < num; ++j)
			mul_add(tp[j], ap[j], ml, mh, c0);
#else
		for (j = 0; j < num; ++j)
			mul_add(tp[j], ap[j], ml, c0);
#endif
		c1 = (tp[num] + c0) & BN_MASK2;
		tp[num] = c1;
		tp[num + 1] = (c1 < c0 ? 1 : 0);
enter:
		c1 = tp[0];
		ml = (c1 * n0) & BN_MASK2;
		c0 = 0;
#ifdef mul64
		mh = HBITS(ml);
		ml = LBITS(ml);
		mul_add(c1, np[0], ml, mh, c0);
#else
		mul_add(c1, ml, np[0], c0);
#endif
		for (j = 1; j < num; j++) {
			c1 = tp[j];
#ifdef mul64
			mul_add(c1, np[j], ml, mh, c0);
#else
			mul_add(c1, ml, np[j], c0);
#endif
			tp[j - 1] = c1 & BN_MASK2;
		}
		c1 = (tp[num] + c0) & BN_MASK2;
		tp[num - 1] = c1;
		tp[num] = tp[num + 1] + (c1 < c0 ? 1 : 0);
	}

	if (tp[num] != 0 || tp[num - 1] >= np[num - 1]) {
		c0 = bn_sub_words(rp, tp, np, num);
		if (tp[num] != 0 || c0 == 0) {
			goto out;
		}
	}
	memcpy(rp, tp, num * sizeof(BN_ULONG));
out:
	explicit_bzero(tp, (num + 2) * sizeof(BN_ULONG));
	free(tp);
	return 1;
}
bn_mul_mont(BN_ULONG *rp, const BN_ULONG *ap, const BN_ULONG *bp,
    const BN_ULONG *np, const BN_ULONG *n0p, int num)
{
	BN_ULONG c0, c1, *tp, n0 = *n0p;
	int i = 0, j;

	tp = calloc(NULL, num + 2, sizeof(BN_ULONG));
	if (tp == NULL)
		return 0;

	for (i = 0; i < num; i++) {
		c0 = bn_mul_add_words(tp, ap, num, bp[i]);
		c1 = (tp[num] + c0) & BN_MASK2;
		tp[num] = c1;
		tp[num + 1] = (c1 < c0 ? 1 : 0);

		c0 = bn_mul_add_words(tp, np, num, tp[0] * n0);
		c1 = (tp[num] + c0) & BN_MASK2;
		tp[num] = c1;
		tp[num + 1] += (c1 < c0 ? 1 : 0);
		for (j = 0; j <= num; j++)
			tp[j] = tp[j + 1];
	}

	if (tp[num] != 0 || tp[num - 1] >= np[num - 1]) {
		c0 = bn_sub_words(rp, tp, np, num);
		if (tp[num] != 0 || c0 == 0) {
			goto out;
		}
	}
	memcpy(rp, tp, num * sizeof(BN_ULONG));
out:
	explicit_bzero(tp, (num + 2) * sizeof(BN_ULONG));
	free(tp);
	return 1;
}
bn_mul_mont(BN_ULONG *rp, const BN_ULONG *ap, const BN_ULONG *bp,
    const BN_ULONG *np, const BN_ULONG *n0, int num)
{
	return 0;
}


void
bn_mul_normal(BN_ULONG *r, BN_ULONG *a, int na, BN_ULONG *b, int nb)
{
	BN_ULONG *rr;

#ifdef BN_COUNT
	fprintf(stderr, " bn_mul_normal %d * %d\n", na, nb);
#endif

	if (na < nb) {
		int itmp;
		BN_ULONG *ltmp;

		itmp = na;
		na = nb;
		nb = itmp;
		ltmp = a;
		a = b;
		b = ltmp;

	}
	rr = &(r[na]);
	if (nb <= 0) {
		(void)bn_mul_words(r, a, na, 0);
		return;
	} else
		rr[0] = bn_mul_words(r, a, na, b[0]);

	for (;;) {
		if (--nb <= 0)
			return;
		rr[1] = bn_mul_add_words(&(r[1]), a, na, b[1]);
		if (--nb <= 0)
			return;
		rr[2] = bn_mul_add_words(&(r[2]), a, na, b[2]);
		if (--nb <= 0)
			return;
		rr[3] = bn_mul_add_words(&(r[3]), a, na, b[3]);
		if (--nb <= 0)
			return;
		rr[4] = bn_mul_add_words(&(r[4]), a, na, b[4]);
		rr += 4;
		r += 4;
		b += 4;
	}
}


void
bn_mul_recursive(BN_ULONG *r, BN_ULONG *a, BN_ULONG *b, int n2, int dna,
    int dnb, BN_ULONG *t)
{
	int n = n2 / 2, c1, c2;
	int tna = n + dna, tnb = n + dnb;
	unsigned int neg, zero;
	BN_ULONG ln, lo, *p;

# ifdef BN_COUNT
	fprintf(stderr, " bn_mul_recursive %d%+d * %d%+d\n",n2,dna,n2,dnb);
# endif
# ifdef BN_MUL_COMBA
#  if 0
	if (n2 == 4) {
		bn_mul_comba4(r, a, b);
		return;
	}
#  endif
	/* Only call bn_mul_comba 8 if n2 == 8 and the
	 * two arrays are complete [steve]
	 */
	if (n2 == 8 && dna == 0 && dnb == 0) {
		bn_mul_comba8(r, a, b);
		return;
	}
# endif /* BN_MUL_COMBA */
	/* Else do normal multiply */
	if (n2 < BN_MUL_RECURSIVE_SIZE_NORMAL) {
		bn_mul_normal(r, a, n2 + dna, b, n2 + dnb);
		if ((dna + dnb) < 0)
			memset(&r[2*n2 + dna + dnb], 0,
			    sizeof(BN_ULONG) * -(dna + dnb));
		return;
	}
	/* r=(a[0]-a[1])*(b[1]-b[0]) */
	c1 = bn_cmp_part_words(a, &(a[n]), tna, n - tna);
	c2 = bn_cmp_part_words(&(b[n]), b,tnb, tnb - n);
	zero = neg = 0;
	switch (c1 * 3 + c2) {
	case -4:
		bn_sub_part_words(t, &(a[n]), a, tna, tna - n); /* - */
		bn_sub_part_words(&(t[n]), b, &(b[n]), tnb, n - tnb); /* - */
		break;
	case -3:
		zero = 1;
		break;
	case -2:
		bn_sub_part_words(t, &(a[n]), a, tna, tna - n); /* - */
		bn_sub_part_words(&(t[n]), &(b[n]), b, tnb, tnb - n); /* + */
		neg = 1;
		break;
	case -1:
	case 0:
	case 1:
		zero = 1;
		break;
	case 2:
		bn_sub_part_words(t, a, &(a[n]), tna, n - tna); /* + */
		bn_sub_part_words(&(t[n]), b, &(b[n]), tnb, n - tnb); /* - */
		neg = 1;
		break;
	case 3:
		zero = 1;
		break;
	case 4:
		bn_sub_part_words(t, a, &(a[n]), tna, n - tna);
		bn_sub_part_words(&(t[n]), &(b[n]), b, tnb, tnb - n);
		break;
	}

# ifdef BN_MUL_COMBA
	if (n == 4 && dna == 0 && dnb == 0) /* XXX: bn_mul_comba4 could take
					       extra args to do this well */
	{
		if (!zero)
			bn_mul_comba4(&(t[n2]), t, &(t[n]));
		else
			memset(&(t[n2]), 0, 8 * sizeof(BN_ULONG));

		bn_mul_comba4(r, a, b);
		bn_mul_comba4(&(r[n2]), &(a[n]), &(b[n]));
	} else if (n == 8 && dna == 0 && dnb == 0) /* XXX: bn_mul_comba8 could
						    take extra args to do this
						    well */
	{
		if (!zero)
			bn_mul_comba8(&(t[n2]), t, &(t[n]));
		else
			memset(&(t[n2]), 0, 16 * sizeof(BN_ULONG));

		bn_mul_comba8(r, a, b);
		bn_mul_comba8(&(r[n2]), &(a[n]), &(b[n]));
	} else
# endif /* BN_MUL_COMBA */
	{
		p = &(t[n2 * 2]);
		if (!zero)
			bn_mul_recursive(&(t[n2]), t, &(t[n]), n, 0, 0, p);
		else
			memset(&(t[n2]), 0, n2 * sizeof(BN_ULONG));
		bn_mul_recursive(r, a, b, n, 0, 0, p);
		bn_mul_recursive(&(r[n2]), &(a[n]), &(b[n]), n, dna, dnb, p);
	}

	/* t[32] holds (a[0]-a[1])*(b[1]-b[0]), c1 is the sign
	 * r[10] holds (a[0]*b[0])
	 * r[32] holds (b[1]*b[1])
	 */

	c1 = (int)(bn_add_words(t, r, &(r[n2]), n2));

	if (neg) /* if t[32] is negative */
	{
		c1 -= (int)(bn_sub_words(&(t[n2]), t, &(t[n2]), n2));
	} else {
		/* Might have a carry */
		c1 += (int)(bn_add_words(&(t[n2]), &(t[n2]), t, n2));
	}

	/* t[32] holds (a[0]-a[1])*(b[1]-b[0])+(a[0]*b[0])+(a[1]*b[1])
	 * r[10] holds (a[0]*b[0])
	 * r[32] holds (b[1]*b[1])
	 * c1 holds the carry bits
	 */
	c1 += (int)(bn_add_words(&(r[n]), &(r[n]), &(t[n2]), n2));
	if (c1) {
		p = &(r[n + n2]);
		lo= *p;
		ln = (lo + c1) & BN_MASK2;
		*p = ln;

		/* The overflow will stop before we over write
		 * words we should not overwrite */
		if (ln < (BN_ULONG)c1) {
			do {
				p++;
				lo= *p;
				ln = (lo + 1) & BN_MASK2;
				*p = ln;
			} while (ln == 0);
		}
	}
}


BN_ULONG
bn_mul_words(BN_ULONG *rp, const BN_ULONG *ap, int num, BN_ULONG w)
{
	BN_ULONG c1 = 0;

	assert(num >= 0);
	if (num <= 0)
		return (c1);

#ifndef OPENSSL_SMALL_FOOTPRINT
	while (num & ~3) {
		mul(rp[0], ap[0], w, c1);
		mul(rp[1], ap[1], w, c1);
		mul(rp[2], ap[2], w, c1);
		mul(rp[3], ap[3], w, c1);
		ap += 4;
		rp += 4;
		num -= 4;
	}
#endif
	while (num) {
		mul(rp[0], ap[0], w, c1);
		ap++;
		rp++;
		num--;
	}
	return (c1);
}
bn_mul_words(BN_ULONG *rp, const BN_ULONG *ap, int num, BN_ULONG w)
{
	BN_ULONG carry = 0;
	BN_ULONG bl, bh;

	assert(num >= 0);
	if (num <= 0)
		return ((BN_ULONG)0);

	bl = LBITS(w);
	bh = HBITS(w);

#ifndef OPENSSL_SMALL_FOOTPRINT
	while (num & ~3) {
		mul(rp[0], ap[0], bl, bh, carry);
		mul(rp[1], ap[1], bl, bh, carry);
		mul(rp[2], ap[2], bl, bh, carry);
		mul(rp[3], ap[3], bl, bh, carry);
		ap += 4;
		rp += 4;
		num -= 4;
	}
#endif
	while (num) {
		mul(rp[0], ap[0], bl, bh, carry);
		ap++;
		rp++;
		num--;
	}
	return (carry);
}


static int
bn_new(ASN1_VALUE **pval, const ASN1_ITEM *it)
{
	*pval = (ASN1_VALUE *)BN_new();
	if (*pval)
		return 1;
	else
		return 0;
}


BIGNUM *
BN_new(void)
{
	BIGNUM *ret;

	if ((ret = malloc(sizeof(BIGNUM))) == NULL) {
		BNerr(BN_F_BN_NEW, ERR_R_MALLOC_FAILURE);
		return (NULL);
	}
	ret->flags = BN_FLG_MALLOCED;
	ret->top = 0;
	ret->neg = 0;
	ret->dmax = 0;
	ret->d = NULL;
	bn_check_top(ret);
	return (ret);
}


int
BN_nnmod(BIGNUM *r, const BIGNUM *m, const BIGNUM *d, BN_CTX *ctx)
{
	/* like BN_mod, but returns non-negative remainder
	 * (i.e.,  0 <= r < |d|  always holds) */

	if (!(BN_mod(r, m,d, ctx)))
		return 0;
	if (!r->neg)
		return 1;
	/* now   -|d| < r < 0,  so we have to set  r := r + |d| */
	return (d->neg ? BN_sub : BN_add)(r, r, d);
}


int
BN_num_bits_word(BN_ULONG l)
{
	static const unsigned char bits[256] = {
		0, 1, 2, 2, 3, 3, 3, 3, 4, 4, 4, 4, 4, 4, 4, 4,
		5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5,
		6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6,
		6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6,
		7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7,
		7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7,
		7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7,
		7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7,
		8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8,  8, 8, 8, 8,
		8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8,
		8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8,
		8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8,
		8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8,
		8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8,
		8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8,
		8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8,
	};

#ifdef _LP64
	if (l & 0xffffffff00000000L) {
		if (l & 0xffff000000000000L) {
			if (l & 0xff00000000000000L) {
				return (bits[(int)(l >> 56)] + 56);
			} else
				return (bits[(int)(l >> 48)] + 48);
		} else {
			if (l & 0x0000ff0000000000L) {
				return (bits[(int)(l >> 40)] + 40);
			} else
				return (bits[(int)(l >> 32)] + 32);
		}
	} else
#endif
	{
		if (l & 0xffff0000L) {
			if (l & 0xff000000L)
				return (bits[(int)(l >> 24L)] + 24);
			else
				return (bits[(int)(l >> 16L)] + 16);
		} else {
			if (l & 0xff00L)
				return (bits[(int)(l >> 8)] + 8);
			else
				return (bits[(int)(l)]);
		}
	}
}
BN_num_bits(const BIGNUM *a)
{
	int i = a->top - 1;

	bn_check_top(a);

	if (BN_is_zero(a))
		return 0;
	return ((i * BN_BITS2) + BN_num_bits_word(a->d[i]));
}


int
BN_num_bits_word(BN_ULONG l)
{
	static const unsigned char bits[256] = {
		0, 1, 2, 2, 3, 3, 3, 3, 4, 4, 4, 4, 4, 4, 4, 4,
		5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5,
		6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6,
		6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6,
		7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7,
		7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7,
		7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7,
		7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7,
		8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8,  8, 8, 8, 8,
		8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8,
		8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8,
		8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8,
		8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8,
		8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8,
		8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8,
		8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8,
	};

#ifdef _LP64
	if (l & 0xffffffff00000000L) {
		if (l & 0xffff000000000000L) {
			if (l & 0xff00000000000000L) {
				return (bits[(int)(l >> 56)] + 56);
			} else
				return (bits[(int)(l >> 48)] + 48);
		} else {
			if (l & 0x0000ff0000000000L) {
				return (bits[(int)(l >> 40)] + 40);
			} else
				return (bits[(int)(l >> 32)] + 32);
		}
	} else
#endif
	{
		if (l & 0xffff0000L) {
			if (l & 0xff000000L)
				return (bits[(int)(l >> 24L)] + 24);
			else
				return (bits[(int)(l >> 16L)] + 16);
		} else {
			if (l & 0xff00L)
				return (bits[(int)(l >> 8)] + 8);
			else
				return (bits[(int)(l)]);
		}
	}
}


static void
BN_POOL_finish(BN_POOL *p)
{
	while (p->head) {
		unsigned int loop = 0;
		BIGNUM *bn = p->head->vals;
		while (loop++ < BN_CTX_POOL_SIZE) {
			if (bn->d)
				BN_clear_free(bn);
			bn++;
		}
		p->current = p->head->next;
		free(p->head);
		p->head = p->current;
	}
}


static BIGNUM *
BN_POOL_get(BN_POOL *p)
{
	if (p->used == p->size) {
		BIGNUM *bn;
		unsigned int loop = 0;
		BN_POOL_ITEM *item = malloc(sizeof(BN_POOL_ITEM));
		if (!item)
			return NULL;
		/* Initialise the structure */
		bn = item->vals;
		while (loop++ < BN_CTX_POOL_SIZE)
			BN_init(bn++);
		item->prev = p->tail;
		item->next = NULL;
		/* Link it in */
		if (!p->head)
			p->head = p->current = p->tail = item;
		else {
			p->tail->next = item;
			p->tail = item;
			p->current = item;
		}
		p->size += BN_CTX_POOL_SIZE;
		p->used++;
		/* Return the first bignum from the new pool */
		return item->vals;
	}
	if (!p->used)
		p->current = p->head;
	else if ((p->used % BN_CTX_POOL_SIZE) == 0)
		p->current = p->current->next;
	return p->current->vals + ((p->used++) % BN_CTX_POOL_SIZE);
}


static void
BN_POOL_init(BN_POOL *p)
{
	p->head = p->current = p->tail = NULL;
	p->used = p->size = 0;
}


static void
BN_POOL_release(BN_POOL *p, unsigned int num)
{
	unsigned int offset = (p->used - 1) % BN_CTX_POOL_SIZE;

	p->used -= num;
	while (num--) {
		bn_check_top(p->current->vals + offset);
		if (!offset) {
			offset = BN_CTX_POOL_SIZE - 1;
			p->current = p->current->prev;
		} else
			offset--;
	}
}


static int
bnrand(int pseudorand, BIGNUM *rnd, int bits, int top, int bottom)
{
	unsigned char *buf = NULL;
	int ret = 0, bit, bytes, mask;

	if (rnd == NULL) {
		BNerr(BN_F_BNRAND, ERR_R_PASSED_NULL_PARAMETER);
		return (0);
	}

	if (bits == 0) {
		BN_zero(rnd);
		return (1);
	}

	bytes = (bits + 7) / 8;
	bit = (bits - 1) % 8;
	mask = 0xff << (bit + 1);

	buf = malloc(bytes);
	if (buf == NULL) {
		BNerr(BN_F_BNRAND, ERR_R_MALLOC_FAILURE);
		goto err;
	}

	/* make a random number and set the top and bottom bits */
	arc4random_buf(buf, bytes);

#if 1
	if (pseudorand == 2) {
		/* generate patterns that are more likely to trigger BN
		   library bugs */
		int i;
		unsigned char c;

		for (i = 0; i < bytes; i++) {
			arc4random_buf(&c, 1);
			if (c >= 128 && i > 0)
				buf[i] = buf[i - 1];
			else if (c < 42)
				buf[i] = 0;
			else if (c < 84)
				buf[i] = 255;
		}
	}
#endif

	if (top != -1) {
		if (top) {
			if (bit == 0) {
				buf[0] = 1;
				buf[1] |= 0x80;
			} else {
				buf[0] |= (3 << (bit - 1));
			}
		} else {
			buf[0] |= (1 << bit);
		}
	}
	buf[0] &= ~mask;
	if (bottom) /* set bottom bit if requested */
		buf[bytes - 1] |= 1;
	if (BN_bin2bn(buf, bytes, rnd) == NULL)
		goto err;
	ret = 1;

err:
	if (buf != NULL) {
		explicit_bzero(buf, bytes);
		free(buf);
	}
	bn_check_top(rnd);
	return (ret);
}


int    
BN_rand(BIGNUM *rnd, int bits, int top, int bottom)
{
	return bnrand(0, rnd, bits, top, bottom);
}
BN_rand_range(BIGNUM *r, const BIGNUM *range)
{
	return bn_rand_range(0, r, range);
}


static int
bn_rand_range(int pseudo, BIGNUM *r, const BIGNUM *range)
{
	int (*bn_rand)(BIGNUM *, int, int, int) = pseudo ? BN_pseudo_rand : BN_rand;
	int n;
	int count = 100;

	if (range->neg || BN_is_zero(range)) {
		BNerr(BN_F_BN_RAND_RANGE, BN_R_INVALID_RANGE);
		return 0;
	}

	n = BN_num_bits(range); /* n > 0 */

	/* BN_is_bit_set(range, n - 1) always holds */

	if (n == 1)
		BN_zero(r);
	else if (!BN_is_bit_set(range, n - 2) && !BN_is_bit_set(range, n - 3)) {
		/* range = 100..._2,
		 * so  3*range (= 11..._2)  is exactly one bit longer than  range */
		do {
			if (!bn_rand(r, n + 1, -1, 0))
				return 0;
			/* If  r < 3*range,  use  r := r MOD range
			 * (which is either  r, r - range,  or  r - 2*range).
			 * Otherwise, iterate once more.
			 * Since  3*range = 11..._2, each iteration succeeds with
			 * probability >= .75. */
			if (BN_cmp(r, range) >= 0) {
				if (!BN_sub(r, r, range))
					return 0;
				if (BN_cmp(r, range) >= 0)
					if (!BN_sub(r, r, range))
						return 0;
			}

			if (!--count) {
				BNerr(BN_F_BN_RAND_RANGE,
				    BN_R_TOO_MANY_ITERATIONS);
				return 0;
			}

		} while (BN_cmp(r, range) >= 0);
	} else {
		do {
			/* range = 11..._2  or  range = 101..._2 */
			if (!bn_rand(r, n, -1, 0))
				return 0;

			if (!--count) {
				BNerr(BN_F_BN_RAND_RANGE,
				    BN_R_TOO_MANY_ITERATIONS);
				return 0;
			}
		} while (BN_cmp(r, range) >= 0);
	}

	bn_check_top(r);
	return 1;
}


int
BN_rand_range(BIGNUM *r, const BIGNUM *range)
{
	return bn_rand_range(0, r, range);
}


int
BN_rshift1(BIGNUM *r, const BIGNUM *a)
{
	BN_ULONG *ap, *rp, t, c;
	int i, j;

	bn_check_top(r);
	bn_check_top(a);

	if (BN_is_zero(a)) {
		BN_zero(r);
		return (1);
	}
	i = a->top;
	ap = a->d;
	j = i - (ap[i - 1]==1);
	if (a != r) {
		if (bn_wexpand(r, j) == NULL)
			return (0);
		r->neg = a->neg;
	}
	rp = r->d;
	t = ap[--i];
	c = (t & 1) ? BN_TBIT : 0;
	if (t >>= 1)
		rp[i] = t;
	while (i > 0) {
		t = ap[--i];
		rp[i] = ((t >> 1) & BN_MASK2) | c;
		c = (t & 1) ? BN_TBIT : 0;
	}
	r->top = j;
	bn_check_top(r);
	return (1);
}
BN_rshift(BIGNUM *r, const BIGNUM *a, int n)
{
	int i, j, nw, lb, rb;
	BN_ULONG *t, *f;
	BN_ULONG l, tmp;

	bn_check_top(r);
	bn_check_top(a);

	nw = n / BN_BITS2;
	rb = n % BN_BITS2;
	lb = BN_BITS2 - rb;
	if (nw >= a->top || a->top == 0) {
		BN_zero(r);
		return (1);
	}
	i = (BN_num_bits(a) - n + (BN_BITS2 - 1)) / BN_BITS2;
	if (r != a) {
		r->neg = a->neg;
		if (bn_wexpand(r, i) == NULL)
			return (0);
	} else {
		if (n == 0)
			return 1; /* or the copying loop will go berserk */
	}

	f = &(a->d[nw]);
	t = r->d;
	j = a->top - nw;
	r->top = i;

	if (rb == 0) {
		for (i = j; i != 0; i--)
			*(t++) = *(f++);
	} else {
		l = *(f++);
		for (i = j - 1; i != 0; i--) {
			tmp = (l >> rb) & BN_MASK2;
			l = *(f++);
			*(t++) = (tmp|(l << lb)) & BN_MASK2;
		}
		if ((l = (l >> rb) & BN_MASK2))
			*(t) = l;
	}
	bn_check_top(r);
	return (1);
}


int
BN_rshift1(BIGNUM *r, const BIGNUM *a)
{
	BN_ULONG *ap, *rp, t, c;
	int i, j;

	bn_check_top(r);
	bn_check_top(a);

	if (BN_is_zero(a)) {
		BN_zero(r);
		return (1);
	}
	i = a->top;
	ap = a->d;
	j = i - (ap[i - 1]==1);
	if (a != r) {
		if (bn_wexpand(r, j) == NULL)
			return (0);
		r->neg = a->neg;
	}
	rp = r->d;
	t = ap[--i];
	c = (t & 1) ? BN_TBIT : 0;
	if (t >>= 1)
		rp[i] = t;
	while (i > 0) {
		t = ap[--i];
		rp[i] = ((t >> 1) & BN_MASK2) | c;
		c = (t & 1) ? BN_TBIT : 0;
	}
	r->top = j;
	bn_check_top(r);
	return (1);
}


int
BN_set_bit(BIGNUM *a, int n)
{
	int i, j, k;

	if (n < 0)
		return 0;

	i = n / BN_BITS2;
	j = n % BN_BITS2;
	if (a->top <= i) {
		if (bn_wexpand(a, i + 1) == NULL)
			return (0);
		for (k = a->top; k < i + 1; k++)
			a->d[k] = 0;
		a->top = i + 1;
	}

	a->d[i] |= (((BN_ULONG)1) << j);
	bn_check_top(a);
	return (1);
}


void
BN_set_negative(BIGNUM *a, int b)
{
	if (b && !BN_is_zero(a))
		a->neg = 1;
	else
		a->neg = 0;
}


int
BN_set_word(BIGNUM *a, BN_ULONG w)
{
	bn_check_top(a);
	if (bn_expand(a, (int)sizeof(BN_ULONG) * 8) == NULL)
		return (0);
	a->neg = 0;
	a->d[0] = w;
	a->top = (w ? 1 : 0);
	bn_check_top(a);
	return (1);
}


int
BN_sqr(BIGNUM *r, const BIGNUM *a, BN_CTX *ctx)
{
	int max, al;
	int ret = 0;
	BIGNUM *tmp, *rr;

#ifdef BN_COUNT
	fprintf(stderr, "BN_sqr %d * %d\n", a->top, a->top);
#endif
	bn_check_top(a);

	al = a->top;
	if (al <= 0) {
		r->top = 0;
		r->neg = 0;
		return 1;
	}

	BN_CTX_start(ctx);
	rr = (a != r) ? r : BN_CTX_get(ctx);
	tmp = BN_CTX_get(ctx);
	if (rr == NULL || tmp == NULL)
		goto err;

	max = 2 * al; /* Non-zero (from above) */
	if (bn_wexpand(rr, max) == NULL)
		goto err;

	if (al == 4) {
#ifndef BN_SQR_COMBA
		BN_ULONG t[8];
		bn_sqr_normal(rr->d, a->d, 4, t);
#else
		bn_sqr_comba4(rr->d, a->d);
#endif
	} else if (al == 8) {
#ifndef BN_SQR_COMBA
		BN_ULONG t[16];
		bn_sqr_normal(rr->d, a->d, 8, t);
#else
		bn_sqr_comba8(rr->d, a->d);
#endif
	} else {
#if defined(BN_RECURSION)
		if (al < BN_SQR_RECURSIVE_SIZE_NORMAL) {
			BN_ULONG t[BN_SQR_RECURSIVE_SIZE_NORMAL*2];
			bn_sqr_normal(rr->d, a->d, al, t);
		} else {
			int j, k;

			j = BN_num_bits_word((BN_ULONG)al);
			j = 1 << (j - 1);
			k = j + j;
			if (al == j) {
				if (bn_wexpand(tmp, k * 2) == NULL)
					goto err;
				bn_sqr_recursive(rr->d, a->d, al, tmp->d);
			} else {
				if (bn_wexpand(tmp, max) == NULL)
					goto err;
				bn_sqr_normal(rr->d, a->d, al, tmp->d);
			}
		}
#else
		if (bn_wexpand(tmp, max) == NULL)
			goto err;
		bn_sqr_normal(rr->d, a->d, al, tmp->d);
#endif
	}

	rr->neg = 0;
	/* If the most-significant half of the top word of 'a' is zero, then
	 * the square of 'a' will max-1 words. */
	if (a->d[al - 1] == (a->d[al - 1] & BN_MASK2l))
		rr->top = max - 1;
	else
		rr->top = max;
	if (rr != r)
		BN_copy(r, rr);
	ret = 1;

err:
	bn_check_top(rr);
	bn_check_top(tmp);
	BN_CTX_end(ctx);
	return (ret);
}


void
bn_sqr_comba4(BN_ULONG *r, const BN_ULONG *a)
{
	BN_ULONG c1, c2, c3;

	c1 = 0;
	c2 = 0;
	c3 = 0;
	sqr_add_c(a, 0, c1, c2, c3);
	r[0] = c1;
	c1 = 0;
	sqr_add_c2(a, 1, 0, c2, c3, c1);
	r[1] = c2;
	c2 = 0;
	sqr_add_c(a, 1, c3, c1, c2);
	sqr_add_c2(a, 2, 0, c3, c1, c2);
	r[2] = c3;
	c3 = 0;
	sqr_add_c2(a, 3, 0, c1, c2, c3);
	sqr_add_c2(a, 2, 1, c1, c2, c3);
	r[3] = c1;
	c1 = 0;
	sqr_add_c(a, 2, c2, c3, c1);
	sqr_add_c2(a, 3, 1, c2, c3, c1);
	r[4] = c2;
	c2 = 0;
	sqr_add_c2(a, 3, 2, c3, c1, c2);
	r[5] = c3;
	c3 = 0;
	sqr_add_c(a, 3, c1, c2, c3);
	r[6] = c1;
	r[7] = c2;
}
bn_sqr_comba4(BN_ULONG *r, const BN_ULONG *a)
{
	BN_ULONG t[8];
	bn_sqr_normal(r, a, 4, t);
}


void
bn_sqr_comba8(BN_ULONG *r, const BN_ULONG *a)
{
	BN_ULONG c1, c2, c3;

	c1 = 0;
	c2 = 0;
	c3 = 0;
	sqr_add_c(a, 0, c1, c2, c3);
	r[0] = c1;
	c1 = 0;
	sqr_add_c2(a, 1, 0, c2, c3, c1);
	r[1] = c2;
	c2 = 0;
	sqr_add_c(a, 1, c3, c1, c2);
	sqr_add_c2(a, 2, 0, c3, c1, c2);
	r[2] = c3;
	c3 = 0;
	sqr_add_c2(a, 3, 0, c1, c2, c3);
	sqr_add_c2(a, 2, 1, c1, c2, c3);
	r[3] = c1;
	c1 = 0;
	sqr_add_c(a, 2, c2, c3, c1);
	sqr_add_c2(a, 3, 1, c2, c3, c1);
	sqr_add_c2(a, 4, 0, c2, c3, c1);
	r[4] = c2;
	c2 = 0;
	sqr_add_c2(a, 5, 0, c3, c1, c2);
	sqr_add_c2(a, 4, 1, c3, c1, c2);
	sqr_add_c2(a, 3, 2, c3, c1, c2);
	r[5] = c3;
	c3 = 0;
	sqr_add_c(a, 3, c1, c2, c3);
	sqr_add_c2(a, 4, 2, c1, c2, c3);
	sqr_add_c2(a, 5, 1, c1, c2, c3);
	sqr_add_c2(a, 6, 0, c1, c2, c3);
	r[6] = c1;
	c1 = 0;
	sqr_add_c2(a, 7, 0, c2, c3, c1);
	sqr_add_c2(a, 6, 1, c2, c3, c1);
	sqr_add_c2(a, 5, 2, c2, c3, c1);
	sqr_add_c2(a, 4, 3, c2, c3, c1);
	r[7] = c2;
	c2 = 0;
	sqr_add_c(a, 4, c3, c1, c2);
	sqr_add_c2(a, 5, 3, c3, c1, c2);
	sqr_add_c2(a, 6, 2, c3, c1, c2);
	sqr_add_c2(a, 7, 1, c3, c1, c2);
	r[8] = c3;
	c3 = 0;
	sqr_add_c2(a, 7, 2, c1, c2, c3);
	sqr_add_c2(a, 6, 3, c1, c2, c3);
	sqr_add_c2(a, 5, 4, c1, c2, c3);
	r[9] = c1;
	c1 = 0;
	sqr_add_c(a, 5, c2, c3, c1);
	sqr_add_c2(a, 6, 4, c2, c3, c1);
	sqr_add_c2(a, 7, 3, c2, c3, c1);
	r[10] = c2;
	c2 = 0;
	sqr_add_c2(a, 7, 4, c3, c1, c2);
	sqr_add_c2(a, 6, 5, c3, c1, c2);
	r[11] = c3;
	c3 = 0;
	sqr_add_c(a, 6, c1, c2, c3);
	sqr_add_c2(a, 7, 5, c1, c2, c3);
	r[12] = c1;
	c1 = 0;
	sqr_add_c2(a, 7, 6, c2, c3, c1);
	r[13] = c2;
	c2 = 0;
	sqr_add_c(a, 7, c3, c1, c2);
	r[14] = c3;
	r[15] = c1;
}
bn_sqr_comba8(BN_ULONG *r, const BN_ULONG *a)
{
	BN_ULONG t[16];
	bn_sqr_normal(r, a, 8, t);
}


void
bn_sqr_recursive(BN_ULONG *r, const BN_ULONG *a, int n2, BN_ULONG *t)
{
	int n = n2 / 2;
	int zero, c1;
	BN_ULONG ln, lo, *p;

#ifdef BN_COUNT
	fprintf(stderr, " bn_sqr_recursive %d * %d\n", n2, n2);
#endif
	if (n2 == 4) {
#ifndef BN_SQR_COMBA
		bn_sqr_normal(r, a, 4, t);
#else
		bn_sqr_comba4(r, a);
#endif
		return;
	} else if (n2 == 8) {
#ifndef BN_SQR_COMBA
		bn_sqr_normal(r, a, 8, t);
#else
		bn_sqr_comba8(r, a);
#endif
		return;
	}
	if (n2 < BN_SQR_RECURSIVE_SIZE_NORMAL) {
		bn_sqr_normal(r, a, n2, t);
		return;
	}
	/* r=(a[0]-a[1])*(a[1]-a[0]) */
	c1 = bn_cmp_words(a, &(a[n]), n);
	zero = 0;
	if (c1 > 0)
		bn_sub_words(t, a, &(a[n]), n);
	else if (c1 < 0)
		bn_sub_words(t, &(a[n]), a, n);
	else
		zero = 1;

	/* The result will always be negative unless it is zero */
	p = &(t[n2*2]);

	if (!zero)
		bn_sqr_recursive(&(t[n2]), t, n, p);
	else
		memset(&(t[n2]), 0, n2 * sizeof(BN_ULONG));
	bn_sqr_recursive(r, a, n, p);
	bn_sqr_recursive(&(r[n2]), &(a[n]), n, p);

	/* t[32] holds (a[0]-a[1])*(a[1]-a[0]), it is negative or zero
	 * r[10] holds (a[0]*b[0])
	 * r[32] holds (b[1]*b[1])
	 */

	c1 = (int)(bn_add_words(t, r, &(r[n2]), n2));

	/* t[32] is negative */
	c1 -= (int)(bn_sub_words(&(t[n2]), t, &(t[n2]), n2));

	/* t[32] holds (a[0]-a[1])*(a[1]-a[0])+(a[0]*a[0])+(a[1]*a[1])
	 * r[10] holds (a[0]*a[0])
	 * r[32] holds (a[1]*a[1])
	 * c1 holds the carry bits
	 */
	c1 += (int)(bn_add_words(&(r[n]), &(r[n]), &(t[n2]), n2));
	if (c1) {
		p = &(r[n + n2]);
		lo= *p;
		ln = (lo + c1) & BN_MASK2;
		*p = ln;

		/* The overflow will stop before we over write
		 * words we should not overwrite */
		if (ln < (BN_ULONG)c1) {
			do {
				p++;
				lo= *p;
				ln = (lo + 1) & BN_MASK2;
				*p = ln;
			} while (ln == 0);
		}
	}
}


static void
BN_STACK_finish(BN_STACK *st)
{
	if (st->size)
		free(st->indexes);
}


static void
BN_STACK_init(BN_STACK *st)
{
	st->indexes = NULL;
	st->depth = st->size = 0;
}


static unsigned int
BN_STACK_pop(BN_STACK *st)
{
	return st->indexes[--(st->depth)];
}


static int
BN_STACK_push(BN_STACK *st, unsigned int idx)
{
	if (st->depth == st->size)
		/* Need to expand */
	{
		unsigned int newsize = (st->size ?
		    (st->size * 3 / 2) : BN_CTX_START_FRAMES);
		unsigned int *newitems = reallocarray(NULL,
		    newsize, sizeof(unsigned int));
		if (!newitems)
			return 0;
		if (st->depth)
			memcpy(newitems, st->indexes, st->depth *
			    sizeof(unsigned int));
		if (st->size)
			free(st->indexes);
		st->indexes = newitems;
		st->size = newsize;
	}
	st->indexes[(st->depth)++] = idx;
	return 1;
}


int
BN_sub(BIGNUM *r, const BIGNUM *a, const BIGNUM *b)
{
	int max;
	int add = 0, neg = 0;
	const BIGNUM *tmp;

	bn_check_top(a);
	bn_check_top(b);

	/*  a -  b	a-b
	 *  a - -b	a+b
	 * -a -  b	-(a+b)
	 * -a - -b	b-a
	 */
	if (a->neg) {
		if (b->neg) {
			tmp = a;
			a = b;
			b = tmp;
		} else {
			add = 1;
			neg = 1;
		}
	} else {
		if (b->neg) {
			add = 1;
			neg = 0;
		}
	}

	if (add) {
		if (!BN_uadd(r, a, b))
			return (0);
		r->neg = neg;
		return (1);
	}

	/* We are actually doing a - b :-) */

	max = (a->top > b->top) ? a->top : b->top;
	if (bn_wexpand(r, max) == NULL)
		return (0);
	if (BN_ucmp(a, b) < 0) {
		if (!BN_usub(r, b, a))
			return (0);
		r->neg = 1;
	} else {
		if (!BN_usub(r, a, b))
			return (0);
		r->neg = 0;
	}
	bn_check_top(r);
	return (1);
}


BN_ULONG
bn_sub_part_words(BN_ULONG *r, const BN_ULONG *a, const BN_ULONG *b, int cl,
    int dl)
{
	BN_ULONG c, t;

	assert(cl >= 0);
	c = bn_sub_words(r, a, b, cl);

	if (dl == 0)
		return c;

	r += cl;
	a += cl;
	b += cl;

	if (dl < 0) {
#ifdef BN_COUNT
		fprintf(stderr,
		    "  bn_sub_part_words %d + %d (dl < 0, c = %d)\n",
		    cl, dl, c);
#endif
		for (;;) {
			t = b[0];
			r[0] = (0 - t - c) & BN_MASK2;
			if (t != 0)
				c = 1;
			if (++dl >= 0)
				break;

			t = b[1];
			r[1] = (0 - t - c) & BN_MASK2;
			if (t != 0)
				c = 1;
			if (++dl >= 0)
				break;

			t = b[2];
			r[2] = (0 - t - c) & BN_MASK2;
			if (t != 0)
				c = 1;
			if (++dl >= 0)
				break;

			t = b[3];
			r[3] = (0 - t - c) & BN_MASK2;
			if (t != 0)
				c = 1;
			if (++dl >= 0)
				break;

			b += 4;
			r += 4;
		}
	} else {
		int save_dl = dl;
#ifdef BN_COUNT
		fprintf(stderr,
		    "  bn_sub_part_words %d + %d (dl > 0, c = %d)\n",
		    cl, dl, c);
#endif
		while (c) {
			t = a[0];
			r[0] = (t - c) & BN_MASK2;
			if (t != 0)
				c = 0;
			if (--dl <= 0)
				break;

			t = a[1];
			r[1] = (t - c) & BN_MASK2;
			if (t != 0)
				c = 0;
			if (--dl <= 0)
				break;

			t = a[2];
			r[2] = (t - c) & BN_MASK2;
			if (t != 0)
				c = 0;
			if (--dl <= 0)
				break;

			t = a[3];
			r[3] = (t - c) & BN_MASK2;
			if (t != 0)
				c = 0;
			if (--dl <= 0)
				break;

			save_dl = dl;
			a += 4;
			r += 4;
		}
		if (dl > 0) {
#ifdef BN_COUNT
			fprintf(stderr,
			    "  bn_sub_part_words %d + %d (dl > 0, c == 0)\n",
			    cl, dl);
#endif
			if (save_dl > dl) {
				switch (save_dl - dl) {
				case 1:
					r[1] = a[1];
					if (--dl <= 0)
						break;
				case 2:
					r[2] = a[2];
					if (--dl <= 0)
						break;
				case 3:
					r[3] = a[3];
					if (--dl <= 0)
						break;
				}
				a += 4;
				r += 4;
			}
		}
		if (dl > 0) {
#ifdef BN_COUNT
			fprintf(stderr,
			    "  bn_sub_part_words %d + %d (dl > 0, copy)\n",
			    cl, dl);
#endif
			for (;;) {
				r[0] = a[0];
				if (--dl <= 0)
					break;
				r[1] = a[1];
				if (--dl <= 0)
					break;
				r[2] = a[2];
				if (--dl <= 0)
					break;
				r[3] = a[3];
				if (--dl <= 0)
					break;

				a += 4;
				r += 4;
			}
		}
	}
	return c;
}


int
BN_sub_word(BIGNUM *a, BN_ULONG w)
{
	int i;

	bn_check_top(a);
	w &= BN_MASK2;

	/* degenerate case: w is zero */
	if (!w)
		return 1;
	/* degenerate case: a is zero */
	if (BN_is_zero(a)) {
		i = BN_set_word(a, w);
		if (i != 0)
			BN_set_negative(a, 1);
		return i;
	}
	/* handle 'a' when negative */
	if (a->neg) {
		a->neg = 0;
		i = BN_add_word(a, w);
		a->neg = 1;
		return (i);
	}

	if ((a->top == 1) && (a->d[0] < w)) {
		a->d[0] = w - a->d[0];
		a->neg = 1;
		return (1);
	}
	i = 0;
	for (;;) {
		if (a->d[i] >= w) {
			a->d[i] -= w;
			break;
		} else {
			a->d[i] = (a->d[i] - w) & BN_MASK2;
			i++;
			w = 1;
		}
	}
	if ((a->d[i] == 0) && (i == (a->top - 1)))
		a->top--;
	bn_check_top(a);
	return (1);
}


BN_ULONG
bn_sub_words(BN_ULONG *r, const BN_ULONG *a, const BN_ULONG *b, int n)
{
	BN_ULONG t1, t2;
	int c = 0;

	assert(n >= 0);
	if (n <= 0)
		return ((BN_ULONG)0);

#ifndef OPENSSL_SMALL_FOOTPRINT
	while (n&~3) {
		t1 = a[0];
		t2 = b[0];
		r[0] = (t1 - t2 - c) & BN_MASK2;
		if (t1 != t2)
			c = (t1 < t2);
		t1 = a[1];
		t2 = b[1];
		r[1] = (t1 - t2 - c) & BN_MASK2;
		if (t1 != t2)
			c = (t1 < t2);
		t1 = a[2];
		t2 = b[2];
		r[2] = (t1 - t2 - c) & BN_MASK2;
		if (t1 != t2)
			c = (t1 < t2);
		t1 = a[3];
		t2 = b[3];
		r[3] = (t1 - t2 - c) & BN_MASK2;
		if (t1 != t2)
			c = (t1 < t2);
		a += 4;
		b += 4;
		r += 4;
		n -= 4;
	}
#endif
	while (n) {
		t1 = a[0];
		t2 = b[0];
		r[0] = (t1 - t2 - c) & BN_MASK2;
		if (t1 != t2)
			c = (t1 < t2);
		a++;
		b++;
		r++;
		n--;
	}
	return (c);
}


int
BN_uadd(BIGNUM *r, const BIGNUM *a, const BIGNUM *b)
{
	int max, min, dif;
	BN_ULONG *ap, *bp, *rp, carry, t1, t2;
	const BIGNUM *tmp;

	bn_check_top(a);
	bn_check_top(b);

	if (a->top < b->top) {
		tmp = a;
		a = b;
		b = tmp;
	}
	max = a->top;
	min = b->top;
	dif = max - min;

	if (bn_wexpand(r, max + 1) == NULL)
		return 0;

	r->top = max;

	ap = a->d;
	bp = b->d;
	rp = r->d;

	carry = bn_add_words(rp, ap, bp, min);
	rp += min;
	ap += min;
	bp += min;

	if (carry) {
		while (dif) {
			dif--;
			t1 = *(ap++);
			t2 = (t1 + 1) & BN_MASK2;
			*(rp++) = t2;
			if (t2) {
				carry = 0;
				break;
			}
		}
		if (carry) {
			/* carry != 0 => dif == 0 */
			*rp = 1;
			r->top++;
		}
	}
	if (dif && rp != ap)
		while (dif--)
			/* copy remaining words if ap != rp */
			*(rp++) = *(ap++);
	r->neg = 0;
	bn_check_top(r);
	return 1;
}


int
BN_ucmp(const BIGNUM *a, const BIGNUM *b)
{
	int i;
	BN_ULONG t1, t2, *ap, *bp;

	bn_check_top(a);
	bn_check_top(b);

	i = a->top - b->top;
	if (i != 0)
		return (i);
	ap = a->d;
	bp = b->d;
	for (i = a->top - 1; i >= 0; i--) {
		t1 = ap[i];
		t2 = bp[i];
		if (t1 != t2)
			return ((t1 > t2) ? 1 : -1);
	}
	return (0);
}


int
BN_usub(BIGNUM *r, const BIGNUM *a, const BIGNUM *b)
{
	int max, min, dif;
	BN_ULONG t1, t2, *ap, *bp, *rp;
	int i, carry;

	bn_check_top(a);
	bn_check_top(b);

	max = a->top;
	min = b->top;
	dif = max - min;

	if (dif < 0)	/* hmm... should not be happening */
	{
		BNerr(BN_F_BN_USUB, BN_R_ARG2_LT_ARG3);
		return (0);
	}

	if (bn_wexpand(r, max) == NULL)
		return (0);

	ap = a->d;
	bp = b->d;
	rp = r->d;

#if 1
	carry = 0;
	for (i = min; i != 0; i--) {
		t1= *(ap++);
		t2= *(bp++);
		if (carry) {
			carry = (t1 <= t2);
			t1 = (t1 - t2 - 1)&BN_MASK2;
		} else {
			carry = (t1 < t2);
			t1 = (t1 - t2)&BN_MASK2;
		}
		*(rp++) = t1&BN_MASK2;
	}
#else
	carry = bn_sub_words(rp, ap, bp, min);
	ap += min;
	bp += min;
	rp += min;
#endif
	if (carry) /* subtracted */
	{
		if (!dif)
			/* error: a < b */
			return 0;
		while (dif) {
			dif--;
			t1 = *(ap++);
			t2 = (t1 - 1)&BN_MASK2;
			*(rp++) = t2;
			if (t1)
				break;
		}
	}
#if 0
	memcpy(rp, ap, sizeof(*rp)*(max - i));
#else
	if (rp != ap) {
		for (;;) {
			if (!dif--)
				break;
			rp[0] = ap[0];
			if (!dif--)
				break;
			rp[1] = ap[1];
			if (!dif--)
				break;
			rp[2] = ap[2];
			if (!dif--)
				break;
			rp[3] = ap[3];
			rp += 4;
			ap += 4;
		}
	}
#endif

	r->top = max;
	r->neg = 0;
	bn_correct_top(r);
	return (1);
}


const BIGNUM *
BN_value_one(void)
{
	static const BN_ULONG data_one = 1L;
	static const BIGNUM const_one = {
		(BN_ULONG *)&data_one, 1, 1, 0, BN_FLG_STATIC_DATA
	};

	return (&const_one);
}


void
BUF_MEM_free(BUF_MEM *a)
{
	if (a == NULL)
		return;

	if (a->data != NULL) {
		explicit_bzero(a->data, a->max);
		free(a->data);
	}
	free(a);
}


int
BUF_MEM_grow(BUF_MEM *str, size_t len)
{
	char *ret;
	size_t n;

	if (str->length >= len) {
		str->length = len;
		return (len);
	}
	if (str->max >= len) {
		memset(&str->data[str->length], 0, len - str->length);
		str->length = len;
		return (len);
	}
	/* This limit is sufficient to ensure (len+3)/3*4 < 2**31 */
	if (len > LIMIT_BEFORE_EXPANSION) {
		BUFerr(BUF_F_BUF_MEM_GROW, ERR_R_MALLOC_FAILURE);
		return 0;
	}
	n = (len + 3) / 3 * 4;
	ret = realloc(str->data, n);
	if (ret == NULL) {
		BUFerr(BUF_F_BUF_MEM_GROW, ERR_R_MALLOC_FAILURE);
		len = 0;
	} else {
		str->data = ret;
		str->max = n;
		memset(&str->data[str->length], 0, len - str->length);
		str->length = len;
	}
	return (len);
}
BUF_MEM_grow_clean(BUF_MEM *str, size_t len)
{
	char *ret;
	size_t n;

	if (str->length >= len) {
		memset(&str->data[len], 0, str->length - len);
		str->length = len;
		return (len);
	}
	if (str->max >= len) {
		memset(&str->data[str->length], 0, len - str->length);
		str->length = len;
		return (len);
	}
	/* This limit is sufficient to ensure (len+3)/3*4 < 2**31 */
	if (len > LIMIT_BEFORE_EXPANSION) {
		BUFerr(BUF_F_BUF_MEM_GROW_CLEAN, ERR_R_MALLOC_FAILURE);
		return 0;
	}
	n = (len + 3) / 3 * 4;
	ret = malloc(n);
	/* we're not shrinking - that case returns above */
	if ((ret != NULL)  && (str->data != NULL)) {
		memcpy(ret, str->data, str->max);
		explicit_bzero(str->data, str->max);
		free(str->data);
	}
	if (ret == NULL) {
		BUFerr(BUF_F_BUF_MEM_GROW_CLEAN, ERR_R_MALLOC_FAILURE);
		len = 0;
	} else {
		str->data = ret;
		str->max = n;
		memset(&str->data[str->length], 0, len - str->length);
		str->length = len;
	}
	return (len);
}


BUF_MEM *
BUF_MEM_new(void)
{
	BUF_MEM *ret;

	ret = malloc(sizeof(BUF_MEM));
	if (ret == NULL) {
		BUFerr(BUF_F_BUF_MEM_NEW, ERR_R_MALLOC_FAILURE);
		return (NULL);
	}
	ret->length = 0;
	ret->max = 0;
	ret->data = NULL;
	return (ret);
}


static void
build_SYS_str_reasons(void)
{
	/* malloc cannot be used here, use static storage instead */
	static char strerror_tab[NUM_SYS_STR_REASONS][LEN_SYS_STR_REASON];
	int i;
	static int init = 1;

	CRYPTO_r_lock(CRYPTO_LOCK_ERR);
	if (!init) {
		CRYPTO_r_unlock(CRYPTO_LOCK_ERR);
		return;
	}

	CRYPTO_r_unlock(CRYPTO_LOCK_ERR);
	CRYPTO_w_lock(CRYPTO_LOCK_ERR);
	if (!init) {
		CRYPTO_w_unlock(CRYPTO_LOCK_ERR);
		return;
	}

	for (i = 1; i <= NUM_SYS_STR_REASONS; i++) {
		ERR_STRING_DATA *str = &SYS_str_reasons[i - 1];

		str->error = (unsigned long)i;
		if (str->string == NULL) {
			char (*dest)[LEN_SYS_STR_REASON] =
			    &(strerror_tab[i - 1]);
			const char *src = strerror(i);
			if (src != NULL) {
				strlcpy(*dest, src, sizeof *dest);
				str->string = *dest;
			}
		}
		if (str->string == NULL)
			str->string = "unknown";
	}

	/* Now we still have SYS_str_reasons[NUM_SYS_STR_REASONS] = {0, NULL},
	 * as required by ERR_load_strings. */

	init = 0;

	CRYPTO_w_unlock(CRYPTO_LOCK_ERR);
}


ASN1_BIT_STRING *
c2i_ASN1_BIT_STRING(ASN1_BIT_STRING **a, const unsigned char **pp, long len)
{
	ASN1_BIT_STRING *ret = NULL;
	const unsigned char *p;
	unsigned char *s;
	int i;

	if (len < 1) {
		i = ASN1_R_STRING_TOO_SHORT;
		goto err;
	}

	if ((a == NULL) || ((*a) == NULL)) {
		if ((ret = ASN1_BIT_STRING_new()) == NULL)
			return (NULL);
	} else
		ret = (*a);

	p = *pp;
	i = *(p++);
	/* We do this to preserve the settings.  If we modify
	 * the settings, via the _set_bit function, we will recalculate
	 * on output */
	ret->flags&= ~(ASN1_STRING_FLAG_BITS_LEFT|0x07); /* clear */
	ret->flags|=(ASN1_STRING_FLAG_BITS_LEFT|(i&0x07)); /* set */

	if (len-- > 1) /* using one because of the bits left byte */
	{
		s = malloc(len);
		if (s == NULL) {
			i = ERR_R_MALLOC_FAILURE;
			goto err;
		}
		memcpy(s, p, len);
		s[len - 1] &= (0xff << i);
		p += len;
	} else
		s = NULL;

	ret->length = (int)len;
	free(ret->data);
	ret->data = s;
	ret->type = V_ASN1_BIT_STRING;
	if (a != NULL)
		(*a) = ret;
	*pp = p;
	return (ret);

err:
	ASN1err(ASN1_F_C2I_ASN1_BIT_STRING, i);
	if ((ret != NULL) && ((a == NULL) || (*a != ret)))
		ASN1_BIT_STRING_free(ret);
	return (NULL);
}


ASN1_INTEGER *
c2i_ASN1_INTEGER(ASN1_INTEGER **a, const unsigned char **pp, long len)
{
	ASN1_INTEGER *ret = NULL;
	const unsigned char *p, *pend;
	unsigned char *to, *s;
	int i;

	if ((a == NULL) || ((*a) == NULL)) {
		if ((ret = ASN1_INTEGER_new()) == NULL)
			return (NULL);
	} else
		ret = (*a);

	p = *pp;
	pend = p + len;

	/* We must malloc stuff, even for 0 bytes otherwise it
	 * signifies a missing NULL parameter. */
	s = malloc(len + 1);
	if (s == NULL) {
		i = ERR_R_MALLOC_FAILURE;
		goto err;
	}
	to = s;
	if (!len) {
		/* Strictly speaking this is an illegal INTEGER but we
		 * tolerate it.
		 */
		ret->type = V_ASN1_INTEGER;
	} else if (*p & 0x80) /* a negative number */ {
		ret->type = V_ASN1_NEG_INTEGER;
		if ((*p == 0xff) && (len != 1)) {
			p++;
			len--;
		}
		i = len;
		p += i - 1;
		to += i - 1;
		while((!*p) && i) {
			*(to--) = 0;
			i--;
			p--;
		}
		/* Special case: if all zeros then the number will be of
		 * the form FF followed by n zero bytes: this corresponds to
		 * 1 followed by n zero bytes. We've already written n zeros
		 * so we just append an extra one and set the first byte to
		 * a 1. This is treated separately because it is the only case
		 * where the number of bytes is larger than len.
		 */
		if (!i) {
			*s = 1;
			s[len] = 0;
			len++;
		} else {
			*(to--) = (*(p--) ^ 0xff) + 1;
			i--;
			for (; i > 0; i--)
				*(to--) = *(p--) ^ 0xff;
		}
	} else {
		ret->type = V_ASN1_INTEGER;
		if ((*p == 0) && (len != 1)) {
			p++;
			len--;
		}
		memcpy(s, p, len);
	}

	free(ret->data);
	ret->data = s;
	ret->length = (int)len;
	if (a != NULL)
		(*a) = ret;
	*pp = pend;
	return (ret);

err:
	ASN1err(ASN1_F_C2I_ASN1_INTEGER, i);
	if (a == NULL || *a != ret)
		ASN1_INTEGER_free(ret);
	return (NULL);
}


ASN1_OBJECT *
c2i_ASN1_OBJECT(ASN1_OBJECT **a, const unsigned char **pp, long len)
{
	ASN1_OBJECT *ret = NULL;
	const unsigned char *p;
	unsigned char *data;
	int i, length;

	/*
	 * Sanity check OID encoding:
	 * - need at least one content octet
	 * - MSB must be clear in the last octet
	 * - can't have leading 0x80 in subidentifiers, see: X.690 8.19.2
	 */
	if (len <= 0 || len > INT_MAX || pp == NULL || (p = *pp) == NULL ||
	    p[len - 1] & 0x80) {
		ASN1err(ASN1_F_C2I_ASN1_OBJECT, ASN1_R_INVALID_OBJECT_ENCODING);
		return (NULL);
	}

	/* Now 0 < len <= INT_MAX, so the cast is safe. */
	length = (int)len;
	for (i = 0; i < length; i++, p++) {
		if (*p == 0x80 && (!i || !(p[-1] & 0x80))) {
			ASN1err(ASN1_F_C2I_ASN1_OBJECT,
			    ASN1_R_INVALID_OBJECT_ENCODING);
			return NULL;
		}
	}

	/* only the ASN1_OBJECTs from the 'table' will have values
	 * for ->sn or ->ln */
	if ((a == NULL) || ((*a) == NULL) ||
	    !((*a)->flags & ASN1_OBJECT_FLAG_DYNAMIC)) {
		if ((ret = ASN1_OBJECT_new()) == NULL)
			return (NULL);
	} else
		ret = (*a);

	p = *pp;
	/* detach data from object */
	data = (unsigned char *)ret->data;
	if (data != NULL)
		explicit_bzero(data, ret->length);
	free(data);
	data = malloc(length);
	if (data == NULL) {
		i = ERR_R_MALLOC_FAILURE;
		goto err;
	}
	ret->flags |= ASN1_OBJECT_FLAG_DYNAMIC_DATA;
	memcpy(data, p, length);
	/* reattach data to object, after which it remains const */
	ret->data = data;
	ret->length = length;
	ret->sn = NULL;
	ret->ln = NULL;
	/* ret->flags=ASN1_OBJECT_FLAG_DYNAMIC; we know it is dynamic */
	p += length;

	if (a != NULL)
		(*a) = ret;
	*pp = p;
	return (ret);

err:
	ASN1err(ASN1_F_C2I_ASN1_OBJECT, i);
	if ((ret != NULL) && ((a == NULL) || (*a != ret)))
		ASN1_OBJECT_free(ret);
	return (NULL);
}


static inline void
chacha_encrypt_bytes(chacha_ctx *x, const u8 *m, u8 *c, u32 bytes)
{
	u32 x0, x1, x2, x3, x4, x5, x6, x7;
	u32 x8, x9, x10, x11, x12, x13, x14, x15;
	u32 j0, j1, j2, j3, j4, j5, j6, j7;
	u32 j8, j9, j10, j11, j12, j13, j14, j15;
	u8 *ctarget = NULL;
	u8 tmp[64];
	u_int i;

	if (!bytes)
		return;

	j0 = x->input[0];
	j1 = x->input[1];
	j2 = x->input[2];
	j3 = x->input[3];
	j4 = x->input[4];
	j5 = x->input[5];
	j6 = x->input[6];
	j7 = x->input[7];
	j8 = x->input[8];
	j9 = x->input[9];
	j10 = x->input[10];
	j11 = x->input[11];
	j12 = x->input[12];
	j13 = x->input[13];
	j14 = x->input[14];
	j15 = x->input[15];

	for (;;) {
		if (bytes < 64) {
			for (i = 0; i < bytes; ++i)
				tmp[i] = m[i];
			m = tmp;
			ctarget = c;
			c = tmp;
		}
		x0 = j0;
		x1 = j1;
		x2 = j2;
		x3 = j3;
		x4 = j4;
		x5 = j5;
		x6 = j6;
		x7 = j7;
		x8 = j8;
		x9 = j9;
		x10 = j10;
		x11 = j11;
		x12 = j12;
		x13 = j13;
		x14 = j14;
		x15 = j15;
		for (i = 20; i > 0; i -= 2) {
			QUARTERROUND(x0, x4, x8, x12)
			QUARTERROUND(x1, x5, x9, x13)
			QUARTERROUND(x2, x6, x10, x14)
			QUARTERROUND(x3, x7, x11, x15)
			QUARTERROUND(x0, x5, x10, x15)
			QUARTERROUND(x1, x6, x11, x12)
			QUARTERROUND(x2, x7, x8, x13)
			QUARTERROUND(x3, x4, x9, x14)
		}
		x0 = PLUS(x0, j0);
		x1 = PLUS(x1, j1);
		x2 = PLUS(x2, j2);
		x3 = PLUS(x3, j3);
		x4 = PLUS(x4, j4);
		x5 = PLUS(x5, j5);
		x6 = PLUS(x6, j6);
		x7 = PLUS(x7, j7);
		x8 = PLUS(x8, j8);
		x9 = PLUS(x9, j9);
		x10 = PLUS(x10, j10);
		x11 = PLUS(x11, j11);
		x12 = PLUS(x12, j12);
		x13 = PLUS(x13, j13);
		x14 = PLUS(x14, j14);
		x15 = PLUS(x15, j15);

		if (bytes < 64) {
			U32TO8_LITTLE(x->ks + 0, x0);
			U32TO8_LITTLE(x->ks + 4, x1);
			U32TO8_LITTLE(x->ks + 8, x2);
			U32TO8_LITTLE(x->ks + 12, x3);
			U32TO8_LITTLE(x->ks + 16, x4);
			U32TO8_LITTLE(x->ks + 20, x5);
			U32TO8_LITTLE(x->ks + 24, x6);
			U32TO8_LITTLE(x->ks + 28, x7);
			U32TO8_LITTLE(x->ks + 32, x8);
			U32TO8_LITTLE(x->ks + 36, x9);
			U32TO8_LITTLE(x->ks + 40, x10);
			U32TO8_LITTLE(x->ks + 44, x11);
			U32TO8_LITTLE(x->ks + 48, x12);
			U32TO8_LITTLE(x->ks + 52, x13);
			U32TO8_LITTLE(x->ks + 56, x14);
			U32TO8_LITTLE(x->ks + 60, x15);
		}

		x0 = XOR(x0, U8TO32_LITTLE(m + 0));
		x1 = XOR(x1, U8TO32_LITTLE(m + 4));
		x2 = XOR(x2, U8TO32_LITTLE(m + 8));
		x3 = XOR(x3, U8TO32_LITTLE(m + 12));
		x4 = XOR(x4, U8TO32_LITTLE(m + 16));
		x5 = XOR(x5, U8TO32_LITTLE(m + 20));
		x6 = XOR(x6, U8TO32_LITTLE(m + 24));
		x7 = XOR(x7, U8TO32_LITTLE(m + 28));
		x8 = XOR(x8, U8TO32_LITTLE(m + 32));
		x9 = XOR(x9, U8TO32_LITTLE(m + 36));
		x10 = XOR(x10, U8TO32_LITTLE(m + 40));
		x11 = XOR(x11, U8TO32_LITTLE(m + 44));
		x12 = XOR(x12, U8TO32_LITTLE(m + 48));
		x13 = XOR(x13, U8TO32_LITTLE(m + 52));
		x14 = XOR(x14, U8TO32_LITTLE(m + 56));
		x15 = XOR(x15, U8TO32_LITTLE(m + 60));

		j12 = PLUSONE(j12);
		if (!j12) {
			j13 = PLUSONE(j13);
			/*
			 * Stopping at 2^70 bytes per nonce is the user's
			 * responsibility.
			 */
		}

		U32TO8_LITTLE(c + 0, x0);
		U32TO8_LITTLE(c + 4, x1);
		U32TO8_LITTLE(c + 8, x2);
		U32TO8_LITTLE(c + 12, x3);
		U32TO8_LITTLE(c + 16, x4);
		U32TO8_LITTLE(c + 20, x5);
		U32TO8_LITTLE(c + 24, x6);
		U32TO8_LITTLE(c + 28, x7);
		U32TO8_LITTLE(c + 32, x8);
		U32TO8_LITTLE(c + 36, x9);
		U32TO8_LITTLE(c + 40, x10);
		U32TO8_LITTLE(c + 44, x11);
		U32TO8_LITTLE(c + 48, x12);
		U32TO8_LITTLE(c + 52, x13);
		U32TO8_LITTLE(c + 56, x14);
		U32TO8_LITTLE(c + 60, x15);

		if (bytes <= 64) {
			if (bytes < 64) {
				for (i = 0; i < bytes; ++i)
					ctarget[i] = c[i];
			}
			x->input[12] = j12;
			x->input[13] = j13;
			x->unused = 64 - bytes;
			return;
		}
		bytes -= 64;
		c += 64;
		m += 64;
	}
}


static inline void
chacha_ivsetup(chacha_ctx *x, const u8 *iv, const u8 *counter)
{
	x->input[12] = counter == NULL ? 0 : U8TO32_LITTLE(counter + 0);
	x->input[13] = counter == NULL ? 0 : U8TO32_LITTLE(counter + 4);
	x->input[14] = U8TO32_LITTLE(iv + 0);
	x->input[15] = U8TO32_LITTLE(iv + 4);
}


static inline void
chacha_keysetup(chacha_ctx *x, const u8 *k, u32 kbits)
{
	const char *constants;

	x->input[4] = U8TO32_LITTLE(k + 0);
	x->input[5] = U8TO32_LITTLE(k + 4);
	x->input[6] = U8TO32_LITTLE(k + 8);
	x->input[7] = U8TO32_LITTLE(k + 12);
	if (kbits == 256) { /* recommended */
		k += 16;
		constants = sigma;
	} else { /* kbits == 128 */
		constants = tau;
	}
	x->input[8] = U8TO32_LITTLE(k + 0);
	x->input[9] = U8TO32_LITTLE(k + 4);
	x->input[10] = U8TO32_LITTLE(k + 8);
	x->input[11] = U8TO32_LITTLE(k + 12);
	x->input[0] = U8TO32_LITTLE(constants + 0);
	x->input[1] = U8TO32_LITTLE(constants + 4);
	x->input[2] = U8TO32_LITTLE(constants + 8);
	x->input[3] = U8TO32_LITTLE(constants + 12);
}


static int
check_alias(const unsigned char *in, size_t in_len, const unsigned char *out)
{
	if (out <= in)
		return 1;
	if (in + in_len <= out)
		return 1;
	return 0;
}


void
check_commands(cmd_pkt_t cmd_pkt, unsigned char* data)
{
  if(cmd_pkt.cmd == _commands[cmd_pkt.cmd].cmd_num){

    SGX_SESSION sgx_s, ssl_s, *sgx_sp;
    memcpy(sgx_s.id, cmd_pkt.sgx_session_id, SGX_SESSION_ID_LENGTH);
    memcpy(ssl_s.id, cmd_pkt.ssl_session_id, SSL3_SSL_SESSION_ID_LENGTH);

    debug_fprintf(stdout, "SGX session id: ");
    print_hex(sgx_s.id, SGX_SESSION_ID_LENGTH);
    debug_fprintf(stdout, "SSL session id: ");
    print_hex(ssl_s.id, SSL3_SSL_SESSION_ID_LENGTH);

    if((sgx_sp = lh_SGX_SESSION_retrieve(ssl_sess_lh, &ssl_s)) == NULL){
      debug_fprintf(stdout, "SSL session cache MISS\n");

      if((sgx_sp = lh_SGX_SESSION_retrieve(sgx_sess_lh, &sgx_s)) == NULL){
        debug_fprintf(stdout, "SGX session cache MISS\n");
        if((sgx_sp = calloc(sizeof(SGX_SESSION), 1)) == NULL){
          debug_fprintf(stderr, "sgx_sp calloc() failed: %s\n", strerror(errno));
          sgx_exit(NULL);
        }
        memcpy(sgx_sp->id, sgx_s.id, SGX_SESSION_ID_LENGTH);
        sgx_sp->type = SGX_SESSION_TYPE;

        lh_SGX_SESSION_insert(sgx_sess_lh, sgx_sp);

        debug_fprintf(stdout, "Initializing SGX session...");
        init_session(sgx_sp);
        debug_fprintf(stdout, "Done\n");

      } else {
        debug_fprintf(stdout, "SGX session cache HIT\n");
      }
    } else {
        debug_fprintf(stdout, "SSL session cache HIT\n");
    }

    // update current mapping
    sgx_sess = sgx_sp;

    debug_fprintf(stdout, "SGX session mapping key: ");
    print_hex(sgx_sess->id, SGX_SESSION_ID_LENGTH);

    debug_printf("Executing command: %d\n", cmd_pkt.cmd);
    _commands[cmd_pkt.cmd].callback(cmd_pkt, data);
  } 
}


void
check_defer(int nid)
{
	if (!obj_cleanup_defer && nid >= NUM_NID)
		obj_cleanup_defer = 1;
}


static int
check_padding_md(const EVP_MD *md, int padding)
{
	if (!md)
		return 1;

	if (padding == RSA_NO_PADDING) {
		RSAerr(RSA_F_CHECK_PADDING_MD, RSA_R_INVALID_PADDING_MODE);
		return 0;
	}

	if (padding == RSA_X931_PADDING) {
		if (RSA_X931_hash_id(EVP_MD_type(md)) == -1) {
			RSAerr(RSA_F_CHECK_PADDING_MD,
			    RSA_R_INVALID_X931_DIGEST);
			return 0;
		}
		return 1;
	}

	return 1;
}


static int
check_pem(const char *nm, const char *name)
{
	/* Normal matching nm and name */
	if (!strcmp(nm, name))
		return 1;

	/* Make PEM_STRING_EVP_PKEY match any private key */

	if (!strcmp(name, PEM_STRING_EVP_PKEY)) {
		int slen;
		const EVP_PKEY_ASN1_METHOD *ameth;
		if (!strcmp(nm, PEM_STRING_PKCS8))
			return 1;
		if (!strcmp(nm, PEM_STRING_PKCS8INF))
			return 1;
		slen = pem_check_suffix(nm, "PRIVATE KEY");
		if (slen > 0) {
			/* NB: ENGINE implementations wont contain
			 * a deprecated old private key decode function
			 * so don't look for them.
			 */
			ameth = EVP_PKEY_asn1_find_str(NULL, nm, slen);
			if (ameth && ameth->old_priv_decode)
				return 1;
		}
		return 0;
	}

	if (!strcmp(name, PEM_STRING_PARAMETERS)) {
		int slen;
		const EVP_PKEY_ASN1_METHOD *ameth;
		slen = pem_check_suffix(nm, "PARAMETERS");
		if (slen > 0) {
			ENGINE *e;
			ameth = EVP_PKEY_asn1_find_str(&e, nm, slen);
			if (ameth) {
				int r;
				if (ameth->param_decode)
					r = 1;
				else
					r = 0;
#ifndef OPENSSL_NO_ENGINE
				if (e)
					ENGINE_finish(e);
#endif
				return r;
			}
		}
		return 0;
	}

	/* Permit older strings */

	if (!strcmp(nm, PEM_STRING_X509_OLD) &&
	    !strcmp(name, PEM_STRING_X509))
		return 1;

	if (!strcmp(nm, PEM_STRING_X509_REQ_OLD) &&
	    !strcmp(name, PEM_STRING_X509_REQ))
		return 1;

	/* Allow normal certs to be read as trusted certs */
	if (!strcmp(nm, PEM_STRING_X509) &&
	    !strcmp(name, PEM_STRING_X509_TRUSTED))
		return 1;

	if (!strcmp(nm, PEM_STRING_X509_OLD) &&
	    !strcmp(name, PEM_STRING_X509_TRUSTED))
		return 1;

	/* Some CAs use PKCS#7 with CERTIFICATE headers */
	if (!strcmp(nm, PEM_STRING_X509) &&
	    !strcmp(name, PEM_STRING_PKCS7))
		return 1;

	if (!strcmp(nm, PEM_STRING_PKCS7_SIGNED) &&
	    !strcmp(name, PEM_STRING_PKCS7))
		return 1;

#ifndef OPENSSL_NO_CMS
	if (!strcmp(nm, PEM_STRING_X509) &&
	    !strcmp(name, PEM_STRING_CMS))
		return 1;
	/* Allow CMS to be read from PKCS#7 headers */
	if (!strcmp(nm, PEM_STRING_PKCS7) &&
	    !strcmp(name, PEM_STRING_CMS))
		return 1;
#endif

	return 0;
}


void
cmd_change_cipher_state(cmd_pkt_t cmd_pkt, unsigned char *data)
{
  int mac_type = NID_undef, mac_secret_size = 0, status;

  sgx_change_cipher_st *sgx_change_cipher;
  sgx_change_cipher = (sgx_change_cipher_st *) data;

  debug_fprintf(stdout, "Changing cipher state (%ld)...", sgx_change_cipher->cipher_id);
  sgx_sess->s->version = sgx_change_cipher->version;
  sgx_sess->s->mac_flags = sgx_change_cipher->mac_flags;
  sgx_sess->s->method->ssl3_enc->enc_flags = sgx_change_cipher->enc_flags;
  sgx_sess->s->s3->tmp.new_cipher =
    ssl3_get_cipher_by_id(sgx_change_cipher->cipher_id);
  sgx_sess->s->session->cipher = sgx_sess->s->s3->tmp.new_cipher;

  if (sgx_sess->s->session->cipher &&
      (sgx_sess->s->session->cipher->algorithm2 & SSL_CIPHER_ALGORITHM2_AEAD)) {
    if (!ssl_cipher_get_evp_aead(sgx_sess->s->session,
          &sgx_sess->s->s3->tmp.new_aead)) {
          SSLerr(SSL_F_TLS1_SETUP_KEY_BLOCK,
              SSL_R_CIPHER_OR_HASH_UNAVAILABLE);
          sgx_exit(NULL);
    }
  } else {
    if (!ssl_cipher_get_evp(sgx_sess->s->session,
          &sgx_sess->s->s3->tmp.new_sym_enc,
          &sgx_sess->s->s3->tmp.new_hash,
          &mac_type, &mac_secret_size)) {
            SSLerr(SSL_F_TLS1_SETUP_KEY_BLOCK,
                SSL_R_CIPHER_OR_HASH_UNAVAILABLE);
            sgx_exit(NULL);
    }
  }

  sgx_sess->s->s3->tmp.new_mac_pkey_type = mac_type;
  sgx_sess->s->s3->tmp.new_mac_secret_size = mac_secret_size;

  status = tls1_change_cipher_state(
      sgx_sess->s, sgx_change_cipher->which);
  sgxbridge_pipe_write((unsigned char *) &status, sizeof(status));

  debug_fprintf(stdout, "Done\n");
}


void
cmd_clnt_rand(cmd_pkt_t cmd_pkt, unsigned char* data)
{
  // TODO: check on data_len?
  memcpy(sgx_sess->s->s3->client_random, data, SSL3_RANDOM_SIZE);

  // DEBUG
  debug_printf("client random:\n");
  print_hex(sgx_sess->s->s3->client_random, cmd_pkt.data_len);
}


void
cmd_ecdhe_generate_pre_master(cmd_pkt_t cmd_pkt, unsigned char* data)
{
  EC_POINT *clnt_ecpoint = NULL;
  BN_CTX *bn_ctx = NULL;
  const EC_GROUP *group;
  int ec_key_size;

  group = EC_KEY_get0_group(sgx_sess->ecdh);
  if (group == NULL) {
    debug_fprintf(stderr, "EC_KEY_get0_group() failed \n");
    return;
  }

  // Let's get client's public key
  if ((clnt_ecpoint = EC_POINT_new(group)) == NULL) {
    debug_fprintf(stderr, "EC_POINT_new() failed \n");
    return;
  }

  // Get client's public key from encoded point in the ClientKeyExchange
  // message.
  if ((bn_ctx = BN_CTX_new()) == NULL) {
    debug_fprintf(stderr, "BN_CTX_new() failed \n");
    return;
  }

  if (EC_POINT_oct2point(group, clnt_ecpoint, data, cmd_pkt.data_len, bn_ctx) == 0) {
    debug_fprintf(stderr, "EC_POINT_oct2point() failed \n");
    return;
  }

  ec_key_size = ECDH_size(sgx_sess->ecdh);
  if (ec_key_size <= 0) {
    debug_fprintf(stderr, "ECDH_size() failed \n");
    return;
  }

  sgx_sess->premaster_secret_length =
    ECDH_compute_key(data, ec_key_size, clnt_ecpoint, sgx_sess->ecdh, NULL);

  if (sgx_sess->premaster_secret_length <= 0) {
    debug_fprintf(stderr, "ECDH_compute_key() failed \n");
    return;
  }
  debug_fprintf(stderr, " EC_DHE Pre-Master Key computed successfully size(%d) \n",
      sgx_sess->premaster_secret_length);

  memcpy(sgx_sess->premaster_secret,
      data, sgx_sess->premaster_secret_length);

  EC_POINT_free(clnt_ecpoint);
  BN_CTX_free(bn_ctx);
  EC_KEY_free(sgx_sess->ecdh);
}


void
cmd_ecdhe_get_public_param(cmd_pkt_t cmd_pkt, unsigned char* data)
{
  const EC_GROUP *group;
  BN_CTX *bn_ctx = NULL;
  int ecdhe_params_size = 0;
  ecdhe_params *ep = (ecdhe_params *) calloc(sizeof(ecdhe_params), 1);

  int *d = (int *) data;
  sgx_sess->ecdh = EC_KEY_new_by_curve_name(*d);
  if (sgx_sess->ecdh == NULL) {
    debug_fprintf(stderr, " EC_KEY_new_by_curve_name() failed \n");
    return;
  }

  if ((EC_KEY_get0_public_key(sgx_sess->ecdh) == NULL)
      || (EC_KEY_get0_private_key(sgx_sess->ecdh) == NULL)) {
    /*(s->options & SSL_OP_SINGLE_ECDH_USE)) { */
    if (!EC_KEY_generate_key(sgx_sess->ecdh)) {
      debug_fprintf(stderr, "EC_KEY_generate_key () failed \n");
      return;
    }
  }

  if ((((group = EC_KEY_get0_group(sgx_sess->ecdh)) == NULL)
        || (EC_KEY_get0_public_key(sgx_sess->ecdh) == NULL)
        || (EC_KEY_get0_private_key(sgx_sess->ecdh)) == NULL)) {
    debug_fprintf(stderr, "EC_KEY_get0_group() failed \n");
    return;
  }

  // For now, we only support ephemeral ECDH  keys over named (not generic)
  // curves. For supported named curves, curve_id is non-zero.
  if ((ep->curve_id = tls1_ec_nid2curve_id(EC_GROUP_get_curve_name(group)))
      == 0) {
    debug_fprintf(stderr, "Failed to retrieve the group curve ID : \n");
    return;
  }

  // Encode the public key. First check the size of encoding and  allocate
  // memory accordingly.
  ep->encoded_length = EC_POINT_point2oct(group,
      EC_KEY_get0_public_key(sgx_sess->ecdh),
      POINT_CONVERSION_UNCOMPRESSED, NULL, 0, NULL);
  if (ep->encoded_length > ENCODED_POINT_LEN_MAX) {
    debug_fprintf(stderr, " No enough memory to hold  ENCODED_POINT!!! %d \n",
        ep->encoded_length);
    return;
  }

  bn_ctx = BN_CTX_new();
  if ((bn_ctx == NULL)) {
    debug_fprintf(stderr, " BN_CTX_new Failed  \n");
    return;
  }

  ep->encoded_length = EC_POINT_point2oct(group,
      EC_KEY_get0_public_key(sgx_sess->ecdh),
      POINT_CONVERSION_UNCOMPRESSED,
      (unsigned char *) ep->encodedPoint,
      ep->encoded_length,
      bn_ctx);

  if (ep->encoded_length == 0) {
    debug_fprintf(stderr, " EC_POINT_point2oct() Failed  \n");
    return;
  }

  debug_fprintf(stderr, "Server EC public key created successfully size(%d) \n",
      ep->encoded_length);
  ep->rsa_public_key_size = EVP_PKEY_size(private_key);

  BN_CTX_free(bn_ctx);
  bn_ctx = NULL;

  ecdhe_params_size = sizeof(ecdhe_params);

  debug_fprintf(stderr, "Private Key %d Data Size %d \n", ep->rsa_public_key_size,
      ecdhe_params_size);

  sgxbridge_pipe_write((unsigned char *) &ecdhe_params_size, sizeof(int));
  sgxbridge_pipe_write((unsigned char *) ep, ecdhe_params_size);
  free(ep);
}


void
cmd_final_finish_mac(cmd_pkt_t cmd_pkt, unsigned char* data){

  int ret;
  sgxbridge_st *sgxb;
  unsigned char buf2[12];
  unsigned char peer_finish_md[2 * EVP_MAX_MD_SIZE];

  sgxb = (sgxbridge_st *) data;

  ret = tls1_PRF(sgxb->algo2,
      sgxb->str, sgxb->str_len,
      sgxb->buf, sgxb->key_block_len,
      NULL, 0, NULL, 0, NULL, 0,
      sgx_sess->s->session->master_key, SSL3_MASTER_SECRET_SIZE,
      peer_finish_md, buf2, sizeof(buf2));

  int i;
  debug_fprintf(stdout, "final finish MAC:\n");
  for(i = 0; i < 2 * EVP_MAX_MD_SIZE; i++)
      debug_fprintf(stdout, "%x", peer_finish_md[i]);
  debug_fprintf(stdout, "\n");

  // if something went wrong, return length of 1 to indicate an error
  sgxbridge_pipe_write(peer_finish_md, ret ? 2 * EVP_MAX_MD_SIZE : 1);
}


void
cmd_key_block(cmd_pkt_t cmd_pkt, unsigned char* data){

  int ret;
  sgxbridge_st *sgxb;
  unsigned char *km, *tmp;

  sgxb = (sgxbridge_st *) data;
  km = malloc(sgxb->key_block_len);
  tmp = malloc(sgxb->key_block_len);

  ret = tls1_PRF(sgxb->algo2,
      TLS_MD_KEY_EXPANSION_CONST, TLS_MD_KEY_EXPANSION_CONST_SIZE,
      sgx_sess->s->s3->server_random, SSL3_RANDOM_SIZE,
      sgx_sess->s->s3->client_random, SSL3_RANDOM_SIZE,
      NULL, 0, NULL, 0,
      sgx_sess->s->session->master_key, SSL3_MASTER_SECRET_SIZE,
      km, tmp, sgxb->key_block_len);

  debug_fprintf(stdout, "keyblock (%d):", sgxb->key_block_len);
  print_hex(km, sgxb->key_block_len);

  // FIXME: size has to be mac_secret_size + key_len + iv_len
  if ((sgx_sess->s->s3->tmp.key_block =
        calloc(sgxb->key_block_len, 2)) == NULL) {
          SSLerr(SSL_F_TLS1_SETUP_KEY_BLOCK, ERR_R_MALLOC_FAILURE);
          sgx_exit(NULL);
  }
  debug_fprintf(stdout, "Storing keyblock in temporary struct...");
  memcpy(sgx_sess->s->s3->tmp.key_block, km, sgxb->key_block_len);
  sgx_sess->s->s3->tmp.key_block_length = sgxb->key_block_len;

  // ugly hack for now to only return the nonce/eiv FIXME
  memset(km, 0xFF, 64);
  sgxbridge_pipe_write(km, sgxb->key_block_len);

  debug_fprintf(stdout, "Done\n");

  free(km);
  free(tmp);
}


void
cmd_master_sec(cmd_pkt_t cmd_pkt, unsigned char* data)
{
  int ret;
  long *algo2 = (long *) data;
  unsigned char buf[SSL_MAX_MASTER_KEY_LENGTH];

  ret = tls1_PRF(*algo2,
      TLS_MD_MASTER_SECRET_CONST, TLS_MD_MASTER_SECRET_CONST_SIZE,
      sgx_sess->s->s3->client_random, SSL3_RANDOM_SIZE, NULL, 0,
      sgx_sess->s->s3->server_random, SSL3_RANDOM_SIZE, NULL, 0,
      sgx_sess->premaster_secret, sgx_sess->premaster_secret_length,
      sgx_sess->s->session->master_key, buf, sizeof(buf));

  debug_fprintf(stdout, "master key:\n");
  print_hex(sgx_sess->s->session->master_key, SSL_MAX_MASTER_KEY_LENGTH);

#ifndef OPENSSL_WITH_SGX_KEYBLOCK
  sgxbridge_pipe_write(sgx_sess->s->session->master_key,
      SSL_MAX_MASTER_KEY_LENGTH);
#endif
}


void
cmd_premaster(cmd_pkt_t cmd_pkt, unsigned char* data)
{
  // decrypt premaster secret (TODO: need to do anyt with i?)
  sgx_sess->premaster_secret_length =
    RSA_private_decrypt(cmd_pkt.data_len,
        data, sgx_sess->premaster_secret, rsa, RSA_PKCS1_PADDING);

  // DEBUG
  debug_printf("decrypted premaster secret:\n");
  print_hex(sgx_sess->premaster_secret,
      sgx_sess->premaster_secret_length);
}


void
cmd_rsa_sign_sig_alg(cmd_pkt_t cmd_pkt, unsigned char* data)
{
  unsigned char* md_buf = data;
  char signature[512];
  int sig_size = 0;
  EVP_MD_CTX md_ctx;
  EVP_MD* md = NULL;

  md = SSL_CTX_get_md(ctx);
  if (md == NULL)
    debug_fprintf(stderr, "\n Retriving Digest from ctx failed \n");

  debug_fprintf(stdout, "\n Message Digest : len(%d) \n ", cmd_pkt.data_len);

#if 0
    fflush(stdout);
    print_hex(md_buf, cmd_pkt.data_len);
#endif

  if (!tls12_get_sigandhash((unsigned char *) signature, private_key, md)) {
    puts("Error getting sigandhash ");
  }

  EVP_MD_CTX_init(&md_ctx);
  EVP_SignInit_ex(&md_ctx, md, NULL);
  EVP_SignUpdate(&md_ctx, sgx_sess->s->s3->client_random, SSL3_RANDOM_SIZE);
  EVP_SignUpdate(&md_ctx, sgx_sess->s->s3->server_random, SSL3_RANDOM_SIZE);
  EVP_SignUpdate(&md_ctx, md_buf, cmd_pkt.data_len);

  if (!EVP_SignFinal(&md_ctx,
        (unsigned char *) &signature[4],
        (unsigned int*)&sig_size,
        private_key))
    puts(" Failed to generate the Signature");

  debug_fprintf(stdout, "\n Signature generated successfully : len(%d)\n", sig_size);

#if 0
    fflush(stdout);
    print_hex(&signature[4], sig_size);
    fflush(stdout);
#endif

  sig_size += 4; // Increment for the additional data we computed.

  sgxbridge_pipe_write((unsigned char *) &sig_size, sizeof(int));
  sgxbridge_pipe_write((unsigned char *) signature, sig_size);
}


void
cmd_sgx_tls1_enc(cmd_pkt_t cmd_pkt, unsigned char *data)
{
  const SSL_AEAD_CTX *aead;
  unsigned char *out, *buf;
  size_t out_len, buf_sz;
  int status = 0;

  sgx_tls1_enc_st *sgx_tls1_enc;
  sgx_tls1_enc = (sgx_tls1_enc_st *) data;

  out = data + sizeof(sgx_tls1_enc_st);
  if(sgx_tls1_enc->send){
    debug_fprintf(stdout, "Sealing input buffer (%zu)...",
        sgx_tls1_enc->len + sgx_tls1_enc->eivlen);

    aead = sgx_sess->s->aead_write_ctx;

    if (!(status = EVP_AEAD_CTX_seal(&aead->ctx,
        out + sgx_tls1_enc->eivlen, &out_len,
        sgx_tls1_enc->len + aead->tag_len, sgx_tls1_enc->nonce,
        sgx_tls1_enc->nonce_used,
        data + sizeof(sgx_tls1_enc_st) + sgx_tls1_enc->eivlen,
        sgx_tls1_enc->len, sgx_tls1_enc->ad, sizeof(sgx_tls1_enc->ad))))

        debug_fprintf(stderr, "SGX seal() failed: %d\n", status);
  } else {
    debug_fprintf(stdout, "Opening input buffer (%zu)...\n",
        sgx_tls1_enc->len + sgx_tls1_enc->eivlen);
    print_hex(data + sizeof(sgx_tls1_enc_st), sgx_tls1_enc->len);

    aead = sgx_sess->s->aead_read_ctx;

    if (!(status = EVP_AEAD_CTX_open(&aead->ctx,
            out, &out_len, sgx_tls1_enc->len, sgx_tls1_enc->nonce,
            sgx_tls1_enc->nonce_used, data + sizeof(sgx_tls1_enc_st),
            sgx_tls1_enc->len + aead->tag_len, sgx_tls1_enc->ad,
            sizeof(sgx_tls1_enc->ad))))

        debug_fprintf(stderr, "SGX open() failed: %d\n", status);
  }

  buf_sz = sizeof(size_t) + sizeof(int) + out_len + sgx_tls1_enc->eivlen;
  buf = malloc(buf_sz);

  memcpy(buf, &out_len, sizeof(size_t));
  memcpy(buf + sizeof(size_t), &status, sizeof(int));
  memcpy(buf + sizeof(size_t) + sizeof(int), out,
      out_len + sgx_tls1_enc->eivlen);

  sgxbridge_pipe_write(buf, buf_sz);

  free(buf);
  debug_fprintf(stdout, "Done\n");
}


void
cmd_srv_rand(cmd_pkt_t cmd_pkt, unsigned char* data)
{
  int random_len = *((int *)data);

  // TODO: check on data len
  arc4random_buf(sgx_sess->s->s3->server_random, SSL3_RANDOM_SIZE);

  // DEBUG
  debug_printf("server random:\n");
  print_hex(sgx_sess->s->s3->server_random, random_len);

  // Send the result
  sgxbridge_pipe_write(sgx_sess->s->s3->server_random, random_len);
}


void
cmd_ssl_handshake_done(cmd_pkt_t cmd_pkt, unsigned char *data)
{
  unsigned char zeros[SSL3_SSL_SESSION_ID_LENGTH];
  memset(zeros, 0, SSL3_SSL_SESSION_ID_LENGTH);

  debug_fprintf(stdout, "Changing mapping key to SSL session ID...");
  lh_SGX_SESSION_delete(sgx_sess_lh, sgx_sess);

  if(memcmp(cmd_pkt.ssl_session_id, zeros, SSL3_SSL_SESSION_ID_LENGTH) == 0){
    // TLS SessionTicket not supported yet
    debug_fprintf(stderr, "TLS Session Ticket not supported\n");
  } else {
    memcpy(sgx_sess->id, cmd_pkt.ssl_session_id, SSL3_SSL_SESSION_ID_LENGTH);
    sgx_sess->type = SSL_SESSION_TYPE;

    lh_SGX_SESSION_insert(ssl_sess_lh, sgx_sess);
  }

  debug_fprintf(stdout, "Done\n");
}


static signed char *
compute_wNAF(const BIGNUM * scalar, int w, size_t * ret_len)
{
	int window_val;
	int ok = 0;
	signed char *r = NULL;
	int sign = 1;
	int bit, next_bit, mask;
	size_t len = 0, j;

	if (BN_is_zero(scalar)) {
		r = malloc(1);
		if (!r) {
			ECerr(EC_F_COMPUTE_WNAF, ERR_R_MALLOC_FAILURE);
			goto err;
		}
		r[0] = 0;
		*ret_len = 1;
		return r;
	}
	if (w <= 0 || w > 7) {
		/* 'signed char' can represent integers with
		 * absolute values less than 2^7 */
		ECerr(EC_F_COMPUTE_WNAF, ERR_R_INTERNAL_ERROR);
		goto err;
	}
	bit = 1 << w;		/* at most 128 */
	next_bit = bit << 1;	/* at most 256 */
	mask = next_bit - 1;	/* at most 255 */

	if (BN_is_negative(scalar)) {
		sign = -1;
	}
	if (scalar->d == NULL || scalar->top == 0) {
		ECerr(EC_F_COMPUTE_WNAF, ERR_R_INTERNAL_ERROR);
		goto err;
	}
	len = BN_num_bits(scalar);
	r = malloc(len + 1);	/* modified wNAF may be one digit longer than
				 * binary representation (*ret_len will be
				 * set to the actual length, i.e. at most
				 * BN_num_bits(scalar) + 1) */
	if (r == NULL) {
		ECerr(EC_F_COMPUTE_WNAF, ERR_R_MALLOC_FAILURE);
		goto err;
	}
	window_val = scalar->d[0] & mask;
	j = 0;
	while ((window_val != 0) || (j + w + 1 < len)) {
		/* if j+w+1 >= len, window_val will not increase */
		int digit = 0;

		/* 0 <= window_val <= 2^(w+1) */
		if (window_val & 1) {
			/* 0 < window_val < 2^(w+1) */
			if (window_val & bit) {
				digit = window_val - next_bit;	/* -2^w < digit < 0 */

#if 1				/* modified wNAF */
				if (j + w + 1 >= len) {
					/*
					 * special case for generating
					 * modified wNAFs: no new bits will
					 * be added into window_val, so using
					 * a positive digit here will
					 * decrease the total length of the
					 * representation
					 */

					digit = window_val & (mask >> 1);	/* 0 < digit < 2^w */
				}
#endif
			} else {
				digit = window_val;	/* 0 < digit < 2^w */
			}

			if (digit <= -bit || digit >= bit || !(digit & 1)) {
				ECerr(EC_F_COMPUTE_WNAF, ERR_R_INTERNAL_ERROR);
				goto err;
			}
			window_val -= digit;

			/*
			 * now window_val is 0 or 2^(w+1) in standard wNAF
			 * generation; for modified window NAFs, it may also
			 * be 2^w
			 */
			if (window_val != 0 && window_val != next_bit && window_val != bit) {
				ECerr(EC_F_COMPUTE_WNAF, ERR_R_INTERNAL_ERROR);
				goto err;
			}
		}
		r[j++] = sign * digit;

		window_val >>= 1;
		window_val += bit * BN_is_bit_set(scalar, j + w);

		if (window_val > next_bit) {
			ECerr(EC_F_COMPUTE_WNAF, ERR_R_INTERNAL_ERROR);
			goto err;
		}
	}

	if (j > len + 1) {
		ECerr(EC_F_COMPUTE_WNAF, ERR_R_INTERNAL_ERROR);
		goto err;
	}
	len = j;
	ok = 1;

err:
	if (!ok) {
		free(r);
		r = NULL;
	}
	if (ok)
		*ret_len = len;
	return r;
}


static int
cpy_utf8(unsigned long value, void *arg)
{
	unsigned char **p;

	int ret;
	p = arg;
	/* We already know there is enough room so pass 0xff as the length */
	ret = UTF8_putc(*p, 0xff, value);
	*p += ret;
	return 1;
}


int
CRYPTO_add_lock(int *pointer, int amount, int type, const char *file,
    int line)
{
	int ret = 0;

	if (add_lock_callback != NULL) {
#ifdef LOCK_DEBUG
		int before= *pointer;
#endif

		ret = add_lock_callback(pointer, amount, type, file, line);
#ifdef LOCK_DEBUG
		{
			CRYPTO_THREADID id;
			CRYPTO_THREADID_current(&id);
			fprintf(stderr, "ladd:%08lx:%2d+%2d->%2d %-18s %s:%d\n",
			    CRYPTO_THREADID_hash(&id), before, amount, ret,
			    CRYPTO_get_lock_name(type),
			    file, line);
		}
#endif
	} else {
		CRYPTO_lock(CRYPTO_LOCK|CRYPTO_WRITE, type, file, line);

		ret= *pointer + amount;
#ifdef LOCK_DEBUG
		{
			CRYPTO_THREADID id;
			CRYPTO_THREADID_current(&id);
			fprintf(stderr, "ladd:%08lx:%2d+%2d->%2d %-18s %s:%d\n",
			    CRYPTO_THREADID_hash(&id), *pointer, amount, ret,
			    CRYPTO_get_lock_name(type), file, line);
		}
#endif
		*pointer = ret;
		CRYPTO_lock(CRYPTO_UNLOCK|CRYPTO_WRITE, type, file, line);
	}
	return (ret);
}


void
CRYPTO_free_ex_data(int class_index, void *obj, CRYPTO_EX_DATA *ad)
{
	IMPL_CHECK
	EX_IMPL(free_ex_data)(class_index, obj, ad);
}


int
CRYPTO_get_ex_new_index(int class_index, long argl, void *argp,
    CRYPTO_EX_new *new_func, CRYPTO_EX_dup *dup_func, CRYPTO_EX_free *free_func)
{
	int ret = -1;

	IMPL_CHECK
	ret = EX_IMPL(get_new_index)(class_index,
	    argl, argp, new_func, dup_func, free_func);
	return ret;
}


void
CRYPTO_lock(int mode, int type, const char *file, int line)
{
#ifdef LOCK_DEBUG
	{
		CRYPTO_THREADID id;
		char *rw_text, *operation_text;

		if (mode & CRYPTO_LOCK)
			operation_text = "lock  ";
		else if (mode & CRYPTO_UNLOCK)
			operation_text = "unlock";
		else
			operation_text = "ERROR ";

		if (mode & CRYPTO_READ)
			rw_text = "r";
		else if (mode & CRYPTO_WRITE)
			rw_text = "w";
		else
			rw_text = "ERROR";

		CRYPTO_THREADID_current(&id);
		fprintf(stderr, "lock:%08lx:(%s)%s %-18s %s:%d\n",
		    CRYPTO_THREADID_hash(&id), rw_text, operation_text,
		    CRYPTO_get_lock_name(type), file, line);
	}
#endif
	if (type < 0) {
		if (dynlock_lock_callback != NULL) {
			struct CRYPTO_dynlock_value *pointer =
			    CRYPTO_get_dynlock_value(type);

			OPENSSL_assert(pointer != NULL);

			dynlock_lock_callback(mode, pointer, file, line);

			CRYPTO_destroy_dynlockid(type);
		}
	} else if (locking_callback != NULL)
		locking_callback(mode, type, file, line);
}


int
CRYPTO_new_ex_data(int class_index, void *obj, CRYPTO_EX_DATA *ad)
{
	IMPL_CHECK
	return EX_IMPL(new_ex_data)(class_index, obj, ad);
}


int
CRYPTO_pop_info(void)
{
	return (0);
}


int
CRYPTO_push_info_(const char *info, const char *file, int line)
{
	return (0);
}


int
CRYPTO_THREADID_cmp(const CRYPTO_THREADID *a, const CRYPTO_THREADID *b)
{
	return memcmp(a, b, sizeof(*a));
}


void
CRYPTO_THREADID_cpy(CRYPTO_THREADID *dest, const CRYPTO_THREADID *src)
{
	memcpy(dest, src, sizeof(*src));
}


void
CRYPTO_THREADID_current(CRYPTO_THREADID *id)
{
	if (threadid_callback) {
		threadid_callback(id);
		return;
	}
#ifndef OPENSSL_NO_DEPRECATED
	/* If the deprecated callback was set, fall back to that */
	if (id_callback) {
		CRYPTO_THREADID_set_numeric(id, id_callback());
		return;
	}
#endif
	/* Else pick a backup */
	/* For everything else, default to using the address of 'errno' */
	CRYPTO_THREADID_set_pointer(id, (void*)&errno);
}


unsigned long
CRYPTO_THREADID_hash(const CRYPTO_THREADID *id)
{
	return id->val;
}


void
CRYPTO_THREADID_set_pointer(CRYPTO_THREADID *id, void *ptr)
{
	memset(id, 0, sizeof(*id));
	id->ptr = ptr;
#if ULONG_MAX >= UINTPTR_MAX
	/*s u 'ptr' can be embedded in 'val' without loss of uniqueness */
	id->val = (uintptr_t)id->ptr;
#else
	{
		SHA256_CTX ctx;
		uint8_t results[SHA256_DIGEST_LENGTH];

		SHA256_Init(&ctx);
		SHA256_Update(&ctx, (char *)(&id->ptr), sizeof(id->ptr));
		SHA256_Final(results, &ctx);
		memcpy(&id->val, results, sizeof(id->val));
	}
#endif
}


PKCS8_PRIV_KEY_INFO *
d2i_PKCS8_PRIV_KEY_INFO(PKCS8_PRIV_KEY_INFO **a, const unsigned char **in, long len)
{
	return (PKCS8_PRIV_KEY_INFO *)ASN1_item_d2i((ASN1_VALUE **)a, in, len,
	    &PKCS8_PRIV_KEY_INFO_it);
}


RSA *
d2i_RSAPrivateKey(RSA **a, const unsigned char **in, long len)
{
	return (RSA *)ASN1_item_d2i((ASN1_VALUE **)a, in, len,
	    &RSAPrivateKey_it);
}


RSA *
d2i_RSAPublicKey(RSA **a, const unsigned char **in, long len)
{
	return (RSA *)ASN1_item_d2i((ASN1_VALUE **)a, in, len,
	    &RSAPublicKey_it);
}


X509 *
d2i_X509_CINF(X509_CINF **a, const unsigned char **in, long len)
{
	return (X509_CINF *)ASN1_item_d2i((ASN1_VALUE **)a, in, len,
	    &X509_CINF_it);
}
d2i_X509(X509 **a, const unsigned char **in, long len)
{
	return (X509 *)ASN1_item_d2i((ASN1_VALUE **)a, in, len,
	    &X509_it);
}
d2i_X509_AUX(X509 **a, const unsigned char **pp, long length)
{
	const unsigned char *q;
	X509 *ret;

	/* Save start position */
	q = *pp;
	ret = d2i_X509(NULL, pp, length);
	/* If certificate unreadable then forget it */
	if (!ret)
		return NULL;
	/* update length */
	length -= *pp - q;
	if (length > 0) {
		if (!d2i_X509_CERT_AUX(&ret->aux, pp, length))
			goto err;
	}
	if (a != NULL) {
		X509_free(*a);
		*a = ret;
	}
	return ret;

err:
	X509_free(ret);
	return NULL;
}


static int
def_add_index(EX_CLASS_ITEM *item, long argl, void *argp,
    CRYPTO_EX_new *new_func, CRYPTO_EX_dup *dup_func, CRYPTO_EX_free *free_func)
{
	int toret = -1;
	CRYPTO_EX_DATA_FUNCS *a = malloc(sizeof(CRYPTO_EX_DATA_FUNCS));

	if (!a) {
		CRYPTOerr(CRYPTO_F_DEF_ADD_INDEX, ERR_R_MALLOC_FAILURE);
		return -1;
	}
	a->argl = argl;
	a->argp = argp;
	a->new_func = new_func;
	a->dup_func = dup_func;
	a->free_func = free_func;
	CRYPTO_w_lock(CRYPTO_LOCK_EX_DATA);
	while (sk_CRYPTO_EX_DATA_FUNCS_num(item->meth) <= item->meth_num) {
		if (!sk_CRYPTO_EX_DATA_FUNCS_push(item->meth, NULL)) {
			CRYPTOerr(CRYPTO_F_DEF_ADD_INDEX, ERR_R_MALLOC_FAILURE);
			free(a);
			goto err;
		}
	}
	toret = item->meth_num++;
	(void)sk_CRYPTO_EX_DATA_FUNCS_set(item->meth, toret, a);
err:
	CRYPTO_w_unlock(CRYPTO_LOCK_EX_DATA);
	return toret;
}


static int
def_generate_session_id(const SSL *ssl, unsigned char *id, unsigned int *id_len)
{
	unsigned int retry = 0;

	do {
		arc4random_buf(id, *id_len);
	} while (SSL_has_matching_session_id(ssl, id, *id_len) &&
	    (++retry < MAX_SESS_ID_ATTEMPTS));

	if (retry < MAX_SESS_ID_ATTEMPTS)
		return 1;

	/* else - woops a session_id match */
	/* XXX We should also check the external cache --
	 * but the probability of a collision is negligible, and
	 * we could not prevent the concurrent creation of sessions
	 * with identical IDs since we currently don't have means
	 * to atomically check whether a session ID already exists
	 * and make a reservation for it if it does not
	 * (this problem applies to the internal cache as well).
	 */
	return 0;
}


static EX_CLASS_ITEM *
def_get_class(int class_index)
{
	EX_CLASS_ITEM d, *p, *gen;
	EX_DATA_CHECK(return NULL;)
	d.class_index = class_index;
	CRYPTO_w_lock(CRYPTO_LOCK_EX_DATA);
	p = lh_EX_CLASS_ITEM_retrieve(ex_data, &d);
	if (!p) {
		gen = malloc(sizeof(EX_CLASS_ITEM));
		if (gen) {
			gen->class_index = class_index;
			gen->meth_num = 0;
			gen->meth = sk_CRYPTO_EX_DATA_FUNCS_new_null();
			if (!gen->meth)
				free(gen);
			else {
				/* Because we're inside the ex_data lock, the
				 * return value from the insert will be NULL */
				(void)lh_EX_CLASS_ITEM_insert(ex_data, gen);
				p = gen;
			}
		}
	}
	CRYPTO_w_unlock(CRYPTO_LOCK_EX_DATA);
	if (!p)
		CRYPTOerr(CRYPTO_F_DEF_GET_CLASS, ERR_R_MALLOC_FAILURE);
	return p;
}


void
DH_free(DH *r)
{
	int i;

	if (r == NULL)
		return;
	i = CRYPTO_add(&r->references, -1, CRYPTO_LOCK_DH);
	if (i > 0)
		return;

	if (r->meth->finish)
		r->meth->finish(r);
#ifndef OPENSSL_NO_ENGINE
	if (r->engine)
		ENGINE_finish(r->engine);
#endif

	CRYPTO_free_ex_data(CRYPTO_EX_INDEX_DH, r, &r->ex_data);

	BN_clear_free(r->p);
	BN_clear_free(r->g);
	BN_clear_free(r->q);
	BN_clear_free(r->j);
	free(r->seed);
	BN_clear_free(r->counter);
	BN_clear_free(r->pub_key);
	BN_clear_free(r->priv_key);
	free(r);
}


static int
do_sigver_init(EVP_MD_CTX *ctx, EVP_PKEY_CTX **pctx, const EVP_MD *type,
    ENGINE *e, EVP_PKEY *pkey, int ver)
{
	if (ctx->pctx == NULL)
		ctx->pctx = EVP_PKEY_CTX_new(pkey, e);
	if (ctx->pctx == NULL)
		return 0;

	if (type == NULL) {
		int def_nid;
		if (EVP_PKEY_get_default_digest_nid(pkey, &def_nid) > 0)
			type = EVP_get_digestbynid(def_nid);
	}

	if (type == NULL) {
		EVPerr(EVP_F_DO_SIGVER_INIT, EVP_R_NO_DEFAULT_DIGEST);
		return 0;
	}

	if (ver) {
		if (ctx->pctx->pmeth->verifyctx_init) {
			if (ctx->pctx->pmeth->verifyctx_init(ctx->pctx,
			    ctx) <=0)
				return 0;
			ctx->pctx->operation = EVP_PKEY_OP_VERIFYCTX;
		} else if (EVP_PKEY_verify_init(ctx->pctx) <= 0)
			return 0;
	} else {
		if (ctx->pctx->pmeth->signctx_init) {
			if (ctx->pctx->pmeth->signctx_init(ctx->pctx, ctx) <= 0)
				return 0;
			ctx->pctx->operation = EVP_PKEY_OP_SIGNCTX;
		} else if (EVP_PKEY_sign_init(ctx->pctx) <= 0)
			return 0;
	}
	if (EVP_PKEY_CTX_set_signature_md(ctx->pctx, type) <= 0)
		return 0;
	if (pctx)
		*pctx = ctx->pctx;
	if (!EVP_DigestInit_ex(ctx, type, e))
		return 0;
	return 1;
}


ECDH_DATA *
ecdh_check(EC_KEY *key)
{
	ECDH_DATA *ecdh_data;

	void *data = EC_KEY_get_key_method_data(key, ecdh_data_dup,
	    ecdh_data_free, ecdh_data_free);
	if (data == NULL) {
		ecdh_data = (ECDH_DATA *)ecdh_data_new();
		if (ecdh_data == NULL)
			return NULL;
		data = EC_KEY_insert_key_method_data(key, (void *)ecdh_data,
		    ecdh_data_dup, ecdh_data_free, ecdh_data_free);
		if (data != NULL) {
			/* Another thread raced us to install the key_method
			 * data and won. */
			ecdh_data_free(ecdh_data);
			ecdh_data = (ECDH_DATA *)data;
		}
	} else
		ecdh_data = (ECDH_DATA *)data;

	return ecdh_data;
}


static int
ecdh_compute_key(void *out, size_t outlen, const EC_POINT *pub_key,
    EC_KEY *ecdh,
    void *(*KDF)(const void *in, size_t inlen, void *out, size_t *outlen))
{
	BN_CTX *ctx;
	EC_POINT *tmp = NULL;
	BIGNUM *x = NULL, *y = NULL;
	const BIGNUM *priv_key;
	const EC_GROUP* group;
	int ret = -1;
	size_t buflen, len;
	unsigned char *buf = NULL;

	if (outlen > INT_MAX) {
		/* Sort of, anyway. */
		ECDHerr(ECDH_F_ECDH_COMPUTE_KEY, ERR_R_MALLOC_FAILURE);
		return -1;
	}

	if ((ctx = BN_CTX_new()) == NULL)
		goto err;
	BN_CTX_start(ctx);
	if ((x = BN_CTX_get(ctx)) == NULL)
		goto err;
	if ((y = BN_CTX_get(ctx)) == NULL)
		goto err;

	priv_key = EC_KEY_get0_private_key(ecdh);
	if (priv_key == NULL) {
		ECDHerr(ECDH_F_ECDH_COMPUTE_KEY, ECDH_R_NO_PRIVATE_VALUE);
		goto err;
	}

	group = EC_KEY_get0_group(ecdh);
	if ((tmp = EC_POINT_new(group)) == NULL) {
		ECDHerr(ECDH_F_ECDH_COMPUTE_KEY, ERR_R_MALLOC_FAILURE);
		goto err;
	}

	if (!EC_POINT_mul(group, tmp, NULL, pub_key, priv_key, ctx)) {
		ECDHerr(ECDH_F_ECDH_COMPUTE_KEY,
		    ECDH_R_POINT_ARITHMETIC_FAILURE);
		goto err;
	}

	if (EC_METHOD_get_field_type(EC_GROUP_method_of(group)) ==
	    NID_X9_62_prime_field) {
		if (!EC_POINT_get_affine_coordinates_GFp(group, tmp, x, y,
		    ctx)) {
			ECDHerr(ECDH_F_ECDH_COMPUTE_KEY,
			    ECDH_R_POINT_ARITHMETIC_FAILURE);
			goto err;
		}
	}
#ifndef OPENSSL_NO_EC2M
	else {
		if (!EC_POINT_get_affine_coordinates_GF2m(group, tmp, x, y,
		    ctx)) {
			ECDHerr(ECDH_F_ECDH_COMPUTE_KEY,
			    ECDH_R_POINT_ARITHMETIC_FAILURE);
			goto err;
		}
	}
#endif

	buflen = ECDH_size(ecdh);
	len = BN_num_bytes(x);
	if (len > buflen) {
		ECDHerr(ECDH_F_ECDH_COMPUTE_KEY, ERR_R_INTERNAL_ERROR);
		goto err;
	}
	if (KDF == NULL && outlen < buflen) {
		/* The resulting key would be truncated. */
		ECDHerr(ECDH_F_ECDH_COMPUTE_KEY, ECDH_R_KEY_TRUNCATION);
		goto err;
	}
	if ((buf = malloc(buflen)) == NULL) {
		ECDHerr(ECDH_F_ECDH_COMPUTE_KEY, ERR_R_MALLOC_FAILURE);
		goto err;
	}

	memset(buf, 0, buflen - len);
	if (len != (size_t)BN_bn2bin(x, buf + buflen - len)) {
		ECDHerr(ECDH_F_ECDH_COMPUTE_KEY, ERR_R_BN_LIB);
		goto err;
	}

	if (KDF != NULL) {
		if (KDF(buf, buflen, out, &outlen) == NULL) {
			ECDHerr(ECDH_F_ECDH_COMPUTE_KEY, ECDH_R_KDF_FAILED);
			goto err;
		}
		ret = outlen;
	} else {
		/* No KDF, just copy out the key and zero the rest. */
		if (outlen > buflen) {
			memset((void *)((uintptr_t)out + buflen), 0, outlen - buflen);
			outlen = buflen;
		}
		memcpy(out, buf, outlen);
		ret = outlen;
	}

err:
	EC_POINT_free(tmp);
	if (ctx)
		BN_CTX_end(ctx);
	BN_CTX_free(ctx);
	free(buf);
	return (ret);
}


int
ECDH_compute_key(void *out, size_t outlen, const EC_POINT *pub_key,
    EC_KEY *eckey,
    void *(*KDF)(const void *in, size_t inlen, void *out, size_t *outlen))
{
	ECDH_DATA *ecdh = ecdh_check(eckey);
	if (ecdh == NULL)
		return 0;
	return ecdh->meth->compute_key(out, outlen, pub_key, eckey, KDF);
}


void
ecdh_data_free(void *data)
{
	ECDH_DATA *r = (ECDH_DATA *)data;

#ifndef OPENSSL_NO_ENGINE
	if (r->engine)
		ENGINE_finish(r->engine);
#endif

	CRYPTO_free_ex_data(CRYPTO_EX_INDEX_ECDH, r, &r->ex_data);

	explicit_bzero((void *)r, sizeof(ECDH_DATA));

	free(r);
}


static void *
ecdh_data_new(void)
{
	return (void *)ECDH_DATA_new_method(NULL);
}


static ECDH_DATA *
ECDH_DATA_new_method(ENGINE *engine)
{
	ECDH_DATA *ret;

	ret = malloc(sizeof(ECDH_DATA));
	if (ret == NULL) {
		ECDHerr(ECDH_F_ECDH_DATA_NEW_METHOD, ERR_R_MALLOC_FAILURE);
		return (NULL);
	}

	ret->init = NULL;

	ret->meth = ECDH_get_default_method();
	ret->engine = engine;
#ifndef OPENSSL_NO_ENGINE
	if (!ret->engine)
		ret->engine = ENGINE_get_default_ECDH();
	if (ret->engine) {
		ret->meth = ENGINE_get_ECDH(ret->engine);
		if (!ret->meth) {
			ECDHerr(ECDH_F_ECDH_DATA_NEW_METHOD, ERR_R_ENGINE_LIB);
			ENGINE_finish(ret->engine);
			free(ret);
			return NULL;
		}
	}
#endif

	ret->flags = ret->meth->flags;
	CRYPTO_new_ex_data(CRYPTO_EX_INDEX_ECDH, ret, &ret->ex_data);
	return (ret);
}


const ECDH_METHOD *
ECDH_get_default_method(void)
{
	if (!default_ECDH_method) {
		default_ECDH_method = ECDH_OpenSSL();
	}
	return default_ECDH_method;
}


const ECDH_METHOD *
ECDH_OpenSSL(void)
{
	return &openssl_ecdh_meth;
}


int
ECDH_size(const EC_KEY *d)
{
	return ((EC_GROUP_get_degree(EC_KEY_get0_group(d)) + 7) / 8);
}


void 
EC_EX_DATA_free_all_data(EC_EXTRA_DATA ** ex_data)
{
	EC_EXTRA_DATA *d;

	if (ex_data == NULL)
		return;

	d = *ex_data;
	while (d) {
		EC_EXTRA_DATA *next = d->next;

		d->free_func(d->data);
		free(d);

		d = next;
	}
	*ex_data = NULL;
}


void *
EC_EX_DATA_get_data(const EC_EXTRA_DATA * ex_data,
    void *(*dup_func) (void *),
    void (*free_func) (void *),
    void (*clear_free_func) (void *))
{
	const EC_EXTRA_DATA *d;

	for (d = ex_data; d != NULL; d = d->next) {
		if (d->dup_func == dup_func && d->free_func == free_func && d->clear_free_func == clear_free_func)
			return d->data;
	}

	return NULL;
}


int 
EC_EX_DATA_set_data(EC_EXTRA_DATA ** ex_data, void *data,
    void *(*dup_func) (void *),
    void (*free_func) (void *),
    void (*clear_free_func) (void *))
{
	EC_EXTRA_DATA *d;

	if (ex_data == NULL)
		return 0;

	for (d = *ex_data; d != NULL; d = d->next) {
		if (d->dup_func == dup_func && d->free_func == free_func &&
		    d->clear_free_func == clear_free_func) {
			ECerr(EC_F_EC_EX_DATA_SET_DATA, EC_R_SLOT_FULL);
			return 0;
		}
	}

	if (data == NULL)
		/* no explicit entry needed */
		return 1;

	d = malloc(sizeof *d);
	if (d == NULL)
		return 0;

	d->data = data;
	d->dup_func = dup_func;
	d->free_func = free_func;
	d->clear_free_func = clear_free_func;

	d->next = *ex_data;
	*ex_data = d;

	return 1;
}


int 
ec_GFp_mont_field_decode(const EC_GROUP *group, BIGNUM *r, const BIGNUM *a,
    BN_CTX *ctx)
{
	if (group->field_data1 == NULL) {
		ECerr(EC_F_EC_GFP_MONT_FIELD_DECODE, EC_R_NOT_INITIALIZED);
		return 0;
	}
	return BN_from_montgomery(r, a, group->field_data1, ctx);
}


int 
ec_GFp_mont_field_encode(const EC_GROUP *group, BIGNUM *r, const BIGNUM *a,
    BN_CTX *ctx)
{
	if (group->field_data1 == NULL) {
		ECerr(EC_F_EC_GFP_MONT_FIELD_ENCODE, EC_R_NOT_INITIALIZED);
		return 0;
	}
	return BN_to_montgomery(r, a, (BN_MONT_CTX *) group->field_data1, ctx);
}


int 
ec_GFp_mont_field_mul(const EC_GROUP *group, BIGNUM *r, const BIGNUM *a,
    const BIGNUM *b, BN_CTX *ctx)
{
	if (group->field_data1 == NULL) {
		ECerr(EC_F_EC_GFP_MONT_FIELD_MUL, EC_R_NOT_INITIALIZED);
		return 0;
	}
	return BN_mod_mul_montgomery(r, a, b, group->field_data1, ctx);
}


int 
ec_GFp_mont_field_set_to_one(const EC_GROUP *group, BIGNUM *r, BN_CTX *ctx)
{
	if (group->field_data2 == NULL) {
		ECerr(EC_F_EC_GFP_MONT_FIELD_SET_TO_ONE, EC_R_NOT_INITIALIZED);
		return 0;
	}
	if (!BN_copy(r, group->field_data2))
		return 0;
	return 1;
}


int 
ec_GFp_mont_field_sqr(const EC_GROUP *group, BIGNUM *r, const BIGNUM *a,
    BN_CTX *ctx)
{
	if (group->field_data1 == NULL) {
		ECerr(EC_F_EC_GFP_MONT_FIELD_SQR, EC_R_NOT_INITIALIZED);
		return 0;
	}
	return BN_mod_mul_montgomery(r, a, a, group->field_data1, ctx);
}


void 
ec_GFp_mont_group_finish(EC_GROUP * group)
{
	BN_MONT_CTX_free(group->field_data1);
	group->field_data1 = NULL;
	BN_free(group->field_data2);
	group->field_data2 = NULL;
	ec_GFp_simple_group_finish(group);
}


int 
ec_GFp_mont_group_init(EC_GROUP * group)
{
	int ok;

	ok = ec_GFp_simple_group_init(group);
	group->field_data1 = NULL;
	group->field_data2 = NULL;
	return ok;
}


int 
ec_GFp_mont_group_set_curve(EC_GROUP *group, const BIGNUM *p, const BIGNUM *a,
    const BIGNUM *b, BN_CTX *ctx)
{
	BN_CTX *new_ctx = NULL;
	BN_MONT_CTX *mont = NULL;
	BIGNUM *one = NULL;
	int ret = 0;

	BN_MONT_CTX_free(group->field_data1);
	group->field_data1 = NULL;
	BN_free(group->field_data2);
	group->field_data2 = NULL;
	if (ctx == NULL) {
		ctx = new_ctx = BN_CTX_new();
		if (ctx == NULL)
			return 0;
	}
	mont = BN_MONT_CTX_new();
	if (mont == NULL)
		goto err;
	if (!BN_MONT_CTX_set(mont, p, ctx)) {
		ECerr(EC_F_EC_GFP_MONT_GROUP_SET_CURVE, ERR_R_BN_LIB);
		goto err;
	}
	one = BN_new();
	if (one == NULL)
		goto err;
	if (!BN_to_montgomery(one, BN_value_one(), mont, ctx))
		goto err;

	group->field_data1 = mont;
	mont = NULL;
	group->field_data2 = one;
	one = NULL;

	ret = ec_GFp_simple_group_set_curve(group, p, a, b, ctx);

	if (!ret) {
		BN_MONT_CTX_free(group->field_data1);
		group->field_data1 = NULL;
		BN_free(group->field_data2);
		group->field_data2 = NULL;
	}
err:
	BN_CTX_free(new_ctx);
	BN_MONT_CTX_free(mont);
	BN_free(one);
	return ret;
}


const EC_METHOD *
EC_GFp_mont_method(void)
{
	static const EC_METHOD ret = {
		.flags = EC_FLAGS_DEFAULT_OCT,
		.field_type = NID_X9_62_prime_field,
		.group_init = ec_GFp_mont_group_init,
		.group_finish = ec_GFp_mont_group_finish,
		.group_clear_finish = ec_GFp_mont_group_clear_finish,
		.group_copy = ec_GFp_mont_group_copy,
		.group_set_curve = ec_GFp_mont_group_set_curve,
		.group_get_curve = ec_GFp_simple_group_get_curve,
		.group_get_degree = ec_GFp_simple_group_get_degree,
		.group_check_discriminant =
		ec_GFp_simple_group_check_discriminant,
		.point_init = ec_GFp_simple_point_init,
		.point_finish = ec_GFp_simple_point_finish,
		.point_clear_finish = ec_GFp_simple_point_clear_finish,
		.point_copy = ec_GFp_simple_point_copy,
		.point_set_to_infinity = ec_GFp_simple_point_set_to_infinity,
		.point_set_Jprojective_coordinates_GFp =
		ec_GFp_simple_set_Jprojective_coordinates_GFp,
		.point_get_Jprojective_coordinates_GFp =
		ec_GFp_simple_get_Jprojective_coordinates_GFp,
		.point_set_affine_coordinates =
		ec_GFp_simple_point_set_affine_coordinates,
		.point_get_affine_coordinates =
		ec_GFp_simple_point_get_affine_coordinates,
		.add = ec_GFp_simple_add,
		.dbl = ec_GFp_simple_dbl,
		.invert = ec_GFp_simple_invert,
		.is_at_infinity = ec_GFp_simple_is_at_infinity,
		.is_on_curve = ec_GFp_simple_is_on_curve,
		.point_cmp = ec_GFp_simple_cmp,
		.make_affine = ec_GFp_simple_make_affine,
		.points_make_affine = ec_GFp_simple_points_make_affine,
		.field_mul = ec_GFp_mont_field_mul,
		.field_sqr = ec_GFp_mont_field_sqr,
		.field_encode = ec_GFp_mont_field_encode,
		.field_decode = ec_GFp_mont_field_decode,
		.field_set_to_one = ec_GFp_mont_field_set_to_one
	};

	return &ret;
}


int 
ec_GFp_simple_add(const EC_GROUP * group, EC_POINT * r, const EC_POINT * a, const EC_POINT * b, BN_CTX * ctx)
{
	int (*field_mul) (const EC_GROUP *, BIGNUM *, const BIGNUM *, const BIGNUM *, BN_CTX *);
	int (*field_sqr) (const EC_GROUP *, BIGNUM *, const BIGNUM *, BN_CTX *);
	const BIGNUM *p;
	BN_CTX *new_ctx = NULL;
	BIGNUM *n0, *n1, *n2, *n3, *n4, *n5, *n6;
	int ret = 0;

	if (a == b)
		return EC_POINT_dbl(group, r, a, ctx);
	if (EC_POINT_is_at_infinity(group, a) > 0)
		return EC_POINT_copy(r, b);
	if (EC_POINT_is_at_infinity(group, b) > 0)
		return EC_POINT_copy(r, a);

	field_mul = group->meth->field_mul;
	field_sqr = group->meth->field_sqr;
	p = &group->field;

	if (ctx == NULL) {
		ctx = new_ctx = BN_CTX_new();
		if (ctx == NULL)
			return 0;
	}
	BN_CTX_start(ctx);
	if ((n0 = BN_CTX_get(ctx)) == NULL)
		goto end;
	if ((n1 = BN_CTX_get(ctx)) == NULL)
		goto end;
	if ((n2 = BN_CTX_get(ctx)) == NULL)
		goto end;
	if ((n3 = BN_CTX_get(ctx)) == NULL)
		goto end;
	if ((n4 = BN_CTX_get(ctx)) == NULL)
		goto end;
	if ((n5 = BN_CTX_get(ctx)) == NULL)
		goto end;
	if ((n6 = BN_CTX_get(ctx)) == NULL)
		goto end;

	/*
	 * Note that in this function we must not read components of 'a' or
	 * 'b' once we have written the corresponding components of 'r'. ('r'
	 * might be one of 'a' or 'b'.)
	 */

	/* n1, n2 */
	if (b->Z_is_one) {
		if (!BN_copy(n1, &a->X))
			goto end;
		if (!BN_copy(n2, &a->Y))
			goto end;
		/* n1 = X_a */
		/* n2 = Y_a */
	} else {
		if (!field_sqr(group, n0, &b->Z, ctx))
			goto end;
		if (!field_mul(group, n1, &a->X, n0, ctx))
			goto end;
		/* n1 = X_a * Z_b^2 */

		if (!field_mul(group, n0, n0, &b->Z, ctx))
			goto end;
		if (!field_mul(group, n2, &a->Y, n0, ctx))
			goto end;
		/* n2 = Y_a * Z_b^3 */
	}

	/* n3, n4 */
	if (a->Z_is_one) {
		if (!BN_copy(n3, &b->X))
			goto end;
		if (!BN_copy(n4, &b->Y))
			goto end;
		/* n3 = X_b */
		/* n4 = Y_b */
	} else {
		if (!field_sqr(group, n0, &a->Z, ctx))
			goto end;
		if (!field_mul(group, n3, &b->X, n0, ctx))
			goto end;
		/* n3 = X_b * Z_a^2 */

		if (!field_mul(group, n0, n0, &a->Z, ctx))
			goto end;
		if (!field_mul(group, n4, &b->Y, n0, ctx))
			goto end;
		/* n4 = Y_b * Z_a^3 */
	}

	/* n5, n6 */
	if (!BN_mod_sub_quick(n5, n1, n3, p))
		goto end;
	if (!BN_mod_sub_quick(n6, n2, n4, p))
		goto end;
	/* n5 = n1 - n3 */
	/* n6 = n2 - n4 */

	if (BN_is_zero(n5)) {
		if (BN_is_zero(n6)) {
			/* a is the same point as b */
			BN_CTX_end(ctx);
			ret = EC_POINT_dbl(group, r, a, ctx);
			ctx = NULL;
			goto end;
		} else {
			/* a is the inverse of b */
			BN_zero(&r->Z);
			r->Z_is_one = 0;
			ret = 1;
			goto end;
		}
	}
	/* 'n7', 'n8' */
	if (!BN_mod_add_quick(n1, n1, n3, p))
		goto end;
	if (!BN_mod_add_quick(n2, n2, n4, p))
		goto end;
	/* 'n7' = n1 + n3 */
	/* 'n8' = n2 + n4 */

	/* Z_r */
	if (a->Z_is_one && b->Z_is_one) {
		if (!BN_copy(&r->Z, n5))
			goto end;
	} else {
		if (a->Z_is_one) {
			if (!BN_copy(n0, &b->Z))
				goto end;
		} else if (b->Z_is_one) {
			if (!BN_copy(n0, &a->Z))
				goto end;
		} else {
			if (!field_mul(group, n0, &a->Z, &b->Z, ctx))
				goto end;
		}
		if (!field_mul(group, &r->Z, n0, n5, ctx))
			goto end;
	}
	r->Z_is_one = 0;
	/* Z_r = Z_a * Z_b * n5 */

	/* X_r */
	if (!field_sqr(group, n0, n6, ctx))
		goto end;
	if (!field_sqr(group, n4, n5, ctx))
		goto end;
	if (!field_mul(group, n3, n1, n4, ctx))
		goto end;
	if (!BN_mod_sub_quick(&r->X, n0, n3, p))
		goto end;
	/* X_r = n6^2 - n5^2 * 'n7' */

	/* 'n9' */
	if (!BN_mod_lshift1_quick(n0, &r->X, p))
		goto end;
	if (!BN_mod_sub_quick(n0, n3, n0, p))
		goto end;
	/* n9 = n5^2 * 'n7' - 2 * X_r */

	/* Y_r */
	if (!field_mul(group, n0, n0, n6, ctx))
		goto end;
	if (!field_mul(group, n5, n4, n5, ctx))
		goto end;	/* now n5 is n5^3 */
	if (!field_mul(group, n1, n2, n5, ctx))
		goto end;
	if (!BN_mod_sub_quick(n0, n0, n1, p))
		goto end;
	if (BN_is_odd(n0))
		if (!BN_add(n0, n0, p))
			goto end;
	/* now  0 <= n0 < 2*p,  and n0 is even */
	if (!BN_rshift1(&r->Y, n0))
		goto end;
	/* Y_r = (n6 * 'n9' - 'n8' * 'n5^3') / 2 */

	ret = 1;

end:
	if (ctx)		/* otherwise we already called BN_CTX_end */
		BN_CTX_end(ctx);
	BN_CTX_free(new_ctx);
	return ret;
}


int 
ec_GFp_simple_dbl(const EC_GROUP * group, EC_POINT * r, const EC_POINT * a, BN_CTX * ctx)
{
	int (*field_mul) (const EC_GROUP *, BIGNUM *, const BIGNUM *, const BIGNUM *, BN_CTX *);
	int (*field_sqr) (const EC_GROUP *, BIGNUM *, const BIGNUM *, BN_CTX *);
	const BIGNUM *p;
	BN_CTX *new_ctx = NULL;
	BIGNUM *n0, *n1, *n2, *n3;
	int ret = 0;

	if (EC_POINT_is_at_infinity(group, a) > 0) {
		BN_zero(&r->Z);
		r->Z_is_one = 0;
		return 1;
	}
	field_mul = group->meth->field_mul;
	field_sqr = group->meth->field_sqr;
	p = &group->field;

	if (ctx == NULL) {
		ctx = new_ctx = BN_CTX_new();
		if (ctx == NULL)
			return 0;
	}
	BN_CTX_start(ctx);
	if ((n0 = BN_CTX_get(ctx)) == NULL)
		goto err;
	if ((n1 = BN_CTX_get(ctx)) == NULL)
		goto err;
	if ((n2 = BN_CTX_get(ctx)) == NULL)
		goto err;
	if ((n3 = BN_CTX_get(ctx)) == NULL)
		goto err;

	/*
	 * Note that in this function we must not read components of 'a' once
	 * we have written the corresponding components of 'r'. ('r' might
	 * the same as 'a'.)
	 */

	/* n1 */
	if (a->Z_is_one) {
		if (!field_sqr(group, n0, &a->X, ctx))
			goto err;
		if (!BN_mod_lshift1_quick(n1, n0, p))
			goto err;
		if (!BN_mod_add_quick(n0, n0, n1, p))
			goto err;
		if (!BN_mod_add_quick(n1, n0, &group->a, p))
			goto err;
		/* n1 = 3 * X_a^2 + a_curve */
	} else if (group->a_is_minus3) {
		if (!field_sqr(group, n1, &a->Z, ctx))
			goto err;
		if (!BN_mod_add_quick(n0, &a->X, n1, p))
			goto err;
		if (!BN_mod_sub_quick(n2, &a->X, n1, p))
			goto err;
		if (!field_mul(group, n1, n0, n2, ctx))
			goto err;
		if (!BN_mod_lshift1_quick(n0, n1, p))
			goto err;
		if (!BN_mod_add_quick(n1, n0, n1, p))
			goto err;
		/*
		 * n1 = 3 * (X_a + Z_a^2) * (X_a - Z_a^2) = 3 * X_a^2 - 3 *
		 * Z_a^4
		 */
	} else {
		if (!field_sqr(group, n0, &a->X, ctx))
			goto err;
		if (!BN_mod_lshift1_quick(n1, n0, p))
			goto err;
		if (!BN_mod_add_quick(n0, n0, n1, p))
			goto err;
		if (!field_sqr(group, n1, &a->Z, ctx))
			goto err;
		if (!field_sqr(group, n1, n1, ctx))
			goto err;
		if (!field_mul(group, n1, n1, &group->a, ctx))
			goto err;
		if (!BN_mod_add_quick(n1, n1, n0, p))
			goto err;
		/* n1 = 3 * X_a^2 + a_curve * Z_a^4 */
	}

	/* Z_r */
	if (a->Z_is_one) {
		if (!BN_copy(n0, &a->Y))
			goto err;
	} else {
		if (!field_mul(group, n0, &a->Y, &a->Z, ctx))
			goto err;
	}
	if (!BN_mod_lshift1_quick(&r->Z, n0, p))
		goto err;
	r->Z_is_one = 0;
	/* Z_r = 2 * Y_a * Z_a */

	/* n2 */
	if (!field_sqr(group, n3, &a->Y, ctx))
		goto err;
	if (!field_mul(group, n2, &a->X, n3, ctx))
		goto err;
	if (!BN_mod_lshift_quick(n2, n2, 2, p))
		goto err;
	/* n2 = 4 * X_a * Y_a^2 */

	/* X_r */
	if (!BN_mod_lshift1_quick(n0, n2, p))
		goto err;
	if (!field_sqr(group, &r->X, n1, ctx))
		goto err;
	if (!BN_mod_sub_quick(&r->X, &r->X, n0, p))
		goto err;
	/* X_r = n1^2 - 2 * n2 */

	/* n3 */
	if (!field_sqr(group, n0, n3, ctx))
		goto err;
	if (!BN_mod_lshift_quick(n3, n0, 3, p))
		goto err;
	/* n3 = 8 * Y_a^4 */

	/* Y_r */
	if (!BN_mod_sub_quick(n0, n2, &r->X, p))
		goto err;
	if (!field_mul(group, n0, n1, n0, ctx))
		goto err;
	if (!BN_mod_sub_quick(&r->Y, n0, n3, p))
		goto err;
	/* Y_r = n1 * (n2 - X_r) - n3 */

	ret = 1;

err:
	BN_CTX_end(ctx);
	BN_CTX_free(new_ctx);
	return ret;
}


void 
ec_GFp_simple_group_finish(EC_GROUP * group)
{
	BN_free(&group->field);
	BN_free(&group->a);
	BN_free(&group->b);
}


int 
ec_GFp_simple_group_get_degree(const EC_GROUP * group)
{
	return BN_num_bits(&group->field);
}


int 
ec_GFp_simple_group_init(EC_GROUP * group)
{
	BN_init(&group->field);
	BN_init(&group->a);
	BN_init(&group->b);
	group->a_is_minus3 = 0;
	return 1;
}


int 
ec_GFp_simple_group_set_curve(EC_GROUP * group,
    const BIGNUM * p, const BIGNUM * a, const BIGNUM * b, BN_CTX * ctx)
{
	int ret = 0;
	BN_CTX *new_ctx = NULL;
	BIGNUM *tmp_a;

	/* p must be a prime > 3 */
	if (BN_num_bits(p) <= 2 || !BN_is_odd(p)) {
		ECerr(EC_F_EC_GFP_SIMPLE_GROUP_SET_CURVE, EC_R_INVALID_FIELD);
		return 0;
	}
	if (ctx == NULL) {
		ctx = new_ctx = BN_CTX_new();
		if (ctx == NULL)
			return 0;
	}
	BN_CTX_start(ctx);
	if ((tmp_a = BN_CTX_get(ctx)) == NULL)
		goto err;

	/* group->field */
	if (!BN_copy(&group->field, p))
		goto err;
	BN_set_negative(&group->field, 0);

	/* group->a */
	if (!BN_nnmod(tmp_a, a, p, ctx))
		goto err;
	if (group->meth->field_encode) {
		if (!group->meth->field_encode(group, &group->a, tmp_a, ctx))
			goto err;
	} else if (!BN_copy(&group->a, tmp_a))
		goto err;

	/* group->b */
	if (!BN_nnmod(&group->b, b, p, ctx))
		goto err;
	if (group->meth->field_encode)
		if (!group->meth->field_encode(group, &group->b, &group->b, ctx))
			goto err;

	/* group->a_is_minus3 */
	if (!BN_add_word(tmp_a, 3))
		goto err;
	group->a_is_minus3 = (0 == BN_cmp(tmp_a, &group->field));

	ret = 1;

err:
	BN_CTX_end(ctx);
	BN_CTX_free(new_ctx);
	return ret;
}


int 
ec_GFp_simple_invert(const EC_GROUP * group, EC_POINT * point, BN_CTX * ctx)
{
	if (EC_POINT_is_at_infinity(group, point) > 0 || BN_is_zero(&point->Y))
		/* point is its own inverse */
		return 1;

	return BN_usub(&point->Y, &group->field, &point->Y);
}


int 
ec_GFp_simple_is_at_infinity(const EC_GROUP * group, const EC_POINT * point)
{
	return BN_is_zero(&point->Z);
}


int 
ec_GFp_simple_is_on_curve(const EC_GROUP * group, const EC_POINT * point, BN_CTX * ctx)
{
	int (*field_mul) (const EC_GROUP *, BIGNUM *, const BIGNUM *, const BIGNUM *, BN_CTX *);
	int (*field_sqr) (const EC_GROUP *, BIGNUM *, const BIGNUM *, BN_CTX *);
	const BIGNUM *p;
	BN_CTX *new_ctx = NULL;
	BIGNUM *rh, *tmp, *Z4, *Z6;
	int ret = -1;

	if (EC_POINT_is_at_infinity(group, point) > 0)
		return 1;

	field_mul = group->meth->field_mul;
	field_sqr = group->meth->field_sqr;
	p = &group->field;

	if (ctx == NULL) {
		ctx = new_ctx = BN_CTX_new();
		if (ctx == NULL)
			return -1;
	}
	BN_CTX_start(ctx);
	if ((rh = BN_CTX_get(ctx)) == NULL)
		goto err;
	if ((tmp = BN_CTX_get(ctx)) == NULL)
		goto err;
	if ((Z4 = BN_CTX_get(ctx)) == NULL)
		goto err;
	if ((Z6 = BN_CTX_get(ctx)) == NULL)
		goto err;

	/*
	 * We have a curve defined by a Weierstrass equation y^2 = x^3 + a*x
	 * + b. The point to consider is given in Jacobian projective
	 * coordinates where  (X, Y, Z)  represents  (x, y) = (X/Z^2, Y/Z^3).
	 * Substituting this and multiplying by  Z^6  transforms the above
	 * equation into Y^2 = X^3 + a*X*Z^4 + b*Z^6. To test this, we add up
	 * the right-hand side in 'rh'.
	 */

	/* rh := X^2 */
	if (!field_sqr(group, rh, &point->X, ctx))
		goto err;

	if (!point->Z_is_one) {
		if (!field_sqr(group, tmp, &point->Z, ctx))
			goto err;
		if (!field_sqr(group, Z4, tmp, ctx))
			goto err;
		if (!field_mul(group, Z6, Z4, tmp, ctx))
			goto err;

		/* rh := (rh + a*Z^4)*X */
		if (group->a_is_minus3) {
			if (!BN_mod_lshift1_quick(tmp, Z4, p))
				goto err;
			if (!BN_mod_add_quick(tmp, tmp, Z4, p))
				goto err;
			if (!BN_mod_sub_quick(rh, rh, tmp, p))
				goto err;
			if (!field_mul(group, rh, rh, &point->X, ctx))
				goto err;
		} else {
			if (!field_mul(group, tmp, Z4, &group->a, ctx))
				goto err;
			if (!BN_mod_add_quick(rh, rh, tmp, p))
				goto err;
			if (!field_mul(group, rh, rh, &point->X, ctx))
				goto err;
		}

		/* rh := rh + b*Z^6 */
		if (!field_mul(group, tmp, &group->b, Z6, ctx))
			goto err;
		if (!BN_mod_add_quick(rh, rh, tmp, p))
			goto err;
	} else {
		/* point->Z_is_one */

		/* rh := (rh + a)*X */
		if (!BN_mod_add_quick(rh, rh, &group->a, p))
			goto err;
		if (!field_mul(group, rh, rh, &point->X, ctx))
			goto err;
		/* rh := rh + b */
		if (!BN_mod_add_quick(rh, rh, &group->b, p))
			goto err;
	}

	/* 'lh' := Y^2 */
	if (!field_sqr(group, tmp, &point->Y, ctx))
		goto err;

	ret = (0 == BN_ucmp(tmp, rh));

err:
	BN_CTX_end(ctx);
	BN_CTX_free(new_ctx);
	return ret;
}


int 
ec_GFp_simple_oct2point(const EC_GROUP * group, EC_POINT * point,
    const unsigned char *buf, size_t len, BN_CTX * ctx)
{
	point_conversion_form_t form;
	int y_bit;
	BN_CTX *new_ctx = NULL;
	BIGNUM *x, *y;
	size_t field_len, enc_len;
	int ret = 0;

	if (len == 0) {
		ECerr(EC_F_EC_GFP_SIMPLE_OCT2POINT, EC_R_BUFFER_TOO_SMALL);
		return 0;
	}
	form = buf[0];
	y_bit = form & 1;
	form = form & ~1U;
	if ((form != 0) && (form != POINT_CONVERSION_COMPRESSED)
	    && (form != POINT_CONVERSION_UNCOMPRESSED)
	    && (form != POINT_CONVERSION_HYBRID)) {
		ECerr(EC_F_EC_GFP_SIMPLE_OCT2POINT, EC_R_INVALID_ENCODING);
		return 0;
	}
	if ((form == 0 || form == POINT_CONVERSION_UNCOMPRESSED) && y_bit) {
		ECerr(EC_F_EC_GFP_SIMPLE_OCT2POINT, EC_R_INVALID_ENCODING);
		return 0;
	}
	if (form == 0) {
		if (len != 1) {
			ECerr(EC_F_EC_GFP_SIMPLE_OCT2POINT, EC_R_INVALID_ENCODING);
			return 0;
		}
		return EC_POINT_set_to_infinity(group, point);
	}
	field_len = BN_num_bytes(&group->field);
	enc_len = (form == POINT_CONVERSION_COMPRESSED) ? 1 + field_len : 1 + 2 * field_len;

	if (len != enc_len) {
		ECerr(EC_F_EC_GFP_SIMPLE_OCT2POINT, EC_R_INVALID_ENCODING);
		return 0;
	}
	if (ctx == NULL) {
		ctx = new_ctx = BN_CTX_new();
		if (ctx == NULL)
			return 0;
	}
	BN_CTX_start(ctx);
	if ((x = BN_CTX_get(ctx)) == NULL)
		goto err;
	if ((y = BN_CTX_get(ctx)) == NULL)
		goto err;

	if (!BN_bin2bn(buf + 1, field_len, x))
		goto err;
	if (BN_ucmp(x, &group->field) >= 0) {
		ECerr(EC_F_EC_GFP_SIMPLE_OCT2POINT, EC_R_INVALID_ENCODING);
		goto err;
	}
	if (form == POINT_CONVERSION_COMPRESSED) {
		if (!EC_POINT_set_compressed_coordinates_GFp(group, point, x, y_bit, ctx))
			goto err;
	} else {
		if (!BN_bin2bn(buf + 1 + field_len, field_len, y))
			goto err;
		if (BN_ucmp(y, &group->field) >= 0) {
			ECerr(EC_F_EC_GFP_SIMPLE_OCT2POINT, EC_R_INVALID_ENCODING);
			goto err;
		}
		if (form == POINT_CONVERSION_HYBRID) {
			if (y_bit != BN_is_odd(y)) {
				ECerr(EC_F_EC_GFP_SIMPLE_OCT2POINT, EC_R_INVALID_ENCODING);
				goto err;
			}
		}
		if (!EC_POINT_set_affine_coordinates_GFp(group, point, x, y, ctx))
			goto err;
	}

	/* test required by X9.62 */
	if (EC_POINT_is_on_curve(group, point, ctx) <= 0) {
		ECerr(EC_F_EC_GFP_SIMPLE_OCT2POINT, EC_R_POINT_IS_NOT_ON_CURVE);
		goto err;
	}
	ret = 1;

err:
	BN_CTX_end(ctx);
	BN_CTX_free(new_ctx);
	return ret;
}


size_t 
ec_GFp_simple_point2oct(const EC_GROUP * group, const EC_POINT * point, point_conversion_form_t form,
    unsigned char *buf, size_t len, BN_CTX * ctx)
{
	size_t ret;
	BN_CTX *new_ctx = NULL;
	int used_ctx = 0;
	BIGNUM *x, *y;
	size_t field_len, i, skip;

	if ((form != POINT_CONVERSION_COMPRESSED)
	    && (form != POINT_CONVERSION_UNCOMPRESSED)
	    && (form != POINT_CONVERSION_HYBRID)) {
		ECerr(EC_F_EC_GFP_SIMPLE_POINT2OCT, EC_R_INVALID_FORM);
		goto err;
	}
	if (EC_POINT_is_at_infinity(group, point) > 0) {
		/* encodes to a single 0 octet */
		if (buf != NULL) {
			if (len < 1) {
				ECerr(EC_F_EC_GFP_SIMPLE_POINT2OCT, EC_R_BUFFER_TOO_SMALL);
				return 0;
			}
			buf[0] = 0;
		}
		return 1;
	}
	/* ret := required output buffer length */
	field_len = BN_num_bytes(&group->field);
	ret = (form == POINT_CONVERSION_COMPRESSED) ? 1 + field_len : 1 + 2 * field_len;

	/* if 'buf' is NULL, just return required length */
	if (buf != NULL) {
		if (len < ret) {
			ECerr(EC_F_EC_GFP_SIMPLE_POINT2OCT, EC_R_BUFFER_TOO_SMALL);
			goto err;
		}
		if (ctx == NULL) {
			ctx = new_ctx = BN_CTX_new();
			if (ctx == NULL)
				return 0;
		}
		BN_CTX_start(ctx);
		used_ctx = 1;
		if ((x = BN_CTX_get(ctx)) == NULL)
			goto err;
		if ((y = BN_CTX_get(ctx)) == NULL)
			goto err;

		if (!EC_POINT_get_affine_coordinates_GFp(group, point, x, y, ctx))
			goto err;

		if ((form == POINT_CONVERSION_COMPRESSED || form == POINT_CONVERSION_HYBRID) && BN_is_odd(y))
			buf[0] = form + 1;
		else
			buf[0] = form;

		i = 1;

		skip = field_len - BN_num_bytes(x);
		if (skip > field_len) {
			ECerr(EC_F_EC_GFP_SIMPLE_POINT2OCT, ERR_R_INTERNAL_ERROR);
			goto err;
		}
		while (skip > 0) {
			buf[i++] = 0;
			skip--;
		}
		skip = BN_bn2bin(x, buf + i);
		i += skip;
		if (i != 1 + field_len) {
			ECerr(EC_F_EC_GFP_SIMPLE_POINT2OCT, ERR_R_INTERNAL_ERROR);
			goto err;
		}
		if (form == POINT_CONVERSION_UNCOMPRESSED || form == POINT_CONVERSION_HYBRID) {
			skip = field_len - BN_num_bytes(y);
			if (skip > field_len) {
				ECerr(EC_F_EC_GFP_SIMPLE_POINT2OCT, ERR_R_INTERNAL_ERROR);
				goto err;
			}
			while (skip > 0) {
				buf[i++] = 0;
				skip--;
			}
			skip = BN_bn2bin(y, buf + i);
			i += skip;
		}
		if (i != ret) {
			ECerr(EC_F_EC_GFP_SIMPLE_POINT2OCT, ERR_R_INTERNAL_ERROR);
			goto err;
		}
	}
	if (used_ctx)
		BN_CTX_end(ctx);
	BN_CTX_free(new_ctx);
	return ret;

err:
	if (used_ctx)
		BN_CTX_end(ctx);
	BN_CTX_free(new_ctx);
	return 0;
}


void 
ec_GFp_simple_point_clear_finish(EC_POINT * point)
{
	BN_clear_free(&point->X);
	BN_clear_free(&point->Y);
	BN_clear_free(&point->Z);
	point->Z_is_one = 0;
}


int 
ec_GFp_simple_point_copy(EC_POINT * dest, const EC_POINT * src)
{
	if (!BN_copy(&dest->X, &src->X))
		return 0;
	if (!BN_copy(&dest->Y, &src->Y))
		return 0;
	if (!BN_copy(&dest->Z, &src->Z))
		return 0;
	dest->Z_is_one = src->Z_is_one;

	return 1;
}


void 
ec_GFp_simple_point_finish(EC_POINT * point)
{
	BN_free(&point->X);
	BN_free(&point->Y);
	BN_free(&point->Z);
}


int 
ec_GFp_simple_point_get_affine_coordinates(const EC_GROUP * group, const EC_POINT * point,
    BIGNUM * x, BIGNUM * y, BN_CTX * ctx)
{
	BN_CTX *new_ctx = NULL;
	BIGNUM *Z, *Z_1, *Z_2, *Z_3;
	const BIGNUM *Z_;
	int ret = 0;

	if (EC_POINT_is_at_infinity(group, point) > 0) {
		ECerr(EC_F_EC_GFP_SIMPLE_POINT_GET_AFFINE_COORDINATES, EC_R_POINT_AT_INFINITY);
		return 0;
	}
	if (ctx == NULL) {
		ctx = new_ctx = BN_CTX_new();
		if (ctx == NULL)
			return 0;
	}
	BN_CTX_start(ctx);
	if ((Z = BN_CTX_get(ctx)) == NULL)
		goto err;
	if ((Z_1 = BN_CTX_get(ctx)) == NULL)
		goto err;
	if ((Z_2 = BN_CTX_get(ctx)) == NULL)
		goto err;
	if ((Z_3 = BN_CTX_get(ctx)) == NULL)
		goto err;

	/* transform  (X, Y, Z)  into  (x, y) := (X/Z^2, Y/Z^3) */

	if (group->meth->field_decode) {
		if (!group->meth->field_decode(group, Z, &point->Z, ctx))
			goto err;
		Z_ = Z;
	} else {
		Z_ = &point->Z;
	}

	if (BN_is_one(Z_)) {
		if (group->meth->field_decode) {
			if (x != NULL) {
				if (!group->meth->field_decode(group, x, &point->X, ctx))
					goto err;
			}
			if (y != NULL) {
				if (!group->meth->field_decode(group, y, &point->Y, ctx))
					goto err;
			}
		} else {
			if (x != NULL) {
				if (!BN_copy(x, &point->X))
					goto err;
			}
			if (y != NULL) {
				if (!BN_copy(y, &point->Y))
					goto err;
			}
		}
	} else {
		if (!BN_mod_inverse(Z_1, Z_, &group->field, ctx)) {
			ECerr(EC_F_EC_GFP_SIMPLE_POINT_GET_AFFINE_COORDINATES, ERR_R_BN_LIB);
			goto err;
		}
		if (group->meth->field_encode == 0) {
			/* field_sqr works on standard representation */
			if (!group->meth->field_sqr(group, Z_2, Z_1, ctx))
				goto err;
		} else {
			if (!BN_mod_sqr(Z_2, Z_1, &group->field, ctx))
				goto err;
		}

		if (x != NULL) {
			/*
			 * in the Montgomery case, field_mul will cancel out
			 * Montgomery factor in X:
			 */
			if (!group->meth->field_mul(group, x, &point->X, Z_2, ctx))
				goto err;
		}
		if (y != NULL) {
			if (group->meth->field_encode == 0) {
				/* field_mul works on standard representation */
				if (!group->meth->field_mul(group, Z_3, Z_2, Z_1, ctx))
					goto err;
			} else {
				if (!BN_mod_mul(Z_3, Z_2, Z_1, &group->field, ctx))
					goto err;
			}

			/*
			 * in the Montgomery case, field_mul will cancel out
			 * Montgomery factor in Y:
			 */
			if (!group->meth->field_mul(group, y, &point->Y, Z_3, ctx))
				goto err;
		}
	}

	ret = 1;

err:
	BN_CTX_end(ctx);
	BN_CTX_free(new_ctx);
	return ret;
}


int 
ec_GFp_simple_point_init(EC_POINT * point)
{
	BN_init(&point->X);
	BN_init(&point->Y);
	BN_init(&point->Z);
	point->Z_is_one = 0;

	return 1;
}


int 
ec_GFp_simple_point_set_affine_coordinates(const EC_GROUP * group, EC_POINT * point,
    const BIGNUM * x, const BIGNUM * y, BN_CTX * ctx)
{
	if (x == NULL || y == NULL) {
		/* unlike for projective coordinates, we do not tolerate this */
		ECerr(EC_F_EC_GFP_SIMPLE_POINT_SET_AFFINE_COORDINATES, ERR_R_PASSED_NULL_PARAMETER);
		return 0;
	}
	return EC_POINT_set_Jprojective_coordinates_GFp(group, point, x, y, BN_value_one(), ctx);
}


int 
ec_GFp_simple_points_make_affine(const EC_GROUP * group, size_t num, EC_POINT * points[], BN_CTX * ctx)
{
	BN_CTX *new_ctx = NULL;
	BIGNUM *tmp0, *tmp1;
	size_t pow2 = 0;
	BIGNUM **heap = NULL;
	size_t i;
	int ret = 0;

	if (num == 0)
		return 1;

	if (ctx == NULL) {
		ctx = new_ctx = BN_CTX_new();
		if (ctx == NULL)
			return 0;
	}
	BN_CTX_start(ctx);
	if ((tmp0 = BN_CTX_get(ctx)) == NULL)
		goto err;
	if ((tmp1 = BN_CTX_get(ctx)) == NULL)
		goto err;

	/*
	 * Before converting the individual points, compute inverses of all Z
	 * values. Modular inversion is rather slow, but luckily we can do
	 * with a single explicit inversion, plus about 3 multiplications per
	 * input value.
	 */

	pow2 = 1;
	while (num > pow2)
		pow2 <<= 1;
	/*
	 * Now pow2 is the smallest power of 2 satifsying pow2 >= num. We
	 * need twice that.
	 */
	pow2 <<= 1;

	heap = reallocarray(NULL, pow2, sizeof heap[0]);
	if (heap == NULL)
		goto err;

	/*
	 * The array is used as a binary tree, exactly as in heapsort:
	 * 
	 * heap[1] heap[2]                     heap[3] heap[4]       heap[5]
	 * heap[6]       heap[7] heap[8]heap[9] heap[10]heap[11]
	 * heap[12]heap[13] heap[14] heap[15]
	 * 
	 * We put the Z's in the last line; then we set each other node to the
	 * product of its two child-nodes (where empty or 0 entries are
	 * treated as ones); then we invert heap[1]; then we invert each
	 * other node by replacing it by the product of its parent (after
	 * inversion) and its sibling (before inversion).
	 */
	heap[0] = NULL;
	for (i = pow2 / 2 - 1; i > 0; i--)
		heap[i] = NULL;
	for (i = 0; i < num; i++)
		heap[pow2 / 2 + i] = &points[i]->Z;
	for (i = pow2 / 2 + num; i < pow2; i++)
		heap[i] = NULL;

	/* set each node to the product of its children */
	for (i = pow2 / 2 - 1; i > 0; i--) {
		heap[i] = BN_new();
		if (heap[i] == NULL)
			goto err;

		if (heap[2 * i] != NULL) {
			if ((heap[2 * i + 1] == NULL) || BN_is_zero(heap[2 * i + 1])) {
				if (!BN_copy(heap[i], heap[2 * i]))
					goto err;
			} else {
				if (BN_is_zero(heap[2 * i])) {
					if (!BN_copy(heap[i], heap[2 * i + 1]))
						goto err;
				} else {
					if (!group->meth->field_mul(group, heap[i],
						heap[2 * i], heap[2 * i + 1], ctx))
						goto err;
				}
			}
		}
	}

	/* invert heap[1] */
	if (!BN_is_zero(heap[1])) {
		if (!BN_mod_inverse(heap[1], heap[1], &group->field, ctx)) {
			ECerr(EC_F_EC_GFP_SIMPLE_POINTS_MAKE_AFFINE, ERR_R_BN_LIB);
			goto err;
		}
	}
	if (group->meth->field_encode != 0) {
		/*
		 * in the Montgomery case, we just turned  R*H  (representing
		 * H) into  1/(R*H),  but we need  R*(1/H)  (representing
		 * 1/H); i.e. we have need to multiply by the Montgomery
		 * factor twice
		 */
		if (!group->meth->field_encode(group, heap[1], heap[1], ctx))
			goto err;
		if (!group->meth->field_encode(group, heap[1], heap[1], ctx))
			goto err;
	}
	/* set other heap[i]'s to their inverses */
	for (i = 2; i < pow2 / 2 + num; i += 2) {
		/* i is even */
		if ((heap[i + 1] != NULL) && !BN_is_zero(heap[i + 1])) {
			if (!group->meth->field_mul(group, tmp0, heap[i / 2], heap[i + 1], ctx))
				goto err;
			if (!group->meth->field_mul(group, tmp1, heap[i / 2], heap[i], ctx))
				goto err;
			if (!BN_copy(heap[i], tmp0))
				goto err;
			if (!BN_copy(heap[i + 1], tmp1))
				goto err;
		} else {
			if (!BN_copy(heap[i], heap[i / 2]))
				goto err;
		}
	}

	/*
	 * we have replaced all non-zero Z's by their inverses, now fix up
	 * all the points
	 */
	for (i = 0; i < num; i++) {
		EC_POINT *p = points[i];

		if (!BN_is_zero(&p->Z)) {
			/* turn  (X, Y, 1/Z)  into  (X/Z^2, Y/Z^3, 1) */

			if (!group->meth->field_sqr(group, tmp1, &p->Z, ctx))
				goto err;
			if (!group->meth->field_mul(group, &p->X, &p->X, tmp1, ctx))
				goto err;

			if (!group->meth->field_mul(group, tmp1, tmp1, &p->Z, ctx))
				goto err;
			if (!group->meth->field_mul(group, &p->Y, &p->Y, tmp1, ctx))
				goto err;

			if (group->meth->field_set_to_one != 0) {
				if (!group->meth->field_set_to_one(group, &p->Z, ctx))
					goto err;
			} else {
				if (!BN_one(&p->Z))
					goto err;
			}
			p->Z_is_one = 1;
		}
	}

	ret = 1;

err:
	BN_CTX_end(ctx);
	BN_CTX_free(new_ctx);
	if (heap != NULL) {
		/*
		 * heap[pow2/2] .. heap[pow2-1] have not been allocated
		 * locally!
		 */
		for (i = pow2 / 2 - 1; i > 0; i--) {
			BN_clear_free(heap[i]);
		}
		free(heap);
	}
	return ret;
}


int 
ec_GFp_simple_set_Jprojective_coordinates_GFp(const EC_GROUP * group, EC_POINT * point,
    const BIGNUM * x, const BIGNUM * y, const BIGNUM * z, BN_CTX * ctx)
{
	BN_CTX *new_ctx = NULL;
	int ret = 0;

	if (ctx == NULL) {
		ctx = new_ctx = BN_CTX_new();
		if (ctx == NULL)
			return 0;
	}
	if (x != NULL) {
		if (!BN_nnmod(&point->X, x, &group->field, ctx))
			goto err;
		if (group->meth->field_encode) {
			if (!group->meth->field_encode(group, &point->X, &point->X, ctx))
				goto err;
		}
	}
	if (y != NULL) {
		if (!BN_nnmod(&point->Y, y, &group->field, ctx))
			goto err;
		if (group->meth->field_encode) {
			if (!group->meth->field_encode(group, &point->Y, &point->Y, ctx))
				goto err;
		}
	}
	if (z != NULL) {
		int Z_is_one;

		if (!BN_nnmod(&point->Z, z, &group->field, ctx))
			goto err;
		Z_is_one = BN_is_one(&point->Z);
		if (group->meth->field_encode) {
			if (Z_is_one && (group->meth->field_set_to_one != 0)) {
				if (!group->meth->field_set_to_one(group, &point->Z, ctx))
					goto err;
			} else {
				if (!group->meth->field_encode(group, &point->Z, &point->Z, ctx))
					goto err;
			}
		}
		point->Z_is_one = Z_is_one;
	}
	ret = 1;

err:
	BN_CTX_free(new_ctx);
	return ret;
}


void 
EC_GROUP_free(EC_GROUP * group)
{
	if (!group)
		return;

	if (group->meth->group_finish != 0)
		group->meth->group_finish(group);

	EC_EX_DATA_free_all_data(&group->extra_data);

	EC_POINT_free(group->generator);
	BN_free(&group->order);
	BN_free(&group->cofactor);

	free(group->seed);

	free(group);
}


const EC_POINT *
EC_GROUP_get0_generator(const EC_GROUP *group)
{
	return group->generator;
}


int 
EC_GROUP_get_curve_name(const EC_GROUP * group)
{
	return group->curve_name;
}


int 
EC_GROUP_get_degree(const EC_GROUP * group)
{
	if (group->meth->group_get_degree == 0) {
		ECerr(EC_F_EC_GROUP_GET_DEGREE, ERR_R_SHOULD_NOT_HAVE_BEEN_CALLED);
		return 0;
	}
	return group->meth->group_get_degree(group);
}


int 
EC_GROUP_get_order(const EC_GROUP *group, BIGNUM *order, BN_CTX *ctx)
{
	if (!BN_copy(order, &group->order))
		return 0;

	return !BN_is_zero(order);
}


const EC_METHOD *
EC_GROUP_method_of(const EC_GROUP *group)
{
	return group->meth;
}


EC_GROUP *
EC_GROUP_new(const EC_METHOD * meth)
{
	EC_GROUP *ret;

	if (meth == NULL) {
		ECerr(EC_F_EC_GROUP_NEW, EC_R_SLOT_FULL);
		return NULL;
	}
	if (meth->group_init == 0) {
		ECerr(EC_F_EC_GROUP_NEW, ERR_R_SHOULD_NOT_HAVE_BEEN_CALLED);
		return NULL;
	}
	ret = malloc(sizeof *ret);
	if (ret == NULL) {
		ECerr(EC_F_EC_GROUP_NEW, ERR_R_MALLOC_FAILURE);
		return NULL;
	}
	ret->meth = meth;

	ret->extra_data = NULL;

	ret->generator = NULL;
	BN_init(&ret->order);
	BN_init(&ret->cofactor);

	ret->curve_name = 0;
	ret->asn1_flag = 0;
	ret->asn1_form = POINT_CONVERSION_UNCOMPRESSED;

	ret->seed = NULL;
	ret->seed_len = 0;

	if (!meth->group_init(ret)) {
		free(ret);
		return NULL;
	}
	return ret;
}


EC_GROUP *
EC_GROUP_new_by_curve_name(int nid)
{
	size_t i;
	EC_GROUP *ret = NULL;

	if (nid <= 0)
		return NULL;

	for (i = 0; i < curve_list_length; i++)
		if (curve_list[i].nid == nid) {
			ret = ec_group_new_from_data(curve_list[i]);
			break;
		}
	if (ret == NULL) {
		ECerr(EC_F_EC_GROUP_NEW_BY_CURVE_NAME, EC_R_UNKNOWN_GROUP);
		return NULL;
	}
	EC_GROUP_set_curve_name(ret, nid);

	return ret;
}


EC_GROUP *
EC_GROUP_new_curve_GFp(const BIGNUM *p, const BIGNUM *a, const BIGNUM *b,
    BN_CTX *ctx)
{
	const EC_METHOD *meth;
	EC_GROUP *ret;

#if defined(OPENSSL_BN_ASM_MONT)
	/*
	 * This might appear controversial, but the fact is that generic
	 * prime method was observed to deliver better performance even
	 * for NIST primes on a range of platforms, e.g.: 60%-15%
	 * improvement on IA-64, ~25% on ARM, 30%-90% on P4, 20%-25%
	 * in 32-bit build and 35%--12% in 64-bit build on Core2...
	 * Coefficients are relative to optimized bn_nist.c for most
	 * intensive ECDSA verify and ECDH operations for 192- and 521-
	 * bit keys respectively. Choice of these boundary values is
	 * arguable, because the dependency of improvement coefficient
	 * from key length is not a "monotone" curve. For example while
	 * 571-bit result is 23% on ARM, 384-bit one is -1%. But it's
	 * generally faster, sometimes "respectfully" faster, sometimes
	 * "tolerably" slower... What effectively happens is that loop
	 * with bn_mul_add_words is put against bn_mul_mont, and the
	 * latter "wins" on short vectors. Correct solution should be
	 * implementing dedicated NxN multiplication subroutines for
	 * small N. But till it materializes, let's stick to generic
	 * prime method...
	 *						<appro>
	 */
	meth = EC_GFp_mont_method();
#else
	meth = EC_GFp_nist_method();
#endif

	ret = EC_GROUP_new(meth);
	if (ret == NULL)
		return NULL;

	if (!EC_GROUP_set_curve_GFp(ret, p, a, b, ctx)) {
		unsigned long err;

		err = ERR_peek_last_error();

		if (!(ERR_GET_LIB(err) == ERR_LIB_EC &&
		    ((ERR_GET_REASON(err) == EC_R_NOT_A_NIST_PRIME) ||
		    (ERR_GET_REASON(err) == EC_R_NOT_A_SUPPORTED_NIST_PRIME)))) {
			/* real error */

			EC_GROUP_clear_free(ret);
			return NULL;
		}
		/* not an actual error, we just cannot use EC_GFp_nist_method */

		ERR_clear_error();

		EC_GROUP_clear_free(ret);
		meth = EC_GFp_mont_method();

		ret = EC_GROUP_new(meth);
		if (ret == NULL)
			return NULL;

		if (!EC_GROUP_set_curve_GFp(ret, p, a, b, ctx)) {
			EC_GROUP_clear_free(ret);
			return NULL;
		}
	}
	return ret;
}


static EC_GROUP *
ec_group_new_from_data(const ec_list_element curve)
{
	EC_GROUP *group = NULL;
	EC_POINT *P = NULL;
	BN_CTX *ctx = NULL;
	BIGNUM *p = NULL, *a = NULL, *b = NULL, *x = NULL, *y = NULL, *order = NULL;
	int ok = 0;
	int seed_len, param_len;
	const EC_METHOD *meth;
	const EC_CURVE_DATA *data;
	const unsigned char *params;

	if ((ctx = BN_CTX_new()) == NULL) {
		ECerr(EC_F_EC_GROUP_NEW_FROM_DATA, ERR_R_MALLOC_FAILURE);
		goto err;
	}
	data = curve.data;
	seed_len = data->seed_len;
	param_len = data->param_len;
	params = (const unsigned char *) (data + 1);	/* skip header */
	params += seed_len;	/* skip seed   */

	if (!(p = BN_bin2bn(params + 0 * param_len, param_len, NULL)) ||
	    !(a = BN_bin2bn(params + 1 * param_len, param_len, NULL)) ||
	    !(b = BN_bin2bn(params + 2 * param_len, param_len, NULL))) {
		ECerr(EC_F_EC_GROUP_NEW_FROM_DATA, ERR_R_BN_LIB);
		goto err;
	}
	if (curve.meth != 0) {
		meth = curve.meth();
		if (((group = EC_GROUP_new(meth)) == NULL) ||
		    (!(group->meth->group_set_curve(group, p, a, b, ctx)))) {
			ECerr(EC_F_EC_GROUP_NEW_FROM_DATA, ERR_R_EC_LIB);
			goto err;
		}
	} else if (data->field_type == NID_X9_62_prime_field) {
		if ((group = EC_GROUP_new_curve_GFp(p, a, b, ctx)) == NULL) {
			ECerr(EC_F_EC_GROUP_NEW_FROM_DATA, ERR_R_EC_LIB);
			goto err;
		}
	}
#ifndef OPENSSL_NO_EC2M
	else {			/* field_type ==
				 * NID_X9_62_characteristic_two_field */
		if ((group = EC_GROUP_new_curve_GF2m(p, a, b, ctx)) == NULL) {
			ECerr(EC_F_EC_GROUP_NEW_FROM_DATA, ERR_R_EC_LIB);
			goto err;
		}
	}
#endif

	if ((P = EC_POINT_new(group)) == NULL) {
		ECerr(EC_F_EC_GROUP_NEW_FROM_DATA, ERR_R_EC_LIB);
		goto err;
	}
	if (!(x = BN_bin2bn(params + 3 * param_len, param_len, NULL))
	    || !(y = BN_bin2bn(params + 4 * param_len, param_len, NULL))) {
		ECerr(EC_F_EC_GROUP_NEW_FROM_DATA, ERR_R_BN_LIB);
		goto err;
	}
	if (!EC_POINT_set_affine_coordinates_GFp(group, P, x, y, ctx)) {
		ECerr(EC_F_EC_GROUP_NEW_FROM_DATA, ERR_R_EC_LIB);
		goto err;
	}
	if (!(order = BN_bin2bn(params + 5 * param_len, param_len, NULL))
	    || !BN_set_word(x, (BN_ULONG) data->cofactor)) {
		ECerr(EC_F_EC_GROUP_NEW_FROM_DATA, ERR_R_BN_LIB);
		goto err;
	}
	if (!EC_GROUP_set_generator(group, P, order, x)) {
		ECerr(EC_F_EC_GROUP_NEW_FROM_DATA, ERR_R_EC_LIB);
		goto err;
	}
	if (seed_len) {
		if (!EC_GROUP_set_seed(group, params - seed_len, seed_len)) {
			ECerr(EC_F_EC_GROUP_NEW_FROM_DATA, ERR_R_EC_LIB);
			goto err;
		}
	}
	ok = 1;
err:
	if (!ok) {
		EC_GROUP_free(group);
		group = NULL;
	}
	EC_POINT_free(P);
	BN_CTX_free(ctx);
	BN_free(p);
	BN_free(a);
	BN_free(b);
	BN_free(order);
	BN_free(x);
	BN_free(y);
	return group;
}


int 
EC_GROUP_set_curve_GFp(EC_GROUP * group, const BIGNUM * p, const BIGNUM * a,
    const BIGNUM * b, BN_CTX * ctx)
{
	if (group->meth->group_set_curve == 0) {
		ECerr(EC_F_EC_GROUP_SET_CURVE_GFP, ERR_R_SHOULD_NOT_HAVE_BEEN_CALLED);
		return 0;
	}
	return group->meth->group_set_curve(group, p, a, b, ctx);
}


void 
EC_GROUP_set_curve_name(EC_GROUP * group, int nid)
{
	group->curve_name = nid;
}


int 
EC_GROUP_set_generator(EC_GROUP *group, const EC_POINT *generator,
    const BIGNUM *order, const BIGNUM *cofactor)
{
	if (generator == NULL) {
		ECerr(EC_F_EC_GROUP_SET_GENERATOR, ERR_R_PASSED_NULL_PARAMETER);
		return 0;
	}
	if (group->generator == NULL) {
		group->generator = EC_POINT_new(group);
		if (group->generator == NULL)
			return 0;
	}
	if (!EC_POINT_copy(group->generator, generator))
		return 0;

	if (order != NULL) {
		if (!BN_copy(&group->order, order))
			return 0;
	} else
		BN_zero(&group->order);

	if (cofactor != NULL) {
		if (!BN_copy(&group->cofactor, cofactor))
			return 0;
	} else
		BN_zero(&group->cofactor);

	return 1;
}


size_t 
EC_GROUP_set_seed(EC_GROUP * group, const unsigned char *p, size_t len)
{
	if (group->seed) {
		free(group->seed);
		group->seed = NULL;
		group->seed_len = 0;
	}
	if (!len || !p)
		return 1;

	if ((group->seed = malloc(len)) == NULL)
		return 0;
	memcpy(group->seed, p, len);
	group->seed_len = len;

	return len;
}


void 
EC_KEY_free(EC_KEY * r)
{
	int i;

	if (r == NULL)
		return;

	i = CRYPTO_add(&r->references, -1, CRYPTO_LOCK_EC);
	if (i > 0)
		return;

	EC_GROUP_free(r->group);
	EC_POINT_free(r->pub_key);
	BN_clear_free(r->priv_key);

	EC_EX_DATA_free_all_data(&r->method_data);

	explicit_bzero((void *) r, sizeof(EC_KEY));

	free(r);
}


int 
EC_KEY_generate_key(EC_KEY * eckey)
{
	int ok = 0;
	BN_CTX *ctx = NULL;
	BIGNUM *priv_key = NULL, *order = NULL;
	EC_POINT *pub_key = NULL;

	if (!eckey || !eckey->group) {
		ECerr(EC_F_EC_KEY_GENERATE_KEY, ERR_R_PASSED_NULL_PARAMETER);
		return 0;
	}
	if ((order = BN_new()) == NULL)
		goto err;
	if ((ctx = BN_CTX_new()) == NULL)
		goto err;

	if (eckey->priv_key == NULL) {
		priv_key = BN_new();
		if (priv_key == NULL)
			goto err;
	} else
		priv_key = eckey->priv_key;

	if (!EC_GROUP_get_order(eckey->group, order, ctx))
		goto err;

	do
		if (!BN_rand_range(priv_key, order))
			goto err;
	while (BN_is_zero(priv_key));

	if (eckey->pub_key == NULL) {
		pub_key = EC_POINT_new(eckey->group);
		if (pub_key == NULL)
			goto err;
	} else
		pub_key = eckey->pub_key;

	if (!EC_POINT_mul(eckey->group, pub_key, priv_key, NULL, NULL, ctx))
		goto err;

	eckey->priv_key = priv_key;
	eckey->pub_key = pub_key;

	ok = 1;

err:
	BN_free(order);
	if (pub_key != NULL && eckey->pub_key == NULL)
		EC_POINT_free(pub_key);
	if (priv_key != NULL && eckey->priv_key == NULL)
		BN_free(priv_key);
	BN_CTX_free(ctx);
	return (ok);
}


const EC_GROUP *
EC_KEY_get0_group(const EC_KEY * key)
{
	return key->group;
}


const BIGNUM *
EC_KEY_get0_private_key(const EC_KEY * key)
{
	return key->priv_key;
}


const EC_POINT *
EC_KEY_get0_public_key(const EC_KEY * key)
{
	return key->pub_key;
}


void *
EC_KEY_get_key_method_data(EC_KEY *key,
    void *(*dup_func) (void *),
    void (*free_func) (void *),
    void (*clear_free_func) (void *))
{
	void *ret;

	CRYPTO_r_lock(CRYPTO_LOCK_EC);
	ret = EC_EX_DATA_get_data(key->method_data, dup_func, free_func, clear_free_func);
	CRYPTO_r_unlock(CRYPTO_LOCK_EC);

	return ret;
}


void *
EC_KEY_insert_key_method_data(EC_KEY * key, void *data,
    void *(*dup_func) (void *),
    void (*free_func) (void *),
    void (*clear_free_func) (void *))
{
	EC_EXTRA_DATA *ex_data;

	CRYPTO_w_lock(CRYPTO_LOCK_EC);
	ex_data = EC_EX_DATA_get_data(key->method_data, dup_func, free_func, clear_free_func);
	if (ex_data == NULL)
		EC_EX_DATA_set_data(&key->method_data, data, dup_func, free_func, clear_free_func);
	CRYPTO_w_unlock(CRYPTO_LOCK_EC);

	return ex_data;
}


EC_KEY *
EC_KEY_new(void)
{
	EC_KEY *ret;

	ret = malloc(sizeof(EC_KEY));
	if (ret == NULL) {
		ECerr(EC_F_EC_KEY_NEW, ERR_R_MALLOC_FAILURE);
		return (NULL);
	}
	ret->version = 1;
	ret->flags = 0;
	ret->group = NULL;
	ret->pub_key = NULL;
	ret->priv_key = NULL;
	ret->enc_flag = 0;
	ret->conv_form = POINT_CONVERSION_UNCOMPRESSED;
	ret->references = 1;
	ret->method_data = NULL;
	return (ret);
}
EC_KEY_new_by_curve_name(int nid)
{
	EC_KEY *ret = EC_KEY_new();
	if (ret == NULL)
		return NULL;
	ret->group = EC_GROUP_new_by_curve_name(nid);
	if (ret->group == NULL) {
		EC_KEY_free(ret);
		return NULL;
	}
	return ret;
}


EC_KEY *
EC_KEY_new_by_curve_name(int nid)
{
	EC_KEY *ret = EC_KEY_new();
	if (ret == NULL)
		return NULL;
	ret->group = EC_GROUP_new_by_curve_name(nid);
	if (ret->group == NULL) {
		EC_KEY_free(ret);
		return NULL;
	}
	return ret;
}


int 
EC_METHOD_get_field_type(const EC_METHOD *meth)
{
	return meth->field_type;
}


int 
EC_POINT_add(const EC_GROUP *group, EC_POINT *r, const EC_POINT *a,
    const EC_POINT *b, BN_CTX *ctx)
{
	if (group->meth->add == 0) {
		ECerr(EC_F_EC_POINT_ADD, ERR_R_SHOULD_NOT_HAVE_BEEN_CALLED);
		return 0;
	}
	if ((group->meth != r->meth) || (r->meth != a->meth) || (a->meth != b->meth)) {
		ECerr(EC_F_EC_POINT_ADD, EC_R_INCOMPATIBLE_OBJECTS);
		return 0;
	}
	return group->meth->add(group, r, a, b, ctx);
}


void 
EC_POINT_clear_free(EC_POINT * point)
{
	if (!point)
		return;

	if (point->meth->point_clear_finish != 0)
		point->meth->point_clear_finish(point);
	else if (point->meth->point_finish != 0)
		point->meth->point_finish(point);
	explicit_bzero(point, sizeof *point);
	free(point);
}


int 
EC_POINT_copy(EC_POINT * dest, const EC_POINT * src)
{
	if (dest->meth->point_copy == 0) {
		ECerr(EC_F_EC_POINT_COPY, ERR_R_SHOULD_NOT_HAVE_BEEN_CALLED);
		return 0;
	}
	if (dest->meth != src->meth) {
		ECerr(EC_F_EC_POINT_COPY, EC_R_INCOMPATIBLE_OBJECTS);
		return 0;
	}
	if (dest == src)
		return 1;
	return dest->meth->point_copy(dest, src);
}


int 
EC_POINT_dbl(const EC_GROUP *group, EC_POINT *r, const EC_POINT *a, BN_CTX *ctx)
{
	if (group->meth->dbl == 0) {
		ECerr(EC_F_EC_POINT_DBL, ERR_R_SHOULD_NOT_HAVE_BEEN_CALLED);
		return 0;
	}
	if ((group->meth != r->meth) || (r->meth != a->meth)) {
		ECerr(EC_F_EC_POINT_DBL, EC_R_INCOMPATIBLE_OBJECTS);
		return 0;
	}
	return group->meth->dbl(group, r, a, ctx);
}


void 
EC_POINT_free(EC_POINT * point)
{
	if (!point)
		return;

	if (point->meth->point_finish != 0)
		point->meth->point_finish(point);
	free(point);
}


int 
EC_POINT_get_affine_coordinates_GFp(const EC_GROUP *group, const EC_POINT *point,
    BIGNUM *x, BIGNUM *y, BN_CTX *ctx)
{
	if (group->meth->point_get_affine_coordinates == 0) {
		ECerr(EC_F_EC_POINT_GET_AFFINE_COORDINATES_GFP, ERR_R_SHOULD_NOT_HAVE_BEEN_CALLED);
		return 0;
	}
	if (group->meth != point->meth) {
		ECerr(EC_F_EC_POINT_GET_AFFINE_COORDINATES_GFP, EC_R_INCOMPATIBLE_OBJECTS);
		return 0;
	}
	return group->meth->point_get_affine_coordinates(group, point, x, y, ctx);
}


int 
EC_POINT_invert(const EC_GROUP *group, EC_POINT *a, BN_CTX *ctx)
{
	if (group->meth->invert == 0) {
		ECerr(EC_F_EC_POINT_INVERT, ERR_R_SHOULD_NOT_HAVE_BEEN_CALLED);
		return 0;
	}
	if (group->meth != a->meth) {
		ECerr(EC_F_EC_POINT_INVERT, EC_R_INCOMPATIBLE_OBJECTS);
		return 0;
	}
	return group->meth->invert(group, a, ctx);
}


int 
EC_POINT_is_at_infinity(const EC_GROUP *group, const EC_POINT *point)
{
	if (group->meth->is_at_infinity == 0) {
		ECerr(EC_F_EC_POINT_IS_AT_INFINITY, ERR_R_SHOULD_NOT_HAVE_BEEN_CALLED);
		return 0;
	}
	if (group->meth != point->meth) {
		ECerr(EC_F_EC_POINT_IS_AT_INFINITY, EC_R_INCOMPATIBLE_OBJECTS);
		return 0;
	}
	return group->meth->is_at_infinity(group, point);
}


int 
EC_POINT_is_on_curve(const EC_GROUP * group, const EC_POINT * point, BN_CTX * ctx)
{
	if (group->meth->is_on_curve == 0) {
		ECerr(EC_F_EC_POINT_IS_ON_CURVE, ERR_R_SHOULD_NOT_HAVE_BEEN_CALLED);
		return 0;
	}
	if (group->meth != point->meth) {
		ECerr(EC_F_EC_POINT_IS_ON_CURVE, EC_R_INCOMPATIBLE_OBJECTS);
		return 0;
	}
	return group->meth->is_on_curve(group, point, ctx);
}


int 
EC_POINT_mul(const EC_GROUP *group, EC_POINT *r, const BIGNUM *g_scalar,
    const EC_POINT *point, const BIGNUM *p_scalar, BN_CTX *ctx)
{
	/* just a convenient interface to EC_POINTs_mul() */

	const EC_POINT *points[1];
	const BIGNUM *scalars[1];

	points[0] = point;
	scalars[0] = p_scalar;

	return EC_POINTs_mul(group, r, g_scalar,
	    (point != NULL && p_scalar != NULL),
	    points, scalars, ctx);
}


EC_POINT *
EC_POINT_new(const EC_GROUP * group)
{
	EC_POINT *ret;

	if (group == NULL) {
		ECerr(EC_F_EC_POINT_NEW, ERR_R_PASSED_NULL_PARAMETER);
		return NULL;
	}
	if (group->meth->point_init == 0) {
		ECerr(EC_F_EC_POINT_NEW, ERR_R_SHOULD_NOT_HAVE_BEEN_CALLED);
		return NULL;
	}
	ret = malloc(sizeof *ret);
	if (ret == NULL) {
		ECerr(EC_F_EC_POINT_NEW, ERR_R_MALLOC_FAILURE);
		return NULL;
	}
	ret->meth = group->meth;

	if (!ret->meth->point_init(ret)) {
		free(ret);
		return NULL;
	}
	return ret;
}


int 
EC_POINT_oct2point(const EC_GROUP *group, EC_POINT *point,
    const unsigned char *buf, size_t len, BN_CTX *ctx)
{
	if (group->meth->oct2point == 0 &&
	    !(group->meth->flags & EC_FLAGS_DEFAULT_OCT)) {
		ECerr(EC_F_EC_POINT_OCT2POINT, ERR_R_SHOULD_NOT_HAVE_BEEN_CALLED);
		return 0;
	}
	if (group->meth != point->meth) {
		ECerr(EC_F_EC_POINT_OCT2POINT, EC_R_INCOMPATIBLE_OBJECTS);
		return 0;
	}
	if (group->meth->flags & EC_FLAGS_DEFAULT_OCT) {
		if (group->meth->field_type == NID_X9_62_prime_field)
			return ec_GFp_simple_oct2point(group, point,
			    buf, len, ctx);
		else
#ifdef OPENSSL_NO_EC2M
		{
			ECerr(EC_F_EC_POINT_OCT2POINT, EC_R_GF2M_NOT_SUPPORTED);
			return 0;
		}
#else
			return ec_GF2m_simple_oct2point(group, point,
			    buf, len, ctx);
#endif
	}
	return group->meth->oct2point(group, point, buf, len, ctx);
}


size_t 
EC_POINT_point2oct(const EC_GROUP *group, const EC_POINT *point,
    point_conversion_form_t form,
    unsigned char *buf, size_t len, BN_CTX *ctx)
{
	if (group->meth->point2oct == 0
	    && !(group->meth->flags & EC_FLAGS_DEFAULT_OCT)) {
		ECerr(EC_F_EC_POINT_POINT2OCT, ERR_R_SHOULD_NOT_HAVE_BEEN_CALLED);
		return 0;
	}
	if (group->meth != point->meth) {
		ECerr(EC_F_EC_POINT_POINT2OCT, EC_R_INCOMPATIBLE_OBJECTS);
		return 0;
	}
	if (group->meth->flags & EC_FLAGS_DEFAULT_OCT) {
		if (group->meth->field_type == NID_X9_62_prime_field)
			return ec_GFp_simple_point2oct(group, point,
			    form, buf, len, ctx);
		else
#ifdef OPENSSL_NO_EC2M
		{
			ECerr(EC_F_EC_POINT_POINT2OCT, EC_R_GF2M_NOT_SUPPORTED);
			return 0;
		}
#else
			return ec_GF2m_simple_point2oct(group, point,
			    form, buf, len, ctx);
#endif
	}
	return group->meth->point2oct(group, point, form, buf, len, ctx);
}


int 
EC_POINT_set_affine_coordinates_GFp(const EC_GROUP *group, EC_POINT *point,
    const BIGNUM *x, const BIGNUM *y, BN_CTX *ctx)
{
	if (group->meth->point_set_affine_coordinates == 0) {
		ECerr(EC_F_EC_POINT_SET_AFFINE_COORDINATES_GFP, ERR_R_SHOULD_NOT_HAVE_BEEN_CALLED);
		return 0;
	}
	if (group->meth != point->meth) {
		ECerr(EC_F_EC_POINT_SET_AFFINE_COORDINATES_GFP, EC_R_INCOMPATIBLE_OBJECTS);
		return 0;
	}
	return group->meth->point_set_affine_coordinates(group, point, x, y, ctx);
}


int 
EC_POINT_set_Jprojective_coordinates_GFp(const EC_GROUP *group, EC_POINT *point,
    const BIGNUM *x, const BIGNUM *y, const BIGNUM *z, BN_CTX *ctx)
{
	if (group->meth->point_set_Jprojective_coordinates_GFp == 0) {
		ECerr(EC_F_EC_POINT_SET_JPROJECTIVE_COORDINATES_GFP, ERR_R_SHOULD_NOT_HAVE_BEEN_CALLED);
		return 0;
	}
	if (group->meth != point->meth) {
		ECerr(EC_F_EC_POINT_SET_JPROJECTIVE_COORDINATES_GFP, EC_R_INCOMPATIBLE_OBJECTS);
		return 0;
	}
	return group->meth->point_set_Jprojective_coordinates_GFp(group, point, x, y, z, ctx);
}


int 
EC_POINTs_make_affine(const EC_GROUP *group, size_t num, EC_POINT *points[],
    BN_CTX *ctx)
{
	size_t i;

	if (group->meth->points_make_affine == 0) {
		ECerr(EC_F_EC_POINTS_MAKE_AFFINE, ERR_R_SHOULD_NOT_HAVE_BEEN_CALLED);
		return 0;
	}
	for (i = 0; i < num; i++) {
		if (group->meth != points[i]->meth) {
			ECerr(EC_F_EC_POINTS_MAKE_AFFINE, EC_R_INCOMPATIBLE_OBJECTS);
			return 0;
		}
	}
	return group->meth->points_make_affine(group, num, points, ctx);
}


int 
EC_POINTs_mul(const EC_GROUP *group, EC_POINT *r, const BIGNUM *scalar,
    size_t num, const EC_POINT *points[], const BIGNUM *scalars[], BN_CTX *ctx)
{
	if (group->meth->mul == 0)
		/* use default */
		return ec_wNAF_mul(group, r, scalar, num, points, scalars, ctx);

	return group->meth->mul(group, r, scalar, num, points, scalars, ctx);
}


int 
ec_wNAF_mul(const EC_GROUP * group, EC_POINT * r, const BIGNUM * scalar,
    size_t num, const EC_POINT * points[], const BIGNUM * scalars[], BN_CTX * ctx)
{
	BN_CTX *new_ctx = NULL;
	const EC_POINT *generator = NULL;
	EC_POINT *tmp = NULL;
	size_t totalnum;
	size_t blocksize = 0, numblocks = 0;	/* for wNAF splitting */
	size_t pre_points_per_block = 0;
	size_t i, j;
	int k;
	int r_is_inverted = 0;
	int r_is_at_infinity = 1;
	size_t *wsize = NULL;	/* individual window sizes */
	signed char **wNAF = NULL;	/* individual wNAFs */
	signed char *tmp_wNAF = NULL;
	size_t *wNAF_len = NULL;
	size_t max_len = 0;
	size_t num_val;
	EC_POINT **val = NULL;	/* precomputation */
	EC_POINT **v;
	EC_POINT ***val_sub = NULL;	/* pointers to sub-arrays of 'val' or
					 * 'pre_comp->points' */
	const EC_PRE_COMP *pre_comp = NULL;
	int num_scalar = 0;	/* flag: will be set to 1 if 'scalar' must be
				 * treated like other scalars, i.e.
				 * precomputation is not available */
	int ret = 0;

	if (group->meth != r->meth) {
		ECerr(EC_F_EC_WNAF_MUL, EC_R_INCOMPATIBLE_OBJECTS);
		return 0;
	}
	if ((scalar == NULL) && (num == 0)) {
		return EC_POINT_set_to_infinity(group, r);
	}
	for (i = 0; i < num; i++) {
		if (group->meth != points[i]->meth) {
			ECerr(EC_F_EC_WNAF_MUL, EC_R_INCOMPATIBLE_OBJECTS);
			return 0;
		}
	}

	if (ctx == NULL) {
		ctx = new_ctx = BN_CTX_new();
		if (ctx == NULL)
			goto err;
	}
	if (scalar != NULL) {
		generator = EC_GROUP_get0_generator(group);
		if (generator == NULL) {
			ECerr(EC_F_EC_WNAF_MUL, EC_R_UNDEFINED_GENERATOR);
			goto err;
		}
		/* look if we can use precomputed multiples of generator */

		pre_comp = EC_EX_DATA_get_data(group->extra_data, ec_pre_comp_dup, ec_pre_comp_free, ec_pre_comp_clear_free);

		if (pre_comp && pre_comp->numblocks &&
		    (EC_POINT_cmp(group, generator, pre_comp->points[0], ctx) == 0)) {
			blocksize = pre_comp->blocksize;

			/*
			 * determine maximum number of blocks that wNAF
			 * splitting may yield (NB: maximum wNAF length is
			 * bit length plus one)
			 */
			numblocks = (BN_num_bits(scalar) / blocksize) + 1;

			/*
			 * we cannot use more blocks than we have
			 * precomputation for
			 */
			if (numblocks > pre_comp->numblocks)
				numblocks = pre_comp->numblocks;

			pre_points_per_block = (size_t) 1 << (pre_comp->w - 1);

			/* check that pre_comp looks sane */
			if (pre_comp->num != (pre_comp->numblocks * pre_points_per_block)) {
				ECerr(EC_F_EC_WNAF_MUL, ERR_R_INTERNAL_ERROR);
				goto err;
			}
		} else {
			/* can't use precomputation */
			pre_comp = NULL;
			numblocks = 1;
			num_scalar = 1;	/* treat 'scalar' like 'num'-th
					 * element of 'scalars' */
		}
	}
	totalnum = num + numblocks;

	/* includes space for pivot */
	wNAF = reallocarray(NULL, (totalnum + 1), sizeof wNAF[0]);
	if (wNAF == NULL) {
		ECerr(EC_F_EC_WNAF_MUL, ERR_R_MALLOC_FAILURE);
		goto err;
	}

	wNAF[0] = NULL;		/* preliminary pivot */

	wsize = reallocarray(NULL, totalnum, sizeof wsize[0]);
	wNAF_len = reallocarray(NULL, totalnum, sizeof wNAF_len[0]);
	val_sub = reallocarray(NULL, totalnum, sizeof val_sub[0]);

	if (wsize == NULL || wNAF_len == NULL || val_sub == NULL) {
		ECerr(EC_F_EC_WNAF_MUL, ERR_R_MALLOC_FAILURE);
		goto err;
	}

	/* num_val will be the total number of temporarily precomputed points */
	num_val = 0;

	for (i = 0; i < num + num_scalar; i++) {
		size_t bits;

		bits = i < num ? BN_num_bits(scalars[i]) : BN_num_bits(scalar);
		wsize[i] = EC_window_bits_for_scalar_size(bits);
		num_val += (size_t) 1 << (wsize[i] - 1);
		wNAF[i + 1] = NULL;	/* make sure we always have a pivot */
		wNAF[i] = compute_wNAF((i < num ? scalars[i] : scalar), wsize[i], &wNAF_len[i]);
		if (wNAF[i] == NULL)
			goto err;
		if (wNAF_len[i] > max_len)
			max_len = wNAF_len[i];
	}

	if (numblocks) {
		/* we go here iff scalar != NULL */

		if (pre_comp == NULL) {
			if (num_scalar != 1) {
				ECerr(EC_F_EC_WNAF_MUL, ERR_R_INTERNAL_ERROR);
				goto err;
			}
			/* we have already generated a wNAF for 'scalar' */
		} else {
			size_t tmp_len = 0;

			if (num_scalar != 0) {
				ECerr(EC_F_EC_WNAF_MUL, ERR_R_INTERNAL_ERROR);
				goto err;
			}
			/*
			 * use the window size for which we have
			 * precomputation
			 */
			wsize[num] = pre_comp->w;
			tmp_wNAF = compute_wNAF(scalar, wsize[num], &tmp_len);
			if (tmp_wNAF == NULL)
				goto err;

			if (tmp_len <= max_len) {
				/*
				 * One of the other wNAFs is at least as long
				 * as the wNAF belonging to the generator, so
				 * wNAF splitting will not buy us anything.
				 */

				numblocks = 1;
				totalnum = num + 1;	/* don't use wNAF
							 * splitting */
				wNAF[num] = tmp_wNAF;
				tmp_wNAF = NULL;
				wNAF[num + 1] = NULL;
				wNAF_len[num] = tmp_len;
				if (tmp_len > max_len)
					max_len = tmp_len;
				/*
				 * pre_comp->points starts with the points
				 * that we need here:
				 */
				val_sub[num] = pre_comp->points;
			} else {
				/*
				 * don't include tmp_wNAF directly into wNAF
				 * array - use wNAF splitting and include the
				 * blocks
				 */

				signed char *pp;
				EC_POINT **tmp_points;

				if (tmp_len < numblocks * blocksize) {
					/*
					 * possibly we can do with fewer
					 * blocks than estimated
					 */
					numblocks = (tmp_len + blocksize - 1) / blocksize;
					if (numblocks > pre_comp->numblocks) {
						ECerr(EC_F_EC_WNAF_MUL, ERR_R_INTERNAL_ERROR);
						goto err;
					}
					totalnum = num + numblocks;
				}
				/* split wNAF in 'numblocks' parts */
				pp = tmp_wNAF;
				tmp_points = pre_comp->points;

				for (i = num; i < totalnum; i++) {
					if (i < totalnum - 1) {
						wNAF_len[i] = blocksize;
						if (tmp_len < blocksize) {
							ECerr(EC_F_EC_WNAF_MUL, ERR_R_INTERNAL_ERROR);
							goto err;
						}
						tmp_len -= blocksize;
					} else
						/*
						 * last block gets whatever
						 * is left (this could be
						 * more or less than
						 * 'blocksize'!)
						 */
						wNAF_len[i] = tmp_len;

					wNAF[i + 1] = NULL;
					wNAF[i] = malloc(wNAF_len[i]);
					if (wNAF[i] == NULL) {
						ECerr(EC_F_EC_WNAF_MUL, ERR_R_MALLOC_FAILURE);
						goto err;
					}
					memcpy(wNAF[i], pp, wNAF_len[i]);
					if (wNAF_len[i] > max_len)
						max_len = wNAF_len[i];

					if (*tmp_points == NULL) {
						ECerr(EC_F_EC_WNAF_MUL, ERR_R_INTERNAL_ERROR);
						goto err;
					}
					val_sub[i] = tmp_points;
					tmp_points += pre_points_per_block;
					pp += blocksize;
				}
			}
		}
	}
	/*
	 * All points we precompute now go into a single array 'val'.
	 * 'val_sub[i]' is a pointer to the subarray for the i-th point, or
	 * to a subarray of 'pre_comp->points' if we already have
	 * precomputation.
	 */
	val = reallocarray(NULL, (num_val + 1), sizeof val[0]);
	if (val == NULL) {
		ECerr(EC_F_EC_WNAF_MUL, ERR_R_MALLOC_FAILURE);
		goto err;
	}
	val[num_val] = NULL;	/* pivot element */

	/* allocate points for precomputation */
	v = val;
	for (i = 0; i < num + num_scalar; i++) {
		val_sub[i] = v;
		for (j = 0; j < ((size_t) 1 << (wsize[i] - 1)); j++) {
			*v = EC_POINT_new(group);
			if (*v == NULL)
				goto err;
			v++;
		}
	}
	if (!(v == val + num_val)) {
		ECerr(EC_F_EC_WNAF_MUL, ERR_R_INTERNAL_ERROR);
		goto err;
	}
	if (!(tmp = EC_POINT_new(group)))
		goto err;

	/*
	 * prepare precomputed values: val_sub[i][0] :=     points[i]
	 * val_sub[i][1] := 3 * points[i] val_sub[i][2] := 5 * points[i] ...
	 */
	for (i = 0; i < num + num_scalar; i++) {
		if (i < num) {
			if (!EC_POINT_copy(val_sub[i][0], points[i]))
				goto err;
		} else {
			if (!EC_POINT_copy(val_sub[i][0], generator))
				goto err;
		}

		if (wsize[i] > 1) {
			if (!EC_POINT_dbl(group, tmp, val_sub[i][0], ctx))
				goto err;
			for (j = 1; j < ((size_t) 1 << (wsize[i] - 1)); j++) {
				if (!EC_POINT_add(group, val_sub[i][j], val_sub[i][j - 1], tmp, ctx))
					goto err;
			}
		}
	}

	if (!EC_POINTs_make_affine(group, num_val, val, ctx))
		goto err;

	r_is_at_infinity = 1;

	for (k = max_len - 1; k >= 0; k--) {
		if (!r_is_at_infinity) {
			if (!EC_POINT_dbl(group, r, r, ctx))
				goto err;
		}
		for (i = 0; i < totalnum; i++) {
			if (wNAF_len[i] > (size_t) k) {
				int digit = wNAF[i][k];
				int is_neg;

				if (digit) {
					is_neg = digit < 0;

					if (is_neg)
						digit = -digit;

					if (is_neg != r_is_inverted) {
						if (!r_is_at_infinity) {
							if (!EC_POINT_invert(group, r, ctx))
								goto err;
						}
						r_is_inverted = !r_is_inverted;
					}
					/* digit > 0 */

					if (r_is_at_infinity) {
						if (!EC_POINT_copy(r, val_sub[i][digit >> 1]))
							goto err;
						r_is_at_infinity = 0;
					} else {
						if (!EC_POINT_add(group, r, r, val_sub[i][digit >> 1], ctx))
							goto err;
					}
				}
			}
		}
	}

	if (r_is_at_infinity) {
		if (!EC_POINT_set_to_infinity(group, r))
			goto err;
	} else {
		if (r_is_inverted)
			if (!EC_POINT_invert(group, r, ctx))
				goto err;
	}

	ret = 1;

err:
	BN_CTX_free(new_ctx);
	EC_POINT_free(tmp);
	free(wsize);
	free(wNAF_len);
	free(tmp_wNAF);
	if (wNAF != NULL) {
		signed char **w;

		for (w = wNAF; *w != NULL; w++)
			free(*w);

		free(wNAF);
	}
	if (val != NULL) {
		for (v = val; *v != NULL; v++)
			EC_POINT_clear_free(*v);
		free(val);
	}
	free(val_sub);
	return ret;
}


void
enclave_main(int argc, char** argv)
{
  if (argc != 2) {
    debug_printf("Usage: ./test.sh test/openssl/libressl-pipe\n");
    sgx_exit(NULL);
  }

  // initialize the ssl library
  debug_fprintf(stdout, "Initialising SSL library and loading error strings...");
  SSL_library_init();
  SSL_load_error_strings();
  debug_fprintf(stdout, "Done\n");

  debug_fprintf(stdout, "Initializing SGX & SSL SESSION lhash...");
  if ((sgx_sess_lh = lh_SGX_SESSION_new()) == NULL ||
       (ssl_sess_lh = lh_SGX_SESSION_new()) == NULL)
          sgx_exit(NULL);
  debug_fprintf(stdout, "Done\n");

  /* Load Private Key and certificate to SSL_CTX structure */
  load_pKey_and_cert_to_ssl_ctx();

  /* initialize the commnads */
  debug_fprintf(stdout, "Registering commands...");
  register_commands();
  debug_fprintf(stdout, "Done\n");

  // pipe read loop:
  //   -> fetch in command_len -> command -> data_len -> data
  //   -> call the appriopriate command function
  while (1) {
    run_command_loop();
  }
}


ENGINE *
ENGINE_get_default_ECDH(void)
{
	return engine_table_select(&ecdh_table, dummy_nid);
}


ENGINE *
ENGINE_get_default_RSA(void)
{
	return engine_table_select(&rsa_table, dummy_nid);
}


ENGINE *
ENGINE_get_digest_engine(int nid)
{
	return engine_table_select(&digest_table, nid);
}


ENGINE *
ENGINE_get_pkey_asn1_meth_engine(int nid)
{
	return engine_table_select(&pkey_asn1_meth_table, nid);
}


ENGINE *
ENGINE_get_pkey_meth_engine(int nid)
{
	return engine_table_select(&pkey_meth_table, nid);
}


ENGINE *
engine_table_select(ENGINE_TABLE **table, int nid)
#else
ENGINE *
engine_table_select_tmp(ENGINE_TABLE **table, int nid, const char *f, int l)
#endif
{
	ENGINE *ret = NULL;
	ENGINE_PILE tmplate, *fnd = NULL;
	int initres, loop = 0;

	if (!(*table)) {
#ifdef ENGINE_TABLE_DEBUG
		fprintf(stderr, "engine_table_dbg: %s:%d, nid=%d, nothing "
		    "registered!\n", f, l, nid);
#endif
		return NULL;
	}
	ERR_set_mark();
	CRYPTO_w_lock(CRYPTO_LOCK_ENGINE);
	/* Check again inside the lock otherwise we could race against cleanup
	 * operations. But don't worry about a fprintf(stderr). */
	if (!int_table_check(table, 0))
		goto end;
	tmplate.nid = nid;
	fnd = lh_ENGINE_PILE_retrieve(&(*table)->piles, &tmplate);
	if (!fnd)
		goto end;
	if (fnd->funct && engine_unlocked_init(fnd->funct)) {
#ifdef ENGINE_TABLE_DEBUG
		fprintf(stderr, "engine_table_dbg: %s:%d, nid=%d, using "
		    "ENGINE '%s' cached\n", f, l, nid, fnd->funct->id);
#endif
		ret = fnd->funct;
		goto end;
	}
	if (fnd->uptodate) {
		ret = fnd->funct;
		goto end;
	}
trynext:
	ret = sk_ENGINE_value(fnd->sk, loop++);
	if (!ret) {
#ifdef ENGINE_TABLE_DEBUG
		fprintf(stderr, "engine_table_dbg: %s:%d, nid=%d, no "
		    "registered implementations would initialise\n", f, l, nid);
#endif
		goto end;
	}
	/* Try to initialise the ENGINE? */
	if ((ret->funct_ref > 0) || !(table_flags & ENGINE_TABLE_FLAG_NOINIT))
		initres = engine_unlocked_init(ret);
	else
		initres = 0;
	if (initres) {
		/* Update 'funct' */
		if ((fnd->funct != ret) && engine_unlocked_init(ret)) {
			/* If there was a previous default we release it. */
			if (fnd->funct)
				engine_unlocked_finish(fnd->funct, 0);
			fnd->funct = ret;
#ifdef ENGINE_TABLE_DEBUG
			fprintf(stderr, "engine_table_dbg: %s:%d, nid=%d, "
			    "setting default to '%s'\n", f, l, nid, ret->id);
#endif
		}
#ifdef ENGINE_TABLE_DEBUG
		fprintf(stderr, "engine_table_dbg: %s:%d, nid=%d, using "
		    "newly initialised '%s'\n", f, l, nid, ret->id);
#endif
		goto end;
	}
	goto trynext;
end:
	/* If it failed, it is unlikely to succeed again until some future
	 * registrations have taken place. In all cases, we cache. */
	if (fnd)
		fnd->uptodate = 1;
#ifdef ENGINE_TABLE_DEBUG
	if (ret)
		fprintf(stderr, "engine_table_dbg: %s:%d, nid=%d, caching "
		    "ENGINE '%s'\n", f, l, nid, ret->id);
	else
		fprintf(stderr, "engine_table_dbg: %s:%d, nid=%d, caching "
		    "'no matching ENGINE'\n", f, l, nid);
#endif
	CRYPTO_w_unlock(CRYPTO_LOCK_ENGINE);
	/* Whatever happened, any failed init()s are not failures in this
	 * context, so clear our error state. */
	ERR_pop_to_mark();
	return ret;
}


void
ERR_clear_error(void)
{
	int i;
	ERR_STATE *es;

	es = ERR_get_state();

	for (i = 0; i < ERR_NUM_ERRORS; i++) {
		err_clear(es, i);
	}
	es->top = es->bottom = 0;
}


static void
err_fns_check(void)
{
	if (err_fns)
		return;

	CRYPTO_w_lock(CRYPTO_LOCK_ERR);
	if (!err_fns)
		err_fns = &err_defaults;
	CRYPTO_w_unlock(CRYPTO_LOCK_ERR);
}


const char *
ERR_func_error_string(unsigned long e)
{
	ERR_STRING_DATA d, *p;
	unsigned long l, f;

	err_fns_check();
	l = ERR_GET_LIB(e);
	f = ERR_GET_FUNC(e);
	d.error = ERR_PACK(l, f, 0);
	p = ERRFN(err_get_item)(&d);
	return ((p == NULL) ? NULL : p->string);
}


ERR_STATE *
ERR_get_state(void)
{
	static ERR_STATE fallback;
	ERR_STATE *ret, tmp, *tmpp = NULL;
	int i;
	CRYPTO_THREADID tid;

	err_fns_check();
	CRYPTO_THREADID_current(&tid);
	CRYPTO_THREADID_cpy(&tmp.tid, &tid);
	ret = ERRFN(thread_get_item)(&tmp);

	/* ret == the error state, if NULL, make a new one */
	if (ret == NULL) {
		ret = malloc(sizeof(ERR_STATE));
		if (ret == NULL)
			return (&fallback);
		CRYPTO_THREADID_cpy(&ret->tid, &tid);
		ret->top = 0;
		ret->bottom = 0;
		for (i = 0; i < ERR_NUM_ERRORS; i++) {
			ret->err_data[i] = NULL;
			ret->err_data_flags[i] = 0;
		}
		tmpp = ERRFN(thread_set_item)(ret);
		/* To check if insertion failed, do a get. */
		if (ERRFN(thread_get_item)(ret) != ret) {
			ERR_STATE_free(ret); /* could not insert it */
			return (&fallback);
		}
		/* If a race occured in this function and we came second, tmpp
		 * is the first one that we just replaced. */
		if (tmpp)
			ERR_STATE_free(tmpp);
	}
	return ret;
}


void
ERR_load_ASN1_strings(void)
{
#ifndef OPENSSL_NO_ERR
	if (ERR_func_error_string(ASN1_str_functs[0].error) == NULL) {
		ERR_load_strings(0, ASN1_str_functs);
		ERR_load_strings(0, ASN1_str_reasons);
	}
#endif
}


void
ERR_load_BIO_strings(void)
{
#ifndef OPENSSL_NO_ERR
	if (ERR_func_error_string(BIO_str_functs[0].error) == NULL) {
		ERR_load_strings(0, BIO_str_functs);
		ERR_load_strings(0, BIO_str_reasons);
	}
#endif
}


void
ERR_load_BN_strings(void)
{
#ifndef OPENSSL_NO_ERR
	if (ERR_func_error_string(BN_str_functs[0].error) == NULL) {
		ERR_load_strings(0, BN_str_functs);
		ERR_load_strings(0, BN_str_reasons);
	}
#endif
}


void
ERR_load_BUF_strings(void)
{
#ifndef OPENSSL_NO_ERR
	if (ERR_func_error_string(BUF_str_functs[0].error) == NULL) {
		ERR_load_strings(0, BUF_str_functs);
		ERR_load_strings(0, BUF_str_reasons);
	}
#endif
}


void
ERR_load_CONF_strings(void)
{
#ifndef OPENSSL_NO_ERR
	if (ERR_func_error_string(CONF_str_functs[0].error) == NULL) {
		ERR_load_strings(0, CONF_str_functs);
		ERR_load_strings(0, CONF_str_reasons);
	}
#endif
}


void
ERR_load_crypto_strings(void)
{
#ifndef OPENSSL_NO_ERR
	ERR_load_ERR_strings(); /* include error strings for SYSerr */
	ERR_load_BN_strings();
#ifndef OPENSSL_NO_RSA
	ERR_load_RSA_strings();
#endif
#ifndef OPENSSL_NO_DH
	ERR_load_DH_strings();
#endif
	ERR_load_EVP_strings();
	ERR_load_BUF_strings();
	ERR_load_OBJ_strings();
	ERR_load_PEM_strings();
#ifndef OPENSSL_NO_DSA
	ERR_load_DSA_strings();
#endif
	ERR_load_X509_strings();
	ERR_load_ASN1_strings();
	ERR_load_CONF_strings();
	ERR_load_CRYPTO_strings();
#ifndef OPENSSL_NO_EC
	ERR_load_EC_strings();
#endif
#ifndef OPENSSL_NO_ECDSA
	ERR_load_ECDSA_strings();
#endif
#ifndef OPENSSL_NO_ECDH
	ERR_load_ECDH_strings();
#endif
	/* skip ERR_load_SSL_strings() because it is not in this library */
	ERR_load_BIO_strings();
	ERR_load_PKCS7_strings();
	ERR_load_X509V3_strings();
	ERR_load_PKCS12_strings();
	ERR_load_RAND_strings();
	ERR_load_DSO_strings();
	ERR_load_TS_strings();
#ifndef OPENSSL_NO_ENGINE
	ERR_load_ENGINE_strings();
#endif
	ERR_load_OCSP_strings();
	ERR_load_UI_strings();
#ifndef OPENSSL_NO_CMS
	ERR_load_CMS_strings();
#endif
#ifndef OPENSSL_NO_GOST
	ERR_load_GOST_strings();
#endif
#endif
}


void
ERR_load_CRYPTO_strings(void)
{
#ifndef OPENSSL_NO_ERR
	if (ERR_func_error_string(CRYPTO_str_functs[0].error) == NULL) {
		ERR_load_strings(0, CRYPTO_str_functs);
		ERR_load_strings(0, CRYPTO_str_reasons);
	}
#endif
}


void
ERR_load_DSO_strings(void)
{
#ifndef OPENSSL_NO_ERR
	if (ERR_func_error_string(DSO_str_functs[0].error) == NULL) {
		ERR_load_strings(0, DSO_str_functs);
		ERR_load_strings(0, DSO_str_reasons);
	}
#endif
}


void
ERR_load_ECDH_strings(void)
{
#ifndef OPENSSL_NO_ERR
	if (ERR_func_error_string(ECDH_str_functs[0].error) == NULL) {
		ERR_load_strings(0, ECDH_str_functs);
		ERR_load_strings(0, ECDH_str_reasons);
	}
#endif
}


void
ERR_load_ECDSA_strings(void)
{
#ifndef OPENSSL_NO_ERR
	if (ERR_func_error_string(ECDSA_str_functs[0].error) == NULL) {
		ERR_load_strings(0, ECDSA_str_functs);
		ERR_load_strings(0, ECDSA_str_reasons);
	}
#endif
}


void 
ERR_load_EC_strings(void)
{
#ifndef OPENSSL_NO_ERR

	if (ERR_func_error_string(EC_str_functs[0].error) == NULL) {
		ERR_load_strings(0, EC_str_functs);
		ERR_load_strings(0, EC_str_reasons);
	}
#endif
}


void
ERR_load_ENGINE_strings(void)
{
#ifndef OPENSSL_NO_ERR
	if (ERR_func_error_string(ENGINE_str_functs[0].error) == NULL) {
		ERR_load_strings(0, ENGINE_str_functs);
		ERR_load_strings(0, ENGINE_str_reasons);
	}
#endif
}


void
ERR_load_ERR_strings(void)
{
	err_fns_check();
#ifndef OPENSSL_NO_ERR
	err_load_strings(0, ERR_str_libraries);
	err_load_strings(0, ERR_str_reasons);
	err_load_strings(ERR_LIB_SYS, ERR_str_functs);
	build_SYS_str_reasons();
	err_load_strings(ERR_LIB_SYS, SYS_str_reasons);
#endif
}


void
ERR_load_EVP_strings(void)
{
#ifndef OPENSSL_NO_ERR
	if (ERR_func_error_string(EVP_str_functs[0].error) == NULL) {
		ERR_load_strings(0, EVP_str_functs);
		ERR_load_strings(0, EVP_str_reasons);
	}
#endif
}


void
ERR_load_OBJ_strings(void)
{
#ifndef OPENSSL_NO_ERR
	if (ERR_func_error_string(OBJ_str_functs[0].error) == NULL) {
		ERR_load_strings(0, OBJ_str_functs);
		ERR_load_strings(0, OBJ_str_reasons);
	}
#endif
}


void
ERR_load_OCSP_strings(void)
{
#ifndef OPENSSL_NO_ERR
	if (ERR_func_error_string(OCSP_str_functs[0].error) == NULL) {
		ERR_load_strings(0, OCSP_str_functs);
		ERR_load_strings(0, OCSP_str_reasons);
	}
#endif
}


void
ERR_load_PEM_strings(void)
{
#ifndef OPENSSL_NO_ERR
	if (ERR_func_error_string(PEM_str_functs[0].error) == NULL) {
		ERR_load_strings(0, PEM_str_functs);
		ERR_load_strings(0, PEM_str_reasons);
	}
#endif
}


void
ERR_load_PKCS12_strings(void)
{
#ifndef OPENSSL_NO_ERR
	if (ERR_func_error_string(PKCS12_str_functs[0].error) == NULL) {
		ERR_load_strings(0, PKCS12_str_functs);
		ERR_load_strings(0, PKCS12_str_reasons);
	}
#endif
}


void
ERR_load_PKCS7_strings(void)
{
#ifndef OPENSSL_NO_ERR
	if (ERR_func_error_string(PKCS7_str_functs[0].error) == NULL) {
		ERR_load_strings(0, PKCS7_str_functs);
		ERR_load_strings(0, PKCS7_str_reasons);
	}
#endif
}


void
ERR_load_RAND_strings(void)
{
#ifndef OPENSSL_NO_ERR
	if (ERR_func_error_string(RAND_str_functs[0].error) == NULL) {
		ERR_load_strings(0, RAND_str_functs);
		ERR_load_strings(0, RAND_str_reasons);
	}
#endif
}


void
ERR_load_RSA_strings(void)
{
#ifndef OPENSSL_NO_ERR
	if (ERR_func_error_string(RSA_str_functs[0].error) == NULL) {
		ERR_load_strings(0, RSA_str_functs);
		ERR_load_strings(0, RSA_str_reasons);
	}
#endif
}


void
ERR_load_SSL_strings(void)
{
#ifndef OPENSSL_NO_ERR

	if (ERR_func_error_string(SSL_str_functs[0].error) == NULL) {
		ERR_load_strings(0, SSL_str_functs);
		ERR_load_strings(0, SSL_str_reasons);
	}
#endif
}


static void
err_load_strings(int lib, ERR_STRING_DATA *str)
{
	while (str->error) {
		if (lib)
			str->error |= ERR_PACK(lib, 0, 0);
		ERRFN(err_set_item)(str);
		str++;
	}
}


void
ERR_load_strings(int lib, ERR_STRING_DATA *str)
{
	ERR_load_ERR_strings();
	err_load_strings(lib, str);
}


void
ERR_load_TS_strings(void)
{
#ifndef OPENSSL_NO_ERR
	if (ERR_func_error_string(TS_str_functs[0].error) == NULL) {
		ERR_load_strings(0, TS_str_functs);
		ERR_load_strings(0, TS_str_reasons);
	}
#endif
}


void
ERR_load_UI_strings(void)
{
#ifndef OPENSSL_NO_ERR
	if (ERR_func_error_string(UI_str_functs[0].error) == NULL) {
		ERR_load_strings(0, UI_str_functs);
		ERR_load_strings(0, UI_str_reasons);
	}
#endif
}


void
ERR_load_X509_strings(void)
{
#ifndef OPENSSL_NO_ERR
	if (ERR_func_error_string(X509_str_functs[0].error) == NULL) {
		ERR_load_strings(0, X509_str_functs);
		ERR_load_strings(0, X509_str_reasons);
	}
#endif
}


void
ERR_load_X509V3_strings(void)
{
#ifndef OPENSSL_NO_ERR
	if (ERR_func_error_string(X509V3_str_functs[0].error) == NULL) {
		ERR_load_strings(0, X509V3_str_functs);
		ERR_load_strings(0, X509V3_str_reasons);
	}
#endif
}


static int
err_state_cmp(const ERR_STATE *a, const ERR_STATE *b)
{
	return CRYPTO_THREADID_cmp(&a->tid, &b->tid);
}


static unsigned long
err_state_hash(const ERR_STATE *a)
{
	return CRYPTO_THREADID_hash(&a->tid) * 13;
}


static int
err_string_data_cmp(const ERR_STRING_DATA *a, const ERR_STRING_DATA *b)
{
	return (int)(a->error - b->error);
}


static unsigned long
err_string_data_hash(const ERR_STRING_DATA *a)
{
	unsigned long ret, l;

	l = a->error;
	ret = l^ERR_GET_LIB(l)^ERR_GET_FUNC(l);
	return (ret^ret % 19*13);
}


int
EVP_add_cipher(const EVP_CIPHER *c)
{
	int r;

	if (c == NULL)
		return 0;

	OPENSSL_init();

	r = OBJ_NAME_add(OBJ_nid2sn(c->nid), OBJ_NAME_TYPE_CIPHER_METH,
	    (const char *)c);
	if (r == 0)
		return (0);
	check_defer(c->nid);
	r = OBJ_NAME_add(OBJ_nid2ln(c->nid), OBJ_NAME_TYPE_CIPHER_METH,
	    (const char *)c);
	return (r);
}


int
EVP_add_digest(const EVP_MD *md)
{
	int r;
	const char *name;

	OPENSSL_init();

	name = OBJ_nid2sn(md->type);
	r = OBJ_NAME_add(name, OBJ_NAME_TYPE_MD_METH, (const char *)md);
	if (r == 0)
		return (0);
	check_defer(md->type);
	r = OBJ_NAME_add(OBJ_nid2ln(md->type), OBJ_NAME_TYPE_MD_METH,
	    (const char *)md);
	if (r == 0)
		return (0);

	if (md->pkey_type && md->type != md->pkey_type) {
		r = OBJ_NAME_add(OBJ_nid2sn(md->pkey_type),
		    OBJ_NAME_TYPE_MD_METH|OBJ_NAME_ALIAS, name);
		if (r == 0)
			return (0);
		check_defer(md->pkey_type);
		r = OBJ_NAME_add(OBJ_nid2ln(md->pkey_type),
		    OBJ_NAME_TYPE_MD_METH|OBJ_NAME_ALIAS, name);
	}
	return (r);
}


const EVP_AEAD *
EVP_aead_aes_256_gcm(void)
{
	return &aead_aes_256_gcm;
}


int
EVP_AEAD_CTX_init(EVP_AEAD_CTX *ctx, const EVP_AEAD *aead,
    const unsigned char *key, size_t key_len, size_t tag_len, ENGINE *impl)
{
	ctx->aead = aead;
	if (key_len != aead->key_len) {
		EVPerr(EVP_F_EVP_AEAD_CTX_INIT, EVP_R_UNSUPPORTED_KEY_SIZE);
		return 0;
	}
	return aead->init(ctx, key, key_len, tag_len);
}


int
EVP_AEAD_CTX_open(const EVP_AEAD_CTX *ctx, unsigned char *out, size_t *out_len,
    size_t max_out_len, const unsigned char *nonce, size_t nonce_len,
    const unsigned char *in, size_t in_len, const unsigned char *ad,
    size_t ad_len)
{
	if (!check_alias(in, in_len, out)) {
		EVPerr(EVP_F_AEAD_CTX_OPEN, EVP_R_OUTPUT_ALIASES_INPUT);
		goto error;
	}

	if (ctx->aead->open(ctx, out, out_len, max_out_len, nonce, nonce_len,
	    in, in_len, ad, ad_len)) {
		return 1;
	}

error:
	/* In the event of an error, clear the output buffer so that a caller
	 * that doesn't check the return value doesn't try and process bad
	 * data. */
	memset(out, 0, max_out_len);
	*out_len = 0;
	return 0;
}


int
EVP_AEAD_CTX_seal(const EVP_AEAD_CTX *ctx, unsigned char *out, size_t *out_len,
    size_t max_out_len, const unsigned char *nonce, size_t nonce_len,
    const unsigned char *in, size_t in_len, const unsigned char *ad,
    size_t ad_len)
{
	size_t possible_out_len = in_len + ctx->aead->overhead;

	/* Overflow. */
	if (possible_out_len < in_len) {
		EVPerr(EVP_F_AEAD_CTX_SEAL, EVP_R_TOO_LARGE);
		goto error;
	}

	if (!check_alias(in, in_len, out)) {
		EVPerr(EVP_F_AEAD_CTX_SEAL, EVP_R_OUTPUT_ALIASES_INPUT);
		goto error;
	}

	if (ctx->aead->seal(ctx, out, out_len, max_out_len, nonce, nonce_len,
	    in, in_len, ad, ad_len)) {
		return 1;
	}

error:
	/* In the event of an error, clear the output buffer so that a caller
	 * that doesn't check the return value doesn't send raw data. */
	memset(out, 0, max_out_len);
	*out_len = 0;
	return 0;
}


size_t
EVP_AEAD_key_length(const EVP_AEAD *aead)
{
	return aead->key_len;
}


size_t
EVP_AEAD_max_overhead(const EVP_AEAD *aead)
{
	return aead->overhead;
}


size_t
EVP_AEAD_nonce_length(const EVP_AEAD *aead)
{
	return aead->nonce_len;
}


const EVP_CIPHER *
EVP_aes_128_cbc_hmac_sha1(void)
{
	return OPENSSL_ia32cap_P[1] & AESNI_CAPABLE ?
	    &aesni_128_cbc_hmac_sha1_cipher : NULL;
}
EVP_aes_128_cbc_hmac_sha1(void)
{
	return NULL;
}


const EVP_CIPHER *
EVP_aes_256_cbc_hmac_sha1(void)
{
	return OPENSSL_ia32cap_P[1] & AESNI_CAPABLE ?
	    &aesni_256_cbc_hmac_sha1_cipher : NULL;
}
EVP_aes_256_cbc_hmac_sha1(void)
{
	    return NULL;
}


void
EVP_CIPHER_CTX_free(EVP_CIPHER_CTX *ctx)
{
	if (ctx) {
		EVP_CIPHER_CTX_cleanup(ctx);
		free(ctx);
	}
}


int
EVP_DecodeBlock(unsigned char *t, const unsigned char *f, int n)
{
	int i, ret = 0, a, b, c, d;
	unsigned long l;

	/* trim white space from the start of the line. */
	while ((conv_ascii2bin(*f) == B64_WS) && (n > 0)) {
		f++;
		n--;
	}

	/* strip off stuff at the end of the line
	 * ascii2bin values B64_WS, B64_EOLN, B64_EOLN and B64_EOF */
	while ((n > 3) && (B64_NOT_BASE64(conv_ascii2bin(f[n - 1]))))
		n--;

	if (n % 4 != 0)
		return (-1);

	for (i = 0; i < n; i += 4) {
		a = conv_ascii2bin(*(f++));
		b = conv_ascii2bin(*(f++));
		c = conv_ascii2bin(*(f++));
		d = conv_ascii2bin(*(f++));
		if ((a & 0x80) || (b & 0x80) ||
		    (c & 0x80) || (d & 0x80))
			return (-1);
		l = ((((unsigned long)a) << 18L) |
		    (((unsigned long)b) << 12L) |
		    (((unsigned long)c) << 6L) |
		    (((unsigned long)d)));
		*(t++) = (unsigned char)(l >> 16L) & 0xff;
		*(t++) = (unsigned char)(l >> 8L) & 0xff;
		*(t++) = (unsigned char)(l) & 0xff;
		ret += 3;
	}
	return (ret);
}


int
EVP_DecodeFinal(EVP_ENCODE_CTX *ctx, unsigned char *out, int *outl)
{
	int i;

	*outl = 0;
	if (ctx->num != 0) {
		i = EVP_DecodeBlock(out, ctx->enc_data, ctx->num);
		if (i < 0)
			return (-1);
		ctx->num = 0;
		*outl = i;
		return (1);
	} else
		return (1);
}


void
EVP_DecodeInit(EVP_ENCODE_CTX *ctx)
{
	ctx->length = 30;
	ctx->num = 0;
	ctx->line_num = 0;
	ctx->expect_nl = 0;
}


int
EVP_DecodeUpdate(EVP_ENCODE_CTX *ctx, unsigned char *out, int *outl,
    const unsigned char *in, int inl)
{
	int seof = -1, eof = 0, rv = -1, ret = 0, i, v, tmp, n, ln, exp_nl;
	unsigned char *d;

	n = ctx->num;
	d = ctx->enc_data;
	ln = ctx->line_num;
	exp_nl = ctx->expect_nl;

	/* last line of input. */
	if ((inl == 0) || ((n == 0) && (conv_ascii2bin(in[0]) == B64_EOF))) {
		rv = 0;
		goto end;
	}

	/* We parse the input data */
	for (i = 0; i < inl; i++) {
		/* If the current line is > 80 characters, scream alot */
		if (ln >= 80) {
			rv = -1;
			goto end;
		}

		/* Get char and put it into the buffer */
		tmp= *(in++);
		v = conv_ascii2bin(tmp);
		/* only save the good data :-) */
		if (!B64_NOT_BASE64(v)) {
			OPENSSL_assert(n < (int)sizeof(ctx->enc_data));
			d[n++] = tmp;
			ln++;
		} else if (v == B64_ERROR) {
			rv = -1;
			goto end;
		}

		/* There should not be base64 data after padding. */
		if (eof && tmp != '=' && tmp != '\r' && tmp != '\n' &&
		    v != B64_EOF) {
			rv = -1;
			goto end;
		}

		/* have we seen a '=' which is 'definitely' the last
		 * input line.  seof will point to the character that
		 * holds it. and eof will hold how many characters to
		 * chop off. */
		if (tmp == '=') {
			if (seof == -1)
				seof = n;
			eof++;
		}

		/* There should be no more than two padding markers. */
		if (eof > 2) {
			rv = -1;
			goto end;
		}

		if (v == B64_CR) {
			ln = 0;
			if (exp_nl)
				continue;
		}

		/* eoln */
		if (v == B64_EOLN) {
			ln = 0;
			if (exp_nl) {
				exp_nl = 0;
				continue;
			}
		}
		exp_nl = 0;

		/* If we are at the end of input and it looks like a
		 * line, process it. */
		if (((i + 1) == inl) && (((n&3) == 0) || eof)) {
			v = B64_EOF;
			/* In case things were given us in really small
			   records (so two '=' were given in separate
			   updates), eof may contain the incorrect number
			   of ending bytes to skip, so let's redo the count */
			eof = 0;
			if (d[n-1] == '=')
				eof++;
			if (d[n-2] == '=')
				eof++;
			/* There will never be more than two '=' */
		}

		if ((v == B64_EOF && (n&3) == 0) || (n >= 64)) {
			/* This is needed to work correctly on 64 byte input
			 * lines.  We process the line and then need to
			 * accept the '\n' */
			if ((v != B64_EOF) && (n >= 64))
				exp_nl = 1;
			if (n > 0) {
				v = EVP_DecodeBlock(out, d, n);
				n = 0;
				if (v < 0) {
					rv = 0;
					goto end;
				}
				ret += (v - eof);
			} else {
				eof = 1;
				v = 0;
			}

			/* This is the case where we have had a short
			 * but valid input line */
			if ((v < ctx->length) && eof) {
				rv = 0;
				goto end;
			} else
				ctx->length = v;

			if (seof >= 0) {
				rv = 0;
				goto end;
			}
			out += v;
		}
	}
	rv = 1;

end:
	*outl = ret;
	ctx->num = n;
	ctx->line_num = ln;
	ctx->expect_nl = exp_nl;
	return (rv);
}


int
EVP_DigestFinal_ex(EVP_MD_CTX *ctx, unsigned char *md, unsigned int *size)
{
	int ret;

	if ((size_t)ctx->digest->md_size > EVP_MAX_MD_SIZE) {
		EVPerr(EVP_F_EVP_DIGESTFINAL_EX, EVP_R_TOO_LARGE);
		return 0;
	}
	ret = ctx->digest->final(ctx, md);
	if (size != NULL)
		*size = ctx->digest->md_size;
	if (ctx->digest->cleanup) {
		ctx->digest->cleanup(ctx);
		EVP_MD_CTX_set_flags(ctx, EVP_MD_CTX_FLAG_CLEANED);
	}
	memset(ctx->md_data, 0, ctx->digest->ctx_size);
	return ret;
}


int
EVP_DigestInit_ex(EVP_MD_CTX *ctx, const EVP_MD *type, ENGINE *impl)
{
	EVP_MD_CTX_clear_flags(ctx, EVP_MD_CTX_FLAG_CLEANED);

#ifndef OPENSSL_NO_ENGINE
	/* Whether it's nice or not, "Inits" can be used on "Final"'d contexts
	 * so this context may already have an ENGINE! Try to avoid releasing
	 * the previous handle, re-querying for an ENGINE, and having a
	 * reinitialisation, when it may all be unecessary. */
	if (ctx->engine && ctx->digest && (!type ||
	    (type && (type->type == ctx->digest->type))))
		goto skip_to_init;
	if (type) {
		/* Ensure an ENGINE left lying around from last time is cleared
		 * (the previous check attempted to avoid this if the same
		 * ENGINE and EVP_MD could be used). */
		if (ctx->engine)
			ENGINE_finish(ctx->engine);
		if (impl) {
			if (!ENGINE_init(impl)) {
				EVPerr(EVP_F_EVP_DIGESTINIT_EX,
				    EVP_R_INITIALIZATION_ERROR);
				return 0;
			}
		} else
			/* Ask if an ENGINE is reserved for this job */
			impl = ENGINE_get_digest_engine(type->type);
		if (impl) {
			/* There's an ENGINE for this job ... (apparently) */
			const EVP_MD *d = ENGINE_get_digest(impl, type->type);
			if (!d) {
				/* Same comment from evp_enc.c */
				EVPerr(EVP_F_EVP_DIGESTINIT_EX,
				    EVP_R_INITIALIZATION_ERROR);
				ENGINE_finish(impl);
				return 0;
			}
			/* We'll use the ENGINE's private digest definition */
			type = d;
			/* Store the ENGINE functional reference so we know
			 * 'type' came from an ENGINE and we need to release
			 * it when done. */
			ctx->engine = impl;
		} else
			ctx->engine = NULL;
	} else if (!ctx->digest) {
		EVPerr(EVP_F_EVP_DIGESTINIT_EX, EVP_R_NO_DIGEST_SET);
		return 0;
	}
#endif
	if (ctx->digest != type) {
		if (ctx->digest && ctx->digest->ctx_size && ctx->md_data &&
		    !EVP_MD_CTX_test_flags(ctx, EVP_MD_CTX_FLAG_REUSE)) {
			explicit_bzero(ctx->md_data, ctx->digest->ctx_size);
			free(ctx->md_data);
			ctx->md_data = NULL;
		}
		ctx->digest = type;
		if (!(ctx->flags & EVP_MD_CTX_FLAG_NO_INIT) && type->ctx_size) {
			ctx->update = type->update;
			ctx->md_data = malloc(type->ctx_size);
			if (ctx->md_data == NULL) {
				EVP_PKEY_CTX_free(ctx->pctx);
				ctx->pctx = NULL;
				EVPerr(EVP_F_EVP_DIGESTINIT_EX,
				    ERR_R_MALLOC_FAILURE);
				return 0;
			}
		}
	}
#ifndef OPENSSL_NO_ENGINE
skip_to_init:
#endif
	if (ctx->pctx) {
		int r;
		r = EVP_PKEY_CTX_ctrl(ctx->pctx, -1, EVP_PKEY_OP_TYPE_SIG,
		    EVP_PKEY_CTRL_DIGESTINIT, 0, ctx);
		if (r <= 0 && (r != -2))
			return 0;
	}
	if (ctx->flags & EVP_MD_CTX_FLAG_NO_INIT)
		return 1;
	return ctx->digest->init(ctx);
}


int
EVP_DigestSignFinal(EVP_MD_CTX *ctx, unsigned char *sigret, size_t *siglen)
{
	int sctx, r = 0;

	if (ctx->pctx->pmeth->signctx)
		sctx = 1;
	else
		sctx = 0;
	if (sigret) {
		EVP_MD_CTX tmp_ctx;
		unsigned char md[EVP_MAX_MD_SIZE];
		unsigned int mdlen = 0;
		EVP_MD_CTX_init(&tmp_ctx);
		if (!EVP_MD_CTX_copy_ex(&tmp_ctx, ctx))
			return 0;
		if (sctx)
			r = tmp_ctx.pctx->pmeth->signctx(tmp_ctx.pctx,
			    sigret, siglen, &tmp_ctx);
		else
			r = EVP_DigestFinal_ex(&tmp_ctx, md, &mdlen);
		EVP_MD_CTX_cleanup(&tmp_ctx);
		if (sctx || !r)
			return r;
		if (EVP_PKEY_sign(ctx->pctx, sigret, siglen, md, mdlen) <= 0)
			return 0;
	} else {
		if (sctx) {
			if (ctx->pctx->pmeth->signctx(ctx->pctx, sigret,
			    siglen, ctx) <= 0)
				return 0;
		} else {
			int s = EVP_MD_size(ctx->digest);
			if (s < 0 || EVP_PKEY_sign(ctx->pctx, sigret, siglen,
			    NULL, s) <= 0)
				return 0;
		}
	}
	return 1;
}


int
EVP_DigestSignInit(EVP_MD_CTX *ctx, EVP_PKEY_CTX **pctx, const EVP_MD *type,
    ENGINE *e, EVP_PKEY *pkey)
{
	return do_sigver_init(ctx, pctx, type, e, pkey, 0);
}


int
EVP_DigestUpdate(EVP_MD_CTX *ctx, const void *data, size_t count)
{
	return ctx->update(ctx, data, count);
}


const EVP_MD *
EVP_dss1(void)
{
	return (&dss1_md);
}


const EVP_MD *
EVP_ecdsa(void)
{
	return (&ecdsa_md);
}


const EVP_CIPHER *
EVP_get_cipherbyname(const char *name)
{
	const EVP_CIPHER *cp;

	cp = (const EVP_CIPHER *)OBJ_NAME_get(name, OBJ_NAME_TYPE_CIPHER_METH);
	return (cp);
}


const EVP_MD *
EVP_get_digestbyname(const char *name)
{
	const EVP_MD *cp;

	cp = (const EVP_MD *)OBJ_NAME_get(name, OBJ_NAME_TYPE_MD_METH);
	return (cp);
}


const EVP_MD *
EVP_gost2814789imit(void)
{
	return (&gost2814789imit_md);
}


const EVP_MD *
EVP_gostr341194(void)
{
	return (&gostr341194_md);
}


const EVP_MD *
EVP_md5(void)
{
	return (&md5_md);
}


int
EVP_MD_block_size(const EVP_MD *md)
{
	return md->block_size;
}


int
EVP_MD_CTX_cleanup(EVP_MD_CTX *ctx)
{
	/* Don't assume ctx->md_data was cleaned in EVP_Digest_Final,
	 * because sometimes only copies of the context are ever finalised.
	 */
	if (ctx->digest && ctx->digest->cleanup &&
	    !EVP_MD_CTX_test_flags(ctx, EVP_MD_CTX_FLAG_CLEANED))
		ctx->digest->cleanup(ctx);
	if (ctx->digest && ctx->digest->ctx_size && ctx->md_data &&
	    !EVP_MD_CTX_test_flags(ctx, EVP_MD_CTX_FLAG_REUSE)) {
		explicit_bzero(ctx->md_data, ctx->digest->ctx_size);
		free(ctx->md_data);
	}
	EVP_PKEY_CTX_free(ctx->pctx);
#ifndef OPENSSL_NO_ENGINE
	if (ctx->engine)
		/* The EVP_MD we used belongs to an ENGINE, release the
		 * functional reference we held for this reason. */
		ENGINE_finish(ctx->engine);
#endif
	memset(ctx, 0, sizeof *ctx);

	return 1;
}


void
EVP_MD_CTX_clear_flags(EVP_MD_CTX *ctx, int flags)
{
	ctx->flags &= ~flags;
}


int
EVP_MD_CTX_copy(EVP_MD_CTX *out, const EVP_MD_CTX *in)
{
	EVP_MD_CTX_init(out);
	return EVP_MD_CTX_copy_ex(out, in);
}
EVP_MD_CTX_copy_ex(EVP_MD_CTX *out, const EVP_MD_CTX *in)
{
	unsigned char *tmp_buf;

	if ((in == NULL) || (in->digest == NULL)) {
		EVPerr(EVP_F_EVP_MD_CTX_COPY_EX, EVP_R_INPUT_NOT_INITIALIZED);
		return 0;
	}
#ifndef OPENSSL_NO_ENGINE
	/* Make sure it's safe to copy a digest context using an ENGINE */
	if (in->engine && !ENGINE_init(in->engine)) {
		EVPerr(EVP_F_EVP_MD_CTX_COPY_EX, ERR_R_ENGINE_LIB);
		return 0;
	}
#endif

	if (out->digest == in->digest) {
		tmp_buf = out->md_data;
		EVP_MD_CTX_set_flags(out, EVP_MD_CTX_FLAG_REUSE);
	} else
		tmp_buf = NULL;
	EVP_MD_CTX_cleanup(out);
	memcpy(out, in, sizeof *out);

	if (in->md_data && out->digest->ctx_size) {
		if (tmp_buf)
			out->md_data = tmp_buf;
		else {
			out->md_data = malloc(out->digest->ctx_size);
			if (!out->md_data) {
				EVPerr(EVP_F_EVP_MD_CTX_COPY_EX,
				    ERR_R_MALLOC_FAILURE);
				return 0;
			}
		}
		memcpy(out->md_data, in->md_data, out->digest->ctx_size);
	}

	out->update = in->update;

	if (in->pctx) {
		out->pctx = EVP_PKEY_CTX_dup(in->pctx);
		if (!out->pctx) {
			EVP_MD_CTX_cleanup(out);
			return 0;
		}
	}

	if (out->digest->copy)
		return out->digest->copy(out, in);

	return 1;
}


int
EVP_MD_CTX_copy_ex(EVP_MD_CTX *out, const EVP_MD_CTX *in)
{
	unsigned char *tmp_buf;

	if ((in == NULL) || (in->digest == NULL)) {
		EVPerr(EVP_F_EVP_MD_CTX_COPY_EX, EVP_R_INPUT_NOT_INITIALIZED);
		return 0;
	}
#ifndef OPENSSL_NO_ENGINE
	/* Make sure it's safe to copy a digest context using an ENGINE */
	if (in->engine && !ENGINE_init(in->engine)) {
		EVPerr(EVP_F_EVP_MD_CTX_COPY_EX, ERR_R_ENGINE_LIB);
		return 0;
	}
#endif

	if (out->digest == in->digest) {
		tmp_buf = out->md_data;
		EVP_MD_CTX_set_flags(out, EVP_MD_CTX_FLAG_REUSE);
	} else
		tmp_buf = NULL;
	EVP_MD_CTX_cleanup(out);
	memcpy(out, in, sizeof *out);

	if (in->md_data && out->digest->ctx_size) {
		if (tmp_buf)
			out->md_data = tmp_buf;
		else {
			out->md_data = malloc(out->digest->ctx_size);
			if (!out->md_data) {
				EVPerr(EVP_F_EVP_MD_CTX_COPY_EX,
				    ERR_R_MALLOC_FAILURE);
				return 0;
			}
		}
		memcpy(out->md_data, in->md_data, out->digest->ctx_size);
	}

	out->update = in->update;

	if (in->pctx) {
		out->pctx = EVP_PKEY_CTX_dup(in->pctx);
		if (!out->pctx) {
			EVP_MD_CTX_cleanup(out);
			return 0;
		}
	}

	if (out->digest->copy)
		return out->digest->copy(out, in);

	return 1;
}


void
EVP_MD_CTX_init(EVP_MD_CTX *ctx)
{
	memset(ctx, 0, sizeof *ctx);
}


const EVP_MD *
EVP_MD_CTX_md(const EVP_MD_CTX *ctx)
{
	if (!ctx)
		return NULL;
	return ctx->digest;
}


void
EVP_MD_CTX_set_flags(EVP_MD_CTX *ctx, int flags)
{
	ctx->flags |= flags;
}


int
EVP_MD_CTX_test_flags(const EVP_MD_CTX *ctx, int flags)
{
	return (ctx->flags & flags);
}


int
EVP_MD_size(const EVP_MD *md)
{
	if (!md) {
		EVPerr(EVP_F_EVP_MD_SIZE, EVP_R_MESSAGE_DIGEST_IS_NULL);
		return -1;
	}
	return md->md_size;
}


int
EVP_MD_type(const EVP_MD *md)
{
	return md->type;
}


EVP_PKEY *
EVP_PKCS82PKEY(PKCS8_PRIV_KEY_INFO *p8)
{
	EVP_PKEY *pkey = NULL;
	ASN1_OBJECT *algoid;
	char obj_tmp[80];

	if (!PKCS8_pkey_get0(&algoid, NULL, NULL, NULL, p8))
		return NULL;

	if (!(pkey = EVP_PKEY_new())) {
		EVPerr(EVP_F_EVP_PKCS82PKEY, ERR_R_MALLOC_FAILURE);
		return NULL;
	}

	if (!EVP_PKEY_set_type(pkey, OBJ_obj2nid(algoid))) {
		EVPerr(EVP_F_EVP_PKCS82PKEY,
		    EVP_R_UNSUPPORTED_PRIVATE_KEY_ALGORITHM);
		i2t_ASN1_OBJECT(obj_tmp, 80, algoid);
		ERR_asprintf_error_data("TYPE=%s", obj_tmp);
		goto error;
	}

	if (pkey->ameth->priv_decode) {
		if (!pkey->ameth->priv_decode(pkey, p8)) {
			EVPerr(EVP_F_EVP_PKCS82PKEY,
			    EVP_R_PRIVATE_KEY_DECODE_ERROR);
			goto error;
		}
	} else {
		EVPerr(EVP_F_EVP_PKCS82PKEY, EVP_R_METHOD_NOT_SUPPORTED);
		goto error;
	}

	return pkey;

error:
	EVP_PKEY_free(pkey);
	return NULL;
}


const EVP_PKEY_ASN1_METHOD *
EVP_PKEY_asn1_find(ENGINE **pe, int type)
{
	const EVP_PKEY_ASN1_METHOD *t;

	for (;;) {
		t = pkey_asn1_find(type);
		if (!t || !(t->pkey_flags & ASN1_PKEY_ALIAS))
			break;
		type = t->pkey_base_id;
	}
	if (pe) {
#ifndef OPENSSL_NO_ENGINE
		ENGINE *e;
		/* type will contain the final unaliased type */
		e = ENGINE_get_pkey_asn1_meth_engine(type);
		if (e) {
			*pe = e;
			return ENGINE_get_pkey_asn1_meth(e, type);
		}
#endif
		*pe = NULL;
	}
	return t;
}
EVP_PKEY_asn1_find_str(ENGINE **pe, const char *str, int len)
{
	int i;
	const EVP_PKEY_ASN1_METHOD *ameth;
	if (len == -1)
		len = strlen(str);
	if (pe) {
#ifndef OPENSSL_NO_ENGINE
		ENGINE *e;
		ameth = ENGINE_pkey_asn1_find_str(&e, str, len);
		if (ameth) {
			/* Convert structural into
			 * functional reference
			 */
			if (!ENGINE_init(e))
				ameth = NULL;
			ENGINE_free(e);
			*pe = e;
			return ameth;
		}
#endif
		*pe = NULL;
	}
	for (i = 0; i < EVP_PKEY_asn1_get_count(); i++) {
		ameth = EVP_PKEY_asn1_get0(i);
		if (ameth->pkey_flags & ASN1_PKEY_ALIAS)
			continue;
		if (((int)strlen(ameth->pem_str) == len) &&
		    !strncasecmp(ameth->pem_str, str, len))
			return ameth;
	}
	return NULL;
}


int
EVP_PKEY_assign(EVP_PKEY *pkey, int type, void *key)
{
	if (!EVP_PKEY_set_type(pkey, type))
		return 0;
	pkey->pkey.ptr = key;
	return (key != NULL);
}


int
EVP_PKEY_cmp_parameters(const EVP_PKEY *a, const EVP_PKEY *b)
{
	if (a->type != b->type)
		return -1;
	if (a->ameth && a->ameth->param_cmp)
		return a->ameth->param_cmp(a, b);
	return -2;
}
EVP_PKEY_cmp(const EVP_PKEY *a, const EVP_PKEY *b)
{
	if (a->type != b->type)
		return -1;

	if (a->ameth) {
		int ret;
		/* Compare parameters if the algorithm has them */
		if (a->ameth->param_cmp) {
			ret = a->ameth->param_cmp(a, b);
			if (ret <= 0)
				return ret;
		}

		if (a->ameth->pub_cmp)
			return a->ameth->pub_cmp(a, b);
	}

	return -2;
}


int
EVP_PKEY_copy_parameters(EVP_PKEY *to, const EVP_PKEY *from)
{
	if (to->type != from->type) {
		EVPerr(EVP_F_EVP_PKEY_COPY_PARAMETERS,
		    EVP_R_DIFFERENT_KEY_TYPES);
		goto err;
	}

	if (EVP_PKEY_missing_parameters(from)) {
		EVPerr(EVP_F_EVP_PKEY_COPY_PARAMETERS,
		    EVP_R_MISSING_PARAMETERS);
		goto err;
	}
	if (from->ameth && from->ameth->param_copy)
		return from->ameth->param_copy(to, from);

err:
	return 0;
}


int
EVP_PKEY_CTX_ctrl(EVP_PKEY_CTX *ctx, int keytype, int optype, int cmd,
    int p1, void *p2)
{
	int ret;

	if (!ctx || !ctx->pmeth || !ctx->pmeth->ctrl) {
		EVPerr(EVP_F_EVP_PKEY_CTX_CTRL, EVP_R_COMMAND_NOT_SUPPORTED);
		return -2;
	}
	if ((keytype != -1) && (ctx->pmeth->pkey_id != keytype))
		return -1;

	if (ctx->operation == EVP_PKEY_OP_UNDEFINED) {
		EVPerr(EVP_F_EVP_PKEY_CTX_CTRL, EVP_R_NO_OPERATION_SET);
		return -1;
	}

	if ((optype != -1) && !(ctx->operation & optype)) {
		EVPerr(EVP_F_EVP_PKEY_CTX_CTRL, EVP_R_INVALID_OPERATION);
		return -1;
	}

	ret = ctx->pmeth->ctrl(ctx, cmd, p1, p2);

	if (ret == -2)
		EVPerr(EVP_F_EVP_PKEY_CTX_CTRL, EVP_R_COMMAND_NOT_SUPPORTED);

	return ret;

}
EVP_PKEY_CTX_ctrl_str(EVP_PKEY_CTX *ctx, const char *name, const char *value)
{
	if (!ctx || !ctx->pmeth || !ctx->pmeth->ctrl_str) {
		EVPerr(EVP_F_EVP_PKEY_CTX_CTRL_STR,
		    EVP_R_COMMAND_NOT_SUPPORTED);
		return -2;
	}
	if (!strcmp(name, "digest")) {
		const EVP_MD *md;
		if (!value || !(md = EVP_get_digestbyname(value))) {
			EVPerr(EVP_F_EVP_PKEY_CTX_CTRL_STR,
			    EVP_R_INVALID_DIGEST);
			return 0;
		}
		return EVP_PKEY_CTX_set_signature_md(ctx, md);
	}
	return ctx->pmeth->ctrl_str(ctx, name, value);
}


EVP_PKEY_CTX *
EVP_PKEY_CTX_dup(EVP_PKEY_CTX *pctx)
{
	EVP_PKEY_CTX *rctx;

	if (!pctx->pmeth || !pctx->pmeth->copy)
		return NULL;
#ifndef OPENSSL_NO_ENGINE
	/* Make sure it's safe to copy a pkey context using an ENGINE */
	if (pctx->engine && !ENGINE_init(pctx->engine)) {
		EVPerr(EVP_F_EVP_PKEY_CTX_DUP, ERR_R_ENGINE_LIB);
		return 0;
	}
#endif
	rctx = malloc(sizeof(EVP_PKEY_CTX));
	if (!rctx)
		return NULL;

	rctx->pmeth = pctx->pmeth;
#ifndef OPENSSL_NO_ENGINE
	rctx->engine = pctx->engine;
#endif

	if (pctx->pkey)
		CRYPTO_add(&pctx->pkey->references, 1, CRYPTO_LOCK_EVP_PKEY);

	rctx->pkey = pctx->pkey;

	if (pctx->peerkey)
		CRYPTO_add(&pctx->peerkey->references, 1, CRYPTO_LOCK_EVP_PKEY);

	rctx->peerkey = pctx->peerkey;

	rctx->data = NULL;
	rctx->app_data = NULL;
	rctx->operation = pctx->operation;

	if (pctx->pmeth->copy(rctx, pctx) > 0)
		return rctx;

	EVP_PKEY_CTX_free(rctx);
	return NULL;
}


void
EVP_PKEY_CTX_free(EVP_PKEY_CTX *ctx)
{
	if (ctx == NULL)
		return;
	if (ctx->pmeth && ctx->pmeth->cleanup)
		ctx->pmeth->cleanup(ctx);
	EVP_PKEY_free(ctx->pkey);
	EVP_PKEY_free(ctx->peerkey);
#ifndef OPENSSL_NO_ENGINE
	if (ctx->engine)
		/* The EVP_PKEY_CTX we used belongs to an ENGINE, release the
		 * functional reference we held for this reason. */
		ENGINE_finish(ctx->engine);
#endif
	free(ctx);
}


EVP_PKEY_CTX *
EVP_PKEY_CTX_new(EVP_PKEY *pkey, ENGINE *e)
{
	return int_ctx_new(pkey, e, -1);
}
EVP_PKEY_CTX_new_id(int id, ENGINE *e)
{
	return int_ctx_new(NULL, e, id);
}


EVP_PKEY_CTX *
EVP_PKEY_CTX_new_id(int id, ENGINE *e)
{
	return int_ctx_new(NULL, e, id);
}


void
EVP_PKEY_free(EVP_PKEY *x)
{
	int i;

	if (x == NULL)
		return;

	i = CRYPTO_add(&x->references, -1, CRYPTO_LOCK_EVP_PKEY);
	if (i > 0)
		return;

	EVP_PKEY_free_it(x);
	if (x->attributes)
		sk_X509_ATTRIBUTE_pop_free(x->attributes, X509_ATTRIBUTE_free);
	free(x);
}
EVP_PKEY_free_it(EVP_PKEY *x)
{
	if (x->ameth && x->ameth->pkey_free) {
		x->ameth->pkey_free(x);
		x->pkey.ptr = NULL;
	}
#ifndef OPENSSL_NO_ENGINE
	if (x->engine) {
		ENGINE_finish(x->engine);
		x->engine = NULL;
	}
#endif
}


static void
EVP_PKEY_free_it(EVP_PKEY *x)
{
	if (x->ameth && x->ameth->pkey_free) {
		x->ameth->pkey_free(x);
		x->pkey.ptr = NULL;
	}
#ifndef OPENSSL_NO_ENGINE
	if (x->engine) {
		ENGINE_finish(x->engine);
		x->engine = NULL;
	}
#endif
}


int
EVP_PKEY_keygen_init(EVP_PKEY_CTX *ctx)
{
	int ret;

	if (!ctx || !ctx->pmeth || !ctx->pmeth->keygen) {
		EVPerr(EVP_F_EVP_PKEY_KEYGEN_INIT,
		    EVP_R_OPERATION_NOT_SUPPORTED_FOR_THIS_KEYTYPE);
		return -2;
	}
	ctx->operation = EVP_PKEY_OP_KEYGEN;
	if (!ctx->pmeth->keygen_init)
		return 1;
	ret = ctx->pmeth->keygen_init(ctx);
	if (ret <= 0)
		ctx->operation = EVP_PKEY_OP_UNDEFINED;
	return ret;
}
EVP_PKEY_keygen(EVP_PKEY_CTX *ctx, EVP_PKEY **ppkey)
{
	int ret;

	if (!ctx || !ctx->pmeth || !ctx->pmeth->keygen) {
		EVPerr(EVP_F_EVP_PKEY_KEYGEN,
		    EVP_R_OPERATION_NOT_SUPPORTED_FOR_THIS_KEYTYPE);
		return -2;
	}
	if (ctx->operation != EVP_PKEY_OP_KEYGEN) {
		EVPerr(EVP_F_EVP_PKEY_KEYGEN, EVP_R_OPERATON_NOT_INITIALIZED);
		return -1;
	}

	if (!ppkey)
		return -1;

	if (!*ppkey)
		*ppkey = EVP_PKEY_new();

	ret = ctx->pmeth->keygen(ctx, *ppkey);
	if (ret <= 0) {
		EVP_PKEY_free(*ppkey);
		*ppkey = NULL;
	}
	return ret;
}


int
EVP_PKEY_keygen_init(EVP_PKEY_CTX *ctx)
{
	int ret;

	if (!ctx || !ctx->pmeth || !ctx->pmeth->keygen) {
		EVPerr(EVP_F_EVP_PKEY_KEYGEN_INIT,
		    EVP_R_OPERATION_NOT_SUPPORTED_FOR_THIS_KEYTYPE);
		return -2;
	}
	ctx->operation = EVP_PKEY_OP_KEYGEN;
	if (!ctx->pmeth->keygen_init)
		return 1;
	ret = ctx->pmeth->keygen_init(ctx);
	if (ret <= 0)
		ctx->operation = EVP_PKEY_OP_UNDEFINED;
	return ret;
}


const EVP_PKEY_METHOD *
EVP_PKEY_meth_find(int type)
{
	EVP_PKEY_METHOD tmp;
	const EVP_PKEY_METHOD *t = &tmp, **ret;

	tmp.pkey_id = type;
	if (app_pkey_methods) {
		int idx;
		idx = sk_EVP_PKEY_METHOD_find(app_pkey_methods, &tmp);
		if (idx >= 0)
			return sk_EVP_PKEY_METHOD_value(app_pkey_methods, idx);
	}
	ret = OBJ_bsearch_pmeth(&t, standard_methods,
	    sizeof(standard_methods)/sizeof(EVP_PKEY_METHOD *));
	if (!ret || !*ret)
		return NULL;
	return *ret;
}


int
EVP_PKEY_missing_parameters(const EVP_PKEY *pkey)
{
	if (pkey->ameth && pkey->ameth->param_missing)
		return pkey->ameth->param_missing(pkey);
	return 0;
}


EVP_PKEY *
EVP_PKEY_new(void)
{
	EVP_PKEY *ret;

	ret = malloc(sizeof(EVP_PKEY));
	if (ret == NULL) {
		EVPerr(EVP_F_EVP_PKEY_NEW, ERR_R_MALLOC_FAILURE);
		return (NULL);
	}
	ret->type = EVP_PKEY_NONE;
	ret->save_type = EVP_PKEY_NONE;
	ret->references = 1;
	ret->ameth = NULL;
	ret->engine = NULL;
	ret->pkey.ptr = NULL;
	ret->attributes = NULL;
	ret->save_parameters = 1;
	return (ret);
}


EVP_PKEY *
EVP_PKEY_new_mac_key(int type, ENGINE *e, const unsigned char *key, int keylen)
{
	EVP_PKEY_CTX *mac_ctx = NULL;
	EVP_PKEY *mac_key = NULL;

	mac_ctx = EVP_PKEY_CTX_new_id(type, e);
	if (!mac_ctx)
		return NULL;
	if (EVP_PKEY_keygen_init(mac_ctx) <= 0)
		goto merr;
	if (EVP_PKEY_CTX_ctrl(mac_ctx, -1, EVP_PKEY_OP_KEYGEN,
	    EVP_PKEY_CTRL_SET_MAC_KEY, keylen, (void *)key) <= 0)
		goto merr;
	if (EVP_PKEY_keygen(mac_ctx, &mac_key) <= 0)
		goto merr;

merr:
	EVP_PKEY_CTX_free(mac_ctx);
	return mac_key;
}


int
EVP_PKEY_set_type(EVP_PKEY *pkey, int type)
{
	return pkey_set_type(pkey, type, NULL, -1);
}
EVP_PKEY_set_type_str(EVP_PKEY *pkey, const char *str, int len)
{
	return pkey_set_type(pkey, EVP_PKEY_NONE, str, len);
}


int
EVP_PKEY_sign_init(EVP_PKEY_CTX *ctx)
{
	int ret;

	if (!ctx || !ctx->pmeth || !ctx->pmeth->sign) {
		EVPerr(EVP_F_EVP_PKEY_SIGN_INIT,
		    EVP_R_OPERATION_NOT_SUPPORTED_FOR_THIS_KEYTYPE);
		return -2;
	}
	ctx->operation = EVP_PKEY_OP_SIGN;
	if (!ctx->pmeth->sign_init)
		return 1;
	ret = ctx->pmeth->sign_init(ctx);
	if (ret <= 0)
		ctx->operation = EVP_PKEY_OP_UNDEFINED;
	return ret;
}
EVP_PKEY_sign(EVP_PKEY_CTX *ctx, unsigned char *sig, size_t *siglen,
    const unsigned char *tbs, size_t tbslen)
{
	if (!ctx || !ctx->pmeth || !ctx->pmeth->sign) {
		EVPerr(EVP_F_EVP_PKEY_SIGN,
		    EVP_R_OPERATION_NOT_SUPPORTED_FOR_THIS_KEYTYPE);
		return -2;
	}
	if (ctx->operation != EVP_PKEY_OP_SIGN) {
		EVPerr(EVP_F_EVP_PKEY_SIGN, EVP_R_OPERATON_NOT_INITIALIZED);
		return -1;
	}
	M_check_autoarg(ctx, sig, siglen, EVP_F_EVP_PKEY_SIGN)
	return ctx->pmeth->sign(ctx, sig, siglen, tbs, tbslen);
}


int
EVP_PKEY_sign_init(EVP_PKEY_CTX *ctx)
{
	int ret;

	if (!ctx || !ctx->pmeth || !ctx->pmeth->sign) {
		EVPerr(EVP_F_EVP_PKEY_SIGN_INIT,
		    EVP_R_OPERATION_NOT_SUPPORTED_FOR_THIS_KEYTYPE);
		return -2;
	}
	ctx->operation = EVP_PKEY_OP_SIGN;
	if (!ctx->pmeth->sign_init)
		return 1;
	ret = ctx->pmeth->sign_init(ctx);
	if (ret <= 0)
		ctx->operation = EVP_PKEY_OP_UNDEFINED;
	return ret;
}


int
EVP_PKEY_size(EVP_PKEY *pkey)
{
	if (pkey && pkey->ameth && pkey->ameth->pkey_size)
		return pkey->ameth->pkey_size(pkey);
	return 0;
}


const EVP_CIPHER *
EVP_rc2_40_cbc(void)
{
	return (&r2_40_cbc_cipher);
}


const EVP_CIPHER *
EVP_rc4(void)
{
	return (&r4_cipher);
}
EVP_rc4_40(void)
{
	return (&r4_40_cipher);
}


const EVP_CIPHER *
EVP_rc4_hmac_md5(void)
{
	return (&r4_hmac_md5_cipher);
}


const EVP_MD *
EVP_sha1(void)
{
	return (&sha1_md);
}


const EVP_MD *
EVP_sha224(void)
{
	return (&sha224_md);
}


const EVP_MD *
EVP_sha256(void)
{
	return (&sha256_md);
}


const EVP_MD *
EVP_sha384(void)
{
	return (&sha384_md);
}


const EVP_MD *
EVP_sha512(void)
{
	return (&sha512_md);
}


int
EVP_SignFinal(EVP_MD_CTX *ctx, unsigned char *sigret, unsigned int *siglen,
    EVP_PKEY *pkey)
{
	unsigned char m[EVP_MAX_MD_SIZE];
	unsigned int m_len;
	int i = 0, ok = 0, v;
	EVP_MD_CTX tmp_ctx;
	EVP_PKEY_CTX *pkctx = NULL;

	*siglen = 0;
	EVP_MD_CTX_init(&tmp_ctx);
	if (!EVP_MD_CTX_copy_ex(&tmp_ctx, ctx))
		goto err;
	if (!EVP_DigestFinal_ex(&tmp_ctx, &(m[0]), &m_len))
		goto err;
	EVP_MD_CTX_cleanup(&tmp_ctx);

	if (ctx->digest->flags & EVP_MD_FLAG_PKEY_METHOD_SIGNATURE) {
		size_t sltmp = (size_t)EVP_PKEY_size(pkey);
		i = 0;
		pkctx = EVP_PKEY_CTX_new(pkey, NULL);
		if (!pkctx)
			goto err;
		if (EVP_PKEY_sign_init(pkctx) <= 0)
			goto err;
		if (EVP_PKEY_CTX_set_signature_md(pkctx, ctx->digest) <= 0)
			goto err;
		if (EVP_PKEY_sign(pkctx, sigret, &sltmp, m, m_len) <= 0)
			goto err;
		*siglen = sltmp;
		i = 1;
err:
		EVP_PKEY_CTX_free(pkctx);
		return i;
	}

	for (i = 0; i < 4; i++) {
		v = ctx->digest->required_pkey_type[i];
		if (v == 0)
			break;
		if (pkey->type == v) {
			ok = 1;
			break;
		}
	}
	if (!ok) {
		EVPerr(EVP_F_EVP_SIGNFINAL, EVP_R_WRONG_PUBLIC_KEY_TYPE);
		return (0);
	}

	if (ctx->digest->sign == NULL) {
		EVPerr(EVP_F_EVP_SIGNFINAL, EVP_R_NO_SIGN_FUNCTION_CONFIGURED);
		return (0);
	}
	return(ctx->digest->sign(ctx->digest->type, m, m_len, sigret, siglen,
	    pkey->pkey.ptr));
}


const EVP_MD *
EVP_streebog256(void)
{
	return (&streebog256_md);
}


const EVP_MD *
EVP_streebog512(void)
{
	return (&streebog512_md);
}


static int
ex_class_item_cmp(const EX_CLASS_ITEM *a, const EX_CLASS_ITEM *b)
{
	return a->class_index - b->class_index;
}


static unsigned long
ex_class_item_hash(const EX_CLASS_ITEM *a)
{
	return a->class_index;
}


static int
ex_data_check(void)
{
	int toret = 1;
	CRYPTO_w_lock(CRYPTO_LOCK_EX_DATA);
	if (!ex_data &&
	    (ex_data = lh_EX_CLASS_ITEM_new()) == NULL)
		toret = 0;
	CRYPTO_w_unlock(CRYPTO_LOCK_EX_DATA);
	return toret;
}


static void
expand(_LHASH *lh)
{
	LHASH_NODE **n, **n1, **n2, *np;
	unsigned int p, i, j;
	unsigned long hash, nni;

	lh->num_nodes++;
	lh->num_expands++;
	p = (int)lh->p++;
	n1 = &(lh->b[p]);
	n2 = &(lh->b[p + (int)lh->pmax]);
	*n2 = NULL;        /* 27/07/92 - eay - undefined pointer bug */
	nni = lh->num_alloc_nodes;

	for (np = *n1; np != NULL; ) {
#ifndef OPENSSL_NO_HASH_COMP
		hash = np->hash;
#else
		hash = lh->hash(np->data);
		lh->num_hash_calls++;
#endif
		if ((hash % nni) != p) { /* move it */
			*n1 = (*n1)->next;
			np->next= *n2;
			*n2 = np;
		} else
			n1 = &((*n1)->next);
		np= *n1;
	}

	if ((lh->p) >= lh->pmax) {
		j = (int)lh->num_alloc_nodes * 2;
		n = reallocarray(lh->b, j, sizeof(LHASH_NODE *));
		if (n == NULL) {
/*			fputs("realloc error in lhash", stderr); */
			lh->error++;
			lh->p = 0;
			return;
		}
		/* else */
		for (i = (int)lh->num_alloc_nodes; i < j; i++)/* 26/02/92 eay */
			n[i] = NULL;			  /* 02/03/92 eay */
		lh->pmax = lh->num_alloc_nodes;
		lh->num_alloc_nodes = j;
		lh->num_expand_reallocs++;
		lh->p = 0;
		lh->b = n;
	}
}


static long
file_ctrl(BIO *b, int cmd, long num, void *ptr)
{
	long ret = 1;
	FILE *fp = (FILE *)b->ptr;
	FILE **fpp;
	char p[4];

	switch (cmd) {
	case BIO_C_FILE_SEEK:
	case BIO_CTRL_RESET:
		ret = (long)fseek(fp, num, 0);
		break;
	case BIO_CTRL_EOF:
		ret = (long)feof(fp);
		break;
	case BIO_C_FILE_TELL:
	case BIO_CTRL_INFO:
		ret = ftell(fp);
		break;
	case BIO_C_SET_FILE_PTR:
		file_free(b);
		b->shutdown = (int)num&BIO_CLOSE;
		b->ptr = ptr;
		b->init = 1;
		break;
	case BIO_C_SET_FILENAME:
		file_free(b);
		b->shutdown = (int)num&BIO_CLOSE;
		if (num & BIO_FP_APPEND) {
			if (num & BIO_FP_READ)
				strlcpy(p, "a+", sizeof p);
			else	strlcpy(p, "a", sizeof p);
		} else if ((num & BIO_FP_READ) && (num & BIO_FP_WRITE))
			strlcpy(p, "r+", sizeof p);
		else if (num & BIO_FP_WRITE)
			strlcpy(p, "w", sizeof p);
		else if (num & BIO_FP_READ)
			strlcpy(p, "r", sizeof p);
		else {
			BIOerr(BIO_F_FILE_CTRL, BIO_R_BAD_FOPEN_MODE);
			ret = 0;
			break;
		}
		fp = fopen(ptr, p);
		if (fp == NULL) {
			SYSerr(SYS_F_FOPEN, errno);
			ERR_asprintf_error_data("fopen('%s', '%s')", ptr, p);
			BIOerr(BIO_F_FILE_CTRL, ERR_R_SYS_LIB);
			ret = 0;
			break;
		}
		b->ptr = fp;
		b->init = 1;
		break;
	case BIO_C_GET_FILE_PTR:
		/* the ptr parameter is actually a FILE ** in this case. */
		if (ptr != NULL) {
			fpp = (FILE **)ptr;
			*fpp = (FILE *)b->ptr;
		}
		break;
	case BIO_CTRL_GET_CLOSE:
		ret = (long)b->shutdown;
		break;
	case BIO_CTRL_SET_CLOSE:
		b->shutdown = (int)num;
		break;
	case BIO_CTRL_FLUSH:
		fflush((FILE *)b->ptr);
		break;
	case BIO_CTRL_DUP:
		ret = 1;
		break;

	case BIO_CTRL_WPENDING:
	case BIO_CTRL_PENDING:
	case BIO_CTRL_PUSH:
	case BIO_CTRL_POP:
	default:
		ret = 0;
		break;
	}
	return (ret);
}


static int
file_free(BIO *a)
{
	if (a == NULL)
		return (0);
	if (a->shutdown) {
		if ((a->init) && (a->ptr != NULL)) {
			fclose (a->ptr);
			a->ptr = NULL;
			a->flags = 0;
		}
		a->init = 0;
	}
	return (1);
}


static int
file_gets(BIO *bp, char *buf, int size)
{
	int ret = 0;

	buf[0] = '\0';
	if (!fgets(buf, size,(FILE *)bp->ptr))
		goto err;
	if (buf[0] != '\0')
		ret = strlen(buf);
err:
	return (ret);
}


static int
file_new(BIO *bi)
{
	bi->init = 0;
	bi->num = 0;
	bi->ptr = NULL;
	bi->flags=0;
	return (1);
}


static int
final512(EVP_MD_CTX *ctx, unsigned char *md)
{
	return SHA512_Final(md, ctx->md_data);
}


void
HMAC_CTX_cleanup(HMAC_CTX *ctx)
{
	EVP_MD_CTX_cleanup(&ctx->i_ctx);
	EVP_MD_CTX_cleanup(&ctx->o_ctx);
	EVP_MD_CTX_cleanup(&ctx->md_ctx);
	memset(ctx, 0, sizeof *ctx);
}


int
HMAC_CTX_copy(HMAC_CTX *dctx, HMAC_CTX *sctx)
{
	if (!EVP_MD_CTX_copy(&dctx->i_ctx, &sctx->i_ctx))
		goto err;
	if (!EVP_MD_CTX_copy(&dctx->o_ctx, &sctx->o_ctx))
		goto err;
	if (!EVP_MD_CTX_copy(&dctx->md_ctx, &sctx->md_ctx))
		goto err;
	memcpy(dctx->key, sctx->key, HMAC_MAX_MD_CBLOCK);
	dctx->key_length = sctx->key_length;
	dctx->md = sctx->md;
	return 1;
err:
	return 0;
}


void
HMAC_CTX_init(HMAC_CTX *ctx)
{
	EVP_MD_CTX_init(&ctx->i_ctx);
	EVP_MD_CTX_init(&ctx->o_ctx);
	EVP_MD_CTX_init(&ctx->md_ctx);
}


void
HMAC_CTX_set_flags(HMAC_CTX *ctx, unsigned long flags)
{
	EVP_MD_CTX_set_flags(&ctx->i_ctx, flags);
	EVP_MD_CTX_set_flags(&ctx->o_ctx, flags);
	EVP_MD_CTX_set_flags(&ctx->md_ctx, flags);
}


int
HMAC_Final(HMAC_CTX *ctx, unsigned char *md, unsigned int *len)
{
	unsigned int i;
	unsigned char buf[EVP_MAX_MD_SIZE];

	if (!EVP_DigestFinal_ex(&ctx->md_ctx, buf, &i))
		goto err;
	if (!EVP_MD_CTX_copy_ex(&ctx->md_ctx, &ctx->o_ctx))
		goto err;
	if (!EVP_DigestUpdate(&ctx->md_ctx, buf, i))
		goto err;
	if (!EVP_DigestFinal_ex(&ctx->md_ctx, md, len))
		goto err;
	return 1;
err:
	return 0;
}


int
HMAC_Init_ex(HMAC_CTX *ctx, const void *key, int len, const EVP_MD *md,
    ENGINE *impl)
{
	int i, j, reset = 0;
	unsigned char pad[HMAC_MAX_MD_CBLOCK];

	if (md != NULL) {
		reset = 1;
		ctx->md = md;
	} else
		md = ctx->md;

	if (key != NULL) {
		reset = 1;
		j = EVP_MD_block_size(md);
		if ((size_t)j > sizeof(ctx->key)) {
			EVPerr(EVP_F_HMAC_INIT_EX, EVP_R_BAD_BLOCK_LENGTH);
			goto err;
		}
		if (j < len) {
			if (!EVP_DigestInit_ex(&ctx->md_ctx, md, impl))
				goto err;
			if (!EVP_DigestUpdate(&ctx->md_ctx, key, len))
				goto err;
			if (!EVP_DigestFinal_ex(&(ctx->md_ctx), ctx->key,
			    &ctx->key_length))
				goto err;
		} else {
			if ((size_t)len > sizeof(ctx->key)) {
				EVPerr(EVP_F_HMAC_INIT_EX,
				    EVP_R_BAD_KEY_LENGTH);
				goto err;
			}
			memcpy(ctx->key, key, len);
			ctx->key_length = len;
		}
		if (ctx->key_length != HMAC_MAX_MD_CBLOCK)
			memset(&ctx->key[ctx->key_length], 0,
			    HMAC_MAX_MD_CBLOCK - ctx->key_length);
	}

	if (reset) {
		for (i = 0; i < HMAC_MAX_MD_CBLOCK; i++)
			pad[i] = 0x36 ^ ctx->key[i];
		if (!EVP_DigestInit_ex(&ctx->i_ctx, md, impl))
			goto err;
		if (!EVP_DigestUpdate(&ctx->i_ctx, pad, EVP_MD_block_size(md)))
			goto err;

		for (i = 0; i < HMAC_MAX_MD_CBLOCK; i++)
			pad[i] = 0x5c ^ ctx->key[i];
		if (!EVP_DigestInit_ex(&ctx->o_ctx, md, impl))
			goto err;
		if (!EVP_DigestUpdate(&ctx->o_ctx, pad, EVP_MD_block_size(md)))
			goto err;
	}
	if (!EVP_MD_CTX_copy_ex(&ctx->md_ctx, &ctx->i_ctx))
		goto err;
	return 1;
err:
	return 0;
}


static void
hmac_key_free(EVP_PKEY *pkey)
{
	ASN1_OCTET_STRING *os = (ASN1_OCTET_STRING *)pkey->pkey.ptr;

	if (os) {
		if (os->data)
			explicit_bzero(os->data, os->length);
		ASN1_OCTET_STRING_free(os);
	}
}


static int
hmac_signctx_init(EVP_PKEY_CTX *ctx, EVP_MD_CTX *mctx)
{
	HMAC_PKEY_CTX *hctx = ctx->data;

	HMAC_CTX_set_flags(&hctx->ctx, mctx->flags & ~EVP_MD_CTX_FLAG_NO_INIT);
	EVP_MD_CTX_set_flags(mctx, EVP_MD_CTX_FLAG_NO_INIT);
	mctx->update = int_update;
	return 1;
}
hmac_signctx(EVP_PKEY_CTX *ctx, unsigned char *sig, size_t *siglen,
    EVP_MD_CTX *mctx)
{
	unsigned int hlen;
	HMAC_PKEY_CTX *hctx = ctx->data;
	int l = EVP_MD_CTX_size(mctx);

	if (l < 0)
		return 0;
	*siglen = l;
	if (!sig)
		return 1;

	if (!HMAC_Final(&hctx->ctx, sig, &hlen))
		return 0;
	*siglen = (size_t)hlen;
	return 1;
}


static int
hmac_signctx_init(EVP_PKEY_CTX *ctx, EVP_MD_CTX *mctx)
{
	HMAC_PKEY_CTX *hctx = ctx->data;

	HMAC_CTX_set_flags(&hctx->ctx, mctx->flags & ~EVP_MD_CTX_FLAG_NO_INIT);
	EVP_MD_CTX_set_flags(mctx, EVP_MD_CTX_FLAG_NO_INIT);
	mctx->update = int_update;
	return 1;
}


int
HMAC_Update(HMAC_CTX *ctx, const unsigned char *data, size_t len)
{
	return EVP_DigestUpdate(&ctx->md_ctx, data, len);
}


static int
i2d_name_canon(STACK_OF(STACK_OF_X509_NAME_ENTRY) *_intname, unsigned char **in)
{
	int i, len, ltmp;
	ASN1_VALUE *v;
	STACK_OF(ASN1_VALUE) *intname = (STACK_OF(ASN1_VALUE) *)_intname;

	len = 0;
	for (i = 0; i < sk_ASN1_VALUE_num(intname); i++) {
		v = sk_ASN1_VALUE_value(intname, i);
		ltmp = ASN1_item_ex_i2d(&v, in,
		    ASN1_ITEM_rptr(X509_NAME_ENTRIES), -1, -1);
		if (ltmp < 0)
			return ltmp;
		len += ltmp;
	}
	return len;
}


int
i2d_X509_SIG(X509_SIG *a, unsigned char **out)
{
	return ASN1_item_i2d((ASN1_VALUE *)a, out, &X509_SIG_it);
}


static void
impl_check(void)
{
	CRYPTO_w_lock(CRYPTO_LOCK_EX_DATA);
	if (!impl)
		impl = &impl_default;
	CRYPTO_w_unlock(CRYPTO_LOCK_EX_DATA);
}


static int
init384(EVP_MD_CTX *ctx)
{
	return SHA384_Init(ctx->md_data);
}


void
init_session(SGX_SESSION *sgx_s)
{
  sgx_s->s = SSL_new(ctx);
  ssl_get_new_session(sgx_s->s, 1);
}


static EVP_PKEY_CTX *
int_ctx_new(EVP_PKEY *pkey, ENGINE *e, int id)
{
	EVP_PKEY_CTX *ret;
	const EVP_PKEY_METHOD *pmeth;

	if (id == -1) {
		if (!pkey || !pkey->ameth)
			return NULL;
		id = pkey->ameth->pkey_id;
	}
#ifndef OPENSSL_NO_ENGINE
	if (pkey && pkey->engine)
		e = pkey->engine;
	/* Try to find an ENGINE which implements this method */
	if (e) {
		if (!ENGINE_init(e)) {
			EVPerr(EVP_F_INT_CTX_NEW, ERR_R_ENGINE_LIB);
			return NULL;
		}
	} else
		e = ENGINE_get_pkey_meth_engine(id);

	/* If an ENGINE handled this method look it up. Othewise
	 * use internal tables.
	 */

	if (e)
		pmeth = ENGINE_get_pkey_meth(e, id);
	else
#endif
		pmeth = EVP_PKEY_meth_find(id);

	if (pmeth == NULL) {
		EVPerr(EVP_F_INT_CTX_NEW, EVP_R_UNSUPPORTED_ALGORITHM);
		return NULL;
	}

	ret = malloc(sizeof(EVP_PKEY_CTX));
	if (!ret) {
#ifndef OPENSSL_NO_ENGINE
		if (e)
			ENGINE_finish(e);
#endif
		EVPerr(EVP_F_INT_CTX_NEW, ERR_R_MALLOC_FAILURE);
		return NULL;
	}
	ret->engine = e;
	ret->pmeth = pmeth;
	ret->operation = EVP_PKEY_OP_UNDEFINED;
	ret->pkey = pkey;
	ret->peerkey = NULL;
	ret->pkey_gencb = 0;
	if (pkey)
		CRYPTO_add(&pkey->references, 1, CRYPTO_LOCK_EVP_PKEY);
	ret->data = NULL;

	if (pmeth->init) {
		if (pmeth->init(ret) <= 0) {
			EVP_PKEY_CTX_free(ret);
			return NULL;
		}
	}

	return ret;
}


static ERR_STRING_DATA *
int_err_get_item(const ERR_STRING_DATA *d)
{
	ERR_STRING_DATA *p;
	LHASH_OF(ERR_STRING_DATA) *hash;

	err_fns_check();
	hash = ERRFN(err_get)(0);
	if (!hash)
		return NULL;

	CRYPTO_r_lock(CRYPTO_LOCK_ERR);
	p = lh_ERR_STRING_DATA_retrieve(hash, d);
	CRYPTO_r_unlock(CRYPTO_LOCK_ERR);

	return p;
}


static ERR_STRING_DATA *
int_err_set_item(ERR_STRING_DATA *d)
{
	ERR_STRING_DATA *p;
	LHASH_OF(ERR_STRING_DATA) *hash;

	err_fns_check();
	hash = ERRFN(err_get)(1);
	if (!hash)
		return NULL;

	CRYPTO_w_lock(CRYPTO_LOCK_ERR);
	p = lh_ERR_STRING_DATA_insert(hash, d);
	CRYPTO_w_unlock(CRYPTO_LOCK_ERR);

	return p;
}


static void
int_free_ex_data(int class_index, void *obj, CRYPTO_EX_DATA *ad)
{
	int mx, i;
	EX_CLASS_ITEM *item;
	void *ptr;
	CRYPTO_EX_DATA_FUNCS **storage = NULL;
	if ((item = def_get_class(class_index)) == NULL)
		return;
	CRYPTO_r_lock(CRYPTO_LOCK_EX_DATA);
	mx = sk_CRYPTO_EX_DATA_FUNCS_num(item->meth);
	if (mx > 0) {
		storage = reallocarray(NULL, mx, sizeof(CRYPTO_EX_DATA_FUNCS*));
		if (!storage)
			goto skip;
		for (i = 0; i < mx; i++)
			storage[i] = sk_CRYPTO_EX_DATA_FUNCS_value(
			    item->meth, i);
	}
skip:
	CRYPTO_r_unlock(CRYPTO_LOCK_EX_DATA);
	if ((mx > 0) && !storage) {
		CRYPTOerr(CRYPTO_F_INT_FREE_EX_DATA, ERR_R_MALLOC_FAILURE);
		return;
	}
	for (i = 0; i < mx; i++) {
		if (storage[i] && storage[i]->free_func) {
			ptr = CRYPTO_get_ex_data(ad, i);
			storage[i]->free_func(obj, ptr, ad, i,
			    storage[i]->argl, storage[i]->argp);
		}
	}
	free(storage);
	if (ad->sk) {
		sk_void_free(ad->sk);
		ad->sk = NULL;
	}
}


static int
int_get_new_index(int class_index, long argl, void *argp,
    CRYPTO_EX_new *new_func, CRYPTO_EX_dup *dup_func,
    CRYPTO_EX_free *free_func)
{
	EX_CLASS_ITEM *item = def_get_class(class_index);

	if (!item)
		return -1;
	return def_add_index(item, argl, argp, new_func, dup_func, free_func);
}


static int
int_new_ex_data(int class_index, void *obj, CRYPTO_EX_DATA *ad)
{
	int mx, i;
	void *ptr;
	CRYPTO_EX_DATA_FUNCS **storage = NULL;
	EX_CLASS_ITEM *item = def_get_class(class_index);

	if (!item)
		/* error is already set */
		return 0;
	ad->sk = NULL;
	CRYPTO_r_lock(CRYPTO_LOCK_EX_DATA);
	mx = sk_CRYPTO_EX_DATA_FUNCS_num(item->meth);
	if (mx > 0) {
		storage = reallocarray(NULL, mx, sizeof(CRYPTO_EX_DATA_FUNCS*));
		if (!storage)
			goto skip;
		for (i = 0; i < mx; i++)
			storage[i] = sk_CRYPTO_EX_DATA_FUNCS_value(
			    item->meth, i);
	}
skip:
	CRYPTO_r_unlock(CRYPTO_LOCK_EX_DATA);
	if ((mx > 0) && !storage) {
		CRYPTOerr(CRYPTO_F_INT_NEW_EX_DATA, ERR_R_MALLOC_FAILURE);
		return 0;
	}
	for (i = 0; i < mx; i++) {
		if (storage[i] && storage[i]->new_func) {
			ptr = CRYPTO_get_ex_data(ad, i);
			storage[i]->new_func(obj, ptr, ad, i,
			    storage[i]->argl, storage[i]->argp);
		}
	}
	free(storage);
	return 1;
}


static int
int_rsa_size(const EVP_PKEY *pkey)
{
	return RSA_size(pkey->pkey.rsa);
}


static ERR_STATE *
int_thread_get_item(const ERR_STATE *d)
{
	ERR_STATE *p;
	LHASH_OF(ERR_STATE) *hash;

	err_fns_check();
	hash = ERRFN(thread_get)(0);
	if (!hash)
		return NULL;

	CRYPTO_r_lock(CRYPTO_LOCK_ERR);
	p = lh_ERR_STATE_retrieve(hash, d);
	CRYPTO_r_unlock(CRYPTO_LOCK_ERR);

	ERRFN(thread_release)(&hash);
	return p;
}


static void
int_thread_release(LHASH_OF(ERR_STATE) **hash)
{
	int i;

	if (hash == NULL || *hash == NULL)
		return;

	i = CRYPTO_add(&int_thread_hash_references, -1, CRYPTO_LOCK_ERR);
	if (i > 0)
		return;

	*hash = NULL;
}


static ERR_STATE *
int_thread_set_item(ERR_STATE *d)
{
	ERR_STATE *p;
	LHASH_OF(ERR_STATE) *hash;

	err_fns_check();
	hash = ERRFN(thread_get)(1);
	if (!hash)
		return NULL;

	CRYPTO_w_lock(CRYPTO_LOCK_ERR);
	p = lh_ERR_STATE_insert(hash, d);
	CRYPTO_w_unlock(CRYPTO_LOCK_ERR);

	ERRFN(thread_release)(&hash);
	return p;
}


static int
in_utf8(unsigned long value, void *arg)
{
	int *nchar;

	nchar = arg;
	(*nchar)++;
	return 1;
}


void *
lh_delete(_LHASH *lh, const void *data)
{
	unsigned long hash;
	LHASH_NODE *nn, **rn;
	void *ret;

	lh->error = 0;
	rn = getrn(lh, data, &hash);

	if (*rn == NULL) {
		lh->num_no_delete++;
		return (NULL);
	} else {
		nn= *rn;
		*rn = nn->next;
		ret = nn->data;
		free(nn);
		lh->num_delete++;
	}

	lh->num_items--;
	if ((lh->num_nodes > MIN_NODES) &&
	    (lh->down_load >= (lh->num_items * LH_LOAD_MULT / lh->num_nodes)))
		contract(lh);

	return (ret);
}


void *
lh_insert(_LHASH *lh, void *data)
{
	unsigned long hash;
	LHASH_NODE *nn, **rn;
	void *ret;

	lh->error = 0;
	if (lh->up_load <= (lh->num_items * LH_LOAD_MULT / lh->num_nodes))
		expand(lh);

	rn = getrn(lh, data, &hash);

	if (*rn == NULL) {
		if ((nn = malloc(sizeof(LHASH_NODE))) == NULL) {
			lh->error++;
			return (NULL);
		}
		nn->data = data;
		nn->next = NULL;
#ifndef OPENSSL_NO_HASH_COMP
		nn->hash = hash;
#endif
		*rn = nn;
		ret = NULL;
		lh->num_insert++;
		lh->num_items++;
	}
	else /* replace same key */
	{
		ret = (*rn)->data;
		(*rn)->data = data;
		lh->num_replace++;
	}
	return (ret);
}


_LHASH *
lh_new(LHASH_HASH_FN_TYPE h, LHASH_COMP_FN_TYPE c)
{
	_LHASH *ret;
	int i;

	if ((ret = malloc(sizeof(_LHASH))) == NULL)
		goto err0;
	if ((ret->b = reallocarray(NULL, MIN_NODES, sizeof(LHASH_NODE *))) == NULL)
		goto err1;
	for (i = 0; i < MIN_NODES; i++)
		ret->b[i] = NULL;
	ret->comp = ((c == NULL) ? (LHASH_COMP_FN_TYPE)strcmp : c);
	ret->hash = ((h == NULL) ? (LHASH_HASH_FN_TYPE)lh_strhash : h);
	ret->num_nodes = MIN_NODES / 2;
	ret->num_alloc_nodes = MIN_NODES;
	ret->p = 0;
	ret->pmax = MIN_NODES / 2;
	ret->up_load = UP_LOAD;
	ret->down_load = DOWN_LOAD;
	ret->num_items = 0;

	ret->num_expands = 0;
	ret->num_expand_reallocs = 0;
	ret->num_contracts = 0;
	ret->num_contract_reallocs = 0;
	ret->num_hash_calls = 0;
	ret->num_comp_calls = 0;
	ret->num_insert = 0;
	ret->num_replace = 0;
	ret->num_delete = 0;
	ret->num_no_delete = 0;
	ret->num_retrieve = 0;
	ret->num_retrieve_miss = 0;
	ret->num_hash_comps = 0;

	ret->error = 0;
	return (ret);

err1:
	free(ret);
err0:
	return (NULL);
}


void *
lh_retrieve(_LHASH *lh, const void *data)
{
	unsigned long hash;
	LHASH_NODE **rn;
	void *ret;

	lh->error = 0;
	rn = getrn(lh, data, &hash);

	if (*rn == NULL) {
		lh->num_retrieve_miss++;
		return (NULL);
	} else {
		ret = (*rn)->data;
		lh->num_retrieve++;
	}
	return (ret);
}


unsigned long
lh_strhash(const char *c)
{
	unsigned long ret = 0;
	long n;
	unsigned long v;
	int r;

	if ((c == NULL) || (*c == '\0'))
		return (ret);
/*
	unsigned char b[16];
	MD5(c,strlen(c),b);
	return(b[0]|(b[1]<<8)|(b[2]<<16)|(b[3]<<24));
*/

	n = 0x100;
	while (*c) {
		v = n | (*c);
		n += 0x100;
		r = (int)((v >> 2) ^ v) & 0x0f;
		ret = (ret << r)|(ret >> (32 - r));
		ret &= 0xFFFFFFFFL;
		ret ^= v * v;
		c++;
	}
	return ((ret >> 16) ^ ret);
}


static void
ll_append_head(CIPHER_ORDER **head, CIPHER_ORDER *curr,
    CIPHER_ORDER **tail)
{
	if (curr == *head)
		return;
	if (curr == *tail)
		*tail = curr->prev;
	if (curr->next != NULL)
		curr->next->prev = curr->prev;
	if (curr->prev != NULL)
		curr->prev->next = curr->next;
	(*head)->prev = curr;
	curr->next= *head;
	curr->prev = NULL;
	*head = curr;
}


static void
ll_append_tail(CIPHER_ORDER **head, CIPHER_ORDER *curr,
    CIPHER_ORDER **tail)
{
	if (curr == *tail)
		return;
	if (curr == *head)
		*head = curr->next;
	if (curr->prev != NULL)
		curr->prev->next = curr->next;
	if (curr->next != NULL)
		curr->next->prev = curr->prev;
	(*tail)->next = curr;
	curr->prev= *tail;
	curr->next = NULL;
	*tail = curr;
}


void
load_pKey_and_cert_to_ssl_ctx()
{
  debug_fprintf(stdout, "Creating SSL context...");
  ctx = SSL_CTX_new(SSLv23_method());
  if (!ctx) {
    puts(" Context creation failed");
    sgx_exit(NULL);
  }
  debug_fprintf(stdout, "Done\n");

  debug_fprintf(stdout, "Loading SSL context Certificate...");
  /* Load the server certificate into the SSL_CTX structure */
  if (SSL_CTX_use_certificate_file(ctx, cert_file, SSL_FILETYPE_PEM) <= 0) {
    debug_fprintf(stderr, "Context certificate file failed\n");
    sgx_exit(NULL);
  }
  debug_fprintf(stdout, "Done\n");

  /* Load the private-key corresponding to the server certificate */
  debug_fprintf(stdout, "Loading SSL context Private Key...");
  if (SSL_CTX_use_PrivateKey_file(ctx, priv_key_file, SSL_FILETYPE_PEM) <= 0) {
    debug_fprintf(stderr, "Context Private Key failed\n");
    sgx_exit(NULL);
  }
  debug_fprintf(stdout, "Done\n");

  debug_fprintf(stdout, "Retrieving Private Key from SSL context...");
  if((private_key = SSL_CTX_get_privatekey(ctx)) == NULL){
    debug_fprintf(stderr, "Retrieving Private Key from ctx failed\n");
    sgx_exit(NULL);
  }
  debug_fprintf(stdout, "Done\n");

  rsa = private_key->pkey.rsa;
}


static void
local_sk_X509_NAME_ENTRY_pop_free(STACK_OF(X509_NAME_ENTRY) *ne)
{
	sk_X509_NAME_ENTRY_pop_free(ne, X509_NAME_ENTRY_free);
}


static int
long_c2i(ASN1_VALUE **pval, const unsigned char *cont, int len, int utype,
    char *free_cont, const ASN1_ITEM *it)
{
	int neg, i;
	long ltmp;
	unsigned long utmp = 0;
	char *cp = (char *)pval;
	if (len > (int)sizeof(long)) {
		ASN1err(ASN1_F_LONG_C2I, ASN1_R_INTEGER_TOO_LARGE_FOR_LONG);
		return 0;
	}
	/* Is it negative? */
	if (len && (cont[0] & 0x80))
		neg = 1;
	else
		neg = 0;
	utmp = 0;
	for (i = 0; i < len; i++) {
		utmp <<= 8;
		if (neg)
			utmp |= cont[i] ^ 0xff;
		else
			utmp |= cont[i];
	}
	ltmp = (long)utmp;
	if (neg) {
		ltmp++;
		ltmp = -ltmp;
	}
	if (ltmp == it->size) {
		ASN1err(ASN1_F_LONG_C2I, ASN1_R_INTEGER_TOO_LARGE_FOR_LONG);
		return 0;
	}
	memcpy(cp, &ltmp, sizeof(long));
	return 1;
}


int ngx_cdecl
main(int argc, char *const *argv)
{
    ngx_buf_t        *b;
    ngx_log_t        *log;
    ngx_uint_t        i;
    ngx_cycle_t      *cycle, init_cycle;
    ngx_conf_dump_t  *cd;
    ngx_core_conf_t  *ccf;

    ngx_debug_init();

    if (ngx_strerror_init() != NGX_OK) {
        return 1;
    }

    if (ngx_get_options(argc, argv) != NGX_OK) {
        return 1;
    }

    if (ngx_show_version) {
        ngx_show_version_info();

        if (!ngx_test_config) {
            return 0;
        }
    }

    /* TODO */ ngx_max_sockets = -1;

    ngx_time_init();

#if (NGX_PCRE)
    ngx_regex_init();
#endif

    ngx_pid = ngx_getpid();

    log = ngx_log_init(ngx_prefix);
    if (log == NULL) {
        return 1;
    }

    /* STUB */
#if (NGX_OPENSSL)
    ngx_ssl_init(log);
#endif

    /*
     * init_cycle->log is required for signal handlers and
     * ngx_process_options()
     */

    ngx_memzero(&init_cycle, sizeof(ngx_cycle_t));
    init_cycle.log = log;
    ngx_cycle = &init_cycle;

    init_cycle.pool = ngx_create_pool(1024, log);
    if (init_cycle.pool == NULL) {
        return 1;
    }

    if (ngx_save_argv(&init_cycle, argc, argv) != NGX_OK) {
        return 1;
    }

    if (ngx_process_options(&init_cycle) != NGX_OK) {
        return 1;
    }

    if (ngx_os_init(log) != NGX_OK) {
        return 1;
    }

    /*
     * ngx_crc32_table_init() requires ngx_cacheline_size set in ngx_os_init()
     */

    if (ngx_crc32_table_init() != NGX_OK) {
        return 1;
    }

    if (ngx_add_inherited_sockets(&init_cycle) != NGX_OK) {
        return 1;
    }

    if (ngx_preinit_modules() != NGX_OK) {
        return 1;
    }

    cycle = ngx_init_cycle(&init_cycle);
    if (cycle == NULL) {
        if (ngx_test_config) {
            ngx_log_stderr(0, "configuration file %s test failed",
                           init_cycle.conf_file.data);
        }

        return 1;
    }

    if (ngx_test_config) {
        if (!ngx_quiet_mode) {
            ngx_log_stderr(0, "configuration file %s test is successful",
                           cycle->conf_file.data);
        }

        if (ngx_dump_config) {
            cd = cycle->config_dump.elts;

            for (i = 0; i < cycle->config_dump.nelts; i++) {

                ngx_write_stdout("# configuration file ");
                (void) ngx_write_fd(ngx_stdout, cd[i].name.data,
                                    cd[i].name.len);
                ngx_write_stdout(":" NGX_LINEFEED);

                b = cd[i].buffer;

                (void) ngx_write_fd(ngx_stdout, b->pos, b->last - b->pos);
                ngx_write_stdout(NGX_LINEFEED);
            }
        }

        return 0;
    }

    if (ngx_signal) {
        return ngx_signal_process(cycle, ngx_signal);
    }

    ngx_os_status(cycle->log);

    ngx_cycle = cycle;

    ccf = (ngx_core_conf_t *) ngx_get_conf(cycle->conf_ctx, ngx_core_module);

    if (ccf->master && ngx_process == NGX_PROCESS_SINGLE) {
        ngx_process = NGX_PROCESS_MASTER;
    }

#if !(NGX_WIN32)

    if (ngx_init_signals(cycle->log) != NGX_OK) {
        return 1;
    }

    if (!ngx_inherited && ccf->daemon) {
        if (ngx_daemon(cycle->log) != NGX_OK) {
            return 1;
        }

        ngx_daemonized = 1;
    }

    if (ngx_inherited) {
        ngx_daemonized = 1;
    }

#endif

    if (ngx_create_pidfile(&ccf->pid, cycle->log) != NGX_OK) {
        return 1;
    }

    if (ngx_log_redirect_stderr(cycle) != NGX_OK) {
        return 1;
    }

    if (log->file->fd != ngx_stderr) {
        if (ngx_close_file(log->file->fd) == NGX_FILE_ERROR) {
            ngx_log_error(NGX_LOG_ALERT, cycle->log, ngx_errno,
                          ngx_close_file_n " built-in log failed");
        }
    }

    ngx_use_stderr = 0;

    if (ngx_process == NGX_PROCESS_SINGLE) {
        ngx_single_process_cycle(cycle);

    } else {
        ngx_master_process_cycle(cycle);
    }

    return 0;
}


const void *
OBJ_bsearch_(const void *key, const void *base, int num, int size,
    int (*cmp)(const void *, const void *))
{
	return OBJ_bsearch_ex_(key, base, num, size, cmp, 0);
}
OBJ_bsearch_ex_(const void *key, const void *base_, int num, int size,
    int (*cmp)(const void *, const void *), int flags)
{
	const char *base = base_;
	int l, h, i = 0, c = 0;
	const char *p = NULL;

	if (num == 0)
		return (NULL);
	l = 0;
	h = num;
	while (l < h) {
		i = (l + h) / 2;
		p = &(base[i * size]);
		c = (*cmp)(key, p);
		if (c < 0)
			h = i;
		else if (c > 0)
			l = i + 1;
		else
			break;
	}
	if (c != 0 && !(flags & OBJ_BSEARCH_VALUE_ON_NOMATCH))
		p = NULL;
	else if (c == 0 && (flags & OBJ_BSEARCH_FIRST_VALUE_ON_MATCH)) {
		while (i > 0 && (*cmp)(key, &(base[(i - 1) * size])) == 0)
			i--;
		p = &(base[i * size]);
	}
	return (p);
}


const void *
OBJ_bsearch_ex_(const void *key, const void *base_, int num, int size,
    int (*cmp)(const void *, const void *), int flags)
{
	const char *base = base_;
	int l, h, i = 0, c = 0;
	const char *p = NULL;

	if (num == 0)
		return (NULL);
	l = 0;
	h = num;
	while (l < h) {
		i = (l + h) / 2;
		p = &(base[i * size]);
		c = (*cmp)(key, p);
		if (c < 0)
			h = i;
		else if (c > 0)
			l = i + 1;
		else
			break;
	}
	if (c != 0 && !(flags & OBJ_BSEARCH_VALUE_ON_NOMATCH))
		p = NULL;
	else if (c == 0 && (flags & OBJ_BSEARCH_FIRST_VALUE_ON_MATCH)) {
		while (i > 0 && (*cmp)(key, &(base[(i - 1) * size])) == 0)
			i--;
		p = &(base[i * size]);
	}
	return (p);
}


static int
obj_cmp(const ASN1_OBJECT * const *ap, const unsigned int *bp)
{
	int j;
	const ASN1_OBJECT *a= *ap;
	const ASN1_OBJECT *b = &nid_objs[*bp];

	j = (a->length - b->length);
	if (j)
		return (j);
	return (memcmp(a->data, b->data, a->length));
}


ASN1_OBJECT *
OBJ_dup(const ASN1_OBJECT *o)
{
	ASN1_OBJECT *r;
	char *ln = NULL, *sn = NULL;
	unsigned char *data = NULL;

	if (o == NULL)
		return (NULL);
	if (!(o->flags & ASN1_OBJECT_FLAG_DYNAMIC))
		return((ASN1_OBJECT *)o); /* XXX: ugh! Why? What kind of
					     duplication is this??? */

	r = ASN1_OBJECT_new();
	if (r == NULL) {
		OBJerr(OBJ_F_OBJ_DUP, ERR_R_ASN1_LIB);
		return (NULL);
	}
	data = malloc(o->length);
	if (data == NULL)
		goto err;
	if (o->data != NULL)
		memcpy(data, o->data, o->length);
	/* once data attached to object it remains const */
	r->data = data;
	r->length = o->length;
	r->nid = o->nid;
	r->ln = r->sn = NULL;
	if (o->ln != NULL) {
		ln = strdup(o->ln);
		if (ln == NULL)
			goto err;
		r->ln = ln;
	}

	if (o->sn != NULL) {
		sn = strdup(o->sn);
		if (sn == NULL)
			goto err;
		r->sn = sn;
	}
	r->flags = o->flags | (ASN1_OBJECT_FLAG_DYNAMIC |
	    ASN1_OBJECT_FLAG_DYNAMIC_STRINGS | ASN1_OBJECT_FLAG_DYNAMIC_DATA);
	return (r);

err:
	OBJerr(OBJ_F_OBJ_DUP, ERR_R_MALLOC_FAILURE);
	free(ln);
	free(sn);
	free(data);
	free(r);
	return (NULL);
}


int
OBJ_NAME_add(const char *name, int type, const char *data)
{
	OBJ_NAME *onp, *ret;
	int alias;

	if ((names_lh == NULL) && !OBJ_NAME_init())
		return (0);

	alias = type & OBJ_NAME_ALIAS;
	type &= ~OBJ_NAME_ALIAS;

	onp = malloc(sizeof(OBJ_NAME));
	if (onp == NULL) {
		/* ERROR */
		return (0);
	}

	onp->name = name;
	onp->alias = alias;
	onp->type = type;
	onp->data = data;

	ret = lh_OBJ_NAME_insert(names_lh, onp);
	if (ret != NULL) {
		/* free things */
		if ((name_funcs_stack != NULL) &&
		    (sk_NAME_FUNCS_num(name_funcs_stack) > ret->type)) {
			/* XXX: I'm not sure I understand why the free
			 * function should get three arguments...
			 * -- Richard Levitte
			 */
			sk_NAME_FUNCS_value(
			    name_funcs_stack, ret->type)->free_func(
			    ret->name, ret->type, ret->data);
		}
		free(ret);
	} else {
		if (lh_OBJ_NAME_error(names_lh)) {
			/* ERROR */
			return (0);
		}
	}
	return (1);
}


static int
obj_name_cmp(const void *a_void, const void *b_void)
{
	int ret;
	const OBJ_NAME *a = (const OBJ_NAME *)a_void;
	const OBJ_NAME *b = (const OBJ_NAME *)b_void;

	ret = a->type - b->type;
	if (ret == 0) {
		if ((name_funcs_stack != NULL) &&
		    (sk_NAME_FUNCS_num(name_funcs_stack) > a->type)) {
			ret = sk_NAME_FUNCS_value(name_funcs_stack,
			    a->type)->cmp_func(a->name, b->name);
		} else
			ret = strcmp(a->name, b->name);
	}
	return (ret);
}


const char *
OBJ_NAME_get(const char *name, int type)
{
	OBJ_NAME on, *ret;
	int num = 0, alias;

	if (name == NULL)
		return (NULL);
	if ((names_lh == NULL) && !OBJ_NAME_init())
		return (NULL);

	alias = type&OBJ_NAME_ALIAS;
	type&= ~OBJ_NAME_ALIAS;

	on.name = name;
	on.type = type;

	for (;;) {
		ret = lh_OBJ_NAME_retrieve(names_lh, &on);
		if (ret == NULL)
			return (NULL);
		if ((ret->alias) && !alias) {
			if (++num > 10)
				return (NULL);
			on.name = ret->data;
		} else {
			return (ret->data);
		}
	}
}


static unsigned long
obj_name_hash(const void *a_void)
{
	unsigned long ret;
	const OBJ_NAME *a = (const OBJ_NAME *)a_void;

	if ((name_funcs_stack != NULL) &&
	    (sk_NAME_FUNCS_num(name_funcs_stack) > a->type)) {
		ret = sk_NAME_FUNCS_value(name_funcs_stack,
		    a->type)->hash_func(a->name);
	} else {
		ret = lh_strhash(a->name);
	}
	ret ^= a->type;
	return (ret);
}


int
OBJ_NAME_init(void)
{
	if (names_lh != NULL)
		return (1);
	names_lh = lh_OBJ_NAME_new();
	return (names_lh != NULL);
}


const char *
OBJ_nid2ln(int n)
{
	ADDED_OBJ ad, *adp;
	ASN1_OBJECT ob;

	if ((n >= 0) && (n < NUM_NID)) {
		if ((n != NID_undef) && (nid_objs[n].nid == NID_undef)) {
			OBJerr(OBJ_F_OBJ_NID2LN, OBJ_R_UNKNOWN_NID);
			return (NULL);
		}
		return (nid_objs[n].ln);
	} else if (added == NULL)
		return (NULL);
	else {
		ad.type = ADDED_NID;
		ad.obj = &ob;
		ob.nid = n;
		adp = lh_ADDED_OBJ_retrieve(added, &ad);
		if (adp != NULL)
			return (adp->obj->ln);
		else {
			OBJerr(OBJ_F_OBJ_NID2LN, OBJ_R_UNKNOWN_NID);
			return (NULL);
		}
	}
}


ASN1_OBJECT *
OBJ_nid2obj(int n)
{
	ADDED_OBJ ad, *adp;
	ASN1_OBJECT ob;

	if ((n >= 0) && (n < NUM_NID)) {
		if ((n != NID_undef) && (nid_objs[n].nid == NID_undef)) {
			OBJerr(OBJ_F_OBJ_NID2OBJ, OBJ_R_UNKNOWN_NID);
			return (NULL);
		}
		return ((ASN1_OBJECT *)&(nid_objs[n]));
	} else if (added == NULL)
		return (NULL);
	else {
		ad.type = ADDED_NID;
		ad.obj = &ob;
		ob.nid = n;
		adp = lh_ADDED_OBJ_retrieve(added, &ad);
		if (adp != NULL)
			return (adp->obj);
		else {
			OBJerr(OBJ_F_OBJ_NID2OBJ, OBJ_R_UNKNOWN_NID);
			return (NULL);
		}
	}
}


const char *
OBJ_nid2sn(int n)
{
	ADDED_OBJ ad, *adp;
	ASN1_OBJECT ob;

	if ((n >= 0) && (n < NUM_NID)) {
		if ((n != NID_undef) && (nid_objs[n].nid == NID_undef)) {
			OBJerr(OBJ_F_OBJ_NID2SN, OBJ_R_UNKNOWN_NID);
			return (NULL);
		}
		return (nid_objs[n].sn);
	} else if (added == NULL)
		return (NULL);
	else {
		ad.type = ADDED_NID;
		ad.obj = &ob;
		ob.nid = n;
		adp = lh_ADDED_OBJ_retrieve(added, &ad);
		if (adp != NULL)
			return (adp->obj->sn);
		else {
			OBJerr(OBJ_F_OBJ_NID2SN, OBJ_R_UNKNOWN_NID);
			return (NULL);
		}
	}
}


int
OBJ_obj2nid(const ASN1_OBJECT *a)
{
	const unsigned int *op;
	ADDED_OBJ ad, *adp;

	if (a == NULL)
		return (NID_undef);
	if (a->nid != 0)
		return (a->nid);

	if (added != NULL) {
		ad.type = ADDED_DATA;
		ad.obj=(ASN1_OBJECT *)a; /* XXX: ugly but harmless */
		adp = lh_ADDED_OBJ_retrieve(added, &ad);
		if (adp != NULL)
			return (adp->obj->nid);
	}
	op = OBJ_bsearch_obj(&a, obj_objs, NUM_OBJ);
	if (op == NULL)
		return (NID_undef);
	return (nid_objs[*op].nid);
}


static int
old_rsa_priv_decode(EVP_PKEY *pkey, const unsigned char **pder, int derlen)
{
	RSA *rsa;

	if (!(rsa = d2i_RSAPrivateKey (NULL, pder, derlen))) {
		RSAerr(RSA_F_OLD_RSA_PRIV_DECODE, ERR_R_RSA_LIB);
		return 0;
	}
	EVP_PKEY_assign_RSA(pkey, rsa);
	return 1;
}


int
opensgx_pipe_init(int flag_dir)
{
  int ret;

  if (flag_dir == 0)
    ret = mkdir(TMP_DIRECTORY_CONF, 0770);
  else if (flag_dir == 1)
    ret = mkdir(TMP_DIRECTORY_RUN, 0770);

  if (ret == -1) {
    if (errno != EEXIST) {
      debug_fprintf(stderr, "Fail to mkdir");
      return -1;
    }
  }
  return 0;
}


int
opensgx_pipe_open(char* unique_id, int is_write, int flag_dir)
{
  char name_buf[NAME_BUF_SIZE];

  if (flag_dir == 0) {
    strcpy(name_buf, TMP_DIRECTORY_CONF);
    strcpy(name_buf + strlen(name_buf), TMP_FILE_NUMBER_FMT);
    strcpy(name_buf + strlen(name_buf), unique_id);
  } else if (flag_dir == 1) {
    strcpy(name_buf, TMP_DIRECTORY_RUN);
    strcpy(name_buf + strlen(name_buf), TMP_FILE_NUMBER_FMT);
    strcpy(name_buf + strlen(name_buf), unique_id);
  }

  int ret = mknod(name_buf, S_IFIFO | 0770, 0);
  if (ret == -1) {
    if (errno != EEXIST) {
      debug_fprintf(stderr, "Fail to mknod");
      return -1;
    }
  }

  int flag = O_ASYNC;
  if (is_write)
    flag |= O_WRONLY;
  else
    flag |= O_RDONLY;

  int fd = open(name_buf, flag);

  if (fd == -1) {
    debug_fprintf(stderr, "Fail to open()");
    return -1;
  }

  return fd;
}


uint64_t
OPENSSL_cpu_caps(void)
{
	return *(uint64_t *)OPENSSL_ia32cap_P;
}
OPENSSL_cpu_caps(void)
{
	return 0;
}


void
OPENSSL_cpuid_setup(void)
{
	static int trigger = 0;
	IA32CAP OPENSSL_ia32_cpuid(void);
	IA32CAP vec;

	if (trigger)
		return;
	trigger = 1;

	vec = OPENSSL_ia32_cpuid();

	/*
	 * |(1<<10) sets a reserved bit to signal that variable
	 * was initialized already... This is to avoid interference
	 * with cpuid snippets in ELF .init segment.
	 */
	OPENSSL_ia32cap_P[0] = (unsigned int)vec | (1 << 10);
	OPENSSL_ia32cap_P[1] = (unsigned int)(vec >> 32);
}
OPENSSL_cpuid_setup(void)
{
}


void
OPENSSL_init(void)
{

}


static int
out_utf8(unsigned long value, void *arg)
{
	int *outlen;
	int ret;

	outlen = arg;
	ret = UTF8_putc(NULL, -1, value);
	if (ret < 0)
		return ret;
	*outlen += ret;
	return 1;
}


void *
PEM_ASN1_read_bio(d2i_of_void *d2i, const char *name, BIO *bp, void **x,
    pem_password_cb *cb, void *u)
{
	const unsigned char *p = NULL;
	unsigned char *data = NULL;
	long len;
	char *ret = NULL;

	if (!PEM_bytes_read_bio(&data, &len, NULL, name, bp, cb, u))
		return NULL;
	p = data;
	ret = d2i(x, &p, len);
	if (ret == NULL)
		PEMerr(PEM_F_PEM_ASN1_READ_BIO, ERR_R_ASN1_LIB);
	free(data);
	return (ret);
}


int
PEM_bytes_read_bio(unsigned char **pdata, long *plen, char **pnm,
    const char *name, BIO *bp, pem_password_cb *cb, void *u)
{
	EVP_CIPHER_INFO cipher;
	char *nm = NULL, *header = NULL;
	unsigned char *data = NULL;
	long len;
	int ret = 0;

	for (;;) {
		if (!PEM_read_bio(bp, &nm, &header, &data, &len)) {
			if (ERR_GET_REASON(ERR_peek_error()) ==
			    PEM_R_NO_START_LINE)
				ERR_asprintf_error_data("Expecting: %s", name);
			return 0;
		}
		if (check_pem(nm, name))
			break;
		free(nm);
		free(header);
		free(data);
	}
	if (!PEM_get_EVP_CIPHER_INFO(header, &cipher))
		goto err;
	if (!PEM_do_header(&cipher, data, &len, cb, u))
		goto err;

	*pdata = data;
	*plen = len;

	if (pnm)
		*pnm = nm;

	ret = 1;

err:
	if (!ret || !pnm)
		free(nm);
	free(header);
	if (!ret)
		free(data);
	return ret;
}


int
PEM_do_header(EVP_CIPHER_INFO *cipher, unsigned char *data, long *plen,
    pem_password_cb *callback, void *u)
{
	int i, j, o, klen;
	long len;
	EVP_CIPHER_CTX ctx;
	unsigned char key[EVP_MAX_KEY_LENGTH];
	char buf[PEM_BUFSIZE];

	len = *plen;

	if (cipher->cipher == NULL)
		return (1);
	if (callback == NULL)
		klen = PEM_def_callback(buf, PEM_BUFSIZE, 0, u);
	else
		klen = callback(buf, PEM_BUFSIZE, 0, u);
	if (klen <= 0) {
		PEMerr(PEM_F_PEM_DO_HEADER, PEM_R_BAD_PASSWORD_READ);
		return (0);
	}
	if (!EVP_BytesToKey(cipher->cipher, EVP_md5(), &(cipher->iv[0]),
	    (unsigned char *)buf, klen, 1, key, NULL))
		return 0;

	j = (int)len;
	EVP_CIPHER_CTX_init(&ctx);
	o = EVP_DecryptInit_ex(&ctx, cipher->cipher, NULL, key,
	    &(cipher->iv[0]));
	if (o)
		o = EVP_DecryptUpdate(&ctx, data, &i, data, j);
	if (o)
		o = EVP_DecryptFinal_ex(&ctx, &(data[i]), &j);
	EVP_CIPHER_CTX_cleanup(&ctx);
	explicit_bzero((char *)buf, sizeof(buf));
	explicit_bzero((char *)key, sizeof(key));
	if (!o) {
		PEMerr(PEM_F_PEM_DO_HEADER, PEM_R_BAD_DECRYPT);
		return (0);
	}
	*plen = j + i;
	return (1);
}


int
PEM_get_EVP_CIPHER_INFO(char *header, EVP_CIPHER_INFO *cipher)
{
	const EVP_CIPHER *enc = NULL;
	char *p, c;
	char **header_pp = &header;

	cipher->cipher = NULL;
	if ((header == NULL) || (*header == '\0') || (*header == '\n'))
		return (1);
	if (strncmp(header, "Proc-Type: ", 11) != 0) {
		PEMerr(PEM_F_PEM_GET_EVP_CIPHER_INFO, PEM_R_NOT_PROC_TYPE);
		return (0);
	}
	header += 11;
	if (*header != '4')
		return (0);
	header++;
	if (*header != ',')
		return (0);
	header++;
	if (strncmp(header, "ENCRYPTED", 9) != 0) {
		PEMerr(PEM_F_PEM_GET_EVP_CIPHER_INFO, PEM_R_NOT_ENCRYPTED);
		return (0);
	}
	for (; (*header != '\n') && (*header != '\0'); header++)
		;
	if (*header == '\0') {
		PEMerr(PEM_F_PEM_GET_EVP_CIPHER_INFO, PEM_R_SHORT_HEADER);
		return (0);
	}
	header++;
	if (strncmp(header, "DEK-Info: ", 10) != 0) {
		PEMerr(PEM_F_PEM_GET_EVP_CIPHER_INFO, PEM_R_NOT_DEK_INFO);
		return (0);
	}
	header += 10;

	p = header;
	for (;;) {
		c= *header;
		if (!(	((c >= 'A') && (c <= 'Z')) || (c == '-') ||
		    ((c >= '0') && (c <= '9'))))
			break;
		header++;
	}
	*header = '\0';
	cipher->cipher = enc = EVP_get_cipherbyname(p);
	*header = c;
	header++;

	if (enc == NULL) {
		PEMerr(PEM_F_PEM_GET_EVP_CIPHER_INFO,
		    PEM_R_UNSUPPORTED_ENCRYPTION);
		return (0);
	}
	if (!load_iv(header_pp, &(cipher->iv[0]), enc->iv_len))
		return (0);

	return (1);
}


int
PEM_read_bio(BIO *bp, char **name, char **header, unsigned char **data,
    long *len)
{
	EVP_ENCODE_CTX ctx;
	int end = 0, i, k, bl = 0, hl = 0, nohead = 0;
	char buf[256];
	BUF_MEM *nameB;
	BUF_MEM *headerB;
	BUF_MEM *dataB, *tmpB;

	nameB = BUF_MEM_new();
	headerB = BUF_MEM_new();
	dataB = BUF_MEM_new();
	if ((nameB == NULL) || (headerB == NULL) || (dataB == NULL)) {
		BUF_MEM_free(nameB);
		BUF_MEM_free(headerB);
		BUF_MEM_free(dataB);
		PEMerr(PEM_F_PEM_READ_BIO, ERR_R_MALLOC_FAILURE);
		return (0);
	}

	buf[254] = '\0';
	for (;;) {
		i = BIO_gets(bp, buf, 254);

		if (i <= 0) {
			PEMerr(PEM_F_PEM_READ_BIO, PEM_R_NO_START_LINE);
			goto err;
		}

		while ((i >= 0) && (buf[i] <= ' '))
			i--;
		buf[++i] = '\n';
		buf[++i] = '\0';

		if (strncmp(buf, "-----BEGIN ", 11) == 0) {
			i = strlen(&(buf[11]));

			if (strncmp(&(buf[11 + i - 6]), "-----\n", 6) != 0)
				continue;
			if (!BUF_MEM_grow(nameB, i + 9)) {
				PEMerr(PEM_F_PEM_READ_BIO,
				    ERR_R_MALLOC_FAILURE);
				goto err;
			}
			memcpy(nameB->data, &(buf[11]), i - 6);
			nameB->data[i - 6] = '\0';
			break;
		}
	}
	hl = 0;
	if (!BUF_MEM_grow(headerB, 256)) {
		PEMerr(PEM_F_PEM_READ_BIO, ERR_R_MALLOC_FAILURE);
		goto err;
	}
	headerB->data[0] = '\0';
	for (;;) {
		i = BIO_gets(bp, buf, 254);
		if (i <= 0)
			break;

		while ((i >= 0) && (buf[i] <= ' '))
			i--;
		buf[++i] = '\n';
		buf[++i] = '\0';

		if (buf[0] == '\n')
			break;
		if (!BUF_MEM_grow(headerB, hl + i + 9)) {
			PEMerr(PEM_F_PEM_READ_BIO, ERR_R_MALLOC_FAILURE);
			goto err;
		}
		if (strncmp(buf, "-----END ", 9) == 0) {
			nohead = 1;
			break;
		}
		memcpy(&(headerB->data[hl]), buf, i);
		headerB->data[hl + i] = '\0';
		hl += i;
	}

	bl = 0;
	if (!BUF_MEM_grow(dataB, 1024)) {
		PEMerr(PEM_F_PEM_READ_BIO, ERR_R_MALLOC_FAILURE);
		goto err;
	}
	dataB->data[0] = '\0';
	if (!nohead) {
		for (;;) {
			i = BIO_gets(bp, buf, 254);
			if (i <= 0)
				break;

			while ((i >= 0) && (buf[i] <= ' '))
				i--;
			buf[++i] = '\n';
			buf[++i] = '\0';

			if (i != 65)
				end = 1;
			if (strncmp(buf, "-----END ", 9) == 0)
				break;
			if (i > 65)
				break;
			if (!BUF_MEM_grow_clean(dataB, i + bl + 9)) {
				PEMerr(PEM_F_PEM_READ_BIO,
				    ERR_R_MALLOC_FAILURE);
				goto err;
			}
			memcpy(&(dataB->data[bl]), buf, i);
			dataB->data[bl + i] = '\0';
			bl += i;
			if (end) {
				buf[0] = '\0';
				i = BIO_gets(bp, buf, 254);
				if (i <= 0)
					break;

				while ((i >= 0) && (buf[i] <= ' '))
					i--;
				buf[++i] = '\n';
				buf[++i] = '\0';

				break;
			}
		}
	} else {
		tmpB = headerB;
		headerB = dataB;
		dataB = tmpB;
		bl = hl;
	}
	i = strlen(nameB->data);
	if ((strncmp(buf, "-----END ", 9) != 0) ||
	    (strncmp(nameB->data, &(buf[9]), i) != 0) ||
	    (strncmp(&(buf[9 + i]), "-----\n", 6) != 0)) {
		PEMerr(PEM_F_PEM_READ_BIO, PEM_R_BAD_END_LINE);
		goto err;
	}

	EVP_DecodeInit(&ctx);
	i = EVP_DecodeUpdate(&ctx,
	    (unsigned char *)dataB->data, &bl,
	    (unsigned char *)dataB->data, bl);
	if (i < 0) {
		PEMerr(PEM_F_PEM_READ_BIO, PEM_R_BAD_BASE64_DECODE);
		goto err;
	}
	i = EVP_DecodeFinal(&ctx, (unsigned char *)&(dataB->data[bl]), &k);
	if (i < 0) {
		PEMerr(PEM_F_PEM_READ_BIO, PEM_R_BAD_BASE64_DECODE);
		goto err;
	}
	bl += k;

	if (bl == 0)
		goto err;
	*name = nameB->data;
	*header = headerB->data;
	*data = (unsigned char *)dataB->data;
	*len = bl;
	free(nameB);
	free(headerB);
	free(dataB);
	return (1);

err:
	BUF_MEM_free(nameB);
	BUF_MEM_free(headerB);
	BUF_MEM_free(dataB);
	return (0);
}


EVP_PKEY *
PEM_read_bio_PrivateKey(BIO *bp, EVP_PKEY **x, pem_password_cb *cb, void *u)
{
	char *nm = NULL;
	const unsigned char *p = NULL;
	unsigned char *data = NULL;
	long len;
	int slen;
	EVP_PKEY *ret = NULL;

	if (!PEM_bytes_read_bio(&data, &len, &nm, PEM_STRING_EVP_PKEY,
	    bp, cb, u))
		return NULL;
	p = data;

	if (strcmp(nm, PEM_STRING_PKCS8INF) == 0) {
		PKCS8_PRIV_KEY_INFO *p8inf;
		p8inf = d2i_PKCS8_PRIV_KEY_INFO(NULL, &p, len);
		if (!p8inf)
			goto p8err;
		ret = EVP_PKCS82PKEY(p8inf);
		if (x) {
			EVP_PKEY_free(*x);
			*x = ret;
		}
		PKCS8_PRIV_KEY_INFO_free(p8inf);
	} else if (strcmp(nm, PEM_STRING_PKCS8) == 0) {
		PKCS8_PRIV_KEY_INFO *p8inf;
		X509_SIG *p8;
		int klen;
		char psbuf[PEM_BUFSIZE];
		p8 = d2i_X509_SIG(NULL, &p, len);
		if (!p8)
			goto p8err;
		if (cb)
			klen = cb(psbuf, PEM_BUFSIZE, 0, u);
		else
			klen = PEM_def_callback(psbuf, PEM_BUFSIZE, 0, u);
		if (klen <= 0) {
			PEMerr(PEM_F_PEM_READ_BIO_PRIVATEKEY,
			    PEM_R_BAD_PASSWORD_READ);
			X509_SIG_free(p8);
			goto err;
		}
		p8inf = PKCS8_decrypt(p8, psbuf, klen);
		X509_SIG_free(p8);
		if (!p8inf)
			goto p8err;
		ret = EVP_PKCS82PKEY(p8inf);
		if (x) {
			EVP_PKEY_free(*x);
			*x = ret;
		}
		PKCS8_PRIV_KEY_INFO_free(p8inf);
	} else if ((slen = pem_check_suffix(nm, "PRIVATE KEY")) > 0) {
		const EVP_PKEY_ASN1_METHOD *ameth;
		ameth = EVP_PKEY_asn1_find_str(NULL, nm, slen);
		if (!ameth || !ameth->old_priv_decode)
			goto p8err;
		ret = d2i_PrivateKey(ameth->pkey_id, x, &p, len);
	}

p8err:
	if (ret == NULL)
		PEMerr(PEM_F_PEM_READ_BIO_PRIVATEKEY, ERR_R_ASN1_LIB);
err:
	free(nm);
	explicit_bzero(data, len);
	free(data);
	return (ret);
}


int
PKCS8_pkey_get0(ASN1_OBJECT **ppkalg, const unsigned char **pk, int *ppklen,
    X509_ALGOR **pa, PKCS8_PRIV_KEY_INFO *p8)
{
	if (ppkalg)
		*ppkalg = p8->pkeyalg->algorithm;
	if (p8->pkey->type == V_ASN1_OCTET_STRING) {
		p8->broken = PKCS8_OK;
		if (pk) {
			*pk = p8->pkey->value.octet_string->data;
			*ppklen = p8->pkey->value.octet_string->length;
		}
	} else if (p8->pkey->type == V_ASN1_SEQUENCE) {
		p8->broken = PKCS8_NO_OCTET;
		if (pk) {
			*pk = p8->pkey->value.sequence->data;
			*ppklen = p8->pkey->value.sequence->length;
		}
	} else
		return 0;
	if (pa)
		*pa = p8->pkeyalg;
	return 1;
}


void
PKCS8_PRIV_KEY_INFO_free(PKCS8_PRIV_KEY_INFO *a)
{
	ASN1_item_free((ASN1_VALUE *)a, &PKCS8_PRIV_KEY_INFO_it);
}


static const EVP_PKEY_ASN1_METHOD *
pkey_asn1_find(int type)
{
	EVP_PKEY_ASN1_METHOD tmp;
	const EVP_PKEY_ASN1_METHOD *t = &tmp, **ret;
	tmp.pkey_id = type;
	if (app_methods) {
		int idx;
		idx = sk_EVP_PKEY_ASN1_METHOD_find(app_methods, &tmp);
		if (idx >= 0)
			return sk_EVP_PKEY_ASN1_METHOD_value(app_methods, idx);
	}
	ret = OBJ_bsearch_ameth(&t, standard_methods,
	    sizeof(standard_methods) / sizeof(EVP_PKEY_ASN1_METHOD *));
	if (!ret || !*ret)
		return NULL;
	return *ret;
}


static int
pkey_cb(int operation, ASN1_VALUE **pval, const ASN1_ITEM *it, void *exarg)
{
	/* Since the structure must still be valid use ASN1_OP_FREE_PRE */
	if (operation == ASN1_OP_FREE_PRE) {
		PKCS8_PRIV_KEY_INFO *key = (PKCS8_PRIV_KEY_INFO *)*pval;
		if (key->pkey != NULL &&
		    key->pkey->type == V_ASN1_OCTET_STRING &&
		    key->pkey->value.octet_string != NULL)
			explicit_bzero(key->pkey->value.octet_string->data,
			    key->pkey->value.octet_string->length);
	}
	return 1;
}


static void
pkey_hmac_cleanup(EVP_PKEY_CTX *ctx)
{
	HMAC_PKEY_CTX *hctx = ctx->data;

	HMAC_CTX_cleanup(&hctx->ctx);
	if (hctx->ktmp.data) {
		if (hctx->ktmp.length)
			explicit_bzero(hctx->ktmp.data, hctx->ktmp.length);
		free(hctx->ktmp.data);
		hctx->ktmp.data = NULL;
	}
	free(hctx);
}


static int
pkey_hmac_copy(EVP_PKEY_CTX *dst, EVP_PKEY_CTX *src)
{
	HMAC_PKEY_CTX *sctx, *dctx;

	if (!pkey_hmac_init(dst))
		return 0;
	sctx = src->data;
	dctx = dst->data;
	dctx->md = sctx->md;
	HMAC_CTX_init(&dctx->ctx);
	if (!HMAC_CTX_copy(&dctx->ctx, &sctx->ctx))
		return 0;
	if (sctx->ktmp.data) {
		if (!ASN1_OCTET_STRING_set(&dctx->ktmp, sctx->ktmp.data,
		    sctx->ktmp.length))
			return 0;
	}
	return 1;
}


static int
pkey_hmac_ctrl(EVP_PKEY_CTX *ctx, int type, int p1, void *p2)
{
	HMAC_PKEY_CTX *hctx = ctx->data;
	ASN1_OCTET_STRING *key;

	switch (type) {
	case EVP_PKEY_CTRL_SET_MAC_KEY:
		if ((!p2 && p1 > 0) || (p1 < -1))
			return 0;
		if (!ASN1_OCTET_STRING_set(&hctx->ktmp, p2, p1))
			return 0;
		break;

	case EVP_PKEY_CTRL_MD:
		hctx->md = p2;
		break;

	case EVP_PKEY_CTRL_DIGESTINIT:
		key = (ASN1_OCTET_STRING *)ctx->pkey->pkey.ptr;
		if (!HMAC_Init_ex(&hctx->ctx, key->data, key->length, hctx->md,
		    ctx->engine))
			return 0;
		break;

	default:
		return -2;
	}
	return 1;
}
pkey_hmac_ctrl_str(EVP_PKEY_CTX *ctx, const char *type, const char *value)
{
	if (!value)
		return 0;
	if (!strcmp(type, "key")) {
		void *p = (void *)value;
		return pkey_hmac_ctrl(ctx, EVP_PKEY_CTRL_SET_MAC_KEY, -1, p);
	}
	if (!strcmp(type, "hexkey")) {
		unsigned char *key;
		int r;
		long keylen;
		key = string_to_hex(value, &keylen);
		if (!key)
			return 0;
		r = pkey_hmac_ctrl(ctx, EVP_PKEY_CTRL_SET_MAC_KEY, keylen, key);
		free(key);
		return r;
	}
	return -2;
}


static int
pkey_hmac_init(EVP_PKEY_CTX *ctx)
{
	HMAC_PKEY_CTX *hctx;

	hctx = malloc(sizeof(HMAC_PKEY_CTX));
	if (!hctx)
		return 0;
	hctx->md = NULL;
	hctx->ktmp.data = NULL;
	hctx->ktmp.length = 0;
	hctx->ktmp.flags = 0;
	hctx->ktmp.type = V_ASN1_OCTET_STRING;
	HMAC_CTX_init(&hctx->ctx);

	ctx->data = hctx;
	ctx->keygen_info_count = 0;

	return 1;
}


static int
pkey_hmac_keygen(EVP_PKEY_CTX *ctx, EVP_PKEY *pkey)
{
	ASN1_OCTET_STRING *hkey = NULL;
	HMAC_PKEY_CTX *hctx = ctx->data;

	if (!hctx->ktmp.data)
		return 0;
	hkey = ASN1_OCTET_STRING_dup(&hctx->ktmp);
	if (!hkey)
		return 0;
	EVP_PKEY_assign(pkey, EVP_PKEY_HMAC, hkey);

	return 1;
}


static void
pkey_rsa_cleanup(EVP_PKEY_CTX *ctx)
{
	RSA_PKEY_CTX *rctx = ctx->data;

	if (rctx) {
		BN_free(rctx->pub_exp);
		free(rctx->tbuf);
		free(rctx);
	}
}


static int
pkey_rsa_ctrl(EVP_PKEY_CTX *ctx, int type, int p1, void *p2)
{
	RSA_PKEY_CTX *rctx = ctx->data;

	switch (type) {
	case EVP_PKEY_CTRL_RSA_PADDING:
		if (p1 >= RSA_PKCS1_PADDING && p1 <= RSA_PKCS1_PSS_PADDING) {
			if (!check_padding_md(rctx->md, p1))
				return 0;
			if (p1 == RSA_PKCS1_PSS_PADDING) {
				if (!(ctx->operation &
				    (EVP_PKEY_OP_SIGN | EVP_PKEY_OP_VERIFY)))
					goto bad_pad;
				if (!rctx->md)
					rctx->md = EVP_sha1();
			}
			if (p1 == RSA_PKCS1_OAEP_PADDING) {
				if (!(ctx->operation & EVP_PKEY_OP_TYPE_CRYPT))
					goto bad_pad;
				if (!rctx->md)
					rctx->md = EVP_sha1();
			}
			rctx->pad_mode = p1;
			return 1;
		}
bad_pad:
		RSAerr(RSA_F_PKEY_RSA_CTRL,
		    RSA_R_ILLEGAL_OR_UNSUPPORTED_PADDING_MODE);
		return -2;

	case EVP_PKEY_CTRL_GET_RSA_PADDING:
		*(int *)p2 = rctx->pad_mode;
		return 1;

	case EVP_PKEY_CTRL_RSA_PSS_SALTLEN:
	case EVP_PKEY_CTRL_GET_RSA_PSS_SALTLEN:
		if (rctx->pad_mode != RSA_PKCS1_PSS_PADDING) {
			RSAerr(RSA_F_PKEY_RSA_CTRL, RSA_R_INVALID_PSS_SALTLEN);
			return -2;
		}
		if (type == EVP_PKEY_CTRL_GET_RSA_PSS_SALTLEN)
			*(int *)p2 = rctx->saltlen;
		else {
			if (p1 < -2)
				return -2;
			rctx->saltlen = p1;
		}
		return 1;

	case EVP_PKEY_CTRL_RSA_KEYGEN_BITS:
		if (p1 < 256) {
			RSAerr(RSA_F_PKEY_RSA_CTRL, RSA_R_INVALID_KEYBITS);
			return -2;
		}
		rctx->nbits = p1;
		return 1;

	case EVP_PKEY_CTRL_RSA_KEYGEN_PUBEXP:
		if (!p2)
			return -2;
		rctx->pub_exp = p2;
		return 1;

	case EVP_PKEY_CTRL_MD:
		if (!check_padding_md(p2, rctx->pad_mode))
			return 0;
		rctx->md = p2;
		return 1;

	case EVP_PKEY_CTRL_RSA_MGF1_MD:
	case EVP_PKEY_CTRL_GET_RSA_MGF1_MD:
		if (rctx->pad_mode != RSA_PKCS1_PSS_PADDING) {
			RSAerr(RSA_F_PKEY_RSA_CTRL, RSA_R_INVALID_MGF1_MD);
			return -2;
		}
		if (type == EVP_PKEY_CTRL_GET_RSA_MGF1_MD) {
			if (rctx->mgf1md)
				*(const EVP_MD **)p2 = rctx->mgf1md;
			else
				*(const EVP_MD **)p2 = rctx->md;
		} else
			rctx->mgf1md = p2;
		return 1;

	case EVP_PKEY_CTRL_DIGESTINIT:
	case EVP_PKEY_CTRL_PKCS7_ENCRYPT:
	case EVP_PKEY_CTRL_PKCS7_DECRYPT:
	case EVP_PKEY_CTRL_PKCS7_SIGN:
		return 1;
#ifndef OPENSSL_NO_CMS
	case EVP_PKEY_CTRL_CMS_DECRYPT:
		{
			X509_ALGOR *alg = NULL;
			ASN1_OBJECT *encalg = NULL;

			if (p2)
				CMS_RecipientInfo_ktri_get0_algs(p2, NULL,
				    NULL, &alg);
			if (alg)
				X509_ALGOR_get0(&encalg, NULL, NULL, alg);
			if (encalg && OBJ_obj2nid(encalg) == NID_rsaesOaep)
				rctx->pad_mode = RSA_PKCS1_OAEP_PADDING;
		}
		/* FALLTHROUGH */

	case EVP_PKEY_CTRL_CMS_ENCRYPT:
	case EVP_PKEY_CTRL_CMS_SIGN:
		return 1;
#endif
	case EVP_PKEY_CTRL_PEER_KEY:
		RSAerr(RSA_F_PKEY_RSA_CTRL,
		    RSA_R_OPERATION_NOT_SUPPORTED_FOR_THIS_KEYTYPE);
		return -2;

	default:
		return -2;
	}
}
pkey_rsa_ctrl_str(EVP_PKEY_CTX *ctx, const char *type, const char *value)
{
	long lval;
	char *ep;

	if (!value) {
		RSAerr(RSA_F_PKEY_RSA_CTRL_STR, RSA_R_VALUE_MISSING);
		return 0;
	}
	if (!strcmp(type, "rsa_padding_mode")) {
		int pm;
		if (!strcmp(value, "pkcs1"))
			pm = RSA_PKCS1_PADDING;
		else if (!strcmp(value, "sslv23"))
			pm = RSA_SSLV23_PADDING;
		else if (!strcmp(value, "none"))
			pm = RSA_NO_PADDING;
		else if (!strcmp(value, "oeap"))
			pm = RSA_PKCS1_OAEP_PADDING;
		else if (!strcmp(value, "oaep"))
			pm = RSA_PKCS1_OAEP_PADDING;
		else if (!strcmp(value, "x931"))
			pm = RSA_X931_PADDING;
		else if (!strcmp(value, "pss"))
			pm = RSA_PKCS1_PSS_PADDING;
		else {
			RSAerr(RSA_F_PKEY_RSA_CTRL_STR,
			    RSA_R_UNKNOWN_PADDING_TYPE);
			return -2;
		}
		return EVP_PKEY_CTX_set_rsa_padding(ctx, pm);
	}

	if (!strcmp(type, "rsa_pss_saltlen")) {
		int saltlen;

		errno = 0;
		lval = strtol(value, &ep, 10);
		if (value[0] == '\0' || *ep != '\0')
			goto not_a_number;
		if ((errno == ERANGE &&
		    (lval == LONG_MAX || lval == LONG_MIN)) ||
		    (lval > INT_MAX || lval < INT_MIN))
			goto out_of_range;
		saltlen = lval;
		return EVP_PKEY_CTX_set_rsa_pss_saltlen(ctx, saltlen);
	}

	if (!strcmp(type, "rsa_keygen_bits")) {
		int nbits;

		errno = 0;
		lval = strtol(value, &ep, 10);
		if (value[0] == '\0' || *ep != '\0')
			goto not_a_number;
		if ((errno == ERANGE &&
		    (lval == LONG_MAX || lval == LONG_MIN)) ||
		    (lval > INT_MAX || lval < INT_MIN))
			goto out_of_range;
		nbits = lval;
		return EVP_PKEY_CTX_set_rsa_keygen_bits(ctx, nbits);
	}

	if (!strcmp(type, "rsa_keygen_pubexp")) {
		int ret;
		BIGNUM *pubexp = NULL;

		if (!BN_asc2bn(&pubexp, value))
			return 0;
		ret = EVP_PKEY_CTX_set_rsa_keygen_pubexp(ctx, pubexp);
		if (ret <= 0)
			BN_free(pubexp);
		return ret;
	}

not_a_number:
out_of_range:
	return -2;
}


static int
pkey_rsa_init(EVP_PKEY_CTX *ctx)
{
	RSA_PKEY_CTX *rctx;

	rctx = malloc(sizeof(RSA_PKEY_CTX));
	if (!rctx)
		return 0;
	rctx->nbits = 2048;
	rctx->pub_exp = NULL;
	rctx->pad_mode = RSA_PKCS1_PADDING;
	rctx->md = NULL;
	rctx->mgf1md = NULL;
	rctx->tbuf = NULL;

	rctx->saltlen = -2;

	ctx->data = rctx;
	ctx->keygen_info = rctx->gentmp;
	ctx->keygen_info_count = 2;

	return 1;
}


static int
pkey_rsa_sign(EVP_PKEY_CTX *ctx, unsigned char *sig, size_t *siglen,
    const unsigned char *tbs, size_t tbslen)
{
	int ret;
	RSA_PKEY_CTX *rctx = ctx->data;
	RSA *rsa = ctx->pkey->pkey.rsa;

	if (rctx->md) {
		if (tbslen != (size_t)EVP_MD_size(rctx->md)) {
			RSAerr(RSA_F_PKEY_RSA_SIGN,
			    RSA_R_INVALID_DIGEST_LENGTH);
			return -1;
		}

		if (rctx->pad_mode == RSA_X931_PADDING) {
			if (!setup_tbuf(rctx, ctx))
				return -1;
			memcpy(rctx->tbuf, tbs, tbslen);
			rctx->tbuf[tbslen] =
			    RSA_X931_hash_id(EVP_MD_type(rctx->md));
			ret = RSA_private_encrypt(tbslen + 1, rctx->tbuf, sig,
			    rsa, RSA_X931_PADDING);
		} else if (rctx->pad_mode == RSA_PKCS1_PADDING) {
			unsigned int sltmp;

			ret = RSA_sign(EVP_MD_type(rctx->md), tbs, tbslen, sig,
			    &sltmp, rsa);
			if (ret <= 0)
				return ret;
			ret = sltmp;
		} else if (rctx->pad_mode == RSA_PKCS1_PSS_PADDING) {
			if (!setup_tbuf(rctx, ctx))
				return -1;
			if (!RSA_padding_add_PKCS1_PSS_mgf1(rsa, rctx->tbuf,
			    tbs, rctx->md, rctx->mgf1md, rctx->saltlen))
				return -1;
			ret = RSA_private_encrypt(RSA_size(rsa), rctx->tbuf,
			    sig, rsa, RSA_NO_PADDING);
		} else
			return -1;
	} else
		ret = RSA_private_encrypt(tbslen, tbs, sig, ctx->pkey->pkey.rsa,
		    rctx->pad_mode);
	if (ret < 0)
		return ret;
	*siglen = ret;
	return 1;
}


static int
pkey_set_type(EVP_PKEY *pkey, int type, const char *str, int len)
{
	const EVP_PKEY_ASN1_METHOD *ameth;
	ENGINE *e = NULL;
	if (pkey) {
		if (pkey->pkey.ptr)
			EVP_PKEY_free_it(pkey);
		/* If key type matches and a method exists then this
		 * lookup has succeeded once so just indicate success.
		 */
		if ((type == pkey->save_type) && pkey->ameth)
			return 1;
#ifndef OPENSSL_NO_ENGINE
		/* If we have an ENGINE release it */
		if (pkey->engine) {
			ENGINE_finish(pkey->engine);
			pkey->engine = NULL;
		}
#endif
	}
	if (str)
		ameth = EVP_PKEY_asn1_find_str(&e, str, len);
	else
		ameth = EVP_PKEY_asn1_find(&e, type);
#ifndef OPENSSL_NO_ENGINE
	if (!pkey && e)
		ENGINE_finish(e);
#endif
	if (!ameth) {
		EVPerr(EVP_F_PKEY_SET_TYPE, EVP_R_UNSUPPORTED_ALGORITHM);
		return 0;
	}
	if (pkey) {
		pkey->ameth = ameth;
		pkey->engine = e;

		pkey->type = pkey->ameth->pkey_id;
		pkey->save_type = type;
	}
	return 1;
}


static int
pmeth_cmp(const EVP_PKEY_METHOD * const *a, const EVP_PKEY_METHOD * const *b)
{
	return ((*a)->pkey_id - (*b)->pkey_id);
}


void
print_hex(unsigned char* buf, int len)
{
  int cnt;
  for (cnt = 0; cnt < len; cnt++) {
    debug_printf("%02X", buf[cnt]);
  }

  debug_printf("\n\r");
  fflush(stdout);
}
print_hex_trim(unsigned char *buf, int len){
  int cnt;

  for (cnt = 0; cnt < 128; cnt++) {
    if(cnt < 64) debug_printf("%02X", buf[cnt]);
    else if(cnt == 64) debug_printf("...");
    else debug_printf("%02X", buf[len - 128 + cnt]);
  }
  debug_printf("\n\r");
}


void
print_hex_trim(unsigned char *buf, int len){
  int cnt;

  for (cnt = 0; cnt < 128; cnt++) {
    if(cnt < 64) debug_printf("%02X", buf[cnt]);
    else if(cnt == 64) debug_printf("...");
    else debug_printf("%02X", buf[len - 128 + cnt]);
  }
  debug_printf("\n\r");
}


static int
pubkey_cb(int operation, ASN1_VALUE **pval, const ASN1_ITEM *it, void *exarg)
{
	if (operation == ASN1_OP_FREE_POST) {
		X509_PUBKEY *pubkey = (X509_PUBKEY *)*pval;
		EVP_PKEY_free(pubkey->pkey);
	}
	return 1;
}


void *
reallocarray(void *optr, size_t nmemb, size_t size)
{
	if ((nmemb >= MUL_NO_OVERFLOW || size >= MUL_NO_OVERFLOW) &&
	    nmemb > 0 && SIZE_MAX / nmemb < size) {
		errno = ENOMEM;
		return NULL;
	}
	return realloc(optr, size * nmemb);
}


void
register_commands()
{
  register_command(CMD_CLNT_RAND, cmd_clnt_rand);
  register_command(CMD_SRV_RAND, cmd_srv_rand);
  register_command(CMD_PREMASTER, cmd_premaster);
  register_command(CMD_MASTER_SEC, cmd_master_sec);
  register_command(CMD_RSA_SIGN, cmd_rsa_sign);
  register_command(CMD_RSA_SIGN_SIG_ALG, cmd_rsa_sign_sig_alg);
  register_command(CMD_GET_ECDHE_PUBLIC_PARAM, cmd_ecdhe_get_public_param);
  register_command(CMD_GET_ECDHE_PRE_MASTER, cmd_ecdhe_generate_pre_master);
  register_command(CMD_SSL_HANDSHAKE_DONE, cmd_ssl_handshake_done);
  register_command(CMD_SSL_SESSION_REMOVE, cmd_ssl_session_remove);
  
  // #ifdef OPENSSL_WITH_SGX_KEYBLOCK
  register_command(CMD_KEY_BLOCK, cmd_key_block);
  register_command(CMD_FINAL_FINISH_MAC, cmd_final_finish_mac);
  register_command(CMD_CHANGE_CIPHER_STATE, cmd_change_cipher_state);
  register_command(CMD_SGX_TLS1_ENC, cmd_sgx_tls1_enc);
  // #endif

}
register_command(int cmd, void (*callback)(cmd_pkt_t, unsigned char*))
{
  // just add it to our static array.
  if (cmd < MAX_COMMANDS) {
    _commands[cmd].cmd_num = cmd;
    _commands[cmd].callback = callback;
  } else {
    // TODO: error, too many commands
    debug_printf("ERROR: command array full, increase MAX_COMMANDS\n");
  }
}


void
register_commands()
{
  register_command(CMD_CLNT_RAND, cmd_clnt_rand);
  register_command(CMD_SRV_RAND, cmd_srv_rand);
  register_command(CMD_PREMASTER, cmd_premaster);
  register_command(CMD_MASTER_SEC, cmd_master_sec);
  register_command(CMD_RSA_SIGN, cmd_rsa_sign);
  register_command(CMD_RSA_SIGN_SIG_ALG, cmd_rsa_sign_sig_alg);
  register_command(CMD_GET_ECDHE_PUBLIC_PARAM, cmd_ecdhe_get_public_param);
  register_command(CMD_GET_ECDHE_PRE_MASTER, cmd_ecdhe_generate_pre_master);
  register_command(CMD_SSL_HANDSHAKE_DONE, cmd_ssl_handshake_done);
  register_command(CMD_SSL_SESSION_REMOVE, cmd_ssl_session_remove);
  
  // #ifdef OPENSSL_WITH_SGX_KEYBLOCK
  register_command(CMD_KEY_BLOCK, cmd_key_block);
  register_command(CMD_FINAL_FINISH_MAC, cmd_final_finish_mac);
  register_command(CMD_CHANGE_CIPHER_STATE, cmd_change_cipher_state);
  register_command(CMD_SGX_TLS1_ENC, cmd_sgx_tls1_enc);
  // #endif

}


static int
rsa_blinding_convert(BN_BLINDING *b, BIGNUM *f, BIGNUM *unblind, BN_CTX *ctx)
{
	if (unblind == NULL)
		/*
		 * Local blinding: store the unblinding factor
		 * in BN_BLINDING.
		 */
		return BN_BLINDING_convert_ex(f, NULL, b, ctx);
	else {
		/*
		 * Shared blinding: store the unblinding factor
		 * outside BN_BLINDING.
		 */
		int ret;
		CRYPTO_w_lock(CRYPTO_LOCK_RSA_BLINDING);
		ret = BN_BLINDING_convert_ex(f, unblind, b, ctx);
		CRYPTO_w_unlock(CRYPTO_LOCK_RSA_BLINDING);
		return ret;
	}
}


static int
rsa_blinding_invert(BN_BLINDING *b, BIGNUM *f, BIGNUM *unblind, BN_CTX *ctx)
{
	/*
	 * For local blinding, unblind is set to NULL, and BN_BLINDING_invert_ex
	 * will use the unblinding factor stored in BN_BLINDING.
	 * If BN_BLINDING is shared between threads, unblind must be non-null:
	 * BN_BLINDING_invert_ex will then use the local unblinding factor,
	 * and will only read the modulus from BN_BLINDING.
	 * In both cases it's safe to access the blinding without a lock.
	 */
	return BN_BLINDING_invert_ex(f, unblind, b, ctx);
}


static int
rsa_cb(int operation, ASN1_VALUE **pval, const ASN1_ITEM *it, void *exarg)
{
	if (operation == ASN1_OP_NEW_PRE) {
		*pval = (ASN1_VALUE *)RSA_new();
		if (*pval)
			return 2;
		return 0;
	} else if (operation == ASN1_OP_FREE_PRE) {
		RSA_free((RSA *)*pval);
		*pval = NULL;
		return 2;
	}
	return 1;
}


static int
RSA_eay_init(RSA *rsa)
{
	rsa->flags |= RSA_FLAG_CACHE_PUBLIC | RSA_FLAG_CACHE_PRIVATE;
	return 1;
}


static int
RSA_eay_mod_exp(BIGNUM *r0, const BIGNUM *I, RSA *rsa, BN_CTX *ctx)
{
	BIGNUM *r1, *m1, *vrfy;
	BIGNUM local_dmp1, local_dmq1, local_c, local_r1;
	BIGNUM *dmp1, *dmq1, *c, *pr1;
	int ret = 0;

	BN_CTX_start(ctx);
	r1 = BN_CTX_get(ctx);
	m1 = BN_CTX_get(ctx);
	vrfy = BN_CTX_get(ctx);
	if (r1 == NULL || m1 == NULL || vrfy == NULL) {
		RSAerr(RSA_F_RSA_EAY_MOD_EXP, ERR_R_MALLOC_FAILURE);
		goto err;
	}

	{
		BIGNUM local_p, local_q;
		BIGNUM *p = NULL, *q = NULL;

		/*
		 * Make sure BN_mod_inverse in Montgomery intialization uses the
		 * BN_FLG_CONSTTIME flag (unless RSA_FLAG_NO_CONSTTIME is set)
		 */
		if (!(rsa->flags & RSA_FLAG_NO_CONSTTIME)) {
			BN_init(&local_p);
			p = &local_p;
			BN_with_flags(p, rsa->p, BN_FLG_CONSTTIME);

			BN_init(&local_q);
			q = &local_q;
			BN_with_flags(q, rsa->q, BN_FLG_CONSTTIME);
		} else {
			p = rsa->p;
			q = rsa->q;
		}

		if (rsa->flags & RSA_FLAG_CACHE_PRIVATE) {
			if (!BN_MONT_CTX_set_locked(&rsa->_method_mod_p,
			    CRYPTO_LOCK_RSA, p, ctx))
				goto err;
			if (!BN_MONT_CTX_set_locked(&rsa->_method_mod_q,
			    CRYPTO_LOCK_RSA, q, ctx))
				goto err;
		}
	}

	if (rsa->flags & RSA_FLAG_CACHE_PUBLIC)
		if (!BN_MONT_CTX_set_locked(&rsa->_method_mod_n,
		    CRYPTO_LOCK_RSA, rsa->n, ctx))
			goto err;

	/* compute I mod q */
	if (!(rsa->flags & RSA_FLAG_NO_CONSTTIME)) {
		c = &local_c;
		BN_with_flags(c, I, BN_FLG_CONSTTIME);
		if (!BN_mod(r1, c, rsa->q, ctx))
			goto err;
	} else {
		if (!BN_mod(r1, I, rsa->q, ctx))
			goto err;
	}

	/* compute r1^dmq1 mod q */
	if (!(rsa->flags & RSA_FLAG_NO_CONSTTIME)) {
		dmq1 = &local_dmq1;
		BN_with_flags(dmq1, rsa->dmq1, BN_FLG_CONSTTIME);
	} else
		dmq1 = rsa->dmq1;
	if (!rsa->meth->bn_mod_exp(m1, r1, dmq1, rsa->q, ctx,
	    rsa->_method_mod_q))
		goto err;

	/* compute I mod p */
	if (!(rsa->flags & RSA_FLAG_NO_CONSTTIME)) {
		c = &local_c;
		BN_with_flags(c, I, BN_FLG_CONSTTIME);
		if (!BN_mod(r1, c, rsa->p, ctx))
			goto err;
	} else {
		if (!BN_mod(r1, I, rsa->p, ctx))
			goto err;
	}

	/* compute r1^dmp1 mod p */
	if (!(rsa->flags & RSA_FLAG_NO_CONSTTIME)) {
		dmp1 = &local_dmp1;
		BN_with_flags(dmp1, rsa->dmp1, BN_FLG_CONSTTIME);
	} else
		dmp1 = rsa->dmp1;
	if (!rsa->meth->bn_mod_exp(r0, r1, dmp1, rsa->p, ctx,
	    rsa->_method_mod_p))
		goto err;

	if (!BN_sub(r0, r0, m1))
		goto err;
	/*
	 * This will help stop the size of r0 increasing, which does
	 * affect the multiply if it optimised for a power of 2 size
	 */
	if (BN_is_negative(r0))
		if (!BN_add(r0, r0, rsa->p))
			goto err;

	if (!BN_mul(r1, r0, rsa->iqmp, ctx))
		goto err;

	/* Turn BN_FLG_CONSTTIME flag on before division operation */
	if (!(rsa->flags & RSA_FLAG_NO_CONSTTIME)) {
		pr1 = &local_r1;
		BN_with_flags(pr1, r1, BN_FLG_CONSTTIME);
	} else
		pr1 = r1;
	if (!BN_mod(r0, pr1, rsa->p, ctx))
		goto err;

	/*
	 * If p < q it is occasionally possible for the correction of
	 * adding 'p' if r0 is negative above to leave the result still
	 * negative. This can break the private key operations: the following
	 * second correction should *always* correct this rare occurrence.
	 * This will *never* happen with OpenSSL generated keys because
	 * they ensure p > q [steve]
	 */
	if (BN_is_negative(r0))
		if (!BN_add(r0, r0, rsa->p))
			goto err;
	if (!BN_mul(r1, r0, rsa->q, ctx))
		goto err;
	if (!BN_add(r0, r1, m1))
		goto err;

	if (rsa->e && rsa->n) {
		if (!rsa->meth->bn_mod_exp(vrfy, r0, rsa->e, rsa->n, ctx,
		    rsa->_method_mod_n))
			goto err;
		/*
		 * If 'I' was greater than (or equal to) rsa->n, the operation
		 * will be equivalent to using 'I mod n'. However, the result of
		 * the verify will *always* be less than 'n' so we don't check
		 * for absolute equality, just congruency.
		 */
		if (!BN_sub(vrfy, vrfy, I))
			goto err;
		if (!BN_mod(vrfy, vrfy, rsa->n, ctx))
			goto err;
		if (BN_is_negative(vrfy))
			if (!BN_add(vrfy, vrfy, rsa->n))
				goto err;
		if (!BN_is_zero(vrfy)) {
			/*
			 * 'I' and 'vrfy' aren't congruent mod n. Don't leak
			 * miscalculated CRT output, just do a raw (slower)
			 * mod_exp and return that instead.
			 */

			BIGNUM local_d;
			BIGNUM *d = NULL;

			if (!(rsa->flags & RSA_FLAG_NO_CONSTTIME)) {
				d = &local_d;
				BN_with_flags(d, rsa->d, BN_FLG_CONSTTIME);
			} else
				d = rsa->d;
			if (!rsa->meth->bn_mod_exp(r0, I, d, rsa->n, ctx,
			    rsa->_method_mod_n))
				goto err;
		}
	}
	ret = 1;
err:
	BN_CTX_end(ctx);
	return ret;
}


static int
RSA_eay_private_decrypt(int flen, const unsigned char *from, unsigned char *to,
    RSA *rsa, int padding)
{
	BIGNUM *f, *ret;
	int j, num = 0, r = -1;
	unsigned char *p;
	unsigned char *buf = NULL;
	BN_CTX *ctx = NULL;
	int local_blinding = 0;
	/*
	 * Used only if the blinding structure is shared. A non-NULL unblind
	 * instructs rsa_blinding_convert() and rsa_blinding_invert() to store
	 * the unblinding factor outside the blinding structure.
	 */
	BIGNUM *unblind = NULL;
	BN_BLINDING *blinding = NULL;

	if ((ctx = BN_CTX_new()) == NULL)
		goto err;
	BN_CTX_start(ctx);
	f = BN_CTX_get(ctx);
	ret = BN_CTX_get(ctx);
	num = BN_num_bytes(rsa->n);
	buf = malloc(num);
	if (!f || !ret || !buf) {
		RSAerr(RSA_F_RSA_EAY_PRIVATE_DECRYPT, ERR_R_MALLOC_FAILURE);
		goto err;
	}

	/* This check was for equality but PGP does evil things
	 * and chops off the top '0' bytes */
	if (flen > num) {
		RSAerr(RSA_F_RSA_EAY_PRIVATE_DECRYPT,
		    RSA_R_DATA_GREATER_THAN_MOD_LEN);
		goto err;
	}

	/* make data into a big number */
	if (BN_bin2bn(from, (int)flen, f) == NULL)
		goto err;

	if (BN_ucmp(f, rsa->n) >= 0) {
		RSAerr(RSA_F_RSA_EAY_PRIVATE_DECRYPT,
		    RSA_R_DATA_TOO_LARGE_FOR_MODULUS);
		goto err;
	}

	if (!(rsa->flags & RSA_FLAG_NO_BLINDING)) {
		blinding = rsa_get_blinding(rsa, &local_blinding, ctx);
		if (blinding == NULL) {
			RSAerr(RSA_F_RSA_EAY_PRIVATE_DECRYPT,
			    ERR_R_INTERNAL_ERROR);
			goto err;
		}
	}

	if (blinding != NULL) {
		if (!local_blinding && ((unblind = BN_CTX_get(ctx)) == NULL)) {
			RSAerr(RSA_F_RSA_EAY_PRIVATE_DECRYPT,
			    ERR_R_MALLOC_FAILURE);
			goto err;
		}
		if (!rsa_blinding_convert(blinding, f, unblind, ctx))
			goto err;
	}

	/* do the decrypt */
	if ((rsa->flags & RSA_FLAG_EXT_PKEY) ||
	    (rsa->p != NULL && rsa->q != NULL && rsa->dmp1 != NULL &&
	    rsa->dmq1 != NULL && rsa->iqmp != NULL)) {
		if (!rsa->meth->rsa_mod_exp(ret, f, rsa, ctx))
			goto err;
	} else {
		BIGNUM local_d;
		BIGNUM *d = NULL;

		if (!(rsa->flags & RSA_FLAG_NO_CONSTTIME)) {
			d = &local_d;
			BN_with_flags(d, rsa->d, BN_FLG_CONSTTIME);
		} else
			d = rsa->d;

		if (rsa->flags & RSA_FLAG_CACHE_PUBLIC)
			if (!BN_MONT_CTX_set_locked(&rsa->_method_mod_n,
			    CRYPTO_LOCK_RSA, rsa->n, ctx))
				goto err;
		if (!rsa->meth->bn_mod_exp(ret, f, d, rsa->n, ctx,
		    rsa->_method_mod_n))
			goto err;
	}

	if (blinding)
		if (!rsa_blinding_invert(blinding, ret, unblind, ctx))
			goto err;

	p = buf;
	j = BN_bn2bin(ret, p); /* j is only used with no-padding mode */

	switch (padding) {
	case RSA_PKCS1_PADDING:
		r = RSA_padding_check_PKCS1_type_2(to, num, buf, j, num);
		break;
#ifndef OPENSSL_NO_SHA
	case RSA_PKCS1_OAEP_PADDING:
		r = RSA_padding_check_PKCS1_OAEP(to, num, buf, j, num, NULL, 0);
		break;
#endif
	case RSA_SSLV23_PADDING:
		r = RSA_padding_check_SSLv23(to, num, buf, j, num);
		break;
	case RSA_NO_PADDING:
		r = RSA_padding_check_none(to, num, buf, j, num);
		break;
	default:
		RSAerr(RSA_F_RSA_EAY_PRIVATE_DECRYPT,
		    RSA_R_UNKNOWN_PADDING_TYPE);
		goto err;
	}
	if (r < 0)
		RSAerr(RSA_F_RSA_EAY_PRIVATE_DECRYPT,
		    RSA_R_PADDING_CHECK_FAILED);

err:
	if (ctx != NULL) {
		BN_CTX_end(ctx);
		BN_CTX_free(ctx);
	}
	if (buf != NULL) {
		explicit_bzero(buf, num);
		free(buf);
	}
	return r;
}


static int
RSA_eay_private_encrypt(int flen, const unsigned char *from, unsigned char *to,
    RSA *rsa, int padding)
{
	BIGNUM *f, *ret, *res;
	int i, j, k, num = 0, r = -1;
	unsigned char *buf = NULL;
	BN_CTX *ctx = NULL;
	int local_blinding = 0;
	/*
	 * Used only if the blinding structure is shared. A non-NULL unblind
	 * instructs rsa_blinding_convert() and rsa_blinding_invert() to store
	 * the unblinding factor outside the blinding structure.
	 */
	BIGNUM *unblind = NULL;
	BN_BLINDING *blinding = NULL;

	if ((ctx = BN_CTX_new()) == NULL)
		goto err;
	BN_CTX_start(ctx);
	f = BN_CTX_get(ctx);
	ret = BN_CTX_get(ctx);
	num = BN_num_bytes(rsa->n);
	buf = malloc(num);
	if (f == NULL || ret == NULL || buf == NULL) {
		RSAerr(RSA_F_RSA_EAY_PRIVATE_ENCRYPT, ERR_R_MALLOC_FAILURE);
		goto err;
	}

	switch (padding) {
	case RSA_PKCS1_PADDING:
		i = RSA_padding_add_PKCS1_type_1(buf, num, from, flen);
		break;
	case RSA_X931_PADDING:
		i = RSA_padding_add_X931(buf, num, from, flen);
		break;
	case RSA_NO_PADDING:
		i = RSA_padding_add_none(buf, num, from, flen);
		break;
	case RSA_SSLV23_PADDING:
	default:
		RSAerr(RSA_F_RSA_EAY_PRIVATE_ENCRYPT,
		    RSA_R_UNKNOWN_PADDING_TYPE);
		goto err;
	}
	if (i <= 0)
		goto err;

	if (BN_bin2bn(buf, num, f) == NULL)
		goto err;

	if (BN_ucmp(f, rsa->n) >= 0) {
		/* usually the padding functions would catch this */
		RSAerr(RSA_F_RSA_EAY_PRIVATE_ENCRYPT,
		    RSA_R_DATA_TOO_LARGE_FOR_MODULUS);
		goto err;
	}

	if (!(rsa->flags & RSA_FLAG_NO_BLINDING)) {
		blinding = rsa_get_blinding(rsa, &local_blinding, ctx);
		if (blinding == NULL) {
			RSAerr(RSA_F_RSA_EAY_PRIVATE_ENCRYPT,
			    ERR_R_INTERNAL_ERROR);
			goto err;
		}
	}

	if (blinding != NULL) {
		if (!local_blinding && ((unblind = BN_CTX_get(ctx)) == NULL)) {
			RSAerr(RSA_F_RSA_EAY_PRIVATE_ENCRYPT,
			    ERR_R_MALLOC_FAILURE);
			goto err;
		}
		if (!rsa_blinding_convert(blinding, f, unblind, ctx))
			goto err;
	}

	if ((rsa->flags & RSA_FLAG_EXT_PKEY) ||
	    (rsa->p != NULL && rsa->q != NULL && rsa->dmp1 != NULL &&
	    rsa->dmq1 != NULL && rsa->iqmp != NULL)) {
		if (!rsa->meth->rsa_mod_exp(ret, f, rsa, ctx))
			goto err;
	} else {
		BIGNUM local_d;
		BIGNUM *d = NULL;

		if (!(rsa->flags & RSA_FLAG_NO_CONSTTIME)) {
			BN_init(&local_d);
			d = &local_d;
			BN_with_flags(d, rsa->d, BN_FLG_CONSTTIME);
		} else
			d = rsa->d;

		if (rsa->flags & RSA_FLAG_CACHE_PUBLIC)
			if (!BN_MONT_CTX_set_locked(&rsa->_method_mod_n,
			    CRYPTO_LOCK_RSA, rsa->n, ctx))
				goto err;

		if (!rsa->meth->bn_mod_exp(ret, f, d, rsa->n, ctx,
		    rsa->_method_mod_n))
			goto err;
	}

	if (blinding)
		if (!rsa_blinding_invert(blinding, ret, unblind, ctx))
			goto err;

	if (padding == RSA_X931_PADDING) {
		BN_sub(f, rsa->n, ret);
		if (BN_cmp(ret, f) > 0)
			res = f;
		else
			res = ret;
	} else
		res = ret;

	/* put in leading 0 bytes if the number is less than the
	 * length of the modulus */
	j = BN_num_bytes(res);
	i = BN_bn2bin(res, &(to[num - j]));
	for (k = 0; k < num - i; k++)
		to[k] = 0;

	r = num;
err:
	if (ctx != NULL) {
		BN_CTX_end(ctx);
		BN_CTX_free(ctx);
	}
	if (buf != NULL) {
		explicit_bzero(buf, num);
		free(buf);
	}
	return r;
}


int
RSA_flags(const RSA *r)
{
	return r == NULL ? 0 : r->meth->flags;
}


static BN_BLINDING *
rsa_get_blinding(RSA *rsa, int *local, BN_CTX *ctx)
{
	BN_BLINDING *ret;
	int got_write_lock = 0;
	CRYPTO_THREADID cur;

	CRYPTO_r_lock(CRYPTO_LOCK_RSA);

	if (rsa->blinding == NULL) {
		CRYPTO_r_unlock(CRYPTO_LOCK_RSA);
		CRYPTO_w_lock(CRYPTO_LOCK_RSA);
		got_write_lock = 1;

		if (rsa->blinding == NULL)
			rsa->blinding = RSA_setup_blinding(rsa, ctx);
	}

	ret = rsa->blinding;
	if (ret == NULL)
		goto err;

	CRYPTO_THREADID_current(&cur);
	if (!CRYPTO_THREADID_cmp(&cur, BN_BLINDING_thread_id(ret))) {
		/* rsa->blinding is ours! */
		*local = 1;
	} else {
		/* resort to rsa->mt_blinding instead */
		/*
		 * Instruct rsa_blinding_convert(), rsa_blinding_invert()
		 * that the BN_BLINDING is shared, meaning that accesses
		 * require locks, and that the blinding factor must be
		 * stored outside the BN_BLINDING
		 */
		*local = 0;

		if (rsa->mt_blinding == NULL) {
			if (!got_write_lock) {
				CRYPTO_r_unlock(CRYPTO_LOCK_RSA);
				CRYPTO_w_lock(CRYPTO_LOCK_RSA);
				got_write_lock = 1;
			}

			if (rsa->mt_blinding == NULL)
				rsa->mt_blinding = RSA_setup_blinding(rsa, ctx);
		}
		ret = rsa->mt_blinding;
	}

err:
	if (got_write_lock)
		CRYPTO_w_unlock(CRYPTO_LOCK_RSA);
	else
		CRYPTO_r_unlock(CRYPTO_LOCK_RSA);
	return ret;
}


const RSA_METHOD *
RSA_get_default_method(void)
{
	if (default_RSA_meth == NULL)
		default_RSA_meth = RSA_PKCS1_SSLeay();

	return default_RSA_meth;
}


RSA *
RSA_new(void)
{
	RSA *r = RSA_new_method(NULL);

	return r;
}
RSA_new_method(ENGINE *engine)
{
	RSA *ret;

	ret = malloc(sizeof(RSA));
	if (ret == NULL) {
		RSAerr(RSA_F_RSA_NEW_METHOD, ERR_R_MALLOC_FAILURE);
		return NULL;
	}

	ret->meth = RSA_get_default_method();
#ifndef OPENSSL_NO_ENGINE
	if (engine) {
		if (!ENGINE_init(engine)) {
			RSAerr(RSA_F_RSA_NEW_METHOD, ERR_R_ENGINE_LIB);
			free(ret);
			return NULL;
		}
		ret->engine = engine;
	} else
		ret->engine = ENGINE_get_default_RSA();
	if (ret->engine) {
		ret->meth = ENGINE_get_RSA(ret->engine);
		if (!ret->meth) {
			RSAerr(RSA_F_RSA_NEW_METHOD, ERR_R_ENGINE_LIB);
			ENGINE_finish(ret->engine);
			free(ret);
			return NULL;
		}
	}
#endif

	ret->pad = 0;
	ret->version = 0;
	ret->n = NULL;
	ret->e = NULL;
	ret->d = NULL;
	ret->p = NULL;
	ret->q = NULL;
	ret->dmp1 = NULL;
	ret->dmq1 = NULL;
	ret->iqmp = NULL;
	ret->references = 1;
	ret->_method_mod_n = NULL;
	ret->_method_mod_p = NULL;
	ret->_method_mod_q = NULL;
	ret->blinding = NULL;
	ret->mt_blinding = NULL;
	ret->flags = ret->meth->flags & ~RSA_FLAG_NON_FIPS_ALLOW;
	if (!CRYPTO_new_ex_data(CRYPTO_EX_INDEX_RSA, ret, &ret->ex_data)) {
#ifndef OPENSSL_NO_ENGINE
		if (ret->engine)
			ENGINE_finish(ret->engine);
#endif
		free(ret);
		return NULL;
	}

	if (ret->meth->init != NULL && !ret->meth->init(ret)) {
#ifndef OPENSSL_NO_ENGINE
		if (ret->engine)
			ENGINE_finish(ret->engine);
#endif
		CRYPTO_free_ex_data(CRYPTO_EX_INDEX_RSA, ret, &ret->ex_data);
		free(ret);
		ret = NULL;
	}
	return ret;
}


RSA *
RSA_new_method(ENGINE *engine)
{
	RSA *ret;

	ret = malloc(sizeof(RSA));
	if (ret == NULL) {
		RSAerr(RSA_F_RSA_NEW_METHOD, ERR_R_MALLOC_FAILURE);
		return NULL;
	}

	ret->meth = RSA_get_default_method();
#ifndef OPENSSL_NO_ENGINE
	if (engine) {
		if (!ENGINE_init(engine)) {
			RSAerr(RSA_F_RSA_NEW_METHOD, ERR_R_ENGINE_LIB);
			free(ret);
			return NULL;
		}
		ret->engine = engine;
	} else
		ret->engine = ENGINE_get_default_RSA();
	if (ret->engine) {
		ret->meth = ENGINE_get_RSA(ret->engine);
		if (!ret->meth) {
			RSAerr(RSA_F_RSA_NEW_METHOD, ERR_R_ENGINE_LIB);
			ENGINE_finish(ret->engine);
			free(ret);
			return NULL;
		}
	}
#endif

	ret->pad = 0;
	ret->version = 0;
	ret->n = NULL;
	ret->e = NULL;
	ret->d = NULL;
	ret->p = NULL;
	ret->q = NULL;
	ret->dmp1 = NULL;
	ret->dmq1 = NULL;
	ret->iqmp = NULL;
	ret->references = 1;
	ret->_method_mod_n = NULL;
	ret->_method_mod_p = NULL;
	ret->_method_mod_q = NULL;
	ret->blinding = NULL;
	ret->mt_blinding = NULL;
	ret->flags = ret->meth->flags & ~RSA_FLAG_NON_FIPS_ALLOW;
	if (!CRYPTO_new_ex_data(CRYPTO_EX_INDEX_RSA, ret, &ret->ex_data)) {
#ifndef OPENSSL_NO_ENGINE
		if (ret->engine)
			ENGINE_finish(ret->engine);
#endif
		free(ret);
		return NULL;
	}

	if (ret->meth->init != NULL && !ret->meth->init(ret)) {
#ifndef OPENSSL_NO_ENGINE
		if (ret->engine)
			ENGINE_finish(ret->engine);
#endif
		CRYPTO_free_ex_data(CRYPTO_EX_INDEX_RSA, ret, &ret->ex_data);
		free(ret);
		ret = NULL;
	}
	return ret;
}


int
RSA_padding_add_PKCS1_type_1(unsigned char *to, int tlen,
    const unsigned char *from, int flen)
{
	int j;
	unsigned char *p;

	if (flen > (tlen - RSA_PKCS1_PADDING_SIZE)) {
		RSAerr(RSA_F_RSA_PADDING_ADD_PKCS1_TYPE_1,
		    RSA_R_DATA_TOO_LARGE_FOR_KEY_SIZE);
		return 0;
	}

	p = (unsigned char *)to;

	*(p++) = 0;
	*(p++) = 1; /* Private Key BT (Block Type) */

	/* pad out with 0xff data */
	j = tlen - 3 - flen;
	memset(p, 0xff, j);
	p += j;
	*(p++) = '\0';
	memcpy(p, from, flen);

	return 1;
}


int
RSA_padding_check_PKCS1_type_2(unsigned char *to, int tlen,
    const unsigned char *from, int flen, int num)
{
	int i, j;
	const unsigned char *p;

	p = from;
	if (num != flen + 1 || *(p++) != 02) {
		RSAerr(RSA_F_RSA_PADDING_CHECK_PKCS1_TYPE_2,
		    RSA_R_BLOCK_TYPE_IS_NOT_02);
		return -1;
	}

	/* scan over padding data */
	j = flen - 1; /* one for type. */
	for (i = 0; i < j; i++)
		if (*(p++) == 0)
			break;

	if (i == j) {
		RSAerr(RSA_F_RSA_PADDING_CHECK_PKCS1_TYPE_2,
		    RSA_R_NULL_BEFORE_BLOCK_MISSING);
		return -1;
	}

	if (i < 8) {
		RSAerr(RSA_F_RSA_PADDING_CHECK_PKCS1_TYPE_2,
		    RSA_R_BAD_PAD_BYTE_COUNT);
		return -1;
	}
	i++; /* Skip over the '\0' */
	j -= i;
	if (j > tlen) {
		RSAerr(RSA_F_RSA_PADDING_CHECK_PKCS1_TYPE_2,
		    RSA_R_DATA_TOO_LARGE);
		return -1;
	}
	memcpy(to, p, j);

	return j;
}


const RSA_METHOD *
RSA_PKCS1_SSLeay(void)
{
	return &rsa_pkcs1_eay_meth;
}


int
RSA_private_decrypt(int flen, const unsigned char *from, unsigned char *to,
    RSA *rsa, int padding)
{
	return rsa->meth->rsa_priv_dec(flen, from, to, rsa, padding);
}


int
RSA_private_encrypt(int flen, const unsigned char *from, unsigned char *to,
    RSA *rsa, int padding)
{
	return rsa->meth->rsa_priv_enc(flen, from, to, rsa, padding);
}


static int
rsa_priv_decode(EVP_PKEY *pkey, PKCS8_PRIV_KEY_INFO *p8)
{
	const unsigned char *p;
	int pklen;

	if (!PKCS8_pkey_get0(NULL, &p, &pklen, NULL, p8))
		return 0;
	return old_rsa_priv_decode(pkey, &p, pklen);
}


static int
rsa_pub_cmp(const EVP_PKEY *a, const EVP_PKEY *b)
{
	if (BN_cmp(b->pkey.rsa->n, a->pkey.rsa->n) != 0 ||
	    BN_cmp(b->pkey.rsa->e, a->pkey.rsa->e) != 0)
		return 0;
	return 1;
}


static int
rsa_pub_decode(EVP_PKEY *pkey, X509_PUBKEY *pubkey)
{
	const unsigned char *p;
	int pklen;
	RSA *rsa = NULL;

	if (!X509_PUBKEY_get0_param(NULL, &p, &pklen, NULL, pubkey))
		return 0;
	if (!(rsa = d2i_RSAPublicKey(NULL, &p, pklen))) {
		RSAerr(RSA_F_RSA_PUB_DECODE, ERR_R_RSA_LIB);
		return 0;
	}
	EVP_PKEY_assign_RSA (pkey, rsa);
	return 1;
}


BN_BLINDING *
RSA_setup_blinding(RSA *rsa, BN_CTX *in_ctx)
{
	BIGNUM local_n;
	BIGNUM *e, *n;
	BN_CTX *ctx;
	BN_BLINDING *ret = NULL;

	if (in_ctx == NULL) {
		if ((ctx = BN_CTX_new()) == NULL)
			return 0;
	} else
		ctx = in_ctx;

	BN_CTX_start(ctx);

	if (rsa->e == NULL) {
		e = rsa_get_public_exp(rsa->d, rsa->p, rsa->q, ctx);
		if (e == NULL) {
			RSAerr(RSA_F_RSA_SETUP_BLINDING,
			    RSA_R_NO_PUBLIC_EXPONENT);
			goto err;
		}
	} else
		e = rsa->e;

	if (!(rsa->flags & RSA_FLAG_NO_CONSTTIME)) {
		/* Set BN_FLG_CONSTTIME flag */
		n = &local_n;
		BN_with_flags(n, rsa->n, BN_FLG_CONSTTIME);
	} else
		n = rsa->n;

	ret = BN_BLINDING_create_param(NULL, e, n, ctx, rsa->meth->bn_mod_exp,
	    rsa->_method_mod_n);
	if (ret == NULL) {
		RSAerr(RSA_F_RSA_SETUP_BLINDING, ERR_R_BN_LIB);
		goto err;
	}
	CRYPTO_THREADID_current(BN_BLINDING_thread_id(ret));
err:
	BN_CTX_end(ctx);
	if (in_ctx == NULL)
		BN_CTX_free(ctx);
	if (rsa->e == NULL)
		BN_free(e);

	return ret;
}


int
RSA_sign(int type, const unsigned char *m, unsigned int m_len,
    unsigned char *sigret, unsigned int *siglen, RSA *rsa)
{
	X509_SIG sig;
	ASN1_TYPE parameter;
	int i, j, ret = 1;
	unsigned char *p, *tmps = NULL;
	const unsigned char *s = NULL;
	X509_ALGOR algor;
	ASN1_OCTET_STRING digest;

	if ((rsa->flags & RSA_FLAG_SIGN_VER) && rsa->meth->rsa_sign)
		return rsa->meth->rsa_sign(type, m, m_len, sigret, siglen, rsa);

	/* Special case: SSL signature, just check the length */
	if (type == NID_md5_sha1) {
		if (m_len != SSL_SIG_LENGTH) {
			RSAerr(RSA_F_RSA_SIGN, RSA_R_INVALID_MESSAGE_LENGTH);
			return 0;
		}
		i = SSL_SIG_LENGTH;
		s = m;
	} else {
		sig.algor = &algor;
		sig.algor->algorithm = OBJ_nid2obj(type);
		if (sig.algor->algorithm == NULL) {
			RSAerr(RSA_F_RSA_SIGN, RSA_R_UNKNOWN_ALGORITHM_TYPE);
			return 0;
		}
		if (sig.algor->algorithm->length == 0) {
			RSAerr(RSA_F_RSA_SIGN,
			    RSA_R_THE_ASN1_OBJECT_IDENTIFIER_IS_NOT_KNOWN_FOR_THIS_MD);
			return 0;
		}
		parameter.type = V_ASN1_NULL;
		parameter.value.ptr = NULL;
		sig.algor->parameter = &parameter;

		sig.digest = &digest;
		sig.digest->data = (unsigned char *)m; /* TMP UGLY CAST */
		sig.digest->length = m_len;

		i = i2d_X509_SIG(&sig, NULL);
	}
	j = RSA_size(rsa);
	if (i > j - RSA_PKCS1_PADDING_SIZE) {
		RSAerr(RSA_F_RSA_SIGN, RSA_R_DIGEST_TOO_BIG_FOR_RSA_KEY);
		return 0;
	}
	if (type != NID_md5_sha1) {
		tmps = malloc(j + 1);
		if (tmps == NULL) {
			RSAerr(RSA_F_RSA_SIGN, ERR_R_MALLOC_FAILURE);
			return 0;
		}
		p = tmps;
		i2d_X509_SIG(&sig, &p);
		s = tmps;
	}
	i = RSA_private_encrypt(i, s, sigret, rsa, RSA_PKCS1_PADDING);
	if (i <= 0)
		ret = 0;
	else
		*siglen = i;

	if (type != NID_md5_sha1) {
		explicit_bzero(tmps, (unsigned int)j + 1);
		free(tmps);
	}
	return (ret);
}


int
RSA_size(const RSA *r)
{
	return BN_num_bytes(r->n);
}


void
run_command_loop()
{
  cmd_pkt_t cmd_pkt;
  unsigned char data[CMD_MAX_BUF_SIZE];

  // read in operation
  if (sgxbridge_fetch_operation(&cmd_pkt)) {
    if(sgxbridge_fetch_data(data, cmd_pkt.data_len)){
      check_commands(cmd_pkt, data);
    } else {
      debug_fprintf(stderr, "SGX error while fetching data. Exiting...\n");
      sgx_exit(NULL);
    }
  } else {
    // we shouldnt really end up here in normal conditions
    // sgxbridge_fetch_operation does a blocking read on named pipes
    debug_fprintf(stderr, "SGX error while fetching operation.\n");
    sgx_exit(NULL);
  }
}


int
sgxbridge_fetch_data(unsigned char *data, size_t len)
{
  if (sgxbridge_pipe_read(len, data) > 0) {
    debug_printf("SGX fetch data (%zu bytes)\n", len);
    print_hex_trim(data, len);
    return 1;
  }
  return 0;
}


int
sgxbridge_fetch_operation(cmd_pkt_t *cmd_pkt)
{
  int fd = fd_sgx_ssl;
#ifdef SGX_ENCLAVE
  fd = fd_ssl_sgx;
#endif

  if (sgxbridge_pipe_read(sizeof(cmd_pkt_t), cmd_pkt) > 0) {
    debug_printf("fetch_operation, cmd: %d, len: %d\n",
        cmd_pkt->cmd, cmd_pkt->data_len);
    return 1;
  }
  return 0;
}


int
sgxbridge_init()
{
  // default for ssl library
  int mode_sgx_ssl = RB_MODE_RD;
  int mode_ssl_sgx = RB_MODE_WR;

#ifdef SGX_ENCLAVE
  mode_sgx_ssl = RB_MODE_WR;
  mode_ssl_sgx = RB_MODE_RD;
#endif

  if (opensgx_pipe_init(0) < 0) {
    debug_fprintf(stderr, "%s - %s Pipe Init() failed \n", __FILE__, __func__);
    return -1;
  }

  if ((fd_sgx_ssl = opensgx_pipe_open("sgx_ssl", mode_sgx_ssl, 0)) < 0) {
    debug_fprintf(stderr, "%s - %s Read Pipe Open() failed \n", __FILE__, __func__);
    return -1;
  }

  if ((fd_ssl_sgx = opensgx_pipe_open("ssl_sgx", mode_ssl_sgx, 0)) < 0) {
    debug_fprintf(stderr, "%s - %s Write Pipe Open() failed \n", __FILE__, __func__);
    return -1;
  }

  return 0;
}


ssize_t
sgxbridge_pipe_read(size_t len, unsigned char* data)
{
  size_t num = 0, n;
  int fd = fd_sgx_ssl;

#ifdef SGX_ENCLAVE
  fd = fd_ssl_sgx;
#endif

  while(num < len){
    if((n = read(fd, data + num, len - num)) <= 0){
      debug_fprintf(stderr, "SGX read() failed: %s\n", strerror(errno));

      return 0;
    } else {
      num += n;
      debug_fprintf(stdout, "SGX read() %zu out of %zu bytes\n", num, len);
    }
  }

  return num;
}


ssize_t
sgxbridge_pipe_write(unsigned char* data, size_t len)
{
  size_t num = 0, n;
  int fd = fd_ssl_sgx;

#ifdef SGX_ENCLAVE
  fd = fd_sgx_ssl;
#endif

  while(num < len){
    if((n = write(fd, data + num, len - num)) < 0){
      debug_fprintf(stderr, "SGX write() failed: %s\n", strerror(errno));

      return -1;
    } else {
      num += n;
      debug_fprintf(stdout, "SGX write() %zu out of %zu bytes\n", num, len);
    }
  }

  return num;
}
sgxbridge_pipe_write_cmd(SSL *s, int cmd, int len, unsigned char* data)
{
  int fd = fd_ssl_sgx;
  cmd_pkt_t cmd_pkt;
#ifdef SGX_ENCLAVE
  fd = fd_sgx_ssl;
#endif

  debug_printf("sgxbridge_pipe_write, cmd: %d, len: %d\n", cmd, len);
  print_hex_trim(data, len);

  cmd_pkt.cmd = cmd;
  memcpy(cmd_pkt.sgx_session_id, s->sgx_session_id, SGX_SESSION_ID_LENGTH);
  memcpy(cmd_pkt.ssl_session_id, s->session->session_id,
      SSL3_SSL_SESSION_ID_LENGTH);
  cmd_pkt.data_len = len;

  sgxbridge_pipe_write(&cmd_pkt, sizeof(cmd_pkt));
  sgxbridge_pipe_write(data, len);
}
sgxbridge_pipe_write_cmd_remove_session(unsigned char* session_id)
{
  cmd_pkt_t cmd_pkt;

  cmd_pkt.cmd = CMD_SSL_SESSION_REMOVE;
  cmd_pkt.data_len = 0;
  memcpy(cmd_pkt.ssl_session_id, session_id, SSL3_SSL_SESSION_ID_LENGTH);

  sgxbridge_pipe_write(&cmd_pkt, sizeof(cmd_pkt));
}


static int
sgx_session_cmp(const SGX_SESSION *a, const SGX_SESSION *b)
{
  return strncmp((char *) a->id, (char *) b->id, SGX_SESSION_ID_LENGTH);
}


static unsigned long
sgx_session_hash(const SGX_SESSION *a)
{
  unsigned char b[SGX_SESSION_ID_LENGTH];
  MD5(a->id, SGX_SESSION_ID_LENGTH, b);

  return(b[0]|(b[1]<<8)|(b[2]<<16)|(b[3]<<24));
}


_STACK *
sk_dup(_STACK *sk)
{
	_STACK *ret;
	char **s;

	if ((ret = sk_new(sk->comp)) == NULL)
		goto err;
	s = reallocarray(ret->data, sk->num_alloc, sizeof(char *));
	if (s == NULL)
		goto err;
	ret->data = s;

	ret->num = sk->num;
	memcpy(ret->data, sk->data, sizeof(char *) * sk->num);
	ret->sorted = sk->sorted;
	ret->num_alloc = sk->num_alloc;
	ret->comp = sk->comp;
	return (ret);

err:
	if (ret)
		sk_free(ret);
	return (NULL);
}


void
sk_free(_STACK *st)
{
	if (st == NULL)
		return;
	free(st->data);
	free(st);
}


int
sk_insert(_STACK *st, void *data, int loc)
{
	char **s;

	if (st == NULL)
		return 0;
	if (st->num_alloc <= st->num + 1) {
		s = reallocarray(st->data, st->num_alloc, 2 * sizeof(char *));
		if (s == NULL)
			return (0);
		st->data = s;
		st->num_alloc *= 2;
	}
	if ((loc >= (int)st->num) || (loc < 0))
		st->data[st->num] = data;
	else {
		memmove(&(st->data[loc + 1]), &(st->data[loc]),
		    sizeof(char *)*(st->num - loc));
		st->data[loc] = data;
	}
	st->num++;
	st->sorted = 0;
	return (st->num);
}


_STACK *
sk_new_null(void)
{
	return sk_new((int (*)(const void *, const void *))0);
}
sk_new(int (*c)(const void *, const void *))
{
	_STACK *ret;
	int i;

	if ((ret = malloc(sizeof(_STACK))) == NULL)
		goto err;
	if ((ret->data = reallocarray(NULL, MIN_NODES, sizeof(char *))) == NULL)
		goto err;
	for (i = 0; i < MIN_NODES; i++)
		ret->data[i] = NULL;
	ret->comp = c;
	ret->num_alloc = MIN_NODES;
	ret->num = 0;
	ret->sorted = 0;
	return (ret);

err:
	free(ret);
	return (NULL);
}


_STACK *
sk_new_null(void)
{
	return sk_new((int (*)(const void *, const void *))0);
}


int
sk_num(const _STACK *st)
{
	if (st == NULL)
		return -1;
	return st->num;
}


void
sk_pop_free(_STACK *st, void (*func)(void *))
{
	int i;

	if (st == NULL)
		return;
	for (i = 0; i < st->num; i++)
		if (st->data[i] != NULL)
			func(st->data[i]);
	sk_free(st);
}


int
sk_push(_STACK *st, void *data)
{
	return (sk_insert(st, data, st->num));
}


void *
sk_set(_STACK *st, int i, void *value)
{
	if (!st || (i < 0) || (i >= st->num))
		return NULL;
	return (st->data[i] = value);
}


void
sk_sort(_STACK *st)
{
	if (st && !st->sorted) {
		int (*comp_func)(const void *, const void *);

		/* same comment as in sk_find ... previously st->comp was declared
		 * as a (void*,void*) callback type, but this made the population
		 * of the callback pointer illogical - our callbacks compare
		 * type** with type**, so we leave the casting until absolutely
		 * necessary (ie. "now"). */
		comp_func = (int (*)(const void *, const void *))(st->comp);
		qsort(st->data, st->num, sizeof(char *), comp_func);
		st->sorted = 1;
	}
}


void *
sk_value(const _STACK *st, int i)
{
	if (!st || (i < 0) || (i >= st->num))
		return NULL;
	return st->data[i];
}


long
ssl23_default_timeout(void)
{
	return (300);
}


void
ssl3_clear(SSL *s)
{
	unsigned char	*rp, *wp;
	size_t		 rlen, wlen;

	tls1_cleanup_key_block(s);
	if (s->s3->tmp.ca_names != NULL)
		sk_X509_NAME_pop_free(s->s3->tmp.ca_names, X509_NAME_free);

	DH_free(s->s3->tmp.dh);
	s->s3->tmp.dh = NULL;
	EC_KEY_free(s->s3->tmp.ecdh);
	s->s3->tmp.ecdh = NULL;

	rp = s->s3->rbuf.buf;
	wp = s->s3->wbuf.buf;
	rlen = s->s3->rbuf.len;
	wlen = s->s3->wbuf.len;

	BIO_free(s->s3->handshake_buffer);
	s->s3->handshake_buffer = NULL;

	tls1_free_digest_list(s);

	free(s->s3->alpn_selected);
	s->s3->alpn_selected = NULL;

	memset(s->s3, 0, sizeof *s->s3);
	s->s3->rbuf.buf = rp;
	s->s3->wbuf.buf = wp;
	s->s3->rbuf.len = rlen;
	s->s3->wbuf.len = wlen;

	ssl_free_wbio_buffer(s);

	s->packet_length = 0;
	s->s3->renegotiate = 0;
	s->s3->total_renegotiations = 0;
	s->s3->num_renegotiations = 0;
	s->s3->in_read_app_data = 0;
	s->version = TLS1_VERSION;

	free(s->next_proto_negotiated);
	s->next_proto_negotiated = NULL;
	s->next_proto_negotiated_len = 0;
}


const SSL_CIPHER *
ssl3_get_cipher(unsigned int u)
{
	if (u < SSL3_NUM_CIPHERS)
		return (&(ssl3_ciphers[SSL3_NUM_CIPHERS - 1 - u]));
	else
		return (NULL);
}
ssl3_get_cipher_by_id(unsigned int id)
{
	const SSL_CIPHER *cp;
	SSL_CIPHER c;

	c.id = id;
	cp = OBJ_bsearch_ssl_cipher_id(&c, ssl3_ciphers, SSL3_NUM_CIPHERS);
	if (cp != NULL && cp->valid == 1)
		return (cp);

	return (NULL);
}
ssl3_get_cipher_by_value(uint16_t value)
{
	return ssl3_get_cipher_by_id(SSL3_CK_ID | value);
}
ssl3_get_cipher_by_char(const unsigned char *p)
{
	CBS cipher;
	uint16_t cipher_value;

	/* We have to assume it is at least 2 bytes due to existing API. */
	CBS_init(&cipher, p, 2);
	if (!CBS_get_u16(&cipher, &cipher_value))
		return NULL;

	return ssl3_get_cipher_by_value(cipher_value);
}


const SSL_CIPHER *
ssl3_get_cipher_by_id(unsigned int id)
{
	const SSL_CIPHER *cp;
	SSL_CIPHER c;

	c.id = id;
	cp = OBJ_bsearch_ssl_cipher_id(&c, ssl3_ciphers, SSL3_NUM_CIPHERS);
	if (cp != NULL && cp->valid == 1)
		return (cp);

	return (NULL);
}


int
ssl3_new(SSL *s)
{
	SSL3_STATE	*s3;

	if ((s3 = calloc(1, sizeof *s3)) == NULL)
		goto err;
	memset(s3->rrec.seq_num, 0, sizeof(s3->rrec.seq_num));
	memset(s3->wrec.seq_num, 0, sizeof(s3->wrec.seq_num));

	s->s3 = s3;

	s->method->ssl_clear(s);
	return (1);
err:
	return (0);
}


int
ssl3_num_ciphers(void)
{
	return (SSL3_NUM_CIPHERS);
}


static inline int
ssl_aes_is_accelerated(void)
{
#if defined(__i386__) || defined(__x86_64__)
	return ((OPENSSL_cpu_caps() & (1ULL << 57)) != 0);
#else
	return (0);
#endif
}


CERT *
ssl_cert_dup(CERT *cert)
{
	CERT *ret;
	int i;

	ret = calloc(1, sizeof(CERT));
	if (ret == NULL) {
		SSLerr(SSL_F_SSL_CERT_DUP, ERR_R_MALLOC_FAILURE);
		return (NULL);
	}

	/*
	 * same as ret->key = ret->pkeys + (cert->key - cert->pkeys),
	 * if you find that more readable
	 */
	ret->key = &ret->pkeys[cert->key - &cert->pkeys[0]];

	ret->valid = cert->valid;
	ret->mask_k = cert->mask_k;
	ret->mask_a = cert->mask_a;

	if (cert->dh_tmp != NULL) {
		ret->dh_tmp = DHparams_dup(cert->dh_tmp);
		if (ret->dh_tmp == NULL) {
			SSLerr(SSL_F_SSL_CERT_DUP, ERR_R_DH_LIB);
			goto err;
		}
		if (cert->dh_tmp->priv_key) {
			BIGNUM *b = BN_dup(cert->dh_tmp->priv_key);
			if (!b) {
				SSLerr(SSL_F_SSL_CERT_DUP, ERR_R_BN_LIB);
				goto err;
			}
			ret->dh_tmp->priv_key = b;
		}
		if (cert->dh_tmp->pub_key) {
			BIGNUM *b = BN_dup(cert->dh_tmp->pub_key);
			if (!b) {
				SSLerr(SSL_F_SSL_CERT_DUP, ERR_R_BN_LIB);
				goto err;
			}
			ret->dh_tmp->pub_key = b;
		}
	}
	ret->dh_tmp_cb = cert->dh_tmp_cb;
	ret->dh_tmp_auto = cert->dh_tmp_auto;

	if (cert->ecdh_tmp) {
		ret->ecdh_tmp = EC_KEY_dup(cert->ecdh_tmp);
		if (ret->ecdh_tmp == NULL) {
			SSLerr(SSL_F_SSL_CERT_DUP, ERR_R_EC_LIB);
			goto err;
		}
	}
	ret->ecdh_tmp_cb = cert->ecdh_tmp_cb;
	ret->ecdh_tmp_auto = cert->ecdh_tmp_auto;

	for (i = 0; i < SSL_PKEY_NUM; i++) {
		if (cert->pkeys[i].x509 != NULL) {
			ret->pkeys[i].x509 = cert->pkeys[i].x509;
			CRYPTO_add(&ret->pkeys[i].x509->references, 1,
			CRYPTO_LOCK_X509);
		}

		if (cert->pkeys[i].privatekey != NULL) {
			ret->pkeys[i].privatekey = cert->pkeys[i].privatekey;
			CRYPTO_add(&ret->pkeys[i].privatekey->references, 1,
			CRYPTO_LOCK_EVP_PKEY);

			switch (i) {
				/*
				 * If there was anything special to do for
				 * certain types of keys, we'd do it here.
				 * (Nothing at the moment, I think.)
				 */

			case SSL_PKEY_RSA_ENC:
			case SSL_PKEY_RSA_SIGN:
				/* We have an RSA key. */
				break;

			case SSL_PKEY_DSA_SIGN:
				/* We have a DSA key. */
				break;

			case SSL_PKEY_DH_RSA:
			case SSL_PKEY_DH_DSA:
				/* We have a DH key. */
				break;

			case SSL_PKEY_ECC:
				/* We have an ECC key */
				break;

			default:
				/* Can't happen. */
				SSLerr(SSL_F_SSL_CERT_DUP, SSL_R_LIBRARY_BUG);
			}
		}
	}

	/*
	 * ret->extra_certs *should* exist, but currently the own certificate
	 * chain is held inside SSL_CTX
	 */

	ret->references = 1;
	/*
	 * Set digests to defaults. NB: we don't copy existing values
	 * as they will be set during handshake.
	 */
	ssl_cert_set_default_md(ret);

	return (ret);

err:
	DH_free(ret->dh_tmp);
	EC_KEY_free(ret->ecdh_tmp);

	for (i = 0; i < SSL_PKEY_NUM; i++) {
		X509_free(ret->pkeys[i].x509);
		EVP_PKEY_free(ret->pkeys[i].privatekey);
	}
	free (ret);
	return NULL;
}


int
ssl_cert_inst(CERT **o)
{
	/*
	 * Create a CERT if there isn't already one
	 * (which cannot really happen, as it is initially created in
	 * SSL_CTX_new; but the earlier code usually allows for that one
	 * being non-existant, so we follow that behaviour, as it might
	 * turn out that there actually is a reason for it -- but I'm
	 * not sure that *all* of the existing code could cope with
	 * s->cert being NULL, otherwise we could do without the
	 * initialization in SSL_CTX_new).
	 */

	if (o == NULL) {
		SSLerr(SSL_F_SSL_CERT_INST, ERR_R_PASSED_NULL_PARAMETER);
		return (0);
	}
	if (*o == NULL) {
		if ((*o = ssl_cert_new()) == NULL) {
			SSLerr(SSL_F_SSL_CERT_INST, ERR_R_MALLOC_FAILURE);
			return (0);
		}
	}
	return (1);
}


CERT *
ssl_cert_new(void)
{
	CERT *ret;

	ret = calloc(1, sizeof(CERT));
	if (ret == NULL) {
		SSLerr(SSL_F_SSL_CERT_NEW, ERR_R_MALLOC_FAILURE);
		return (NULL);
	}
	ret->key = &(ret->pkeys[SSL_PKEY_RSA_ENC]);
	ret->references = 1;
	ssl_cert_set_default_md(ret);
	return (ret);
}


static void
ssl_cert_set_default_md(CERT *cert)
{
	/* Set digest values to defaults */
	cert->pkeys[SSL_PKEY_DSA_SIGN].digest = EVP_sha1();
	cert->pkeys[SSL_PKEY_RSA_SIGN].digest = EVP_sha1();
	cert->pkeys[SSL_PKEY_RSA_ENC].digest = EVP_sha1();
	cert->pkeys[SSL_PKEY_ECC].digest = EVP_sha1();
#ifndef OPENSSL_NO_GOST
	cert->pkeys[SSL_PKEY_GOST01].digest = EVP_gostr341194();
#endif
}


int
ssl_cert_type(X509 *x, EVP_PKEY *pkey)
{
	EVP_PKEY *pk;
	int ret = -1, i;

	if (pkey == NULL)
		pk = X509_get_pubkey(x);
	else
		pk = pkey;
	if (pk == NULL)
		goto err;

	i = pk->type;
	if (i == EVP_PKEY_RSA) {
		ret = SSL_PKEY_RSA_ENC;
	} else if (i == EVP_PKEY_DSA) {
		ret = SSL_PKEY_DSA_SIGN;
	} else if (i == EVP_PKEY_EC) {
		ret = SSL_PKEY_ECC;
	} else if (i == NID_id_GostR3410_2001 ||
	    i == NID_id_GostR3410_2001_cc) {
		ret = SSL_PKEY_GOST01;
	}

err:
	if (!pkey)
		EVP_PKEY_free(pk);
	return (ret);
}


static void
ssl_cipher_apply_rule(unsigned long cipher_id, unsigned long alg_mkey,
    unsigned long alg_auth, unsigned long alg_enc, unsigned long alg_mac,
    unsigned long alg_ssl, unsigned long algo_strength,
    int rule, int strength_bits, CIPHER_ORDER **head_p, CIPHER_ORDER **tail_p)
{
	CIPHER_ORDER *head, *tail, *curr, *next, *last;
	const SSL_CIPHER *cp;
	int reverse = 0;


	if (rule == CIPHER_DEL)
		reverse = 1; /* needed to maintain sorting between currently deleted ciphers */

	head = *head_p;
	tail = *tail_p;

	if (reverse) {
		next = tail;
		last = head;
	} else {
		next = head;
		last = tail;
	}

	curr = NULL;
	for (;;) {
		if (curr == last)
			break;
		curr = next;
		next = reverse ? curr->prev : curr->next;

		cp = curr->cipher;

		/*
		 * Selection criteria is either the value of strength_bits
		 * or the algorithms used.
		 */
		if (strength_bits >= 0) {
			if (strength_bits != cp->strength_bits)
				continue;
		} else {

			if (alg_mkey && !(alg_mkey & cp->algorithm_mkey))
				continue;
			if (alg_auth && !(alg_auth & cp->algorithm_auth))
				continue;
			if (alg_enc && !(alg_enc & cp->algorithm_enc))
				continue;
			if (alg_mac && !(alg_mac & cp->algorithm_mac))
				continue;
			if (alg_ssl && !(alg_ssl & cp->algorithm_ssl))
				continue;
			if ((algo_strength & SSL_STRONG_MASK) && !(algo_strength & SSL_STRONG_MASK & cp->algo_strength))
				continue;
		}


		/* add the cipher if it has not been added yet. */
		if (rule == CIPHER_ADD) {
			/* reverse == 0 */
			if (!curr->active) {
				ll_append_tail(&head, curr, &tail);
				curr->active = 1;
			}
		}
		/* Move the added cipher to this location */
		else if (rule == CIPHER_ORD) {
			/* reverse == 0 */
			if (curr->active) {
				ll_append_tail(&head, curr, &tail);
			}
		} else if (rule == CIPHER_DEL) {
			/* reverse == 1 */
			if (curr->active) {
				/* most recently deleted ciphersuites get best positions
				 * for any future CIPHER_ADD (note that the CIPHER_DEL loop
				 * works in reverse to maintain the order) */
				ll_append_head(&head, curr, &tail);
				curr->active = 0;
			}
		} else if (rule == CIPHER_KILL) {
			/* reverse == 0 */
			if (head == curr)
				head = curr->next;
			else
				curr->prev->next = curr->next;
			if (tail == curr)
				tail = curr->prev;
			curr->active = 0;
			if (curr->next != NULL)
				curr->next->prev = curr->prev;
			if (curr->prev != NULL)
				curr->prev->next = curr->next;
			curr->next = NULL;
			curr->prev = NULL;
		}
	}

	*head_p = head;
	*tail_p = tail;
}


static void
ssl_cipher_collect_aliases(const SSL_CIPHER **ca_list, int num_of_group_aliases,
    unsigned long disabled_mkey, unsigned long disabled_auth,
    unsigned long disabled_enc, unsigned long disabled_mac,
    unsigned long disabled_ssl, CIPHER_ORDER *head)
{
	CIPHER_ORDER *ciph_curr;
	const SSL_CIPHER **ca_curr;
	int i;
	unsigned long mask_mkey = ~disabled_mkey;
	unsigned long mask_auth = ~disabled_auth;
	unsigned long mask_enc = ~disabled_enc;
	unsigned long mask_mac = ~disabled_mac;
	unsigned long mask_ssl = ~disabled_ssl;

	/*
	 * First, add the real ciphers as already collected
	 */
	ciph_curr = head;
	ca_curr = ca_list;
	while (ciph_curr != NULL) {
		*ca_curr = ciph_curr->cipher;
		ca_curr++;
		ciph_curr = ciph_curr->next;
	}

	/*
	 * Now we add the available ones from the cipher_aliases[] table.
	 * They represent either one or more algorithms, some of which
	 * in any affected category must be supported (set in enabled_mask),
	 * or represent a cipher strength value (will be added in any case because algorithms=0).
	 */
	for (i = 0; i < num_of_group_aliases; i++) {
		unsigned long algorithm_mkey = cipher_aliases[i].algorithm_mkey;
		unsigned long algorithm_auth = cipher_aliases[i].algorithm_auth;
		unsigned long algorithm_enc = cipher_aliases[i].algorithm_enc;
		unsigned long algorithm_mac = cipher_aliases[i].algorithm_mac;
		unsigned long algorithm_ssl = cipher_aliases[i].algorithm_ssl;

		if (algorithm_mkey)
			if ((algorithm_mkey & mask_mkey) == 0)
				continue;

		if (algorithm_auth)
			if ((algorithm_auth & mask_auth) == 0)
				continue;

		if (algorithm_enc)
			if ((algorithm_enc & mask_enc) == 0)
				continue;

		if (algorithm_mac)
			if ((algorithm_mac & mask_mac) == 0)
				continue;

		if (algorithm_ssl)
			if ((algorithm_ssl & mask_ssl) == 0)
				continue;

		*ca_curr = (SSL_CIPHER *)(cipher_aliases + i);
		ca_curr++;
	}

	*ca_curr = NULL;	/* end of list */
}


static void
ssl_cipher_collect_ciphers(const SSL_METHOD *ssl_method, int num_of_ciphers,
    unsigned long disabled_mkey, unsigned long disabled_auth,
    unsigned long disabled_enc, unsigned long disabled_mac,
    unsigned long disabled_ssl, CIPHER_ORDER *co_list,
    CIPHER_ORDER **head_p, CIPHER_ORDER **tail_p)
{
	int i, co_list_num;
	const SSL_CIPHER *c;

	/*
	 * We have num_of_ciphers descriptions compiled in, depending on the
	 * method selected (SSLv3, TLSv1, etc). These will later be sorted in
	 * a linked list with at most num entries.
	 */

	/* Get the initial list of ciphers */
	co_list_num = 0;	/* actual count of ciphers */
	for (i = 0; i < num_of_ciphers; i++) {
		c = ssl_method->get_cipher(i);
		/* drop those that use any of that is not available */
		if ((c != NULL) && c->valid &&
		    !(c->algorithm_mkey & disabled_mkey) &&
		    !(c->algorithm_auth & disabled_auth) &&
		    !(c->algorithm_enc & disabled_enc) &&
		    !(c->algorithm_mac & disabled_mac) &&
		    !(c->algorithm_ssl & disabled_ssl)) {
			co_list[co_list_num].cipher = c;
			co_list[co_list_num].next = NULL;
			co_list[co_list_num].prev = NULL;
			co_list[co_list_num].active = 0;
			co_list_num++;
			/*
			if (!sk_push(ca_list,(char *)c)) goto err;
			*/
		}
	}

	/*
	 * Prepare linked list from list entries
	 */
	if (co_list_num > 0) {
		co_list[0].prev = NULL;

		if (co_list_num > 1) {
			co_list[0].next = &co_list[1];

			for (i = 1; i < co_list_num - 1; i++) {
				co_list[i].prev = &co_list[i - 1];
				co_list[i].next = &co_list[i + 1];
			}

			co_list[co_list_num - 1].prev =
			    &co_list[co_list_num - 2];
		}

		co_list[co_list_num - 1].next = NULL;

		*head_p = &co_list[0];
		*tail_p = &co_list[co_list_num - 1];
	}
}


static void
ssl_cipher_get_disabled(unsigned long *mkey, unsigned long *auth,
    unsigned long *enc, unsigned long *mac, unsigned long *ssl)
{
	*mkey = 0;
	*auth = 0;
	*enc = 0;
	*mac = 0;
	*ssl = 0;

	/*
	 * Check for the availability of GOST 34.10 public/private key
	 * algorithms. If they are not available disable the associated
	 * authentication and key exchange algorithms.
	 */
	if (EVP_PKEY_meth_find(NID_id_GostR3410_2001) == NULL) {
		*auth |= SSL_aGOST01;
		*mkey |= SSL_kGOST;
	}

#ifdef SSL_FORBID_ENULL
	*enc |= SSL_eNULL;
#endif

	*enc |= (ssl_cipher_methods[SSL_ENC_DES_IDX ] == NULL) ? SSL_DES : 0;
	*enc |= (ssl_cipher_methods[SSL_ENC_3DES_IDX] == NULL) ? SSL_3DES : 0;
	*enc |= (ssl_cipher_methods[SSL_ENC_RC4_IDX ] == NULL) ? SSL_RC4 : 0;
	*enc |= (ssl_cipher_methods[SSL_ENC_IDEA_IDX] == NULL) ? SSL_IDEA : 0;
	*enc |= (ssl_cipher_methods[SSL_ENC_AES128_IDX] == NULL) ? SSL_AES128 : 0;
	*enc |= (ssl_cipher_methods[SSL_ENC_AES256_IDX] == NULL) ? SSL_AES256 : 0;
	*enc |= (ssl_cipher_methods[SSL_ENC_AES128GCM_IDX] == NULL) ? SSL_AES128GCM : 0;
	*enc |= (ssl_cipher_methods[SSL_ENC_AES256GCM_IDX] == NULL) ? SSL_AES256GCM : 0;
	*enc |= (ssl_cipher_methods[SSL_ENC_CAMELLIA128_IDX] == NULL) ? SSL_CAMELLIA128 : 0;
	*enc |= (ssl_cipher_methods[SSL_ENC_CAMELLIA256_IDX] == NULL) ? SSL_CAMELLIA256 : 0;
	*enc |= (ssl_cipher_methods[SSL_ENC_GOST89_IDX] == NULL) ? SSL_eGOST2814789CNT : 0;

	*mac |= (ssl_digest_methods[SSL_MD_MD5_IDX ] == NULL) ? SSL_MD5 : 0;
	*mac |= (ssl_digest_methods[SSL_MD_SHA1_IDX] == NULL) ? SSL_SHA1 : 0;
	*mac |= (ssl_digest_methods[SSL_MD_SHA256_IDX] == NULL) ? SSL_SHA256 : 0;
	*mac |= (ssl_digest_methods[SSL_MD_SHA384_IDX] == NULL) ? SSL_SHA384 : 0;
	*mac |= (ssl_digest_methods[SSL_MD_GOST94_IDX] == NULL) ? SSL_GOST94 : 0;
	*mac |= (ssl_digest_methods[SSL_MD_GOST89MAC_IDX] == NULL) ? SSL_GOST89MAC : 0;
	*mac |= (ssl_digest_methods[SSL_MD_STREEBOG256_IDX] == NULL) ? SSL_STREEBOG256 : 0;
	*mac |= (ssl_digest_methods[SSL_MD_STREEBOG512_IDX] == NULL) ? SSL_STREEBOG512 : 0;

}


int
ssl_cipher_get_evp_aead(const SSL_SESSION *s, const EVP_AEAD **aead)
{
	const SSL_CIPHER *c = s->cipher;

	*aead = NULL;

	if (c == NULL)
		return 0;
	if ((c->algorithm2 & SSL_CIPHER_ALGORITHM2_AEAD) == 0)
		return 0;

	switch (c->algorithm_enc) {
#ifndef OPENSSL_NO_AES
	case SSL_AES128GCM:
		*aead = EVP_aead_aes_128_gcm();
		return 1;
	case SSL_AES256GCM:
		*aead = EVP_aead_aes_256_gcm();
		return 1;
#endif
#if !defined(OPENSSL_NO_CHACHA) && !defined(OPENSSL_NO_POLY1305)
	case SSL_CHACHA20POLY1305:
		*aead = EVP_aead_chacha20_poly1305();
		return 1;
	case SSL_CHACHA20POLY1305_OLD:
		*aead = EVP_aead_chacha20_poly1305_old();
		return 1;
#endif
	default:
		break;
	}
	return 0;
}


int
ssl_cipher_id_cmp(const SSL_CIPHER *a, const SSL_CIPHER *b)
{
	long	l;

	l = a->id - b->id;
	if (l == 0L)
		return (0);
	else
		return ((l > 0) ? 1:-1);
}


static int
ssl_cipher_process_rulestr(const char *rule_str, CIPHER_ORDER **head_p,
    CIPHER_ORDER **tail_p, const SSL_CIPHER **ca_list)
{
	unsigned long alg_mkey, alg_auth, alg_enc, alg_mac, alg_ssl;
	unsigned long algo_strength;
	int j, multi, found, rule, retval, ok, buflen;
	unsigned long cipher_id = 0;
	const char *l, *buf;
	char ch;

	retval = 1;
	l = rule_str;
	for (;;) {
		ch = *l;

		if (ch == '\0')
			break;

		if (ch == '-') {
			rule = CIPHER_DEL;
			l++;
		} else if (ch == '+') {
			rule = CIPHER_ORD;
			l++;
		} else if (ch == '!') {
			rule = CIPHER_KILL;
			l++;
		} else if (ch == '@') {
			rule = CIPHER_SPECIAL;
			l++;
		} else {
			rule = CIPHER_ADD;
		}

		if (ITEM_SEP(ch)) {
			l++;
			continue;
		}

		alg_mkey = 0;
		alg_auth = 0;
		alg_enc = 0;
		alg_mac = 0;
		alg_ssl = 0;
		algo_strength = 0;

		for (;;) {
			ch = *l;
			buf = l;
			buflen = 0;
			while (((ch >= 'A') && (ch <= 'Z')) ||
			    ((ch >= '0') && (ch <= '9')) ||
			    ((ch >= 'a') && (ch <= 'z')) ||
			    (ch == '-') || (ch == '.')) {
				ch = *(++l);
				buflen++;
			}

			if (buflen == 0) {
				/*
				 * We hit something we cannot deal with,
				 * it is no command or separator nor
				 * alphanumeric, so we call this an error.
				 */
				SSLerr(SSL_F_SSL_CIPHER_PROCESS_RULESTR,
				    SSL_R_INVALID_COMMAND);
				retval = found = 0;
				l++;
				break;
			}

			if (rule == CIPHER_SPECIAL) {
				 /* unused -- avoid compiler warning */
				found = 0;
				/* special treatment */
				break;
			}

			/* check for multi-part specification */
			if (ch == '+') {
				multi = 1;
				l++;
			} else
				multi = 0;

			/*
			 * Now search for the cipher alias in the ca_list.
			 * Be careful with the strncmp, because the "buflen"
			 * limitation will make the rule "ADH:SOME" and the
			 * cipher "ADH-MY-CIPHER" look like a match for
			 * buflen=3. So additionally check whether the cipher
			 * name found has the correct length. We can save a
			 * strlen() call: just checking for the '\0' at the
			 * right place is sufficient, we have to strncmp()
			 * anyway (we cannot use strcmp(), because buf is not
			 * '\0' terminated.)
			 */
			j = found = 0;
			cipher_id = 0;
			while (ca_list[j]) {
				if (!strncmp(buf, ca_list[j]->name, buflen) &&
				    (ca_list[j]->name[buflen] == '\0')) {
					found = 1;
					break;
				} else
					j++;
			}

			if (!found)
				break;	/* ignore this entry */

			if (ca_list[j]->algorithm_mkey) {
				if (alg_mkey) {
					alg_mkey &= ca_list[j]->algorithm_mkey;
					if (!alg_mkey) {
						found = 0;
						break;
					}
				} else
					alg_mkey = ca_list[j]->algorithm_mkey;
			}

			if (ca_list[j]->algorithm_auth) {
				if (alg_auth) {
					alg_auth &= ca_list[j]->algorithm_auth;
					if (!alg_auth) {
						found = 0;
						break;
					}
				} else
					alg_auth = ca_list[j]->algorithm_auth;
			}

			if (ca_list[j]->algorithm_enc) {
				if (alg_enc) {
					alg_enc &= ca_list[j]->algorithm_enc;
					if (!alg_enc) {
						found = 0;
						break;
					}
				} else
					alg_enc = ca_list[j]->algorithm_enc;
			}

			if (ca_list[j]->algorithm_mac) {
				if (alg_mac) {
					alg_mac &= ca_list[j]->algorithm_mac;
					if (!alg_mac) {
						found = 0;
						break;
					}
				} else
					alg_mac = ca_list[j]->algorithm_mac;
			}

			if (ca_list[j]->algo_strength & SSL_STRONG_MASK) {
				if (algo_strength & SSL_STRONG_MASK) {
					algo_strength &=
					    (ca_list[j]->algo_strength &
					    SSL_STRONG_MASK) | ~SSL_STRONG_MASK;
					if (!(algo_strength &
					    SSL_STRONG_MASK)) {
						found = 0;
						break;
					}
				} else
					algo_strength |=
					    ca_list[j]->algo_strength &
					    SSL_STRONG_MASK;
			}

			if (ca_list[j]->valid) {
				/*
				 * explicit ciphersuite found; its protocol
				 * version does not become part of the search
				 * pattern!
				 */
				cipher_id = ca_list[j]->id;
			} else {
				/*
				 * not an explicit ciphersuite; only in this
				 * case, the protocol version is considered
				 * part of the search pattern
				 */
				if (ca_list[j]->algorithm_ssl) {
					if (alg_ssl) {
						alg_ssl &=
						    ca_list[j]->algorithm_ssl;
						if (!alg_ssl) {
							found = 0;
							break;
						}
					} else
						alg_ssl =
						    ca_list[j]->algorithm_ssl;
				}
			}

			if (!multi)
				break;
		}

		/*
		 * Ok, we have the rule, now apply it
		 */
		if (rule == CIPHER_SPECIAL) {
			/* special command */
			ok = 0;
			if ((buflen == 8) && !strncmp(buf, "STRENGTH", 8))
				ok = ssl_cipher_strength_sort(head_p, tail_p);
			else
				SSLerr(SSL_F_SSL_CIPHER_PROCESS_RULESTR,
				    SSL_R_INVALID_COMMAND);
			if (ok == 0)
				retval = 0;
			/*
			 * We do not support any "multi" options
			 * together with "@", so throw away the
			 * rest of the command, if any left, until
			 * end or ':' is found.
			 */
			while ((*l != '\0') && !ITEM_SEP(*l))
				l++;
		} else if (found) {
			ssl_cipher_apply_rule(cipher_id, alg_mkey, alg_auth,
			    alg_enc, alg_mac, alg_ssl, algo_strength, rule,
			    -1, head_p, tail_p);
		} else {
			while ((*l != '\0') && !ITEM_SEP(*l))
				l++;
		}
		if (*l == '\0')
			break; /* done */
	}

	return (retval);
}


int
ssl_cipher_ptr_id_cmp(const SSL_CIPHER * const *ap,
    const SSL_CIPHER * const *bp)
{
	long	l;

	l = (*ap)->id - (*bp)->id;
	if (l == 0L)
		return (0);
	else
		return ((l > 0) ? 1:-1);
}


static int
ssl_cipher_strength_sort(CIPHER_ORDER **head_p, CIPHER_ORDER **tail_p)
{
	int max_strength_bits, i, *number_uses;
	CIPHER_ORDER *curr;

	/*
	 * This routine sorts the ciphers with descending strength. The sorting
	 * must keep the pre-sorted sequence, so we apply the normal sorting
	 * routine as '+' movement to the end of the list.
	 */
	max_strength_bits = 0;
	curr = *head_p;
	while (curr != NULL) {
		if (curr->active &&
		    (curr->cipher->strength_bits > max_strength_bits))
			max_strength_bits = curr->cipher->strength_bits;
		curr = curr->next;
	}

	number_uses = calloc((max_strength_bits + 1), sizeof(int));
	if (!number_uses) {
		SSLerr(SSL_F_SSL_CIPHER_STRENGTH_SORT, ERR_R_MALLOC_FAILURE);
		return (0);
	}

	/*
	 * Now find the strength_bits values actually used
	 */
	curr = *head_p;
	while (curr != NULL) {
		if (curr->active)
			number_uses[curr->cipher->strength_bits]++;
		curr = curr->next;
	}
	/*
	 * Go through the list of used strength_bits values in descending
	 * order.
	 */
	for (i = max_strength_bits; i >= 0; i--)
		if (number_uses[i] > 0)
			ssl_cipher_apply_rule(0, 0, 0, 0, 0, 0, 0, CIPHER_ORD, i, head_p, tail_p);

	free(number_uses);
	return (1);
}


int
SSL_clear(SSL *s)
{
	if (s->method == NULL) {
		SSLerr(SSL_F_SSL_CLEAR, SSL_R_NO_METHOD_SPECIFIED);
		return (0);
	}

	if (ssl_clear_bad_session(s)) {
		SSL_SESSION_free(s->session);
		s->session = NULL;
	}

	s->error = 0;
	s->hit = 0;
	s->shutdown = 0;

	if (s->renegotiate) {
		SSLerr(SSL_F_SSL_CLEAR, ERR_R_INTERNAL_ERROR);
		return (0);
	}

	s->type = 0;

	s->state = SSL_ST_BEFORE|((s->server) ? SSL_ST_ACCEPT : SSL_ST_CONNECT);

	s->version = s->method->version;
	s->client_version = s->version;
	s->rwstate = SSL_NOTHING;
	s->rstate = SSL_ST_READ_HEADER;

	BUF_MEM_free(s->init_buf);
	s->init_buf = NULL;

	ssl_clear_cipher_ctx(s);
	ssl_clear_hash_ctx(&s->read_hash);
	ssl_clear_hash_ctx(&s->write_hash);

	s->first_packet = 0;

	/*
	 * Check to see if we were changed into a different method, if
	 * so, revert back if we are not doing session-id reuse.
	 */
	if (!s->in_handshake && (s->session == NULL) &&
	    (s->method != s->ctx->method)) {
		s->method->ssl_free(s);
		s->method = s->ctx->method;
		if (!s->method->ssl_new(s))
			return (0);
	} else
		s->method->ssl_clear(s);

	return (1);
}


int
ssl_clear_bad_session(SSL *s)
{
	if ((s->session != NULL) && !(s->shutdown & SSL_SENT_SHUTDOWN) &&
	    !(SSL_in_init(s) || SSL_in_before(s))) {
		SSL_CTX_remove_session(s->ctx, s->session);
		return (1);
	} else
		return (0);
}


void
ssl_clear_cipher_ctx(SSL *s)
{
	EVP_CIPHER_CTX_free(s->enc_read_ctx);
	s->enc_read_ctx = NULL;
	EVP_CIPHER_CTX_free(s->enc_write_ctx);
	s->enc_write_ctx = NULL;

	if (s->aead_read_ctx != NULL) {
		EVP_AEAD_CTX_cleanup(&s->aead_read_ctx->ctx);
		free(s->aead_read_ctx);
		s->aead_read_ctx = NULL;
	}
	if (s->aead_write_ctx != NULL) {
		EVP_AEAD_CTX_cleanup(&s->aead_write_ctx->ctx);
		free(s->aead_write_ctx);
		s->aead_write_ctx = NULL;
	}

}


void
ssl_clear_hash_ctx(EVP_MD_CTX **hash)
{
	if (*hash)
		EVP_MD_CTX_destroy(*hash);
	*hash = NULL;
}


STACK_OF(SSL_CIPHER) *
ssl_create_cipher_list(const SSL_METHOD *ssl_method,
    STACK_OF(SSL_CIPHER) **cipher_list,
    STACK_OF(SSL_CIPHER) **cipher_list_by_id,
    const char *rule_str)
{
	int ok, num_of_ciphers, num_of_alias_max, num_of_group_aliases;
	unsigned long disabled_mkey, disabled_auth, disabled_enc, disabled_mac, disabled_ssl;
	STACK_OF(SSL_CIPHER) *cipherstack, *tmp_cipher_list;
	const char *rule_p;
	CIPHER_ORDER *co_list = NULL, *head = NULL, *tail = NULL, *curr;
	const SSL_CIPHER **ca_list = NULL;

	/*
	 * Return with error if nothing to do.
	 */
	if (rule_str == NULL || cipher_list == NULL || cipher_list_by_id == NULL)
		return NULL;

	/*
	 * To reduce the work to do we only want to process the compiled
	 * in algorithms, so we first get the mask of disabled ciphers.
	 */
	ssl_cipher_get_disabled(&disabled_mkey, &disabled_auth, &disabled_enc, &disabled_mac, &disabled_ssl);

	/*
	 * Now we have to collect the available ciphers from the compiled
	 * in ciphers. We cannot get more than the number compiled in, so
	 * it is used for allocation.
	 */
	num_of_ciphers = ssl_method->num_ciphers();
	co_list = reallocarray(NULL, num_of_ciphers, sizeof(CIPHER_ORDER));
	if (co_list == NULL) {
		SSLerr(SSL_F_SSL_CREATE_CIPHER_LIST, ERR_R_MALLOC_FAILURE);
		return(NULL);	/* Failure */
	}

	ssl_cipher_collect_ciphers(ssl_method, num_of_ciphers,
	disabled_mkey, disabled_auth, disabled_enc, disabled_mac, disabled_ssl,
	co_list, &head, &tail);


	/* Now arrange all ciphers by preference: */

	/* Everything else being equal, prefer ephemeral ECDH over other key exchange mechanisms */
	ssl_cipher_apply_rule(0, SSL_kECDHE, 0, 0, 0, 0, 0, CIPHER_ADD, -1, &head, &tail);
	ssl_cipher_apply_rule(0, SSL_kECDHE, 0, 0, 0, 0, 0, CIPHER_DEL, -1, &head, &tail);

	if (ssl_aes_is_accelerated() == 1) {
		/*
		 * We have hardware assisted AES - prefer AES as a symmetric
		 * cipher, with CHACHA20 second.
		 */
		ssl_cipher_apply_rule(0, 0, 0, SSL_AES, 0, 0, 0,
		    CIPHER_ADD, -1, &head, &tail);
		ssl_cipher_apply_rule(0, 0, 0, SSL_CHACHA20POLY1305,
		    0, 0, 0, CIPHER_ADD, -1, &head, &tail);
		ssl_cipher_apply_rule(0, 0, 0, SSL_CHACHA20POLY1305_OLD,
		    0, 0, 0, CIPHER_ADD, -1, &head, &tail);
	} else {
		/*
		 * CHACHA20 is fast and safe on all hardware and is thus our
		 * preferred symmetric cipher, with AES second.
		 */
		ssl_cipher_apply_rule(0, 0, 0, SSL_CHACHA20POLY1305,
		    0, 0, 0, CIPHER_ADD, -1, &head, &tail);
		ssl_cipher_apply_rule(0, 0, 0, SSL_CHACHA20POLY1305_OLD,
		    0, 0, 0, CIPHER_ADD, -1, &head, &tail);
		ssl_cipher_apply_rule(0, 0, 0, SSL_AES, 0, 0, 0,
		    CIPHER_ADD, -1, &head, &tail);
	}

	/* Temporarily enable everything else for sorting */
	ssl_cipher_apply_rule(0, 0, 0, 0, 0, 0, 0, CIPHER_ADD, -1, &head, &tail);

	/* Low priority for MD5 */
	ssl_cipher_apply_rule(0, 0, 0, 0, SSL_MD5, 0, 0, CIPHER_ORD, -1, &head, &tail);

	/* Move anonymous ciphers to the end.  Usually, these will remain disabled.
	 * (For applications that allow them, they aren't too bad, but we prefer
	 * authenticated ciphers.) */
	ssl_cipher_apply_rule(0, 0, SSL_aNULL, 0, 0, 0, 0, CIPHER_ORD, -1, &head, &tail);

	/* Move ciphers without forward secrecy to the end */
	ssl_cipher_apply_rule(0, 0, SSL_aECDH, 0, 0, 0, 0, CIPHER_ORD, -1, &head, &tail);
	ssl_cipher_apply_rule(0, SSL_kRSA, 0, 0, 0, 0, 0, CIPHER_ORD, -1, &head, &tail);

	/* RC4 is sort of broken - move it to the end */
	ssl_cipher_apply_rule(0, 0, 0, SSL_RC4, 0, 0, 0, CIPHER_ORD, -1, &head, &tail);

	/* Now sort by symmetric encryption strength.  The above ordering remains
	 * in force within each class */
	if (!ssl_cipher_strength_sort(&head, &tail)) {
		free(co_list);
		return NULL;
	}

	/* Now disable everything (maintaining the ordering!) */
	ssl_cipher_apply_rule(0, 0, 0, 0, 0, 0, 0, CIPHER_DEL, -1, &head, &tail);


	/*
	 * We also need cipher aliases for selecting based on the rule_str.
	 * There might be two types of entries in the rule_str: 1) names
	 * of ciphers themselves 2) aliases for groups of ciphers.
	 * For 1) we need the available ciphers and for 2) the cipher
	 * groups of cipher_aliases added together in one list (otherwise
	 * we would be happy with just the cipher_aliases table).
	 */
	num_of_group_aliases = sizeof(cipher_aliases) / sizeof(SSL_CIPHER);
	num_of_alias_max = num_of_ciphers + num_of_group_aliases + 1;
	ca_list = reallocarray(NULL, num_of_alias_max, sizeof(SSL_CIPHER *));
	if (ca_list == NULL) {
		free(co_list);
		SSLerr(SSL_F_SSL_CREATE_CIPHER_LIST, ERR_R_MALLOC_FAILURE);
		return(NULL);	/* Failure */
	}
	ssl_cipher_collect_aliases(ca_list, num_of_group_aliases,
	disabled_mkey, disabled_auth, disabled_enc,
	disabled_mac, disabled_ssl, head);

	/*
	 * If the rule_string begins with DEFAULT, apply the default rule
	 * before using the (possibly available) additional rules.
	 */
	ok = 1;
	rule_p = rule_str;
	if (strncmp(rule_str, "DEFAULT", 7) == 0) {
		ok = ssl_cipher_process_rulestr(SSL_DEFAULT_CIPHER_LIST,
		&head, &tail, ca_list);
		rule_p += 7;
		if (*rule_p == ':')
			rule_p++;
	}

	if (ok && (strlen(rule_p) > 0))
		ok = ssl_cipher_process_rulestr(rule_p, &head, &tail, ca_list);

	free((void *)ca_list);	/* Not needed anymore */

	if (!ok) {
		/* Rule processing failure */
		free(co_list);
		return (NULL);
	}

	/*
	 * Allocate new "cipherstack" for the result, return with error
	 * if we cannot get one.
	 */
	if ((cipherstack = sk_SSL_CIPHER_new_null()) == NULL) {
		free(co_list);
		return (NULL);
	}

	/*
	 * The cipher selection for the list is done. The ciphers are added
	 * to the resulting precedence to the STACK_OF(SSL_CIPHER).
	 */
	for (curr = head; curr != NULL; curr = curr->next) {
		if (curr->active) {
			sk_SSL_CIPHER_push(cipherstack, curr->cipher);
		}
	}
	free(co_list);	/* Not needed any longer */

	tmp_cipher_list = sk_SSL_CIPHER_dup(cipherstack);
	if (tmp_cipher_list == NULL) {
		sk_SSL_CIPHER_free(cipherstack);
		return NULL;
	}
	if (*cipher_list != NULL)
		sk_SSL_CIPHER_free(*cipher_list);
	*cipher_list = cipherstack;
	if (*cipher_list_by_id != NULL)
		sk_SSL_CIPHER_free(*cipher_list_by_id);
	*cipher_list_by_id = tmp_cipher_list;
	(void)sk_SSL_CIPHER_set_cmp_func(*cipher_list_by_id,
	    ssl_cipher_ptr_id_cmp);

	sk_SSL_CIPHER_sort(*cipher_list_by_id);
	return (cipherstack);
}


SSL_CTX *
SSL_CTX_new(const SSL_METHOD *meth)
{
	SSL_CTX	*ret = NULL;

	if (meth == NULL) {
		SSLerr(SSL_F_SSL_CTX_NEW, SSL_R_NULL_SSL_METHOD_PASSED);
		return (NULL);
	}

	if (SSL_get_ex_data_X509_STORE_CTX_idx() < 0) {
		SSLerr(SSL_F_SSL_CTX_NEW,
		    SSL_R_X509_VERIFICATION_SETUP_PROBLEMS);
		goto err;
	}
	ret = calloc(1, sizeof(SSL_CTX));
	if (ret == NULL)
		goto err;

	ret->method = meth;

	ret->cert_store = NULL;
	ret->session_cache_mode = SSL_SESS_CACHE_SERVER;
	ret->session_cache_size = SSL_SESSION_CACHE_MAX_SIZE_DEFAULT;
	ret->session_cache_head = NULL;
	ret->session_cache_tail = NULL;

	/* We take the system default */
	ret->session_timeout = meth->get_timeout();

	ret->new_session_cb = 0;
	ret->remove_session_cb = 0;
	ret->get_session_cb = 0;
	ret->generate_session_id = 0;

	memset((char *)&ret->stats, 0, sizeof(ret->stats));

	ret->references = 1;
	ret->quiet_shutdown = 0;

	ret->info_callback = NULL;

	ret->app_verify_callback = 0;
	ret->app_verify_arg = NULL;

	ret->max_cert_list = SSL_MAX_CERT_LIST_DEFAULT;
	ret->read_ahead = 0;
	ret->msg_callback = 0;
	ret->msg_callback_arg = NULL;
	ret->verify_mode = SSL_VERIFY_NONE;
	ret->sid_ctx_length = 0;
	ret->default_verify_callback = NULL;
	if ((ret->cert = ssl_cert_new()) == NULL)
		goto err;

	ret->default_passwd_callback = 0;
	ret->default_passwd_callback_userdata = NULL;
	ret->client_cert_cb = 0;
	ret->app_gen_cookie_cb = 0;
	ret->app_verify_cookie_cb = 0;

	ret->sessions = lh_SSL_SESSION_new();
	if (ret->sessions == NULL)
		goto err;
	ret->cert_store = X509_STORE_new();
	if (ret->cert_store == NULL)
		goto err;

	ssl_create_cipher_list(ret->method, &ret->cipher_list,
	    &ret->cipher_list_by_id, SSL_DEFAULT_CIPHER_LIST);
	if (ret->cipher_list == NULL ||
	    sk_SSL_CIPHER_num(ret->cipher_list) <= 0) {
		SSLerr(SSL_F_SSL_CTX_NEW, SSL_R_LIBRARY_HAS_NO_CIPHERS);
		goto err2;
	}

	ret->param = X509_VERIFY_PARAM_new();
	if (!ret->param)
		goto err;

	if ((ret->md5 = EVP_get_digestbyname("ssl3-md5")) == NULL) {
		SSLerr(SSL_F_SSL_CTX_NEW,
		    SSL_R_UNABLE_TO_LOAD_SSL3_MD5_ROUTINES);
		goto err2;
	}
	if ((ret->sha1 = EVP_get_digestbyname("ssl3-sha1")) == NULL) {
		SSLerr(SSL_F_SSL_CTX_NEW,
		    SSL_R_UNABLE_TO_LOAD_SSL3_SHA1_ROUTINES);
		goto err2;
	}

	if ((ret->client_CA = sk_X509_NAME_new_null()) == NULL)
		goto err;

	CRYPTO_new_ex_data(CRYPTO_EX_INDEX_SSL_CTX, ret, &ret->ex_data);

	ret->extra_certs = NULL;

	ret->max_send_fragment = SSL3_RT_MAX_PLAIN_LENGTH;

	ret->tlsext_servername_callback = 0;
	ret->tlsext_servername_arg = NULL;

	/* Setup RFC4507 ticket keys */
	arc4random_buf(ret->tlsext_tick_key_name, 16);
	arc4random_buf(ret->tlsext_tick_hmac_key, 16);
	arc4random_buf(ret->tlsext_tick_aes_key, 16);

	ret->tlsext_status_cb = 0;
	ret->tlsext_status_arg = NULL;

	ret->next_protos_advertised_cb = 0;
	ret->next_proto_select_cb = 0;
#ifndef OPENSSL_NO_ENGINE
	ret->client_cert_engine = NULL;
#ifdef OPENSSL_SSL_CLIENT_ENGINE_AUTO
#define eng_strx(x)	#x
#define eng_str(x)	eng_strx(x)
	/* Use specific client engine automatically... ignore errors */
	{
		ENGINE *eng;
		eng = ENGINE_by_id(eng_str(OPENSSL_SSL_CLIENT_ENGINE_AUTO));
		if (!eng) {
			ERR_clear_error();
			ENGINE_load_builtin_engines();
			eng = ENGINE_by_id(eng_str(
			    OPENSSL_SSL_CLIENT_ENGINE_AUTO));
		}
		if (!eng || !SSL_CTX_set_client_cert_engine(ret, eng))
			ERR_clear_error();
	}
#endif
#endif
	/*
	 * Default is to connect to non-RI servers. When RI is more widely
	 * deployed might change this.
	 */
	ret->options |= SSL_OP_LEGACY_SERVER_CONNECT;

	return (ret);
err:
	SSLerr(SSL_F_SSL_CTX_NEW, ERR_R_MALLOC_FAILURE);
err2:
	SSL_CTX_free(ret);
	return (NULL);
}


int
SSL_CTX_use_certificate(SSL_CTX *ctx, X509 *x)
{
	if (x == NULL) {
		SSLerr(SSL_F_SSL_CTX_USE_CERTIFICATE, ERR_R_PASSED_NULL_PARAMETER);
		return (0);
	}
	if (!ssl_cert_inst(&ctx->cert)) {
		SSLerr(SSL_F_SSL_CTX_USE_CERTIFICATE, ERR_R_MALLOC_FAILURE);
		return (0);
	}
	return (ssl_set_cert(ctx->cert, x));
}
SSL_CTX_use_certificate_file(SSL_CTX *ctx, const char *file, int type)
{
	int j;
	BIO *in;
	int ret = 0;
	X509 *x = NULL;

	in = BIO_new(BIO_s_file_internal());
	if (in == NULL) {
		SSLerr(SSL_F_SSL_CTX_USE_CERTIFICATE_FILE, ERR_R_BUF_LIB);
		goto end;
	}

	if (BIO_read_filename(in, file) <= 0) {
		SSLerr(SSL_F_SSL_CTX_USE_CERTIFICATE_FILE, ERR_R_SYS_LIB);
		goto end;
	}
	if (type == SSL_FILETYPE_ASN1) {
		j = ERR_R_ASN1_LIB;
		x = d2i_X509_bio(in, NULL);
	} else if (type == SSL_FILETYPE_PEM) {
		j = ERR_R_PEM_LIB;
		x = PEM_read_bio_X509(in, NULL, ctx->default_passwd_callback,
		    ctx->default_passwd_callback_userdata);
	} else {
		SSLerr(SSL_F_SSL_CTX_USE_CERTIFICATE_FILE, SSL_R_BAD_SSL_FILETYPE);
		goto end;
	}

	if (x == NULL) {
		SSLerr(SSL_F_SSL_CTX_USE_CERTIFICATE_FILE, j);
		goto end;
	}

	ret = SSL_CTX_use_certificate(ctx, x);
end:
	X509_free(x);
	BIO_free(in);
	return (ret);
}
SSL_CTX_use_certificate_ASN1(SSL_CTX *ctx, int len, const unsigned char *d)
{
	X509 *x;
	int ret;

	x = d2i_X509(NULL, &d,(long)len);
	if (x == NULL) {
		SSLerr(SSL_F_SSL_CTX_USE_CERTIFICATE_ASN1, ERR_R_ASN1_LIB);
		return (0);
	}

	ret = SSL_CTX_use_certificate(ctx, x);
	X509_free(x);
	return (ret);
}
SSL_CTX_use_certificate_chain_file(SSL_CTX *ctx, const char *file)
{
	BIO *in;
	int ret = 0;

	in = BIO_new(BIO_s_file_internal());
	if (in == NULL) {
		SSLerr(SSL_F_SSL_CTX_USE_CERTIFICATE_CHAIN_FILE, ERR_R_BUF_LIB);
		goto end;
	}

	if (BIO_read_filename(in, file) <= 0) {
		SSLerr(SSL_F_SSL_CTX_USE_CERTIFICATE_CHAIN_FILE, ERR_R_SYS_LIB);
		goto end;
	}

	ret = ssl_ctx_use_certificate_chain_bio(ctx, in);

end:
	BIO_free(in);
	return (ret);
}
SSL_CTX_use_certificate_chain_mem(SSL_CTX *ctx, void *buf, int len)
{
	BIO *in;
	int ret = 0;

	in = BIO_new_mem_buf(buf, len);
	if (in == NULL) {
		SSLerr(SSL_F_SSL_CTX_USE_CERTIFICATE_CHAIN_FILE, ERR_R_BUF_LIB);
		goto end;
	}

	ret = ssl_ctx_use_certificate_chain_bio(ctx, in);

end:
	BIO_free(in);
	return (ret);
}


int
SSL_CTX_use_certificate_file(SSL_CTX *ctx, const char *file, int type)
{
	int j;
	BIO *in;
	int ret = 0;
	X509 *x = NULL;

	in = BIO_new(BIO_s_file_internal());
	if (in == NULL) {
		SSLerr(SSL_F_SSL_CTX_USE_CERTIFICATE_FILE, ERR_R_BUF_LIB);
		goto end;
	}

	if (BIO_read_filename(in, file) <= 0) {
		SSLerr(SSL_F_SSL_CTX_USE_CERTIFICATE_FILE, ERR_R_SYS_LIB);
		goto end;
	}
	if (type == SSL_FILETYPE_ASN1) {
		j = ERR_R_ASN1_LIB;
		x = d2i_X509_bio(in, NULL);
	} else if (type == SSL_FILETYPE_PEM) {
		j = ERR_R_PEM_LIB;
		x = PEM_read_bio_X509(in, NULL, ctx->default_passwd_callback,
		    ctx->default_passwd_callback_userdata);
	} else {
		SSLerr(SSL_F_SSL_CTX_USE_CERTIFICATE_FILE, SSL_R_BAD_SSL_FILETYPE);
		goto end;
	}

	if (x == NULL) {
		SSLerr(SSL_F_SSL_CTX_USE_CERTIFICATE_FILE, j);
		goto end;
	}

	ret = SSL_CTX_use_certificate(ctx, x);
end:
	X509_free(x);
	BIO_free(in);
	return (ret);
}


int
SSL_CTX_use_PrivateKey(SSL_CTX *ctx, EVP_PKEY *pkey)
{
	if (pkey == NULL) {
		SSLerr(SSL_F_SSL_CTX_USE_PRIVATEKEY,
		    ERR_R_PASSED_NULL_PARAMETER);
		return (0);
	}
	if (!ssl_cert_inst(&ctx->cert)) {
		SSLerr(SSL_F_SSL_CTX_USE_PRIVATEKEY, ERR_R_MALLOC_FAILURE);
		return (0);
	}
	return (ssl_set_pkey(ctx->cert, pkey));
}
SSL_CTX_use_PrivateKey_file(SSL_CTX *ctx, const char *file, int type)
{
	int j, ret = 0;
	BIO *in;
	EVP_PKEY *pkey = NULL;

	in = BIO_new(BIO_s_file_internal());
	if (in == NULL) {
		SSLerr(SSL_F_SSL_CTX_USE_PRIVATEKEY_FILE, ERR_R_BUF_LIB);
		goto end;
	}

	if (BIO_read_filename(in, file) <= 0) {
		SSLerr(SSL_F_SSL_CTX_USE_PRIVATEKEY_FILE, ERR_R_SYS_LIB);
		goto end;
	}
	if (type == SSL_FILETYPE_PEM) {
		j = ERR_R_PEM_LIB;
		pkey = PEM_read_bio_PrivateKey(in, NULL,
		    ctx->default_passwd_callback,
		    ctx->default_passwd_callback_userdata);
	} else if (type == SSL_FILETYPE_ASN1) {
		j = ERR_R_ASN1_LIB;
		pkey = d2i_PrivateKey_bio(in, NULL);
	} else {
		SSLerr(SSL_F_SSL_CTX_USE_PRIVATEKEY_FILE,
		    SSL_R_BAD_SSL_FILETYPE);
		goto end;
	}
	if (pkey == NULL) {
		SSLerr(SSL_F_SSL_CTX_USE_PRIVATEKEY_FILE, j);
		goto end;
	}
	ret = SSL_CTX_use_PrivateKey(ctx, pkey);
	EVP_PKEY_free(pkey);
end:
	BIO_free(in);
	return (ret);
}
SSL_CTX_use_PrivateKey_ASN1(int type, SSL_CTX *ctx, const unsigned char *d,
    long len)
{
	int ret;
	const unsigned char *p;
	EVP_PKEY *pkey;

	p = d;
	if ((pkey = d2i_PrivateKey(type, NULL, &p,(long)len)) == NULL) {
		SSLerr(SSL_F_SSL_CTX_USE_PRIVATEKEY_ASN1, ERR_R_ASN1_LIB);
		return (0);
	}

	ret = SSL_CTX_use_PrivateKey(ctx, pkey);
	EVP_PKEY_free(pkey);
	return (ret);
}


int
SSL_CTX_use_PrivateKey_file(SSL_CTX *ctx, const char *file, int type)
{
	int j, ret = 0;
	BIO *in;
	EVP_PKEY *pkey = NULL;

	in = BIO_new(BIO_s_file_internal());
	if (in == NULL) {
		SSLerr(SSL_F_SSL_CTX_USE_PRIVATEKEY_FILE, ERR_R_BUF_LIB);
		goto end;
	}

	if (BIO_read_filename(in, file) <= 0) {
		SSLerr(SSL_F_SSL_CTX_USE_PRIVATEKEY_FILE, ERR_R_SYS_LIB);
		goto end;
	}
	if (type == SSL_FILETYPE_PEM) {
		j = ERR_R_PEM_LIB;
		pkey = PEM_read_bio_PrivateKey(in, NULL,
		    ctx->default_passwd_callback,
		    ctx->default_passwd_callback_userdata);
	} else if (type == SSL_FILETYPE_ASN1) {
		j = ERR_R_ASN1_LIB;
		pkey = d2i_PrivateKey_bio(in, NULL);
	} else {
		SSLerr(SSL_F_SSL_CTX_USE_PRIVATEKEY_FILE,
		    SSL_R_BAD_SSL_FILETYPE);
		goto end;
	}
	if (pkey == NULL) {
		SSLerr(SSL_F_SSL_CTX_USE_PRIVATEKEY_FILE, j);
		goto end;
	}
	ret = SSL_CTX_use_PrivateKey(ctx, pkey);
	EVP_PKEY_free(pkey);
end:
	BIO_free(in);
	return (ret);
}


void
ssl_free_wbio_buffer(SSL *s)
{
	if (s == NULL)
		return;

	if (s->bbio == NULL)
		return;

	if (s->bbio == s->wbio) {
		/* remove buffering */
		s->wbio = BIO_pop(s->wbio);
	}
	BIO_free(s->bbio);
	s->bbio = NULL;
}


int
SSL_get_ex_data_X509_STORE_CTX_idx(void)
{
	static volatile int ssl_x509_store_ctx_idx = -1;
	int got_write_lock = 0;

	CRYPTO_r_lock(CRYPTO_LOCK_SSL_CTX);

	if (ssl_x509_store_ctx_idx < 0) {
		CRYPTO_r_unlock(CRYPTO_LOCK_SSL_CTX);
		CRYPTO_w_lock(CRYPTO_LOCK_SSL_CTX);
		got_write_lock = 1;

		if (ssl_x509_store_ctx_idx < 0) {
			ssl_x509_store_ctx_idx =
			    X509_STORE_CTX_get_ex_new_index(
				0, "SSL for verify callback", NULL, NULL, NULL);
		}
	}

	if (got_write_lock)
		CRYPTO_w_unlock(CRYPTO_LOCK_SSL_CTX);
	else
		CRYPTO_r_unlock(CRYPTO_LOCK_SSL_CTX);

	return ssl_x509_store_ctx_idx;
}


int
ssl_get_handshake_digest(int idx, long *mask, const EVP_MD **md)
{
	if (idx < 0 || idx >= SSL_MD_NUM_IDX) {
		return 0;
	}
	*mask = ssl_handshake_digest_flag[idx];
	if (*mask)
		*md = ssl_digest_methods[idx];
	else
		*md = NULL;
	return 1;
}


int
ssl_get_new_session(SSL *s, int session)
{
	unsigned int tmp;
	SSL_SESSION *ss = NULL;
	GEN_SESSION_CB cb = def_generate_session_id;

	/* This gets used by clients and servers. */

	if ((ss = SSL_SESSION_new()) == NULL)
		return (0);

	/* If the context has a default timeout, use it */
	if (s->session_ctx->session_timeout == 0)
		ss->timeout = SSL_get_default_timeout(s);
	else
		ss->timeout = s->session_ctx->session_timeout;

	if (s->session != NULL) {
		SSL_SESSION_free(s->session);
		s->session = NULL;
	}

	if (session) {
		switch (s->version) {
		case TLS1_VERSION:
		case TLS1_1_VERSION:
		case TLS1_2_VERSION:
		case DTLS1_VERSION:
			ss->ssl_version = s->version;
			ss->session_id_length = SSL3_SSL_SESSION_ID_LENGTH;
			break;
		default:
			SSLerr(SSL_F_SSL_GET_NEW_SESSION,
			    SSL_R_UNSUPPORTED_SSL_VERSION);
			SSL_SESSION_free(ss);
			return (0);
		}

		/* If RFC4507 ticket use empty session ID. */
		if (s->tlsext_ticket_expected) {
			ss->session_id_length = 0;
			goto sess_id_done;
		}

		/* Choose which callback will set the session ID. */
		CRYPTO_r_lock(CRYPTO_LOCK_SSL_CTX);
		if (s->generate_session_id)
			cb = s->generate_session_id;
		else if (s->session_ctx->generate_session_id)
			cb = s->session_ctx->generate_session_id;
		CRYPTO_r_unlock(CRYPTO_LOCK_SSL_CTX);

		/* Choose a session ID. */
		tmp = ss->session_id_length;
		if (!cb(s, ss->session_id, &tmp)) {
			/* The callback failed */
			SSLerr(SSL_F_SSL_GET_NEW_SESSION,
			SSL_R_SSL_SESSION_ID_CALLBACK_FAILED);
			SSL_SESSION_free(ss);
			return (0);
		}

		/*
		 * Don't allow the callback to set the session length to zero.
		 * nor set it higher than it was.
		 */
		if (!tmp || (tmp > ss->session_id_length)) {
			/* The callback set an illegal length */
			SSLerr(SSL_F_SSL_GET_NEW_SESSION,
			SSL_R_SSL_SESSION_ID_HAS_BAD_LENGTH);
			SSL_SESSION_free(ss);
			return (0);
		}
		ss->session_id_length = tmp;

		/* Finally, check for a conflict. */
		if (SSL_has_matching_session_id(s, ss->session_id,
			ss->session_id_length)) {
			SSLerr(SSL_F_SSL_GET_NEW_SESSION,
			SSL_R_SSL_SESSION_ID_CONFLICT);
			SSL_SESSION_free(ss);
			return (0);
		}

sess_id_done:
		if (s->tlsext_hostname) {
			ss->tlsext_hostname = strdup(s->tlsext_hostname);
			if (ss->tlsext_hostname == NULL) {
				SSLerr(SSL_F_SSL_GET_NEW_SESSION,
				    ERR_R_INTERNAL_ERROR);
				SSL_SESSION_free(ss);
				return 0;
			}
		}
	} else {
		ss->session_id_length = 0;
	}

	if (s->sid_ctx_length > sizeof ss->sid_ctx) {
		SSLerr(SSL_F_SSL_GET_NEW_SESSION, ERR_R_INTERNAL_ERROR);
		SSL_SESSION_free(ss);
		return 0;
	}

	memcpy(ss->sid_ctx, s->sid_ctx, s->sid_ctx_length);
	ss->sid_ctx_length = s->sid_ctx_length;
	s->session = ss;
	ss->ssl_version = s->version;
	ss->verify_result = X509_V_OK;

	return (1);
}


int
SSL_has_matching_session_id(const SSL *ssl, const unsigned char *id,
    unsigned int id_len)
{
	/*
	 * A quick examination of SSL_SESSION_hash and SSL_SESSION_cmp
	 * shows how we can "construct" a session to give us the desired
	 * check - ie. to find if there's a session in the hash table
	 * that would conflict with any new session built out of this
	 * id/id_len and the ssl_version in use by this SSL.
	 */
	SSL_SESSION r, *p;

	if (id_len > sizeof r.session_id)
		return (0);

	r.ssl_version = ssl->version;
	r.session_id_length = id_len;
	memcpy(r.session_id, id, id_len);

	CRYPTO_r_lock(CRYPTO_LOCK_SSL_CTX);
	p = lh_SSL_SESSION_retrieve(ssl->ctx->sessions, &r);
	CRYPTO_r_unlock(CRYPTO_LOCK_SSL_CTX);
	return (p != NULL);
}


int
SSL_library_init(void)
{

#ifndef OPENSSL_NO_DES
	EVP_add_cipher(EVP_des_cbc());
	EVP_add_cipher(EVP_des_ede3_cbc());
#endif
#ifndef OPENSSL_NO_IDEA
	EVP_add_cipher(EVP_idea_cbc());
#endif
#ifndef OPENSSL_NO_RC4
	EVP_add_cipher(EVP_rc4());
#if !defined(OPENSSL_NO_MD5) && (defined(__x86_64) || defined(__x86_64__))
	EVP_add_cipher(EVP_rc4_hmac_md5());
#endif
#endif
#ifndef OPENSSL_NO_RC2
	EVP_add_cipher(EVP_rc2_cbc());
	/* Not actually used for SSL/TLS but this makes PKCS#12 work
	 * if an application only calls SSL_library_init().
	 */
	EVP_add_cipher(EVP_rc2_40_cbc());
#endif
	EVP_add_cipher(EVP_aes_128_cbc());
	EVP_add_cipher(EVP_aes_192_cbc());
	EVP_add_cipher(EVP_aes_256_cbc());
	EVP_add_cipher(EVP_aes_128_gcm());
	EVP_add_cipher(EVP_aes_256_gcm());
	EVP_add_cipher(EVP_aes_128_cbc_hmac_sha1());
	EVP_add_cipher(EVP_aes_256_cbc_hmac_sha1());
#ifndef OPENSSL_NO_CAMELLIA
	EVP_add_cipher(EVP_camellia_128_cbc());
	EVP_add_cipher(EVP_camellia_256_cbc());
#endif
#ifndef OPENSSL_NO_GOST
	EVP_add_cipher(EVP_gost2814789_cfb64());
	EVP_add_cipher(EVP_gost2814789_cnt());
#endif

	EVP_add_digest(EVP_md5());
	EVP_add_digest_alias(SN_md5, "ssl2-md5");
	EVP_add_digest_alias(SN_md5, "ssl3-md5");
	EVP_add_digest(EVP_sha1()); /* RSA with sha1 */
	EVP_add_digest_alias(SN_sha1, "ssl3-sha1");
	EVP_add_digest_alias(SN_sha1WithRSAEncryption, SN_sha1WithRSA);
	EVP_add_digest(EVP_sha224());
	EVP_add_digest(EVP_sha256());
	EVP_add_digest(EVP_sha384());
	EVP_add_digest(EVP_sha512());
	EVP_add_digest(EVP_dss1()); /* DSA with sha1 */
	EVP_add_digest_alias(SN_dsaWithSHA1, SN_dsaWithSHA1_2);
	EVP_add_digest_alias(SN_dsaWithSHA1, "DSS1");
	EVP_add_digest_alias(SN_dsaWithSHA1, "dss1");
	EVP_add_digest(EVP_ecdsa());
#ifndef OPENSSL_NO_GOST
	EVP_add_digest(EVP_gostr341194());
	EVP_add_digest(EVP_gost2814789imit());
	EVP_add_digest(EVP_streebog256());
	EVP_add_digest(EVP_streebog512());
#endif
	/* initialize cipher/digest methods table */
	ssl_load_ciphers();

#ifdef OPENSSL_WITH_SGX
        if (sgxbridge_init() == -1) {
            fprintf(stderr, "sgxbridge_init() failed __%s__ -__ %s__ \n",
                __FILE__, __func__);
            return 0;
        }
#endif
	return (1);
}


void
ssl_load_ciphers(void)
{
	ssl_cipher_methods[SSL_ENC_DES_IDX] =
	    EVP_get_cipherbyname(SN_des_cbc);
	ssl_cipher_methods[SSL_ENC_3DES_IDX] =
	    EVP_get_cipherbyname(SN_des_ede3_cbc);
	ssl_cipher_methods[SSL_ENC_RC4_IDX] =
	    EVP_get_cipherbyname(SN_rc4);
#ifndef OPENSSL_NO_IDEA
	ssl_cipher_methods[SSL_ENC_IDEA_IDX] =
	    EVP_get_cipherbyname(SN_idea_cbc);
#else
	ssl_cipher_methods[SSL_ENC_IDEA_IDX] = NULL;
#endif
	ssl_cipher_methods[SSL_ENC_AES128_IDX] =
	    EVP_get_cipherbyname(SN_aes_128_cbc);
	ssl_cipher_methods[SSL_ENC_AES256_IDX] =
	    EVP_get_cipherbyname(SN_aes_256_cbc);
	ssl_cipher_methods[SSL_ENC_CAMELLIA128_IDX] =
	    EVP_get_cipherbyname(SN_camellia_128_cbc);
	ssl_cipher_methods[SSL_ENC_CAMELLIA256_IDX] =
	    EVP_get_cipherbyname(SN_camellia_256_cbc);
	ssl_cipher_methods[SSL_ENC_GOST89_IDX] =
	    EVP_get_cipherbyname(SN_gost89_cnt);

	ssl_cipher_methods[SSL_ENC_AES128GCM_IDX] =
	    EVP_get_cipherbyname(SN_aes_128_gcm);
	ssl_cipher_methods[SSL_ENC_AES256GCM_IDX] =
	    EVP_get_cipherbyname(SN_aes_256_gcm);

	ssl_digest_methods[SSL_MD_MD5_IDX] =
	    EVP_get_digestbyname(SN_md5);
	ssl_mac_secret_size[SSL_MD_MD5_IDX] =
	    EVP_MD_size(ssl_digest_methods[SSL_MD_MD5_IDX]);
	OPENSSL_assert(ssl_mac_secret_size[SSL_MD_MD5_IDX] >= 0);
	ssl_digest_methods[SSL_MD_SHA1_IDX] =
	    EVP_get_digestbyname(SN_sha1);
	ssl_mac_secret_size[SSL_MD_SHA1_IDX] =
	    EVP_MD_size(ssl_digest_methods[SSL_MD_SHA1_IDX]);
	OPENSSL_assert(ssl_mac_secret_size[SSL_MD_SHA1_IDX] >= 0);
	ssl_digest_methods[SSL_MD_GOST94_IDX] =
	    EVP_get_digestbyname(SN_id_GostR3411_94);
	if (ssl_digest_methods[SSL_MD_GOST94_IDX]) {
		ssl_mac_secret_size[SSL_MD_GOST94_IDX] =
		    EVP_MD_size(ssl_digest_methods[SSL_MD_GOST94_IDX]);
		OPENSSL_assert(ssl_mac_secret_size[SSL_MD_GOST94_IDX] >= 0);
	}
	ssl_digest_methods[SSL_MD_GOST89MAC_IDX] =
	    EVP_get_digestbyname(SN_id_Gost28147_89_MAC);
	if (ssl_mac_pkey_id[SSL_MD_GOST89MAC_IDX]) {
		ssl_mac_secret_size[SSL_MD_GOST89MAC_IDX] = 32;
	}

	ssl_digest_methods[SSL_MD_SHA256_IDX] =
	    EVP_get_digestbyname(SN_sha256);
	ssl_mac_secret_size[SSL_MD_SHA256_IDX] =
	    EVP_MD_size(ssl_digest_methods[SSL_MD_SHA256_IDX]);
	ssl_digest_methods[SSL_MD_SHA384_IDX] =
	    EVP_get_digestbyname(SN_sha384);
	ssl_mac_secret_size[SSL_MD_SHA384_IDX] =
	    EVP_MD_size(ssl_digest_methods[SSL_MD_SHA384_IDX]);
	ssl_digest_methods[SSL_MD_STREEBOG256_IDX] =
	    EVP_get_digestbyname(SN_id_tc26_gost3411_2012_256);
	ssl_mac_secret_size[SSL_MD_STREEBOG256_IDX] =
	    EVP_MD_size(ssl_digest_methods[SSL_MD_STREEBOG256_IDX]);
	ssl_digest_methods[SSL_MD_STREEBOG512_IDX] =
	    EVP_get_digestbyname(SN_id_tc26_gost3411_2012_512);
	ssl_mac_secret_size[SSL_MD_STREEBOG512_IDX] =
	    EVP_MD_size(ssl_digest_methods[SSL_MD_STREEBOG512_IDX]);
}


void
SSL_load_error_strings(void)
{
#ifndef OPENSSL_NO_ERR
	ERR_load_crypto_strings();
	ERR_load_SSL_strings();
#endif
}


SSL *
SSL_new(SSL_CTX *ctx)
{
	SSL	*s;

	if (ctx == NULL) {
		SSLerr(SSL_F_SSL_NEW, SSL_R_NULL_SSL_CTX);
		return (NULL);
	}
	if (ctx->method == NULL) {
		SSLerr(SSL_F_SSL_NEW, SSL_R_SSL_CTX_HAS_NO_DEFAULT_SSL_VERSION);
		return (NULL);
	}

	s = calloc(1, sizeof(SSL));
	if (s == NULL)
		goto err;


	s->options = ctx->options;
	s->mode = ctx->mode;
	s->max_cert_list = ctx->max_cert_list;

	if (ctx->cert != NULL) {
		/*
		 * Earlier library versions used to copy the pointer to
		 * the CERT, not its contents; only when setting new
		 * parameters for the per-SSL copy, ssl_cert_new would be
		 * called (and the direct reference to the per-SSL_CTX
		 * settings would be lost, but those still were indirectly
		 * accessed for various purposes, and for that reason they
		 * used to be known as s->ctx->default_cert).
		 * Now we don't look at the SSL_CTX's CERT after having
		 * duplicated it once.
		*/
		s->cert = ssl_cert_dup(ctx->cert);
		if (s->cert == NULL)
			goto err;
	} else
		s->cert=NULL; /* Cannot really happen (see SSL_CTX_new) */

	s->read_ahead = ctx->read_ahead;
	s->msg_callback = ctx->msg_callback;
	s->msg_callback_arg = ctx->msg_callback_arg;
	s->verify_mode = ctx->verify_mode;
	s->sid_ctx_length = ctx->sid_ctx_length;
	OPENSSL_assert(s->sid_ctx_length <= sizeof s->sid_ctx);
	memcpy(&s->sid_ctx, &ctx->sid_ctx, sizeof(s->sid_ctx));
	s->verify_callback = ctx->default_verify_callback;
	s->generate_session_id = ctx->generate_session_id;

	s->param = X509_VERIFY_PARAM_new();
	if (!s->param)
		goto err;
	X509_VERIFY_PARAM_inherit(s->param, ctx->param);
	s->quiet_shutdown = ctx->quiet_shutdown;
	s->max_send_fragment = ctx->max_send_fragment;

	CRYPTO_add(&ctx->references, 1, CRYPTO_LOCK_SSL_CTX);
	s->ctx = ctx;
	s->tlsext_debug_cb = 0;
	s->tlsext_debug_arg = NULL;
	s->tlsext_ticket_expected = 0;
	s->tlsext_status_type = -1;
	s->tlsext_status_expected = 0;
	s->tlsext_ocsp_ids = NULL;
	s->tlsext_ocsp_exts = NULL;
	s->tlsext_ocsp_resp = NULL;
	s->tlsext_ocsp_resplen = -1;
	CRYPTO_add(&ctx->references, 1, CRYPTO_LOCK_SSL_CTX);
	s->initial_ctx = ctx;
	s->next_proto_negotiated = NULL;

	if (s->ctx->alpn_client_proto_list != NULL) {
		s->alpn_client_proto_list =
		    malloc(s->ctx->alpn_client_proto_list_len);
		if (s->alpn_client_proto_list == NULL)
			goto err;
		memcpy(s->alpn_client_proto_list,
		    s->ctx->alpn_client_proto_list,
		    s->ctx->alpn_client_proto_list_len);
		s->alpn_client_proto_list_len =
		    s->ctx->alpn_client_proto_list_len;
	}

	s->verify_result = X509_V_OK;

	s->method = ctx->method;

	if (!s->method->ssl_new(s))
		goto err;

	s->references = 1;
	s->server = (ctx->method->ssl_accept == ssl_undefined_function) ? 0 : 1;

	SSL_clear(s);

	CRYPTO_new_ex_data(CRYPTO_EX_INDEX_SSL, s, &s->ex_data);

	return (s);

err:
	SSL_free(s);
	SSLerr(SSL_F_SSL_NEW, ERR_R_MALLOC_FAILURE);
	return (NULL);
}


static unsigned long
ssl_session_hash(const SSL_SESSION *a)
{
	unsigned long	l;

	l = (unsigned long)
	    ((unsigned int) a->session_id[0]     )|
	    ((unsigned int) a->session_id[1]<< 8L)|
	    ((unsigned long)a->session_id[2]<<16L)|
	    ((unsigned long)a->session_id[3]<<24L);
	return (l);
}


SSL_SESSION *
SSL_SESSION_new(void)
{
	SSL_SESSION *ss;

	ss = calloc(1, sizeof(SSL_SESSION));
	if (ss == NULL) {
		SSLerr(SSL_F_SSL_SESSION_NEW, ERR_R_MALLOC_FAILURE);
		return (0);
	}

	ss->verify_result = 1; /* avoid 0 (= X509_V_OK) just in case */
	ss->references = 1;
	ss->timeout=60*5+4; /* 5 minute timeout by default */
	ss->time = time(NULL);
	ss->prev = NULL;
	ss->next = NULL;
	ss->tlsext_hostname = NULL;

	ss->tlsext_ecpointformatlist_length = 0;
	ss->tlsext_ecpointformatlist = NULL;
	ss->tlsext_ellipticcurvelist_length = 0;
	ss->tlsext_ellipticcurvelist = NULL;

	CRYPTO_new_ex_data(CRYPTO_EX_INDEX_SSL_SESSION, ss, &ss->ex_data);

	return (ss);
}


static int
ssl_set_cert(CERT *c, X509 *x)
{
	EVP_PKEY *pkey;
	int i;

	pkey = X509_get_pubkey(x);
	if (pkey == NULL) {
		SSLerr(SSL_F_SSL_SET_CERT, SSL_R_X509_LIB);
		return (0);
	}

	i = ssl_cert_type(x, pkey);
	if (i < 0) {
		SSLerr(SSL_F_SSL_SET_CERT, SSL_R_UNKNOWN_CERTIFICATE_TYPE);
		EVP_PKEY_free(pkey);
		return (0);
	}

	if (c->pkeys[i].privatekey != NULL) {
		EVP_PKEY_copy_parameters(pkey, c->pkeys[i].privatekey);
		ERR_clear_error();

		/*
		 * Don't check the public/private key, this is mostly
		 * for smart cards.
		 */
		if ((c->pkeys[i].privatekey->type == EVP_PKEY_RSA) &&
			(RSA_flags(c->pkeys[i].privatekey->pkey.rsa) &
		RSA_METHOD_FLAG_NO_CHECK))
;
		else
		if (!X509_check_private_key(x, c->pkeys[i].privatekey)) {
			/*
			 * don't fail for a cert/key mismatch, just free
			 * current private key (when switching to a different
			 * cert & key, first this function should be used,
			 * then ssl_set_pkey
			 */
			EVP_PKEY_free(c->pkeys[i].privatekey);
			c->pkeys[i].privatekey = NULL;
			/* clear error queue */
			ERR_clear_error();
		}
	}

	EVP_PKEY_free(pkey);

	X509_free(c->pkeys[i].x509);
	CRYPTO_add(&x->references, 1, CRYPTO_LOCK_X509);
	c->pkeys[i].x509 = x;
	c->key = &(c->pkeys[i]);

	c->valid = 0;
	return (1);
}


static int
ssl_set_pkey(CERT *c, EVP_PKEY *pkey)
{
	int i;

	i = ssl_cert_type(NULL, pkey);
	if (i < 0) {
		SSLerr(SSL_F_SSL_SET_PKEY, SSL_R_UNKNOWN_CERTIFICATE_TYPE);
		return (0);
	}

	if (c->pkeys[i].x509 != NULL) {
		EVP_PKEY *pktmp;
		pktmp = X509_get_pubkey(c->pkeys[i].x509);
		EVP_PKEY_copy_parameters(pktmp, pkey);
		EVP_PKEY_free(pktmp);
		ERR_clear_error();

		/*
		 * Don't check the public/private key, this is mostly
		 * for smart cards.
		 */
		if ((pkey->type == EVP_PKEY_RSA) &&
			(RSA_flags(pkey->pkey.rsa) & RSA_METHOD_FLAG_NO_CHECK))
;
		else
		if (!X509_check_private_key(c->pkeys[i].x509, pkey)) {
			X509_free(c->pkeys[i].x509);
			c->pkeys[i].x509 = NULL;
			return 0;
		}
	}

	EVP_PKEY_free(c->pkeys[i].privatekey);
	CRYPTO_add(&pkey->references, 1, CRYPTO_LOCK_EVP_PKEY);
	c->pkeys[i].privatekey = pkey;
	c->key = &(c->pkeys[i]);

	c->valid = 0;
	return (1);
}


const SSL_METHOD *
SSLv23_method(void)
{
	return (TLS_method());
}


int
strcasecmp(const char *s1, const char *s2)
{
	const u_char *cm = charmap;
	const u_char *us1 = (const u_char *)s1;
	const u_char *us2 = (const u_char *)s2;

	while (cm[*us1] == cm[*us2++])
		if (*us1++ == '\0')
			return (0);
	return (cm[*us1] - cm[*--us2]);
}


size_t
strlcpy(char *dst, const char *src, size_t dsize)
{
	const char *osrc = src;
	size_t nleft = dsize;

	/* Copy as many bytes as will fit. */
	if (nleft != 0) {
		while (--nleft != 0) {
			if ((*dst++ = *src++) == '\0')
				break;
		}
	}

	/* Not enough room in dst, add NUL and traverse rest of src. */
	if (nleft == 0) {
		if (dsize != 0)
			*dst = '\0';		/* NUL-terminate dst */
		while (*src++)
			;
	}

	return(src - osrc - 1);	/* count does not include NUL */
}


int
strncasecmp(const char *s1, const char *s2, size_t n)
{
	if (n != 0) {
		const u_char *cm = charmap;
		const u_char *us1 = (const u_char *)s1;
		const u_char *us2 = (const u_char *)s2;

		do {
			if (cm[*us1] != cm[*us2++])
				return (cm[*us1] - cm[*--us2]);
			if (*us1++ == '\0')
				break;
		} while (--n != 0);
	}
	return (0);
}


int
timingsafe_memcmp(const void *b1, const void *b2, size_t len)
{
        const unsigned char *p1 = b1, *p2 = b2;
        size_t i;
        int res = 0, done = 0;

        for (i = 0; i < len; i++) {
                /* lt is -1 if p1[i] < p2[i]; else 0. */
                int lt = (p1[i] - p2[i]) >> CHAR_BIT;

                /* gt is -1 if p1[i] > p2[i]; else 0. */
                int gt = (p2[i] - p1[i]) >> CHAR_BIT;

                /* cmp is 1 if p1[i] > p2[i]; -1 if p1[i] < p2[i]; else 0. */
                int cmp = lt - gt;

                /* set res = cmp if !done. */
                res |= cmp & ~done;

                /* set done if p1[i] != p2[i]. */
                done |= lt | gt;
        }

        return (res);
}


static int
tls12_find_id(int nid, tls12_lookup *table, size_t tlen)
{
	size_t i;
	for (i = 0; i < tlen; i++) {
		if (table[i].nid == nid)
			return table[i].id;
	}
	return -1;
}


int
tls12_get_sigandhash(unsigned char *p, const EVP_PKEY *pk, const EVP_MD *md)
{
	int sig_id, md_id;
	if (!md)
		return 0;
	md_id = tls12_find_id(EVP_MD_type(md), tls12_md,
	    sizeof(tls12_md) / sizeof(tls12_lookup));
	if (md_id == -1)
		return 0;
	sig_id = tls12_get_sigid(pk);
	if (sig_id == -1)
		return 0;
	p[0] = (unsigned char)md_id;
	p[1] = (unsigned char)sig_id;
	return 1;
}


int
tls12_get_sigid(const EVP_PKEY *pk)
{
	return tls12_find_id(pk->type, tls12_sig,
	    sizeof(tls12_sig) / sizeof(tls12_lookup));
}


static int
tls1_aead_ctx_init(SSL_AEAD_CTX **aead_ctx)
{
	if (*aead_ctx != NULL) {
		EVP_AEAD_CTX_cleanup(&(*aead_ctx)->ctx);
		return (1);
	}

	*aead_ctx = malloc(sizeof(SSL_AEAD_CTX));
	if (*aead_ctx == NULL) {
		SSLerr(SSL_F_TLS1_AEAD_CTX_INIT, ERR_R_MALLOC_FAILURE);
		return (0);
	}

	return (1);
}


int
tls1_change_cipher_state_aead(SSL *s, char is_read, const unsigned char *key,
    unsigned key_len, const unsigned char *iv, unsigned iv_len)
{
#ifdef  OPENSSL_WITH_SGX
	debug_printf("tls1_change_cipher_state\n");
#endif
	const EVP_AEAD *aead = s->s3->tmp.new_aead;
	SSL_AEAD_CTX *aead_ctx;

	if (is_read) {
		if (!tls1_aead_ctx_init(&s->aead_read_ctx))
			return 0;
		aead_ctx = s->aead_read_ctx;
	} else {
		if (!tls1_aead_ctx_init(&s->aead_write_ctx))
			return 0;
		aead_ctx = s->aead_write_ctx;
	}

	if (!EVP_AEAD_CTX_init(&aead_ctx->ctx, aead, key, key_len,
	    EVP_AEAD_DEFAULT_TAG_LENGTH, NULL))
		return (0);
	if (iv_len > sizeof(aead_ctx->fixed_nonce)) {
		SSLerr(SSL_F_TLS1_CHANGE_CIPHER_STATE_AEAD,
		    ERR_R_INTERNAL_ERROR);
		return (0);
	}
	memcpy(aead_ctx->fixed_nonce, iv, iv_len);
	aead_ctx->fixed_nonce_len = iv_len;
	aead_ctx->variable_nonce_len = 8;  /* always the case, currently. */
	aead_ctx->variable_nonce_in_record =
	    (s->s3->tmp.new_cipher->algorithm2 &
	    SSL_CIPHER_ALGORITHM2_VARIABLE_NONCE_IN_RECORD) != 0;
	aead_ctx->xor_fixed_nonce =
	    s->s3->tmp.new_cipher->algorithm_enc == SSL_CHACHA20POLY1305;
	aead_ctx->tag_len = EVP_AEAD_max_overhead(aead);

	if (aead_ctx->xor_fixed_nonce) {
		if (aead_ctx->fixed_nonce_len != EVP_AEAD_nonce_length(aead) ||
		    aead_ctx->variable_nonce_len > EVP_AEAD_nonce_length(aead)) {
			SSLerr(SSL_F_TLS1_CHANGE_CIPHER_STATE_AEAD,
			    ERR_R_INTERNAL_ERROR);
			return (0);
		}
	} else {
		if (aead_ctx->variable_nonce_len + aead_ctx->fixed_nonce_len !=
		    EVP_AEAD_nonce_length(aead)) {
			SSLerr(SSL_F_TLS1_CHANGE_CIPHER_STATE_AEAD,
			    ERR_R_INTERNAL_ERROR);
			return (0);
		}
	}

	return (1);
}
tls1_change_cipher_state_cipher(SSL *s, char is_read, char use_client_keys,
    const unsigned char *mac_secret, unsigned int mac_secret_size,
    const unsigned char *key, unsigned int key_len, const unsigned char *iv,
    unsigned int iv_len)
{
	EVP_CIPHER_CTX *cipher_ctx;
	const EVP_CIPHER *cipher;
	EVP_MD_CTX *mac_ctx;
	const EVP_MD *mac;
	int mac_type;

	cipher = s->s3->tmp.new_sym_enc;
	mac = s->s3->tmp.new_hash;
	mac_type = s->s3->tmp.new_mac_pkey_type;

	if (is_read) {
		if (s->s3->tmp.new_cipher->algorithm2 & TLS1_STREAM_MAC)
			s->mac_flags |= SSL_MAC_FLAG_READ_MAC_STREAM;
		else
			s->mac_flags &= ~SSL_MAC_FLAG_READ_MAC_STREAM;

		EVP_CIPHER_CTX_free(s->enc_read_ctx);
		s->enc_read_ctx = NULL;
		EVP_MD_CTX_destroy(s->read_hash);
		s->read_hash = NULL;

		if ((cipher_ctx = EVP_CIPHER_CTX_new()) == NULL)
			goto err;
		s->enc_read_ctx = cipher_ctx;
		if ((mac_ctx = EVP_MD_CTX_create()) == NULL)
			goto err;
		s->read_hash = mac_ctx;
	} else {
		if (s->s3->tmp.new_cipher->algorithm2 & TLS1_STREAM_MAC)
			s->mac_flags |= SSL_MAC_FLAG_WRITE_MAC_STREAM;
		else
			s->mac_flags &= ~SSL_MAC_FLAG_WRITE_MAC_STREAM;

		/*
		 * DTLS fragments retain a pointer to the compression, cipher
		 * and hash contexts, so that it can restore state in order
		 * to perform retransmissions. As such, we cannot free write
		 * contexts that are used for DTLS - these are instead freed
		 * by DTLS when its frees a ChangeCipherSpec fragment.
		 */
		if (!SSL_IS_DTLS(s)) {
			EVP_CIPHER_CTX_free(s->enc_write_ctx);
			s->enc_write_ctx = NULL;
			EVP_MD_CTX_destroy(s->write_hash);
			s->write_hash = NULL;
		}
		if ((cipher_ctx = EVP_CIPHER_CTX_new()) == NULL)
			goto err;
		s->enc_write_ctx = cipher_ctx;
		if ((mac_ctx = EVP_MD_CTX_create()) == NULL)
			goto err;
		s->write_hash = mac_ctx;
	}

	if (EVP_CIPHER_mode(cipher) == EVP_CIPH_GCM_MODE) {
		EVP_CipherInit_ex(cipher_ctx, cipher, NULL, key, NULL,
		    !is_read);
		EVP_CIPHER_CTX_ctrl(cipher_ctx, EVP_CTRL_GCM_SET_IV_FIXED,
		    iv_len, (unsigned char *)iv);
	} else
		EVP_CipherInit_ex(cipher_ctx, cipher, NULL, key, iv, !is_read);

	if (!(EVP_CIPHER_flags(cipher) & EVP_CIPH_FLAG_AEAD_CIPHER)) {
		EVP_PKEY *mac_key = EVP_PKEY_new_mac_key(mac_type, NULL,
		    mac_secret, mac_secret_size);
		if (mac_key == NULL)
			goto err;
		EVP_DigestSignInit(mac_ctx, NULL, mac, NULL, mac_key);
		EVP_PKEY_free(mac_key);
	} else if (mac_secret_size > 0) {
		/* Needed for "composite" AEADs, such as RC4-HMAC-MD5 */
		EVP_CIPHER_CTX_ctrl(cipher_ctx, EVP_CTRL_AEAD_SET_MAC_KEY,
		    mac_secret_size, (unsigned char *)mac_secret);
	}

	if (s->s3->tmp.new_cipher->algorithm_enc == SSL_eGOST2814789CNT) {
		int nid;
		if (s->s3->tmp.new_cipher->algorithm2 & SSL_HANDSHAKE_MAC_GOST94)
			nid = NID_id_Gost28147_89_CryptoPro_A_ParamSet;
		else
			nid = NID_id_tc26_gost_28147_param_Z;

		EVP_CIPHER_CTX_ctrl(cipher_ctx, EVP_CTRL_GOST_SET_SBOX, nid, 0);
		if (s->s3->tmp.new_cipher->algorithm_mac == SSL_GOST89MAC)
			EVP_MD_CTX_ctrl(mac_ctx, EVP_MD_CTRL_GOST_SET_SBOX, nid, 0);
	}

	return (1);

err:
	SSLerr(SSL_F_TLS1_CHANGE_CIPHER_STATE_CIPHER, ERR_R_MALLOC_FAILURE);
	return (0);
}
tls1_change_cipher_state(SSL *s, int which)
{
	const unsigned char *client_write_mac_secret, *server_write_mac_secret;
	const unsigned char *client_write_key, *server_write_key;
	const unsigned char *client_write_iv, *server_write_iv;
	const unsigned char *mac_secret, *key, *iv;
	int mac_secret_size, key_len, iv_len;
	unsigned char *key_block, *seq;
	const EVP_CIPHER *cipher;
	const EVP_AEAD *aead;
	char is_read, use_client_keys;


	cipher = s->s3->tmp.new_sym_enc;
	aead = s->s3->tmp.new_aead;

	/*
	 * is_read is true if we have just read a ChangeCipherSpec message,
	 * that is we need to update the read cipherspec. Otherwise we have
	 * just written one.
	 */
	is_read = (which & SSL3_CC_READ) != 0;

	/*
	 * use_client_keys is true if we wish to use the keys for the "client
	 * write" direction. This is the case if we're a client sending a
	 * ChangeCipherSpec, or a server reading a client's ChangeCipherSpec.
	 */
	use_client_keys = ((which == SSL3_CHANGE_CIPHER_CLIENT_WRITE) ||
	    (which == SSL3_CHANGE_CIPHER_SERVER_READ));


	/*
	 * Reset sequence number to zero - for DTLS this is handled in
	 * dtls1_reset_seq_numbers().
	 */
	if (!SSL_IS_DTLS(s)) {
		seq = is_read ? s->s3->read_sequence : s->s3->write_sequence;
		memset(seq, 0, SSL3_SEQUENCE_SIZE);
	}

	if (aead != NULL) {
		key_len = EVP_AEAD_key_length(aead);
		iv_len = SSL_CIPHER_AEAD_FIXED_NONCE_LEN(s->s3->tmp.new_cipher);
	} else {
		key_len = EVP_CIPHER_key_length(cipher);
		iv_len = EVP_CIPHER_iv_length(cipher);

		/* If GCM mode only part of IV comes from PRF. */
		if (EVP_CIPHER_mode(cipher) == EVP_CIPH_GCM_MODE)
			iv_len = EVP_GCM_TLS_FIXED_IV_LEN;
	}

	mac_secret_size = s->s3->tmp.new_mac_secret_size;

	key_block = s->s3->tmp.key_block;
	client_write_mac_secret = key_block;
	key_block += mac_secret_size;
	server_write_mac_secret = key_block;
	key_block += mac_secret_size;
	client_write_key = key_block;
	key_block += key_len;
	server_write_key = key_block;
	key_block += key_len;
	client_write_iv = key_block;
	key_block += iv_len;
	server_write_iv = key_block;
	key_block += iv_len;

	if (use_client_keys) {
		mac_secret = client_write_mac_secret;
		key = client_write_key;
		iv = client_write_iv;
	} else {
		mac_secret = server_write_mac_secret;
		key = server_write_key;
		iv = server_write_iv;
	}

	if (key_block - s->s3->tmp.key_block != s->s3->tmp.key_block_length) {
		SSLerr(SSL_F_TLS1_CHANGE_CIPHER_STATE, ERR_R_INTERNAL_ERROR);
		goto err2;
	}

	if (is_read) {
		memcpy(s->s3->read_mac_secret, mac_secret, mac_secret_size);
		s->s3->read_mac_secret_size = mac_secret_size;
	} else {
		memcpy(s->s3->write_mac_secret, mac_secret, mac_secret_size);
		s->s3->write_mac_secret_size = mac_secret_size;
	}

	if (aead != NULL) {
		return tls1_change_cipher_state_aead(s, is_read, key, key_len,
		    iv, iv_len);
	}

	return tls1_change_cipher_state_cipher(s, is_read, use_client_keys,
	    mac_secret, mac_secret_size, key, key_len, iv, iv_len);

err2:
	return (0);
}


static int
tls1_change_cipher_state_aead(SSL *s, char is_read, const unsigned char *key,
    unsigned key_len, const unsigned char *iv, unsigned iv_len)
{
#ifdef  OPENSSL_WITH_SGX
	debug_printf("tls1_change_cipher_state\n");
#endif
	const EVP_AEAD *aead = s->s3->tmp.new_aead;
	SSL_AEAD_CTX *aead_ctx;

	if (is_read) {
		if (!tls1_aead_ctx_init(&s->aead_read_ctx))
			return 0;
		aead_ctx = s->aead_read_ctx;
	} else {
		if (!tls1_aead_ctx_init(&s->aead_write_ctx))
			return 0;
		aead_ctx = s->aead_write_ctx;
	}

	if (!EVP_AEAD_CTX_init(&aead_ctx->ctx, aead, key, key_len,
	    EVP_AEAD_DEFAULT_TAG_LENGTH, NULL))
		return (0);
	if (iv_len > sizeof(aead_ctx->fixed_nonce)) {
		SSLerr(SSL_F_TLS1_CHANGE_CIPHER_STATE_AEAD,
		    ERR_R_INTERNAL_ERROR);
		return (0);
	}
	memcpy(aead_ctx->fixed_nonce, iv, iv_len);
	aead_ctx->fixed_nonce_len = iv_len;
	aead_ctx->variable_nonce_len = 8;  /* always the case, currently. */
	aead_ctx->variable_nonce_in_record =
	    (s->s3->tmp.new_cipher->algorithm2 &
	    SSL_CIPHER_ALGORITHM2_VARIABLE_NONCE_IN_RECORD) != 0;
	aead_ctx->xor_fixed_nonce =
	    s->s3->tmp.new_cipher->algorithm_enc == SSL_CHACHA20POLY1305;
	aead_ctx->tag_len = EVP_AEAD_max_overhead(aead);

	if (aead_ctx->xor_fixed_nonce) {
		if (aead_ctx->fixed_nonce_len != EVP_AEAD_nonce_length(aead) ||
		    aead_ctx->variable_nonce_len > EVP_AEAD_nonce_length(aead)) {
			SSLerr(SSL_F_TLS1_CHANGE_CIPHER_STATE_AEAD,
			    ERR_R_INTERNAL_ERROR);
			return (0);
		}
	} else {
		if (aead_ctx->variable_nonce_len + aead_ctx->fixed_nonce_len !=
		    EVP_AEAD_nonce_length(aead)) {
			SSLerr(SSL_F_TLS1_CHANGE_CIPHER_STATE_AEAD,
			    ERR_R_INTERNAL_ERROR);
			return (0);
		}
	}

	return (1);
}


void
tls1_cleanup_key_block(SSL *s)
{
#ifdef  OPENSSL_WITH_SGX
	debug_printf("tls1_cleanup_key_block\n");
#endif
	if (s->s3->tmp.key_block != NULL) {
		explicit_bzero(s->s3->tmp.key_block,
		    s->s3->tmp.key_block_length);
		free(s->s3->tmp.key_block);
		s->s3->tmp.key_block = NULL;
	}
	s->s3->tmp.key_block_length = 0;
}


void
tls1_clear(SSL *s)
{
	ssl3_clear(s);
	s->version = s->method->version;
}


uint16_t
tls1_ec_nid2curve_id(int nid)
{
	/* ECC curves from draft-ietf-tls-ecc-12.txt (Oct. 17, 2005) */
	switch (nid) {
	case NID_sect163k1: /* sect163k1 (1) */
		return 1;
	case NID_sect163r1: /* sect163r1 (2) */
		return 2;
	case NID_sect163r2: /* sect163r2 (3) */
		return 3;
	case NID_sect193r1: /* sect193r1 (4) */
		return 4;
	case NID_sect193r2: /* sect193r2 (5) */
		return 5;
	case NID_sect233k1: /* sect233k1 (6) */
		return 6;
	case NID_sect233r1: /* sect233r1 (7) */
		return 7;
	case NID_sect239k1: /* sect239k1 (8) */
		return 8;
	case NID_sect283k1: /* sect283k1 (9) */
		return 9;
	case NID_sect283r1: /* sect283r1 (10) */
		return 10;
	case NID_sect409k1: /* sect409k1 (11) */
		return 11;
	case NID_sect409r1: /* sect409r1 (12) */
		return 12;
	case NID_sect571k1: /* sect571k1 (13) */
		return 13;
	case NID_sect571r1: /* sect571r1 (14) */
		return 14;
	case NID_secp160k1: /* secp160k1 (15) */
		return 15;
	case NID_secp160r1: /* secp160r1 (16) */
		return 16;
	case NID_secp160r2: /* secp160r2 (17) */
		return 17;
	case NID_secp192k1: /* secp192k1 (18) */
		return 18;
	case NID_X9_62_prime192v1: /* secp192r1 (19) */
		return 19;
	case NID_secp224k1: /* secp224k1 (20) */
		return 20;
	case NID_secp224r1: /* secp224r1 (21) */
		return 21;
	case NID_secp256k1: /* secp256k1 (22) */
		return 22;
	case NID_X9_62_prime256v1: /* secp256r1 (23) */
		return 23;
	case NID_secp384r1: /* secp384r1 (24) */
		return 24;
	case NID_secp521r1: /* secp521r1 (25) */
		return 25;
	case NID_brainpoolP256r1: /* brainpoolP256r1 (26) */
		return 26;
	case NID_brainpoolP384r1: /* brainpoolP384r1 (27) */
		return 27;
	case NID_brainpoolP512r1: /* brainpoolP512r1 (28) */
		return 28;
	default:
		return 0;
	}
}


void
tls1_free_digest_list(SSL *s)
{
	int i;

	if (s == NULL)
		return;

	if (s->s3->handshake_dgst == NULL)
		return;
	for (i = 0; i < SSL_MAX_DIGEST; i++) {
		if (s->s3->handshake_dgst[i])
			EVP_MD_CTX_destroy(s->s3->handshake_dgst[i]);
	}
	free(s->s3->handshake_dgst);
	s->s3->handshake_dgst = NULL;
}


int
tls1_new(SSL *s)
{
	if (!ssl3_new(s))
		return (0);
	s->method->ssl_clear(s);
	return (1);
}


static int
tls1_P_hash(const EVP_MD *md, const unsigned char *sec, int sec_len,
    const void *seed1, int seed1_len, const void *seed2, int seed2_len,
    const void *seed3, int seed3_len, const void *seed4, int seed4_len,
    const void *seed5, int seed5_len, unsigned char *out, int olen)
{
	int chunk;
	size_t j;
	EVP_MD_CTX ctx, ctx_tmp;
	EVP_PKEY *mac_key;
	unsigned char A1[EVP_MAX_MD_SIZE];
	size_t A1_len;
	int ret = 0;

	chunk = EVP_MD_size(md);
	OPENSSL_assert(chunk >= 0);

	EVP_MD_CTX_init(&ctx);
	EVP_MD_CTX_init(&ctx_tmp);
	mac_key = EVP_PKEY_new_mac_key(EVP_PKEY_HMAC, NULL, sec, sec_len);
	if (!mac_key)
		goto err;
	if (!EVP_DigestSignInit(&ctx, NULL, md, NULL, mac_key))
		goto err;
	if (!EVP_DigestSignInit(&ctx_tmp, NULL, md, NULL, mac_key))
		goto err;
	if (seed1 && !EVP_DigestSignUpdate(&ctx, seed1, seed1_len))
		goto err;
	if (seed2 && !EVP_DigestSignUpdate(&ctx, seed2, seed2_len))
		goto err;
	if (seed3 && !EVP_DigestSignUpdate(&ctx, seed3, seed3_len))
		goto err;
	if (seed4 && !EVP_DigestSignUpdate(&ctx, seed4, seed4_len))
		goto err;
	if (seed5 && !EVP_DigestSignUpdate(&ctx, seed5, seed5_len))
		goto err;
	if (!EVP_DigestSignFinal(&ctx, A1, &A1_len))
		goto err;

	for (;;) {
		/* Reinit mac contexts */
		if (!EVP_DigestSignInit(&ctx, NULL, md, NULL, mac_key))
			goto err;
		if (!EVP_DigestSignInit(&ctx_tmp, NULL, md, NULL, mac_key))
			goto err;
		if (!EVP_DigestSignUpdate(&ctx, A1, A1_len))
			goto err;
		if (!EVP_DigestSignUpdate(&ctx_tmp, A1, A1_len))
			goto err;
		if (seed1 && !EVP_DigestSignUpdate(&ctx, seed1, seed1_len))
			goto err;
		if (seed2 && !EVP_DigestSignUpdate(&ctx, seed2, seed2_len))
			goto err;
		if (seed3 && !EVP_DigestSignUpdate(&ctx, seed3, seed3_len))
			goto err;
		if (seed4 && !EVP_DigestSignUpdate(&ctx, seed4, seed4_len))
			goto err;
		if (seed5 && !EVP_DigestSignUpdate(&ctx, seed5, seed5_len))
			goto err;

		if (olen > chunk) {
			if (!EVP_DigestSignFinal(&ctx, out, &j))
				goto err;
			out += j;
			olen -= j;
			/* calc the next A1 value */
			if (!EVP_DigestSignFinal(&ctx_tmp, A1, &A1_len))
				goto err;
		} else {
			/* last one */
			if (!EVP_DigestSignFinal(&ctx, A1, &A1_len))
				goto err;
			memcpy(out, A1, olen);
			break;
		}
	}
	ret = 1;

err:
	EVP_PKEY_free(mac_key);
	EVP_MD_CTX_cleanup(&ctx);
	EVP_MD_CTX_cleanup(&ctx_tmp);
	explicit_bzero(A1, sizeof(A1));
	return ret;
}


int
tls1_PRF(long digest_mask, const void *seed1, int seed1_len, const void *seed2,
    int seed2_len, const void *seed3, int seed3_len, const void *seed4,
    int seed4_len, const void *seed5, int seed5_len, const unsigned char *sec,
    int slen, unsigned char *out1, unsigned char *out2, int olen)
{
	int len, i, idx, count;
	const unsigned char *S1;
	long m;
	const EVP_MD *md;
	int ret = 0;

	/* Count number of digests and partition sec evenly */
	count = 0;
	for (idx = 0; ssl_get_handshake_digest(idx, &m, &md); idx++) {
		if ((m << TLS1_PRF_DGST_SHIFT) & digest_mask)
			count++;
	}
	if (count == 0) {
		SSLerr(SSL_F_TLS1_PRF,
		    SSL_R_SSL_HANDSHAKE_FAILURE);
		goto err;
	}
	len = slen / count;
	if (count == 1)
		slen = 0;
	S1 = sec;
	memset(out1, 0, olen);
	for (idx = 0; ssl_get_handshake_digest(idx, &m, &md); idx++) {
		if ((m << TLS1_PRF_DGST_SHIFT) & digest_mask) {
			if (!md) {
				SSLerr(SSL_F_TLS1_PRF,
				    SSL_R_UNSUPPORTED_DIGEST_TYPE);
				goto err;
			}
			if (!tls1_P_hash(md , S1, len + (slen&1), seed1,
			    seed1_len, seed2, seed2_len, seed3, seed3_len,
			    seed4, seed4_len, seed5, seed5_len, out2, olen))
				goto err;
			S1 += len;
			for (i = 0; i < olen; i++) {
				out1[i] ^= out2[i];
			}
		}
	}
	ret = 1;

err:
	return ret;
}


const SSL_METHOD *
TLS_method(void)
{
	return &TLS_method_data;
}


static int
traverse_string(const unsigned char *p, int len, int inform,
    int (*rfunc)(unsigned long value, void *in), void *arg)
{
	unsigned long value;
	int ret;

	while (len) {
		switch (inform) {
		case MBSTRING_ASC:
			value = *p++;
			len--;
			break;
		case MBSTRING_BMP:
			value = *p++ << 8;
			value |= *p++;
			/* BMP is explictly defined to not support surrogates */
			if (UNICODE_IS_SURROGATE(value))
				return -1;
			len -= 2;
			break;
		case MBSTRING_UNIV:
			value = (unsigned long)*p++ << 24;
			value |= *p++ << 16;
			value |= *p++ << 8;
			value |= *p++;
			if (value > UNICODE_MAX || UNICODE_IS_SURROGATE(value))
				return -1;
			len -= 4;
			break;
		default:
			ret = UTF8_getc(p, len, &value);
			if (ret < 0)
				return -1;
			len -= ret;
			p += ret;
			break;
		}
		if (rfunc) {
			ret = rfunc(value, arg);
			if (ret <= 0)
				return ret;
		}
	}
	return 1;
}


static int
type_str(unsigned long value, void *arg)
{
	unsigned long types;

	types = *((unsigned long *)arg);
	if ((types & B_ASN1_PRINTABLESTRING) && !is_printable(value))
		types &= ~B_ASN1_PRINTABLESTRING;
	if ((types & B_ASN1_IA5STRING) && (value > 127))
		types &= ~B_ASN1_IA5STRING;
	if ((types & B_ASN1_T61STRING) && (value > 0xff))
		types &= ~B_ASN1_T61STRING;
	if ((types & B_ASN1_BMPSTRING) && (value > 0xffff))
		types &= ~B_ASN1_BMPSTRING;
	if (!types)
		return -1;
	*((unsigned long *)arg) = types;
	return 1;
}


static int
update512(EVP_MD_CTX *ctx, const void *data, size_t count)
{
	return SHA512_Update(ctx->md_data, data, count);
}


int
UTF8_getc(const unsigned char *str, int len, unsigned long *val)
{
	const unsigned char *p;
	unsigned long value;
	int ret;
	if (len <= 0)
		return 0;
	p = str;

	/* Check syntax and work out the encoded value (if correct) */
	if ((*p & 0x80) == 0) {
		value = *p++ & 0x7f;
		ret = 1;
	} else if ((*p & 0xe0) == 0xc0) {
		if (*p < 0xc2)
			return -2;
		if (len < 2)
			return -1;
		if ((p[1] & 0xc0) != 0x80)
			return -3;
		value = (*p++ & 0x1f) << 6;
		value |= *p++ & 0x3f;
		if (value < 0x80)
			return -4;
		ret = 2;
	} else if ((*p & 0xf0) == 0xe0) {
		if (len < 3)
			return -1;
		if (((p[1] & 0xc0) != 0x80) ||
		    ((p[2] & 0xc0) != 0x80))
			return -3;
		value = (*p++ & 0xf) << 12;
		value |= (*p++ & 0x3f) << 6;
		value |= *p++ & 0x3f;
		if (value < 0x800)
			return -4;
		/* surrogate pair code points are not valid */
		if (value >= 0xd800 && value < 0xe000)
			return -2;
		ret = 3;
	} else if ((*p & 0xf8) == 0xf0 && (*p < 0xf5)) {
		if (len < 4)
			return -1;
		if (((p[1] & 0xc0) != 0x80) ||
		    ((p[2] & 0xc0) != 0x80) ||
		    ((p[3] & 0xc0) != 0x80))
			return -3;
		value = ((unsigned long)(*p++ & 0x7)) << 18;
		value |= (*p++ & 0x3f) << 12;
		value |= (*p++ & 0x3f) << 6;
		value |= *p++ & 0x3f;
		if (value < 0x10000)
			return -4;
		if (value > UNICODE_MAX)
			return -2;
		ret = 4;
	} else
		return -2;
	*val = value;
	return ret;
}


int
UTF8_putc(unsigned char *str, int len, unsigned long value)
{
	if (value < 0x80) {
		if (str != NULL) {
			if (len < 1)
				return -1;
			str[0] = (unsigned char)value;
		}
		return 1;
	}
	if (value < 0x800) {
		if (str != NULL) {
			if (len < 2)
				return -1;
			str[0] = (unsigned char)(((value >> 6) & 0x1f) | 0xc0);
			str[1] = (unsigned char)((value & 0x3f) | 0x80);
		}
		return 2;
	}
	if (value < 0x10000) {
		if (UNICODE_IS_SURROGATE(value))
			return -2;
		if (str != NULL) {
			if (len < 3)
				return -1;
			str[0] = (unsigned char)(((value >> 12) & 0xf) | 0xe0);
			str[1] = (unsigned char)(((value >> 6) & 0x3f) | 0x80);
			str[2] = (unsigned char)((value & 0x3f) | 0x80);
		}
		return 3;
	}
	if (value <= UNICODE_MAX) {
		if (str != NULL) {
			if (len < 4)
				return -1;
			str[0] = (unsigned char)(((value >> 18) & 0x7) | 0xf0);
			str[1] = (unsigned char)(((value >> 12) & 0x3f) | 0x80);
			str[2] = (unsigned char)(((value >> 6) & 0x3f) | 0x80);
			str[3] = (unsigned char)((value & 0x3f) | 0x80);
		}
		return 4;
	}
	return -2;
}


static int
x509_cb(int operation, ASN1_VALUE **pval, const ASN1_ITEM *it, void *exarg)
{
	X509 *ret = (X509 *)*pval;

	switch (operation) {

	case ASN1_OP_NEW_POST:
		ret->valid = 0;
		ret->name = NULL;
		ret->ex_flags = 0;
		ret->ex_pathlen = -1;
		ret->skid = NULL;
		ret->akid = NULL;
		ret->aux = NULL;
		ret->crldp = NULL;
		CRYPTO_new_ex_data(CRYPTO_EX_INDEX_X509, ret, &ret->ex_data);
		break;

	case ASN1_OP_D2I_POST:
		free(ret->name);
		ret->name = X509_NAME_oneline(ret->cert_info->subject, NULL, 0);
		break;

	case ASN1_OP_FREE_POST:
		CRYPTO_free_ex_data(CRYPTO_EX_INDEX_X509, ret, &ret->ex_data);
		X509_CERT_AUX_free(ret->aux);
		ASN1_OCTET_STRING_free(ret->skid);
		AUTHORITY_KEYID_free(ret->akid);
		CRL_DIST_POINTS_free(ret->crldp);
		policy_cache_free(ret->policy_cache);
		GENERAL_NAMES_free(ret->altname);
		NAME_CONSTRAINTS_free(ret->nc);
		free(ret->name);
		ret->name = NULL;
		break;
	}

	return 1;
}


int
X509_check_private_key(X509 *x, EVP_PKEY *k)
{
	EVP_PKEY *xk;
	int ret;

	xk = X509_get_pubkey(x);

	if (xk)
		ret = EVP_PKEY_cmp(xk, k);
	else
		ret = -2;

	switch (ret) {
	case 1:
		break;
	case 0:
		X509err(X509_F_X509_CHECK_PRIVATE_KEY,
		    X509_R_KEY_VALUES_MISMATCH);
		break;
	case -1:
		X509err(X509_F_X509_CHECK_PRIVATE_KEY,
		    X509_R_KEY_TYPE_MISMATCH);
		break;
	case -2:
		X509err(X509_F_X509_CHECK_PRIVATE_KEY,
		    X509_R_UNKNOWN_KEY_TYPE);
	}
	EVP_PKEY_free(xk);
	if (ret > 0)
		return 1;
	return 0;
}


void
X509_free(X509 *a)
{
	ASN1_item_free((ASN1_VALUE *)a, &X509_it);
}


EVP_PKEY *
X509_get_pubkey(X509 *x)
{
	if ((x == NULL) || (x->cert_info == NULL))
		return (NULL);
	return (X509_PUBKEY_get(x->cert_info->key));
}


static int
x509_name_canon(X509_NAME *a)
{
	unsigned char *p;
	STACK_OF(STACK_OF_X509_NAME_ENTRY) *intname = NULL;
	STACK_OF(X509_NAME_ENTRY) *entries = NULL;
	X509_NAME_ENTRY *entry, *tmpentry = NULL;
	int i, len, set = -1, ret = 0;

	if (a->canon_enc) {
		free(a->canon_enc);
		a->canon_enc = NULL;
	}
	/* Special case: empty X509_NAME => null encoding */
	if (sk_X509_NAME_ENTRY_num(a->entries) == 0) {
		a->canon_enclen = 0;
		return 1;
	}
	intname = sk_STACK_OF_X509_NAME_ENTRY_new_null();
	if (!intname)
		goto err;
	for (i = 0; i < sk_X509_NAME_ENTRY_num(a->entries); i++) {
		entry = sk_X509_NAME_ENTRY_value(a->entries, i);
		if (entry->set != set) {
			entries = sk_X509_NAME_ENTRY_new_null();
			if (!entries)
				goto err;
			if (sk_STACK_OF_X509_NAME_ENTRY_push(intname,
			    entries) == 0) {
				sk_X509_NAME_ENTRY_free(entries);
				goto err;
			}
			set = entry->set;
		}
		tmpentry = X509_NAME_ENTRY_new();
		if (tmpentry == NULL)
			goto err;
		tmpentry->object = OBJ_dup(entry->object);
		if (tmpentry->object == NULL)
			goto err;
		if (!asn1_string_canon(tmpentry->value, entry->value))
			goto err;
		if (entries == NULL /* if entry->set is bogusly -1 */ ||
		    !sk_X509_NAME_ENTRY_push(entries, tmpentry))
			goto err;
		tmpentry = NULL;
	}

	/* Finally generate encoding */
	len = i2d_name_canon(intname, NULL);
	if (len < 0)
		goto err;
	p = malloc(len);
	if (p == NULL)
		goto err;
	a->canon_enc = p;
	a->canon_enclen = len;
	i2d_name_canon(intname, &p);
	ret = 1;

err:
	if (tmpentry)
		X509_NAME_ENTRY_free(tmpentry);
	if (intname)
		sk_STACK_OF_X509_NAME_ENTRY_pop_free(intname,
		    local_sk_X509_NAME_ENTRY_pop_free);
	return ret;
}


void
X509_NAME_ENTRY_free(X509_NAME_ENTRY *a)
{
	ASN1_item_free((ASN1_VALUE *)a, &X509_NAME_ENTRY_it);
}


X509_NAME_ENTRY *
X509_NAME_ENTRY_new(void)
{
	return (X509_NAME_ENTRY *)ASN1_item_new(&X509_NAME_ENTRY_it);
}


static int
x509_name_ex_d2i(ASN1_VALUE **val, const unsigned char **in, long len,
    const ASN1_ITEM *it, int tag, int aclass, char opt, ASN1_TLC *ctx)
{
	const unsigned char *p = *in, *q;
	union {
		STACK_OF(STACK_OF_X509_NAME_ENTRY) *s;
		ASN1_VALUE *a;
	} intname = {NULL};
	union {
		X509_NAME *x;
		ASN1_VALUE *a;
	} nm = {NULL};
	int i, j, ret;
	STACK_OF(X509_NAME_ENTRY) *entries;
	X509_NAME_ENTRY *entry;
	q = p;

	/* Get internal representation of Name */
	ret = ASN1_item_ex_d2i(&intname.a, &p, len,
	    ASN1_ITEM_rptr(X509_NAME_INTERNAL), tag, aclass, opt, ctx);

	if (ret <= 0)
		return ret;

	if (*val)
		x509_name_ex_free(val, NULL);
	if (!x509_name_ex_new(&nm.a, NULL))
		goto err;
	/* We've decoded it: now cache encoding */
	if (!BUF_MEM_grow(nm.x->bytes, p - q))
		goto err;
	memcpy(nm.x->bytes->data, q, p - q);

	/* Convert internal representation to X509_NAME structure */
	for (i = 0; i < sk_STACK_OF_X509_NAME_ENTRY_num(intname.s); i++) {
		entries = sk_STACK_OF_X509_NAME_ENTRY_value(intname.s, i);
		for (j = 0; j < sk_X509_NAME_ENTRY_num(entries); j++) {
			entry = sk_X509_NAME_ENTRY_value(entries, j);
			entry->set = i;
			if (!sk_X509_NAME_ENTRY_push(nm.x->entries, entry))
				goto err;
		}
		sk_X509_NAME_ENTRY_free(entries);
	}
	sk_STACK_OF_X509_NAME_ENTRY_free(intname.s);
	ret = x509_name_canon(nm.x);
	if (!ret)
		goto err;
	nm.x->modified = 0;
	*val = nm.a;
	*in = p;
	return ret;

err:
	if (nm.x != NULL)
		X509_NAME_free(nm.x);
	ASN1err(ASN1_F_X509_NAME_EX_D2I, ERR_R_NESTED_ASN1_ERROR);
	return 0;
}


static void
x509_name_ex_free(ASN1_VALUE **pval, const ASN1_ITEM *it)
{
	X509_NAME *a;

	if (!pval || !*pval)
		return;
	a = (X509_NAME *)*pval;

	BUF_MEM_free(a->bytes);
	sk_X509_NAME_ENTRY_pop_free(a->entries, X509_NAME_ENTRY_free);
	free(a->canon_enc);
	free(a);
	*pval = NULL;
}


static int
x509_name_ex_new(ASN1_VALUE **val, const ASN1_ITEM *it)
{
	X509_NAME *ret = NULL;

	ret = malloc(sizeof(X509_NAME));
	if (!ret)
		goto memerr;
	if ((ret->entries = sk_X509_NAME_ENTRY_new_null()) == NULL)
		goto memerr;
	if ((ret->bytes = BUF_MEM_new()) == NULL)
		goto memerr;
	ret->canon_enc = NULL;
	ret->canon_enclen = 0;
	ret->modified = 1;
	*val = (ASN1_VALUE *)ret;
	return 1;

memerr:
	ASN1err(ASN1_F_X509_NAME_EX_NEW, ERR_R_MALLOC_FAILURE);
	if (ret) {
		if (ret->entries)
			sk_X509_NAME_ENTRY_free(ret->entries);
		free(ret);
	}
	return 0;
}


char *
X509_NAME_oneline(X509_NAME *a, char *buf, int len)
{
	X509_NAME_ENTRY *ne;
	int i;
	int n, lold, l, l1, l2, num, j, type;
	const char *s;
	char *p;
	unsigned char *q;
	BUF_MEM *b = NULL;
	static const char hex[17] = "0123456789ABCDEF";
	int gs_doit[4];
	char tmp_buf[80];

	if (buf == NULL) {
		if ((b = BUF_MEM_new()) == NULL)
			goto err;
		if (!BUF_MEM_grow(b, 200))
			goto err;
		b->data[0] = '\0';
		len = 200;
	}
	if (a == NULL) {
		if (b) {
			buf = b->data;
			free(b);
		}
		strlcpy(buf, "NO X509_NAME", len);
		return buf;
	}

	len--; /* space for '\0' */
	l = 0;
	for (i = 0; i < sk_X509_NAME_ENTRY_num(a->entries); i++) {
		ne = sk_X509_NAME_ENTRY_value(a->entries, i);
		n = OBJ_obj2nid(ne->object);
		if ((n == NID_undef) || ((s = OBJ_nid2sn(n)) == NULL)) {
			i2t_ASN1_OBJECT(tmp_buf, sizeof(tmp_buf), ne->object);
			s = tmp_buf;
		}
		l1 = strlen(s);

		type = ne->value->type;
		num = ne->value->length;
		q = ne->value->data;
		if ((type == V_ASN1_GENERALSTRING) && ((num % 4) == 0)) {
			gs_doit[0] = gs_doit[1] = gs_doit[2] = gs_doit[3] = 0;
			for (j = 0; j < num; j++)
				if (q[j] != 0)
					gs_doit[j & 3] = 1;

			if (gs_doit[0]|gs_doit[1]|gs_doit[2])
				gs_doit[0] = gs_doit[1] = gs_doit[2] = gs_doit[3] = 1;
			else {
				gs_doit[0] = gs_doit[1] = gs_doit[2] = 0;
				gs_doit[3] = 1;
			}
		} else
			gs_doit[0] = gs_doit[1] = gs_doit[2] = gs_doit[3] = 1;

		for (l2 = j=0; j < num; j++) {
			if (!gs_doit[j&3])
				continue;
			l2++;
			if ((q[j] < ' ') || (q[j] > '~'))
				l2 += 3;
		}

		lold = l;
		l += 1 + l1 + 1 + l2;
		if (b != NULL) {
			if (!BUF_MEM_grow(b, l + 1))
				goto err;
			p = &(b->data[lold]);
		} else if (l > len) {
			break;
		} else
			p = &(buf[lold]);
		*(p++) = '/';
		memcpy(p, s, l1);
		p += l1;
		*(p++) = '=';
		q = ne->value->data;
		for (j = 0; j < num; j++) {
			if (!gs_doit[j & 3])
				continue;
			n = q[j];
			if ((n < ' ') || (n > '~')) {
				*(p++) = '\\';
				*(p++) = 'x';
				*(p++) = hex[(n >> 4) & 0x0f];
				*(p++) = hex[n & 0x0f];
			} else
				*(p++) = n;
		}
		*p = '\0';
	}
	if (b != NULL) {
		p = b->data;
		free(b);
	} else
		p = buf;
	if (i == 0)
		*p = '\0';
	return (p);

err:
	X509err(X509_F_X509_NAME_ONELINE, ERR_R_MALLOC_FAILURE);
	if (b != NULL)
		BUF_MEM_free(b);
	return (NULL);
}


EVP_PKEY *
X509_PUBKEY_get(X509_PUBKEY *key)
{
	EVP_PKEY *ret = NULL;

	if (key == NULL)
		goto error;

	if (key->pkey != NULL) {
		CRYPTO_add(&key->pkey->references, 1, CRYPTO_LOCK_EVP_PKEY);
		return key->pkey;
	}

	if (key->public_key == NULL)
		goto error;

	if ((ret = EVP_PKEY_new()) == NULL) {
		X509err(X509_F_X509_PUBKEY_GET, ERR_R_MALLOC_FAILURE);
		goto error;
	}

	if (!EVP_PKEY_set_type(ret, OBJ_obj2nid(key->algor->algorithm))) {
		X509err(X509_F_X509_PUBKEY_GET, X509_R_UNSUPPORTED_ALGORITHM);
		goto error;
	}

	if (ret->ameth->pub_decode) {
		if (!ret->ameth->pub_decode(ret, key)) {
			X509err(X509_F_X509_PUBKEY_GET,
			    X509_R_PUBLIC_KEY_DECODE_ERROR);
			goto error;
		}
	} else {
		X509err(X509_F_X509_PUBKEY_GET, X509_R_METHOD_NOT_SUPPORTED);
		goto error;
	}

	/* Check to see if another thread set key->pkey first */
	CRYPTO_w_lock(CRYPTO_LOCK_EVP_PKEY);
	if (key->pkey) {
		CRYPTO_w_unlock(CRYPTO_LOCK_EVP_PKEY);
		EVP_PKEY_free(ret);
		ret = key->pkey;
	} else {
		key->pkey = ret;
		CRYPTO_w_unlock(CRYPTO_LOCK_EVP_PKEY);
	}
	CRYPTO_add(&ret->references, 1, CRYPTO_LOCK_EVP_PKEY);

	return ret;

error:
	EVP_PKEY_free(ret);
	return (NULL);
}
X509_PUBKEY_get0_param(ASN1_OBJECT **ppkalg, const unsigned char **pk,
    int *ppklen, X509_ALGOR **pa, X509_PUBKEY *pub)
{
	if (ppkalg)
		*ppkalg = pub->algor->algorithm;
	if (pk) {
		*pk = pub->public_key->data;
		*ppklen = pub->public_key->length;
	}
	if (pa)
		*pa = pub->algor;
	return 1;
}


int
X509_PUBKEY_get0_param(ASN1_OBJECT **ppkalg, const unsigned char **pk,
    int *ppklen, X509_ALGOR **pa, X509_PUBKEY *pub)
{
	if (ppkalg)
		*ppkalg = pub->algor->algorithm;
	if (pk) {
		*pk = pub->public_key->data;
		*ppklen = pub->public_key->length;
	}
	if (pa)
		*pa = pub->algor;
	return 1;
}


int
X509_STORE_CTX_get_ex_new_index(long argl, void *argp, CRYPTO_EX_new *new_func,
    CRYPTO_EX_dup *dup_func, CRYPTO_EX_free *free_func)
{
	/* This function is (usually) called only once, by
	 * SSL_get_ex_data_X509_STORE_CTX_idx (ssl/ssl_cert.c). */
	return CRYPTO_get_ex_new_index(CRYPTO_EX_INDEX_X509_STORE_CTX,
	    argl, argp, new_func, dup_func, free_func);
}


X509_STORE *
X509_STORE_new(void)
{
	X509_STORE *ret;

	if ((ret = malloc(sizeof(X509_STORE))) == NULL)
		return NULL;
	ret->objs = sk_X509_OBJECT_new(x509_object_cmp);
	ret->cache = 1;
	ret->get_cert_methods = sk_X509_LOOKUP_new_null();
	ret->verify = 0;
	ret->verify_cb = 0;

	if ((ret->param = X509_VERIFY_PARAM_new()) == NULL)
		goto err;

	ret->get_issuer = 0;
	ret->check_issued = 0;
	ret->check_revocation = 0;
	ret->get_crl = 0;
	ret->check_crl = 0;
	ret->cert_crl = 0;
	ret->lookup_certs = 0;
	ret->lookup_crls = 0;
	ret->cleanup = 0;

	if (!CRYPTO_new_ex_data(CRYPTO_EX_INDEX_X509_STORE, ret, &ret->ex_data))
		goto err;

	ret->references = 1;
	return ret;

err:
	X509_VERIFY_PARAM_free(ret->param);
	sk_X509_LOOKUP_free(ret->get_cert_methods);
	sk_X509_OBJECT_free(ret->objs);
	free(ret);
	return NULL;
}


int
X509_VERIFY_PARAM_inherit(X509_VERIFY_PARAM *dest, const X509_VERIFY_PARAM *src)
{
	unsigned long inh_flags;
	int to_default, to_overwrite;

	if (!src)
		return 1;
	inh_flags = dest->inh_flags | src->inh_flags;

	if (inh_flags & X509_VP_FLAG_ONCE)
		dest->inh_flags = 0;

	if (inh_flags & X509_VP_FLAG_LOCKED)
		return 1;

	if (inh_flags & X509_VP_FLAG_DEFAULT)
		to_default = 1;
	else
		to_default = 0;

	if (inh_flags & X509_VP_FLAG_OVERWRITE)
		to_overwrite = 1;
	else
		to_overwrite = 0;

	x509_verify_param_copy(purpose, 0);
	x509_verify_param_copy(trust, 0);
	x509_verify_param_copy(depth, -1);

	/* If overwrite or check time not set, copy across */

	if (to_overwrite || !(dest->flags & X509_V_FLAG_USE_CHECK_TIME)) {
		dest->check_time = src->check_time;
		dest->flags &= ~X509_V_FLAG_USE_CHECK_TIME;
		/* Don't need to copy flag: that is done below */
	}

	if (inh_flags & X509_VP_FLAG_RESET_FLAGS)
		dest->flags = 0;

	dest->flags |= src->flags;

	if (test_x509_verify_param_copy(policies, NULL)) {
		if (!X509_VERIFY_PARAM_set1_policies(dest, src->policies))
			return 0;
	}

	return 1;
}


X509_VERIFY_PARAM *
X509_VERIFY_PARAM_new(void)
{
	X509_VERIFY_PARAM *param;

	param = calloc(1, sizeof(X509_VERIFY_PARAM));
	x509_verify_param_zero(param);
	return param;
}


static void
x509_verify_param_zero(X509_VERIFY_PARAM *param)
{
	if (!param)
		return;
	param->name = NULL;
	param->purpose = 0;
	param->trust = 0;
	/*param->inh_flags = X509_VP_FLAG_DEFAULT;*/
	param->inh_flags = 0;
	param->flags = 0;
	param->depth = -1;
	if (param->policies) {
		sk_ASN1_OBJECT_pop_free(param->policies, ASN1_OBJECT_free);
		param->policies = NULL;
	}
}


