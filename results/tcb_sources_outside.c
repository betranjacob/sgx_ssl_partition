static int
ameth_cmp(const EVP_PKEY_ASN1_METHOD * const *a,
    const EVP_PKEY_ASN1_METHOD * const *b)
{
	return ((*a)->pkey_id - (*b)->pkey_id);
}

DECLARE_OBJ_BSEARCH_CMP_FN(const EVP_PKEY_ASN1_METHOD *,
    const EVP_PKEY_ASN1_METHOD *, ameth);

IMPLEMENT_OBJ_BSEARCH_CMP_FN(const EVP_PKEY_ASN1_METHOD *,
    const EVP_PKEY_ASN1_METHOD *, ameth);

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

#ifdef BN_LLONG
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
#else /* !BN_LLONG */
BN_ULONG
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
#endif /* !BN_LLONG */

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

