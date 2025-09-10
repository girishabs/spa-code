/*
 * This file implements the procedures required for the group representation and its various operations.
 * Although we use the additive group from the elliptic curve for our work, the representation and 
 * abstraction used in this implementation is multiplicative.
 *
 */
#include <iostream>
#include "common.h"

#include "group.h"


// We generate the generators used in our protocol in our code in NUMS fashion by hasing the uncompressed version
// of the genreator point (which includes the strings for x and y coordinates), generate SHA256 hash of it.
// The resultant value of hash is used as the x-coordinate to evaluate the curve at the point 



unsigned char curvePrime[32] {
	0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 
	0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
	0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
	0xff, 0xff, 0xff, 0xfe, 0xff, 0xff, 0xfc, 0x2f,
};

GroupElement::GroupElement(Group *_grp)
{
	grp = _grp;
	ep = EC_POINT_new(grp->ecg);
}

GroupElement::GroupElement(EC_POINT *element, Group *_grp)
{
	BIGNUM *x = BN_new();
	BIGNUM *y = BN_new();
	grp = _grp;

	ep = element;
	EC_POINT_get_affine_coordinates(grp->ecg, ep, x, y, NULL);
	
	gpt.xn = BN_bn2bin(x, gpt.gx);
	gpt.yn = BN_bn2bin(y, gpt.gy);
	BN_free(x);
	BN_free(y);
}
GroupElement::GroupElement(Group *_grp, GrpPoint *_gpt)
{
	BIGNUM *x = BN_new();
	BIGNUM *y = BN_new();

	grp = _grp;

	gpt = *_gpt;
	BN_bin2bn(gpt.gx,gpt.xn,x);
	BN_bin2bn(gpt.gy,gpt.yn,y);
	
	ep = EC_POINT_new(grp->ecg);
	if(EC_POINT_set_affine_coordinates(grp->ecg, ep, x, y, NULL) == 0)
	{	
		printf("ERROR occurred while setting affine coordinates\n");
		printGroupPoint(_gpt);
	}
}

void Group::initGroup()
{
			BN_CTX *ctx = BN_CTX_new();
    		BIGNUM *k; 
			
			EC_POINT *i = EC_POINT_new(ecg);
			BIGNUM *x = BN_new();
			BIGNUM *y = BN_new();
			BN_set_word(x, 0);
			BN_set_word(y, 0);
			
			EC_POINT_set_affine_coordinates(ecg, i, x, y,ctx);
			ident = new GroupElement(i, this);

    		k = BN_new(); // Place holder for the order of group
			EC_GROUP_get_order(ecg, k, ctx);
			q = BN_new();
			q = k;
			//printf("q = \n");
			//BN_print_fp(stdout, q);

			
			numBitsInOrder = BN_num_bits(k);
			EC_POINT *ecpg = (EC_POINT *) EC_GROUP_get0_generator(ecg);
			g = new GroupElement(ecpg, this);

			//printf("g = \n");
			//printGroupElement(g);

			chooseNUMSPoints();


			if(EC_POINT_set_to_infinity(ecg, ident->ep) == 0)
			{
				printf("Setting point to infinity failed\n");
			}


#ifdef DEBUG			
			
			printf("****Group initialized****\n");
			printGroupParams();
#endif			
}

void GroupElement::setPoint()
{
	BIGNUM *x = BN_new();
	BIGNUM *y = BN_new();
	BN_CTX *ctx = BN_CTX_new();

	
	EC_POINT_get_affine_coordinates(grp->ecg, ep, x, y, ctx);
	
	gpt.xn = BN_bn2bin(x, gpt.gx);
	gpt.yn = BN_bn2bin(y, gpt.gy);	
	BN_free(x);
	BN_free(y);
	BN_CTX_free(ctx);
}

void GroupElement::gPrint(unsigned char *c, uint num)
{
	for (uint i = 0; i < num; i++)
	{
		printf("%02X",c[i]);
	}
	cout << endl;
	//cout << num << " bytes" << endl;
}

void GroupElement::printGroupPoint(GrpPoint *gpt)
{
	if(gpt->xn > MAX_BIG_NUM_SIZE || gpt->yn > MAX_BIG_NUM_SIZE)
	{	
		printf("Group point seems corrupted. Not printg\n");
		return;
	}	

	printf("x = ");

	gPrint(gpt->gx, gpt->xn);
   	cout << "\tand" << endl << "y = ";

   	gPrint(gpt->gy, gpt->yn);
   	cout << endl;
}
void Group::dupGroupElement(GroupElement *d, GroupElement *s)
{
	d->ep = EC_POINT_dup(s->ep, ecg);
	d->setPoint();
}

GroupElement* Group::getRandomGroupElement() 
{
    BIGNUM *k = getRandomNumber(); 
    GroupElement *r = new GroupElement(this);

    if (!EC_POINT_mul(ecg,r->ep,k,r->ep,k,NULL)) 
    {
		printf("Something went wrong with get point mul\n");
   		BN_free(k);
  		return NULL; 
    } 
	return r;
}	



int Group::getGroupDegree()
{
	return EC_GROUP_get_degree(ecg);
}

void Group::printGroupElement(GroupElement* p)
{
	BIGNUM *x = BN_new();
	BIGNUM *y = BN_new();
	
	EC_POINT_get_affine_coordinates(ecg, p->ep, x, y, NULL);
	printf("x = ");
	BN_print_fp(stdout, x);
   	cout << "\tand" << endl << "y = ";
   	BN_print_fp(stdout, y);
   	cout << endl;
    BN_free(x);
    BN_free(y);
}


/** Computes the product of two group elements
 *  \param  group  underlying group object
 *  \param  c    GroupElement object for the result (r = a * b)
 *  \param  a      GroupElement object with the first multiplicand
 *  \param  b      GroupElement object with the second multiplicand
 *  \param  ctx    BN_CTX object (optional)
 *  \return c on success and NULL if an error occurred
 */		



uint Group::elementMultiply(GroupElement *ret, GroupElement *a, GroupElement *b)
{

	if(EC_POINT_add(ecg, ret->ep,  a->ep, b->ep, NULL) == 0)
	{
		printf("Group: Error in elementMultiply\n");
		return 0;
	}
	//printf("Inside elementMultiply\n");
	//printECPoint(ret->ep);
	ret->setPoint();
	return 1;
}

/** Computes r = generator * n + q * m
 *  \param  group  underlying EC_GROUP object
 *  \param  r      EC_POINT object for the result
 *  \param  n      BIGNUM with the multiplier for the group generator (optional)
 *  \param  q      EC_POINT object with the first factor of the second summand
 *  \param  m      BIGNUM with the second factor of the second summand
 *  \param  ctx    BN_CTX object (optional)
 *  \return 1 on success and 0 if an error occurred
 */

uint Group::power(GroupElement *ret, GroupElement *base, BIGNUM *exp)
{
	if(EC_POINT_mul(ecg, ret->ep, NULL, base->ep, exp, NULL) == 0) 
	{
		printf("Group: Error in power\n");
		return 0;
	}
	ret->setPoint();
	return 1;
}

/** Gets a random element from Z_q **/

BIGNUM * Group::getRandomNumber()
{
	BN_CTX *ctx = NULL;
    BIGNUM *k; 
      
    k = BN_new(); 

	if (!BN_pseudo_rand(k, numBitsInOrder, 0, 0))
	{
		printf("Something went wrong with get pseudorand\n");
		return NULL;
    } 
    return k;
}

/** Computes ret = \prod_{i=0}^{num-1} p[i] ^ m[i]
 *  \param  group  underlying group object
 *  \param  ret      GroupElement object for the result
 *  \param  num    number further multiplicands
 *  \param  p      array of size num of GroupElement objects
 *  \param  m      array of size num of BIGNUM objects
 *  \param  ctx    BN_CTX object (optional)
 *  \return GroupElement pointer on success and NULL if an error occurred
 */

 
GroupElement *Group::multiElementMultiply(GroupElement* gelem[], uint id)
{
	GroupElement *ret = new GroupElement(this);
	EC_POINT *p[MAX_BIDDERS];
	BIGNUM *m[MAX_BIDDERS];
	BIGNUM *n;
	BN_set_word(n, 0);

	for(uint i = 0; i < id; i++)
	{

		p[i] = gelem[i]->ep;
		BN_set_word(m[i], 1);
	}

	if(EC_POINTs_mul(ecg, ret->ep, n, id, (const EC_POINT **)p, (const BIGNUM **)m, NULL) == 0)
	{
		printf("Group: Error in multiElementMultiply\n");
		return NULL;
	}
	return ret;
}

/** Computes the inverse of a EC_POINT
 *  \param  group  underlying EC_GROUP object
 *  \param  a      EC_POINT object to be inverted (it's used for the result as well)
 *  \param  ctx    BN_CTX object (optional)
 *  \return 1 on success and 0 if an error occurred
 */
uint Group::getInverse(GroupElement *e)
{
	if(EC_POINT_invert(ecg, e->ep, NULL) == 0)
	{
		printf("Group: Error in getInverse\n");
		return 0;
	}
	e->setPoint();
	return 1;
}
/** Compares two GroupElements
 *  \param  a      first GroupElement object
 *  \param  b      second GroupElement object
 *  \return 1 if the points are not equal, 0 if they are, or -1 on error
 */
uint Group::compareElements(GroupElement *a, GroupElement *b)
{
	return(EC_POINT_cmp(ecg, a->ep, b->ep, NULL));
}

// Utility function for printing the different group parameters.

void Group::printGroupParams()
{
	printf("Identity is:\n");
	printGroupElement(ident);
	printf("Generator g is:\n");
	printGroupElement(g);
	printf("Element h is:\n");
	printGroupElement(h);
	printf("Element g1 is:\n");
	printGroupElement(g1);
	printf("Element T1 is:\n");
	printGroupElement(T1);
	printf("Order of Group q is:\n");
	BN_print_fp(stdout, q);
	cout << endl;

}

void Group::printECPoint(EC_POINT* ep)
{
	BIGNUM *x = BN_new();
	BIGNUM *y = BN_new();
	
	EC_POINT_get_affine_coordinates(ecg, ep, x, y, NULL);
	printf("x = ");
	BN_print_fp(stdout, x);
   	cout << "\tand" << endl << "y = ";
   	BN_print_fp(stdout, y);
   	cout << endl;
    BN_free(x);
    BN_free(y);
}

// The following function evaluates the secp256k1 curve at the point x and sets the value y accordingly.
// The equation used is: y^2 = x^3 +7 mod p
// where p = 0xffffffff ffffffff ffffffff ffffffff ffffffff ffffffff fffffffe fffffc2f
void Group::eval(BIGNUM* x, BIGNUM* y)
{
	BIGNUM *c = BN_new();
	BIGNUM *p = BN_new();
	BIGNUM *xsq = BN_new();
	BN_CTX *ctx = BN_CTX_new();
	BIGNUM *t = BN_new();

	BN_set_word(c, 7);

	BN_bin2bn(curvePrime, MAX_BIG_NUM_SIZE, p);
	BN_mod_sqr(xsq, x, p, ctx); // xsq = x^2
	BN_mod_mul(t, x, xsq, p,ctx); // t = x^3
	BN_mod_add(t, t, c, p, ctx); // t = x^3 +7

	BN_mod_sqrt(y, t, p, ctx); // y = sqrt(x^3 + 7);

// There are two square roots - one is a negative of the other. We choose the second one for our use.
	BN_mod_sub(y, p, y, p, ctx); // y = p-y


#ifdef GRP_DEBUG
	printf("Eval: x and y are:\n");
	BN_print_fp(stdout, x);
	cout << endl;
	BN_print_fp(stdout, y);
	cout << endl;
#endif // GRP_DEBUG

	BN_CTX_free(ctx);
	BN_free(c);
	BN_free(p);
	BN_free(xsq);
	BN_free(t);


}

void Group::chooseNUMSPoints()
{
    // We repeatedly hash the generator g and check if the resulting point is a valid point on curve.
    BIGNUM *x = BN_new();
    BIGNUM *y = BN_new();

    unsigned char buffer[2*MAX_BIG_NUM_SIZE+1];
    buffer[0] = 0x04;


    // Choose the generator h by hashing g
    unsigned char hash[SHA256_DIGEST_LENGTH];

    //EC_POINT_point2oct(grp->ecg, grp->g->ep, POINT_CONVERSION_UNCOMPRESSED, buffer, MAX_BIG_NUM_SIZE+1, NULL);
    
    memcpy(buffer+1, g->gpt.gx, MAX_BIG_NUM_SIZE );
    memcpy( buffer+1+MAX_BIG_NUM_SIZE, g->gpt.gy, MAX_BIG_NUM_SIZE );
    
    
    int rc;

    SHA256(buffer, 2*MAX_BIG_NUM_SIZE+1, hash);
    
    BN_bin2bn(hash, MAX_BIG_NUM_SIZE,x);
    

    eval(x, y);

    EC_POINT *eph = EC_POINT_new(ecg);

    if(EC_POINT_set_affine_coordinates(ecg, eph, x, y, NULL) == 0)
    {   
        printf("chooseNUMSPoints ERROR occurred while setting affine coordinates of h\n");
        printECPoint(eph);
    }
    
    rc = EC_POINT_is_on_curve(ecg, eph, NULL);

    if(rc == 1)
    {
        h = new GroupElement(eph, this);
    }

    // Choose the generator g1 by hashing g twice
    
    
    
    SHA256(hash, SHA256_DIGEST_LENGTH, hash);
    BN_bin2bn(hash, MAX_BIG_NUM_SIZE,x);


    eval(x, y);

    EC_POINT *epg1 = EC_POINT_new(ecg);

    if(EC_POINT_set_affine_coordinates(ecg, epg1, x, y, NULL) == 0)
    {   
        printf("chooseNUMSPoints ERROR occurred while setting affine coordinates of h\n");
        printECPoint(epg1);
    }
    
    rc = EC_POINT_is_on_curve(ecg, epg1, NULL);

    if(rc == 1)
    {
        g1 = new GroupElement(epg1, this);
    }
    
    // Choose the generator T1 by hashing g thrice
    SHA256(hash, SHA256_DIGEST_LENGTH, hash);
    BN_bin2bn(hash, MAX_BIG_NUM_SIZE,x);


    eval(x, y);

    EC_POINT *ept1 = EC_POINT_new(ecg);
    EC_POINT *ept2 = EC_POINT_new(ecg);


    if(EC_POINT_set_affine_coordinates(ecg, ept1, x, y, NULL) == 0)
    {   
        printf("chooseNUMSPoints ERROR occurred while setting affine coordinates of h\n");
        printECPoint(ept1);
    }

    // Create a duplicate to get the inverse
    if(EC_POINT_set_affine_coordinates(ecg, ept2, x, y, NULL) == 0)
    {   
        printf("chooseNUMSPoints ERROR occurred while setting affine coordinates of h\n");
        printECPoint(ept1);
    }
    
    rc = EC_POINT_is_on_curve(ecg, ept1, NULL);

   	// We first get T1 into the invT1 variable and then invert the same to get actual inverse.
   	// This is because, underlying library clobbers the passed parameter.

    invT1 = new GroupElement(ept2, this); 
    getInverse(invT1);

    // Now that invT1 is fixed, create actual T1
    T1 = new GroupElement(ept1, this); 
    


}
