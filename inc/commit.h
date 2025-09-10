#ifndef COMMIT_H
#define COMMIT_H
#include <openssl/sha.h>
#include "group.h"

class commitment
{
public:
	commitment();
	~commitment(){}
	commitment(Group *group)
	{
		grp = group;
		g = grp->g;
		h = grp->h;
		g1 = grp->g1;
		//printf("Inside commitment\n");
		//grp->printGroupParams();

	}

	uint Commit(GroupElement *ret, BIGNUM *b, BIGNUM* hash, BIGNUM *r)
	{
		GroupElement x = GroupElement(grp);
		GroupElement y = GroupElement(grp);
		GroupElement z = GroupElement(grp);

		grp->power(&x,g,b);
		grp->power(&y,h,r);
		grp->power(&z,g1,hash);

		grp->elementMultiply(&x, &x,&y);
		grp->elementMultiply(ret, &x,&z);
#ifdef DEBUG
		printf("Commitment is :\n");
		grp->printGroupElement(ret);
#endif
		return 1;
	}
	uint Open(GroupElement *c, BIGNUM *b, BIGNUM *hash, BIGNUM *r)
	{
#ifdef DEBUG		
		printf("Claimed to open Commitment:\n");
		grp->printGroupElement(c);
		cout << "for bid"<<endl;
		BN_print_fp(stdout, b);
		cout << endl << "for hash"<<endl;
		BN_print_fp(stdout, hash);
		cout << endl << "with randomness"<<endl;
		BN_print_fp(stdout, r);
		cout << endl;
#endif		

		GroupElement x = GroupElement(grp);
		Commit(&x,b, hash, r);
#ifdef DEBUG
		printf("Reconstructed commitment is:\n");
		grp->printGroupElement(&x);
#endif		

		if(grp->compareElements(c, &x) == 0)
		{
			printf("Successful opening of commitment\n");
			return 1;
		}
		else
		{
			printf("!!!Commitment opening fails!!!\n");	
			return 0;
		}	
	}

private:
	Group *grp;
	GroupElement *g;
	GroupElement *h;
	GroupElement *g1;

};


#endif
