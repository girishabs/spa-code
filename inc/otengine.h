#ifndef OTENGINE_H
#define OTENGINE_H
#include "group.h"
#include "common.h"

class OTEngine
{
public:
	OTEngine(Group *_grp)
	{
		grp = _grp;
		g = grp->g;
		h = grp->h;
		q = grp->q;

		T1 = grp->getRandomGroupElement();
		//cout << "Inside OTEngine" << endl;

	}
	~OTEngine()
	{
		delete T1;
	}

protected:
	Group *grp;
	GroupElement *g;
	GroupElement *h;
	GroupElement *T1;
	BIGNUM *q;
};

class OTRcvr : public OTEngine
{
public:
	OTRcvr(Group *_grp):OTEngine(_grp)
	{
		T2 = grp->getRandomGroupElement();
		for (uint i = 0; i < MAX_BIT_LENGTH; i++)
		{
			// Pre-allocate OT random values for all rounds.
			alpha[i] = grp->getRandomNumber();
		}		
		G = new GroupElement(grp);
		H = new GroupElement(grp);
		//cout << "Inside OTRcvr" << endl;
	}
	~OTRcvr()
	{
		delete T2;
		delete G;
		delete H;
		for (uint i = 0; i < MAX_BIT_LENGTH; i++)
		{
			BN_free(alpha[i]);
		}	
	}
	void commitOTBit(bit_t b, uint round)
	{
		if(b == 0)
		{
			grp->power(G, g, alpha[round]);
			grp->power(H, h, alpha[round]);
		}
		else
		{
			printf("b = 1\n");
			GroupElement tmp = GroupElement(grp);
			grp->power(G, g, alpha[round]);	
			grp->power(H, h, alpha[round]);

			grp->elementMultiply(G, G, T1);
			grp->elementMultiply(H, H, T2);
		}
	//	printf("commitOTBit: Outputs are G, H\n");
	//	grp->printGroupElement(G);
	//	grp->printGroupElement(H);
	}
	void retrieveOTMsg(GroupElement *ret, GroupElement *ciph, GroupElement *z, uint round)
	{
		// Computes M = ciph.z^(-alpha)
	//	printf("\nretrieveOTMsg: Inputs are: ciph, z\n");
	//	grp->printGroupElement(ciph);
	//	grp->printGroupElement(z);

		GroupElement tmp1 = GroupElement(grp);
		
		BIGNUM* n = BN_dup(alpha[round]);
		BN_set_negative(n, 1); // invert alpha
		
		grp->power(&tmp1, z, n);
		grp->elementMultiply(ret, ciph, &tmp1);
		BN_free(n);
	//	printf("\nretrieveOTMsg: Outputs are: ret\n");
	//	grp->printGroupElement(ret);


	}

	GroupElement *T2;
	GroupElement *G;
	GroupElement *H;
	BIGNUM * alpha[MAX_BIT_LENGTH];
};

class OTSender : public OTEngine
{
public:
	OTSender(Group *_grp):OTEngine(_grp)
	{
		GroupElement tmp1 = GroupElement(grp);
		GroupElement tmp2 = GroupElement(grp);


		for (uint i = 0; i < MAX_BIT_LENGTH; i++)
		{
			s[i] = grp->getRandomNumber();
			t[i] = grp->getRandomNumber();
			z[i] = new GroupElement(grp);
			grp->power(&tmp1, g, s[i]);
			grp->power(&tmp2, h, t[i]);
			grp->elementMultiply(z[i], &tmp1, &tmp2);
			C0[i] = new GroupElement(grp);
		}
	
		
		//cout << "Inside OTSender" << endl;
	}
	~OTSender()
	{
		for (uint i = 0; i < MAX_BIT_LENGTH; i++)
		{
			BN_free(s[i]);
			BN_free(t[i]);
			delete C0[i];
		}
	}
	void sendOTMsg(GroupElement *G, GroupElement *H, GroupElement *m, uint round)
	{
		// Computes G^s.H^t.m

	//	printf("sendOTMsg: Inputs are:G, H, m\n");
	//	grp->printGroupElement(G);
	//	grp->printGroupElement(H);
	//	grp->printGroupElement(m);

		GroupElement tmp1 = GroupElement(grp);
		GroupElement tmp2 = GroupElement(grp);
		grp->power(&tmp1, G, s[round]);
		grp->power(&tmp2, H, t[round]);
		grp->elementMultiply(&tmp1, &tmp1, &tmp2);
		grp->elementMultiply(C0[round], &tmp1, m);
	
	//	printf("sendOTMsg: Outputs are:z, C0\n");
	//	grp->printGroupElement(z[round]);
	//	grp->printGroupElement(C0[round]);


	}

	GroupElement *z[MAX_BIT_LENGTH];
	GroupElement *C0[MAX_BIT_LENGTH];
	GroupElement *C1;
	BIGNUM *s[MAX_BIT_LENGTH];
	BIGNUM *t[MAX_BIT_LENGTH];
};


#endif