/* 
 * This source file implements the bid encoding that is used in the protocol.
 * Both encode and decode functions are implemented here.
 *
 */
#include "encoder.h"
#include "bidder.h"

Encoder::Encoder(Group *group)
{
	grp = group;
	g = grp->g;
	//printf("Inside encoder\n");
	//grp->printGroupParams();
}


uint Encoder::oneBitEncode(GroupElement *ret, BIGNUM *r)
{

	return grp->power(ret, grp->g, r);		
}
uint Encoder::zeroBitEncode(GroupElement *ret, BIGNUM *x, uint id, uint round, BulletinBoard* bb)
{
	uint retval;
	GroupElement y = GroupElement(grp); 
	computeZeroBase(&y, id, round, bb);
#ifdef ENC_DEBUG	
	printf("y[%d][%d] is:\n", id, round);
	grp->printGroupElement(&y);
	printf("Private Key [%d][%d] is:\n", id,round);
	BN_print_fp(stdout, x);
	cout << endl;
#endif	
		
	retval =  grp->power(ret, &y,x);
	//printf("Computed ret is:\n");
	//grp->printGroupElement(ret);
	if(retval == 0)
	{
		printf("zeroBitEncode: Call to power() failed\n");
	}
	return retval;
}

uint Encoder::computeZeroBase(GroupElement *ret, uint id, uint round, BulletinBoard* bb)
{
	GroupElement yn = GroupElement(grp);
	if(id == 0)
	{
		grp->dupGroupElement(&yn, grp->ident);
	}
	else
	{
		grp->dupGroupElement(&yn, grp->ident);
		GrpPoint *gpt;
#ifdef ENC_DEBUG		
		printf(" yn before compute is:\n");
		grp->printGroupElement(&yn);
#endif		
		for (uint i = 0; i < id; i ++)
		{
	 		BBMemoryBidder *bidderBB = static_cast<struct BBMemoryBidder *>(&bb->bidderBB[i]);
	 		gpt = &bidderBB->pubKey[round];
	 		
	 		GroupElement pubKey = GroupElement(grp, gpt);
#ifdef ENC_DEBUG
        	printf("yn: publickey[%d][%d] is :\n",i,round);
	 		grp->printGroupElement(&pubKey);  	
#endif	 		
            	
			grp->elementMultiply(&yn, &yn, &pubKey);
#ifdef ENC_DEBUG			
			printf("Computed yn[%d] is:\n",i);
			grp->printGroupElement(&yn);				
#endif			
				
		}
			
			
	}	
	GroupElement yd = GroupElement(grp);
	if(id == MAX_BIDDERS -1)
	{
		grp->dupGroupElement(&yd, grp->ident);

	}
	else
	{
		GrpPoint *gpt;

	
		grp->dupGroupElement(&yd, grp->ident);

#ifdef ENC_DEBUG
		printf(" yd before compute is:\n");
		grp->printGroupElement(&yd);
#endif		
		
		for (uint i = id+1; i < MAX_BIDDERS; i ++)
		{
	
			BBMemoryBidder *bidderBB = static_cast<struct BBMemoryBidder *>(&bb->bidderBB[i]);
	 		gpt = static_cast< GrpPoint *>(&bidderBB->pubKey[round]);
	 		GroupElement pubKey = GroupElement(grp, gpt);
#ifdef ENC_DEBUG	 		
        	printf("yd: publickey[%d][%d] is :\n",i,round);
	 		grp->printECPoint(pubKey.ep);  	       
#endif	 		
            
			grp->elementMultiply(&yd, &yd, &pubKey);
#ifdef ENC_DEBUG			
			printf("Computed yd[%d] is:\n",i);
			grp->printGroupElement(&yd);
#endif			
		}

	
	}
	
	grp->getInverse(&yd);

		
		
	grp->elementMultiply(ret, &yn, &yd);
	return 1;

}

bool Encoder::decodeBitcode(uint j, Bidder* bidder)
{
	GroupElement e = GroupElement(grp);
	grp->dupGroupElement(&e, grp->ident);

#ifdef ENC_DEBUG
	printf("e.ep is\n");
	grp->printGroupElement(&e);

	if(EC_POINT_is_at_infinity(grp->ecg, e.ep) == 1)
	{
		printf("e.ep  is neutral point\n");
			
	}
	printf("ident is\n");
	grp->printGroupElement(grp->ident);
#endif	
	for(uint i = 0; i < MAX_BIDDERS ; i++)
	{
#ifdef ENC_DEBUG		
		printf("e.ep is\n");
		grp->printGroupElement(&e);
		printf("bitcode[%d][%d] is:\n",i,j);
		grp->printGroupElement(&bidder->bidderBitcode[i][j]);
#endif		
		
		grp->elementMultiply(&e, &e, bidder->bidderBitcode[i]);
#ifdef ENC_DEBUG		
		printf("Computed e[%d][%d] is:\n",i,j);
		grp->printGroupElement(&e);
		printf("bitcode[%d][%d] after decode is:\n",i,j);
		grp->printGroupElement(&bidder->bidderBitcode[i][j]);
#endif		
	}

	
#ifdef ENC_DEBUG	
	printf("\nDecoded bit code is :\n");
	grp->printGroupElement(&e);
#endif
	
	if(EC_POINT_is_at_infinity(grp->ecg, e.ep) == 1)
	{
		return 0;
	}

	return 1;
}
