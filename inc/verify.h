// This file contains various verification routines used by the protocol.

#ifndef VERIFY_H
#define VERIFY_H

#include "group.h"
#include "common.h"
#include "commit.h"
#include "encoder.h"

class Verify
{
public:
	Verify(BulletinBoard* _bb)
	{
		bb = _bb;
		
		grp = new Group(NID_secp256k1);
		enc = new Encoder(grp);
		char name[16];
		commitObj = new commitment(grp); 
		for(uint i = 0; i < MAX_BIDDERS; i++)
        {
            sprintf(name, "bidderSyn-%d",i); // Each semaphore has a name of the form "bidder-<id>". E.g.: Bidder 12 has name "bidder-12"

            verify_sync_sem[i] = sem_open(name, O_CREAT, 0777, 0);
            if(verify_sync_sem[i] == SEM_FAILED)
            {
                perror("verify_sync_sem: Semaphore creation failed");
            }
        }

	}
	~Verify(){}

void runVerify()
{
	uint id;
	
	for(uint i = 0; i < MAX_BIDDERS; i++)
	{
		while(!bb->verifyStageDone[i])
			usleep(100); 
		//printf("Waiting for eval Semaphore\n");
	    //sem_wait(verify_sync_sem[i]); // Wait till Evaluator is done with verification stage

	}
	
	auto start = std::chrono::high_resolution_clock::now();

	verifyProofOfComputation();

	for(uint i = 1; i < MAX_BIDDERS; i++)
	{
		//printf("Waiting for winnerClaim %d\n", i);

		if(bb->winnerClaim != -1)
		{
			id = bb->winnerClaim;
			break;
		}
	    //sem_wait(verify_sync_sem[i]); // Wait till ith bidder is done with verification stage.

		while(!bb->verifyStageDone[i]); 
	}
	verifybidderWinProof(id);
	if(id == 0)// Required only for the eval
	{
		if(verifyEvalWinProof())
			printf("Evaluator Verification successful\n"); 
		else
			printf("Evaluator Verification fails\n"); 
	}

	auto end = std::chrono::high_resolution_clock::now();
	std::chrono::duration<double, std::milli> float_ms = end - start;


	std::cout << "Total Verification stage elapsed time for Verifier is " << 
    	float_ms.count() << " ms" << std::endl;
}

void verifybidderWinProof(uint id)
{
	BIGNUM * rcommit = BN_new();
	BIGNUM * bid = BN_new();
	BIGNUM * hashval = BN_new();
	GrpPoint *gpt;

	BN_set_word(bid, bb->winningBid);
	if(id > MAX_BIDDERS)
	{
		printf("Id value is corrupted. Exiting\n");
		exit(-1);
	}

	BBMemoryBidder *bidderBB = static_cast<struct BBMemoryBidder *>(&bb->bidderBB[id]);
	gpt = &bidderBB->commitment;
	

	GroupElement e = GroupElement(grp, gpt); // Create a GroupElement using the commitment available on BB

	BN_bin2bn(bb->bidderWinProof[id], MAX_BIG_NUM_SIZE, rcommit); // Create BIGNUM* using the proof of winning

	getKeyHash(hashval);

	if(commitObj->Open(&e, bid, hashval, rcommit) == 0)
	{
		printf("Commit verification failed for Bidder %d\n", id);
	}
	else
		printf("Commit verification successful for Bidder %d\n", id);	

}
void getKeyHash(BIGNUM *hashval)
{
    // Extract the private keys from the BB


    unsigned char buffer[MAX_BIG_NUM_SIZE*(4*MAX_BIT_LENGTH)];
    uint offset = 0 ;
    for(uint j = 0; j < MAX_BIT_LENGTH; j++)
    {
        memcpy(&buffer[MAX_BIG_NUM_SIZE * j], &bb->xWinner[j], MAX_BIG_NUM_SIZE);
    }
    
    offset = offset + MAX_BIG_NUM_SIZE* MAX_BIT_LENGTH ;
    for(uint j = 0; j < MAX_BIT_LENGTH; j++)
    {
        memcpy(&buffer[offset + MAX_BIG_NUM_SIZE * j], &bb->rWinner[j], MAX_BIG_NUM_SIZE);
    }
    offset = offset + MAX_BIG_NUM_SIZE* MAX_BIT_LENGTH ;
    for(uint j = 0; j < MAX_BIT_LENGTH; j++)
    {
        memcpy(&buffer[offset + MAX_BIG_NUM_SIZE * j], &bb->sWinner[j], MAX_BIG_NUM_SIZE);
    }
    
    offset = offset + MAX_BIG_NUM_SIZE* MAX_BIT_LENGTH ;
    for(uint j = 0; j < MAX_BIT_LENGTH; j++)
    {
        memcpy(&buffer[offset + MAX_BIG_NUM_SIZE * j], &bb->tWinner[j], MAX_BIG_NUM_SIZE);
    }

#ifdef DEBUG
    printf("Reconstructed buffer is:\n");
    printBuffer(buffer, MAX_BIG_NUM_SIZE*(4*MAX_BIT_LENGTH));
#endif    

    unsigned char hashString[SHA256_DIGEST_LENGTH];

    SHA256(buffer, MAX_BIG_NUM_SIZE*(4*MAX_BIT_LENGTH), hashString);

    BN_bin2bn(hashString, MAX_BIG_NUM_SIZE, hashval);
    //printf("The reconstructed Hash computed for the winner is\n");
    //printBuffer(hashString, SHA256_DIGEST_LENGTH);
}

void printBuffer(unsigned char *buffer, uint n)
{
    cout << endl;
    for(uint k = 0; k < n; k++)
    {
        printf("%0X", buffer[k]);
    }
    cout << endl;
}
bool verifyEvalWinProof()
{
	// Retrieve delta values from the BB
	BIGNUM * delta[MAX_BIT_LENGTH];
	GroupElement *Gval[MAX_BIDDERS+1][MAX_BIT_LENGTH];


	for(uint j=0; j < MAX_BIT_LENGTH; j++)
    {
    	delta[j] = BN_new();
    	BN_bin2bn(bb->evalWinProof[j], MAX_BIG_NUM_SIZE, delta[j]);       
#ifdef DEBUG    	
    	printf("\nVerify's delta[%d] is \n", j);
        BN_print_fp(stdout, delta[j]);
#endif        
    }
    
    for(uint i = 1; i < MAX_BIDDERS; i++)
    {
    	for(uint j=0; j < MAX_BIT_LENGTH; j++)
    	{
    		Gval[i][j] = new GroupElement(grp, &bb->bidderBB[i].G[j]); //Retrieve G values from BB
#ifdef DEBUG    		
    		printf("Gval[%d][%d]\n",i,j);
    		grp->printGroupElement(Gval[i][j]);
#endif    		
    	}

    }
    GroupElement e = GroupElement(grp);
    GroupElement f = GroupElement(grp);
    GroupElement *t1 = grp->T1;
    bool retval;

    
    for(uint j=0; j < MAX_BIT_LENGTH; j++)
    {
    	grp->dupGroupElement(&e, grp->ident);
    	for(uint i = 1; i < MAX_BIDDERS; i++)
    	{
    		grp->elementMultiply(&e, &e, Gval[i][j]);

    	}
    	grp->power(&f,grp->g, delta[j]);
    	if(bb->winBit[j])
    	{
    		for(uint i = 1; i < MAX_BIDDERS; i++)
    		{	
    			grp->elementMultiply(&f, &f, t1);
    		}	
    	}	
    	if(grp->compareElements(&f, &e) == 0)
    	{
    		// printf("Verified eval proof for round %d\n",j);
    		retval = true;
    	}
    	else
    	{
    		printf("Failed eval proof for round %d\n",j);	
    		retval = false;
    	}
    }
cleanup:	
    for(uint j=0; j < MAX_BIT_LENGTH; j++)
    {
    	BN_free(delta[j]);
    	
    }
    for(uint i = 1; i < MAX_BIDDERS; i++)
    {
    	for(uint j=0; j < MAX_BIT_LENGTH; j++)
    	{
    		delete Gval[i][j] ; //Clean up memory for G values
    	}
    }
    return retval;
}
void verifyProofOfComputation()
{
	// printf("Inside verifyProofOfComputation\n");
	bool retval;
	for(uint k = 1; k <MAX_BIT_LENGTH; k++)
	{
		//while(bb->evalUpdatedRound != k);
		if(bb->winBit[k])
			continue;
		constructBitCodesFromBB(k);
		if(decodeBitcode() == 0)
		{
#ifdef DEBUG			
			printf("\tVerification of computation for round %d is successful\n",k);
#endif			
			retval = true;
		}
		else
		{
			printf("\tVerification of computation for round %d fails\n",k);
			retval = false;
			break;
		}
	}
	if(retval)
		printf("\tVerification of eval computation is successful\n");

	releaseBitCodes();
}

void constructBitCodesFromBB(uint j)
{

	for(int i =0; i < MAX_BIDDERS; i++)
    {
    	bidderBitcode[i] = new GroupElement(grp, &bb->proofOfComputation[i][j]) ; // Retrieve bit codes from BB
    }
    
}
void releaseBitCodes()
{

	for(int i =0; i < MAX_BIDDERS; i++)
    {
    	delete bidderBitcode[i] ;
    }
    
}
uint decodeBitcode()
{
	GroupElement e = GroupElement(grp);
	grp->dupGroupElement(&e, grp->ident);
#ifdef DEBUG
	printf("\tdecodeBitcode: e.ep is\n");
	grp->printGroupElement(&e);



	if(EC_POINT_is_at_infinity(grp->ecg, e.ep) == 1)
	{
		printf("\tdecodeBitcode: e.ep  is neutral point\n");
			
	}


	printf("\tdecodeBitcode: ident is\n");
	grp->printGroupElement(grp->ident);
#endif


	for(uint i = 0; i < MAX_BIDDERS ; i++)
	{
#ifdef DEBUG
		printf("\tdecodeBitcode: e.ep is\n");
		grp->printGroupElement(&e);
		printf("\tdecodeBitcode: bitcode[%d] is:\n",i);
		grp->printGroupElement(bidderBitcode[i]);
#endif
		grp->elementMultiply(&e, &e, bidderBitcode[i]);
#ifdef DEBUG		
		printf("\tdecodeBitcode: Computed e[%d] is:\n",i);
		grp->printGroupElement(&e);
#endif		
	}

	
#ifdef DEBUG	
	printf("\ndecodeBitcode: Decoded bit code is :\n");
	grp->printGroupElement(&e);
#endif

	if(EC_POINT_is_at_infinity(grp->ecg, e.ep) == 1)
	{
		return 0;
	}
	
	return 1;
}	

private:
	BulletinBoard *bb;
	Group *grp;
	Encoder *enc;
	commitment *commitObj;
	GroupElement* bidderBitcode[MAX_BIDDERS];
	sem_t *verify_sync_sem[MAX_BIDDERS+1];

};
#endif // VERIFY_H
