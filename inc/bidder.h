#ifndef BIDDER_H
#define BIDDER_H
#include "common.h"
#include "group.h"
#include "commit.h"
#include "encoder.h"
#include <semaphore.h>


class Bidder
{
public:
	uint addr_sc; // Address of the Smart Token to reach out
	uint deposit; // Security deposit
	PParam pp; //Public Parameters
	uint id; 
	BulletinBoard* bb;
	uint currentRound;
	bool auctionLost;
	bool highestBidder;
	void printBidBits()
	{
		printf("Bits of the bid %X for bidder %d are: ",bidval, id);
		
		for(uint j = 0; j < MAX_BIT_LENGTH; j++)
		{
			printf("%i\t", bitsOfBid[j] );
		}
		cout << endl;
	}
	Bidder(){}

	Bidder(uint v, uint b, uint d, uint addr, uint _id, BulletinBoard* _bb)
	{

		grp = new Group(NID_secp256k1);
		enc = new Encoder(grp);
		
		value = v;
		bidval = b;
		deposit = d;
		addr_sc = addr;
		id = _id;
		uint mask = 1;
		bb = static_cast<struct BulletinBoard *>(_bb);
		auctionLost = false;
		highestBidder = false;
		currentRound = 0; // The round 0 is invalid value. Valid range for rounds is [1,...,l]

		


		bidderBB = static_cast<struct BBMemoryBidder *>(&bb->bidderBB[id]);
		uint n = b;
		for(uint j = 0; j < MAX_BIT_LENGTH; j++)
		{
       		bitsOfBid[MAX_BIT_LENGTH-1-j] = static_cast<bool>(n % 2);
       		n = n / 2;      
		}	
		GroupElement e = GroupElement(grp);
		GroupElement f = GroupElement(grp);
		for(uint j = 0; j < MAX_BIT_LENGTH; j++)
		{
			s[j] = grp->getRandomNumber();
			t[j] = grp->getRandomNumber();
			grp->power(&e, grp->g, s[j]);
			grp->power(&f, grp->h, t[j]);
			grp->elementMultiply(&e,&e,&f);
			bidderBB->z[j] = e.gpt;
			// printf("z[%d][%d] is:\n",id, j);
			// grp->printGroupElement(&e);
			usleep(1);
		}

		
		for(uint j = 0; j < MAX_BIT_LENGTH; j++)
		{
			bitcode[j] = new GroupElement(grp);	
			bitCommit[j] = new GroupElement(grp);
			pubKey[j] = new GroupElement(grp);
			yCode[j] = new GroupElement(grp);

			zeroToken[j] = new GroupElement(grp);	
			ztCommit[j] = new GroupElement(grp);	

		}
		for(uint i = 0; i < MAX_BIDDERS; i++)
		{
			for(uint j = 0; j < MAX_BIT_LENGTH; j++)
			{
				bidderZToken[i][j] = new GroupElement(grp);
			}
		}		
		zeroBitCode = GroupElement(grp);	

		char name[32];

		sprintf(name, "bidderThr-%d",id); // Each semaphore has a name of the form "bidder-<id>". E.g.: Bidder 12 has name "bidder-12"

		bidder_thr_sem = sem_open(name, O_CREAT, 0777, MAX_BIDDERS-1);
		if(bidder_thr_sem == SEM_FAILED)
    	{
        	perror("bidder_thr_sem: Semaphore creation failed");
    	}
    	sprintf(name, "bidderSyn-%d",id); // Each semaphore has a name of the form "bidder-<id>". E.g.: Bidder 12 has name "bidder-12"

		bidder_sync_sem = sem_open(name, O_CREAT, 0777, 0);
		if(bidder_sync_sem == SEM_FAILED)
    	{
        	perror("bidder_sync_sem: Semaphore creation failed");
    	}

		comp_stg_sem = sem_open("sem_comp_stg", O_CREAT, 0777, 0);
		if(comp_stg_sem == SEM_FAILED)
    	{
        	perror("sem_comp_stg: Semaphore creation failed");
    	}


	}
	~Bidder()
	{
		for(uint j = 0; j < MAX_BIT_LENGTH; j++)
		{
			BN_free(s[j]);
			BN_free(t[j]);
			
			delete bitcode[j];	
			delete zeroToken[j];
			delete ztCommit[j];

			BN_free(beta[j]);
			BN_free(invbeta[j]);
		}	
		delete grp;	
		for(uint i = 0; i < MAX_BIDDERS; i++)
		{
			for(uint j = 0; j < MAX_BIT_LENGTH; j++)
			{
				delete bidderZToken[i][j];
			}
		}

		sem_close(bidder_thr_sem);
		sem_close(comp_stg_sem);
		sem_close(bidder_sync_sem);


		for(uint i = 0; i < MAX_BIDDERS; i++)
		{
			sem_close(&eval_init_sem[i]);

			sem_close(&eval_thr_sem[i]);
			sem_close(&eval_sync_sem[i]);
		}	
	}

	void printBuffer(unsigned char *buffer, uint n);

	// Following functions need to be reimplemented for inherited classes.
	virtual PStage protocolSetupStage();	
	virtual PStage protocolComputeStageBidder();
	virtual void protocolVerificationStage();
	
	PStage currentState;

	void initBidder();

	void announceWinner();
	bool verifyWinnerClaim();

	uint  exp(int a, int n) 
	{ 
		uint e = 1;
		for(uint i =1; i <=n; i++)
		{
			e = e * a;
		}
		return e;
	}

	uint utility()
	{
		return value - bidval;
	}
	bool getABPbit(uint j)
	{
		bool b;
		
		if(auctionLost)
			b = false;
		else
		 	b= bitsOfBid[j];
		return b;
	}

	uint bidval;

	bool bitsOfBid[MAX_BIT_LENGTH];

	bool winBit[MAX_BIT_LENGTH]; // The winning bits during each round

	bool computeBit[MAX_BIT_LENGTH]; // Computed bits for each round

	uint value;
	Group *grp; // The Group on which all crypto primitives are based
	BBMemoryBidder *bidderBB; // Pointer to the bulletin board where bidder can write its artefacts
	Encoder *enc;

	BIGNUM *bid; // Bid value represented as BIGNUM

	BIGNUM* x[MAX_BIT_LENGTH]; // Private key for computing the 0-bit code
	BIGNUM* r[MAX_BIT_LENGTH]; // Private key for computing the 1-bit code

	BIGNUM * a[MAX_BIT_LENGTH]; // Randomness used for bit commitments

	unsigned char keyHash[SHA256_DIGEST_LENGTH]; // Hash of the private keys

	BIGNUM* s[MAX_BIT_LENGTH]; // Randomness used during OT 2nd message
	BIGNUM* t[MAX_BIT_LENGTH]; // Randomness used during OT 2nd message


	GroupElement *bitcode[MAX_BIT_LENGTH]; // Bit codes used during the computation stage
	GroupElement *bitCommit[MAX_BIT_LENGTH]; // Commitments to individual bits of bid value
	GroupElement *pubKey[MAX_BIT_LENGTH]; // Public keys
	GroupElement *yCode[MAX_BIT_LENGTH]; // Y_j - used for encoding the 0-bit

	GroupElement zeroBitCode; // Place holder to store zero bit codes during a round


	GroupElement* bidderBitcode[MAX_BIDDERS]; // Place holder to store the bit codes for computation

	BIGNUM * beta[MAX_BIT_LENGTH];          // OT first message randomness
	BIGNUM * invbeta[MAX_BIT_LENGTH];       // Inverse value - used during message retrieval



	// OT first message parameters
	GrpPoint G0[MAX_BIT_LENGTH];
	GrpPoint H0[MAX_BIT_LENGTH];
	GrpPoint G1[MAX_BIT_LENGTH];
	GrpPoint H1[MAX_BIT_LENGTH];
	GroupElement *T;

	// Zero Tokens used to prove that correct choice bit is used for OT
	BIGNUM * omega[MAX_BIT_LENGTH]; // Random value to generate Zero token is picked from Z_q 
	BIGNUM * delta[MAX_BIT_LENGTH]; // Random value to commit to Zero token is picked from Z_q 
	GroupElement *zeroToken[MAX_BIT_LENGTH]; // zeroToken = g^omega
	GroupElement *ztCommit[MAX_BIT_LENGTH]; // Pedersen Commitment to omega - used to generate zeroToken. 
	GroupElement *bidderZToken[MAX_BIDDERS][MAX_BIT_LENGTH]; // Array to store the zero tokens received from other parties.


	pthread_cond_t *cond; // Conditional variable
	pthread_mutex_t *mutex; // Corresponding mutex


	// Bits used during computation by Evaluator					
	uint evalComputeBit[MAX_BIT_LENGTH];
	sem_t eval_thr_sem[MAX_BIDDERS];
	sem_t eval_init_sem[MAX_BIDDERS];
	sem_t eval_sync_sem[MAX_BIDDERS];


	sem_t *bidder_thr_sem; // Semaphore held by the bidder
	sem_t *comp_stg_sem; // Semaphore used during the computation stage
	sem_t *bidder_sync_sem; // Semaphore used by bidder for general sync with Eval
};

#endif
