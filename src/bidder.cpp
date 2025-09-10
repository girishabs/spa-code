/*
 * This source file implements the SPA protocol. The protocol is divided into various phases as in the paper: https://eprint.iacr.org/2024/1011.
 */ 
#include <iostream>
#include <cstdlib>
#include <pthread.h>
#include <boost/interprocess/ipc/message_queue.hpp>


#include "common.h"
#include "bidder.h"
#include "nizk.h"

using namespace boost::interprocess;


/* This procedure implements the setup stage of the protocol. It proceeds as follows:
 * After obtaining the public parameters, bidder initializes its internal parameters.
 * Generates the commitment for bits of its private bid value.
 * Selects private keys for the auction rounds.
 * Generates corresponding public keys. 
 * Write commitments and public keys on to the bulletin board.
*/
PStage Bidder::protocolSetupStage()
{
    //printf("Bid value for bidder %d is %X\n", id, bidval);
    

    bid = BN_new();
    BN_set_word(bid, bidval);
    //printf("The bid value is:\n");
    //BN_print_fp(stdout, bid);
    //cout << endl;
#ifdef DEBUG    
    printBidBits();
#endif

    BN_set_word(bid, bidval);
    

    GroupElement e = GroupElement(grp);

    // Generate Public/Private keys for each round
    for(int j = 0; j < MAX_BIT_LENGTH; j++)
    {

        
        x[j] = grp->getRandomNumber() ;
        r[j] = grp->getRandomNumber() ;

        grp->power(pubKey[j], grp->g, x[j]); //pubKey = g^x

        bidderBB->pubKey[j] = pubKey[j]->gpt; // Write public keys to BB
        
        // printf("Bidder public key [%d][%d]:\n",id,j);
        // e.printGroupPoint(&bidderBB->common.pubKey[j]);
        // printf("Bidder private key [%d]:\n",j);
        // BN_print_fp(stdout, x[j]);
        // cout << endl;    
    }

    initBidder();

    
    
    bb->setupStageDone[id] = true;

    
    for(uint i = 0; i < MAX_BIDDERS; i++)
    {
        // printf("Bidder %d Waiting for bidder %d\n",id,i);
        while(!bb->setupStageDone[i]) 
            usleep(1);    
    }
	return computeStage;
 
}


struct thread_data
{
    uint id; // Bidder who owns the threads
    uint i; // Bidder id
    uint j; // auction round
    bool bit; // Bit being encoded
    Bidder *bidder; // Pointer to Bidder class.
};

// The following function initializes the Bidder object
void Bidder::initBidder()
{

    //printf("Entering initBidder\n");

    auto ststart = std::chrono::high_resolution_clock::now();
    
    // Allocate OT parameters and write them on to BB
    BIGNUM *num;
    GroupElement e  = GroupElement(grp);  
    GroupElement f  = GroupElement(grp);  


    uint rc = 0, i, j;

    for(i = 0; i < MAX_BIDDERS; i++)
    {

        for(j = 0; j < MAX_BIT_LENGTH; j ++)
        {
            beta[j] = grp->getRandomNumber();
            invbeta[j] = BN_new();
            BN_sub(invbeta[j],grp->q,beta[j]);

            num = grp->getRandomNumber() ;
            auto pstart = std::chrono::high_resolution_clock::now();

            grp->power(&f, grp->g, num); // Choose random num from Z_q and raise g^num to get zeta.

            bidderBB->zeta[j] = f.gpt; // Write zeta values to BB
                
            grp->power(&e,grp->g, beta[j]); // G0 = g^beta
            G0[j] = e.gpt;


            grp->elementMultiply(&e, &e, &f); // G1 = G0.zeta = g^beta.zeta
            G1[j] = e.gpt;
                
            grp->power(&e,grp->h, beta[j]); // H0 = h^beta
            H0[j] = e.gpt;

            grp->elementMultiply(&e, &e, grp->T1); // H1 = H0.T1 = h^beta.T1
            H1[j] = e.gpt;

            // Pick random values for zeroToken and its commitment
            omega[j] = grp->getRandomNumber(); 
            delta[j] = grp->getRandomNumber();

            grp->power(zeroToken[j], grp->g, omega[j]); // Choose random num from Z_q and raise g^omega to get zeroToken.
            grp->power(&f, grp->h, delta[j]); // Choose random num from Z_q and raise h^num to generate commitment.

            grp->elementMultiply(&e, &f, zeroToken[j]); // ztCommitment = g^omega . h^delta
            bidderBB->ztCommit[j] = e.gpt; // Copy the commitment to BB


        }
        
    
    }



    
    for(i = 0; i < MAX_BIDDERS; i++)
    {
        bidderBitcode[i] = new GroupElement(grp);    
    } 


    for(j = 0; j < MAX_BIT_LENGTH; j++)
    {
        // Need to generate commitments for each bit in the bid.
        // The Pedersen commitments for jth bit are of the form: cj = g^bj . h^aj

        a[j] = grp->getRandomNumber();
        grp->power(bitCommit[j], grp->h, a[j]);

        if(bitsOfBid[j])
            grp->elementMultiply(bitCommit[j], grp->g, bitCommit[j]); // cj = g . h^aj
        
        bidderBB->bitCommit[j] = bitCommit[j]->gpt;

    }
 
    


}



void * OldOTUpdate(void *input)
{
    struct thread_data *td = (struct thread_data *) input;
    uint id = td->id;
    uint i = td->i;
    uint j = td->j;

    Bidder *bidder = (Bidder *)td->bidder;

    //cout << "Inside thread " << i<< " for bidder " << id << " j = " << j << endl;
    //bidder->grp->printGroupElement(bidder->grp->g);
    //bidder->grp->power(&e,bidder->grp->g, bidder->beta[i][j]);
    //BN_print_fp(stdout, bidder->beta[i][j]);
    //cout << endl;

    if(td->bit == 0) // OT params for choice bit = 0
    {
        bidder->bidderBB[id].G[j] = bidder->G0[j] ; 

        bidder->bidderBB[id].H[j] = bidder->H0[j] ; 

    }
    else if(td->bit == 1) // OT params for choice bit = 1
    {
        bidder->bidderBB[id].G[j] = bidder->G1[j] ;    
        bidder->bidderBB[id].H[j] = bidder->H1[j] ; 
    }
    GroupElement *e  = new GroupElement(bidder->grp, &bidder->bidderBB[id].G[j]);   
    GroupElement *f  = new GroupElement(bidder->grp, &bidder->bidderBB[id].H[j]);   

#ifdef DEBUG
    printf("Values of G and H %d,%d are:\n", i,j);
    bidder->grp->printGroupElement(e);
    bidder->grp->printGroupElement(f);
#endif    

    bidder->bb->OTParamsUpdated[id][j] = true;   

    BBMemoryBidder *bidderBB = static_cast<struct BBMemoryBidder *>(&bidder->bb->bidderBB[i]);

// Now wait for individual bidders to get back     

    //printf("Inside thread %d\n",i);

    char name[16];
    sprintf(name, "bidderSyn-%d",i); // Each semaphore has a name of the form "bidder-<id>". E.g.: Bidder 12 has name "bidder-12"


    sem_t *sem = sem_open(name, O_CREAT, 0777, 0);
    if(sem == SEM_FAILED)
    {
        perror("sem: Semaphore creation failed");
    }
    //sem_wait(sem); // Wait to hear back from bidder i

    int sval = 0;
    sem_getvalue(sem, &sval);
    //printf("Value of sync semaphore %d is %d\n", i, sval);
    

    sem_post(&bidder->eval_thr_sem[i]); // Increment the counting semaphore

    pthread_exit(NULL);    
}

void * OTUpdate(void *input)
{
    struct thread_data *td = (struct thread_data *) input;
    uint id = td->id;
    uint i = td->i;
    uint j = td->j;

    Bidder *bidder = (Bidder *)td->bidder;
    Group *grp = bidder->grp;

    GroupElement e  = GroupElement(grp);   
    GroupElement f  = GroupElement(grp);

    //cout << "Inside thread " << i<< " for bidder " << id << " j = " << j << endl;
    //bidder->grp->printGroupElement(bidder->grp->g);
    //bidder->grp->power(&e,bidder->grp->g, bidder->beta[i][j]);
    //BN_print_fp(stdout, bidder->beta[i][j]);
    //cout << endl;

    GroupElement zeta_i = GroupElement(grp, &bidder->bb->bidderBB[i].zeta[j]);
    grp->getInverse(&zeta_i); // We are not going to use zeta; Only its inverse is useful

    GroupElement G_ij = GroupElement(grp, &bidder->bb->bidderBB[i].G[j]);
    GroupElement H_ij = GroupElement(grp, &bidder->bb->bidderBB[i].H[j]);


    grp->elementMultiply(&e, &G_ij, &zeta_i); // Perform (G/zeta)
    grp->elementMultiply(&f, &H_ij, grp->invT1); // Perform (H/T1)

    // s and t values are that of sender, bidder[id]

    grp->power(&e, &e, bidder->s[j]); // Perform (G/zeta)^s
    grp->power(&f, &f, bidder->t[j]); // Perform (H/T1)^t 

    grp->elementMultiply(&e, &e, &f);
    grp->elementMultiply(&e, &e, bidder->bitcode[j]);

    // Send OT messages to other parties
    bidder->bb->bidderBB[i].OTPostBox_1[id][j] = e.gpt; // Post the OT message to Bidder_i's postbox, at the entry (id,j)


    // Similarly encoding for M_0 is: C_0 = (G)^s . (H)^t . zeroToken_ij (where zeroToken_ij is the 0-token for j'th round.   

    grp->power(&e, &G_ij, bidder->s[j]); // Perform (G)^s
    grp->power(&f, &H_ij, bidder->t[j]); // Perform (H)^t 

    grp->elementMultiply(&e, &e, &f);
    grp->elementMultiply(&e, &e, bidder->zeroToken[j]);



    bidder->bb->bidderBB[i].OTPostBox_0[id][j] = e.gpt; // Post the OT message to Bidder_i's postbox, at the entry (id,j)    

    pthread_exit(NULL);    
}

/* This procedure implements the computation stage of the protocol - for the bidder.
 * The bidder computes the ABP bit.
 * Uses BES to enode the bit to generate the bit code.
 * Generates the OT encryption for the bit, using the randomness shared by Eval.
 * Writes the encrypted messages for msg-0 and msg-1 of OT to the BB
 *  
*/
PStage Bidder::protocolComputeStageBidder()
{
    bool testBit ;
    int rc;
    int number;
    unsigned int priority;
    message_queue::size_type recvd_size;

    for(uint j = 0; j < MAX_BIT_LENGTH; j++)
    {    
            
        GroupElement e  = GroupElement(grp);   
        GroupElement f  = GroupElement(grp);

      

        if(highestBidder) 
            computeBit[j] = true; // Highest bidder sends only 1-bit codes through OT
        else
            computeBit[j] = getABPbit(j);

        if (computeBit[j])
        {
            enc->oneBitEncode(bitcode[j], r[j]);
            enc->computeZeroBase(yCode[j], id, j, bb);
            
            // printf("Constructed onebitcode[%d][%d] is :\n",id,j);            
        }
        else 
        {
            enc->computeZeroBase(yCode[j], id, j, bb);
            enc->zeroBitEncode(bitcode[j], x[j],id,j, bb); 
            // printf("Constructed zerobitcode[%d][%d] is :\n",id,j);
        }

        // grp->printGroupElement(bitcode[j]);

        if(computeBit[j] == 0) // OT params for choice bit = 0
        {
            bidderBB->G[j] = G0[j] ; 

            bidderBB->H[j] = H0[j] ; 

        }
        else if(computeBit[j] == 1) // OT params for choice bit = 1
        {
            bidderBB->G[j] = G1[j] ;    
            bidderBB->H[j] = H1[j] ; 
        }
     

        bb->OTParamsUpdated[id][j] = true;   

// Run OT to send  the bit code to other bidders
        struct thread_data td[MAX_BIDDERS];
        pthread_t threads[MAX_BIDDERS];

        for(uint i = 0; i < MAX_BIDDERS; i++)
        {
                        
            if (i == id)
                continue; // No need to consider self.
            

            while(bb->OTParamsUpdated[i][j] != true) // Wait for Bidder i to update the OT parameters.
                usleep(1);

            // Retrieve the OT parameters for bidder[i] (to whom bidder[id] needs to send): zeta, G, H



            GroupElement zeta_i = GroupElement(grp, &bb->bidderBB[i].zeta[j]);
            grp->getInverse(&zeta_i); // We are not going to use zeta; Only its inverse is useful

            GroupElement G_ij = GroupElement(grp, &bb->bidderBB[i].G[j]);
            GroupElement H_ij = GroupElement(grp, &bb->bidderBB[i].H[j]);

        
            grp->elementMultiply(&e, &G_ij, &zeta_i); // Perform (G/zeta)
            grp->elementMultiply(&f, &H_ij, grp->invT1); // Perform (H/T1)

            // s and t values are that of sender, bidder[id]

            grp->power(&e, &e, s[j]); // Perform (G/zeta)^s
            grp->power(&f, &f, t[j]); // Perform (H/T1)^t 

            grp->elementMultiply(&e, &e, &f);
            grp->elementMultiply(&e, &e, bitcode[j]);

            // Send OT messages to other parties
            bb->bidderBB[i].OTPostBox_1[id][j] = e.gpt; // Post the OT message to Bidder_i's postbox, at the entry (id,j)


            // Similarly encoding for M_0 is: C_0 = (G)^s . (H)^t . zeroToken_ij (where zeroToken_ij is the 0-token for j'th round.    
            grp->power(&e, &G_ij, s[j]); // Perform (G)^s
            grp->power(&f, &H_ij, t[j]); // Perform (H)^t 

            grp->elementMultiply(&e, &e, &f);
            grp->elementMultiply(&e, &e, zeroToken[j]);



            bb->bidderBB[i].OTPostBox_0[id][j] = e.gpt; // Post the OT message to Bidder_i's postbox, at the entry (id,j)
                          


        
        }    
     

        bb->sentBitCodes[id][j] = true;



        
        
        // Having sent the j'th bit code to all other bidders, receive the bit codes from other bidders
        //printf("Bidder %d is contributing a 1 bit in round %d. So need to check what others have.\n",id,j);
        for(uint i = 0; i < MAX_BIDDERS; i++)
        {
            if(i == id)
            {
                enc->zeroBitEncode(bidderBitcode[i],x[j],id,j, bb); // Copy own zero bit for this round code to i'th position where i = id
                continue; // Ignore self
            }
            // printf("Bidder %d is waiting for bidder %d to send bit code in round %d\n",id, i,j);
     

            while(bb->sentBitCodes[i][j] == false)
                usleep(1); // Wait for all other bidders to send their bit codes    

            // Receive the OT message from other senders

            GroupElement z  = GroupElement(grp, &bb->bidderBB[i].z[j]); // Retrive the value of z for this round for bidder[i]
            GroupElement a  = GroupElement(grp);
            grp->power(&a,&z,invbeta[j]);

            if(computeBit[j])
            {                    
                GroupElement C1 = GroupElement(grp, &bidderBB->OTPostBox_1[i][j]); // Retrieve the message C1 (bit code) sent by bidder[i] for round j
            
                grp->elementMultiply(bidderBitcode[i],&C1,&a); // Retrieve bitcode from i'th party
                // printf("The received bit code[%d][%d] is:\n",i,j);
                // grp->printGroupElement(bidderBitcode[i]);
            }

            else
            {            
                GroupElement C0 = GroupElement(grp, &bidderBB->OTPostBox_0[i][j]); // Retrieve the message C0 (0-token) sent by bidder[i] for round j                
                grp->elementMultiply(bidderZToken[i][j],&C0,&a); // Retrieve zeroToken from i'th party            
            }


        }
        if(computeBit[j]) 
        {        
            // Compute the winning bit by setting own bit code to 0.
            // If the winning bit is 1, that means, some other party is also contributing a 1 bit code in this round
            // Else if winning bit is 0, that means, the party is indeed the winner
            
            testBit = enc->decodeBitcode(j, this); 
            // printf("testBit computed by %d in round %d is %d\n", id, j, testBit);
            if((testBit == false) && (highestBidder == false) && (computeBit[j] == true))
            {
                printf("Bidder %d is the highest bidder\n", id);
                highestBidder = true;
            }
        }

        if(highestBidder) 
        {
            // Write the same bitcode to BB as that of second highest bidder - i.e. bit code for testBit
            if(testBit)
            {
                //printf("Winner is writing 1 in round %d\n",j);
                enc->oneBitEncode(bitcode[j], r[j]);
            }
            else
            {
                //printf("Winner is writing 0 in round %d\n",j);
                enc->zeroBitEncode(bitcode[j], x[j],id,j, bb); 

            }
        }


        // Write the bit code to BB
        bb->bidderBB[id].bitCode[j] = bitcode[j]->gpt;
        //printf("Bidder %d: Written Bit code[%d][%d] is:\n",id, id,j);
        //grp->printGroupElement(bitcode[j]);

      

        bb->updatedBB[id][j] = true;

        //printf("Bidder %d has updated updatedBB flag in round %d\n",id, j);

        // Wait till all bidders have written to BB
        for(uint i = 0; i < MAX_BIDDERS; i++)
        {
            if(i == id)
                continue;
            //printf("Bidder %d is waiting for bidder %d to write bit code to BB in round %d\n",id, i,j);
      

            while(!bb->updatedBB[i][j])
                usleep(1);
                //sleep(1);
        }
        

        // Compute the winning bit for this round
        for(uint i = 0; i < MAX_BIDDERS; i++)
        {
            delete bidderBitcode[i]; // Cleanup the existing bit codes and get afresh from BB 
            bidderBitcode[i] = new GroupElement(grp, &bb->bidderBB[i].bitCode[j]);

            //printf("Bidder %d: Retrieved Bit code[%d][%d] is:\n",id, i,j);
            //grp->printGroupElement(bidderBitcode[i]);

        }    

        winBit[j] = enc->decodeBitcode(j, this);

        //if(highestBidder)

            //printf("Bidder %d: Winning bit for round %d is %d\n",id, j, winBit[j]);

    
        if((winBit[j] == 1) && (computeBit[j] == false) && (highestBidder == false))
            auctionLost = true;
        //cout << "Round " << j << " is completed for bidder " << id << endl;
        
    }

    uint winBid = 0;
    
    for(uint j = 0; j < MAX_BIT_LENGTH; j++)
    {
        //printf("%d\t",winBit[j]);
        if(winBit[j])
        {
            winBid = winBid + exp(2, MAX_BIT_LENGTH-j-1);
        }
        //printf("Computed winning bid value is %d\n", winBid);
    }
    
    printf("Second highest bid value computed by bidder %d is %d\n", id, winBid);

	return verifyStage;
}


void Bidder::protocolVerificationStage()
{
    uint i, j, k;
    /* 
    // At this stage auction is complete. The winner needs to provide the range proof that 
    // her bid value is higher than computed bid value.
    // Losing bidders provide the zero tokens for the rounds that have computed output to be zero.
    // Losing bidders also provide NIZK of correct computation for the rounds that have computed output to be one.
    */

    if(highestBidder) // Winner
    {
        // Prepare a range proof
        bb->winnerClaim = id; // Claim victory
        sem_post(bidder_sync_sem);
        bb->verifyStageDone[id] = true;
        
        bb->zeroTokenProduced[id] = true;

        return;
    }
    
    // Produce zero tokens for the rounds with computed bit 0
    for(j = 0; j < MAX_BIT_LENGTH; j++)
    {
        if(winBit[j])
            continue;

        bidderBB->zeroToken[j] = zeroToken[j]->gpt;
    }
    bb->zeroTokenProduced[id] = true;

    for(i = 0; i <MAX_BIDDERS; i++)
    {
        if(i == id)
            continue;
        // printf("Bidder %d waiting for bidder %d to write zero token %d\n", id, i, bb->zeroTokenProduced[i]);
        while(bb->zeroTokenProduced[i] != true) // Wait till ith bidder has produced the token.    
            usleep(10);
    }
    for(j = 0; j < MAX_BIT_LENGTH; j++)
    {
        BN_bn2bin(delta[j], bidderBB->ztDelta[j]); // Reveal the randomness used for commitment of tokens
        bidderBB->zeroToken[j] = zeroToken[j]->gpt;
    }
    // printf("Done with zero tokens\n");

    // Prepare NIZK proofs for each round which has computed output to be 1

    NIZKProof prf(grp);

    ProofData *pData = new ProofData;

    uint proofIndex, prevDeciderRnd = 0; // To indicate the proof to be generated

    

    for(j = 0; j < MAX_BIT_LENGTH; j++)
    {

        if(winBit[j] == false)
        {

            continue;
        }
        if(winBit[j] == 1 && prevDeciderRnd == 0) // There has been no decider round so far
            prevDeciderRnd = j;
        
        // printf("Bidder %d: computeBit[%d] = %d, winBit[%d] = %d, prevDeciderRnd = %d, bitsOfBid[%d]=%d\n", id, j, computeBit[j], j, winBit[j], prevDeciderRnd, j, bitsOfBid[j]);

        pData->cj = bitCommit[j];
        pData->Bj = bitcode[j];
        pData->Bj_prev = bitcode[prevDeciderRnd];
        pData->Yj = yCode[j];
        pData->Yj_prev = yCode[prevDeciderRnd];
        pData->Xj = pubKey[j];
        pData->Xj_prev = pubKey[prevDeciderRnd];

        pData->aj = a[j];
        pData->xj = x[j];
        pData->xj_prev = x[prevDeciderRnd];
        pData->rj = r[j];
        pData->rj_prev = r[prevDeciderRnd];


        if((computeBit[j] == 0) && (bitsOfBid[j] == 0))
        {
            proofIndex = 0;        
        }
        else if((computeBit[j] == 1) && (bitsOfBid[j] == 1))
        {
            proofIndex = 1;
        }
        else if((computeBit[j] == 0) && (bitsOfBid[j] == 1))
            proofIndex = 2;
    
        if(winBit[j] == 1)
            prevDeciderRnd = j;


        for(k = 0; k < NUM_PROOF_CLAUSES; k++)
        {
            if(k == proofIndex)
            {
                pData->wRand[k] = BN_new();
                BN_zero(pData->wRand[k]);
            }
            else
                pData->wRand[k] = grp->getRandomNumber();

        }
        for(k = 0; k < NUM_RAND; k ++)
        {
            pData->vRand[k] = grp->getRandomNumber();

        }



        prf.generateNIZKProof(pData);

        // Write the proof to BB
        for(k = 0; k < NUM_PROOF_CLAUSES; k++)
        {
            BN_bn2bin(prf.pPack.gamma[k], bidderBB->pPack[j].gamma[k]);        
        }
        
        for(k = 0; k < NUM_RAND; k++)
        {
            BN_bn2bin(prf.pPack.sToken[k], bidderBB->pPack[j].sToken[k]);    
        }

        // Retrieve the proof from BB
        NIZKProof vrfyPrf(grp);

        for(k = 0; k < NUM_PROOF_CLAUSES; k++)
        {
            BN_bin2bn(bidderBB->pPack[j].gamma[k],MAX_BIG_NUM_SIZE,vrfyPrf.pPack.gamma[k]);                
        }
        
        for(k = 0; k < NUM_RAND; k++)
        {
            BN_bin2bn(bidderBB->pPack[j].sToken[k],MAX_BIG_NUM_SIZE,vrfyPrf.pPack.sToken[k]);    
        }


        if(prf.verifyNIZKProof(pData, &prf.pPack))
        {
            printf("*******NIZK proof succeeds********\n\n\n");
        }
        else 
            printf("*****NIZK proof rejected******\n\n\n");
    }


}






void Bidder::printBuffer(unsigned char *buffer, uint n)
{
    cout << endl;
    for(uint k = 0; k < n; k++)
    {
        printf("%0X", buffer[k]);
    }
    cout << endl;
}
