/* This file contains the main function. The auction program can be started as either a bidder or verifier by 
* passing two parameters: id which is 1-99 and the bid value. 
* The program also takes second argument which is for specifying the bid value.
*
*/

#include <string>
#include "bidder.h"
#include <cmath>
#include <iostream>

int main(int argc, char const *argv[])
{

	const char *type = argv[1];


	PType processType;

	if(argc != 3)
	{
		cout << "Usage: auction id bidvalue" << endl;
		exit(-1);
	}


	if(strcmp(argv[1],"999") == 0)
	{
		//cout << "Process is a Verifier" << endl;
		processType = pVerifier;
	}
	else
	{ 
		//cout << "Process is a Bidder" << endl;
		processType = pBidder;

	}

	auto start = std::chrono::high_resolution_clock::now();
    
    
	//Create a shared memory object. We use the Boost Interprocess library
    shared_memory_object shm (open_or_create, "Bulletin Board", read_write);

    //Set size
    shm.truncate(sizeof(struct BulletinBoard));


    //Map the whole shared memory in this process
    mapped_region region(shm, read_write);

    BulletinBoard *bb = static_cast<BulletinBoard*>(region.get_address());

	uint id = atoi(argv[1]);
	uint size = region.get_size();
	uint bidvalue = atoi(argv[2]);
   	
	// printf("id = %d, size = %d, bidvalue = %d\n", id, size, bidvalue);
	
    switch(processType)
	{
		case pBidder:
		{
			
			Bidder bidder = Bidder((D+100*id), bidvalue, D, ADDR_Verify, id, bb);
			//printf("Entering setup for bidder %d\n",id);

			bidder.protocolSetupStage();
			//printf("Finished setup for bidder %d\n",id);
			bidder.protocolComputeStageBidder();
			


			bidder.protocolVerificationStage();
			
		

			auto st_end = std::chrono::high_resolution_clock::now();

			std::chrono::duration<double, std::milli> st_float_ms = st_end - start;

		    cout << "Total elapsed time is " << 
    		st_float_ms.count() << " ms for bidder " << id << std::endl;
			
			break;	
		}
		case pVerifier:
		{
			//Verify ver = Verify(bb);
			//ver.runVerify();
			
			break;
		}
		default:
			cout << "Unrecognized types" << endl;
	}



	return 0;
}

