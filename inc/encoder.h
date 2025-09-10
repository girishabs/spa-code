#ifndef ENCODER_H
#define ENCODER_H

#include "group.h"
#include "common.h"

//GroupElement publickey[MAX_BIDDERS][MAX_BIT_LENGTH];
//BIGNUM* privateKey[MAX_BIDDERS][MAX_BIT_LENGTH];

class Bidder;

class Encoder
{
public:
	Encoder(Group *group);
	
	~Encoder(){}

	uint oneBitEncode(GroupElement *ret, BIGNUM *r);

	uint zeroBitEncode(GroupElement *ret, BIGNUM *x, uint id, uint round, BulletinBoard* bb);


	uint computeZeroBase(GroupElement *ret, uint id, uint round, BulletinBoard* bb);
	
	bool decodeBitcode(uint j, Bidder* bidder);

	bool checkAddition(EC_POINT *e1, EC_POINT *e2, EC_POINT *e3);

	void checkGenMult(void);



private:
	Group *grp;
	GroupElement *g;
};

#endif
