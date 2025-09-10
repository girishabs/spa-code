#ifndef GROUP_H
#define GROUP_H

#include <openssl/obj_mac.h>

#include <openssl/ec.h>

#define MAX_BIG_NUM_SIZE 32

using namespace::std;

class Group;
class GroupElement;
class Encoder;
typedef struct t_grpPoint
{
	unsigned char gx[MAX_BIG_NUM_SIZE];
	uint xn;
	unsigned char gy[MAX_BIG_NUM_SIZE];
	uint yn;
} GrpPoint;

typedef unsigned char zqPoint[MAX_BIG_NUM_SIZE];

class GroupElement
{
public:
	GroupElement(){}
	

	GroupElement(EC_POINT *element, Group *_grp);
	GroupElement(Group *_grp, GrpPoint *_gpt);
	GroupElement(Group* grp);
	~GroupElement()	
	{
		EC_POINT_clear_free(ep);

	}
	void setPoint();

	void gPrint(unsigned char *c, uint num);
	void printGroupPoint(GrpPoint *gpt);

	
	EC_POINT *ep;
	Group *grp;
	GrpPoint gpt;

private:
	
	friend class Group;
	friend class Encoder;

};

class Group
{
public:

		friend class GroupElement;
		friend class Encoder;

		~Group()
		{
			delete g;
			delete h;
			delete ident;
			delete g1;
			BN_free(q);
		}


		/*
		 * nid: NID of the curve
		 */
		
		Group(int nid )
		{
			ecg = EC_GROUP_new_by_curve_name(nid);
			initGroup();
		}
	

		void initGroup();
		
		
		uint power(GroupElement *ret, GroupElement *g, BIGNUM *r);

		GroupElement* getRandomGroupElement();
		int getGroupDegree();
		GroupElement* GroupMultiply(GroupElement base, const BIGNUM *exp);
		uint elementMultiply(GroupElement *ret, GroupElement *a, GroupElement *b);

		GroupElement *multiElementMultiply(GroupElement* gelem[], uint id);
		uint compareElements(GroupElement *a, GroupElement *b);

		void printGroupElement(GroupElement *p);
		
		BIGNUM * getRandomNumber();

		uint getInverse(GroupElement *element);
		void printECPoint(EC_POINT* ep);
		void printGroupParams();
		void dupGroupElement(GroupElement *d, GroupElement *s);
		void chooseNUMSPoints();

		void eval(BIGNUM* x, BIGNUM* y);



		GroupElement *g; //generator
		GroupElement *g1; //second generator
		GroupElement *h; //Group Element used for Commitments
		GroupElement *T1; // Group Element used for OT
		GroupElement *invT1; // Group Element used for OT

		GroupElement *ident;

		BIGNUM *q;
		int numBitsInOrder;
		EC_GROUP *ecg;


private:
	Group()	{} // Default constructor not accessible
	


};
#endif
