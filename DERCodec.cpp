#include "DERCodec.h"
#define UNIVERSAL_PRIMITIVE_INTEGER 0x02

char DERCodec::getByte(unsigned int N)
{
        char ch = 0x00;
                        int mask = 0x80;
                        for(int i=0;i<8;i++)
                                {
                                        ch<<=1;
                                        if((N&mask)!=0)
                                                ch|=0x01;
                                        mask>>=1;
                                }
return ch;
}

vector<char> DERCodec::wrapSequence(vector<char> bs) {
	return DERCodec::wrapType(bs, SEQUENCE);
}

vector<char> DERCodec::wrapType(vector<char> byteStream, DERType tp ) {
vector<char> finalStream;
char ch = 0x30; /* Universal non primitive ( SEQUENCE ) */

unsigned int bLen = byteStream.size();

if(tp == INTEGER)
	{
		ch = 0x02;
		finalStream.push_back(ch);
	}
else if(tp == BITSTRING)
	{
		ch = 0x03;
		finalStream.push_back(ch);
	}
else if(tp == SEQUENCE)
        {
                ch = 0x30;
                finalStream.push_back(ch);
        }
else if(tp == T61STRING)
        {
		ch = 0x0E;
		finalStream.push_back(ch);
        }
else {
	cerr<<"ERROR!! - Unable to Wrap Type :unknown DERType"<<endl;
	}
	

if(bLen<=127) {
		cout<<"encoding short form "<<bLen<<endl;
                ch = getByte(bLen);
                finalStream.push_back(ch);
        }
/*else if(bLen<=255){
		cout<<"encoding Long form 1Byte"<<bLen<<endl;
                ch = 0x81;
                finalStream.push_back(ch);
                ch = getByte(bLen);
                finalStream.push_back(ch);
}*/
else if(bLen<=65535)
         {      /* Long Form - look at 2 more bytes*/
		cout<<"encoding Long form 2Byte"<<bLen<<endl;
                ch = 0x82;
                finalStream.push_back(ch);
                ch = getByte(bLen>>8);
                finalStream.push_back(ch);
                ch = getByte(bLen);
                finalStream.push_back(ch);
         }
else {
                /* Long form - look at 3 more bytes(anything more is insane)*/
		cout<<"encoding Long form 3Byte"<<bLen<<endl;
                ch = 0x83;
                finalStream.push_back(ch);
                ch = getByte(bLen>>16);
                finalStream.push_back(ch);
                ch = getByte(bLen>>8);
                finalStream.push_back(ch);
                ch = getByte(bLen);
                finalStream.push_back(ch);
        }

/*if(tp == BITSTRING)
	{
		ch = 0x00;
		finalStream.push_back(ch);
	}
*/

for(int i=0;i<byteStream.size();i++)
        finalStream.push_back(byteStream[i]);

return finalStream;
}

string DERCodec::getBitStr(char N)
{
string bstr = "";
int mask = (1<<7);
        for(int i=0;i<8;i++,mask>>=1)
                {
                        if(N&mask)
                                bstr+="1";
                        else bstr+="0";
                }
return bstr;
}

/* Get the Tag */
int DERCodec::getTag(vector<char> byteStream, int &pos) {

        char curByte = byteStream[pos];
        /*if(dbg) cout<<DERCodec::getBitStr(curByte)<<" : "<<int(curByte)<<endl;

if((curByte&(1<<7)) || (curByte&(1<<6)));
else
        if(dbg) cout<<" Universal "<<endl;
	*/

        int tag = curByte&(0x1F);
        pos++;
        //if(dbg) cout<<"Tag number is "<<tag<<" and pos is "<<pos<<endl;
        return tag;
}

unsigned int DERCodec::getFieldLength(vector<char> byteStream, int &pos, int& len){
        len = pos;
        char curByte = byteStream[pos];
        unsigned int lengthOfSeq = 0;

        if((curByte & 0x80) == 0 )
        {
                //Data is in Short form
                lengthOfSeq = ( curByte & 0x7F );
        }
        else
        {
                //Data in Long Form
                int fieldSizeLookup = ( curByte & 0x7F );

                //if(dbg) cout<<" Field Length : ";
                for(int i=0;i<fieldSizeLookup;i++)
                {
                        pos++;
                        curByte = byteStream[pos];
                        int mask = 0x80;
                        for(int i=0;i<8;i++)
                                {
                                        lengthOfSeq<<=1;
                                        if((curByte&mask)!=0)
                                                lengthOfSeq|=0x01;
                                        mask>>=1;
                                }

                        /*lengthOfSeq<<=8;
                        lengthOfSeq|=curByte;*/
                        //if(dbg) cout<<DERCodec::getBitStr(curByte)<<"("<<lengthOfSeq<<")";
                }
        }
        pos++;
        //if(dbg) cout<<"returning length of dataType as "<<lengthOfSeq<<" and pos is "<<pos<<endl;
        len = pos - len;
        return lengthOfSeq;
}

vector<char> DERCodec::getPrimitiveByteStream(berMpzClass dat) {
vector<char> byteStream;
char ch;
ch = UNIVERSAL_PRIMITIVE_INTEGER;
byteStream.push_back(ch);

int len = dat.getLen();
if(len<=127) {
                ch = DERCodec::getByte(len);
                byteStream.push_back(ch);
        }
/*else if(len<=255){
		ch = 0x81;
                byteStream.push_back(ch);
                ch = getByte(len);
                byteStream.push_back(ch);
}*/
else if(len<=65535)
         {      /* Long Form - look at 2 more bytes*/
                ch = 0x82;
                byteStream.push_back(ch);
                ch = DERCodec::getByte(len>>8);
                byteStream.push_back(ch);
                ch = DERCodec::getByte(len);
                byteStream.push_back(ch);
         }
else {
                /* Long form - look at 3 more bytes(anything more is insane)*/
                ch = 0x83;
                byteStream.push_back(ch);
                ch = DERCodec::getByte(len>>16);
                byteStream.push_back(ch);
                ch = DERCodec::getByte(len>>8);
                byteStream.push_back(ch);
                ch = DERCodec::getByte(len);
                byteStream.push_back(ch);
        }
/* get content byte stream and append here */
vector<char> bigNumStream = dat.getByteStream();
for(int i=0;i<bigNumStream.size();i++)
        byteStream.push_back(bigNumStream[i]);

return byteStream;
}

berMpzClass DERCodec::extractBigInteger(vector<char> byteStream, int& pos, int lenOfType) {
        string bitStr = "";
        for(int i=0;i<lenOfType;i++)
                {
                        bitStr+= DERCodec::getBitStr(byteStream[pos]);
                        pos++;
                }
        berMpzClass bigNum = berMpzClass(bitStr, 2, lenOfType);
        return bigNum;
}

