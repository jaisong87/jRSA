#include "X509.h"
#include <ctime>

// Get current date/time, format is YYYY-MM-DD.HH:mm:ss
std::string currentDateTime() {
    time_t     now = time(0);
    struct tm  tstruct;
    char       buf[80];
    tstruct = *localtime(&now);
    // Visit http://www.cplusplus.com/reference/clibrary/ctime/strftime/
    // for more information about date/time format
    strftime(buf, sizeof(buf), "%Y%m%d" /*.%X"*/, &tstruct);

	string curTm = string(buf);
    return curTm.substr(2);
}


X509::X509(vector<char> byteStream) {
int pos1 = 0;
int len1 = byteStream.size();
string hexdump = DERCodec::extractBigInteger(byteStream, pos1, len1).getRsaHexStr();
//cout<<hexdump<<endl;
	
	int pos = 0;
	int tag =  DERCodec::getTag(byteStream, pos);
	int len = DERCodec::getFieldLength(byteStream, pos, len);
	
	vector<char> seq1 = DERCodec::extractSequence(byteStream, pos, len);
	//cout<<" pos is : "<<pos<<" and size is "<<len1<<endl;
	

	pos = 0;
	tag =  DERCodec::getTag(seq1, pos);
	len = DERCodec::getFieldLength(seq1, pos, len);
	vector<char> seq2 = DERCodec::extractSequence(seq1, pos, len);
	pos -= len;
	hexdump = DERCodec::extractBigInteger(seq1, pos, len).getRsaHexStr();
	//cout<<"Seq2 : "<<hexdump<<endl;
	
	pos = 0;
	tag =  DERCodec::getTag(seq2, pos); /* some null tag ( could be some optional field ) */
	if(tag == 0 )
		{
		pos++;

     		/* get Version*/ 	
		tag =  DERCodec::getTag(seq2, pos);
		}

        len = DERCodec::getFieldLength(seq2, pos, len);
	version = DERCodec::extractBigInteger(seq2, pos, len);
     
	/* get serialNumber*/ 	
	tag =  DERCodec::getTag(seq2, pos);
        len = DERCodec::getFieldLength(seq2, pos, len);
	serialNum = DERCodec::extractBigInteger(seq2, pos, len);
	
	cout<<"Version : "<<version.getData()<<endl;
	cout<<"Serial Number : "<< serialNum.getRsaHexStr()<<endl;

	/* SHA1 with RSA encryption */
	tag = DERCodec::getTag(seq2, pos);
        len = DERCodec::getFieldLength(seq2, pos, len);
	//cout<<"Next Tag : "<<tag<<" len : "<<len<<endl;
	berMpzClass tmp = DERCodec::extractBigInteger(seq2, pos, len);
	if( tmp.getRsaHexStr().find("06:09:2a:86:48:86:f7:0d:01:01:05:05:00") != string::npos )
		cout<<"    Signature Algorithm : sha1WithRSAEncryption"<<endl;
	else 
		cout<<"    Signature Algorithm :"<<tmp.getRsaHexStr()<<endl;
	//06:09:2a:86:48:86:f7:0d:01:01:05:05:00

	/* What Next ??*/
	tag = DERCodec::getTag(seq2, pos);
        len = DERCodec::getFieldLength(seq2, pos, len);
	//cout<<"Next Tag : "<<tag<<" len : "<<len<<" remaining : "<<seq2.size()-pos<<endl;
	tmp = DERCodec::extractBigInteger(seq2, pos, len);
	//cout<<"Issuer : "<<tmp.getRsaHexStr()<<endl;
		
	tag = DERCodec::getTag(seq2, pos);
        len = DERCodec::getFieldLength(seq2, pos, len);
	//cout<<"Next Tag : "<<tag<<" len : "<<len<<" remaining : "<<seq2.size()-pos<<endl;
	//tmp = DERCodec::extractBigInteger(seq2, pos, len);
	//cout<<"Validity : "<<endl<<tmp.getRsaHexStr()<<endl;
	vector<char> validitySeq = DERCodec::extractSequence(seq2, pos, len);
		int vpos, vlen;
		vpos = vlen = 0;
		tag = DERCodec::getTag(validitySeq, vpos);
	        vlen = DERCodec::getFieldLength(validitySeq, vpos, vlen);
		string from = DERCodec::extractBigInteger(validitySeq, vpos, vlen).getASCIIStr();
		cout<<" Not Before : "<<from<<endl;
		fromDate = from.substr(0,6);

		tag = DERCodec::getTag(validitySeq, vpos);
	        vlen = DERCodec::getFieldLength(validitySeq, vpos, vlen);
		string till = DERCodec::extractBigInteger(validitySeq, vpos, vlen).getASCIIStr();
		cout<<" Not After : "<<till<<endl;
		toDate = till.substr(0,6);
	
		//cout<<"Current Time : "<<currentDateTime()<<endl;		

	tag = DERCodec::getTag(seq2, pos);
        len = DERCodec::getFieldLength(seq2, pos, len);
	//cout<<"Next Tag : "<<tag<<" len : "<<len<<" remaining : "<<seq2.size()-pos<<endl;
	tmp = DERCodec::extractBigInteger(seq2, pos, len);
	//cout<<"Subject : "<<tmp.getRsaHexStr()<<endl;	

	tag = DERCodec::getTag(seq2, pos);
        len = DERCodec::getFieldLength(seq2, pos, len);
	//cout<<"Next Tag : "<<tag<<" len : "<<len<<" remaining : "<<seq2.size()-pos<<endl;
	vector<char> pSeq = DERCodec::extractSequence(seq2, pos, len);
	pos -= len;
	tmp = DERCodec::extractBigInteger(seq2, pos, len);
	cout<<" RSAPublicKey : "<<endl<<tmp.getRsaHexStr()<<endl;
	
	pubSeq = DERCodec::wrapSequence(pSeq);
	//pubKey = RSAPublicKey(pubSequence, false);
/*
	tag = DERCodec::getTag(seq2, pos);
        len = DERCodec::getFieldLength(seq2, pos, len);
	cout<<"Next Tag : "<<tag<<" len : "<<len<<endl;
	tmp = DERCodec::extractBigInteger(seq2, pos, len);
	cout<<tmp.getRsaHexStr()<<endl;
*/
}

RSAPublicKey X509::getPublicKey()
{
	RSAPublicKey pubKey = RSAPublicKey(pubSeq, false);
	return pubKey;
}

bool X509::isValid()
{
	string dt = currentDateTime();
	if(fromDate <= dt && toDate >dt)
		return true;
	else
		return false;
}	
