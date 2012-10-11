#include "berUtils.h"

berMpzClass::berMpzClass() {
		data = 0;
		len = 0;
	}
	
	berMpzClass::berMpzClass(mpz_class num) {
		data = num;
		stringstream ss1;
                ss1<<hex<<data;
                string str = ss1.str();
                len = (str.length() + 1)/2;
	}	
	
	berMpzClass::berMpzClass(string num, int base) {
		data = mpz_class(num,base);
		stringstream ss1;
		ss1<<hex<<data;
		string str = ss1.str();
		
		len = (str.length() + 1)/2;
	}	

	berMpzClass::berMpzClass(string num, int base, int l)
		{
			len = l;
			data = mpz_class(num,base);
			//cout<<"Constructing mpz_class from "<<num<<" base-"<<base<<endl;
			//cout<<l<<" => "<<hex<<data<<endl;
		}

mpz_class berMpzClass::getData() {
		return data;
	}

int berMpzClass::getLen() {
		return len;
	}

string berMpzClass::getRsaHexStr() {
	stringstream ss1;
	ss1<<hex<<data;
	string num = ss1.str();
	while(num.length() < 2*len)
		num = "0" + num;
	
	string fnum ="";
	for(int i=0;i<num.length();i++)
		{
			if(i>0 && i%2==0)
				fnum+=":";
			if(i>0 && i%30==0)
				fnum+="\n";
			if(i%30 == 0)
				fnum+="\t";
			fnum+=num[i];	
		}
	return fnum;
}

vector<char> berMpzClass::getByteStream()
{
	mpz_class num = data;
 
       stringstream ss1;
        ss1<<hex<<num;
        string hexNum = ss1.str();

        int padding = 2*len - hexNum.length();
        for(int i=0;i<padding;i++)
                hexNum = "0" + hexNum;

        vector<char> byteStream;
        int pos = 0;
        for(int i=0;i<len;i++)
                {
                        char ch = 0 ;
                        ch |= getHexVal(hexNum[pos]);
                        ch<<=4; pos++;
                        ch|=getHexVal(hexNum[pos]);
                        pos++;
                        byteStream.push_back(ch);
                }
        //cout<<"RSAEngine::getByteStream is returning stream with "<<dec<<byteStream.size()<<" bytes"<<endl;
        return byteStream;
}

string berMpzClass::getASCIIStr(){
	vector<char> bstr = getByteStream();
	string str = "";
	for(int i=0;i<bstr.size();i++)
		str += bstr[i];
	return str;
}

int  berMpzClass::getHexVal(char ch){
        int i = 0;
        if(ch >= '0' && ch<='9')
                i = ch - '0';
        else if(ch>='A'&&ch<='Z')
                i = ch - 'A' + 10;
        else
                i = ch - 'a' + 10;
        return i;
}
