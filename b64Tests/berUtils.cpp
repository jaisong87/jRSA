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
