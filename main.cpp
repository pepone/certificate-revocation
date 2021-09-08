
#include <fstream>
#include <string>
#include <stdexcept>
#include <sstream>
#include <iostream>

#include <Security/Security.h>
#include <CoreFoundation/CoreFoundation.h>

using namespace std;

CFMutableDataRef readCertFile(const string& file);

int main(int argc, char** argv)
{
    SecCertificateRef ca = SecCertificateCreateWithData(0, readCertFile("cacert1.der"));
    if(ca == 0)
    {
        throw runtime_error("error reading certiticate cacert1.der ");
    }

    SecCertificateRef servercert = SecCertificateCreateWithData(0, readCertFile("servercert.der"));
    if(ca == 0)
    {
        throw runtime_error("error reading certiticate servercert.der ");
    }

    CFMutableArrayRef policies = CFArrayCreateMutable(NULL, 0, &kCFTypeArrayCallBacks);

    SecPolicyRef basicPolicy = SecPolicyCreateBasicX509();
    CFArrayAppendValue(policies, basicPolicy);

    SecPolicyRef revocationPolicy = SecPolicyCreateRevocation(
        kSecRevocationCRLMethod |
        kSecRevocationRequirePositiveResponse);
    if(revocationPolicy == 0)
    {
        throw runtime_error("error creating revocation policy");
    }
    CFArrayAppendValue(policies, revocationPolicy);

    SecTrustRef trust;
    OSStatus status = SecTrustCreateWithCertificates(servercert, policies, &trust);
    if(status != errSecSuccess)
    {
        ostringstream os;
        os << "error creating trust object: " << status << endl;
        throw runtime_error(os.str());
    }

    CFMutableArrayRef trustedCertificates = CFArrayCreateMutable(NULL, 0, &kCFTypeArrayCallBacks);
    CFArrayAppendValue(trustedCertificates, ca);
    status = SecTrustSetAnchorCertificates(trust, trustedCertificates);
    if(status != errSecSuccess)
    {
        ostringstream os;
        os << "error setting anchor certificates: " << status << endl;
        throw runtime_error(os.str());
    }
    SecTrustSetAnchorCertificatesOnly(trust, true);

    //SecTrustSetOptions(trust, kSecTrustOptionUseTrustSettings);

    CFErrorRef trustErr;
    if (SecTrustEvaluateWithError(trust, &trustErr))
    {
        cerr << "trusted" << endl;
    }
    else
    {
        cerr << "not trusted error code: " << CFErrorGetCode(trustErr) << endl;
    }

    // cleanup

    CFRelease(trustErr);
    CFRelease(trust);

    CFRelease(basicPolicy);
    CFRelease(revocationPolicy);
    CFRelease(policies);

    CFRelease(servercert);
    CFRelease(ca);

    return 0;
}

CFMutableDataRef readCertFile(const string& file)
{
    ifstream is(file, ios::in | ios::binary);
    if(!is.good())
    {
        throw runtime_error("error opening file " + file);
    }

    is.seekg(0, is.end);
    size_t size = static_cast<size_t>(is.tellg());
    is.seekg(0, is.beg);

    CFMutableDataRef data(CFDataCreateMutable(kCFAllocatorDefault, static_cast<CFIndex>(size)));
    CFDataSetLength(data, static_cast<CFIndex>(size));
    is.read(reinterpret_cast<char*>(CFDataGetMutableBytePtr(data)), static_cast<streamsize>(size));
    if(!is.good())
    {
        throw runtime_error("error reading file " + file);
    }
    return data;
}
