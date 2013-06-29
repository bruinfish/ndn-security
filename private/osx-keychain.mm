/* -*- Mode:C++; c-file-style:"gnu"; indent-tabs-mode:nil -*- */
/*
 * Copyright (c) 2013, Regents of the University of California
 *                     Alexander Afanasyev
 *
 * BSD license, See the LICENSE file for more information
 *
 * Author: Alexander Afanasyev <alexander.afanasyev@ucla.edu>
 *         Yingdi Yu <yingdi@cs.ucla.edu>
 */

#include "osx-keychain.h"
#include "logging.h"

#include <Foundation/Foundation.h>
//#include <CoreFoundation/CoreFoundation.h>
#include <AppKit/AppKit.h>
#include <Security/Security.h>


INIT_LOGGER ("Keychain.OSX");

namespace keychain {
class OSX_Private
{
public:
  static void
  LogHumanError (OSStatus res, const std::string &errMsgStr)
  {
    CFStringRef errMsgPtr = SecCopyErrorMessageString (res, NULL);
    char errMsg[1024];
    CFStringGetCString (errMsgPtr, errMsg, 1024, kCFStringEncodingUTF8);
    _LOG_DEBUG ("LogHumanError Open status: " << errMsgStr << errMsg);

  }

  SecKeychainRef m_keychain;
  SecKeychainRef m_origDefaultKeychain;
  static const std::string s_keychainPath;
};

const std::string OSX_Private::s_keychainPath = "NDN.keychain";
} // keychain



keychain::OSX::OSX ()
{
  m_private = new OSX_Private ();
  OSX_Private *self = reinterpret_cast<OSX_Private*> (m_private);

  SecKeychainSetUserInteractionAllowed (true);

  OSStatus res = SecKeychainCreate (OSX_Private::s_keychainPath.c_str (),
                                    0, NULL, true, NULL,
                                    &self->m_keychain);
  _LOG_DEBUG ("Create status: " << res);

  if (res == errSecDuplicateKeychain)
    {
      res = SecKeychainOpen (OSX_Private::s_keychainPath.c_str (),
                             &self->m_keychain);
      _LOG_DEBUG ("Open status: " << res);
    }

  if (res != errSecSuccess)
    OSX_Private::LogHumanError (res, "Cannot open or create OSX Keychain");

  res = SecKeychainCopyDefault (&self->m_origDefaultKeychain);
  _LOG_DEBUG ("Copy default: " << res);
  
  res = SecKeychainSetDefault (self->m_keychain);
}

keychain::OSX::~OSX ()
{
  OSX_Private *self = reinterpret_cast<OSX_Private*> (m_private);
  
  SecKeychainSetDefault (self->m_origDefaultKeychain);

  CFRelease (self->m_keychain);
  CFRelease (self->m_origDefaultKeychain);
  delete self;
}

void 
keychain::OSX::revert ()
{
  OSX_Private *self = reinterpret_cast<OSX_Private*> (m_private);
  SecKeychainOpen ("login.keychain",
                   &self->m_origDefaultKeychain);
  OSStatus res = SecKeychainSetDefault (self->m_origDefaultKeychain);
  
  _LOG_DEBUG("set Default: "<< res);

  CFRelease (self->m_keychain);
  CFRelease (self->m_origDefaultKeychain);
  delete self;
}

void
keychain::OSX::generateKeyPair (const std::string keyName)
{
  CFStringRef label = CFStringCreateWithCString (NULL, keyName.c_str (), kCFStringEncodingUTF8);
  CFDataRef tag = CFDataCreate (NULL, reinterpret_cast<const unsigned char *> (keyName.c_str ()), keyName.size ());

  SecTrustedApplicationRef trustedApps[2];
  OSStatus app_res = SecTrustedApplicationCreateFromPath ("/Users/yuyingdi/Develop/ndn-security/build/app1",
                                                          &(trustedApps[0]));
  _LOG_DEBUG("create app1: " << app_res);

//   app_res = SecTrustedApplicationCreateFromPath ("/Users/yuyingdi/Develop/ndn-security/build/app2",
//                                                           &(trustedApps[1]));
//   _LOG_DEBUG("create app2: " << app_res);

  CFArrayRef applicationList  = CFArrayCreate (NULL,
                                               (const void **)trustedApps, 
                                               1,
//                                                2,
                                               &kCFTypeArrayCallBacks);
  
  SecAccessRef accessRef;
  OSStatus acc_res = SecAccessCreate(CFStringCreateWithCString (NULL, keyName.c_str (), kCFStringEncodingUTF8),
                                     applicationList,
                                     &accessRef);

//   CFArrayRef aclList = SecAccessCopyMatchingACLList (accessRef, (CFTypeRef)(CFSTR("ACLAuthorizationChangeACL")));
//   SecACLRef changeACL = (SecACLRef)CFArrayGetValueAtIndex(aclList, 0);

//   CFArrayRef changeApp  = CFArrayCreate (NULL,
//                                                (const void **)trustedApps, 
//                                                1,
//                                                &kCFTypeArrayCallBacks);
  
//   OSStatus acl_res = SecACLSetContents(changeACL, 
//                                        changeApp,
//                                        label,
//                                        kSecKeychainPromptRequirePassphase);

  


//   _LOG_DEBUG("change aclList: " << acl_res);


  const void *	keys[] = {
    kSecAttrLabel,
    kSecAttrAccess,
    kSecAttrKeyType,
    kSecAttrKeySizeInBits,
    kSecAttrApplicationTag
  };
  
  int keySize = 2048;
  const void *	values[] = {
    label,
    accessRef,
    kSecAttrKeyTypeRSA,
    CFNumberCreate (NULL, kCFNumberIntType, &keySize),
    tag
  };

  CFDictionaryRef dict = CFDictionaryCreate (NULL,
                                             keys, values,
                                             sizeof(keys) / sizeof(*keys),
                                             &kCFTypeDictionaryKeyCallBacks, NULL);

  SecKeyRef publicKey, privateKey;

  OSStatus res = SecKeyGeneratePair (dict, &publicKey, &privateKey);
  _LOG_DEBUG ("GeneratePair stats: " << res);

  if (res != errSecSuccess)
    OSX_Private::LogHumanError (res, "Cannot generate public/private key pair");

  CFRelease (publicKey);
  CFRelease (privateKey);
}

void
keychain::OSX::deleteKeyPair (const std::string keyName)
{
  const void *	keys[] = {
    kSecClass,
    kSecAttrApplicationTag
  };

  CFDataRef tag = CFDataCreate (NULL, reinterpret_cast<const unsigned char *> (keyName.c_str ()), keyName.size ());

  const void *	values[] = {
    kSecClassKey,
    tag
  };

  CFDictionaryRef dict = CFDictionaryCreate (NULL,
                                             keys, values,
                                             sizeof(keys) / sizeof(*keys),
                                             NULL, NULL);

  OSStatus res = errSecSuccess;
  while (res == errSecSuccess)
    {
      res = SecItemDelete (dict);
      _LOG_DEBUG ("SecItemDelete status: " << res);
    }

  if (res != errSecItemNotFound)
    OSX_Private::LogHumanError (res, "Error while deleting key " + keyName);
}

void
keychain::OSX::deletePublicKey (const std::string keyName)
{
}

void
keychain::OSX::getPublicKey (const std::string keyName)
{
  const void *	keys[] = {
    kSecClass,
    kSecAttrKeyType,
    kSecAttrKeyClass,
    kSecAttrApplicationTag,
    kSecReturnRef
  };

  CFDataRef tag = CFDataCreate (NULL, reinterpret_cast<const unsigned char *> (keyName.c_str ()), keyName.size ());

  const void *	values[] = {
    kSecClassKey,
    kSecAttrKeyTypeRSA,
    kSecAttrKeyClassPublic,
    tag,
    kCFBooleanTrue
  };

  CFDictionaryRef query = CFDictionaryCreate (NULL,
                                              keys, values,
                                              sizeof(keys) / sizeof(*keys),
                                              NULL, NULL);

  //  NSData* publicKey;
  // OSStatus res = SecItemCopyMatching (query, (CFTypeRef *)(&publicKey));
  //  SecKeyRef* pubkeyRef;
  SecKeychainItemRef* pubkeyRef;
  OSStatus res = SecItemCopyMatching (query, (CFTypeRef *)(&pubkeyRef));
  if (res != errSecSuccess)
    OSX_Private::LogHumanError (res, "Cannot find public key " + keyName);

  // Ptr<Blob> retval (new Blob ([publicKey bytes], [publicKey length]));
  // _LOG_DEBUG ("Key size: " << [publicKey length]);

  NSData* publicKey;

  SecKeyImportExportParameters param;
  param.version = SEC_KEY_IMPORT_EXPORT_PARAMS_VERSION;
  param.flags = kSecItemPemArmour;
  OSStatus res2 = SecItemExport(pubkeyRef,
                                kSecFormatOpenSSL,
                                kSecItemPemArmour,
                                NULL,
                                (CFDataRef *)(&publicKey));

  _LOG_DEBUG ("Key size: " << (const char*)[publicKey bytes]);

}

bool
keychain::OSX::signData (const std::string keyName, CFDataRef dataRef)
{
  const void* keys [] = {
    kSecClass,
    kSecAttrKeyType,
    kSecAttrKeyClass,
    kSecAttrApplicationTag,
    kSecReturnRef
  };
  
  CFDataRef tag = CFDataCreate (NULL, reinterpret_cast<const unsigned char *> (keyName.c_str()), keyName.size());

  const void* values[] = {
    kSecClassKey,
    kSecAttrKeyTypeRSA,
    kSecAttrKeyClassPrivate,
    tag,
    kCFBooleanTrue
  };

  CFDictionaryRef query = CFDictionaryCreate (NULL,
                                              keys, values,
                                              sizeof(keys) / sizeof(*keys),
                                              &kCFTypeDictionaryKeyCallBacks, &kCFTypeDictionaryValueCallBacks);

  SecKeychainItemRef privateKey;
  OSStatus res = SecItemCopyMatching(query, (CFTypeRef *) &privateKey);
  
  _LOG_DEBUG("getPrivateKey: " << res);

  CFErrorRef error;
  SecTransformRef signer = SecSignTransformCreate((SecKeyRef)privateKey, &error);
  if (error) { CFShow(error); exit(-1); }

  Boolean set_res = SecTransformSetAttribute(signer, 
                                               kSecTransformInputAttributeName,
                                               dataRef,
                                               &error);
  if (error) { CFShow(error); exit(-1); }
  
  CFDataRef signature = (CFDataRef) SecTransformExecute(signer, &error);
  if (error) { CFShow(error); exit(-1); }
 
  if (!signature) {
    fprintf(stderr, "Signature is NULL!\n");
    exit(-1);
  }


  const void *  attr_keys[] = {
    kSecClass,
    kSecAttrKeyType,
    kSecAttrKeyClass,
    kSecAttrApplicationTag,
    kSecReturnRef,
  };

  const void *  attr_values[] = {
    kSecClassKey,
    kSecAttrKeyTypeRSA,
    kSecAttrKeyClassPublic,
    tag,
    kCFBooleanTrue
  };

  CFDictionaryRef attr_query = CFDictionaryCreate (NULL,
                                              attr_keys, attr_values,
                                              sizeof(attr_keys) / sizeof(*attr_keys),
                                              &kCFTypeDictionaryKeyCallBacks, &kCFTypeDictionaryValueCallBacks);

  SecKeychainItemRef publicKey;
  res = SecItemCopyMatching(attr_query, (CFTypeRef *)&publicKey);

  if (res != errSecSuccess)
    OSX_Private::LogHumanError (res, "Cannot find public key " + keyName);

  _LOG_DEBUG("Find public Key");

  SecTransformRef verifier = SecVerifyTransformCreate((SecKeyRef)publicKey, signature, &error);

  _LOG_DEBUG("Set verifier");

  set_res = SecTransformSetAttribute(verifier,
                                     kSecTransformInputAttributeName,
                                     dataRef,
                                     &error);
  if (error) { CFShow(error); exit(-1); }

  CFTypeRef result = SecTransformExecute(verifier, &error);
  if (error) { CFShow(error); exit(-1); }

  if (result == kCFBooleanTrue) {
    _LOG_DEBUG("Verification Succeed!");
    return true;
  } else {
    return ("Verification Fail!");
    return false;
  }
}


bool
keychain::OSX::verifyData(const std::string keyName, CFDataRef dataRef, CFDataRef signature)
{
  return false;
}

void 
keychain::OSX::checkACL(const std::string keyName)
{
  const void *  attr_keys[] = {
    kSecClass,
    kSecAttrKeyType,
    kSecAttrKeyClass,
    kSecAttrApplicationTag,
    kSecReturnRef,
  };

  CFDataRef tag = CFDataCreate (NULL, reinterpret_cast<const unsigned char *> (keyName.c_str()), keyName.size());

  const void *  attr_values[] = {
    kSecClassKey,
    kSecAttrKeyTypeRSA,
    kSecAttrKeyClassPrivate,
    tag,
    kCFBooleanTrue
  };

  CFDictionaryRef attr_query = CFDictionaryCreate (NULL,
                                              attr_keys, attr_values,
                                              sizeof(attr_keys) / sizeof(*attr_keys),
                                              &kCFTypeDictionaryKeyCallBacks, &kCFTypeDictionaryValueCallBacks);

  SecKeychainItemRef privateKey;
  OSStatus res = SecItemCopyMatching(attr_query, (CFTypeRef *)&privateKey);

  if (res != errSecSuccess)
    OSX_Private::LogHumanError (res, "Cannot find private key " + keyName);
  
  SecAccessRef accRef;
  OSStatus acc_res = SecKeychainItemCopyAccess (privateKey, &accRef);

  _LOG_DEBUG("GET acc_res: " << acc_res);

  CFArrayRef signACL = SecAccessCopyMatchingACLList (accRef,
                                                     kSecACLAuthorizationSign);

  _LOG_DEBUG("ACL size: " << CFArrayGetCount(signACL));


  SecACLRef aclRef = (SecACLRef) CFArrayGetValueAtIndex(signACL, 0);

  CFArrayRef appList;
  CFStringRef description;
  SecKeychainPromptSelector promptSelector;
  OSStatus acl_res = SecACLCopyContents (aclRef,
                                &appList,
                                &description,
                                &promptSelector);

  _LOG_DEBUG("AppList size: " << CFArrayGetCount(appList));

  SecTrustedApplicationRef trustedApps[2];
  trustedApps[0] = (SecTrustedApplicationRef) CFArrayGetValueAtIndex(appList, 0);
  acl_res = SecTrustedApplicationCreateFromPath ("/Users/yuyingdi/Develop/ndn-security/build/app2",
                                                 &(trustedApps[1]));

  CFArrayRef applicationList  = CFArrayCreate (NULL,
                                               (const void **)trustedApps, 
                                               2,
                                               &kCFTypeArrayCallBacks);

  CFArrayRef authList = SecACLCopyAuthorizations (aclRef);

  acl_res = SecACLRemove(aclRef);

  _LOG_DEBUG("Remove ACL: " << acl_res);


  SecACLRef newACL;
  acl_res = SecACLCreateWithSimpleContents (accRef,
                                            applicationList,
                                            description,
                                            promptSelector,
                                            &newACL);

  acl_res = SecACLUpdateAuthorizations (newACL, authList);

  acc_res = SecKeychainItemSetAccess(privateKey, accRef);
  
}



/// @todo Release data structures after use

