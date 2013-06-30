/* -*- Mode:C++; c-file-style:"gnu"; indent-tabs-mode:nil -*- */
/*
 * Copyright (c) 2013, Regents of the University of California
 *                     Alexander Afanasyev
 *
 * BSD license, See the LICENSE file for more information
 *
 * Author: Yingdi Yu <yingdi@cs.ucla.edu>
 */

#include "keychain-osx.h"
#include "logging.h"

using namespace std;

namespace keychain{

  KeychainOSX::KeychainOSX(string keychainName):Keychain(keychainName){
    if (m_keychainName == NULL)
      m_keychainName = "NDN.keychain";

    SecAccessRef initialAccess = NULL;
    
    OSStatus res = SecKeychainCreate (m_keychainName.c_str (), //Keychain path
                                      0,                       //Keychain password length
                                      NULL,                    //Keychain password
                                      true,                    //User prompt
                                      initialAccess,           //Initial access of Keychain
                                      &m_keychainRef);         //Keychain reference

    if (res == errSecDuplicateKeychain)
        res = SecKeychainOpen (m_keychainName.c_str (),
                               &m_keychainRef);
    if (res != errSecSuccess){
      _LOG_DEBUG ("Fail to initialize keychain ref: " << res);
      exit(-1);
    }

    res = SecKeychainCopyDefault (&m_originalDefaultKeychain);

    res = SecKeychainSetDefault (m_keychainRef);
    if (res != errSecSuccess){
      _LOG_DEBUG ("Fail to set default keychain: " << res);
      exit(-1);
    }
  }

  KeychainOSX::~KeychainOSX (){
    //TODO: implement
  }

  bool KeychainOSX::nameUsed(string keyName){
    CFDataRef keyTag = CFDataCreate (NULL,
                                     reinterpret_cast<const unsigned char *> (keyName.c_str ()),
                                     keyName.size ());
    
    CFMutableDictionaryRef attrDict = CFDictionaryCreateMutable(NULL,
                                                                2,
                                                                kCFTypeDictionaryKeyCallBacks,
                                                                NULL);
    
    CFDictionaryAddValue(attrDict, kSecAttrApplicationTag, keyTag);
    CFDictionaryAddValue(attrDict, kSecReturnRef, kCFBooleanTrue);
    
    SecKeychainItemRef itemRef;
    OSStatus res = SecItemCopyMatching(attrDict, itemRef);
    
    if(res == errSecItemNotFound)
      return true;
    
    if(res == errSecSuccess)
      return false;

    _LOG_DEBUG("nameUsed other error!");
    exit(-1);
    return true;
  }

  PubKeyPtr KeychainOSX::generateKeyPair(string keyName,
                                         int keyType,
                                         int keySize){
    if(nameUsed(keyName)){
      _LOG_DEBUG("keyName has been used!")
      return NULL;
    }

    SecKeyRef publicKey, privateKey;

    CFDataRef keyTag = CFDataCreate (NULL, 
                                     reinterpret_cast<const unsigned char *> (keyName.c_str ()), 
                                     keyName.size ());
    
    CFMutableDictionaryRef attrDict = CFDictionaryCreateMutable(NULL,
                                                             0,
                                                             kCFTypeDictionaryKeyCallBacks,
                                                             NULL);

    CFDictionaryAddValue(attrDict, kSecAttrKeyType, getKeyType(keyType));
    CFDictionaryAddValue(attrDict, kSecAttrKeySizeInBits, CFNumberCreate (NULL, kCFNumberIntType, &keySize));
    CFDictionaryAddValue(attrDict, kSecAttrApplicationTag, keyTag);

    OSStatus res = SecKeyGeneratePair ((CFDictionaryRef)attrDict, &publicKey, &privateKey);
    if (res != errSecSuccess){
      _LOG_DEBUG ("Fail to create a key pair: " << res);
      exit(-1);
    }

    CFDictionaryRemoveValue(attrDict, kSecAttrKeySizeInBits);
    CFDictionaryAddValue(attrDict, kSecAttrKeyClass, kSecAttrKeyClassPublic);
    CFDictionaryAddValue(attrDict, kSecReturnData, kCFBooleanTrue);
    
    CFDataRef keyBits;
    SecItemCopyMatching((CFDictionary)attrDict, (CFTypeRef*)&keyBits);
    
    CFDictionarySetValue(attrDict, kSecReturnAttributes, kCFBooleanTrue);
    
    CFDictionaryRef rAttrDict;
    SecItemCopyMatching((CFDictionary)attrDict, (CFTypeRef*)&rAttrDict);
    
    CFStringRef appLabel = (CFString) CFDictionaryGetValue(rAttrDict, kSecAttrApplicationLabel);

    //TODO: Convert appLabel to labelPtr, keyBits to bitsPtr
    BytePtr labelPtr = NULL;
    BytePtr bitsPtr = NULL;
        
    PubKeyPtr = make_shared<PubKey>(keyName, keyType, labelPtr, bitsPtr);

    CFRelease (publicKey);
    CFRelease (privateKey);
  }

  void * KeychainOSX::fetchKey(string keyName, int keyType, int keyClass){

    CFDataRef keyTag = CFDataCreate (NULL, 
                                     reinterpret_cast<const unsigned char *> (keyName.c_str ()), 
                                     keyName.size ());
    
    CFMutableDictionaryRef attrDict = CFDictionaryCreateMutable(NULL,
                                                             0,
                                                             kCFTypeDictionaryKeyCallBacks,
                                                             NULL);

    CFDictionaryAddValue(attrDict, kSecAttrClass, kSecClassKey);
    CFDictionaryAddValue(attrDict, kSecAttrKeyType, getKeyType(keyType));
    CFDictionaryAddValue(attrDict, kSecAttrApplicationTag, keyTag);
    CFDictionaryAddValue(attrDict, kSecAttrKeyClass, getKeyClass(keyClass));
    CFDictionaryAddValue(attrDict, kSecReturnRef, kCFBooleanTrue);
    
    SecKeychainItemRef keyItem;

    OSStatus res = SecItemCopyMatching((CFDictionary) attrDict, (CFType*)&keyItem);
    
    if(res != errSecSuccess){
      _LOG_DEBUG("Fail to find the key!");
      return NULL;
    }
    else
      return keyItem;
  }
  
  string KeychainOSX::exportPublicKeyBits(string keyName, int keyType, bool pem){
    SecKeychainItemRef keyItem = (SecKeychainItemRef) fetchKey(keyName, keyType, KeychainConstant.KEY_CLASS_PUBLIC);
    
    if(keyItem == NULL){
      _LOG_DEBUG("No key to export!");
      return NULL;
    }

    //TODO: complete format;
    CFDataRef outFormat = kSecFormatOpenSSL;

    CFDataRef pemFlag = NULL;

    if(pem)
      pemFlag = kSecItemPemArmour;
    
    CFDataRef output;
    
    OSStatus res2 = SecItemExport(keyItem,
                                  outFormat,
                                  pemFlag,
                                  NULL,
                                  (CFDataRef *)(&output));

    //TODO: convert output to outputPtr
    BytePtr outputPtr = NULL;

    return outputPtr;
  }
  bool KeychainOSX::deleteKeyPair(string keyName, int keyType, BytePtr keyLabel){
    CFMutableDictionaryRef attrDict = CFDictionaryCreateMutable(NULL,
                                                                0,
                                                                kCFTypeDictionaryKeyCallBacks,
                                                                NULL);

    CFDictionaryAddValue(attrDict, kSecAttrKeyType, getKeyType(keyType));
    CFDictionaryAddValue(attrDict, kSecAttrApplicationTag, keyTag);

    OSStatus res = SecItemDelete(attrDict);
    
    if(res == errSecSuccess)
      return true;
    else
      return false;
  }

  BytesPtr KeychainOSX::signData(int keyName, int keyType, BytePtr data){
    //TODO: convert data to dataRef
    CFDataRef dataRef = NULL;

    SecKeyRef privateKey = (SecKeyRef) fetchKey(keyName, keyType, KeychainConstant.KEY_CLASS_PRIVATE);
    
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
    
    //TODO: convert signature to sigPtr;
    BytePtr sigPtr = NULL;

    return sigPtr;
  }

  BytesPtr KeychainOSX::decryptData(int keyName, int keyType, BytePtr data){
    //TODO: implemenet
  }

  bool KeychainOSX::setACL(int keyName, int keyType, const char * appPath){
    SecKeychainItemRef privateKey = (SecKeychainItemRef) fetchKey(keyName, keyType, KeychainConstant.KEY_CLASS_PRIVATE);
    
    SecAccessRef accRef;
    OSStatus acc_res = SecKeychainItemCopyAccess (privateKey, &accRef);

    CFArrayRef signACL = SecAccessCopyMatchingACLList (accRef,
                                                       kSecACLAuthorizationSign);

    SecACLRef aclRef = (SecACLRef) CFArrayGetValueAtIndex(signACL, 0);

    CFArrayRef appList;
    CFStringRef description;
    SecKeychainPromptSelector promptSelector;
    OSStatus acl_res = SecACLCopyContents (aclRef,
                                           &appList,
                                           &description,
                                           &promptSelector);

    CFMutableArrayRef newAppList = CFArrayCreateMutableCopy(NULL,
                                                            0,
                                                            appList);

    SecTrustedApplicationRef trustedApp;
    acl_res = SecTrustedApplicationCreateFromPath (appPath,
                                                   &trustedApp);
    
    CFArrayAppendValue(newAppList, trustedApp);


    CFArrayRef authList = SecACLCopyAuthorizations (aclRef);
    
    acl_res = SecACLRemove(aclRef);
    
    acl_res = SecACLCreateWithSimpleContents (accRef,
                                              newAppList,
                                              description,
                                              promptSelector,
                                              &newACL);

    acl_res = SecACLUpdateAuthorizations (newACL, authList);

    acc_res = SecKeychainItemSetAccess(privateKey, accRef);
  }

  CFDataRef KeychainOSX::getKeyType(int keyType){
    switch(keyType){
    case KeychainConstant.KEY_TYPE_RSA:
      return kSecAttrKeyTypeRSA;
    default:
      _LOG_DEBUG("Unrecognized key type!")
      return NULL;
    }
  }

  CFDataRef KeychainOSX::getKeyClass(int keyClass){
    switch(keyClass){
    case KeychainConstant.KEY_CLASS_PRIVATE:
      return kSecAttrKeyClassPrivate;
    case KeychainConstant.KEY_CLASS_PUBLIC:
      return kSecAttrKeyClassPublic;
    case KeychainConstant.KEY_CLASS_SYMMETRIC:
      return kSecAttrKeyClassSymmetric;
    default:
      _LOG_DEBUG("Unrecognized key class!");
      return NULL;
    }
  }

}//keychain
