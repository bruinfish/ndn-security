/* -*- Mode:C++; c-file-style:"gnu"; indent-tabs-mode:nil -*- */
/*
 * Copyright (c) 2013, Regents of the University of California
 *                     Alexander Afanasyev
 *
 * BSD license, See the LICENSE file for more information
 *
 * Author: Yingdi Yu <yingdi@cs.ucla.edu>
 */

#ifndef KEYCHAIN_H
#define KEYCHAIN_H

#include <string>
#include "keychain-common.h"
#include "pubkey.h"

using namespace std;


namespace keychain {
  
  class Keychain{
  public:
    Keychain(string keychainName = NULL) {m_keychainName = keychainName;}
    
    ~Keychain();

    virtual PubKeyPtr generateKeyPair(string keyName) = 0;
    
    virtual bool nameUsed(string keyName) = 0;

    virtual void * fetchKey(string keyName, int keyType) = 0;

    virtual BytesPtr exportPublicKeyBits(string keyName, int keyType, bool pem) = 0;

    virtual bool deleteKeyPair(string keyName) = 0;

    virtual BytesPtr signData(string keyName) = 0;
    
    virtual BytesPtr decryptData(string keyName) = 0;

    //TODO Symmetrical key stuff.

  private:
    string m_keychainName;
} //keychain


#endif
