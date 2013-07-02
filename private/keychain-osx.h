/* -*- Mode:C++; c-file-style:"gnu"; indent-tabs-mode:nil -*- */
/*
 * Copyright (c) 2013, Regents of the University of California
 *                     Alexander Afanasyev
 *
 * BSD license, See the LICENSE file for more information
 *
 * Author: Yingdi Yu <yingdi@cs.ucla.edu>
 */
#ifndef KEYCHAIN_OSX_H
#define KEYCHAIN_OSX_H

#include <string>

#include <CoreFoundation/CoreFoundation.h>
#include <AppKit/AppKit.h>
#include <Security/Security.h>

#include "keychain.h"

using namespace std;

namespace keychain{
  class KeychainOSX : public Keychain(){
  public:
    KeychainOSX(string keychainName = NULL);

    virtual ~KeychainOSX();

    CFDataRef GetKeyType(int);

    CFDataRef GetKeyClass(int);

    bool SetACL(string keyName, int keyType);


  private:
    SecKeychainRef m_keychainRef;
    SecKeychainRef m_originalDefaultKeychain;
  }
  
}//keychain

#endif KEYCHAIN_OSX_H
