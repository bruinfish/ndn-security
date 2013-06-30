/* -*- Mode:C++; c-file-style:"gnu"; indent-tabs-mode:nil -*- */
/*
 * Copyright (c) 2013, Regents of the University of California
 *                     Alexander Afanasyev
 *
 * BSD license, See the LICENSE file for more information
 *
 * Author: Yingdi Yu <yingdi@cs.ucla.edu>
 */

#ifndef KEYCHAIN_PUBKEY_H
#define KEYCHAIN_PUBKEY_H

#include <string>
#include "keychain-common.h"

using namespace std;

namespace keychain {
  class PubKey;
  typedef boost::shared_ptr<PubKey> PubKeyPtr;

  class PubKey{
  public:

    PubKey(string keyName, int keyType, BytePtr keyLabel, BytePtr keyBits) {
      m_keyName = keyName;
      m_keyType = keyType;
      m_keyTag = keyLabel;
      m_keyBits = keyBits;
    }
    
    virtual ~PubKey();

    virtual string getKeyName() {return m_keyName;}

    virtual int getKey() { return m_keyType;}

    virtual BytePtr getKeyLabel {return m_keyLabel;}
    
    virtual BytePtr getKeyBits {return m_keyBits;}

    virtual int getKeySize {return m_keyBits->size();}
    
  private:
    string m_keyName;
    int m_keyType;
    BytesPtr m_keyLabel;
    BytesPtr m_keyBits;
  }
} //keychain


#endif
