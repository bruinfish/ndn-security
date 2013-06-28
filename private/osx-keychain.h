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

#ifndef NDN_KEYCHAIN_OSX_H
#define NDN_KEYCHAIN_OSX_H

#include<string>

namespace keychain {

class OSX
{
public:
  OSX ();

  virtual
  ~OSX ();

  virtual void generateKeyPair (const std::string keyName);

  virtual void deleteKeyPair (const std::string keyName);

  virtual void deletePublicKey (const std::string keyName);

  virtual void getPublicKey (const std::string keyName);

  virtual void signData (const std::string keyName);

  virtual void revert ();

private:
  void *m_private;
};

} // keychain

#endif // NDN_KEYCHAIN_OSX_H

