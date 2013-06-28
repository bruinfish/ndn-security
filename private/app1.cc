/* -*- Mode:C++; c-file-style:"gnu"; indent-tabs-mode:nil -*- */
/*
 * Copyright (c) 2013, Regents of the University of California
 *                     Alexander Afanasyev
 *                     Zhenkai Zhu
 *
 * BSD license, See the LICENSE file for more information
 *
 * Author: Zhenkai Zhu <zhenkai@cs.ucla.edu>
 *         Alexander Afanasyev <alexander.afanasyev@ucla.edu>
 *         Yingdi Yu <yingdi@cs.ucla.edu>
 */

#include "osx-keychain.h"
#include <fstream>
#include <sys/types.h>
#include <iostream>

using namespace std;

int main(int argc, char* argv[])
{
  keychain::OSX * keychain = new keychain::OSX();

  string keyName = "/my/private/key2";
  keychain->generateKeyPair (keyName);
  keychain->checkACL (keyName);
  // keychain->deleteKeyPair (keyName);

  // keychain->getPublicKey (keyName);
  // ofstream f ("out.pub");
  // f.write (key->buf (), key->size ());
  // keychain->~OSX ();
  keychain->revert();
}

