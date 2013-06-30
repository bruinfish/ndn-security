/* -*- Mode:C++; c-file-style:"gnu"; indent-tabs-mode:nil -*- */
/*
 * Copyright (c) 2013, Regents of the University of California
 *                     Alexander Afanasyev
 *
 * BSD license, See the LICENSE file for more information
 *
 * Author: Yingdi Yu <yingdi@cs.ucla.edu>
 */
#ifndef KEYCHAIN_COMMON_H
#define KEYCHAIN_COMMON_H

#include <boost/shared_ptr.hpp>
#include <boost/make_shared.hpp>

namespace keychain { 
  typedef std::vector<unsigned char> Bytes;
  typedef boost::shared_ptr<Bytes> BytesPtr


  class KeychainConstant{
  public:
    static const int KEY_TYPE_RSA = 1;
    
    static const int KEY_CLASS_PRIVATE = 1;
    static const int KEY_CLASS_PUBLIC = 2;
    static const int KEY_CLASS_SYMMETRIC = 3;
  }
  
} //keychain

#endif
