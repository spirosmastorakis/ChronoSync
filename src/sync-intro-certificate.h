/* -*- Mode:C++; c-file-style:"gnu"; indent-tabs-mode:nil -*- */
/*
 * Copyright (c) 2013, Regents of the University of California
 *                     Yingdi Yu
 *
 * BSD license, See the LICENSE file for more information
 *
 * Author: Yingdi Yu <yingdi@cs.ucla.edu>
 */

#ifndef SYNC_INTRO_CERTIFICATE_H
#define SYNC_INTRO_CERTIFICATE_H

#include <ndn-cpp/security/certificate/certificate.hpp>
#include <ndn-cpp/security/certificate/identity-certificate.hpp>

class SyncIntroCertificate : public ndn::Certificate
{
public:
  enum IntroType{
    PRODUCER,
    INTRODUCER
  };
  
public:
  SyncIntroCertificate ();
  
  SyncIntroCertificate (const ndn::Name& nameSpace,
                        const ndn::Name& keyName,
                        const ndn::Name& signerName,
                        const ndn::MillisecondsSince1970& notBefore,
                        const ndn::MillisecondsSince1970& notAfter,
                        const ndn::PublicKey& key,
                        const IntroType& introType = PRODUCER);
  
  SyncIntroCertificate (const ndn::Name& nameSpace,
                        const ndn::IdentityCertificate& identityCertificate,
                        const ndn::Name& signerName,
                        const IntroType& introType);
  
  SyncIntroCertificate (const ndn::Data& data);
  
  SyncIntroCertificate (const SyncIntroCertificate& chronosIntroCertificate);
  
  
  virtual 
  ~SyncIntroCertificate ()
  {}
  
  ndn::Data&
  setName (const ndn::Name& name);
  
  inline virtual ndn::Name 
  getPublicKeyName () const
  { return m_keyName; }
  
  inline IntroType
  getIntroType()
  { return m_introType; }

  static bool
  isSyncIntroCertificate(const ndn::Certificate& certificate);

protected:
  ndn::Name m_keyName;
  IntroType m_introType;
};

#endif
