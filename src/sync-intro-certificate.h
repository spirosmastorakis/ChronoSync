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

#include <ndn-cpp-dev/security/certificate.hpp>
#include <ndn-cpp-dev/security/identity-certificate.hpp>

class SyncIntroCertificate : public ndn::Certificate
{
public:
  struct Error : public ndn::Certificate::Error { Error(const std::string &what) : ndn::Certificate::Error(what) {} };

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
  
  inline const ndn::Name &
  getPublicKeyName() const;
  
  inline IntroType
  getIntroType();

  inline const ndn::Name &
  getNameSpace() const;
  
  static bool
  isSyncIntroCertificate(const ndn::Certificate& certificate);

protected:
  ndn::Name m_nameSpace;
  ndn::Name m_keyName;
  IntroType m_introType;
};

SyncIntroCertificate::IntroType
SyncIntroCertificate::getIntroType()
{ return m_introType; }

const ndn::Name &
SyncIntroCertificate::getPublicKeyName () const
{ return m_keyName; }

const ndn::Name &
SyncIntroCertificate::getNameSpace() const
{ return m_nameSpace; }

#endif
