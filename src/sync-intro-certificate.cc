/* -*- Mode:C++; c-file-style:"gnu"; indent-tabs-mode:nil -*- */
/*
 * Copyright (c) 2013, Regents of the University of California
 *                     Yingdi Yu
 *
 * BSD license, See the LICENSE file for more information
 *
 * Author: Yingdi Yu <yingdi@cs.ucla.edu>
 */

#include "sync-intro-certificate.h"

using namespace ndn;
using namespace std;
using namespace boost;

SyncIntroCertificate::SyncIntroCertificate ()
  : Certificate()
{}

SyncIntroCertificate::SyncIntroCertificate (const Name& nameSpace,
					    const Name& keyName,
					    const Name& signerName,
					    const MillisecondsSince1970& notBefore,
					    const MillisecondsSince1970& notAfter,
					    const PublicKey& key,
					    const IntroType& introType)
  : m_nameSpace(nameSpace)
  , m_keyName(keyName)
  , m_introType(introType)
{
  Name certificateName = nameSpace;
  certificateName.append("WOT").append(keyName.wireEncode()).append("INTRO-CERT").append(signerName.wireEncode());
  switch(introType)
    {
    case PRODUCER:
      certificateName.append("PRODUCER");
      break;
    case INTRODUCER:
      certificateName.append("INTRODUCER");
      break;
    default:
      throw Error("Wrong Introduction Type!");
    }
  certificateName.appendVersion();
 
  Data::setName(certificateName);
  setNotBefore(notBefore);
  setNotAfter(notAfter);
  setPublicKeyInfo(key);
  addSubjectDescription(CertificateSubjectDescription("2.5.4.41", keyName.toUri()));
  encode();
}

SyncIntroCertificate::SyncIntroCertificate (const Name& nameSpace,
					    const IdentityCertificate& identityCertificate,
					    const Name& signerName,
					    const IntroType& introType)
  : m_nameSpace(nameSpace)
  , m_introType(introType)
{
  m_keyName = identityCertificate.getPublicKeyName();

  Name certificateName = nameSpace;
  certificateName.append("WOT").append(m_keyName.wireEncode()).append("INTRO-CERT").append(signerName.wireEncode());
  switch(introType)
    {
    case PRODUCER:
      certificateName.append("PRODUCER");
      break;
    case INTRODUCER:
      certificateName.append("INTRODUCER");
      break;
    default:
      throw Error("Wrong Introduction Type!");
    }
  certificateName.appendVersion();
 
  Data::setName(certificateName);
  setNotBefore(identityCertificate.getNotBefore());
  setNotAfter(identityCertificate.getNotAfter());
  setPublicKeyInfo(identityCertificate.getPublicKeyInfo());
  addSubjectDescription(CertificateSubjectDescription("2.5.4.41", m_keyName.toUri()));
}
  
SyncIntroCertificate::SyncIntroCertificate (const Data& data)
  : Certificate(data)
{ setName(getName()); }

SyncIntroCertificate::SyncIntroCertificate (const SyncIntroCertificate& chronosIntroCertificate)
  : Certificate(chronosIntroCertificate)
  , m_nameSpace(chronosIntroCertificate.m_nameSpace)
  , m_keyName(chronosIntroCertificate.m_keyName)
  , m_introType(chronosIntroCertificate.m_introType)
{}

Data &
SyncIntroCertificate::setName (const Name& certificateName)
{
  int nameLength = certificateName.size();

  if(nameLength < 6)
    throw Error("Wrong SyncIntroCertificate Name!");

  m_nameSpace = certificateName.getPrefix(-6);

  if(!certificateName.get(-6).equals("WOT"))
    throw Error("Wrong SyncIntroCertificate Name!");

  m_keyName.wireDecode(Block(certificateName.get(-5).getValue().buf(), 
                             certificateName.get(-5).getValue().size()));

  if(!certificateName.get(-4).equals("INTRO-CERT"))
    throw Error("Wrong SyncIntroCertificate Name!");

  if(certificateName.get(-2).equals("PRODUCER"))
    m_introType = PRODUCER;
  else if(certificateName.get(-2).equals("INTRODUCER"))
    m_introType = INTRODUCER;
  else
    throw Error("Wrong SyncIntroCertificate Name!");

  return *this;
}

bool
SyncIntroCertificate::isSyncIntroCertificate(const Certificate& certificate)
{
  const Name& certificateName = certificate.getName();

  int nameLength = certificateName.size();

  if(nameLength < 6)
    return false;

  if(!certificateName.get(-6).equals("WOT"))
    return false;

  if(!certificateName.get(-4).equals("INTRO-CERT"))
    return false;

  if(!certificateName.get(-2).equals("PRODUCER") && !certificateName.get(-2).equals("INTRODUCER"))
    return false;

  return true;
}
