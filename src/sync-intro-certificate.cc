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
#include <ndn.cxx/security/exception.h>

using namespace ndn;
using namespace ndn::security;
using namespace std;

SyncIntroCertificate::SyncIntroCertificate ()
  : Certificate()
{}

SyncIntroCertificate::SyncIntroCertificate (const Name& nameSpace,
					    const Name& keyName,
					    const Name& signerName,
					    const Time& notBefore,
					    const Time& notAfter,
					    const Publickey& key,
					    const IntroType& introType)
  : m_keyName(keyName)
  , m_introType(introType)
{
  Name certificateName = nameSpace;
  certificateName.append("WOT").append(keyName).append("INTRO-CERT").append(signerName);
  switch(introType)
    {
    case PRODUCER:
      certificateName.append("PRODUCER");
      break;
    case INTRODUCER:
      certificateName.append("INTRODUCER");
      break;
    default:
      throw SecException("Wrong Introduction Type!");
    }
  certificateName.appendVersion();
 
  Data::setName(certificateName);
  setNotBefore(notBefore);
  setNotAfter(notAfter);
  setPublicKeyInfo(key);
  addSubjectDescription(CertificateSubDescrypt("2.5.4.41", keyName.toUri()));
  encode();
}

SyncIntroCertificate::SyncIntroCertificate (const Name& nameSpace,
					    const IdentityCertificate& identityCertificate,
					    const Name& signerName,
					    const IntroType& introType)
  : m_introType(introType)
{
  m_keyName = identityCertificate.getPublicKeyName();

  Name certificateName = nameSpace;
  certificateName.append("WOT").append(m_keyName).append("INTRO-CERT").append(signerName);
  switch(introType)
    {
    case PRODUCER:
      certificateName.append("PRODUCER");
      break;
    case INTRODUCER:
      certificateName.append("INTRODUCER");
      break;
    default:
      throw SecException("Wrong Introduction Type!");
    }
  certificateName.appendVersion();
 
  setName(certificateName);
  setNotBefore(identityCertificate.getNotBefore());
  setNotAfter(identityCertificate.getNotAfter());
  setPublicKeyInfo(identityCertificate.getPublicKeyInfo());
  addSubjectDescription(CertificateSubDescrypt("2.5.4.41", m_keyName.toUri()));
}
  
SyncIntroCertificate::SyncIntroCertificate (const Data& data)
  : Certificate(data)
{
  Name certificateName = getName();
  int i = 0;
  int keyNameStart = 0;
  int keyNameEnd = 0;
  for(; i < certificateName.size(); i++)
    {
      if(certificateName.get(i).toUri() == string("WOT"))
	{
	  keyNameStart = i + 1;
	  break;
	}
    }
  
  if(i >= certificateName.size())
    throw SecException("Wrong SyncIntroCertificate Name!");
    
  for(; i< certificateName.size(); i++)
    {
      if(certificateName.get(i).toUri() == string("INTRO-CERT"))
	{
	  keyNameEnd = i;
	  break;
	}
    }

  if(i >= certificateName.size())
    throw SecException("Wrong SyncIntroCertificate Name!");

  m_keyName = certificateName.getSubName(keyNameStart, keyNameEnd - keyNameStart);

  string typeComponent = certificateName.get(certificateName.size() - 2).toUri();
  if(typeComponent == string("PRODUCER"))
    m_introType = PRODUCER;
  else if(typeComponent == string("INTRODUCER"))
    m_introType = INTRODUCER;
  else
    throw SecException("Wrong SyncIntroCertificate Name!");
}

SyncIntroCertificate::SyncIntroCertificate (const SyncIntroCertificate& chronosIntroCertificate)
  : Certificate(chronosIntroCertificate)
  , m_keyName(chronosIntroCertificate.m_keyName)
  , m_introType(chronosIntroCertificate.m_introType)
{}

Data &
SyncIntroCertificate::setName (const Name& certificateName)
{
  int i = 0;
  int keyNameStart = 0;
  int keyNameEnd = 0;
  for(; i < certificateName.size(); i++)
    {
      if(certificateName.get(i).toUri() == string("WOT"))
	{
	  keyNameStart = i + 1;
	  break;
	}
    }
    
  if(i >= certificateName.size())
    throw SecException("Wrong SyncIntroCertificate Name!");
  
  for(; i< certificateName.size(); i++)
    {
      if(certificateName.get(i).toUri() == string("INTRO-CERT"))
	{
	  keyNameEnd = i;
	  break;
	}
    }

  if(i >= certificateName.size())
    throw SecException("Wrong SyncIntroCertificate Name!");

  m_keyName = certificateName.getSubName(keyNameStart, keyNameEnd);

  string typeComponent = certificateName.get(certificateName.size() - 2).toUri();
  if(typeComponent == string("PRODUCER"))
    m_introType = PRODUCER;
  else if(typeComponent == string("INTRODUCER"))
    m_introType = INTRODUCER;
  else
    throw SecException("Wrong SyncIntroCertificate Name!");
    
  return *this;
}

bool
SyncIntroCertificate::isSyncIntroCertificate(const Certificate& certificate)
{
  const Name& certificateName = certificate.getName();
  string introType = certificateName.get(certificateName.size() - 2).toUri();
  if(introType != string("PRODUCER") && introType != string("INTRODUCER"))
    return false;

  int i = 0;
  bool findWot = false;
  bool findIntroCert = false;
  for(; i < certificateName.size(); i++)
    {
      if(certificateName.get(i).toUri() == string("WOT"))
	{
	  findWot = true;
	  break;
	}
    }
    
  if(!findWot)
    return false;
  
  for(; i < certificateName.size(); i++)
    {
      if(certificateName.get(i).toUri() == string("INTRO-CERT"))
	{
	  findIntroCert = true;
	  break;
	}
    }
  if(!findIntroCert)
    return false;
  
  if(i < certificateName.size() - 2)
    return true;
  
  return false;    
}
