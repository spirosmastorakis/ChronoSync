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
#include <ndn-cpp/security/security-exception.hpp>

#include <boost/date_time/posix_time/posix_time.hpp>

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
      throw Error("Wrong Introduction Type!");
    }

  posix_time::time_duration now = posix_time::microsec_clock::universal_time () - posix_time::ptime(gregorian::date (1970, boost::gregorian::Jan, 1));
  uint64_t version = (now.total_seconds () << 12) | (0xFFF & (now.fractional_seconds () / 244));
  certificateName.appendVersion(version);
 
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
      throw Error("Wrong Introduction Type!");
    }
  posix_time::time_duration now = posix_time::microsec_clock::universal_time () - posix_time::ptime(gregorian::date (1970, boost::gregorian::Jan, 1));
  uint64_t version = (now.total_seconds () << 12) | (0xFFF & (now.fractional_seconds () / 244));
  certificateName.appendVersion(version);
 
  setName(certificateName);
  setNotBefore(identityCertificate.getNotBefore());
  setNotAfter(identityCertificate.getNotAfter());
  setPublicKeyInfo(identityCertificate.getPublicKeyInfo());
  addSubjectDescription(CertificateSubjectDescription("2.5.4.41", m_keyName.toUri()));
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
      if(certificateName.get(i).toEscapedString() == string("WOT"))
	{
	  keyNameStart = i + 1;
	  break;
	}
    }
  
  if(i >= certificateName.size())
    throw Error("Wrong SyncIntroCertificate Name!");
    
  for(; i< certificateName.size(); i++)
    {
      if(certificateName.get(i).toEscapedString() == string("INTRO-CERT"))
	{
	  keyNameEnd = i;
	  break;
	}
    }

  if(i >= certificateName.size())
    throw Error("Wrong SyncIntroCertificate Name!");

  m_keyName = certificateName.getSubName(keyNameStart, keyNameEnd - keyNameStart);

  string typeComponent = certificateName.get(certificateName.size() - 2).toEscapedString();
  if(typeComponent == string("PRODUCER"))
    m_introType = PRODUCER;
  else if(typeComponent == string("INTRODUCER"))
    m_introType = INTRODUCER;
  else
    throw Error("Wrong SyncIntroCertificate Name!");
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
      if(certificateName.get(i).toEscapedString() == string("WOT"))
	{
	  keyNameStart = i + 1;
	  break;
	}
    }
    
  if(i >= certificateName.size())
    throw Error("Wrong SyncIntroCertificate Name!");
  
  for(; i< certificateName.size(); i++)
    {
      if(certificateName.get(i).toEscapedString() == string("INTRO-CERT"))
	{
	  keyNameEnd = i;
	  break;
	}
    }

  if(i >= certificateName.size())
    throw Error("Wrong SyncIntroCertificate Name!");

  m_keyName = certificateName.getSubName(keyNameStart, keyNameEnd - keyNameStart);

  string typeComponent = certificateName.get(certificateName.size() - 2).toEscapedString();
  if(typeComponent == string("PRODUCER"))
    m_introType = PRODUCER;
  else if(typeComponent == string("INTRODUCER"))
    m_introType = INTRODUCER;
  else
    throw Error("Wrong SyncIntroCertificate Name!");
    
  return *this;
}

bool
SyncIntroCertificate::isSyncIntroCertificate(const Certificate& certificate)
{
  const Name& certificateName = certificate.getName();
  string introType = certificateName.get(certificateName.size() - 2).toEscapedString();
  if(introType != string("PRODUCER") && introType != string("INTRODUCER"))
    return false;

  int i = 0;
  bool findWot = false;
  bool findIntroCert = false;
  for(; i < certificateName.size(); i++)
    {
      if(certificateName.get(i).toEscapedString() == string("WOT"))
	{
	  findWot = true;
	  break;
	}
    }
    
  if(!findWot)
    return false;
  
  for(; i < certificateName.size(); i++)
    {
      if(certificateName.get(i).toEscapedString() == string("INTRO-CERT"))
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
