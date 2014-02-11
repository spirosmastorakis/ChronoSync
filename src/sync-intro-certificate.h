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

#include <ndn-cpp-dev/security/identity-certificate.hpp>
#include <ndn-cpp-dev/security/signature-sha256-with-rsa.hpp>

namespace Sync {

class IntroCertificate : public ndn::Data
{
public:
  struct Error : public ndn::Data::Error { Error(const std::string &what) : ndn::Data::Error(what) {} };

  IntroCertificate()
  {}
  
  /**
   * @brief Construct IntroCertificate from IdentityCertificate
   *
   * @param syncPrefix
   * @param introduceeCert
   * @param introducerName
   */
  IntroCertificate(const ndn::Name& syncPrefix,
                   const ndn::IdentityCertificate& introduceeCert,
                   const ndn::Name& introducerName); //without version number

  /**
   * @brief Construct IntroCertificate using a plain data.
   * 
   * if data is not actually IntroCertificate, Error will be thrown out.
   *
   * @param data
   * @throws ndn::IntroCertificate::Error.
   */
  IntroCertificate(const ndn::Data& data);

  virtual
  ~IntroCertificate() {};

  const ndn::IdentityCertificate&
  getIntroduceeCert() const
  {
    return m_introduceeCert;
  }

  const ndn::Name&
  getIntroducerName() const
  {
    return m_introducerName;
  }

  const ndn::Name&
  getIntroduceeName() const
  {
    return m_introduceeName;
  }

private:
  ndn::Name m_syncPrefix;
  ndn::IdentityCertificate m_introduceeCert;
  ndn::Name m_introducerName;
  ndn::Name m_introduceeName;
};

inline
IntroCertificate::IntroCertificate(const ndn::Name& syncPrefix,
                                   const ndn::IdentityCertificate& introduceeCert,
                                   const ndn::Name& introducerName)
  : m_syncPrefix(syncPrefix)
  , m_introduceeCert(introduceeCert)
  , m_introducerName(introducerName)
  , m_introduceeName(introduceeCert.getName().getPrefix(-1))
{
  // Naming convention /<sync_prefix>/intro-cert/introducee_certname/introducer_certname/version/
  ndn::Name dataName = m_syncPrefix;
  dataName.append("intro-cert").append(introduceeCert.getName().getPrefix(-1).wireEncode()).append(introducerName.wireEncode()).appendVersion();
  
  setName(dataName);
  setContent(introduceeCert.wireEncode());
}

inline
IntroCertificate::IntroCertificate(const ndn::Data& data)
  : Data(data)
{
  ndn::Name dataName = data.getName();
  ndn::Name introduceeCertName;
  ndn::Name introducerName;

  if(dataName.size() < 4 || dataName.get(-4).toEscapedString() != "intro-cert")
    throw Error("Not a Sync::IntroCertificate");

  m_syncPrefix = dataName.getPrefix(-4);

  try
    {
      m_introduceeCert.wireDecode(data.getContent().blockFromValue());
      m_introducerName.wireDecode(dataName.get(-2).blockFromValue());
      introduceeCertName.wireDecode(dataName.get(-3).blockFromValue());
    }
  catch(ndn::IdentityCertificate::Error& e)
    {
      throw Error("Cannot decode introducee cert");
    }
  catch(ndn::Name::Error& e)
    {
      throw Error("Cannot decode name");
    }
  catch(ndn::Block::Error& e)
    {
      throw Error("Cannot decode block name");
    }

  if(introduceeCertName != m_introduceeCert.getName().getPrefix(-1))
    throw Error("Invalid Sync::IntroCertificate (inconsistent introducee name)");

  m_introduceeName = introduceeCertName;

  try
    {
      ndn::SignatureSha256WithRsa sig(data.getSignature());
      introducerName = sig.getKeyLocator().getName();
    }
  catch(ndn::KeyLocator::Error& e)
    {
      throw Error("Invalid Sync::IntroCertificate (inconsistent introducer name#1)");
    }
  catch(ndn::SignatureSha256WithRsa::Error& e)
    {
      throw Error("Invalid Sync::IntroCertificate (inconsistent introducer name#2)");
    }

  if(m_introducerName != introducerName)
    throw Error("Invalid Sync::IntroCertificate (inconsistent introducer name#3)");

  if(m_introducerName != introducerName)
    throw Error("Invalid Sync::IntroCertificate (inconsistent introducer name#3)");
}


} // namespace Sync

#endif //SYNC_INTRO_CERTIFICATE_H
