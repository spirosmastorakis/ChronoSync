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

#include <ndn-cxx/security/identity-certificate.hpp>
#include <ndn-cxx/security/signature-sha256-with-rsa.hpp>

namespace Sync {

class IntroCertificate : public ndn::Data
{
  /**
   * Naming convention of IntroCertificate:
   * /<sync_prefix>/CHRONOS-INTRO-CERT/introducee_certname/introducer_certname/version
   * Content: introducee's identity certificate;
   * KeyLocator: introducer's identity certificate;
   */
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
                   const ndn::Name& introducerCertName); //without version number

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
  getIntroducerCertName() const
  {
    return m_introducerCertName;
  }

  const ndn::Name&
  getIntroduceeCertName() const
  {
    return m_introduceeCertName;
  }

private:
  ndn::Name m_syncPrefix;
  ndn::IdentityCertificate m_introduceeCert;
  ndn::Name m_introducerCertName;
  ndn::Name m_introduceeCertName;
};

inline
IntroCertificate::IntroCertificate(const ndn::Name& syncPrefix,
                                   const ndn::IdentityCertificate& introduceeCert,
                                   const ndn::Name& introducerCertName)
  : m_syncPrefix(syncPrefix)
  , m_introduceeCert(introduceeCert)
  , m_introducerCertName(introducerCertName)
  , m_introduceeCertName(introduceeCert.getName().getPrefix(-1))
{
  // Naming convention /<sync_prefix>/CHRONOS-INTRO-CERT/introducee_certname/introducer_certname/version
  ndn::Name dataName = m_syncPrefix;
  dataName.append("CHRONOS-INTRO-CERT")
    .append(m_introduceeCertName.wireEncode())
    .append(m_introducerCertName.wireEncode())
    .appendVersion();

  setName(dataName);
  setContent(m_introduceeCert.wireEncode());
}

inline
IntroCertificate::IntroCertificate(const ndn::Data& data)
  : Data(data)
{
  // Naming convention /<sync_prefix>/CHRONOS-INTRO-CERT/introducee_certname/introducer_certname/version
  ndn::Name dataName = data.getName();

  if(dataName.size() < 4 || dataName.get(-4).toUri() != "CHRONOS-INTRO-CERT")
    throw Error("Not a Sync::IntroCertificate");

  try
    {
      m_introduceeCert.wireDecode(data.getContent().blockFromValue());
      m_introducerCertName.wireDecode(dataName.get(-2).blockFromValue());
      m_introduceeCertName.wireDecode(dataName.get(-3).blockFromValue());
      m_syncPrefix = dataName.getPrefix(-4);
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

  if(m_introduceeCertName != m_introduceeCert.getName().getPrefix(-1))
    throw Error("Invalid Sync::IntroCertificate (inconsistent introducee name)");

  ndn::Name keyLocatorName;
  try
    {
      ndn::SignatureSha256WithRsa sig(data.getSignature());
      keyLocatorName = sig.getKeyLocator().getName();
    }
  catch(ndn::KeyLocator::Error& e)
    {
      throw Error("Invalid Sync::IntroCertificate (inconsistent introducer name#1)");
    }
  catch(ndn::SignatureSha256WithRsa::Error& e)
    {
      throw Error("Invalid Sync::IntroCertificate (inconsistent introducer name#2)");
    }

  if(m_introducerCertName != keyLocatorName)
    throw Error("Invalid Sync::IntroCertificate (inconsistent introducer name#3)");
}


} // namespace Sync

#endif //SYNC_INTRO_CERTIFICATE_H
