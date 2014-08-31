/* -*- Mode: C++; c-file-style: "gnu"; indent-tabs-mode:nil -*- */
/*
 * Copyright (c) 2012-2014 University of California, Los Angeles
 *
 * This file is part of ChronoSync, synchronization library for distributed realtime
 * applications for NDN.
 *
 * ChronoSync is free software: you can redistribute it and/or modify it under the terms
 * of the GNU General Public License as published by the Free Software Foundation, either
 * version 3 of the License, or (at your option) any later version.
 *
 * ChronoSync is distributed in the hope that it will be useful, but WITHOUT ANY WARRANTY;
 * without even the implied warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR
 * PURPOSE.  See the GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License along with
 * ChronoSync, e.g., in COPYING.md file.  If not, see <http://www.gnu.org/licenses/>.
 *
 * @author Yingdi Yu <http://irl.cs.ucla.edu/~yingdi/web/index.html>
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
