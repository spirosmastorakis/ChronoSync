/* -*- Mode:C++; c-file-style:"gnu"; indent-tabs-mode:nil -*- */
/*
 * Copyright (c) 2013, Regents of the University of California
 *                     Yingdi Yu
 *
 * BSD license, See the LICENSE file for more information
 *
 * Author: Yingdi Yu <yingdi@cs.ucla.edu>
 */

#include "sync-policy-manager.h"

#include "sync-intro-certificate.h"
#include "sync-logging.h"

using namespace ndn;
using namespace ndn::security;
using namespace std;

INIT_LOGGER("SyncPolicyManager");

SyncPolicyManager::SyncPolicyManager(const Name& signingIdentity,
				     const Name& signingCertificateName,
				     const Name& syncPrefix,
                                     int stepLimit)
  : m_signingIdentity(signingIdentity)
  , m_signingCertificateName(signingCertificateName.getPrefix(signingCertificateName.size()-1))
  , m_syncPrefix(syncPrefix)
  , m_stepLimit(stepLimit)
{
  Name wotPrefix = syncPrefix;
  wotPrefix.append("WOT");
  m_syncPrefixRegex = Regex::fromName(syncPrefix);
  m_wotPrefixRegex = Regex::fromName(wotPrefix);
  m_chatDataPolicy = Ptr<IdentityPolicyRule>(new IdentityPolicyRule("^[^<FH>]*<FH>([^<chronos>]*)<chronos><>",
                                                                    "^([^<KEY>]*)<KEY>(<>*)[<dsk-.*><ksk-.*>]<ID-CERT>$",
                                                                    "==", "\\1", "\\1", true));  
}
  
SyncPolicyManager::~SyncPolicyManager()
{}

bool 
SyncPolicyManager::skipVerifyAndTrust (const Data& data)
{ return false; }

bool
SyncPolicyManager::requireVerify (const Data& data)
{ return true; }

Ptr<ValidationRequest>
SyncPolicyManager::checkVerificationPolicy(Ptr<Data> data, 
					   const int& stepCount, 
					   const DataCallback& verifiedCallback,
					   const UnverifiedCallback& unverifiedCallback)
{
// #ifdef _DEBUG
//   _LOG_DEBUG("checkVerificationPolicy");
//   verifiedCallback(data);
//   return NULL;
// #else
  //TODO:
  if(stepCount > m_stepLimit)
    {
      unverifiedCallback(data);
      return NULL;
    }

  Ptr<const signature::Sha256WithRsa> sha256sig = DynamicCast<const signature::Sha256WithRsa> (data->getSignature());
  if(KeyLocator::KEYNAME != sha256sig->getKeyLocator().getType())
    {
      unverifiedCallback(data);
      return NULL;
    }

  const Name& keyLocatorName = sha256sig->getKeyLocator().getKeyName();
  _LOG_DEBUG("data name: " << data->getName());
  _LOG_DEBUG("signer name: " << keyLocatorName);
  
  // if data is intro cert
  if(m_wotPrefixRegex->match(data->getName()))
    {
      _LOG_DEBUG("Intro Cert");
      Name keyName = IdentityCertificate::certificateNameToPublicKeyName(keyLocatorName);
      map<Name, Publickey>::const_iterator it = m_trustedIntroducers.find(keyName);
      if(m_trustedIntroducers.end() != it)
	{
	  if(verifySignature(*data, it->second))
	    verifiedCallback(data);
	  else
	    unverifiedCallback(data);
	  return NULL;
	}
      else
	return prepareRequest(keyName, true, data, stepCount, verifiedCallback, unverifiedCallback);
    }

  // if data is sync data or chat data
  if(m_syncPrefixRegex->match(data->getName()) || m_chatDataPolicy->satisfy(*data))
    {
      _LOG_DEBUG("Sync/Chat Data");
      Name keyName = IdentityCertificate::certificateNameToPublicKeyName(keyLocatorName);
      _LOG_DEBUG("keyName: " << keyName.toUri());

      map<Name, Publickey>::const_iterator it = m_trustedIntroducers.find(keyName);
      if(m_trustedIntroducers.end() != it)
	{
          _LOG_DEBUG("Find trusted introducer!");
	  if(verifySignature(*data, it->second))
	    verifiedCallback(data);
	  else
	    unverifiedCallback(data);
	  return NULL;
	}

      it = m_trustedProducers.find(keyName);
      if(m_trustedProducers.end() != it)
	{
          _LOG_DEBUG("Find trusted producer!");
	  if(verifySignature(*data, it->second))
	    verifiedCallback(data);
	  else
	    unverifiedCallback(data);
	  return NULL;
	}

      _LOG_DEBUG("Did not find any trusted one!");
      return prepareRequest(keyName, false, data, stepCount, verifiedCallback, unverifiedCallback);
    }
  
  unverifiedCallback(data);
  return NULL;
// #endif
}

bool 
SyncPolicyManager::checkSigningPolicy(const Name& dataName, 
				      const Name& certificateName)
{ 

  return true;

// #ifdef _DEBUG
//   _LOG_DEBUG("checkSigningPolicy");
//   return true;
// #else
  // return (m_syncPrefixRegex->match(dataName) && certificateName.getPrefix(certificateName.size()-1) == m_signingCertificateName) ? true : false; 
// #endif
}
    
Name 
SyncPolicyManager::inferSigningIdentity(const ndn::Name& dataName)
{ return m_signingIdentity; }

void
SyncPolicyManager::addTrustAnchor(const IdentityCertificate& identityCertificate, bool isIntroducer)
{
  _LOG_DEBUG("Add intro/producer: " << identityCertificate.getPublicKeyName());
  if(isIntroducer)
    m_trustedIntroducers.insert(pair <Name, Publickey > (identityCertificate.getPublicKeyName(), identityCertificate.getPublicKeyInfo()));
  else
    m_trustedProducers.insert(pair <Name, Publickey > (identityCertificate.getPublicKeyName(), identityCertificate.getPublicKeyInfo()));
}

void
SyncPolicyManager::addChatDataRule(const Name& prefix, 
                                   const IdentityCertificate& identityCertificate,
                                   bool isIntroducer)
{
  // Name dataPrefix = prefix;
  // dataPrefix.append("chronos").append(m_syncPrefix.get(-1));
  // Ptr<Regex> dataRegex = Regex::fromName(prefix);
  // Name certName = identityCertificate.getName();
  // Name signerName = certName.getPrefix(certName.size()-1);
  // Ptr<Regex> signerRegex = Regex::fromName(signerName, true);
  
  // SpecificPolicyRule rule(dataRegex, signerRegex);
  // map<Name, SpecificPolicyRule>::iterator it = m_chatDataRules.find(dataPrefix);
  // if(it != m_chatDataRules.end())
  //   it->second = rule;
  // else
  //   m_chatDataRules.insert(pair <Name, SpecificPolicyRule > (dataPrefix, rule));

  addTrustAnchor(identityCertificate, isIntroducer);
}


Ptr<const vector<Name> >
SyncPolicyManager::getAllIntroducerName()
{
  Ptr<vector<Name> > nameList = Ptr<vector<Name> >(new vector<Name>);
  
  map<Name, Publickey>::iterator it =  m_trustedIntroducers.begin();
  for(; it != m_trustedIntroducers.end(); it++)
    nameList->push_back(it->first);
  
  return nameList;
}

Ptr<ValidationRequest>
SyncPolicyManager::prepareRequest(const Name& keyName, 
				  bool forIntroducer,
				  Ptr<Data> data,
				  const int & stepCount, 
				  const DataCallback& verifiedCallback,
				  const UnverifiedCallback& unverifiedCallback)
{
  Ptr<Name> interestPrefixName = Ptr<Name>(new Name(m_syncPrefix));
  interestPrefixName->append("WOT").append(keyName).append("INTRO-CERT");

  Ptr<const std::vector<ndn::Name> > nameList = getAllIntroducerName();
  if(0 == nameList->size())
    {
      unverifiedCallback(data);
      return NULL;
    }

  Name interestName = *interestPrefixName;
  interestName.append(nameList->at(0));

  if(forIntroducer)
    interestName.append("INTRODUCER");

  Ptr<Interest> interest = Ptr<Interest>(new Interest(interestName));
  _LOG_DEBUG("send interest for intro cert: " << interest->getName());
  interest->setChildSelector(Interest::CHILD_RIGHT);

  DataCallback requestedCertVerifiedCallback = boost::bind(&SyncPolicyManager::onIntroCertVerified, 
							   this, 
							   _1,
							   forIntroducer, 
							   data,
							   verifiedCallback,
							   unverifiedCallback);
                                                             
  UnverifiedCallback requestedCertUnverifiedCallback = boost::bind(&SyncPolicyManager::onIntroCertUnverified, 
								   this, 
								   _1, 
								   interestPrefixName,
								   forIntroducer,
								   nameList,
								   1,
								   data,
								   verifiedCallback,
								   unverifiedCallback);

    
  Ptr<ValidationRequest> nextStep = Ptr<ValidationRequest>(new ValidationRequest(interest, 
										 requestedCertVerifiedCallback,
										 requestedCertUnverifiedCallback,
										 1,
										 m_stepLimit-1)
							   );
  return nextStep;
}

void
SyncPolicyManager::onIntroCertVerified(Ptr<Data> introCertificateData,
				       bool forIntroducer,
				       Ptr<Data> originalData,
				       const DataCallback& verifiedCallback,
				       const UnverifiedCallback& unverifiedCallback)
{
  Ptr<SyncIntroCertificate> introCertificate = Ptr<SyncIntroCertificate>(new SyncIntroCertificate(*introCertificateData));
  if(forIntroducer)
    m_trustedIntroducers.insert(pair <Name, Publickey > (introCertificate->getPublicKeyName(), introCertificate->getPublicKeyInfo()));
  else
    m_trustedProducers.insert(pair <Name, Publickey > (introCertificate->getPublicKeyName(), introCertificate->getPublicKeyInfo()));

  if(verifySignature(*originalData, introCertificate->getPublicKeyInfo()))      
    verifiedCallback(originalData);    
  else
    unverifiedCallback(originalData);
}

void 
SyncPolicyManager::onIntroCertUnverified(Ptr<Data> introCertificateData,
					 Ptr<Name> interestPrefixName,
					 bool forIntroducer,
					 Ptr<const std::vector<ndn::Name> > introNameList,
					 const int& nextIntroducerIndex,
					 Ptr<Data> originalData,
					 const DataCallback& verifiedCallback,
					 const UnverifiedCallback& unverifiedCallback)
{
  Name interestName = *interestPrefixName;
  if(nextIntroducerIndex < introNameList->size())
    interestName.append(introNameList->at(nextIntroducerIndex));
  else
    unverifiedCallback(originalData);

  if(forIntroducer)
    interestName.append("INTRODUCER");
  
  Ptr<Interest> interest = Ptr<Interest>(new Interest(interestName));
  interest->setChildSelector(Interest::CHILD_RIGHT);

  DataCallback requestedCertVerifiedCallback = boost::bind(&SyncPolicyManager::onIntroCertVerified, 
							   this, 
							   _1,
							   forIntroducer, 
							   originalData,
							   verifiedCallback,
							   unverifiedCallback);
    
  UnverifiedCallback requestedCertUnverifiedCallback = boost::bind(&SyncPolicyManager::onIntroCertUnverified, 
								   this, 
								   _1,
								   interestPrefixName,
								   forIntroducer,
								   introNameList,
								   nextIntroducerIndex + 1,
								   originalData, 
								   verifiedCallback,
								   unverifiedCallback);
  
  TimeoutCallback requestedCertTimeoutCallback = boost::bind(&SyncPolicyManager::onIntroCertTimeOut, 
							     this, 
							     _1, 
							     _2, 
							     1,
							     requestedCertUnverifiedCallback,
							     originalData);
      
  Ptr<Closure> closure = Ptr<Closure> (new Closure(requestedCertVerifiedCallback,
						   requestedCertTimeoutCallback,
						   requestedCertUnverifiedCallback,
						   m_stepLimit-1)
				       );
    
  m_handler->sendInterest(interest, closure);
}

void
SyncPolicyManager::onIntroCertTimeOut(Ptr<Closure> closure, 
				      Ptr<Interest> interest, 
				      int retry, 
				      const UnverifiedCallback& unverifiedCallback,
				      Ptr<Data> data)
{
  if(retry > 0)
    {
      Ptr<Closure> newClosure = Ptr<Closure>(new Closure(closure->m_dataCallback,
							 boost::bind(&SyncPolicyManager::onIntroCertTimeOut, 
								     this, 
								     _1, 
								     _2, 
								     retry - 1, 
								     unverifiedCallback,
								     data),
							 closure->m_unverifiedCallback,
							 closure->m_stepCount)
					     );
      m_handler->sendInterest(interest, newClosure);
    }
  else
    unverifiedCallback(data);
}
