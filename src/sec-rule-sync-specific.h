/* -*- Mode:C++; c-file-style:"gnu"; indent-tabs-mode:nil -*- */
/*
 * Copyright (c) 2013, Regents of the University of California
 *                     Yingdi Yu
 *
 * BSD license, See the LICENSE file for more information
 *
 * Author: Yingdi Yu <yingdi@cs.ucla.edu>
 */

#ifndef SEC_RULE_SYNC_SPECIFIC_H
#define SEC_RULE_SYNC_SPECIFIC_H

#include <ndn-cpp-et/policy/sec-rule.hpp>
#include <ndn-cpp-et/regex/regex.hpp>

class SecRuleSyncSpecific : public ndn::SecRule
{
  
public:
  SecRuleSyncSpecific(ndn::ptr_lib::shared_ptr<ndn::Regex> dataRegex,
                      ndn::ptr_lib::shared_ptr<ndn::Regex> signerRegex);

  SecRuleSyncSpecific(const SecRuleSyncSpecific& rule);

  virtual
  ~SecRuleSyncSpecific() {};

  bool 
  matchDataName(const ndn::Data& data);

  bool 
  matchSignerName(const ndn::Data& data);

  bool
  satisfy(const ndn::Data& data);

  bool
  satisfy(const ndn::Name& dataName, const ndn::Name& signerName);
  
private:
  ndn::ptr_lib::shared_ptr<ndn::Regex> m_dataRegex;
  ndn::ptr_lib::shared_ptr<ndn::Regex> m_signerRegex;
};

#endif
