/* -*- Mode:C++; c-file-style:"gnu"; indent-tabs-mode:nil -*- */
/*
 * Copyright (c) 2013, Regents of the University of California
 *                     Yingdi Yu
 *
 * BSD license, See the LICENSE file for more information
 *
 * Author: Yingdi Yu <yingdi@cs.ucla.edu>
 */

#ifndef SPECIFIC_POLICY_RULE_H
#define SPECIFIC_POLICY_RULE_H

#include <ndn.cxx/security/policy/policy-rule.h>
#include <ndn.cxx/regex/regex.h>

class SpecificPolicyRule : public ndn::security::PolicyRule
{
  
public:
  SpecificPolicyRule(ndn::Ptr<ndn::Regex> dataRegex,
                     ndn::Ptr<ndn::Regex> signerRegex);

  SpecificPolicyRule(const SpecificPolicyRule& rule);

  virtual
  ~SpecificPolicyRule() {};

  bool 
  matchDataName(const ndn::Data & data);

  bool 
  matchSignerName(const ndn::Data & data);

  bool
  satisfy(const ndn::Data & data);

  bool
  satisfy(const ndn::Name & dataName, const ndn::Name & signerName);
  
private:
  ndn::Ptr<ndn::Regex> m_dataRegex;
  ndn::Ptr<ndn::Regex> m_signerRegex;
};

#endif //CHAT_POLICY_RULE_H
