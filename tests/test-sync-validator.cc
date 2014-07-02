/* -*- Mode:C++; c-file-style:"gnu"; indent-tabs-mode:nil -*- */
/*
 * Copyright (c) 2012 University of California, Los Angeles
 */

#include <boost/test/unit_test.hpp>
#include "sync-validator.h"

#include <boost/lexical_cast.hpp>
#include <boost/asio.hpp>
#include <ndn-cxx/util/scheduler.hpp>

BOOST_AUTO_TEST_SUITE(TestSyncValidator)

void
onValidated(const ndn::shared_ptr<const ndn::Data>& data)
{
  BOOST_CHECK(true);
}

void
onValidationFailed(const ndn::shared_ptr<const ndn::Data>& data,
                   const std::string& failureInfo)
{
  BOOST_CHECK(false);
}

void
onValidated2(const ndn::shared_ptr<const ndn::Data>& data)
{
  BOOST_CHECK(false);
}

void
onValidationFailed2(const ndn::shared_ptr<const ndn::Data>& data,
                    const std::string& failureInfo)
{
  BOOST_CHECK(true);
}

void
publishData(const uint8_t* buf, size_t len, int freshness)
{
}

BOOST_AUTO_TEST_CASE (Graph)
{
  using namespace Sync;
  using namespace ndn;

  Name prefix("/Sync/TestSyncValidator/AddEdge");
  KeyChain keychain;

  Name identity1("/TestSyncValidator/AddEdge-1/" + boost::lexical_cast<std::string>(ndn::time::toUnixTimestamp(ndn::time::system_clock::now()).count()));
  Name certName1 = keychain.createIdentity(identity1);
  shared_ptr<IdentityCertificate> anchor = keychain.getCertificate(certName1);

  Name identity2("/TestSyncValidator/AddEdge-2/" + boost::lexical_cast<std::string>(ndn::time::toUnixTimestamp(ndn::time::system_clock::now()).count()));
  Name certName2 = keychain.createIdentity(identity2);
  shared_ptr<IdentityCertificate> introducer = keychain.getCertificate(certName2);

  Name identity3("/TestSyncValidator/AddEdge-3/" + boost::lexical_cast<std::string>(ndn::time::toUnixTimestamp(ndn::time::system_clock::now()).count()));
  Name certName3 = keychain.createIdentity(identity3);
  shared_ptr<IdentityCertificate> introducee = keychain.getCertificate(certName3);

  Name identity4("/TestSyncValidator/AddEdge-4/" + boost::lexical_cast<std::string>(ndn::time::toUnixTimestamp(ndn::time::system_clock::now()).count()));
  Name certName4 = keychain.createIdentity(identity4);
  shared_ptr<IdentityCertificate> introducer2 = keychain.getCertificate(certName4);

  Name identity5("/TestSyncValidator/AddEdge-5/" + boost::lexical_cast<std::string>(ndn::time::toUnixTimestamp(ndn::time::system_clock::now()).count()));
  Name certName5 = keychain.createIdentity(identity5);
  shared_ptr<IdentityCertificate> introducee2 = keychain.getCertificate(certName5);

  shared_ptr<boost::asio::io_service> ioService = make_shared<boost::asio::io_service>();
  shared_ptr<Face> face = make_shared<Face>(ref(*ioService));
  shared_ptr<SecRuleRelative> rule;
  SyncValidator validator(prefix, *anchor, *face,
                          bind(&publishData, _1, _2, _3),
                          rule);

  validator.addParticipant(*introducer);
  BOOST_CHECK(validator.canTrust(certName2));

  IntroCertificate introCert(prefix, *introducee, certName2.getPrefix(-1));
  keychain.sign(introCert, certName2);
  validator.addParticipant(introCert);
  BOOST_CHECK(validator.canTrust(certName3));

  IntroCertificate introCert1(prefix, *anchor, certName3.getPrefix(-1));
  keychain.sign(introCert1, certName3);
  validator.addParticipant(introCert1);
  validator.setAnchor(*introducer);
  BOOST_CHECK(validator.canTrust(certName2));
  BOOST_CHECK(validator.canTrust(certName3));
  BOOST_CHECK(validator.canTrust(certName1));

  IntroCertificate introCert2(prefix, *introducee2, certName4.getPrefix(-1));
  keychain.sign(introCert2, certName4);
  validator.addParticipant(introCert2);
  BOOST_CHECK(validator.canTrust(certName5) == false);
  BOOST_CHECK(validator.canTrust(certName4) == false);

  IntroCertificate introCert3(prefix, *introducee, certName5.getPrefix(-1));
  keychain.sign(introCert3, certName5);
  validator.addParticipant(introCert3);
  BOOST_CHECK(validator.canTrust(certName5) == false);
  BOOST_CHECK(validator.canTrust(certName4) == false);

  validator.setAnchor(*introducee2);
  BOOST_CHECK(validator.canTrust(certName1));
  BOOST_CHECK(validator.canTrust(certName2));
  BOOST_CHECK(validator.canTrust(certName3));
  BOOST_CHECK(validator.canTrust(certName4) == false);
  BOOST_CHECK(validator.canTrust(certName5));


  keychain.deleteIdentity(identity1);
  keychain.deleteIdentity(identity2);
  keychain.deleteIdentity(identity3);
  keychain.deleteIdentity(identity4);
  keychain.deleteIdentity(identity5);
}

BOOST_AUTO_TEST_CASE (OfflineValidate)
{
  using namespace Sync;
  using namespace ndn;

  Name prefix("/Sync/TestSyncValidator/OfflineValidate");
  KeyChain keychain;

  Name identity1("/TestSyncValidator/OfflineValidate-1/"
                 + boost::lexical_cast<std::string>(ndn::time::toUnixTimestamp(ndn::time::system_clock::now()).count()));
  Name certName1 = keychain.createIdentity(identity1);
  shared_ptr<IdentityCertificate> anchor = keychain.getCertificate(certName1);

  Name identity2("/TestSyncValidator/OfflineValidate-2/"
                 + boost::lexical_cast<std::string>(ndn::time::toUnixTimestamp(ndn::time::system_clock::now()).count()));
  Name certName2 = keychain.createIdentity(identity2);
  shared_ptr<IdentityCertificate> introducer = keychain.getCertificate(certName2);

  Name identity3("/TestSyncValidator/OfflineValidate-3/"
                 + boost::lexical_cast<std::string>(ndn::time::toUnixTimestamp(ndn::time::system_clock::now()).count()));
  Name certName3 = keychain.createIdentity(identity3);
  shared_ptr<IdentityCertificate> introducee = keychain.getCertificate(certName3);

  Name identity4("/TestSyncValidator/OfflineValidate-4/"
                 + boost::lexical_cast<std::string>(ndn::time::toUnixTimestamp(ndn::time::system_clock::now()).count()));
  Name certName4 = keychain.createIdentity(identity4);
  shared_ptr<IdentityCertificate> introducer2 = keychain.getCertificate(certName4);

  Name identity5("/TestSyncValidator/OfflineValidate-5/"
                 + boost::lexical_cast<std::string>(ndn::time::toUnixTimestamp(ndn::time::system_clock::now()).count()));
  Name certName5 = keychain.createIdentity(identity5);
  shared_ptr<IdentityCertificate> introducee2 = keychain.getCertificate(certName5);

  shared_ptr<boost::asio::io_service> ioService = make_shared<boost::asio::io_service>();
  shared_ptr<Face> face = make_shared<Face>(ref(*ioService));
  shared_ptr<SecRuleRelative> rule;
  SyncValidator validator(prefix, *anchor, *face,
                          bind(&publishData, _1, _2, _3),
                          rule);

  validator.addParticipant(*introducer);
  BOOST_CHECK(validator.canTrust(certName2));

  IntroCertificate introCert(prefix, *introducee, certName2.getPrefix(-1));
  keychain.sign(introCert, certName2);
  validator.addParticipant(introCert);
  BOOST_CHECK(validator.canTrust(certName3));

  IntroCertificate introCert2(prefix, *introducee2, certName4.getPrefix(-1));
  keychain.sign(introCert2, certName4);
  validator.addParticipant(introCert2);
  BOOST_CHECK(validator.canTrust(certName5) == false);
  BOOST_CHECK(validator.canTrust(certName4) == false);

  validator.setAnchor(*introducer2);
  BOOST_CHECK(validator.canTrust(certName1) == false);
  BOOST_CHECK(validator.canTrust(certName2) == false);
  BOOST_CHECK(validator.canTrust(certName3) == false);
  BOOST_CHECK(validator.canTrust(certName4));
  BOOST_CHECK(validator.canTrust(certName5));

  Name dataName1 = prefix;
  dataName1.append("data-1");
  shared_ptr<Data> data1 = make_shared<Data>(dataName1);
  keychain.sign(*data1, certName5);

  validator.validate(*data1,
		     bind(&onValidated, _1),
		     bind(&onValidationFailed, _1, _2));

  Name dataName2 = prefix;
  dataName2.append("data-2");
  shared_ptr<Data> data2 = make_shared<Data>(dataName2);
  keychain.sign(*data2, certName1);

  validator.validate(*data2,
		     bind(&onValidated2, _1),
		     bind(&onValidationFailed2, _1, _2));

  // ioService->run();

  keychain.deleteIdentity(identity1);
  keychain.deleteIdentity(identity2);
  keychain.deleteIdentity(identity3);
  keychain.deleteIdentity(identity4);
  keychain.deleteIdentity(identity5);
}

struct FacesFixture
{
  FacesFixture()
    : regPrefixId(0)
    , regPrefixId2(0)
  {}

  void
  onInterest(ndn::shared_ptr<ndn::Face> face, ndn::shared_ptr<ndn::Data> data)
  {
    face->put(*data);
    face->unsetInterestFilter(regPrefixId);
  }

  void
  onInterest2(ndn::shared_ptr<ndn::Face> face, ndn::shared_ptr<ndn::Data> data)
  {
    face->put(*data);
    face->unsetInterestFilter(regPrefixId2);
  }

  void
  onRegFailed()
  {}

  void
  validate(ndn::shared_ptr<Sync::SyncValidator> validator, ndn::shared_ptr<ndn::Data> data,
           const ndn::Name& certName3, const ndn::Name& certName4)
  {
    validator->validate(*data,
                        bind(&onValidated, _1),
                        bind(&onValidationFailed, _1, _2));


    BOOST_CHECK(validator->canTrust(certName3));
    BOOST_CHECK(validator->canTrust(certName4));
  }

  void
  terminate(ndn::shared_ptr<ndn::Face> face)
  {
    face->getIoService().stop();
  }

  const ndn::RegisteredPrefixId* regPrefixId;
  const ndn::RegisteredPrefixId* regPrefixId2;
};

BOOST_FIXTURE_TEST_CASE(OnlineValidate, FacesFixture)
{
  using namespace Sync;
  using namespace ndn;

  Name prefix("/Sync/TestSyncValidator/OnlineValidate");
  KeyChain keychain;

  Name identity1("/TestSyncValidator/OnlineValidate-1/"
                 + boost::lexical_cast<std::string>(ndn::time::toUnixTimestamp(ndn::time::system_clock::now()).count()));
  Name certName1 = keychain.createIdentity(identity1);
  shared_ptr<IdentityCertificate> anchor = keychain.getCertificate(certName1);

  Name identity2("/TestSyncValidator/OnlineValidate-2/"
                 + boost::lexical_cast<std::string>(ndn::time::toUnixTimestamp(ndn::time::system_clock::now()).count()));
  Name certName2 = keychain.createIdentity(identity2);
  shared_ptr<IdentityCertificate> introducer = keychain.getCertificate(certName2);

  Name identity3("/TestSyncValidator/OnlineValidate-3/"
                 + boost::lexical_cast<std::string>(ndn::time::toUnixTimestamp(ndn::time::system_clock::now()).count()));
  Name certName3 = keychain.createIdentity(identity3);
  shared_ptr<IdentityCertificate> introducee = keychain.getCertificate(certName3);

  Name identity4("/TestSyncValidator/OnlineValidate-4/"
                 + boost::lexical_cast<std::string>(ndn::time::toUnixTimestamp(ndn::time::system_clock::now()).count()));
  Name certName4 = keychain.createIdentity(identity4);
  shared_ptr<IdentityCertificate> introducee2 = keychain.getCertificate(certName4);

  shared_ptr<boost::asio::io_service> ioService = make_shared<boost::asio::io_service>();
  shared_ptr<Face> face = make_shared<Face>(ref(*ioService));
  shared_ptr<Face> face2 = make_shared<Face>(ref(*ioService));

  shared_ptr<SecRuleRelative> rule;
  shared_ptr<SyncValidator> validator = shared_ptr<SyncValidator>
    (new SyncValidator(prefix, *anchor, *face2, bind(&publishData, _1, _2, _3), rule));

  validator->addParticipant(*introducer);
  BOOST_CHECK(validator->canTrust(certName2));

  shared_ptr<IntroCertificate> introCert = shared_ptr<IntroCertificate>(new IntroCertificate(prefix, *introducee, certName2.getPrefix(-1)));
  keychain.sign(*introCert, certName2);
  BOOST_CHECK(validator->canTrust(certName3) == false);

  shared_ptr<IntroCertificate> introCert2 = shared_ptr<IntroCertificate>(new IntroCertificate(prefix, *introducee2, certName3.getPrefix(-1)));
  keychain.sign(*introCert2, certName3);
  BOOST_CHECK(validator->canTrust(certName4) == false);

  Name dataName1 = prefix;
  dataName1.append("data-1");
  shared_ptr<Data> data1 = make_shared<Data>(dataName1);
  keychain.sign(*data1, certName4);

  ndn::Scheduler scheduler(*ioService);

  scheduler.scheduleEvent(time::seconds(1),
                          bind(&FacesFixture::terminate, this, face));

  regPrefixId = face->setInterestFilter(introCert->getName().getPrefix(-1),
                                       bind(&FacesFixture::onInterest, this, face, introCert),
                                       bind(&FacesFixture::onRegFailed, this));

  regPrefixId2 = face->setInterestFilter(introCert2->getName().getPrefix(-1),
					bind(&FacesFixture::onInterest2, this, face, introCert2),
					bind(&FacesFixture::onRegFailed, this));

  scheduler.scheduleEvent(time::milliseconds(200),
                          bind(&FacesFixture::validate, this,
			       validator, data1, certName3, certName4));

  keychain.deleteIdentity(identity1);
  keychain.deleteIdentity(identity2);
  keychain.deleteIdentity(identity3);
  keychain.deleteIdentity(identity4);
}

BOOST_AUTO_TEST_SUITE_END()
