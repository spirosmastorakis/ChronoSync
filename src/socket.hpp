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
 * @author Zhenkai Zhu <http://irl.cs.ucla.edu/~zhenkai/>
 * @author Chaoyi Bian <bcy@pku.edu.cn>
 * @author Alexander Afanasyev <http://lasr.cs.ucla.edu/afanasyev/index.html>
 * @author Yingdi Yu <yingdi@cs.ucla.edu>
 */

#ifndef CHRONOSYNC_SOCKET_HPP
#define CHRONOSYNC_SOCKET_HPP

#include <ndn-cxx/face.hpp>
#include <ndn-cxx/security/validation-request.hpp>

#include "logic.hpp"

namespace chronosync {

/**
 * @brief A simple interface to interact with client code
 *
 * Though it is called Socket, it is not a real socket. It just trying to provide
 * a simplified interface for data publishing and fetching.
 *
 * This interface simplify data publishing.  Client can simply dump raw data
 * into this interface without handling the ChronoSync specific details, such
 * as sequence number and session id.
 *
 * This interface also simplify data fetching.  Client only needs to provide a
 * data fetching strategy (through a updateCallback).
 */
class Socket : noncopyable
{
public:
  class Error : public std::runtime_error
  {
  public:
    explicit
    Error(const std::string& what)
      : std::runtime_error(what)
    {
    }
  };

  Socket(const Name& syncPrefix,
         const Name& userPrefix,
         ndn::Face& face,
         const UpdateCallback& updateCallback);

  /**
   * @brief Publish a data packet in the session and trigger synchronization updates
   *
   * This method will create a data packet with the supplied content.
   * The packet name is the local session + seqNo.
   * The seqNo is automatically maintained by internal Logic.
   *
   * @param buf Pointer to the bytes in content
   * @param len size of the bytes in content
   * @param freshness FreshnessPeriod of the data packet.
   */
  void
  publishData(const uint8_t* buf, size_t len, const ndn::time::milliseconds& freshness);

  /**
   * @brief Publish a data packet in the session and trigger synchronization updates
   *
   * This method will create a data packet with the supplied content.
   * The packet name is the local session + seqNo.
   * The seqNo is automatically maintained by internal Logic.
   *
   * @param content Block that will be set as the content of the data packet.
   * @param freshness FreshnessPeriod of the data packet.
   */
  void
  publishData(const Block& content, const ndn::time::milliseconds& freshness);

  /**
   * @brief Retrive a data packet with a particular seqNo from a session
   *
   * @param sessionName The name of the target session.
   * @param seq The seqNo of the data packet.
   * @param onValidated The callback when the retrieved packet has been validated.
   * @param nRetries The number of retries.
   */
  void
  fetchData(const Name& sessionName, const SeqNo& seq,
            const ndn::OnDataValidated& onValidated,
            int nRetries = 0);

  /**
   * @brief Retrive a data packet with a particular seqNo from a session
   *
   * @param sessionName The name of the target session.
   * @param seq The seqNo of the data packet.
   * @param onValidated The callback when the retrieved packet has been validated.
   * @param nRetries The number of retries.
   */
  void
  fetchData(const Name& sessionName, const SeqNo& seq,
            const ndn::OnDataValidated& onValidated,
            const ndn::OnDataValidationFailed& onValidationFailed,
            const ndn::OnTimeout& onTimeout,
            int nRetries = 0);

  /// @brief Get the root digest of current sync tree
  ndn::ConstBufferPtr
  getRootDigest() const;

  Logic&
  getLogic()
  {
    return m_logic;
  }

private:
  void
  onData(const Interest& interest, Data& data,
         const ndn::OnDataValidated& dataCallback,
         const ndn::OnDataValidationFailed& failCallback);

  void
  onDataTimeout(const Interest& interest, int nRetries,
                const ndn::OnDataValidated& dataCallback,
                const ndn::OnDataValidationFailed& failCallback);

  void
  onDataValidationFailed(const shared_ptr<const Data>& data,
                         const std::string& failureInfo);

private:

  Name m_userPrefix;
  ndn::Face& m_face;

  Logic m_logic;

  ndn::KeyChain m_keyChain;
};

} // namespace chronosync

#endif // CHRONOSYNC_SOCKET_HPP
