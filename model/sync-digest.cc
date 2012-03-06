/* -*- Mode: C++; c-file-style: "gnu"; indent-tabs-mode:nil -*- */
/*
 * Copyright (c) 2012 University of California, Los Angeles
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2 as
 * published by the Free Software Foundation;
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA
 *
 * Author: Zhenkai Zhu <zhenkai@cs.ucla.edu>
 *         卞超轶 Chaoyi Bian <bcy@pku.edu.cn>
 *	   Alexander Afanasyev <alexander.afanasyev@ucla.edu>
 */

#include "sync-digest.h"
#include <string.h>

#include <boost/assert.hpp>
#include <boost/exception/errinfo_at_line.hpp>

// for printing, may be disabled in optimized build

// #ifdef DIGEST_BASE64
// #include <boost/archive/iterators/base64_from_binary.hpp>
// #include <boost/archive/iterators/binary_from_base64.hpp>
// #endif

#include <boost/archive/iterators/transform_width.hpp>
#include <boost/iterator/transform_iterator.hpp>
#include <boost/archive/iterators/dataflow_exception.hpp>

using namespace boost;
using namespace boost::archive::iterators;
using namespace std;

// Other options: VP_md2, EVP_md5, EVP_sha, EVP_sha1, EVP_sha256, EVP_dss, EVP_dss1, EVP_mdc2, EVP_ripemd160
#define HASH_FUNCTION EVP_sha1


// #ifndef DIGEST_BASE64

template<class CharType>
struct hex_from_4_bit
{
  typedef CharType result_type;
  CharType operator () (CharType ch) const
  {
    const char *lookup_table = "0123456789abcdef";
    // cout << "New character: " << (int) ch << " (" << (char) ch << ")" << "\n";
    BOOST_ASSERT (ch < 16);
    return lookup_table[static_cast<size_t>(ch)];
  }
};

typedef transform_iterator<hex_from_4_bit<string::const_iterator::value_type>,
                           transform_width<string::const_iterator, 4, 8, string::const_iterator::value_type> > string_from_binary;


template<class CharType>
struct hex_to_4_bit
{
  typedef CharType result_type;
  CharType operator () (CharType ch) const
  {
    const signed char lookup_table [] = {
      -1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,
      -1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,
      -1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,
      0, 1, 2, 3, 4, 5, 6, 7, 8, 9,-1,-1,-1,-1,-1,-1,
      -1,10,11,12,13,14,15,-1,-1,-1,-1,-1,-1,-1,-1,-1,
      -1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,
      -1,10,11,12,13,14,15,-1,-1,-1,-1,-1,-1,-1,-1,-1,
      -1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1
    };

    // cout << "New character: " << hex << (int) ch << " (" << (char) ch << ")" << "\n";
    signed char value = -1;
    if ((unsigned)ch < 128)
      value = lookup_table [(unsigned)ch];
    if (value == -1)
      throw Sync::DigestCalculationError () << errinfo_at_line (__LINE__);
    
    return value;
  }
};

typedef transform_width<transform_iterator<hex_to_4_bit<string::const_iterator::value_type>, string::const_iterator>, 8, 4> string_to_binary;

// #else

// typedef base64_from_binary<transform_width<string::const_iterator, 6, 8> > string_from_binary;
// typedef binary_from_base64<transform_width<string::const_iterator, 8, 6> > string_to_binary;

// #endif

namespace Sync {

Digest::Digest ()
  : m_buffer (0)
  , m_hashLength (0)
{
  m_context = EVP_MD_CTX_create ();

  reset ();
}

Digest::~Digest ()
{
  if (m_buffer != 0)
    delete [] m_buffer;

  EVP_MD_CTX_destroy (m_context);
}

void
Digest::reset ()
{
  if (m_buffer != 0)
    {
      delete [] m_buffer;
      m_buffer = 0;
    }

  int ok = EVP_DigestInit_ex (m_context, HASH_FUNCTION (), 0);
  if (!ok)
    throw DigestCalculationError () << errinfo_at_line (__LINE__);
}


void
Digest::finalize ()
{
  if (m_buffer != 0) return;

  m_buffer = new uint8_t [EVP_MAX_MD_SIZE];

  int ok = EVP_DigestFinal_ex (m_context,
			       m_buffer, &m_hashLength);
  if (!ok)
    throw DigestCalculationError () << errinfo_at_line (__LINE__);
}
  
std::size_t
Digest::getHash ()
{
  if (m_buffer == 0)
    finalize ();

  BOOST_ASSERT (sizeof (std::size_t) <= m_hashLength);
  
  // just getting first sizeof(std::size_t) bytes
  // not ideal, but should work pretty well
  return reinterpret_cast<std::size_t> (m_buffer);
}

bool
Digest::operator == (Digest &digest)
{
  if (m_buffer == 0)
    finalize ();

  if (digest.m_buffer == 0)
    digest.finalize ();
  
  BOOST_ASSERT (m_hashLength == digest.m_hashLength);

  return memcmp (m_buffer, digest.m_buffer, m_hashLength) == 0;
}


void
Digest::update (const uint8_t *buffer, size_t size)
{
  // cout << "Update: " << (void*)buffer << " / size: " << size << "\n";
  
  // cannot update Digest when it has been finalized
  if (m_buffer != 0)
    throw DigestCalculationError () << errinfo_at_line (__LINE__);

  bool ok = EVP_DigestUpdate (m_context, buffer, size);
  if (!ok)
    throw DigestCalculationError () << errinfo_at_line (__LINE__);
}


Digest &
Digest::operator << (const Digest &src)
{
  if (src.m_buffer == 0) 
    throw DigestCalculationError () << errinfo_at_line (__LINE__);

  update (src.m_buffer, src.m_hashLength);

  return *this;
}

std::ostream &
operator << (std::ostream &os, const Digest &digest)
{
  BOOST_ASSERT (digest.m_hashLength != 0);
  
  ostreambuf_iterator<char> out_it (os); // ostream iterator
  // need to encode to base64
  copy (string_from_binary (reinterpret_cast<const char*> (digest.m_buffer)),
        string_from_binary (reinterpret_cast<const char*> (digest.m_buffer+digest.m_hashLength)),
        out_it);

  return os;
}

std::istream &
operator >> (std::istream &is, Digest &digest)
{
  string str;
  is >> str; // read string first
  // uint8_t padding = (3 - str.size () % 3) % 3;
  // for (uint8_t i = 0; i < padding; i++) str.push_back ('=');

  // only empty digest object can be used for reading
  if (digest.m_buffer != 0)
    throw DigestCalculationError () << errinfo_at_line (__LINE__);

  digest.m_buffer = new uint8_t [EVP_MAX_MD_SIZE];
  uint8_t *end = copy (string_to_binary (str.begin ()),
                       string_to_binary (str.end ()),
                       digest.m_buffer);

  digest.m_hashLength = end - digest.m_buffer;

  return is;
}


} // Sync

