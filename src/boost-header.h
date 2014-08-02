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
 * @author Yingdi Yu <yingdi@cs.ucla.edu>
 */

#ifndef BOOST_HEADER_HPP
#define BOOST_HEADER_HPP

// suppress Boost warnings
#pragma GCC system_header
#pragma clang system_header

#include <boost/random.hpp>

#include <boost/assert.hpp>
#include <boost/throw_exception.hpp>

#include <boost/iterator/transform_iterator.hpp>
#include <boost/archive/iterators/dataflow_exception.hpp>
#include <boost/archive/iterators/transform_width.hpp>

#endif // BOOST_HEADER_HPP
