/*
 * plugin-rconics-rcon.cpp
 *
 *  Created on: 01 June 2012
 *      Author: oaskivvy@gmail.com
 */

/*-----------------------------------------------------------------.
| Copyright (C) 2012 SooKee oasookee@googlemail.com               |
'------------------------------------------------------------------'

This program is free software; you can redistribute it and/or
modify it under the terms of the GNU General Public License
as published by the Free Software Foundation; either version 2
of the License, or (at your option) any later version.

This program is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU General Public License for more details.

You should have received a copy of the GNU General Public License
along with this program; if not, write to the Free Software
Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA
02110-1301, USA.

http://www.gnu.org/licenses/gpl-2.0.html

'-----------------------------------------------------------------*/

#include <cerrno>
#include <cstring>
#include <sys/socket.h>
#include <unistd.h>
#include <fcntl.h>
#include <arpa/inet.h>
#include <netdb.h>

#include <thread>
#include <chrono>

#include <sstream>

#include <sookee/log.h>
#include <sookee/bug.h>

#include <skivvy/logrep.h>
#include <skivvy/plugin-rconics-rcon.h>
#include <skivvy/types.h>

namespace skivvy { namespace net {

using namespace skivvy;
using namespace skivvy::utils;
using namespace skivvy::types;


#define TIMEOUT 1000

bool aocom(const str& cmd, str_vec& packets, const str& host, int port
	, siz wait = TIMEOUT)
{
	addrinfo hints;
	memset(&hints, 0, sizeof hints);
	hints.ai_family = AF_UNSPEC; // AF_INET or AF_INET6
	hints.ai_socktype = SOCK_DGRAM;

	addrinfo* res;
	if(int status = getaddrinfo(host.c_str(), std::to_string(port).c_str(), &hints, &res) != 0)
	{
		log(gai_strerror(status));
		return false;
	}

	st_time_point timeout = st_clk::now() + std::chrono::milliseconds(wait);

	// try to connect to each
	int cs;
	addrinfo* p;
	for(p = res; p; p = p->ai_next)
	{
		if((cs = socket(p->ai_family, p->ai_socktype, p->ai_protocol)) == -1)
			continue;
		if(!connect(cs, p->ai_addr, p->ai_addrlen))
			break;
		::close(cs);
	}

	freeaddrinfo(res);

	if(!p)
	{
		log("aocom: failed to connect: " << host << ":" << port);
		return false;
	}

	// cs good

	const str msg = "\xFF\xFF\xFF\xFF" + cmd;

	int n = 0;
	if((n = send(cs, msg.c_str(), msg.size(), 0)) < 0 || n < (int)msg.size())
	{
		log("cs send: " << strerror(errno));
		return false;
	}

	packets.clear();

	char buf[2048];

	n = sizeof(buf);
	while(n == sizeof(buf))
	{
		while((n = recv(cs, buf, sizeof(buf), MSG_DONTWAIT)) ==  -1 && (errno == EAGAIN || errno == EWOULDBLOCK || errno == EINTR))
		{
			if(st_clk::now() > timeout)
			{
				log("socket timed out connecting to: " << host << ":" << port);
				return false;
			}
			std::this_thread::yield();
		}
		if(n < 0)
			log("cs recv: " << strerror(errno));
		if(n > 0)
			packets.push_back(str(buf, n));
	}

	close(cs);

	return true;
}

bool rcon(const str& cmd, str& reply, const str& host, int port)
//bool rcon(const str& host, siz port, const str& cmd, str& reply) const
{
	str_vec packets;
	if(!aocom(cmd, packets, host, port, TIMEOUT))
		return false;

	const str header = "\xFF\xFF\xFF\xFFprint\x0A";

	if(packets.empty())
	{
		log("Empty response.");
		return false;
	}

	reply.clear();
	for(const str& packet: packets)
	{
		if(packet.find(header) != 0)
		{
			log("Unrecognised response.");
			return false;
		}

		reply.append(packet.substr(header.size()));
	}

	return true;
}

}} // skivvy::net

