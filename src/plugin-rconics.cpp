/*
 * ircbot-rconics.cpp
 *
 *  Created on: 04 Jun 2012
 *      Author: oasookee@googlemail.com
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

#include <skivvy/plugin-rconics.h>

#include <iomanip>
#include <array>
#include <cmath>
#include <future>
#include <thread>
#include <fstream>
#include <sstream>
#include <functional>
#include <mutex>

#include <cassert>

#include <fstream>

#include <tr1/regex>

#include <skivvy/ios.h>
#include <skivvy/irc.h>
#include <skivvy/stl.h>
#include <skivvy/str.h>
#include <skivvy/ircbot.h>
#include <skivvy/logrep.h>
#include <skivvy/network.h>
#include <skivvy/rcon.h>

#include <skivvy/socketstream.h>

namespace skivvy { namespace ircbot {

IRC_BOT_PLUGIN(RConicsIrcBotPlugin);
PLUGIN_INFO("OA rcon utils", "0.1");

using namespace skivvy;
using namespace skivvy::irc;
using namespace skivvy::types;
using namespace skivvy::utils;
using namespace skivvy::string;

namespace tr1 = std::tr1;

const str WHOIS_USER = "rconics.whois.user";
const str RCON_USER = "rconics.user";
const str RCON_SERVER = "rconics.server";
const str RCON_STATS_FILE = "rconics.stats_file";
const str RCON_STATS_FILE_DEFAULT = "rconics-stats.txt";
const str RCON_STATS = "rconics.stats";
const str RCON_BOT_NAME = "rconics.bot_name";
const str RCON_BOT_NAME_DEFAULT = "^1S^2ki^3v^5vy";
const str RCON_AUTOMSG_FILE = "rconics.automsg_file";
const str RCON_AUTOMSG_FILE_DEFAULT = "rconics-automsgs.txt";
const str RCON_MANAGED = "rconics.managed";
const str RCON_STATS_INTERVAL = "rconics.stats_interval";
const siz RCON_STATS_INTERVAL_DEFAULT = 5;
const str RCON_ADMINKILL_USERS = "rconics.adminkill.user";
const str RCON_ADMINKILL_PASS = "rconics.adminkill.pass";

const str BAN_BY_GUID = "rconics.autoban.guid";
const str UNBAN_BY_GUID = "rconics.autounban.guid";
const str BAN_BY_IP = "rconics.autoban.ip";
const str UNBAN_BY_IP = "rconics.autounban.ip";
const str BAN_BY_NAME = "rconics.autoban.name";
const str UNBAN_BY_NAME = "rconics.autounban.name";
const str BAN_BY_LOC = "rconics.autoban.loc";
const str UNBAN_BY_LOC = "rconics.autounban.loc";
const str BAN_BY_ISP = "rconics.autoban.isp";
const str UNBAN_BY_ISP = "rconics.autounban.isp";

const str LOCMAP_FILE = "rconics.locmap.file";
const str LOCMAP_FILE_DEFAULT = "rconics-locmap.txt";
const str ISPMAP_FILE = "rconics.ispmap.file";
const str ISPMAP_FILE_DEFAULT = "rconics-ispmap.txt";

const str SEARCH_ENGINE_ISP = "rconics.engine.isp";


// alias: GUID, name
// ip: GUID, IP
// stat: tot_score, tot_ping, tot_samples

struct cmp
{
	bool operator()(const message& m1, const message& m2) const
	{
		return m1.to < m2.to;
	}
};

std::mutex RConicsIrcBotPlugin::db_mtx;

RConicsIrcBotPlugin::RConicsIrcBotPlugin(IrcBot& bot)
: BasicIrcBotPlugin(bot)
, automsg_timer([&](const void*){ regular_poll(); })
{
}

RConicsIrcBotPlugin::~RConicsIrcBotPlugin() {}

RConicsIrcBotPlugin::rcon_server_map& RConicsIrcBotPlugin::get_rcon_server_map()
{
	static rcon_server_map sm;
	static time_t config_load_time = bot.get_config_load_time();
	if(config_load_time < bot.get_config_load_time())
		sm.clear();
	if(sm.empty())
	{
		const str_vec list = bot.get_vec(RCON_SERVER);
		str k, v;
		rcon_server s;
		for(const str& l: list)
		{
			// server host:port pass
			std::istringstream iss(l);
			if(std::getline(iss >> k >> v >> std::ws, s.pass))
			{
				siz pos;
				if((pos = v.find(':')) != str::npos)
				{
					s.host = v.substr(0, pos);
					std::istringstream(v.substr(pos + 1)) >> s.port;
				}
				else
					s.host = v;

				sm[k] = s;
			}
		}
	}
	return sm;
}

RConicsIrcBotPlugin::rcon_user_map& RConicsIrcBotPlugin::get_rcon_user_map()
{
	static rcon_user_map um;
	static time_t config_load_time = bot.get_config_load_time();
	str k, v;
	if(config_load_time < bot.get_config_load_time())
		um.clear();
	if(um.empty())
		for(const str& s: bot.get_vec(RCON_USER))
			if(std::getline(std::istringstream(s) >> k >> std::ws, v))
				um[k].push_back(v);
	return um;
}

bool RConicsIrcBotPlugin::rcon_user_valid(const str& user, const str& server)
{
	if(do_adminkill.count(server))
	{
		for(const str& s: bot.get_vec(RCON_ADMINKILL_USERS))
			if(user.find(s) != str::npos)
				return true;
		return false;
	}

	rcon_user_map& um = get_rcon_user_map();

	rcon_user_map::iterator u;
	if((u = um.find(server)) == um.end())
		return false;

	for(const str& s: u->second)
		if(user.find(s) != str::npos)
			return true;

	return false;
}

//bool RConicsIrcBotPlugin::whois_user_valid(const str& user)
//{
//	for(const str& s: bot.get_vec(WHOIS_USER))
//		if(user.find(s) != str::npos)
//			return true;
//	return false;
//}
str RConicsIrcBotPlugin::rcon(str cmd, const rcon_server& s)
{
	str res;
	std::ostringstream oss;
	oss << "rcon " << s.pass << " " << cmd;
	net::rcon(oss.str(), res, s.host, s.port);
	return res;
}

str RConicsIrcBotPlugin::do_rcon(const message& msg, str cmd, const rcon_server& s)
{
	return do_rcon(msg, cmd, s.host, s.port, s.pass);
}
str RConicsIrcBotPlugin::do_rcon(const message& msg, str cmd, const str& host, siz port, const str& pass)
{
	str res;
	std::ostringstream oss;

	// Drop mega advertising
	str lwr = lowercase(cmd);
	if(lwr.find(" mega") != str::npos
	|| lwr.find("mega ") != str::npos
	|| lwr.find("teammega") != str::npos)
	{
		log("MEGA advert eradicated: " << cmd);
		return "";
	}

	const str bot_name = bot.get(RCON_BOT_NAME, RCON_BOT_NAME_DEFAULT);

	if(!cmd.find("say_team"))
		cmd = "say_team ^7(" + bot_name + "^7) " + cmd.substr(8);
	else if(!cmd.find("say"))
		cmd = "say ^7(" + bot_name + "^7) " + cmd.substr(3);
	else if(!cmd.find("chat"))
		cmd = "chat " + bot_name + "^7: " + cmd.substr(4);
	else if(!cmd.find("cp"))
		cmd +=  " - " + bot_name;
	else if(!cmd.find("!ban") || !cmd.find("!adjust") || !cmd.find("!kick"))
		cmd += " - " + msg.get_sender();

	oss << "rcon " << pass << " " << cmd;
	net::rcon(oss.str(), res, host, port);
	return res;
}

bool RConicsIrcBotPlugin::do_checked_rcon(const message& msg, const str& cmd, str& res)
{
	bug_func();
	str server;
	if(!bot.extract_params(msg, {&server}))
		return false;

	if(!rcon_user_valid(msg.from, server))
	{
		bot.fc_reply(msg, msg.get_sender() + " is not authorised for server " + server + ".");
		return false;
	}

	rcon_server_map& sm = get_rcon_server_map();

	rcon_server_map::iterator s;
	if((s = sm.find(server)) == sm.end())
	{
		bot.fc_reply(msg, "There is no server named " + server);
		return false;
	}

	res = do_rcon(msg, cmd, s->second);

	return true;
}

bool is_ban_duration(const str&)
{
	return true;
}

bool RConicsIrcBotPlugin::showbans(const message& msg)
{
	BUG_COMMAND(msg);
	str res;
	if(!do_checked_rcon(msg, "!showbans", res))
		return false;

//	   1      ROFK!LL 86.73.120.145   05/01/12        console PERMANENT
//	     \__ 1y
//	   2 Eric Batsbac 87.145.135.48   07/04/12 Jiro dreams of 3.3 days
//	     \__ voting off admin twice
//	   3        Meele 189.200.200.65  07/05/12 Jiro dreams of PERMANENT
//	     \__ - A|I|M
//	   4     chinaski 189.41.130.212  07/06/12  *m*^Zimmer106 27.9 days
//	     \__ Game Spoiling - SooKee
//	!showbans: showing bans 1 - 4 of 4 (4 total).

	struct ban
	{
		siz num;
		str name;
		str ip;
		str date;
		str admin;
		str length;
		str reason;
	};

	ban b;
	str line;
	std::istringstream iss(res);
	while(std::getline(iss, line))
	{
		siz ips = 0; // ip start
		str_vec item = split(line);
		for(siz i = 0; i < item.size(); ++i)
		{
			if(trim(item[i]).empty())
				continue;
//			if(is_ip(item[i]))
//				ips = i;
			if(item[i] == "PERMANEMT")
			{
				for(siz n = ips; n < i; ++n)
					b.admin += b.admin.empty() ? item[n] : " " + item[n];
				b.length = item[i];
			}
			if(!item[i].find("day") || !item[i].find("week") || !item[i].find("year"))
			{
				siz n = ips;
				for(; n < (i - 1); ++n)
					b.admin += b.admin.empty() ? item[n] : " " + item[n];
				for(; n <= i; ++n)
					b.length += b.length.empty() ? item[n] : " " + item[n];
			}
		}

		b.ip = item[ips];
		b.date = item[ips + 1];
		std::istringstream iss(line.substr(0, ips));
		if(std::getline(iss >> b.num >> std::ws, b.name))
		{
			trim(b.name);
		}
		else if(b.num)
		{
			// line after info? Reason line?
			siz pos = line.find("\\__");
			if(pos != str::npos && pos + 3 < line.size())
				b.reason = line.substr(pos + 3);

			// Output full item here
			bot.fc_reply(msg, "num   : " + std::to_string(b.num));
			bot.fc_reply(msg, "name  : " + b.name);
			bot.fc_reply(msg, "ip    : " + b.ip);
			bot.fc_reply(msg, "date  : " + b.date);
			bot.fc_reply(msg, "admin : " + b.admin);
			bot.fc_reply(msg, "length: " + b.length);
			bot.fc_reply(msg, "reason: " + b.reason);
		}

		b.num = 0;
	}

	return true;
}

void RConicsIrcBotPlugin::rcon(const message& msg)
{
	BUG_COMMAND(msg);

	str server, cmd;
	std::getline(std::istringstream(msg.get_user_params()) >> server >> std::ws, cmd);

	str res;
	if(!do_checked_rcon(msg, trim(cmd), res))
		return;

	str line;
	std::istringstream iss(trim(res));
	while(std::getline(iss, line))
	{
		bug("line: " << line);
		bot.fc_reply(msg, line);
	}
}

void RConicsIrcBotPlugin::read_automsgs()
{
	automsg amg;
	lock_guard lock(automsgs_mtx);
	std::ifstream ifs(bot.getf(RCON_AUTOMSG_FILE, RCON_AUTOMSG_FILE_DEFAULT));
	automsgs.clear();
	while(ifs >> amg)
		automsgs.push_back(amg);
}

void RConicsIrcBotPlugin::write_automsgs()
{
	lock_guard lock(automsgs_mtx);
	std::ofstream ofs(bot.getf(RCON_AUTOMSG_FILE, RCON_AUTOMSG_FILE_DEFAULT));
	str sep;
	for(const automsg& amsg: automsgs)
		{ ofs << sep << amsg; sep = '\n'; }
}

str::size_type get_last_field(const str& line, str& val, char delim = ' ')
{
	val.clear();
	str::size_type pos = line.size() - 1;
	while(pos != str::npos && line[pos] != delim)
		val.insert(0, 1, line[pos--]);
	return pos;
}

bool is_guid(const str& s, siz min = 8)
{
	assert(min <= 8);
	return s.size() <= 8 && s.size() >= min
//	&& (siz)std::count_if(s.begin(), s.end(), [](char c) { return isxdigit(c); }) == s.size();
	&& stl::count_if(s, std::ptr_fun<int, int>(isxdigit)) == s.size();
}

bool is_ip(const str& s)
{
	siz dot = stl::count(s, '.');
	if(dot > 3)
		return false;

	siz dig = stl::count_if(s, std::ptr_fun<int, int>(isdigit));
	if(dig > dot * 3 + 3)
		return false;

	return s.size() == dot + dig;
}

struct db_rec
{
	str guid;
	siz count;
	str data;

	db_rec(): count(0) {}

	bool operator<(const db_rec& r) const { return guid < r.guid; }

	friend std::ostream& operator<<(std::ostream& os, const db_rec& r)
	{
		return os << r.guid << ' ' << r.count << ' ' << r.data << '\n';
	}
	friend std::istream& operator>>(std::istream& is, db_rec& r)
	{
		return std::getline((is >> r.guid >> r.count).ignore(), r.data);
	}
};

struct ent
{
	siz count;
	str data;
	ent(): count(0) {}
	ent(const ent& e): count(e.count), data(e.data) {}
	ent(siz count, str data): count(count), data(data) {}
	bool operator<(const ent& e) const
	{
		if(count == e.count)
			return data < e.data;
		return count > e.count;
	}
};

typedef std::map<const str, db_rec> str_rec_map;
typedef std::pair<const str, db_rec> str_rec_pair;
typedef std::set<ent> ent_set;
typedef std::map<const str, ent_set> str_ent_set_map;
typedef std::pair<const str, ent_set> str_ent_set_pair;

str adjust(const str& name)
{
	str s = name;
	for(siz i = 1; i < s.size(); ++i)
		if(s[i - 1] == '^' && std::isdigit(s[i]))
			replace(s, str(s.c_str() + i - 1, 2), "");
	return s;
}

bool RConicsIrcBotPlugin::get_loc_map(const str& ip, location_map& m)
{
	bug_func();
	static const str_map itemmap =
	{
		{"code", "<tr><td width=200>My IP country code:</td><td>"}
		, {"country", "<tr><td>My IP address country: </td><td>"}
		, {"state", "<tr><td>My IP address state:</td><td>"}
		, {"city", "<tr><td>My IP address city:</td><td>"}
		, {"zip", "<tr><td>My IP postcode:	</td><td>"}
		, {"lat", "<tr><td>My IP address latitude:	</td><td>"}
		, {"long", "<tr><td>My IP address longitude:</td><td>"}
	};

	typedef std::map<str, location_map> location_cache;
	typedef std::pair<str, location_map> location_pair;
	static location_cache cache;
	static time_t cache_read = 0;

	const time_t now = std::time(0);

	int keep = bot.get("rconics.cache.loc.keep", delay("1w"));
	if(keep < (now - cache_read))
		cache.clear(); // re-read cache every week

	static std::mutex mtx;
	lock_guard lock(mtx);
	if(cache.empty())
	{
		log("initialising locmap:");
		bool modified = false;
		time_t time; // time cached
		str line, key, k, v;
		std::ifstream ifs(bot.getf(LOCMAP_FILE, LOCMAP_FILE_DEFAULT));
		while(std::getline(ifs, line))
		{
			std::istringstream iss(line);
			if(iss >> time && keep < (now - time))
			{
				modified = true;
				continue; // drop from cache after 1 week
			}
			if(std::getline(iss >> key >> std::ws, line))
			{
				std::istringstream iss(line);
				while(ios::getstring(iss >> k >> std::ws, v))
				{
					cache[key][k] = v;
				}
			}
		}
		ifs.close();
		if(modified) // write changes back to disk
		{
			log("writing back changes to locmap:");
			std::ofstream ofs(bot.getf(LOCMAP_FILE, LOCMAP_FILE_DEFAULT));
			for(const location_pair& lp: cache)
			{
				ofs << std::time(0) << ' ' << lp.first;
				for(const str_pair sp: lp.second)
					ofs << ' ' << sp.first << " \"" << sp.second << "\"";
				ofs << '\n';
			}

		}
		cache_read = now;
	}

	if(cache.find(ip) != cache.end())
	{
		m = cache[ip];
		return true;
	}

	net::socketstream ss;
	ss.open("www.my-ip-address-is.com", 80);
	ss << "GET /ip/" << ip << " HTTP/1.1\r\n";
	ss << "Host: www.my-ip-address-is.com" << "\r\n";
	ss << "User-Agent: Skivvy: " << VERSION << "\r\n";
	ss << "Accept: text/html" << "\r\n";
	ss << "\r\n" << std::flush;

	net::header_map headers;
	if(!net::read_http_headers(ss, headers))
	{
		log("ERROR reading headers.");
		return false;
	}

//	for(const net::header_pair& hp: headers)
//		con(hp.first << ": " << hp.second);

	str html;
	if(!net::read_http_response_data(ss, headers, html))
	{
		log("ERROR reading response data.");
		return false;
	}
	ss.close();

	m.clear();
	str line;
	std::istringstream iss(html);
	while(std::getline(iss, line))
	{
		for(const str_pair& item: itemmap)
		{
			siz pos;
			if((pos = line.find(item.second)) != str::npos)
			{
				line = line.substr(pos + item.second.size());
				if((pos = line.find('<')) != str::npos)
				{
					m[item.first] = net::fix_entities(line.substr(0, pos));
				}
			}
		}
	}

	cache[ip] = m;
	std::ofstream ofs(bot.getf(LOCMAP_FILE, LOCMAP_FILE_DEFAULT), std::ios::app);
	ofs << std::time(0) << ' ' << ip;
	for(const str_pair sp: cache[ip])
		ofs << ' ' << sp.first << " \"" << sp.second << "\"";
	ofs << '\n';

	return true;
}

// search engine details
struct eng
{
	str host;
	str path;
	str lhs;
	str rhs;
	siz fail;
	time_t down;
};

str RConicsIrcBotPlugin::get_isp(const str& ip)
{
	static std::mutex mtx;
	static str_map ispmap; // ip -> IAP
	static str_siz_map retries; // ip -> tries

	if(!is_ip(ip))
		return "";

	static time_t cache_read = 0;

	const time_t now = std::time(0);

	int keep = bot.get("rconics.cache.isp.keep", delay("1w"));
	if(keep < (now - cache_read))
		ispmap.clear(); // re-read cache every week

	if(ispmap.empty())
	{
		log("initialising ispmap:");
		bool modified = false;
		str k, v;
		time_t time;
		std::ifstream ifs(bot.getf(ISPMAP_FILE, ISPMAP_FILE_DEFAULT));
		while(std::getline(ifs >> time >> k >> std::ws, v))
		{
			if(keep < (now - time))
			{
				modified = true;
				continue;
			}
			ispmap[k] = v;
		}
		ifs.close();
		if(modified)
		{
			// write changes back to disk
			log("writing back changes to ispmap:");
			std::ofstream ofs(bot.getf(ISPMAP_FILE, ISPMAP_FILE_DEFAULT));
			for(str_pair sp: ispmap)
				ofs << std::time(0) << ' ' << sp.first << ' ' << sp.second << '\n';
		}
		cache_read = now;
	}

	lock_guard lock(mtx);

	if(ispmap.find(ip) != ispmap.cend())
		return ispmap[ip];

	static const std::vector<eng> builtin_engs =
	{
		{"www.ip-adress.com", "/reverse_ip/", "ISP:</h3>", "<", 0, 0}
		, {"whatismyipaddress.com", "/ip/", "ISP:</th><td>", "<", 0, 0}
	};

	static time_t engs_loaded = 0;
	static std::vector<eng> engs;
	if(bot.get_config_load_time() > engs_loaded)
	{
		engs.assign(builtin_engs.cbegin(), builtin_engs.cend());
		str_vec cfengs = bot.get_vec(SEARCH_ENGINE_ISP);
		for(const str& cfeng: cfengs)
		{
			// rconics.engine.isp: www.ip-adress.com /reverse_ip/ "ISP:</h3>" "<"
			eng e;
			std::istringstream iss(cfeng);
			if(ios::getstring(iss, e.host)
			&& ios::getstring(iss, e.path)
			&& ios::getstring(iss, e.lhs)
			&& ios::getstring(iss, e.rhs))
				engs.push_back(e);
			else
				log("Error reading custom ISP engine: " << cfeng);
		}
		engs_loaded = std::time(0);
	}

	static siz idx = 0;

	// http://whatismyipaddress.com/ip/178.239.102.183
	if(engs.empty())
		return "no isp search engines";

	for(eng& e: engs)
		if(e.down && (now - e.down) > int(bot.get("rconics.server.down.retry", delay("1h"))))
			{ e.fail = 0; e.down = 0; }

	++idx;
	if(idx == engs.size())
		idx = 0;

	siz i;
	for(i = idx; i < engs.size(); ++i)
		if(!engs[i].down)
			break;

	if(i == engs.size())
	{
		for(i = 0; i < idx; ++i)
			if(!engs[i].down)
				break;
		if(i == idx)
			return "all isp engines down";
	}

	eng& e = engs[i];

	bug_var(e.host);
	bug_var(e.fail);
	con("GET " << e.path << ip << " HTTP/1.1");

	// http://www.iplocation.net/index.php?query=195.67.217.88
	// http://www.robtex.com/ip/178.239.102.183.html#ip

	net::socketstream ss;
	ss.open(e.host, 80);
	ss << "GET " << e.path << ip << " HTTP/1.1\r\n";
	ss << "Host: " << e.host << "\r\n";
	ss << "User-Agent: Skivvy: " << VERSION << "\r\n";
	ss << "Accept: text/html" << "\r\n";
	ss << "\r\n" << std::flush;

	net::header_map headers;
	if(!net::read_http_headers(ss, headers))
	{
		++e.fail;
		if(e.fail > 3)
			e.down = std::time(0);
		log("ERROR reading headers.");
		return "";
	}

	str html;
	if(!net::read_http_response_data(ss, headers, html))
	{
		++e.fail;
		if(e.fail > 3)
			e.down = std::time(0);
		log("ERROR reading response data.");
		return "";
	}
	ss.close();

	e.fail = 0; // clear failures on success

	// <h3> IP:</h3>83.100.193.172<h3> server location:</h3>Kingston Upon Hull in United Kingdom<h3> ISP:</h3>Kcom<!-- google_ad_section_end -->

	siz pos;
	str line;
	std::istringstream iss(html);
	while(std::getline(iss, line))
	{
		if((pos = line.find(e.lhs)) != str::npos)
		{
			line = line.substr(pos + e.lhs.size());
			if((pos = line.find(e.rhs)) != str::npos)
			{
				std::ofstream ofs(bot.getf(ISPMAP_FILE, ISPMAP_FILE_DEFAULT), std::ios::app);
				line = net::fix_entities(line.substr(0, pos));
				ofs << std::time(0) << ' ' << ip << ' ' << line << '\n';
				return (ispmap[ip] = line);
			}
		}
	}
	if(++retries[ip] > 3)
	{
		retries.erase(ip);
		return (ispmap[ip] = "unknown");
	}
	return "";
}

str RConicsIrcBotPlugin::get_loc(const str& ip, const str& item)
{
	location_map m;
	if(get_loc_map(ip, m))
		return m[item];
	return "";
}

void RConicsIrcBotPlugin::write_to_db(const str& db, const str& guid_in
	, const str& data, DB_SORT sort)
{
	// TODO: use standard variables "data_dir" etc...
	const str db_file = "data/rconics-db-" + db + ".txt";
	const str tmp_file = "data/rconics-db-tmp.txt";

	if(!is_guid(guid_in))
	{
		log("Bad guid: " << guid_in);
		return;
	}

//	str sep;
	str guid, line;
//	siz count;
	str_siz_map items;

	std::ifstream ifs;
	std::ofstream ofs;

	// same mutex because they all use the same temp file
	lock_guard lock(db_mtx);

	ifs.open(db_file);
	ofs.open(tmp_file);

	db_rec r;
	items.clear();
	while(ifs >> r)
	{
		if(r.guid == guid_in)
			items[r.data] = r.count;
		else
			ofs << r;
	}
	ofs.close();
	ifs.close();

	if(sort == DB_SORT::MOST_POPULAR && items[data] < std::numeric_limits<siz>::max())
		++items[data];
	else if(sort == DB_SORT::MOST_RECENT)
		items[data] = std::time(0);

	ofs.open(db_file);
	ifs.open(tmp_file);

	while(ifs >> r)
		ofs << r;
	ifs.close();
	r.guid = guid_in;
	for(const str_siz_pair& s: items)
	{
		r.count = s.second;
		r.data = s.first;
		ofs << r;
	}
	ofs.close();
}

//void write_namelog_to_db(const str& text)
//{
//	// ^2|<^8MAD^1Kitty Too^7: ^2why no? ))
//	// ^30  (*2BC45233)  77.123.107.231^7 '^2BDSM^7'
//	// ^31  (*1DE6454E)  90.192.206.146^7 '^4A^5ngel ^4E^5yes^7'
//	// -  (*4A8B117F)    86.1.110.133^7 'Andrius [LTU]^7'
//	// ^33  (*F1147474)    37.47.104.24^7 'UFK POLAND^7'
//	// ^34  (*ACF58F90)  95.118.224.206^7 '^1Vamp ^3G^1i^3r^1l^7'
//	// ^35  (*EAF1A70C)  88.114.147.124^7 ':D^7'
//	// -  (*E5DAD0FE)   201.37.205.57^7 '^1*^7M^1*^7^^1p^7ev^7'
//	// -  (*B45368DF)    82.50.105.85^7 'Kiloren^7'
//	// ^36  (*5F9DFD1F)      86.2.36.24^7 'SodaMan^7'
//	// -  (*11045255)   79.154.175.14^7 '^3R^^2ocket^7' '^4G^1O^3O^4G^2L^1E^7'
//
//	std::istringstream iss(text);
//	str line, skip, guid, ip, names, name;
//	while(std::getline(iss, line))
//	{
//		bug("line: " << line);
//		std::istringstream iss(line);
//		if(std::getline(iss >> skip >> guid >> ip >> std::ws, names))
//		{
//			if(ip.size() < 7)
//				continue;
//			bug("skip : " << skip);
//			bug("guid : " << guid);
//			bug("ip   : " << ip);
//			bug("names: " << names);
//			if(is_ip(ip) && guid.size() == 11 && guid[0] == '(' && guid [1] == '*')
//			{
//				guid = guid.substr(2, 8);
//				write_to_db("ip", guid, ip, DB_SORT::MOST_RECENT);
//
//				std::istringstream iss(names);
//				while(std::getline(iss, skip, '\'') && std::getline(iss, name, '\''))
//					write_to_db("name", guid, name, DB_SORT::MOST_POPULAR);
//			}
//			bug("");
//		}
//	}
//}

void log_namelog(const str& text)
{
	// ^2|<^8MAD^1Kitty Too^7: ^2why no? ))
	// ^30  (*2BC45233)  77.123.107.231^7 '^2BDSM^7'
	// ^31  (*1DE6454E)  90.192.206.146^7 '^4A^5ngel ^4E^5yes^7'
	// -  (*4A8B117F)    86.1.110.133^7 'Andrius [LTU]^7'
	// ^33  (*F1147474)    37.47.104.24^7 'UFK POLAND^7'
	// ^34  (*ACF58F90)  95.118.224.206^7 '^1Vamp ^3G^1i^3r^1l^7'
	// ^35  (*EAF1A70C)  88.114.147.124^7 ':D^7'
	// -  (*E5DAD0FE)   201.37.205.57^7 '^1*^7M^1*^7^^1p^7ev^7'
	// -  (*B45368DF)    82.50.105.85^7 'Kiloren^7'
	// ^36  (*5F9DFD1F)      86.2.36.24^7 'SodaMan^7'
	// -  (*11045255)   79.154.175.14^7 '^3R^^2ocket^7' '^4G^1O^3O^4G^2L^1E^7'

	static std::mutex mtx;
	static str_deq lines;

	std::istringstream iss(text);
	str line, skip, num, guid, ip, names, name;
	while(std::getline(iss, line))
	{
//		bug(line);

		std::istringstream iss(line);
		if(!std::getline(iss >> num >> guid >> ip >> std::ws, names) || num == "!namelog:")
			continue;

		if(guid.size() != 11 || guid[0] != '(' || guid [1] != '*' || !is_ip(ip))
			continue;

		guid = guid.substr(2, 8);

//		bug("num  : " << num);
//		bug("guid : " << guid);
//		bug("ip   : " << ip);
//		bug("names: " << names);

		// Don't log identical lines from the previous 100 unique entries
		{
			lock_guard lock(mtx);
			if(stl::find(lines, line) != lines.end())
				continue;
			lines.push_back(line);
			while(lines.size() > 100) // keep max 100 entries
				lines.pop_front();
		}

		iss.clear();
		iss.str(names);
		while(std::getline(iss, skip, '\'') && std::getline(iss, name, '\''))
			log("NAMELOG    : " << num << ' ' << guid << ' ' << ip << ' ' << name);
	}
}

str RConicsIrcBotPlugin::var_sub(const str& s, const str& server)
{
	// "${guid:1DE6454E} ^3is ADMIN. If you kick, you will be punished..."

	const str VAR_GUID = "guid:"; // Player name from GUID database
	const str VAR_PLAYER = "player:"; // current player GUID

	str ret = s;
	siz pos, end;
//	bool subst = true;
	while(true)
	{
		if((pos = ret.find("${")) == str::npos)
			break;
		if((end = ret.find("}", pos)) == str::npos)
			break;
		if(end < pos)
			break;
		if(ret.find(VAR_PLAYER) == pos + 2)
		{
			if(end != pos + 2 + VAR_PLAYER.size() + 8)
			{
				log("Bad var format: " << s);
				break;
			}
			str guid = ret.substr(pos + 2 + VAR_PLAYER.size(), 8);
			if(is_guid(guid))
			{
				lock_guard lock(curr_mtx);
				player_set_citer p = stl::find_if(curr[server],[guid](const player& p)
				{
					return p.guid == guid;
				});

				if(p != curr[server].end())
					ret.replace(pos, end - pos + 1, p->name);
				else
					ret = ""; // name not found, message is irrelevant
			}
		}
		else if(ret.find(VAR_GUID) == pos + 2)
		{
			if(end != pos + 2 + VAR_GUID.size() + 8)
			{
				log("Bad var format: " << s);
				break;
			}
			str guid = ret.substr(pos + 2 + VAR_GUID.size(), 8);
			if(is_guid(guid))
			{
				db_rec r;
				ent_set names;

				{
					lock_guard lock(db_mtx);
					std::ifstream ifs("data/rconics-db-name.txt");
					while(ifs >> r)
						if(lowercase(r.guid) == lowercase(guid))
							names.insert(ent(r.count, r.data));
					ifs.close();
				}

				if(!names.empty())
					ret.replace(pos, end - pos + 1, names.begin()->data);
			}
		}
		else
			ret.replace(pos, end - pos + 1, "");
	}
	return ret;
}

//bool RConicsIrcBotPlugin::autoban_check(const str& server, const str& line, const str& data, str& test)
//{
//	typedef std::map<str_pair, bool> data_cache;
//	typedef std::pair<const str_pair, bool> data_cache_pair;
//	typedef data_cache::iterator data_cache_itr;
//	typedef data_cache::const_iterator data_cache_citr;
//
//	typedef std::pair<str, str> time_pair;
//	typedef std::map<str, time_pair> time_cache;
//	typedef time_cache::iterator time_cache_itr;
//	typedef time_cache::const_iterator time_cache_citr;
//
//	static time_cache tc; // line -> {begin, end} time of rule
//	static data_cache dc; // (line, data} -> result
//	static time_t cache_cleared = 0;
//
//	str srv;
//	std::istringstream iss(line);
//	iss >> srv;
//	if(srv != server)
//		return false;
//
//	if(cache_cleared < bot.get_config_load_time())
//	{
//		dc.clear();
//		cache_cleared = std::time(0);
//	}
//
//	time_cache_itr tci = time_cache.find(line);
//	if(tci == time_cache.end())
//	{
//		// need to cache line in time_cache
//		time_pair tp;
//		std::getline(iss, skip, '{');
//		std::getline(iss, tp.first, ',');
//		std::getline(iss, tp.second, '}');
//
//		if(!iss)
//			return false;
//
//		trim(tp.first);
//		trim(tp.second);
//		tci = time_cache.insert(time_cache.begin(), std::make_pair(line, tp));
//	}
//
//	time_t t = std::time(0);
//	str now = std::ctime(&t); // now = "Www Mmm dd hh:mm:ss yyyy"
//	if(now.size() < 17)
//		return false;
//	now = now.substr(11, 5);
//
//	if(now < tci->second.first || now > tci->second.second)
//		return false;
//
//	// rule still in force
//	str_pair dp = std::make_pair(line, data);
//	data_cache_itr dci = dc.find(dp);
//	if(dci != sc.end())
//		return dci->second; // cached result
//
//	// result needs calculating/caching
//	dc[dp] = autoban_check()
//	return true;
//}

bool autoban_check(const str& server, const str& line, str& test)
{
	// goo {04:00,10:00} "ban text"
	str srv, stime, etime, skip;
	std::istringstream iss(line);
	iss >> srv;
	if(srv != server)
		return false;

	std::getline(iss, skip, '{');
	std::getline(iss, stime, ',');
	std::getline(iss, etime, '}');

	if(!iss)
		return false;

	trim(stime);
	trim(etime);

	time_t t = std::time(0);
	str now = std::ctime(&t); // now = "Www Mmm dd hh:mm:ss yyyy"

	if(now.size() < 17)
		return false;

	now = now.substr(11, 5);

	if(now < stime || now > etime)
		return false;

	return ios::getstring(iss, test);
}

bool autounban_check(const str& server, const str& line, str& ban)
{
	// goo "ban text"
	str srv, skip;
	std::istringstream iss(line);
	if(!(iss >> srv) || srv != server)
		return false;

	return ios::getstring(iss, ban);
}

void RConicsIrcBotPlugin::regular_poll()
{
	bug_func();

	std::ostringstream oss;
	const rcon_server_map& sm = get_rcon_server_map();

	if(do_automsg && polltime(poll::RCONMSG, 60))
	{
		bug_var(do_automsg);
		lock_guard lock(automsgs_mtx);
		bug_var(automsgs.size());
		for(automsg& amsg: automsgs)
		{
			if(!amsg.active)
				continue;
			if(!sm.count(amsg.server))
			{
				log("Server info missing for: " + amsg.server + ".");
				continue;
			}

			if(!amsg.when)
				amsg.when = std::time(0) - rand_int(0, amsg.repeat);

			bug_var(amsg.when);
			bug_var(amsg.repeat);
			bug_var(delay(std::time(0) - amsg.when));
			if(amsg.repeat < delay(std::time(0) - amsg.when))
			{
				oss.str("");
				oss << amsg.method << ' ' << amsg.text;
				str text = var_sub(oss.str(), amsg.server);

				str ret;
				if(!text.empty())
					ret = rcon(text, sm.at(amsg.server));
				bug_var(ret);
				amsg.when = std::time(0);

				// Echo to all subscribing channels
				lock_guard lock(automsg_subs_mtx);
				for(const message& msg: automsg_subs[amsg.server])
					bot.fc_reply(msg, "{" + amsg.server + "} " + oa_to_IRC(trim(ret).c_str()));
			}
		}
	}

	siz ival = bot.get(RCON_STATS_INTERVAL, RCON_STATS_INTERVAL_DEFAULT);
	//bug_var(do_stats.count(s.first));
	// every ival minutes
	if(!do_stats.empty() && polltime(poll::STATS, ival * 60) && bot.has_plugin("OA Stats Reporter"))
	{
		bug("Have OA Stats Reporter");
		for(const str& server: do_stats)
		{
			log("\tserver: " << server);
			if(!sm.count(server))
			{
				log("Server info missing for stats: " + server + ".");
				continue;
			}
			static std::mutex mtx;
			static stats_vector v;

			if(v.empty())
			{
				lock_guard lock(mtx);
				if(v.empty())
					if(!rpc_get_oatop("", v))
						log("rpc_get_oatop() error");

				std::sort(v.begin(), v.end(), [&](const keystats& ks1, const keystats& ks2)
				{
					return ks1.rank < ks2.rank;
				});

				if(v.size() > 20)
					v.erase(v.begin() + 20, v.end());
			}

			siz max = v.size() > 20 ? 20 : v.size();

			if(!v.empty())
			{
				siz i = rand_int(0, max - 1);

				oss.str("");
				oss.precision(1);
				oss << std::fixed;
				oss << "chat ^7#" << v[i].rank << (v[i].rank < 10 ? " " : "");
				oss << " ^2Kil ^7" << v[i].kd;
				oss << " ^5Cap ^7" << v[i].cd;
				oss << " ^61v1 ^7" << int(v[i].pw + 0.5);
				oss << " ^3All ^7" << v[i].overall;
				oss << " " << v[i].name;
				str ret = rcon(oss.str(), sm.at(server));

				for(const message& msg: stats_subs)
					bot.fc_reply(msg, "{" + server + "} " + oa_to_IRC(trim(ret).c_str()));

				bug("STATS ANNOUNCE: " << oss.str());
				v.erase(v.begin() + i);
			}
		}
	}

	//return;

	bug("== GET INTEL ==");

	struct dbent
	{
		str guid, ip, name;
		dbent(const str& guid, const str& ip, const str& name): guid(guid), ip(ip), name(name) {}
		dbent(const dbent& e): guid(e.guid), ip(e.ip), name(e.name) {}
		bool operator<(const dbent& e) const
		{
			if(guid != e.guid)
				return guid < e.guid;
			if(ip != e.ip)
				return ip < e.ip;
			return name < e.name;
		}
	};

	static std::set<dbent> db_cache;
	static std::set<dbent> db_record;

	// Log intel to trap hacker
	// Get intel
//	rcon_server_map::const_iterator s;
	player p;
	std::istringstream iss;
	str_vec managed = bot.get_vec(RCON_MANAGED);
	for(const str& server: managed)
	{
		log("server: " << server);

//		if((s = sm.find(server)) == sm.cend())
		if(!sm.count(server))
		{
			log("Managed server " << server << " has no details.");
			continue;
		}

		{
			prev[server] = curr[server];
			curr[server].clear();
		}

		str res = rcon("!namelog", sm.at(server));

		if(trim(res).empty())
			log("No response from rcon !namelog.");
		else
			log_namelog(res);

		// We have two data streams to parse in order to get one whole data item
		// for each player. So we need to record if the first parsing succeeded
		// before attempting the second.
		bool parsed = false;

		res = rcon("!listplayers", sm.at(server));

		if(trim(res).empty())
		{
			log("No response from rcon !listplayers.");
			continue;
		}

		// !listplayers: 4 players connected:
		//  0 R 0   Unknown Player (*01505619)   Excaliber
		//  1 S 5  Server Operator (*1DE6454E)   *m*^Zimmer106
		//  4 B 0   Unknown Player (*3840871C)   z
		//  8 S 0   Unknown Player (*0AC40FCD)   Bacon Strips

		iss.clear();
		iss.str(res);
		str line, skip;

		while(std::getline(iss, line) && !trim(line).empty())
		{
			if(line[0] == '!')
				continue;

			std::istringstream iss(line);
			if(!std::getline(std::getline(std::getline(iss >> p.num >> p.team, skip, '*'), p.guid, ')') >> std::ws, p.name))
				continue;

			parsed = true;
			log("LISTPLAYERS: " << p.num << ' ' << p.guid << ' ' << p.name);
			if(trim(p.guid).empty())
				continue;

			curr[server].insert(p);

			for(const str& line: bot.get_vec(BAN_BY_GUID))
			{
				str srv, guid;
				if(!(std::istringstream(line) >> srv >> guid))
					continue;
				if(srv != server || guid != p.guid)
					continue;

				log("AUTO-BAN BY GUID: " << p.guid);
				res = rcon("!ban " + std::to_string(p.num) + " AUTOBAN", sm.at(server));
				log("RESULT: " << res);
				if(trim(res).empty())
					log("No response from rcon status.");
			}
		}

		if(!parsed)
		{
			log("Error parsing rcon !listplayers.");
			log(res);
			continue;
		}

		res = rcon("status", sm.at(server));
		if(trim(res).empty())
		{
			log("No response from rcon status.");
			continue;
		}

		// map: mlctf1beta
		// num score ping name            lastmsg address               qport rate
		// --- ----- ---- --------------- ------- --------------------- ----- -----
		//   0     0   48 ^1S^2oo^3K^5ee^7       0 81.109.248.108        15232 25000
		//   1     0    0 Kyonshi^7            50 bot                   64050 16384
		iss.clear();
		iss.str(res);

		while(std::getline(iss, line) && !trim(line).empty() && line[0] != '-')
			if(!line.find("map:") && line.size() > 5)
				mapname = line.substr(5);

		str prev_line[2]; // TODO: DEBUG LINE
		while(std::getline(iss, line) && !trim(line).empty())
		{
			player p;
			str skip, ip;

			siz pos = get_last_field(line, skip);
			while(pos != str::npos && line[pos] == ' ') --pos;
			if(pos != str::npos)
				pos = get_last_field(line.substr(0, pos + 1), skip);
			while(pos != str::npos && line[pos] == ' ') --pos;
			if(pos != str::npos)
				pos = get_last_field(line.substr(0, pos + 1), ip);
			while(pos != str::npos && line[pos] == ' ') --pos;
			if(pos != str::npos)
				pos = get_last_field(line.substr(0, pos + 1), skip);
			while(pos != str::npos && line[pos] == ' ') --pos;
			std::istringstream iss(line.substr(0, pos + 1));

			if(!(iss >> p.num >> p.score >> p.ping).ignore())
				continue;
//			iss.ignore(1);

			if(ip != "bot" && !is_ip(ip))
			{
				log("IP PARSE ERROR: " << prev_line[0]);
				log("IP PARSE ERROR: " << prev_line[1]);
				log("IP PARSE ERROR: " << line);
				bug("==================================================");
				bug(res);
				bug("==================================================");
				continue;
			}

			prev_line[0] = prev_line[1];
			prev_line[1] = line;

			str name; // can be empty, if so keep name from !listplayers
			std::getline(iss, name);
			log("STATUS     : " << p.num << ' ' << p.ping << ' ' << ip << ' '<< name);
			if(!name.empty() && name != "^7")
				p.name = name;

			// AUTOBAN
			str_vec reasons, unreasons;
			str srv, test;//, unban;
			str loc, isp;

			// Unban specific GUIDs
			for(const str& line: bot.get_vec(UNBAN_BY_GUID))
				if(autounban_check(server, line, test) && p.guid == test)
					unreasons.push_back("AUTO-BAN PROTECTION BY GUID: " + p.guid);

			// rconics.autoban.ip: goo 188.162.80.53
			// rconics.autoban.name: goo {04:00,10:00} "^0UnnamedPlayer^7"
			// rconics.autoban.loc: goo {04:00,10:00} "Kingston upon Hull"
			// rconics.autoban.isp: goo {04:00,10:00} "Virgin Media"

//			static str_map ban_cache;
//			static str_map unban_cache;
//			static time_t bans_loaded = 0;
//
//			if(bans_loaded < bot.get_config_load_time())
//			{
//				ban_cache.clear();
//				unban_cache.clear();
//				bans_loaded = std::time(0);
//			}
			// AUTOBAN BY TIME AND IP

			for(const str& line: bot.get_vec(BAN_BY_IP))
				if(autoban_check(server, line, test) && !ip.find(test))
					reasons.push_back("AUTO-BAN BY IP: " + ip);
			for(const str& line: bot.get_vec(UNBAN_BY_IP))
				if(autounban_check(server, line, test) && !ip.find(test))
					unreasons.push_back("AUTO-BAN PROTECTION BY IP: " + ip);

			// AUTOBAN BY TIME AND NAME

			for(const str& line: bot.get_vec(BAN_BY_NAME))
				if(autoban_check(server, line, test) && p.name == test)
					reasons.push_back("AUTO-BAN BY NAME: " + p.name);
			for(const str& line: bot.get_vec(UNBAN_BY_NAME))
				if(autounban_check(server, line, test)  && p.name == test)
					unreasons.push_back("AUTO-BAN PROTECTION BY NAME: " + p.name);

			for(const str& reason: reasons)
				log(reason);

			for(const str& unreason: unreasons)
				log(unreason);

			if(unreasons.empty() && !reasons.empty())
			{
				// str cmd = "!ban " + std::to_string(p.num)	+ " AUTOBAN";

				// 2012-07-18 03:30:50: STATUS     : 1 103 90.192.206.157 ^3*^7m^3*^^1Z^6immer^4106^7
				// 2012-07-18 03:30:50: STATUS     : 10 999 181.95.101.149 ^0UnnamedPlayer^7
				// 2012-07-18 03:30:50: AUTO-BAN BY NAME: ^0UnnamedPlayer^7

				// Correctly !ban client #10 in admin.log
				// 19:15: -1: XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX: console: : ban: "10 AUTOBAN"

				// Incorrectly kicked client #1 according to rcon return info (and reality)
				// 2012-07-18 03:30:52: !ban  RESULT: !ban: WARNING bot or without GUID or IP cannot write to ban file
				// broadcast: print "^3*^7m^3*^^1Z^6immer^4106^7 has been banned by console^7, duration: PERMANENT, reason: AUTOBAN\n"
				// Kill: 1022 1 20: <world> killed ^3*^7m^3*^^1Z^6immer^4106 by MOD_SUICIDE
				// PlayerScore: 1 51: ^3*^7m^3*^^1Z^6immer^4106 now has 51 points
				// Playerstore: Stored player with guid: 2A5E71DF80B9A6BA7796CB3F1DE6454E in 0
				// ClientDisconnect: 1

				// Incorrectly kicked client #1 according to server.log
				// (note client #10 leaves before kick is issued)
				// 19:10 ClientUserinfoChanged: 10 n\UnnamedPlayer\t\3\model\beret/red\hmodel\beret/red\g_redteam\\g_blueteam\\c1\\c2\\hc\100\w\0\l\0\tt\0\tl\0\id\74587B3A2D1BE4AD3D87887957D295B6
				// 19:10 ClientConnect: 10
				// 19:12 Kill: 8 3 10: ^1*M^5*^1^^5L^1E^5G^1E^5N^1D killed Pixelized by MOD_RAILGUN
				// 19:12 PlayerScore: 8 83: ^1*M^5*^1^^5L^1E^5G^1E^5N^1D now has 83 points
				// 19:12 Challenge: 8 215 1: Client 8 got award 215
				// 19:12 Challenge: 8 1 1: Client 8 got award 1
				// 19:12 Challenge: 3 2 1: Client 3 got award 2
				// 19:12 Award: 8 1: ^1*M^5*^1^^5L^1E^5G^1E^5N^1D gained the EXCELLENT award!
				// 19:12 Challenge: 8 302 1: Client 8 got award 302
				// 19:12 Award: 8 2: ^1*M^5*^1^^5L^1E^5G^1E^5N^1D gained the IMPRESSIVE award!
				// 19:12 Challenge: 8 301 1: Client 8 got award 301
				// 19:12 Kill: 5 8 10: ^1D^2i^3n^4g^5L^6e^7s killed ^1*M^5*^1^^5L^1E^5G^1E^5N^1D by MOD_RAILGUN
				// 19:12 PlayerScore: 5 28: ^1D^2i^3n^4g^5L^6e^7s now has 28 points
				// 19:12 Challenge: 5 215 1: Client 5 got award 215
				// 19:12 Challenge: 5 1 1: Client 5 got award 1
				// 19:12 Challenge: 8 2 1: Client 8 got award 2
				// 19:13 ClientDisconnect: 10
				// 19:13 Item: 6 team_CTF_blueflag
				// 19:13 PlayerScore: 6 78: portuano now has 78 points
				// 19:13 CTF: 6 2 2: portuano returned the BLUE flag!
				// 19:15 Kill: 1022 1 20: <world> killed ^3*^7m^3*^^1Z^6immer^4106 by MOD_SUICIDE
				// 19:15 PlayerScore: 1 51: ^3*^7m^3*^^1Z^6immer^4106 now has 51 points
				// 19:15 Playerstore: Stored player with guid: 2A5E71DF80B9A6BA7796CB3F1DE6454E in 0
				// 19:15 ClientDisconnect: 1

				str cmd = "!ban " + ip	+ " AUTOBAN"; // use ip because #num is buggy
				log("cmd: " << cmd);
				res = rcon(cmd, sm.at(server));
				log("!ban  RESULT: " << res);
				res = rcon("addip " + ip, sm.at(server));
				log("addip RESULT: " << res);
			}
			else if(unreasons.empty()) // Do other (slower) checks
			{
				// AUTOBAN BY TIME AND LOCATION

				for(const str& line: bot.get_vec(BAN_BY_LOC))
					if(autoban_check(server, line, test))
						if(lowercase((loc = get_loc(ip, "city"))).find(lowercase(test)) != str::npos)
							reasons.push_back("AUTO-BAN BY LOC: " + loc);
				for(const str& line: bot.get_vec(UNBAN_BY_LOC))
					if(autounban_check(server, line, test))
						if(lowercase((loc = get_loc(ip, "city"))).find(lowercase(test)) != str::npos)
							unreasons.push_back("AUTO-BAN PROTECTION BY LOC: " + loc);

				// AUTOBAN BY TIME AND ISP

				for(const str& line: bot.get_vec(BAN_BY_ISP))
					if(autoban_check(server, line, test))
						if(lowercase((isp = get_isp(ip))).find(lowercase(test)) != str::npos)
							reasons.push_back("AUTO-BAN BY ISP: " + isp);
				for(const str& line: bot.get_vec(UNBAN_BY_ISP))
					if(autounban_check(server, line, test))
						if(lowercase((isp = get_isp(ip))).find(lowercase(test)) != str::npos)
							unreasons.push_back("AUTO-BAN PROTECTION BY ISP: " + isp);

				for(const str& reason: reasons)
					log(reason);

				for(const str& unreason: unreasons)
					log(unreason);

				if(unreasons.empty() && !reasons.empty())
				{
					res = rcon("!ban " + std::to_string(p.num)	+ " AUTOBAN", sm.at(server));
					log("!ban  RESULT: " << res);
					res = rcon("addip " + ip, sm.at(server));
					log("addip RESULT: " << res);
				}
			}

			player_set_iter psi = curr[server].find(p);

			if(psi == curr[server].end())
				continue;

			if(ip == "bot")
			{
				curr[server].erase(psi);

				// Renaming of bots

				if(!polltime(poll::RENAMES, 60) || renames[server].empty())
					continue;
				if(renames[server].find(p.name) == renames[server].end())
					continue;
				oss.str("");
				oss << "!rename " << p.num << ' ' << renames[server][p.name];
				str ret = rcon(oss.str(), sm.at(server));
				bug_var(ret);
				for(const message& msg: renames_subs[server])
				{
					std::istringstream iss(trim(ret));
					for(str line; std::getline(iss, line);)
						bot.fc_reply(msg, "{" + server + "} " + oa_to_IRC(line.c_str()));
				}
				continue;
			}

			p.guid = psi->guid;
			p.team = psi->team;
			curr[server].erase(psi);
			curr[server].insert(p);

			// reteam: Force player to a given team
			str_reteam_map_itr srmi = reteams[server].find(p.guid);
			if(srmi != reteams[server].end())
			{
				if(!srmi->second.mapname.empty()
				&& srmi->second.mapname != mapname)
				{
					reteams[server].erase(srmi);
				}
				else if(std::time(0) - srmi->second.when > int(srmi->second.secs))
				{
					reteams[server].erase(srmi);
				}
				else if(p.team != 'S' && p.team != srmi->second.team)
				{
					oss.str("");
					oss << "!putteam " << p.num << ' ' << srmi->second.team;
					str ret = rcon(oss.str(), sm.at(server));
					for(const message& msg: reteams_subs[server])
					{
						std::istringstream iss(trim(ret));
						for(str line; getline(iss, line);)
							if(line.find("!putteam") != str::npos)
								bot.fc_reply(msg, "{" + server + "} " + oa_to_IRC(line.c_str()));
					}
				}
			}

			// Add to DataBase

			const dbent e(p.guid, ip, p.name);
			if(!db_record.count(e))
			{
				bug("DB_CACHE: inserting: " << e.guid << ", " << e.ip << ", " << e.name);
				db_cache.insert(e);
				db_record.insert(e);
			}
		}

		bug_var(write_db);
		if(write_db && polltime(poll::DB_WRITE, 5 * 60) && !db_cache.empty())
		{
			for(const dbent& e: db_cache)
			{
				bug("ADD TO DB: " << e.guid);
				write_to_db("ip", e.guid, e.ip, DB_SORT::MOST_RECENT);
				write_to_db("name", e.guid, e.name, DB_SORT::MOST_POPULAR);
			}
			db_cache.clear();
			bug_var(db_record.size());
		}
	}
}

bool RConicsIrcBotPlugin::rpc_get_oatop(const str& params, stats_vector& v)
{
	bug_func();

	IrcBotPluginPtr ptr = bot.get_plugin("OA Stats Reporter");
	OAStatsIrcBotPlugin* plugin = dynamic_cast<OAStatsIrcBotPlugin*>(ptr.get());
//	std::shared_ptr<OAStatsIrcBotPlugin> plugin = bot.get_typed_plugin<OAStatsIrcBotPlugin>("OA Stats Reporter");
	if(!plugin)
	{
		log("OA Stats Reporter not found.");
		return false;
	}

//	IrcBotPluginHandle<OAStatsIrcBotPlugin> ph
//		= bot.get_plugin_handle<OAStatsIrcBotPlugin>("OA Stats Reporter");
	bot.get_plugin_handle<OAStatsIrcBotPlugin>("OA Stats Reporter");

	return plugin->get_oatop(params, v);

//	return false;

//	IrcBotRPCService* s = bot.get_rpc_service("OA Stats Reporter");
//	if(!s)
//	{
//		log("IrcBotRPCService not present.");
//		return false;
//	}
//	bool ret = false;
//	IrcBotRPCService::call_ptr c = s->create_call();
//	//local_call* cp = dynamic_cast<local_call*>(&(*c));
//	c->set_func("get_oatop");
//	c->add_param(params);
//	c->add_param(v);
//	s->rpc(*c);
//	ret = c->get_return_value<bool>();
//	v.clear();
//	c->get_return_param(v);
//	return ret;
}

bool RConicsIrcBotPlugin::whois(const message& msg)
{
	BUG_COMMAND(msg);

	static const str prompt = IRC_BOLD + IRC_COLOR + IRC_Purple + "whois"
		+ IRC_COLOR + IRC_Black + ": " + IRC_NORMAL;

	if(!is_user_valid(msg, WHOIS_USER))
		return bot.cmd_error(msg, msg.get_sender() + " is not authorised to use whois database.");

	bool exact = false;
	bool add_loc = false;
	bool add_ip = false;
	bool add_isp = false;
	str add_loc_type = "code";

	siz chunk = 1;
	std::istringstream iss(msg.get_user_params());

	str query;
	ios::getstring(iss, query);

	str param;
	while(iss >> param)
	{
		if(param == "+x")
			exact = true;
		else if(param == "+ip")
			add_ip = true;
		else if(param == "+isp")
			add_isp = true;
		else if(!param.find("+loc"))
		{
			str skip;
			std::istringstream iss(param);
			std::getline(iss, skip, '=') >> add_loc_type;
			add_loc = true;
		}
		else if(!param.empty() && param[0] == '#')
			std::istringstream(param.substr(1)) >> chunk;
		else if(!param.empty())
			return bot.fc_reply_help(msg, help(msg.get_user_cmd())
				, "04" + msg.get_user_cmd() + ": 01");
	}

	if(!chunk)
		return bot.fc_reply_help(msg, prompt + "Bad batch number (at least #1)");

	std::ifstream ifs;
	str_ent_set_map names;
	str_ent_set_map ips;

	db_rec r;

	query = lowercase(query);

	if(is_guid(query, 2))
	{
		lock_guard lock(db_mtx);
		ifs.open("data/rconics-db-name.txt");
		while(ifs >> r)
			if(exact && lowercase(r.guid) == query)
				names[r.guid].insert(ent(r.count, r.data));
			else if(!exact && lowercase(r.guid).find(query) != str::npos)
				names[r.guid].insert(ent(r.count, r.data));
		ifs.close();
		ifs.open("data/rconics-db-ip.txt");
		while(ifs >> r)
			if(exact && lowercase(r.guid) == query)
				ips[r.guid].insert(ent(r.count, r.data));
			else if(!exact && lowercase(r.guid).find(query) != str::npos)
				ips[r.guid].insert(ent(r.count, r.data));
		ifs.close();
	}

	if(is_ip(query))
	{
		//bug("IP Query: " << query);
		lock_guard lock(db_mtx);
		ifs.open("data/rconics-db-ip.txt");
		while(ifs >> r)
			if(exact && r.data == query)
				ips[r.guid].insert(ent(r.count, r.data));
			else if(!exact && !r.data.find(query)) // starts with
				ips[r.guid].insert(ent(r.count, r.data));
		ifs.close();
		ifs.open("data/rconics-db-name.txt");
		while(ifs >> r)
			if(ips.find(r.guid) != ips.end())
				names[r.guid].insert(ent(r.count, r.data));
		ifs.close();
		add_ip = true;
	}

	{
		lock_guard lock(db_mtx);
		ifs.open("data/rconics-db-name.txt");
		siz count = 0;
		while(ifs >> r)
		{
			++count;
			str data = lowercase(adjust(r.data));
			if(exact && data == query)
			{
				//bug("found: " << data << " at " << count);
				names[r.guid].insert(ent(r.count, r.data));
			}
			else if(!exact && data.find(query) != str::npos)
			{
				//bug("found: " << data << " at " << count);
				names[r.guid].insert(ent(r.count, r.data));
			}
		}
		ifs.close();
		ifs.open("data/rconics-db-ip.txt");
		while(ifs >> r)
			if(names.find(r.guid) != names.end())
				ips[r.guid].insert(ent(r.count, r.data));
		ifs.close();
	}

	siz size = 0;
	for(const str_ent_set_pair&p : names)
		size += p.second.size();

	std::ostringstream oss;

	const siz start = (chunk - 1) * 10;
	const siz end = (start + 10) > size ? size : (start + 10);

	if(((chunk - 1) * 10) > size)
		return bot.cmd_error(msg, "Batch number too high.");

	bot.fc_reply(msg, prompt + "Listing #" + std::to_string(chunk)
		+ " of " + std::to_string((size + 9)/10)
		+ " (from " + std::to_string(start + 1) + " to "
		+ std::to_string(end) + " of " + std::to_string(size) + ") " + (exact?"<exact>":"<sub>") + ".");

	siz count = 0;
	for(const str_ent_set_pair&p : names)
	{
		if(count >= start && count >= end)
			break;
		for(const ent& e: p.second)
		{
			if(count >= start && count >= end)
				break;
			if(count >= start)
			{
				oss.str("");
				oss << prompt << " " << (count + 1) << ".";
				oss << " (" << p.first << ") ";
				oss << IRC_BOLD << oa_to_IRC(e.data.c_str());

				if(add_ip)
				{
					oss << " [";
					ent_set::iterator ent = ips[p.first].begin();
					str sep;
					for(siz i = 0; i < 3 && ent != ips[p.first].end(); ++i, ++ent)
					{
						oss << sep << ent->data;
						if(add_loc)
						{
							oss << " {loc: " << get_loc(ent->data, add_loc_type) << "}";
						}
						if(add_isp)
						{
							oss << " {isp: " << get_isp(ent->data) << "}";
						}
						sep = " ";
					}
					oss << "]";
				}
				else if(add_loc)
				{
					oss << " [";
					ent_set::iterator ent = ips[p.first].begin();
					str sep;
					for(siz i = 0; i < 3 && ent != ips[p.first].end(); ++i, ++ent)
					{
						oss << sep << get_loc(ent->data, add_loc_type);
						if(add_isp)
						{
							oss << " {isp: " << get_isp(ent->data) << "}";
						}
						sep = " ";
					}
					oss << "]";
				}
				else if(add_isp)
				{
					oss << " [";
					ent_set::iterator ent = ips[p.first].begin();
					str sep;
					for(siz i = 0; i < 3 && ent != ips[p.first].end(); ++i, ++ent)
					{
						oss << sep << get_isp(ent->data);
						if(add_loc)
						{
							oss << " {loc: " << get_loc(ent->data, add_loc_type) << "}";
						}
						sep = " ";
					}
					oss << "]";
				}

				bot.fc_reply(msg, oss.str());
			}
			++count;
		}
	}

	bot.fc_reply(msg, prompt + "End of listing.");

	return true;
}

bool RConicsIrcBotPlugin::notes(const message& msg)
{
	BUG_COMMAND(msg);

	static const str prompt = IRC_BOLD + IRC_COLOR + IRC_Purple + "notes"
		+ IRC_COLOR + IRC_Black + ": " + IRC_NORMAL;

	if(!is_user_valid(msg, WHOIS_USER))
		return bot.cmd_error(msg, msg.get_sender() + " is not authorised to use the whois database.");

	// !notes <GUID> (add <text> | mod <n> <text> | del <n> | list)

	str guid, cmd;
	if(!bot.extract_params(msg, {&guid, &cmd}, true))
		return false;

	if(!is_guid(guid))
		return bot.cmd_error(msg, prompt + "Invalid GUID: " + guid);

	if(cmd == "add")
	{
		str text;
		if(!bot.extract_params(msg, {&guid, &cmd, &text}, true))
			return false;

		str g, note;
		str_vec notes;

		lock_guard lock(db_mtx);

		std::ifstream ifs("data/rconics-db-note.txt");
		while(std::getline(ifs >> g >> std::ws, note))
			if(g == guid)
				notes.push_back(note);
		ifs.close();
		notes.push_back(text);

		std::ofstream ofs("data/rconics-db-note.txt");
		for(const str& note: notes)
			ofs << guid << ' ' << note << '\n';
		ofs.close();
		bot.fc_reply(msg, prompt + "Note added for: " + guid);
	}
	else if(cmd == "mod")
	{
		// !notes GUID mod 4 "New text here"
		str num, text;
		if(!bot.extract_params(msg, {&guid, &cmd, &num, &text}, true))
			return false;

		siz n = 0;
		if(!(std::istringstream(num) >> n))
			return bot.cmd_error(msg, prompt + "Expected line number, got: " + num);

		str g, note;
		str_vec notes;

		lock_guard lock(db_mtx);

		std::ifstream ifs("data/rconics-db-note.txt");

		for(siz i = 0; std::getline(ifs >> g >> std::ws, note);)
			if(g == guid)
				notes.push_back(++i == n ? text : note);
		ifs.close();

		std::ofstream ofs("data/rconics-db-note.txt");
		for(const str& note: notes)
			ofs << guid << ' ' << note << '\n';
		ofs.close();
		bot.fc_reply(msg, prompt + "Note modified for: " + guid);
	}
	else if(cmd == "ins")
	{
		// !notes GUID ins 4 "New text here" // inserts after
		str num, text;
		if(!bot.extract_params(msg, {&guid, &cmd, &num, &text}, true))
			return false;

		siz n = 0;
		if(!(std::istringstream(num) >> n))
			bot.cmd_error(msg, prompt + "Expected line number, got: " + num);

		str g, note;
		str_vec notes;

		lock_guard lock(db_mtx);

		std::ifstream ifs("data/rconics-db-note.txt");

		if(n == 0)
			notes.push_back(text);
		for(siz i = 0; std::getline(ifs >> g >> std::ws, note);)
			if(g == guid)
			{
				notes.push_back(note);
				if(++i == n)
					notes.push_back(text);
			}
		ifs.close();

		std::ofstream ofs("data/rconics-db-note.txt");
		for(const str& note: notes)
			ofs << guid << ' ' << note << '\n';
		ofs.close();
		bot.fc_reply(msg, prompt + "Note inserted for: " + guid);
	}
	else if(cmd == "del")
	{
		// !notes GUID del 4
		str num;
		if(!bot.extract_params(msg, {&guid, &cmd, &num}, true))
			return false;

		siz n = 0;
		if(!(std::istringstream(num) >> n))
			return bot.cmd_error(msg, prompt + "Expected line number, got: " + num);

		str g, note;
		str_vec notes;

		lock_guard lock(db_mtx);

		std::ifstream ifs("data/rconics-db-note.txt");
		for(siz i = 0; std::getline(ifs >> g >> std::ws, note);)
			if(g == guid && ++i != n)
				notes.push_back(note);
		ifs.close();

		std::ofstream ofs("data/rconics-db-note.txt");
		for(const str& note: notes)
			ofs << guid << ' ' << note << '\n';
		ofs.close();
		bot.fc_reply(msg, prompt + "Note deleted from: " + guid);
	}
	else if(cmd.empty() || cmd == "list")
	{
		str g, note;
		lock_guard lock(db_mtx);
		std::ifstream ifs("data/rconics-db-note.txt");
		for(siz i = 0; std::getline(ifs >> g >> std::ws, note);)
			if(g == guid)
				bot.fc_reply(msg, prompt + " " + std::to_string(++i) + " " + note);
		ifs.close();
		bot.fc_reply(msg, prompt + "End of notes for: " + guid);
	}
	else
	{
		return bot.cmd_error(msg, prompt + "Unknown command: " + cmd);
	}
	return true;
}

bool RConicsIrcBotPlugin::rconmsg(const message& msg)
{
	BUG_COMMAND(msg);

	//std::istringstream iss(msg.get_user_params());

	str cmd, server;
	if(!bot.extract_params(msg, {&server, &cmd}))
		return false;

	if(!rcon_user_valid(msg.from, server))
		return bot.cmd_error(msg, msg.get_sender() + " is not authorised for " + server + ".");

	bug("cmd: " << cmd);

	if(cmd == "add") // !oarconmsg add google chat 1h "Wibble Wobble Woo"
	{
		automsg amsg;
		str repeat;
		if(!bot.extract_params(msg, {&amsg.server, &cmd, &amsg.method, &repeat, &amsg.text}))
			return false;

		bug("cmd        : " << cmd);
		bug("amsg.name  : " << amsg.server);
		bug("amsg.method: " << amsg.method);
		bug("repeat     : " << repeat);
		bug("amsg.text  : " << amsg.text);

		if(!(std::istringstream(repeat) >> amsg.repeat))
			return bot.cmd_error(msg, help(msg.get_user_cmd()));

		std::time(&amsg.when);
		amsg.owner = msg;
		amsg.active = true;
		{
			lock_guard lock(automsgs_mtx);
			automsgs.push_back(amsg);
		}
		write_automsgs();
		bot.fc_reply(msg, "Message added.");
	}
	else if(cmd == "del" || cmd == "delete")
	{
		str p;
		if(!bot.extract_params(msg, {&server, &cmd, &p}))
			return false;
		bug("p: " << p);
		siz pos;
		if(!(std::istringstream(p) >> pos))
			return bot.cmd_error(msg, "Expected number, found " + p + ".");

		bug("pos: " << pos);
		if(!(pos < automsgs.size()))
			return bot.cmd_error(msg, "Number " + p + " out of range.");

		{
			lock_guard lock(automsgs_mtx);
			for(siz i = 0; i < automsgs.size(); ++i)
				if(automsgs[i].server == server)
					if(!pos--) { automsgs.erase(automsgs.begin() + i); break; }
		}
		write_automsgs();
		bot.fc_reply(msg, "Message deleted.");
	}
	else if(cmd == "list")
	{
		siz i = 0;
		lock_guard lock(automsgs_mtx);
		for(const automsg& amsg: automsgs)
		{
			if(amsg.server == server)
			{
				str prefix = "x ";
				if(amsg.active)
					prefix = "/ ";
				std::ostringstream oss;
				oss << std::boolalpha;
				oss << (i++) << ": " << prefix << amsg.server << " " << amsg.method << " " << amsg.repeat << " \"" << amsg.text << "\"";
				bot.fc_reply(msg, oss.str());
			}
		}
		bot.fc_reply(msg, "-: ----------------------------");
	}
	else if(cmd == "echo")
	{
		// !rconmsg <server> echo (on|off) [#<n>]
		str state; // on | off
		str p; // #0-n (optional)
		if(!bot.extract_params(msg, {&server, &cmd, &state, &p}, false)
		&& !bot.extract_params(msg, {&server, &cmd, &state}, true))
			return false;
		state = lowercase(state);
		bug("state: " << state);

		if(!p.empty() && (p.size() < 2 || p[0] != '#'))
			return bot.cmd_error(msg, "expected index (eg. #2)");

		siz pos = 0;
		if(!p.empty() && (!std::istringstream(p.substr(1)) >> pos))
			return bot.cmd_error(msg, "expected number after # (eg. #2)");

		bug("pos: " << pos);

		if(state == "on")
		{
			lock_guard lock(automsg_subs_mtx);
			if(automsg_subs[server].count(msg))
				bot.fc_reply(msg, "Auto messages for " + server + " are already being echoed to this channel.");
			else
			{
				automsg_subs[server].insert(msg);
				bot.fc_reply(msg, "Auto messages for " + server + " will now be echoed to this channel.");
			}
		}
		else if(state == "off")
		{
			lock_guard lock(automsg_subs_mtx);
			if(automsg_subs[server].count(msg))
				bot.fc_reply(msg, "Auto messages for " + server + " were not being echoed to this channel.");
			else
			{
				automsg_subs[server].erase(msg);
				bot.fc_reply(msg, "Auto messages for " + server + " will no longer be echoed to this channel.");
			}
		}
		else
		{
			return bot.cmd_error(msg, "expected \"on\" or \"off\".");
		}
	}
	else if(cmd == "on")
	{
		str p; // #0-n (optional)
		bot.extract_params(msg, {&server, &cmd, &p}, false);

		if(!p.empty() && (p.size() < 2 || p[0] != '#'))
			return bot.cmd_error(msg, "expected index (eg. #2)");

		siz pos = 0;
		if(!p.empty() && (!std::istringstream(p.substr(1)) >> pos))
			return bot.cmd_error(msg, "expected number after # (eg. #2)");

		lock_guard lock(automsgs_mtx);
		for(siz i = 0; i < automsgs.size(); ++i)
		{
			if(automsgs[i].server == server)
			{
				if(p.empty())
				{
					if(!automsgs[i].active)
						automsgs[i].when = std::time(0) - rand_int(0, automsgs[i].repeat);
					automsgs[i].active = true;
					do_automsg = true;
				}
				else if(!pos--)
				{
					if(!automsgs[i].active)
						automsgs[i].when = std::time(0) - rand_int(0, automsgs[i].repeat);
					automsgs[i].active = true;
					do_automsg = true;
					bot.fc_reply(msg, msg.get_user_cmd() + ": "
						+ "Message " + std::to_string(i)
						+ " on " + server + " turned on.");
					break;
				}
			}
		}
		if(do_automsg)
			bot.fc_reply(msg, "Sending messages has been turned on.");
	}
	else if(cmd == "off")
	{
		str p; // #0-n (optional)
		bot.extract_params(msg, {&server, &cmd, &p}, false);

		if(!p.empty() && (p.size() < 2 || p[0] != '#'))
			return bot.cmd_error(msg, "expected index (eg. #2)");

		siz pos = 0;
		if(!p.empty() && (!std::istringstream(p.substr(1)) >> pos))
			return bot.cmd_error(msg, "expected number after # (eg. #2)");

		lock_guard lock(automsgs_mtx);
		for(siz i = 0; i < automsgs.size(); ++i)
		{
			if(automsgs[i].server == server)
			{
				if(p.empty())
				{
					automsgs[i].active = false;
					do_automsg = false;
				}
				else if(!pos--)
				{
					automsgs[i].active = false;
					bot.fc_reply(msg, msg.get_user_cmd() + ": "
						+ "Message " + std::to_string(i)
						+ " on " + server + " turned off.");
					break;
				}
			}
		}
		if(!do_automsg)
			bot.fc_reply(msg, "Sending messages has been turned off.");
	}
	else
	{
		return bot.cmd_error(msg, help(msg.get_user_cmd()));
	}
	return true;
}

/*
   num score ping name                 lastmsg address        qport rate
   0   102   100  ^3*^4C^3R^4A^3S^4H^7 50      83.40.9.233    11794 25000
   1   169    51  ^3<^4C^3L^4A^3S^4H^7 50      90.192.206.146 61741 25000
   2    76    48  SodaMan^7            50      86.2.36.24     40032 25000
   3     9    50  INFOSAUR^7            0      188.129.108.62 50366 25000
   4    44   162  Siju^7               50      84.149.86.221  61493  2500
   5   118    12  MoFo^7               50      81.165.47.147   7150 25000
   6    18   118  TUT^7                50      78.166.20.57   53487 25000
 */
struct rcon_status_t
{
	siz num;
	siz score;
	siz ping;
	str name;
	siz lastmsg;
	str address;
	siz qport;
	siz rate;
};

/*

server name avescore aveping

*/

bool RConicsIrcBotPlugin::rename(const message& msg)
{
	str server, from, to;
	if(!bot.extract_params(msg, {&server, &from, &to}))
		return false;

	if(!rcon_user_valid(msg.from, server))
		return bot.cmd_error(msg, msg.get_sender() + " is not authorised for " + server + ".");

	lock_guard lock1(renames_mtx);
	renames[server][from] = to;
	lock_guard lock2(renames_subs_mtx);
	renames_subs[server].insert(msg);

	return true;
}

bool RConicsIrcBotPlugin::reteam(const message& msg)
{
	str server, guid, team;
	if(!bot.extract_params(msg, {&server, &guid, &team}))
		return false;

	if(!rcon_user_valid(msg.from, server))
		return bot.cmd_error(msg, msg.get_sender() + " is not authorised for " + server + ".");

	rcon_server_map& sm = get_rcon_server_map();
	rcon_server_map::iterator s;

	if((s = sm.find(server)) == sm.end())
	{
		bot.fc_reply(msg, "There is no server named " + server);
		return false;
	}

	team = lowercase(team);

	reteam_info info;

	info.team = ' '; // delete reteam entry
	if(team == "r" || team == "red")
		info.team = 'r';
	else if(team == "b" || team == "blue")
		info.team = 'b';
	else if(team == "s" || team == "spec")
		info.team = 's';

	str res = do_rcon(msg, "status", s->second);
	if(!trim(res).empty())
	{
		// map: mlctf1beta
		// num score ping name            lastmsg address               qport rate
		// --- ----- ---- --------------- ------- --------------------- ----- -----
		std::istringstream iss(res);
		str line;
		while(std::getline(iss, line) && !trim(line).empty() && line[0] != '-')
			if(!line.find("map:") && line.size() > 5)
				mapname = line.substr(5);
		info.mapname = mapname;
	}

	info.when = std::time(0);
	info.secs = bot.get("rconics.reteam.duration", 5 * 60);

	lock_guard lock1(reteams_mtx);
	if(info.team == ' ')
	{
		reteams[server].erase(reteams[server].find(guid));
		bot.fc_reply(msg, "Reteam removed for: " + guid);
	}
	else
	{
		reteams[server][guid] = info;
		bot.fc_reply(msg, str("Reteam to ") + info.team + " added for: " + guid);
	}

	lock_guard lock2(reteams_subs_mtx);
	if(info.team == ' ')
		reteams_subs[server].erase(reteams_subs[server].find(msg));
	else
		reteams_subs[server].insert(msg);

	return true;
}

bool RConicsIrcBotPlugin::is_user_valid(const message& msg, const str& svar)
{
	for(const str& s: bot.get_vec(svar))
		if(msg.from.find(s) != str::npos)
			return true;
	return false;
}

bool RConicsIrcBotPlugin::adminkill(const message& msg)
{
	static const str prompt = IRC_BOLD + IRC_COLOR + IRC_Red + "adminkill"
		+ IRC_COLOR + IRC_Black + ": " + IRC_NORMAL;

	if(!is_user_valid(msg, RCON_ADMINKILL_USERS))
	{
		bot.fc_reply(msg, prompt + msg.get_sender() + " is not authorised to use the adminkill feature.");
		return false;
	}

	// !adminkill <server> <guid>+

	str server, guid;
	std::istringstream iss(msg.get_user_params());

	rcon_server_map& sm = get_rcon_server_map();

	if(!(iss >> server) || sm.find(server) == sm.cend())
	{
		bot.fc_reply_pm(msg, prompt + server + " is not a known server name.");
		return false;
	}

	rcon_server& s = sm.at(server);

	str pass = bot.get(RCON_ADMINKILL_PASS);
	if(trim(pass).empty())
	{
		bot.fc_reply_pm(msg, prompt + "Emergency password is empty.");
		return false;
	}

	// Get admins for server
	do_adminkill.insert(server); // Initiate adminkill for this server

	str_map admins; // GUID -> #num
	str ret = do_rcon(msg, "!listadmins", s);
	str line, num, id;
	iss.clear();
	iss.str(ret);
	while(std::getline(iss, line))
	{
		//	  68    5 Server Operator (*1FC5218E) *M*^AIM
		if(line.find("!listadmins") == str::npos)
		{
			if(!(std::istringstream(line) >> num >> id >> id >> id) || id.size() != 11)
			{
				bot.fc_reply_pm(msg, prompt + "Error parsing !listadmins: " + line);
				continue;
			}
			admins[id] = num;
		}
	}

	ret = do_rcon(msg, "rconpassword " + bot.get(RCON_ADMINKILL_PASS), s);
	s.pass = bot.get(RCON_ADMINKILL_PASS);

	while(iss >> guid)
	{
		if(!is_guid(guid))
		{
			bot.fc_reply_pm(msg, prompt + guid + " is not a valid GUID.");
			continue;
		}
		if(admins.find(guid) == admins.end())
		{
			bot.fc_reply_pm(msg, prompt + guid + " is not a valid admin on " + server + ".");
			continue;
		}

		// get all their IP addresses
		db_rec r;
		str_set ips;
		std::ifstream ifs("data/rconics-db-ip.txt");
		while(ifs >> r)
			if(lowercase(r.guid) == lowercase(guid))
				ips.insert(r.data);
		ifs.close();

		// Remove their !admin rights
		ret = do_rcon(msg, "!setlevel " + admins[guid] + " 0", s);

		// ban all their known IP addresses
		for(const str& ip: ips)
		{
			std::this_thread::sleep_for(std::chrono::milliseconds(500));
			ret = rcon("addip " + ip, s);
		}
	}

	return true;
}

bool RConicsIrcBotPlugin::rcon_stats(const message& msg)
{
	static const str prompt = IRC_BOLD + IRC_COLOR + IRC_Green + "rcon_stats"
		+ IRC_COLOR + IRC_Black + ": " + IRC_NORMAL;
	// !rcon_stats <server> [echo] (on|off)

	str server;
	std::istringstream iss(msg.get_user_params());

	if(!(iss >> server))
		return bot.cmd_error(msg, "Expected server name.");
	if(!rcon_user_valid(msg.from, server))
		return bot.cmd_error(msg, msg.get_sender() + " is not authorised for " + server + ".");

	str cmd;
	if(!(iss >> cmd))
		return bot.cmd_error(msg, "Expected [echo] (on|off).");

	if(cmd == "on")
	{
		do_stats.insert(server);
		bot.fc_reply(msg, "Stats announcing has been turned on for " + server + ".");
	}
	else if(cmd == "off")
	{
		do_stats.erase(server);
		bot.fc_reply(msg, "Stats announcing has been turned off for " + server + ".");
	}
	else if(cmd == "echo")
	{
		if(!(iss >> cmd))
			return bot.cmd_error(msg, "Expected (on|off).");

		if(cmd == "on")
		{
			lock_guard lock(stats_subs_mtx);
			stats_subs.insert(msg);
			bot.fc_reply(msg, "Stats announcing will now be echoed to this channel.");
		}
		else if(cmd == "off")
		{
			lock_guard lock(stats_subs_mtx);
			stats_subs.erase(msg);
			bot.fc_reply(msg, "Stats announcing will no longer be echoed to this channel.");
		}
	}
	return true;
}

bool RConicsIrcBotPlugin::initialize()
{
	read_automsgs();
	add
	({
		"!notes"
		, "!notes <GUID> (add|mod|del|list) ... Edit notes."
		  "\n  !notes <GUID> add <text> - Add a new note to player with GUID."
		  "\n  !notes <GUID> mod <n> <text> - Replace a note #n on player with GUID."
		  "\n  !notes <GUID> del <n> - Delete note #n from player with GUID."
		  "\n  !notes <GUID> list - List notes for player with GUID."
		, [&](const message& msg){ notes(msg); }
	});
	add
	({
		"!write_db_on"
		, "!write_db_on Turn on data capture."
		, [&](const message& msg){ write_db = true; bot.fc_reply(msg, "Capture of GUID/IP data now on."); }
	});
	add
	({
		"!write_db_off"
		, "!write_db_off Turn off data capture."
		, [&](const message& msg){ write_db = false; bot.fc_reply(msg, "Capture of GUID/IP data now off."); }
	});
	add
	({
		"!rcon_stats"
		, "!rcon_stats <server> [echo] (on|off)."
			"\n  Turn on|off stats announcing [or echoing] for a server."
		, [&](const message& msg){ rcon_stats(msg); }
	});
	add
	({
		"!whois"
		, "!whois (GUID|IP|name) [+ip] [+loc[=(code|country|state|city|zip|lat|long)]] [+isp] [#n]"
			"\n	 Find other known aliases for player with GUID, IP or name."
			"\n  Add optional IP location (+ip) or location (+loc) or ISP (+isp) to the report."
		, [&](const message& msg){ whois(msg); }
	});
	add
	({
		"!rcon"
		, "!rcon <server> <cmd> Send rcon to server id <name> (only users specified in config)."
		, [&](const message& msg){ rcon(msg); }
	});
	add
	({
		"!showbans"
		, "!showbans <server> Show bans on the given server."
		, [&](const message& msg){ showbans(msg); }
	});
	add
	({
		"!rconmsg"
		, "!rconmsg <server> add (cp|say|chat) <delay> - Add message <delay> = 1m (1minute) 1h (1 hour) 1d (1 day)"
			"\n  !rconmsg <server> del <#n> - Delete specific message from <server>"
			"\n  !rconmsg <server> list - List messages for a given <server>"
			"\n  !rconmsg <server> echo (on|off) [#<n>] - Adjust echo for a specific (#<n>) or all messages for <server>."
		, [&](const message& msg){ rconmsg(msg); }
	});
	add
	({
		"!rename"
		, "!rename <server> <from> <to> Rename a bot from <from> to <to> on the specified <server>."
		, [&](const message& msg){ rename(msg); }
	});
	add
	({
		"!reteam"
		, "!reteam <server> <guid> <r|b|s|x> Keep forcing a player with <guid> onto the given team <r|b|s|x> (x = delete)."
		, [&](const message& msg){ reteam(msg); }
	});
	add
	({
		"!adminkill"
		, "!adminkill <guid>."
		, [&](const message& msg){ adminkill(msg); }
		, action::INVISIBLE
	});
	automsg_timer.set_maxdelay(10);
	automsg_timer.set_mindelay(10);
	automsg_timer.on(0);
	return true;
}

// INTERFACE: IrcBotPlugin

str RConicsIrcBotPlugin::get_name() const { return NAME; }
str RConicsIrcBotPlugin::get_version() const { return VERSION; }

void RConicsIrcBotPlugin::exit()
{
	automsg_timer.turn_off();
}

}} // sookee::ircbot