#pragma once
#ifndef _SOOKEE_IRCBOT_RCONICS_H_
#define _SOOKEE_IRCBOT_RCONICS_H_
/*
 * ircbot-rconics.h
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

#include <skivvy/ircbot.h>

#include <ctime>
#include <utility>
#include <chrono>

// RPC
#include <skivvy/plugin-oastats.h>
#include <skivvy/store.h>

namespace skivvy { namespace rconics {

using namespace skivvy;
using namespace skivvy::utils;
using namespace skivvy::ircbot;

struct automsg;

std::ostream& serialize_0_1(std::ostream& os, const automsg& amsg);

std::istream& deserialize_unversionned(std::istream& is, automsg& m);
//std::istream& deserialize_unversionned(std::istream&& is, automsg& m);
std::istream& deserialize_0_1(std::istream& is, automsg& m);
//std::istream& deserialize_0_1(std::istream&& is, automsg& m);

struct automsg
{
	bool active = false;
	str server; // server name
	str method; // say | chat | cp
	delay repeat; // delay in seconds
	str text;
	time_t when; // last trigger

	automsg(): when(0) {}

	typedef std::function<std::istream&(std::istream&,automsg&)> deserialize_func;

	static deserialize_func get_deserialize(const str& version)
	{
		bug_func();
		bug_var(version);
		if(version == "0.1")
			return &deserialize_0_1;
		return &deserialize_unversionned;
	}
};

inline
std::ostream& serialize_0_1(std::ostream& os, const automsg& m)
{
	os << '{' << m.active;
	os << ',' << m.server;
	os << ',' << m.method;
	os << ',' << m.repeat;
	os << ',' << escaped(m.text) << '}';
	return os;
}

std::ostream& operator<<(std::ostream& os, const automsg& m)
{
	return serialize_0_1(os, m);
}

// true,{owner},zim,chat,12m,Some text to print
inline
std::istream& deserialize_unversionned(std::istream& is, automsg& m)
{
	bug_func();
	is >> m.active >> std::ws;
	is >> m.server >> std::ws;
	is >> m.method >> std::ws;
	is >> m.repeat >> std::ws;
	std::getline(is, m.text);
	m.when = 0;

	return is;
}

inline
std::istream& deserialize_unversionned(std::istream&& is, automsg& m)
{
	return deserialize_unversionned(is, m);
}

inline
std::istream& deserialize_0_1(std::istream& is, automsg& m)
{
	bug_func();
	str o;
	if(!getobject(is, o))
		return is;
	bug_var(o);
	siss iss(o);
	(iss >> m.active).ignore(1, ',');
	sgl(iss, m.server, ',');
	sgl(iss, m.method, ',');
	(iss >> m.repeat).ignore(1, ',');
	if(!sgl(iss, m.text))
		is.setstate(std::ios::failbit); // protocol error
	else
		unescape(m.text);
	return is;
}

inline
std::istream& deserialize_0_1(std::istream&& is, automsg& m)
{
	return deserialize_0_1(is, m);
}

inline
std::istream& operator>>(std::istream& is, automsg& m)
{
	return deserialize_0_1(is, m);
}

inline
std::istream& operator>>(std::istream&& is, automsg& m)
{
	return operator>>(is, m);
}

/**
 *
 */
class RConicsIrcBotPlugin
: public BasicIrcBotPlugin
//, public IrcBotRPCService
{
private:

	std::mutex rconlog_mtx;

	enum class poll
	{
		RCONMSG
		, STATS
		, DB_WRITE
		, RENAMES
	};

	typedef std::map<poll, st_time_point> pollmap;

	pollmap polls;

	inline bool polltime(const poll& p, const std::chrono::seconds& secs)
	{
		if(polls[p] + secs < st_clk::now())
		{
			//bug("POLLING");
			polls[p] = st_clk::now() ;
			return true;
		}
		return false;
	}

	inline bool polltime(const poll& p, const str& var, siz dflt = 0)
	{
		return polltime(p,  std::chrono::seconds(bot.get(var, dflt)));
	}

	// rconics.user: <user>
	// rconics.user.name: <user> <name>
	// rconics.user.pass: <user> <pass>
	// rconics.user.preg: <user> <regex>

	struct rc_user
	{
		str name;
		str pass;
		str_vec pregs;
	};

	typedef std::map<str, rc_user> usermap;

	struct rcon_server
	{
		str host;
		siz port = 27960;
		str pass;
	};

	typedef std::map<const str, str_vec> rcon_user_map;
	typedef std::pair<const str, str_vec> rcon_user_pair;

	typedef std::map<const str, rcon_server> rcon_server_map;
	typedef std::pair<const str, rcon_server> rcon_server_pair;
	typedef rcon_server_map::iterator server_map_iter;
	typedef rcon_server_map::const_iterator rcon_server_map_citer;

	typedef std::map<str, std::map<str, bool> > server_var_map;
	typedef std::pair<const str, std::map<str, bool> > server_var_pair;

	server_var_map varmap; // <server> -> {var -> <active>}

	usermap& get_rcon_users();

	rcon_user_map& get_rcon_user_map();
	rcon_server_map& get_rcon_server_map();

	RandomTimer automsg_timer;
	BackupStore store;

	str var_sub(const str& s, const str& server);
	void regular_poll();

	typedef std::vector<automsg> automsg_vec;

	automsg_vec automsgs;
	std::mutex automsgs_mtx;

	struct cmp_messages
	{
		bool operator()(const message& m1, const message& m2) const
		{
			return m1.get_to() < m2.get_to();
		}
	};


//	typedef std::set<message, cmp_messages> message_set;
	typedef str_set chan_set;
	typedef std::map<str, chan_set> chan_set_map;
	typedef std::pair<const str, chan_set> chan_set_pair;

	bool save_automsg_state_to_store();
	bool load_automsg_state_to_store();
	bool do_automsg = true;
	str_set do_automsg_for; // server
	chan_set_map automsg_subs; // automsg subscriptions

	str_set do_stats; // servers to announce stats to

	chan_set stats_subs; // stats subscriptions
	std::mutex stats_subs_mtx;

	typedef str_map location_map;

	str get_isp(const str& ip);
	bool get_loc_map(const str& ip, location_map& m);
	str get_loc(const str& ip, const str& item = "code");

	void read_automsgs();
	void write_automsgs();

	bool rcon_user_valid(const str& user, const str& server_name);
//	bool whois_user_valid(const str& user);
	bool is_user_valid(const message& msg, const str& svar);

	// Raw rcon
	str rcon(str cmd, const rcon_server& s);

	// Filtered (adds rconics botname to chats etc...)
	str do_rcon(const message& msg, str cmd, const str& host, siz port, const str& pass);
	str do_rcon(const message& msg, str cmd, const rcon_server& s);

	// managed servers

	struct player
	{
		siz num; // game slot
		siz admin; // admin level
		str guid;
		str name;
		char team; // R|B|S
		siz score;
		siz ping;
		siz count;

		player(): num(0), score(0), ping(0), count(0) {}

		bool operator<(const player& p) const { return this->num < p.num; }
	};

	typedef std::set<player> player_set;
	typedef player_set::iterator player_set_iter;
	typedef player_set::const_iterator player_set_citer;

	typedef std::map<const str, player_set> player_map;
	typedef std::pair<const str, player_set> player_pair;

	// regular polled info (each minute)

	player_map prev;
	std::mutex prev_mtx;
	player_map curr;
	std::mutex curr_mtx;

	str mapname; // current mapname

	//str_vec managed;

	enum class DB_SORT
	{
		MOST_POPULAR
		, MOST_RECENT
	};

	bool write_db = true;
	static std::mutex db_mtx;
	void write_to_db(const str& db, const str& guid_in, const str& data, DB_SORT sort);

	// rename
	typedef std::map<str, str_map> str_str_map;
	typedef std::map<str, chan_set> str_message_set_map;

	str_str_map renames; // {"server" -> {"from" -> "to"}}
	std::mutex renames_mtx;
	str_message_set_map renames_subs; // rename subscriptions
	std::mutex renames_subs_mtx;

	// reteam

	struct reteam_info
	{
		char team;
		time_t when;
		delay secs; // how many minutes to keep
		str mapname; // keep only for this map if not empty()
	};
	typedef std::map<str, reteam_info> str_reteam_map;
	typedef str_reteam_map::iterator str_reteam_map_itr;
	typedef std::map<str, str_reteam_map> str_str_reteam_map;
	typedef str_str_reteam_map::iterator str_str_reteam_map_itr;

	typedef std::map<str, char> str_chr_map;
	typedef std::map<str, str_chr_map> str_str_chr_map;

//	str_str_chr_map reteams; // {"server" -> {"guid", {'team'}}}
	str_str_reteam_map reteams; // {"server" -> {"guid", {team, when, mapname}}}
	std::mutex reteams_mtx;
	str_message_set_map reteams_subs; // reteam subscriptions
	std::mutex reteams_subs_mtx;

	str_set do_adminkill; // server's undergoing adminkill process

	// RPC clients
	bool rpc_get_oatop(const str& params, stats_vector& v);

	// Bot Commands

	/**
	 * Do permission checks on user before executing rcon
	 */
	bool do_checked_rcon(const message& msg, const str& cmd, str& res);

	bool showbans(const message& msg);
	bool rcon(const message& msg);
	bool rconmsg(const message& msg);
	bool rcon_stats(const message& msg);
	bool whois(const message& msg);
	siz count_notes(const str& guid);
	bool notes(const message& msg);
	bool rename(const message& msg);
	bool reteam(const message& msg);
	bool adminkill(const message& msg);
	bool alert(const message& msg);

	bool rcon_short(const message& msg);//, const str& cmd);
	bool rcon_exec(const message& msg);

public:
	RConicsIrcBotPlugin(IrcBot& bot);
	virtual ~RConicsIrcBotPlugin();

	// INTERFACE: BasicIrcBotPlugin

	virtual bool initialize();

	// INTERFACE: IrcBotPlugin

	virtual str get_id() const;
	virtual str get_name() const;
	virtual str get_version() const;
	virtual void exit();

	// INTERFACE RPC

};

}} // skivvy::rconics

#endif // _SOOKEE_IRCBOT_RCONICS_H_
