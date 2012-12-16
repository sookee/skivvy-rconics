/*
 * test.cpp
 *
 *  Created on: Dec 15, 2012
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

#include <skivvy-rconics/plugin-rconics.h>

using namespace skivvy::ircbot;

int main()
{
	automsg amsg;

	message owner;

//	str from; // ":Nick!user@network"
//	str cmd; // "PRIVMSG"
//	str params; // not same as user_params()
//	str to; // "#oa-ictf" | Nick;
//	str text; // "evening all";


	owner.from = "<message from>";
	owner.cmd = "<message cmd>";
	owner.params = "<message params>";
	owner.to = "<message to>";
	owner.text = "<message text>";

	amsg.active = true;
	amsg.owner = owner;
	amsg.server = "<server>";
	amsg.method= "<method>";
	amsg.repeat = 60;
	amsg.text = "<message>";
	amsg. when = 0; // last trigger

	std::cout << "amsg: " << amsg << '\n';
}

