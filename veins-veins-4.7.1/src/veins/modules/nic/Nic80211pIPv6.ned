//
// Copyright (C) 2011 David Eckhoff <eckhoff@cs.fau.de>
//
// Documentation for these modules is at http://veins.car2x.org/
//
// This program is free software; you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation; either version 2 of the License, or
// (at your option) any later version.
//
// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// GNU General Public License for more details.
//
// You should have received a copy of the GNU General Public License
// along with this program; if not, write to the Free Software
// Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA
//

package org.car2x.veins.modules.nic;

import org.car2x.veins.modules.phy.PhyLayer80211p;
import org.car2x.veins.modules.mac.ieee80211p.Mac1609_4;
import org.car2x.veins.modules.nic.INic80211pIPv6;
import inet.networklayer.common.InterfaceTable;

//
// This NIC implements an 802.11p network interface card.
//
// @author David Eckhoff
//
// @see BaseWaveApplLayer
// @see Mac1609_4
// @see PhyLayer80211p
//
module Nic80211pIPv6 like INic80211pIPv6
{
	parameters:
        @class(::inet::InterfaceEntry);
        string interfaceTableModule;    
        *.interfaceTableModule = default(absPath(interfaceTableModule));
		@display("i=block/ifcard;bgl=53");
		
    gates:
        input upperLayerIn; // to upper layers
        output upperLayerOut; // from upper layers
        output upperControlOut; // control information
        input upperControlIn; // control information
        input radioIn; // radioIn gate for sendDirect

    submodules:
        phy80211p: PhyLayer80211p {
            @display("p=69,218;i=block/process_s");
        }

        mac1609_4: Mac1609_4 {
            @display("p=69,82");
        }

    connections:
        radioIn --> phy80211p.radioIn;

        mac1609_4.lowerControlOut --> phy80211p.upperControlIn;
        mac1609_4.lowerLayerOut --> phy80211p.upperLayerIn;
        phy80211p.upperLayerOut --> mac1609_4.lowerLayerIn;
        phy80211p.upperControlOut --> mac1609_4.lowerControlIn;
        
        mac1609_4.upperControlIn <-- upperControlIn;
        mac1609_4.upperLayerIn <-- upperLayerIn;

        mac1609_4.upperLayerOut --> upperLayerOut;
        mac1609_4.upperControlOut --> upperControlOut;
          
}
