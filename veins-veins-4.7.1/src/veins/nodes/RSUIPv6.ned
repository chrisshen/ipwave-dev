//
// Copyright (C) 2008 Christoph Sommer <christoph.sommer@informatik.uni-erlangen.de>
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

package org.car2x.veins.nodes;

import org.car2x.veins.base.modules.*;
import org.car2x.veins.modules.nic.Nic80211pIPv6;
import inet.node.ipv6.Router6;

module RSUIPv6 extends Router6
{
    parameters:
        string applType; //type of the application layer
        string nicType = default("Nic80211pIPv6"); // type of network interface card

    gates:
        input veinsradioIn; // gate for sendDirect
    submodules:
        appl: <applType> like org.car2x.veins.base.modules.IBaseApplLayer {
            parameters:
                @display("p=799.5,79.299995");
        }

        nic: <nicType> like org.car2x.veins.modules.nic.INic80211pIPv6 {
            parameters:
                @display("p=599.3,575.89996");
        }

        mobility: BaseMobility {
            parameters:
                @display("p=124.799995,170.3;i=block/cogwheel");
        }

    connections:
        veinsradioIn --> nic.radioIn;

        appl.lowerLayerOut --> at.in++;
        appl.lowerLayerIn <-- at.out++;
        appl.lowerControlIn <-- at.out++;
        appl.lowerControlOut --> at.in++;

        nl.in++ <-- nic.upperLayerOut;
        nl.out++ --> nic.upperLayerIn;
        nl.in++ <-- nic.upperControlOut;
        nl.out++ --> nic.upperControlIn;
}
