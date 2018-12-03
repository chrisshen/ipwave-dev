//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU Lesser General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.
// 
// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// GNU Lesser General Public License for more details.
// 
// You should have received a copy of the GNU Lesser General Public License
// along with this program.  If not, see http://www.gnu.org/licenses/.
// 

import org.car2x.veins.nodes.RSU;
import org.car2x.veins.nodes.RSUIPv6;
import org.car2x.veins.nodes.ScenarioIPv6;

network IPv6ExampleScenario extends ScenarioIPv6
{
    submodules:
        rsu[1]: RSUIPv6 {
            @display("p=150,140;i=veins/sign/yellowdiamond;is=vs");
        }
}
