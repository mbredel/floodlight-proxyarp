package net.floodlightcontroller.proxyarp;

/*
* Copyright (c) 2013, California Institute of Technology
* ALL RIGHTS RESERVED.
* Based on Government Sponsored Research DE-SC0007346
* Author Michael Bredel <michael.bredel@cern.ch>
* 
* Licensed under the Apache License, Version 2.0 (the "License");
* you may not use this file except in compliance with the License.
* You may obtain a copy of the License at
* 
*     http://www.apache.org/licenses/LICENSE-2.0
* 
* THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
* "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
* LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR
* A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT
* HOLDER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT,
* INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING,
* BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS
* OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED
* AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
* LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY
* WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
* POSSIBILITY OF SUCH DAMAGE.
* 
* Neither the name of the California Institute of Technology
* (Caltech) nor the names of its contributors may be used to endorse
* or promote products derived from this software without specific prior
* written permission.
*/

import java.io.IOException;
import java.util.ArrayList;
import java.util.Collection;
import java.util.HashSet;
import java.util.Hashtable;
import java.util.Iterator;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.Timer;
import java.util.TimerTask;

import org.openflow.protocol.OFMessage;
import org.openflow.protocol.OFPacketIn;
import org.openflow.protocol.OFPacketOut;
import org.openflow.protocol.OFPhysicalPort;
import org.openflow.protocol.OFPort;
import org.openflow.protocol.OFType;
import org.openflow.protocol.action.OFAction;
import org.openflow.protocol.action.OFActionOutput;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import net.floodlightcontroller.core.FloodlightContext;
import net.floodlightcontroller.core.IFloodlightProviderService;
import net.floodlightcontroller.core.IOFMessageListener;
import net.floodlightcontroller.core.IOFSwitch;
import net.floodlightcontroller.core.module.FloodlightModuleContext;
import net.floodlightcontroller.core.module.IFloodlightModule;
import net.floodlightcontroller.core.module.IFloodlightService;
import net.floodlightcontroller.devicemanager.IDeviceService;
import net.floodlightcontroller.devicemanager.internal.Device;
import net.floodlightcontroller.packet.ARP;
import net.floodlightcontroller.packet.Data;
import net.floodlightcontroller.packet.Ethernet;
import net.floodlightcontroller.packet.IPacket;
import net.floodlightcontroller.packet.IPv4;
import net.floodlightcontroller.routing.IRoutingDecision;
import net.floodlightcontroller.routing.RoutingDecision;
import net.floodlightcontroller.util.MACAddress;
import net.floodlightcontroller.topology.ITopologyService;

/**
 * The ARPProxy uses the topology information gathered by Floodlight and,
 * therefore, is aware of the location of the traffic's destination. It 
 * offers the MAC address directly to a requesting host. To this end, ARP
 * messages are not forwarded by the data plane, but handled by the
 * control plane. Thus, ARP messages are sort of tunneled to the OpenFlow
 * network. Moreover, the ARPProxy takes care that ARP requests are 
 * deleted after a certain timeout.
 * 
 * @author Michael Bredel <michael.bredel@cern.ch>
 */
public class ARPProxy extends TimerTask implements IOFMessageListener, IFloodlightModule {
	/** Broadcast MAC address. */
	protected static final long BROADCAST_MAC = 0xffffffffffffL;
	/** APR timeout in milliseconds. */
	protected static final long ARP_TIMEOUT = 5000L;
	
	/** Logger to log ProxyARP events.*/
	protected static Logger logger;
	/** Required Module: Floodlight Provider Service. */
	protected IFloodlightProviderService floodlightProvider;
	/** Required Module: Floodlight Device Manager Service. */
	protected IDeviceService deviceManager;
	/** Required Module: Topology Manager module. We listen to the topologyManager for changes of the topology. */
	protected ITopologyService topologyManager;
	/** A map that maps: TargetIPAddress -> Set of ARPRequest. */
	protected Map<Long, Set<ARPRequest>> arpRequests;
	/** A timer object to schedule ARP timeouts. */
	protected Timer timer;
	
	/**
	 * Encapsulates information regarding the ARP request and its
	 * state. 
	 * 
	 * @author Michael Bredel <michael.bredel@cern.ch>
	 */
	protected class ARPRequest {
		/** The MAC address of the source host */
		private long sourceMACAddress;
		/** The IP address of the source host. */
		private long sourceIPAddress;
		/** The MAC address of the target (destination) host. */
		private long targetMACAddress;
		/** The IP address of the target (destination) host. */
		private long targetIPAddress;
		/** The switch ID of the switch where the ARP request is received. */
		private long switchId;
		/** The port ID of the port where the ARP request is received. */
		private short inPort;
		/** The time the ARP request started. */
		private long startTime;
		
		/** 
		 * Setter for the IP address of the source host that initialized the ARP request.
		 * 
		 * @param sourceIPAddress The IP address of the source host.
		 * @return <b>ARPRequest</b> The current ARPRequest object.
		 */
		public ARPRequest setSourceMACAddress(long sourceMACAddress) {
			this.sourceMACAddress = sourceMACAddress;
			return this;
		}
		
		/**
		 * Setter for the IP address of the source host that initialized the ARP request.
		 * 
		 * @param sourceIPAddress The IP address of the source host.
		 * @return <b>ARPRequest</b> The current ARPRequest object.
		 */
		public ARPRequest setSourceIPAddress(long sourceIPAddress) {
			this.sourceIPAddress = sourceIPAddress;
			return this;
		}
		
		/**
		 * Setter for the MAC address of the target (destination) host.
		 * 
		 * @param targetMACAddress The MAC address of the target (destination) host.
		 * @return <b>ARPRequest</b> The current ARPRequest object.
		 */
		public ARPRequest setTargetMACAddress(long targetMACAddress) {
			this.targetMACAddress = targetMACAddress;
			return this;
		}
		
		/**
		 * Setter for the IP address of the target (destination) host.
		 * 
		 * @param targetIPAddress The IP address of the target (destination) host.
		 * @return <b>ARPRequest</b> The current ARPRequest object.
		 */
		public ARPRequest setTargetIPAddress(long targetIPAddress) {
			this.targetIPAddress = targetIPAddress;
			return this;
		}
		
		/**
		 * Setter for the SwitchId where the ARP request is received.
		 * 
		 * @param switchId Where the ARP request is received.
		 * @return <b>ARPRequest</b> The current ARPRequest object.
		 */
		public ARPRequest setSwitchId(long switchId) {
			this.switchId = switchId;
			return this;
		}
		
		/**
		 * Setter for the PortId where the ARP request is received.
		 * 
		 * @param portId Where the ARP request is received.
		 * @return <b>ARPRequest</b> The current ARPRequest object.
		 */
		public ARPRequest setInPort(short portId) {
			this.inPort = portId;
			return this;
		}
		
		/**
		 * Setter for the start time when the ARP request is received.
		 * 
		 * @param startTime The time when the ARP request is received.
		 * @return <b>ARPRequest</b> The current ARPRequest object.
		 */
		public ARPRequest setStartTime(long startTime) {
			this.startTime = startTime;
			return this;
		}
		
		/**
		 * Getter for the source MAC address, i.e from the node that initialized the ARP request.
		 * 
		 * @return <b>long</b> The MAC address of the source of the ARP request. 
		 */
		public long getSourceMACAddress() {
			return this.sourceMACAddress;
		}
		
		/**
		 * Getter for the source IP address, i.e. from the node that initialized the ARP request.
		 * 
		 * @return <b>long</b> The IP address of the source of the ARP request. 
		 */
		public long getSourceIPAddress() {
			return this.sourceIPAddress;
		}
		
		/**
		 * Getter for the target (destination) MAC address.
		 * 
		 * @return <b>long</b> The MAC address of the target (destination) of the ARP request. 
		 */
		public long getTargetMACAddress() {
			return this.targetMACAddress;
		}
		
		/**
		 * Getter for the target (destination) IP address.
		 * 
		 * @return <b>long</b> The IP address of the target (destination) of the ARP request. 
		 */
		public long getTargetIPAddress() {
			return this.targetIPAddress;
		}
		
		/**
		 * Getter for the switch ID of the ARP incoming switch.
		 * 
		 * @return <b>long</b> The switch ID of the switch where the ARP request is received.
		 */
		public long getSwitchId() {
			return this.switchId;
		}
		
		/**
		 * Getter for the port ID if the ARP incoming port.
		 * 
		 * @return <b>short</b> The port ID of the port where the ARP request is received.
		 */
		public short getInPort() {
			return this.inPort;
		}
		
		/**
		 * Getter for the start time of the ARP request.
		 * 
		 * @return <b>long</b> The start time when the ARP request is received.
		 */
		public long getStartTime() {
			return this.startTime;
		}
	}

	@Override
	public String getName() {
		return "ARPHandler";
	}

	@Override
	public boolean isCallbackOrderingPrereq(OFType type, String name) {
		return false;
	}

	@Override
	public boolean isCallbackOrderingPostreq(OFType type, String name) {
		return (type.equals(OFType.PACKET_IN) && name.equals("forwarding"));
	}

	@Override
	public Collection<Class<? extends IFloodlightService>> getModuleServices() {
		return null;
	}

	@Override
	public Map<Class<? extends IFloodlightService>, IFloodlightService> getServiceImpls() {
		return null;
	}

	@Override
	public Collection<Class<? extends IFloodlightService>> getModuleDependencies() {
		Collection<Class<? extends IFloodlightService>> l = new ArrayList<Class<? extends IFloodlightService>>();
		l.add(IFloodlightProviderService.class);
		return l;
	}

	@Override
	public void init(FloodlightModuleContext context) {
		floodlightProvider = context.getServiceImpl(IFloodlightProviderService.class);
		topologyManager = context.getServiceImpl(ITopologyService.class);
		deviceManager = context.getServiceImpl(IDeviceService.class);
		logger = LoggerFactory.getLogger(ARPProxy.class);	
	}

	@Override
	public void startUp(FloodlightModuleContext context) {
		floodlightProvider.addOFMessageListener(OFType.PACKET_IN, this);
		arpRequests = new Hashtable<Long, Set<ARPRequest>>();
		timer = new Timer();
		timer.schedule(this, ARP_TIMEOUT, ARP_TIMEOUT);
	}

	@Override
	public Command receive(	IOFSwitch sw, OFMessage msg, FloodlightContext cntx) {
		switch (msg.getType()) {
        	case PACKET_IN:
        		IRoutingDecision decision = null;
                if (cntx != null) {
                    decision = IRoutingDecision.rtStore.get(cntx, IRoutingDecision.CONTEXT_DECISION);
                    return this.processPacketInMessage(sw, (OFPacketIn) msg, decision, cntx);
                }
                break;
        	default:
        		break;
			}
		return Command.CONTINUE;
	}
	
	/**
	 * Handles packetIn messages and decides what to do with it.
	 * 
	 * @param sw The switch the packet is received.
	 * @param piMsg The OpenFlow PacketIN message from the switch containing all relevant information.
	 * @param decision A forwarding decision made by a previous module. 
	 * @param cntx The Floodlight context.
	 * @return <b>Command</b> The command whether another listener should proceed or not.
	 */
	protected Command processPacketInMessage(IOFSwitch sw, OFPacketIn piMsg, IRoutingDecision decision, FloodlightContext cntx) {
		/* A new empty ARP packet. */
		ARP arp = new ARP();
		/* Get the Ethernet frame representation of the PacketIn message. */
		Ethernet ethPacket = IFloodlightProviderService.bcStore.get(cntx, IFloodlightProviderService.CONTEXT_PI_PAYLOAD);
		
		// If this is not an ARP message, continue.
		if (ethPacket.getEtherType() != Ethernet.TYPE_ARP )
			return Command.CONTINUE;
		
		// Get the ARP packet or continue.
		if (ethPacket.getPayload() instanceof ARP) {
            arp = (ARP) ethPacket.getPayload();
		} else {
			return Command.CONTINUE;
		}
		
		// Handle ARP request.
		if (arp.getOpCode() == ARP.OP_REQUEST) {
			return this.handleARPRequest(arp, sw.getId(), piMsg.getInPort());
		}
		
		// Handle ARP reply.
		if (arp.getOpCode() == ARP.OP_REPLY) {
			return this.handleARPReply(arp);
		}
		
		// Handle RARP request. TODO
		
		// Handle RARP reply. TODO
		
		// Make a routing decision and drop the ARP instead of forwarding it.
		decision = new RoutingDecision(sw.getId(), piMsg.getInPort(), IDeviceService.fcStore.get(cntx, IDeviceService.CONTEXT_SRC_DEVICE), IRoutingDecision.RoutingAction.DROP);
        decision.addToContext(cntx);
		
		return Command.CONTINUE;
	}
	
	/**
	 * Handles incoming ARP requests. Reads the relevant information, creates an ARPRequest
	 * object, sends out the ARP request message or, if the information is already known by
	 * the system, sends back an ARP reply message.
	 * 
	 * @param arp The ARP (request) packet received.
	 * @param switchId The ID of the incoming switch where the ARP message is received. 
	 * @param port The Port ID where the ARP message is received.
	 * @return <b>Command</b> The command whether another listener should proceed or not.
	 */
	protected Command handleARPRequest(ARP arp, long switchId, short port) {
		/* The known IP address of the ARP source. */
		long sourceIPAddress = IPv4.toIPv4Address(arp.getSenderProtocolAddress());
		/* The known MAC address of the ARP source. */
		long sourceMACAddress = Ethernet.toLong(arp.getSenderHardwareAddress());
		/* The IP address of the (yet unknown) ARP target. */
		long targetIPAddress = IPv4.toIPv4Address(arp.getTargetProtocolAddress());
		/* The MAC address of the (yet unknown) ARP target. */
		long targetMACAddress = 0; 
		
		// Check if there is an ongoing ARP process for this packet.
		if (arpRequests.containsKey(targetIPAddress)) {
			// Update start time of current ARPRequest objects
			long startTime = System.currentTimeMillis();
			Set<ARPRequest> arpRequestSet = arpRequests.get(targetIPAddress);
			
			for (Iterator<ARPRequest> iter = arpRequestSet.iterator(); iter.hasNext();) {
				iter.next().setStartTime(startTime);
			}
			return Command.CONTINUE;
		}
		
		
		@SuppressWarnings("unchecked")
		Iterator<Device> diter = (Iterator<Device>) deviceManager.queryDevices(null, null, (int) targetIPAddress, null, null);	

		// There should be only one MAC address to the given IP address. In any case, 
		// we return only the first MAC address found.
		if (diter.hasNext()) {
			// If we know the destination device, get the corresponding MAC address and send an ARP reply.
			Device device = diter.next();
			targetMACAddress = device.getMACAddress();
			//long age = System.currentTimeMillis() - device.getLastSeen().getTime();
			
			//if (targetMACAddress > 0 && age < ARP_TIMEOUT) {
			if (targetMACAddress > 0) {
				ARPRequest arpRequest = new ARPRequest()
					.setSourceMACAddress(sourceMACAddress)
					.setSourceIPAddress(sourceIPAddress)
					.setTargetMACAddress(targetMACAddress)
					.setTargetIPAddress(targetIPAddress)
					.setSwitchId(switchId)
					.setInPort(port);
				// Send ARP reply.
				this.sendARPReply(arpRequest);
			} else {
				ARPRequest arpRequest = new ARPRequest()
					.setSourceMACAddress(sourceMACAddress)
					.setSourceIPAddress(sourceIPAddress)
					.setTargetIPAddress(targetIPAddress)
					.setSwitchId(switchId)
					.setInPort(port)
					.setStartTime(System.currentTimeMillis());
				// Put new ARPRequest object to current ARPRequests list.
				this.putArpRequest(targetIPAddress, arpRequest);
				// Send ARP request.
				this.sendARPReqest(arpRequest);
			}
			
		} else {
			ARPRequest arpRequest = new ARPRequest()
				.setSourceMACAddress(sourceMACAddress)
				.setSourceIPAddress(sourceIPAddress)
				.setTargetIPAddress(targetIPAddress)
				.setSwitchId(switchId)
				.setInPort(port)
				.setStartTime(System.currentTimeMillis());
			// Put new ARPRequest object to current ARPRequests list.		
			this.putArpRequest(targetIPAddress, arpRequest);
			// Send ARP request
			this.sendARPReqest(arpRequest);
		}
		
		return Command.CONTINUE;
	}
	
	/**
	 * Handles incoming ARP replies. Reads the relevant information, get the corresponding 
	 * ARPRequest object, and sends back and ARP reply message.
	 * 
	 * @param arp The ARP (reply) packet received.
	 * @return <p>Command</p> The command whether another listener should proceed or not.
	 */
	protected Command handleARPReply(ARP arp) {
		/* The IP address of the ARP target. */
		long targetIPAddress = IPv4.toIPv4Address(arp.getSenderProtocolAddress());
		/* The set of APRRequest objects related to the target IP address.*/
		Set<ARPRequest> arpRequestSet = arpRequests.remove(targetIPAddress);
		/* The ARPRequenst object related to the ARP reply message. */
		ARPRequest arpRequest;
		
		// If the ARP request has already timed out, consume the message.
		// The sending host should send a new request, actually.
		if (arpRequestSet == null)
			return Command.CONTINUE;
		
		for (Iterator<ARPRequest> iter = arpRequestSet.iterator(); iter.hasNext();) {
			arpRequest = iter.next();
			iter.remove();
			arpRequest.setTargetMACAddress(MACAddress.valueOf(arp.getSenderHardwareAddress()).toLong());
			sendARPReply(arpRequest);
		}
		
		return Command.CONTINUE;
	}
	
	/**
	 * Creates an ARP request frame, puts it into a packet out message and 
	 * sends the packet out message to all switch ports (attachment point ports)
	 * that are not connected to other OpenFlow switches.
	 * 
	 * @param arpRequest The ARPRequest object containing information regarding the current ARP process.
	 */
	protected void sendARPReqest(ARPRequest arpRequest) {
		// Create an ARP request frame
		IPacket arpReply = new Ethernet()
    		.setSourceMACAddress(Ethernet.toByteArray(arpRequest.getSourceMACAddress()))
        	.setDestinationMACAddress(Ethernet.toByteArray(BROADCAST_MAC))
        	.setEtherType(Ethernet.TYPE_ARP)
        	.setPayload(new ARP()
				.setHardwareType(ARP.HW_TYPE_ETHERNET)
				.setProtocolType(ARP.PROTO_TYPE_IP)
				.setOpCode(ARP.OP_REQUEST)
				.setHardwareAddressLength((byte)6)
				.setProtocolAddressLength((byte)4)
				.setSenderHardwareAddress(Ethernet.toByteArray(arpRequest.getSourceMACAddress()))
				.setSenderProtocolAddress(IPv4.toIPv4AddressBytes((int)arpRequest.getSourceIPAddress()))
				.setTargetHardwareAddress(Ethernet.toByteArray(arpRequest.getTargetMACAddress()))
				.setTargetProtocolAddress(IPv4.toIPv4AddressBytes((int)arpRequest.getTargetIPAddress()))
				.setPayload(new Data(new byte[] {0x01})));
		
		// Send ARP request to all external ports (i.e. attachment point ports).
		for (long switchId : floodlightProvider.getSwitches().keySet()) {
			IOFSwitch sw = floodlightProvider.getSwitches().get(switchId);
			for (OFPhysicalPort port : sw.getPorts()) {
				short portId = port.getPortNumber();
				if (topologyManager.isAttachmentPointPort(switchId, portId))
					this.sendPOMessage(arpReply, sw, portId);
			}
		}
	}
	
	/**
	 * Creates an ARP reply frame, puts it into a packet out message and 
	 * sends the packet out message to the switch that received the ARP
	 * request message.
	 * 
	 * @param arpRequest The ARPRequest object containing information regarding the current ARP process.
	 */
	protected void sendARPReply(ARPRequest arpRequest) {
		// Create an ARP reply frame (from target (source) to source (destination)).
		IPacket arpReply = new Ethernet()
    		.setSourceMACAddress(Ethernet.toByteArray(arpRequest.getTargetMACAddress()))
        	.setDestinationMACAddress(Ethernet.toByteArray(arpRequest.getSourceMACAddress()))
        	.setEtherType(Ethernet.TYPE_ARP)
        	.setPayload(new ARP()
				.setHardwareType(ARP.HW_TYPE_ETHERNET)
				.setProtocolType(ARP.PROTO_TYPE_IP)
				.setOpCode(ARP.OP_REPLY)
				.setHardwareAddressLength((byte)6)
				.setProtocolAddressLength((byte)4)
				.setSenderHardwareAddress(Ethernet.toByteArray(arpRequest.getTargetMACAddress()))
				.setSenderProtocolAddress(IPv4.toIPv4AddressBytes((int)arpRequest.getTargetIPAddress()))
				.setTargetHardwareAddress(Ethernet.toByteArray(arpRequest.getSourceMACAddress()))
				.setTargetProtocolAddress(IPv4.toIPv4AddressBytes((int)arpRequest.getSourceIPAddress()))
				.setPayload(new Data(new byte[] {0x01})));
		// Send ARP reply.
		sendPOMessage(arpReply, floodlightProvider.getSwitches().get(arpRequest.getSwitchId()), arpRequest.getInPort());
	}
	
	/**
	 * Creates and sends an OpenFlow PacketOut message containing the packet 
	 * information to the switch. The packet included on the PacketOut message 
	 * is sent out at the given port. 
	 * 
	 * @param packet The packet that is sent out.
	 * @param sw The switch the packet is sent out.
	 * @param port The port the packet is sent out.
	 */
	protected void sendPOMessage(IPacket packet, IOFSwitch sw, short port) {		
		// Serialize and wrap in a packet out
        byte[] data = packet.serialize();
        OFPacketOut po = (OFPacketOut) floodlightProvider.getOFMessageFactory().getMessage(OFType.PACKET_OUT);
        po.setBufferId(OFPacketOut.BUFFER_ID_NONE);
        po.setInPort(OFPort.OFPP_NONE);

        // Set actions
        List<OFAction> actions = new ArrayList<OFAction>();
        actions.add(new OFActionOutput(port, (short) 0));
        po.setActions(actions);
        po.setActionsLength((short) OFActionOutput.MINIMUM_LENGTH);

        // Set data
        po.setLengthU(OFPacketOut.MINIMUM_LENGTH + po.getActionsLength() + data.length);
        po.setPacketData(data);
        
        // Send message
        try {
        	sw.write(po, null);
        	sw.flush();
        } catch (IOException e) {
        	logger.error("Failure sending ARP out port {} on switch {}", new Object[] { port, sw.getStringId() }, e);
        }
	}
	
	/**
	 * Puts the current ARP request to a list of concurrent ARP requests.
	 * 
	 * @param targetIPAddress The IP address of the target (destination) hosts.
	 * @param arpRequest The ARP request initialized by the source hosts.
	 */
	private void putArpRequest(long targetIPAddress, ARPRequest arpRequest) {
		if (arpRequests.containsKey(targetIPAddress)) {
			arpRequests.get(targetIPAddress).add(arpRequest);
		} else {
			arpRequests.put(targetIPAddress, new HashSet<ARPRequest>());
			arpRequests.get(targetIPAddress).add(arpRequest);
		}
	}
	
	/**
	 * Check for old ARP request. Remove ARP requests 
	 * older than ARP_TIMEOUT from the arpRequests data 
	 * structure.
	 */
	private void removeOldArpRequests() {
		/* The current time stamp. */
		long currentTime = System.currentTimeMillis();
		
		for (long targetIPAddress : arpRequests.keySet()) {
			Set<ARPRequest> arpRequestSet = arpRequests.get(targetIPAddress);
			for (Iterator<ARPRequest> iter = arpRequestSet.iterator(); iter.hasNext();) {
				if ((currentTime - iter.next().getStartTime()) > ARP_TIMEOUT)
					iter.remove();
				if (arpRequestSet.isEmpty()) 
					arpRequests.remove(targetIPAddress);
			}
		}
	}

	@Override
	public void run() {
		if (!arpRequests.isEmpty()) {
			this.removeOldArpRequests();
		}
	}

}
