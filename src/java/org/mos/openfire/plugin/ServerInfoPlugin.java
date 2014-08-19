/**
 * $RCSfile: ServerInfo.java,v $
 * $Revision: 1 $
 * $Date: 2014-08-07 21:20:00 -0300 (Thu, 07 Aug 2014) $
 *
 * Copyright (C) 2014 Marcelo Hartmann Terres. All rights reserved.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package org.mos.openfire.plugin;

import java.net.*;
import java.io.*;
import java.text.DecimalFormat;
import java.util.ArrayList;
import java.util.Collection;
import java.util.Collections;
import java.util.List;
import java.util.Map;
import java.util.StringTokenizer;

import org.dom4j.Element;
import org.jivesoftware.openfire.SessionManager;
import org.jivesoftware.openfire.XMPPServer;
import org.jivesoftware.openfire.container.Plugin;
import org.jivesoftware.openfire.container.PluginManager;
import org.jivesoftware.openfire.user.User;
import org.jivesoftware.openfire.user.UserManager;
import org.jivesoftware.util.JiveGlobals;
import org.jivesoftware.util.PropertyEventDispatcher;
import org.jivesoftware.util.PropertyEventListener;
import org.jivesoftware.util.Log;
import org.slf4j.LoggerFactory;
import org.xmpp.component.Component;
import org.xmpp.component.ComponentException;
import org.xmpp.component.ComponentManager;
import org.xmpp.component.ComponentManagerFactory;
import org.xmpp.packet.IQ;
import org.xmpp.packet.JID;
import org.xmpp.packet.Message;
import org.xmpp.packet.Packet;
import org.xmpp.packet.PacketError;
import org.xmpp.packet.Presence;

/**
 * ServerInfo service plugin. It accepts messages and return the requested
 * information. The address <tt>info@[serviceName].[server]</tt> is
 * reserved for receiving the requests.
 *
 * @author Marcelo Hartmann Terres
 */
public class ServerInfoPlugin implements Plugin, Component, PropertyEventListener {

	//private static final Logger Log = LoggerFactory.getLogger(ServerInfoPlugin.class);

    private String serviceName;
    private SessionManager sessionManager;
    private ComponentManager componentManager;
    private PluginManager pluginManager;
    private UserManager userManager;
    private Socket          socket   = null;
    private ServerSocket    server   = null;
    private DataInputStream streamIn =  null;
    private OFD_Server ofd_srv = new OFD_Server();
    public static Thread ofThread;
    public static Boolean NotExit = true;

    /**
     * Constructs a new serverinfo plugin.
     */
    public ServerInfoPlugin() {
        serviceName = JiveGlobals.getProperty("plugin.serverinfo.serviceName", "serverinfo");
    }

    // Plugin Interface

    public void initializePlugin(PluginManager manager, File pluginDirectory)
    {

	Log.info("ServerInfo - Starting plugin.");

        pluginManager = manager;
        sessionManager = SessionManager.getInstance();

        userManager = UserManager.getInstance();

        // Register as a component.
        componentManager = ComponentManagerFactory.getComponentManager();
        try {
            componentManager.addComponent(serviceName, this);
        }
        catch (Exception e) {
            Log.error(e.getMessage(), e);
        }
        PropertyEventDispatcher.addListener(this);

	Log.info("ServerInfo - Starting bind on port 4455.");
	ofd_srv.startServer();
    }

    public void destroyPlugin() {

	Log.info("ServerInfo - Closing plugin.");

        PropertyEventDispatcher.removeListener(this);
        // Unregister component.
        if (componentManager != null) {
            try {
                componentManager.removeComponent(serviceName);
            }
            catch (Exception e) {
                Log.error(e.getMessage(), e);
            }
        }
        serviceName = JiveGlobals.getProperty("plugin.serverinfo.serviceName", "");
        componentManager = null;
        userManager = null;
        pluginManager = null;
        sessionManager = null;

	Log.info("ServerInfo - Closing thread.");
	clientConnect();
	ServerInfoPlugin.NotExit=false;
	ServerInfoPlugin.ofThread.stop();
	Log.info("ServerInfo - Thread closed.");
    }

    public void initialize(JID jid, ComponentManager componentManager) {
    }

    public void start() {
    }

    public void shutdown() {
 	Log.info("ServerInfo - Shutdown thread.");
	clientConnect();
	ServerInfoPlugin.NotExit=false;
	ServerInfoPlugin.ofThread.stop();
	Log.info("ServerInfo - Thread closed.");
    }

    public void clientConnect() {

	try
	{
		Log.info("ServerInfo - Making local connection.");
	        Socket clientSocket = new Socket("localhost", 4455);
        	DataOutputStream outToServer = new DataOutputStream(clientSocket.getOutputStream());

	        outToServer.writeBytes(".\n");
        	clientSocket.close();
	}
	catch (UnknownHostException e) 
	{
                Log.error(e.getMessage(), e);
	}
        catch (IOException e) 
	{

                Log.error(e.getMessage(), e);
	}
    }

    // Component Interface

    public String getName() {
        // Get the name from the plugin.xml file.
        return pluginManager.getName(this);
    }

    public String getDescription() {
        // Get the description from the plugin.xml file.
        return pluginManager.getDescription(this);
    }

    public void processPacket(Packet packet) {
        boolean canProceed = false;
        String toNode = packet.getTo().getNode();
        boolean targetSrv = "info".equals(toNode);
        if (targetSrv) {
            JID address = new JID(packet.getFrom().toBareJID());
            canProceed = true;
        }
        if (packet instanceof Message) {
            // Respond to incoming messages
            Message message = (Message)packet;
            processMessage(message, targetSrv, canProceed);
        }
        else if (packet instanceof Presence) {
            // Respond to presence subscription request or presence probe
            Presence presence = (Presence) packet;
            processPresence(canProceed, presence);
        }
        else if (packet instanceof IQ) {
            // Handle disco packets
            IQ iq = (IQ) packet;
            // Ignore IQs of type ERROR or RESULT
            if (IQ.Type.error == iq.getType() || IQ.Type.result == iq.getType()) {
                return;
            }
            processIQ(iq, targetSrv, canProceed);
        }
    }


    private void processMessage(Message message, boolean targetSrv,boolean canProceed) 
    {

        if (targetSrv) 
	{

   	    String body = message.getBody();

            MyMessage MyMsg = new MyMessage();
	    String text = MyMsg.returnMessage(body);

	    String xmppdomain = "@" + JiveGlobals.getProperty("xmpp.domain");
	    String to = message.getFrom().toBareJID();
	    
	    Message newMessage = new Message();
	    newMessage.setTo(to);
	    newMessage.setFrom("info@serverinfo."+JiveGlobals.getProperty("xmpp.domain"));
	    newMessage.setSubject("Resultado");
	    newMessage.setBody(text);

	    try 
	    {
		componentManager.sendPacket(this, newMessage);
            } catch (Exception e) 
	    {
		Log.error(e.getMessage(), e);
	    }
        }
    }

    private void processPresence(boolean canProceed, Presence presence) {
        try {
            if (Presence.Type.subscribe == presence.getType()) {
                // Accept all presence requests if user has permissions
                // Reply that the subscription request was approved or rejected
                Presence reply = new Presence();
                reply.setTo(presence.getFrom());
                reply.setFrom(presence.getTo());
                reply.setType(canProceed ? Presence.Type.subscribed : Presence.Type.unsubscribed);
                componentManager.sendPacket(this, reply);
            }
            else if (Presence.Type.unsubscribe == presence.getType()) {
                // Send confirmation of unsubscription
                Presence reply = new Presence();
                reply.setTo(presence.getFrom());
                reply.setFrom(presence.getTo());
                reply.setType(Presence.Type.unsubscribed);
                componentManager.sendPacket(this, reply);
            }
            else if (Presence.Type.probe == presence.getType()) {
                // Send that the service is available
                Presence reply = new Presence();
                reply.setTo(presence.getFrom());
                reply.setFrom(presence.getTo());
                componentManager.sendPacket(this, reply);
            }
        }
        catch (ComponentException e) {
            Log.error(e.getMessage(), e);
        }
    }

    private void processIQ(IQ iq, boolean targetSrv,boolean canProceed) {
        IQ reply = IQ.createResultIQ(iq);
        Element childElement = iq.getChildElement();
        String namespace = childElement.getNamespaceURI();
        Element childElementCopy = iq.getChildElement().createCopy();
        reply.setChildElement(childElementCopy);
        if ("http://jabber.org/protocol/disco#info".equals(namespace)) {
            if (iq.getTo().getNode() == null) {
                // Return service identity and features
                Element identity = childElementCopy.addElement("identity");
                identity.addAttribute("category", "component");
                identity.addAttribute("type", "generic");
                identity.addAttribute("name", "ServerInfo service");
                childElementCopy.addElement("feature")
                        .addAttribute("var", "http://jabber.org/protocol/disco#info");
                childElementCopy.addElement("feature")
                        .addAttribute("var", "http://jabber.org/protocol/disco#items");
            }
            else {
                if (targetSrv) {
                    // Return identity and features of the "all" group
                    Element identity = childElementCopy.addElement("identity");
                    identity.addAttribute("category", "component");
                    identity.addAttribute("type", "generic");
                    identity.addAttribute("name", "Display requested server information");
                    childElementCopy.addElement("feature")
                            .addAttribute("var", "http://jabber.org/protocol/disco#info");
                }
            }
        }
        try {
            componentManager.sendPacket(this, reply);
        }
        catch (Exception e) {
            Log.error(e.getMessage(), e);
        }
    }

    // Other Methods

    /**
     * Returns the service name of this component, which is "serverinfo" by default.
     *
     * @return the service name of this component.
     */
    public String getServiceName() {
        return serviceName;
    }

    /**
     * Sets the service name of this component, which is "serverinfo" by default.
     *
     * @param serviceName the service name of this component.
     */
    public void setServiceName(String serviceName) {
        JiveGlobals.setProperty("plugin.serverinfo.serviceName", serviceName);
    }

    // PropertyEventListener Methods

    public void propertySet(String property, Map<String, Object> params) {
        if (property.equals("plugin.serverinfo.serviceName")) {
            changeServiceName((String)params.get("value"));
        }
    }

    public void propertyDeleted(String property, Map<String, Object> params) {
        if (property.equals("plugin.serverinfo.serviceName")) {
            changeServiceName("serverinfo");
        }
    }

    public void xmlPropertySet(String property, Map<String, Object> params) {
        // Ignore.
    }

    public void xmlPropertyDeleted(String property, Map<String, Object> params) {
        // Ignore.
    }

    /**
     * Changes the service name to a new value.
     *
     * @param serviceName the service name.
     */
    private void changeServiceName(String serviceName) {
         if (serviceName == null) {
            throw new NullPointerException("Service name cannot be null");
        }
        if (this.serviceName.equals(serviceName)) {
            return;
        }

        // Re-register the service.
        try {
            componentManager.removeComponent(this.serviceName);
        }
        catch (Exception e) {
            Log.error(e.getMessage(), e);
        }
        try {
            componentManager.addComponent(serviceName, this);
        }
        catch (Exception e) {
            Log.error(e.getMessage(), e);
        }
        this.serviceName = serviceName;
    }
}

class OFD_Server {

    public static void main(String[] args) {
    	Log.info("ServerInfo - Running startServer.");
        new OFD_Server().startServer();
    }

    public void startServer() {

        Runnable serverTask = new Runnable() {
            @Override
            public void run() {
                try {
		    Log.info("ServerInfo - Opening socket in port 4455.");
                    ServerSocket serverSocket = new ServerSocket(4455);
                    Log.info("ServerInfo - Waiting for connection.");
                    while (ServerInfoPlugin.NotExit) {
                        Socket clientSocket = serverSocket.accept();
      			String input="";
			String line;

      			try {
			        // Get input from the client
			        DataInputStream in = new DataInputStream (clientSocket.getInputStream());
			        PrintStream out = new PrintStream(clientSocket.getOutputStream());

				input = "";

			        while((line = in.readLine()) != null && !line.equals(".")) {
					input=input + line;
					MyMessage MyMsg = new MyMessage();
				    	String text = MyMsg.returnMessage(input);
	  
					out.println(text);
					input = "";

					if (!ServerInfoPlugin.NotExit) {
						Log.info("ServerInfo - Receive signal to close thread.");
						break;
					}
			        }


			        clientSocket.close();		
			      } catch (IOException ioe) {
			        Log.error("ServerInfo - IOException on socket listen: " + ioe);
			        ioe.printStackTrace();
			      }
 
                    }


		    Log.info("ServerInfo - Thread closing.");
                } catch (IOException e) {
                    Log.error("ServerInfo - Unable to process client request");
                    e.printStackTrace();
                }
            }
        };
        ServerInfoPlugin.ofThread = new Thread(serverTask);
        ServerInfoPlugin.ofThread.start();
	Log.info("ServerInfo - Thread Created.");

    }

}


class MyMessage {

  private String msg =  "";
  private int msgTot = 0;

  private UserManager userManager = UserManager.getInstance();
  private SessionManager sessionManager = SessionManager.getInstance();
  private XMPPServer xmppServer = XMPPServer.getInstance();
  private DecimalFormat mbFormat = new DecimalFormat("#0.00");
  private DecimalFormat mbIntFormat = new DecimalFormat("#0");
 
  public String returnMessage(String message) {
	
  	msg =  "Invalid command: " + message + ". Try again.";

	Log.debug("ServerInfo - Command: " + message + ".");

	if ( message.equals("online users") ) {

       		msg = "";
		msgTot = sessionManager.getUserSessionsCount(true);
	}

	else if ( message.equals("server sessions") ) {

		msg= "";
		msgTot = sessionManager.getIncomingServerSessionsCount(true);

	}

	else if ( message.equals("total users") ) {

		msg= "";
		msgTot = 0;

		Collection<User> users = userManager.getUsers();

      		for (User u : users) {
			msgTot = msgTot + 1;
		}

	}

	else if ( message.equals("version") ) {

		msg="ServerInfo version 0.3.2";
	}

	else if ( message.equals("openfire version") ) {

		msg="Openfire version: " + xmppServer.getServerInfo().getVersion().getVersionString();
	}

	else if ( message.equals("openfire host") ) {

		msg="Openfire hostname: " + xmppServer.getServerInfo().getHostname();
	}

	else if ( message.equals("openfire uptime") ) {

		msg="Openfire last started: " + xmppServer.getServerInfo().getLastStarted();
	}

	else if ( message.equals("java version") ) {
		
		msg = "Java " + System.getProperty("java.version") + " " +System.getProperty("java.vendor") + " " + System.getProperty("java.vm.name");
	}

	else if ( message.equals("total memory") ) {

		msg = "Total available memory to the JVM: " + mbFormat.format((((Runtime.getRuntime().totalMemory())/1024)/1024)) + "MB";
	}

	else if ( message.equals("total memory num") ) {

		msg = mbIntFormat.format((((Runtime.getRuntime().totalMemory())/1024)/1024));
	}

	else if ( message.equals("free memory") ) {

		msg = "Total free available memory to the JVM: " + mbFormat.format((((Runtime.getRuntime().freeMemory())/1024)/1024)) + "MB";
	}

	else if ( message.equals("free memory num") ) {

		msg = mbIntFormat.format((((Runtime.getRuntime().freeMemory())/1024)/1024));
	}

	else if ( message.equals("used memory") ) {

		msg = "Total used memory by the JVM: " + mbFormat.format(((((Runtime.getRuntime().totalMemory() - Runtime.getRuntime().freeMemory()))/1024)/1024)) + "MB";
	}

	else if ( message.equals("used memory num") ) {

		msg = mbIntFormat.format(((((Runtime.getRuntime().totalMemory() - Runtime.getRuntime().freeMemory()))/1024)/1024));
	}

        else if ( message.equals("max memory") ) {

	msg = "Total maximum available memory to the JVM: " + mbFormat.format((((Runtime.getRuntime().maxMemory())/1024)/1024)) + "MB";
	}

        else if ( message.equals("max memory num") ) {

	msg = mbIntFormat.format((((Runtime.getRuntime().maxMemory())/1024)/1024));
	}

	if ( msg.equals("") ) {

		return Integer.toString(msgTot);
	}
	else {

		return msg;
	}
  }
}


