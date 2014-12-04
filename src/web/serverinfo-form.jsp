<%@ page
   import="org.jivesoftware.openfire.XMPPServer,
           org.mos.openfire.plugin.ServerInfoPlugin,
           org.jivesoftware.util.ParamUtils,
           java.util.*,
           java.util.regex.*,
	   java.net.*"
   errorPage="error.jsp"%>

<%@ taglib uri="http://java.sun.com/jstl/core_rt" prefix="c"%>
<%@ taglib uri="http://java.sun.com/jstl/fmt_rt" prefix="fmt"%>

<%
	boolean save = request.getParameter("save") != null;	
	String serverInfoPort = ParamUtils.getParameter(request, "serverInfoPort");
	String serverInfoIP = ParamUtils.getParameter(request, "serverInfoIP");

	String ipv4Pattern = "(([01]?\\d\\d?|2[0-4]\\d|25[0-5])\\.){3}([01]?\\d\\d?|2[0-4]\\d|25[0-5])";

    
	ServerInfoPlugin plugin = (ServerInfoPlugin) XMPPServer.getInstance().getPluginManager().getPlugin("serverinfo");

	Map<String, String> errors = new HashMap<String, String>();	

	if (save) {
	  if (serverInfoPort == null || serverInfoPort.equals("0")) {

	     serverInfoPort="4455";
	  }
	  else {
	  	try {
			
			int nPort=Integer.parseInt(serverInfoPort);
		}
		catch (Exception e) {

			serverInfoPort="4455";
		}
	  }
       
	  if (serverInfoIP == null || serverInfoIP.trim().length() < 1) {
	     serverInfoIP="127.0.0.1";
	  }

	  String validIPs = "Valid IPs: ";
	  Boolean ipFound = false;

	  Enumeration e = NetworkInterface.getNetworkInterfaces();
  	  while(e.hasMoreElements()) {

		NetworkInterface n = (NetworkInterface) e.nextElement();
		Enumeration ee = n.getInetAddresses();
		while (ee.hasMoreElements()) {

			InetAddress i = (InetAddress) ee.nextElement();

			Pattern VALID_IPV4_PATTERN=Pattern.compile(ipv4Pattern, Pattern.CASE_INSENSITIVE);
			Matcher ipv4=VALID_IPV4_PATTERN.matcher(i.getHostAddress());

			if (ipv4.matches()) {

				String localIP=i.getHostAddress();
				validIPs+=localIP+" ";

				if (localIP.equals(serverInfoIP)) {

					ipFound=true;
				}
			}
		}
	  }

	  request.setAttribute("VALIDIPS", validIPs); 

	  if (!ipFound) {

	  	if (!serverInfoIP.equals("0.0.0.0")) {

			errors.put("invalidIP", "invalidIP");
		}
	  }

	  if (errors.size() == 0) {
	     plugin.setPort(serverInfoPort);
	     plugin.setIP(serverInfoIP);
           
	     response.sendRedirect("serverinfo-form.jsp?settingsSaved=true");
	     return;
	  }		
	}
    
	serverInfoPort = plugin.getPort();
	serverInfoIP = plugin.getIP();
%>

<html>
	<head>
	  <title><fmt:message key="serverinfo.title" /></title>
	  <meta name="pageID" content="serverinfo-form"/>
	</head>
	<body>

<form action="serverinfo-form.jsp?save" method="post">

<div class="jive-contentBoxHeader"><fmt:message key="serverinfo.options" /></div>
<div class="jive-contentBox">
   
	<% if (ParamUtils.getBooleanParameter(request, "settingsSaved")) { %>
   
	<div class="jive-success">
	<table cellpadding="0" cellspacing="0" border="0">
	<tbody>
	  <tr>
	     <td class="jive-icon"><img src="images/success-16x16.gif" width="16" height="16" border="0"></td>
	     <td class="jive-icon-label"><fmt:message key="serverinfo.saved.success" /></td>
	  </tr>
	</tbody>
	</table>
	</div>
   
	<% } %>
   
   <br><br>
	<p><fmt:message key="serverinfo.directions" /></p>
   
	<table cellpadding="3" cellspacing="0" border="0" width="100%">
	<tbody>
	  <tr>
	     <td width="5%" valign="top"><fmt:message key="serverinfo.port" />:&nbsp;</td>
	     <td width="95%"><input type="text" name="serverInfoPort" value="<%= serverInfoPort %>"></td>
	  </tr>
	  <tr>
	     <td width="5%" valign="top"><fmt:message key="serverinfo.IP" />:&nbsp;</td>
	     <td width="95%"><input type="text" name="serverInfoIP" value="<%= serverInfoIP %>"></td>
             <% if (errors.containsKey("invalidIP")) { %>
                <span class="jive-error-text"><fmt:message key="serverinfo.message.ipinvalid" /><br>
                <%= request.getAttribute("VALIDIPS") %></span>
             <% } %>

	  </tr>
	</tbody>
	</table>
</div>
<input type="submit" value="<fmt:message key="serverinfo.button.save" />"/>
</form>

</body>
</html>
