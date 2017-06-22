package com.mindoo.nginx.auth;

import java.io.IOException;
import java.net.InetAddress;
import java.net.UnknownHostException;
import java.nio.charset.Charset;
import java.util.Enumeration;
import java.util.HashMap;
import java.util.Locale;
import java.util.Map;
import java.util.Vector;
import java.util.logging.Level;

import javax.servlet.Servlet;
import javax.servlet.ServletConfig;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import lotus.domino.Database;
import lotus.domino.Document;
import lotus.domino.NotesException;
import lotus.domino.NotesFactory;
import lotus.domino.NotesThread;
import lotus.domino.Session;
import lotus.domino.View;

import com.ibm.commons.util.StringUtil;
import com.ibm.domino.osgi.core.context.ContextInfo;
import com.mindoo.nginx.auth.utils.DominoUtilsExt;
import com.mindoo.nginx.auth.utils.DominoUtilsExt.SessionHolder;
import com.mindoo.nginx.auth.utils.HttpUtils;

/**
 * Nginx auth script to check mail login credentials, implementing the
 * <a href="http://nginx.org/en/docs/mail/ngx_mail_auth_http_module.html" target="_blank">NGINX auth protocol</a>
 * 
 * @author Karsten Lehmann
 */
public class AuthServlet extends HttpServlet implements Servlet {
	private static final long serialVersionUID = 7945147664890309387L;

	private String m_authKeyHeader;
	private String m_authKeyValue;
	
	private String m_iniPublicServerIP;
	private String[] m_iniLocalDomainsLC;
	private String m_iniWaitOnError;
	private boolean m_iniDebug;
	private boolean m_servletInitFailed;

	private boolean m_enabled;
	
	private String getLocalIP() throws UnknownHostException {
		if (m_iniPublicServerIP!=null && m_iniPublicServerIP.length()>0) {
			return m_iniPublicServerIP;
		}
		return InetAddress.getLocalHost().getHostAddress();
	}
	
	@Override
	public void init(ServletConfig config) throws ServletException {
		super.init(config);
		
		//read configuration from Notes.ini
		NotesThread.sinitThread();
		Session session = null;
		try {
			session = NotesFactory.createSession();
			//REQUIRED list of domains that are considered to be local,
			//used for incoming SMTP connections delivering mails from external servers
			String localDomainsConc = session.getEnvironmentString("NGINXAUTH_LOCALDOMAINS").trim(); //e.g. mylocaldomain.de,mylocaldomain.com
			if (localDomainsConc.length()==0) {
				log(Level.SEVERE, "Ini variable $NGINXAUTH_LOCALDOMAINS must be set ");
			}
			m_iniLocalDomainsLC = localDomainsConc.length()==0 ? new String[0] : localDomainsConc.split(",");
			for (int i=0; i<m_iniLocalDomainsLC.length; i++) {
				m_iniLocalDomainsLC[i] = m_iniLocalDomainsLC[i].toLowerCase(Locale.ENGLISH).trim();
			}

			//OPTIONAL IP of this server that NGINX can use to establish SMTP connection;
			//if this value is missing, we let the JDK read the IP which might be the wrong one
			m_iniPublicServerIP = session.getEnvironmentString("NGINXAUTH_PUBLICIP"); // e.g. 1.2.3.4

			//OPTIONAL switch to write debug message in the server console (disabled by default)
			m_iniDebug = "true".equalsIgnoreCase(session.getEnvironmentString("NGINXAUTH_DEBUG"));
			//OPTIONAL switch to disable this servlet (enabled by default)
			m_enabled = !"false".equalsIgnoreCase(session.getEnvironmentString("NGINXAUTH_ENABLED"));
			
			//OPTIONAL shared auth header to let NGINX make sure the request is coming from
			//a trusted server
			m_authKeyHeader = session.getEnvironmentString("NGINXAUTH_AUTHKEY_HEADER"); // e.g. X-NGX-Auth-Key
			m_authKeyValue = session.getEnvironmentString("NGINXAUTH_AUTHKEY_VALUE"); // e.g. 81jbdvdl

			//OPTIONAL number of seconds to wait on auth errors
			m_iniWaitOnError = session.getEnvironmentString("NGINXAUTH_WAITONERROR"); // e.g. "3"
			
		} catch (NotesException e) {
			log(Level.SEVERE, "Could not read NGINX auth config values from Notes.ini", e);
			m_servletInitFailed = true;
		}
		finally {
			if (session!=null) {
				try {
					session.recycle();
				}
				catch (NotesException e) {
					//ignore
				}
			}
			NotesThread.stermThread();
		}
	}

	protected void log(Level level, String msg) {
		log(level, msg, (Throwable) null);
	}
	
	protected void log(Level level, String msg, Throwable t) {
		System.out.println("NGINXAUTH ("+level.getLocalizedName()+"): "+msg);
		if (t!=null) {
			t.printStackTrace(System.out);
		}
	}
	
	@Override
	protected void doGet(HttpServletRequest req, HttpServletResponse resp) throws ServletException, IOException {
		if (m_servletInitFailed) {
			resp.sendError(HttpServletResponse.SC_INTERNAL_SERVER_ERROR, "Servlet initialization failed. See server console for details.");
			return;
		}
		if (!m_enabled) {
			resp.sendError(HttpServletResponse.SC_FORBIDDEN, "Servlet is not enabled.");
			return;
		}
		
		//get anonymous web session
		Session webSession = ContextInfo.getUserSession();
		
		String authUserEnc = req.getHeader("Auth-User");
		String authPasswordEnc = req.getHeader("Auth-Pass");
		
		String authUser;
		String authPassword;

		String authProtocol = req.getHeader("Auth-Protocol");
		String authLoginAttempt = req.getHeader("Auth-Login-Attempt");
		String clientIP = req.getHeader("Client-IP");
		
		String smtpFrom = req.getHeader("Auth-SMTP-From"); //Mail from:<peter.miller@gmail.com>
		String smtpFromLC = smtpFrom==null ? null : smtpFrom.toLowerCase(Locale.ENGLISH);
		String smtpTo = req.getHeader("Auth-SMTP-To"); //RCPT to:<john.doe@mylocaldomain.com>
		String smtpToLC = smtpTo==null ? null : smtpTo.toLowerCase(Locale.ENGLISH);
		
		boolean debug = m_iniDebug || "true".equalsIgnoreCase(req.getHeader("X-Auth-debug"));

		if (debug) {
			//dump all fields of current request to the server console
			Map<String,String> headers = new HashMap<String,String>();
			@SuppressWarnings("unchecked")
			Enumeration<String> headerNames = req.getHeaderNames();
			while (headerNames.hasMoreElements()) {
				String currHeaderName = headerNames.nextElement();
				String currHeaderVal = req.getHeader(currHeaderName);
				if ("Auth-Pass".equals(currHeaderName)) {
					headers.put(currHeaderName, "***");
					
				}
				else {
					headers.put(currHeaderName, currHeaderVal);
				}
			}
			System.out.println("nginx auth: Request received: "+headers);
		}
		
//		GET /auth HTTP/1.0
//		Host: localhost
//		Auth-Method: plain # plain/apop/cram-md5/external
//		Auth-User: user
//		Auth-Pass: password
//		Auth-Protocol: imap # imap/pop3/smtp
//		Auth-Login-Attempt: 1
//		Client-IP: 192.0.2.42
//		Client-Host: client.example.org
		
		SessionHolder serverSessionHolder = null;
		try {
			String serverName = webSession.getServerName();
			
			//get session with server rights to be able to open address books
			serverSessionHolder = DominoUtilsExt.createSessionAsUser(serverName);
			Session serverSession = serverSessionHolder.getSession();

			boolean reportSuccess = false;
			boolean isSmtpFromInLocalDomain = false;
			boolean isSmtpToInLocalDomain = false;
			
			if (StringUtil.isEmpty(authUserEnc) && StringUtil.isEmpty(authPasswordEnc)) {
				//user and password are empty for smtp delivery from external hosts
				//(nginx option smtp_auth none)
				authUser = "";
				authPassword = "";
				
				if (smtpFromLC!=null) {
					for (String currDomain : m_iniLocalDomainsLC) {
						if (smtpFromLC.contains("@"+currDomain)) {
							isSmtpFromInLocalDomain = true;
							break;
						}
					}
				}
				if (smtpToLC!=null) {
					for (String currDomain : m_iniLocalDomainsLC) {
						if (smtpToLC.contains("@"+currDomain)) {
							isSmtpToInLocalDomain = true;
							break;
						}
					}
				}
				
				if (isSmtpToInLocalDomain) {
					//only allow anonymous connections when delivering email from outside to our own users,
					//not to others
					reportSuccess = true;
				}
			}
			else {
				authUser = authUserEnc==null ? "" : HttpUtils.urlDecode(authUserEnc, Charset.forName("UTF-8"), false);
				authPassword = authPasswordEnc==null ? "" : HttpUtils.urlDecode(authPasswordEnc, Charset.forName("UTF-8"), false);
				
				@SuppressWarnings("unchecked")
				Vector<Database> addressBooks = serverSession.getAddressBooks();

				Document docPerson = null;
				
				for (Database currNABDb : addressBooks) {
					if (!currNABDb.isOpen()) {
						currNABDb.open();
					}
					View viewUsers = currNABDb.getView("($Users)");
					docPerson = viewUsers.getDocumentByKey(authUser, false);
					if (docPerson!=null)
						break;
				}
				
				
				if (docPerson!=null) {
					String hashedPW = docPerson.getItemValueString("HTTPPassword");
					if (serverSession.verifyPassword(authPassword, hashedPW)) {
						//success
						reportSuccess = true;
					}
				}
				else {
					if (debug)
						System.out.println("nginx auth: User "+authUser+" not found in directory, client ip: "+clientIP+", attempt: "+authLoginAttempt);
				}
			}
			
			resp.setStatus(HttpServletResponse.SC_OK);
			resp.setContentType("text/html");
			resp.setContentLength(0);
			
			if (reportSuccess) {
//				HTTP/1.0 200 OK
//				Auth-Status: OK
//				Auth-Server: 198.51.100.1
//				Auth-Port: 143
				if (debug) {
					System.out.println("Reporting success");
				}
				
				resp.setHeader("Auth-User", authUser);
				resp.setHeader("Auth-Pass", authPassword);
				resp.setHeader("Auth-Status", "OK");
				
				//we must return an IP address here to not get error
				//4143 auth http server 1.2.3.4:80 sent invalid server address:"mail.domain.de" while in http auth state
				String localIP = getLocalIP();
				if (StringUtil.isNotEmpty(localIP)) {
					resp.setHeader("Auth-Server", localIP);
				}
				
				if ("pop3".equals(authProtocol)) {
					resp.setHeader("Auth-Port", "110");
				}
				else if ("imap".equals(authProtocol)) {
					resp.setHeader("Auth-Port", "143");
				}
				else if ("smtp".equals(authProtocol)) {
					resp.setHeader("Auth-Port", "25");
				}

				//send shared secret to ensure that the request comes from this script
				if (StringUtil.isNotEmpty(m_authKeyHeader) && StringUtil.isNotEmpty(m_authKeyValue)) {
					resp.setHeader(m_authKeyHeader, m_authKeyValue);
				}
			}
			else {
//				HTTP/1.0 200 OK
//				Auth-Status: Invalid login or password
//				Auth-Wait: 3
				if (StringUtil.isNotEmpty(authUser)) {
					//user provided wrong credentials
					if (debug)
						System.out.println("nginx auth: Password mismatch for user "+authUser+", client ip: "+clientIP+", attempt: "+authLoginAttempt);
					
					resp.setHeader("Auth-Status", "Invalid login or password");
				}
				else {
					//user tried anonymous access and tried to send mail to external hosts
					if (isSmtpFromInLocalDomain) {
						//from contained a local user
						if (debug)
							System.out.println("nginx auth: sending info that authentication is required for sending mail to external hosts, "+smtpFrom+" => "+smtpTo+", client ip: "+clientIP+", attempt: "+authLoginAttempt);
						
						resp.setHeader("Auth-Status", "This mail server requires authentication before sending mail from a locally hosted domain. Please reconfigure your mail client to authenticate before sending mail.");
						resp.setHeader("Auth-Error-Code", "551");
					}
					else {
						//from contained an external user
						if (debug)
							System.out.println("nginx auth: Relaying forbidden, "+smtpFrom+" => "+smtpTo+", client ip: "+clientIP+", attempt: "+authLoginAttempt);
						
						resp.setHeader("Auth-Status", "Relaying denied");
						resp.setHeader("Auth-Error-Code", "550");
					}
				}
				if (StringUtil.isNotEmpty(m_iniWaitOnError))
					resp.setHeader("Auth-Wait", m_iniWaitOnError);
			}
		}
		catch (Exception e) {
			log(Level.SEVERE, "Error checking incoming SMTP connection credentials from "+smtpFrom+" to "+smtpTo+" via "+clientIP, e);
		}
		finally {
			if (serverSessionHolder!=null) {
				try {
					serverSessionHolder.recycle();
				} catch (NotesException e) {
					log(Level.SEVERE, "Error recycling session", e);
				}
			}
		}
	}
	
}
