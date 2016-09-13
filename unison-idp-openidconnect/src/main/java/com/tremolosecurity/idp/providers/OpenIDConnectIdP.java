/*******************************************************************************
 * Copyright 2015, 2016 Tremolo Security, Inc.
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *     http://www.apache.org/licenses/LICENSE-2.0
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 *******************************************************************************/
package com.tremolosecurity.idp.providers;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.net.MalformedURLException;
import java.net.URISyntaxException;
import java.net.URL;
import java.net.URLEncoder;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.StringTokenizer;
import java.util.UUID;
import java.util.zip.Deflater;
import java.util.zip.DeflaterOutputStream;
import java.util.zip.GZIPOutputStream;
import java.util.zip.Inflater;
import java.util.zip.InflaterInputStream;
import java.util.zip.ZipOutputStream;

import javax.crypto.SecretKey;
import javax.servlet.ServletContext;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import javax.servlet.http.HttpSession;

import org.apache.log4j.Logger;
import org.apache.xml.security.utils.Base64;
import org.joda.time.DateTime;
import org.jose4j.jwk.JsonWebKey;
import org.jose4j.jwk.JsonWebKeySet;
import org.jose4j.jws.AlgorithmIdentifiers;
import org.jose4j.jws.JsonWebSignature;
import org.jose4j.jwt.JwtClaims;
import org.jose4j.lang.JoseException;

import com.google.gson.Gson;
import com.google.gson.GsonBuilder;
import com.novell.ldap.LDAPEntry;
import com.novell.ldap.LDAPException;
import com.novell.ldap.LDAPSearchResults;
import com.tremolosecurity.config.util.ConfigManager;
import com.tremolosecurity.config.util.UrlHolder;
import com.tremolosecurity.config.xml.AuthChainType;
import com.tremolosecurity.idp.providers.oidc.model.OpenIDConnectConfig;
import com.tremolosecurity.idp.server.IDP;
import com.tremolosecurity.idp.server.IdentityProvider;
import com.tremolosecurity.provisioning.core.ProvisioningException;
import com.tremolosecurity.provisioning.core.User;
import com.tremolosecurity.provisioning.mapping.MapIdentity;
import com.tremolosecurity.proxy.auth.AuthController;
import com.tremolosecurity.proxy.auth.AuthInfo;
import com.tremolosecurity.proxy.auth.AzSys;
import com.tremolosecurity.proxy.auth.RequestHolder;
import com.tremolosecurity.proxy.filter.HttpFilterChain;
import com.tremolosecurity.proxy.filter.HttpFilterChainImpl;
import com.tremolosecurity.proxy.filter.HttpFilterRequest;
import com.tremolosecurity.proxy.filter.HttpFilterRequestImpl;
import com.tremolosecurity.proxy.filter.HttpFilterResponse;
import com.tremolosecurity.proxy.filter.HttpFilterResponseImpl;
import com.tremolosecurity.proxy.filter.PostProcess;
import com.tremolosecurity.proxy.util.NextSys;
import com.tremolosecurity.proxy.util.ProxyConstants;
import com.tremolosecurity.saml.Attribute;
import com.tremolosecurity.server.GlobalEntries;

public class OpenIDConnectIdP implements IdentityProvider {

	static Logger logger = Logger.getLogger(OpenIDConnectIdP.class.getName());
	
	private static final String TRANSACTION_DATA = "unison.openidconnect.session";
	String idpName;
	HashMap<String,OpenIDConnectTrust> trusts;
	String jwtSigningKeyName;

	
	
	private MapIdentity mapper;
	
	public void doDelete(HttpServletRequest request, HttpServletResponse response) throws IOException, ServletException {


	}

	public void doGet(HttpServletRequest request, HttpServletResponse response) throws IOException, ServletException {
		String action = (String) request.getAttribute(IDP.ACTION_NAME);
		
		if (action.equalsIgnoreCase(".well-known/openid-configuration")) {
			
			Gson gson = new GsonBuilder().setPrettyPrinting().create();
			String json = gson.toJson(new OpenIDConnectConfig(this.idpName,request,mapper));
			response.setContentType("application/json");
			response.getWriter().print(json);
			return;
		
		} else if (action.equalsIgnoreCase("certs")) {
			try {
				X509Certificate cert = GlobalEntries.getGlobalEntries().getConfigManager().getCertificate(this.jwtSigningKeyName);
				JsonWebKey jwk = JsonWebKey.Factory.newJwk(cert.getPublicKey());
				
				
				StringBuffer b = new StringBuffer();
				b.append(cert.getSubjectDN().getName()).append('-').append(cert.getIssuerDN().getName()).append('-').append(cert.getSerialNumber().toString());
				jwk.setKeyId(b.toString());
				jwk.setUse("sig");
				jwk.setAlgorithm("RS256");
				response.setContentType("application/json");
				response.getWriter().print(new JsonWebKeySet(jwk).toJson());
				return;
			} catch (JoseException e) {
				throw new ServletException("Could not generate jwt",e);
			}
		} else if (action.equalsIgnoreCase("auth")) {
			String clientID = request.getParameter("client_id");
			String responseCode = request.getParameter("response_type");
			String scope = request.getParameter("scope");
			String redirectURI = request.getParameter("redirect_uri");
			String state = request.getParameter("state");
			String nonce = request.getParameter("nonce");
			
			OpenIDConnectTransaction transaction = new OpenIDConnectTransaction();
			transaction.setClientID(clientID);
			transaction.setResponseCode(responseCode);
			transaction.setNonce(nonce);
			
			StringTokenizer toker = new StringTokenizer(scope," ",false);
			while (toker.hasMoreTokens()) {
				String token = toker.nextToken();
				transaction.getScope().add(token);
			}
			
			
			
			transaction.setRedirectURI(redirectURI);
			transaction.setState(state);
			
			OpenIDConnectTrust trust = trusts.get(clientID);
			
			if (trust == null) {
				StringBuffer b = new StringBuffer();
				b.append(redirectURI).append("?error=unauthorized_client");
				logger.warn("Trust '" + clientID + "' not found");
				response.sendRedirect(b.toString());
				return;
			}
			
			if (! trust.getRedirectURI().equals(redirectURI)) {
				StringBuffer b = new StringBuffer();
				b.append(trust.getRedirectURI()).append("?error=unauthorized_client");
				logger.warn("Invalid redirect");
				response.sendRedirect(b.toString());
				return;
			}
			
			if (transaction.getScope().size() == 0 || ! transaction.getScope().get(0).equals("openid")) {
				StringBuffer b = new StringBuffer();
				b.append(trust.getRedirectURI()).append("?error=invalid_scope");
				logger.warn("First scope not openid");
				response.sendRedirect(b.toString());
				return;
			} else {
				//we don't need the openid scope anymore
				transaction.getScope().remove(0);
			}
			
			String authChain = trust.getAuthChain();
			
			if (authChain == null) {
				StringBuffer b = new StringBuffer();
				b.append("IdP does not have an authenticaiton chain configured");
				throw new ServletException(b.toString());
			}
			
			HttpSession session = request.getSession();
			
			AuthInfo authData = ((AuthController) session.getAttribute(ProxyConstants.AUTH_CTL)).getAuthInfo();
			UrlHolder holder = (UrlHolder) request.getAttribute(ProxyConstants.AUTOIDM_CFG);
			
			AuthChainType act = holder.getConfig().getAuthChains().get(authChain);
			
			session.setAttribute(OpenIDConnectIdP.TRANSACTION_DATA, transaction);
			
			if (authData == null || ! authData.isAuthComplete() && ! (authData.getAuthLevel() < act.getLevel()) ) {
				nextAuth(request,response,session,false,act);
			} else {
				if (authData.getAuthLevel() < act.getLevel()) {
					//step up authentication, clear existing auth data

					
					session.removeAttribute(ProxyConstants.AUTH_CTL);
					holder.getConfig().createAnonUser(session);
					
					nextAuth(request,response,session,false,act);
				} else {
					
					StringBuffer b = genFinalURL(request);
					response.sendRedirect(b.toString());
					
				}
			}
			
			
		} else if (action.contentEquals("completeFed")) {
			this.completeFederation(request, response);
		}
		

	}
	
	private boolean nextAuth(HttpServletRequest req,HttpServletResponse resp,HttpSession session,boolean jsRedirect,AuthChainType act) throws ServletException, IOException {
		
		RequestHolder reqHolder;
		
		UrlHolder holder = (UrlHolder) req.getAttribute(ProxyConstants.AUTOIDM_CFG);
		String urlChain = holder.getUrl().getAuthChain();
		
		
		StringBuffer b = genFinalURL(req);
		
		
		return holder.getConfig().getAuthManager().execAuth(req, resp, session, jsRedirect, holder, act,b.toString());
	}
	
	private StringBuffer genFinalURL(HttpServletRequest req) {
		if (logger.isDebugEnabled()) {
			logger.debug("url : '" + req.getRequestURL() + "'");
		}
		
		ConfigManager cfg = (ConfigManager) req.getAttribute(ProxyConstants.TREMOLO_CFG_OBJ);
		
		String url = req.getRequestURL().substring(0,req.getRequestURL().indexOf("/",8));
		StringBuffer b = new StringBuffer(url);
		b.append(cfg.getAuthIdPPath()).append(this.idpName).append("/completeFed");
		
		if (logger.isDebugEnabled()) {
			logger.debug("final url : '" + b + "'");
		}
		return b;
	}

	public void doHead(HttpServletRequest request, HttpServletResponse response) throws IOException, ServletException {


	}

	public void doOptions(HttpServletRequest request, HttpServletResponse response) throws IOException, ServletException {


	}

	public void doPost(HttpServletRequest request, HttpServletResponse response) throws IOException, ServletException {
		String action = (String) request.getAttribute(IDP.ACTION_NAME);
		if (action.contentEquals("completeFed")) {
			this.completeFederation(request, response);
		} else if (action.equalsIgnoreCase("token")) {
			String code = request.getParameter("code");
			String clientID = request.getParameter("client_id");
			String clientSecret = request.getParameter("client_secret");
			String redirectURI = request.getParameter("redirect_uri");
			String grantType = request.getParameter("grant_type");
			
			
			String lastMileToken = null;
			
			try {
				lastMileToken = this.inflate(code);
				lastMileToken = Base64.encode(lastMileToken.getBytes("UTF-8"));
			} catch (Exception e) {
				throw new ServletException("Could not inflate code",e);
			}
			
			OpenIDConnectTrust trust = this.trusts.get(clientID);
			
			if (! clientSecret.equals(trust.getClientSecret())) {
				response.sendError(403);
				return;
			}
			
			ConfigManager cfg = (ConfigManager) request.getAttribute(ProxyConstants.TREMOLO_CFG_OBJ);
			
			SecretKey codeKey = cfg.getSecretKey(trust.getCodeLastmileKeyName());
			com.tremolosecurity.lastmile.LastMile lmreq = new com.tremolosecurity.lastmile.LastMile();
			try {
				lmreq.loadLastMielToken(lastMileToken, codeKey);
			} catch (Exception e) {
				logger.warn("Could not decrypt code token",e);
				response.sendError(403);
				return;
			}
			
			if (! lmreq.isValid()) {
				
				response.sendError(403);
				logger.warn("Could not validate code token");
				return;
			}
			
			Attribute dn = null;
			Attribute scopes = null;
			String nonce = null;
			
			for (Attribute attr : lmreq.getAttributes()) {
				if (attr.getName().equalsIgnoreCase("dn")) {
					dn = attr;
				} else if (attr.getName().equalsIgnoreCase("scope")) {
					scopes = attr;
				} else if (attr.getName().equalsIgnoreCase("nonce")) {
					nonce = attr.getValues().get(0);
				}
			}
			
			
			ConfigManager cfgMgr = (ConfigManager) request.getAttribute(ProxyConstants.TREMOLO_CFG_OBJ);
			
			DateTime now = new DateTime();
			DateTime notBefore = now.minus(trust.getCodeTokenTimeToLive());
			DateTime notAfter = now.plus(trust.getCodeTokenTimeToLive());
			
			int authLevel = lmreq.getLoginLevel();
			String authMethod = lmreq.getAuthChain();
			
			try {
				lmreq = new com.tremolosecurity.lastmile.LastMile(request.getRequestURI(),notBefore,notAfter,authLevel,authMethod);
			} catch (URISyntaxException e) {
				throw new ServletException("Could not request access token",e);
			}
			
			
			/*
			lmreq.getAttributes().add(new Attribute("dn",dn.getValues().get(0)));
			SecretKey key = cfgMgr.getSecretKey(trust.getAccessLastmileKeyName());
			String accessToken = null;
			try {
				accessToken = lmreq.generateLastMileToken(key);
			} catch (Exception e) {
				throw new ServletException("Could not generate access token",e);
			}*/
			
			String accessToken = null;
			try {
				accessToken = this.produceJWT(dn.getValues().get(0), scopes.getValues(), cfgMgr, new URL(request.getRequestURL().toString()), trust,request,nonce);
			} catch (JoseException | LDAPException | ProvisioningException e1) {
				throw new ServletException("Could not generate jwt",e1);
			} 
			
			
			
			
			
			
			OpenIDConnectAccessToken access = new OpenIDConnectAccessToken();
			
			access.setAccess_token(accessToken);
			access.setExpires_in(Integer.toString((int) (trust.getAccessTokenTimeToLive() / 1000)));
			try {
				access.setId_token(this.produceJWT(dn.getValues().get(0), scopes.getValues(), cfgMgr, new URL(request.getRequestURL().toString()), trust,request,nonce));
			} catch (Exception e) {
				throw new ServletException("Could not generate JWT",e);
			} 
			
			access.setToken_type("Bearer");
			
			Gson gson = new Gson();
			String json = gson.toJson(access);
			
			response.setContentType("text/json");
			response.getOutputStream().write(json.getBytes());
			response.getOutputStream().flush();
			
			
			
		}

	}

	private String inflate(String saml) throws Exception {
		byte[] compressedData = Base64.decode(saml);
		ByteArrayInputStream bin = new ByteArrayInputStream(compressedData);
		
		InflaterInputStream decompressor  = new InflaterInputStream(bin,new Inflater(true));
		//decompressor.setInput(compressedData);
		
		// Create an expandable byte array to hold the decompressed data
		ByteArrayOutputStream bos = new ByteArrayOutputStream(compressedData.length);
		
		// Decompress the data
		byte[] buf = new byte[1024];
		int len;
		while ((len = decompressor.read(buf)) > 0) {
		    
		        
		        bos.write(buf, 0, len);
		    
		}
		try {
		    bos.close();
		} catch (IOException e) {
		}

		// Get the decompressed data
		byte[] decompressedData = bos.toByteArray();
		
		String decoded = new String(decompressedData);
		
		return decoded;
	}
	
	public void doPut(HttpServletRequest request, HttpServletResponse response) throws IOException, ServletException {
	

	}

	
	private void completeFederation(HttpServletRequest request,
			HttpServletResponse response) throws IOException, ServletException,
			MalformedURLException {
		final OpenIDConnectTransaction transaction = (OpenIDConnectTransaction) request.getSession().getAttribute(OpenIDConnectIdP.TRANSACTION_DATA);
		
		request.setAttribute(AzSys.FORCE, "true");
		NextSys completeFed = new NextSys() {

			
			public void nextSys(final HttpServletRequest request,
					final HttpServletResponse response) throws IOException,
					ServletException {
				//System.out.println("Authorized!!!!");
				
				
				final AuthInfo authInfo = ((AuthController) request.getSession().getAttribute(ProxyConstants.AUTH_CTL)).getAuthInfo();
				UrlHolder holder = (UrlHolder) request.getAttribute(ProxyConstants.AUTOIDM_CFG);
				
				HttpFilterRequest filterReq = new HttpFilterRequestImpl(request, null);
				HttpFilterResponse filterResp = new HttpFilterResponseImpl(response);

				PostProcess postProc = new PostProcess() {

					@Override
					public void postProcess(HttpFilterRequest req,
							HttpFilterResponse resp, UrlHolder holder,HttpFilterChain chain)
							throws Exception {
						postResponse(transaction, request, response, authInfo,
								holder);
						
					}

					

					@Override
					public boolean addHeader(String name) {
						
						return false;
					}
					
				};
				
				HttpFilterChain chain = new HttpFilterChainImpl(holder,postProc);
				try {
					chain.nextFilter(filterReq, filterResp, chain);
				} catch (Exception e) {
					
					throw new ServletException(e);
				}
				
				
				
				
			}
			
		};
		
		AzSys az = new AzSys();
		az.doAz(request, response, completeFed);
	}
	
	private void postResponse(OpenIDConnectTransaction transaction, HttpServletRequest request,
			HttpServletResponse response, AuthInfo authInfo, UrlHolder holder) throws Exception {
		//first generate a lastmile token
		OpenIDConnectTrust trust = trusts.get(transaction.getClientID());
		
		ConfigManager cfgMgr = (ConfigManager) request.getAttribute(ProxyConstants.TREMOLO_CFG_OBJ);
		
		DateTime now = new DateTime();
		DateTime notBefore = now.minus(trust.getCodeTokenTimeToLive());
		DateTime notAfter = now.plus(trust.getCodeTokenTimeToLive());
		
		com.tremolosecurity.lastmile.LastMile lmreq = new com.tremolosecurity.lastmile.LastMile(request.getRequestURI(),notBefore,notAfter,authInfo.getAuthLevel(),authInfo.getAuthMethod());
		lmreq.getAttributes().add(new Attribute("dn",authInfo.getUserDN()));
		Attribute attr = new Attribute("scope");
		attr.getValues().addAll(transaction.getScope());
		lmreq.getAttributes().add(attr);
		if (transaction.getNonce() != null) {
			lmreq.getAttributes().add(new Attribute("nonce",transaction.getNonce()));
		}
		SecretKey key = cfgMgr.getSecretKey(trust.getCodeLastmileKeyName());
		
		String codeToken = lmreq.generateLastMileToken(key);
		
		ByteArrayOutputStream baos = new ByteArrayOutputStream();
		
		DeflaterOutputStream compressor  = new DeflaterOutputStream(baos,new Deflater(Deflater.BEST_COMPRESSION,true));
		
		compressor.write(Base64.decode(codeToken.getBytes("UTF-8")));
		compressor.flush();
		compressor.close();
		
		
		
		String b64 = new String( Base64.encode(baos.toByteArray()));
		
		
		StringBuffer b = new StringBuffer();
		b.append(trust.getRedirectURI())
			.append("?")
			.append("code=").append(URLEncoder.encode(b64,"UTF-8"))
			.append("&state=").append(URLEncoder.encode(transaction.getState(),"UTF-8"));
		
		response.sendRedirect(b.toString());
		
	}
	
	public void init(String idpName,ServletContext ctx, HashMap<String, Attribute> init,
			HashMap<String, HashMap<String, Attribute>> trustCfg,MapIdentity mapper) {
		
		this.idpName = idpName;
		this.trusts = new HashMap<String,OpenIDConnectTrust>();
		for (String trustName : trustCfg.keySet()) {
			HashMap<String,Attribute> attrs = trustCfg.get(trustName);
			OpenIDConnectTrust trust = new OpenIDConnectTrust();
			trust.setClientID(attrs.get("clientID").getValues().get(0));
			trust.setClientSecret(attrs.get("clientSecret").getValues().get(0));
			trust.setRedirectURI(attrs.get("redirectURI").getValues().get(0));
			trust.setAccessLastmileKeyName(attrs.get("accessLastMileKeyName").getValues().get(0));
			trust.setCodeLastmileKeyName(attrs.get("codeLastMileKeyName").getValues().get(0));
			trust.setAuthChain(attrs.get("authChainName").getValues().get(0));
			trust.setCodeTokenTimeToLive(Long.parseLong(attrs.get("codeTokenSkewMilis").getValues().get(0)));
			trust.setAccessTokenTimeToLive(Long.parseLong(attrs.get("accessTokenSkewMilis").getValues().get(0)));
			trust.setTrustName(trustName);
			trusts.put(trust.getClientID(), trust);
			
		}
		
		this.mapper = mapper;
		this.jwtSigningKeyName = init.get("jwtSigningKey").getValues().get(0);

	}

	
	private String produceJWT(String dn,List<String> scopes,ConfigManager cfg,URL url,OpenIDConnectTrust trust,HttpServletRequest request,String nonce) throws JoseException, LDAPException, ProvisioningException {
		
		StringBuffer issuer = new StringBuffer();
		issuer.append(url.getProtocol()).append("://").append(url.getHost());
		if (url.getPort() > 0) {
			issuer.append(':').append(url.getPort());
		}
	
		issuer.append(cfg.getAuthIdPPath()).append(this.idpName);
		
		
		// Create the Claims, which will be the content of the JWT
	    JwtClaims claims = new JwtClaims();
	    claims.setIssuer(issuer.toString());  // who creates the token and signs it
	    claims.setAudience(trust.getClientID()); // to whom the token is intended to be sent
	    claims.setExpirationTimeMinutesInTheFuture(trust.getAccessTokenTimeToLive() / 1000 / 60); // time when the token will expire (10 minutes from now)
	    claims.setGeneratedJwtId(); // a unique identifier for the token
	    claims.setIssuedAtToNow();  // when the token was issued/created (now)
	    claims.setNotBeforeMinutesInThePast(2); // time before which the token is not yet valid (2 minutes ago)
	    claims.setSubject(dn); // the subject/principal is whom the token is about
	    if (nonce != null) {
	    	claims.setClaim("nonce", nonce);
	    }
	    ArrayList<String> attrs = new ArrayList<String>();
	    LDAPSearchResults res = cfg.getMyVD().search(dn,0, "(objectClass=*)", attrs);
	    
	    res.hasMore();
	    LDAPEntry entry = res.next();
	    
	    User user = new User(entry); 
	    user = this.mapper.mapUser(user, true);
	    
	    for (String attrName : scopes) {
	    	Attribute attr = user.getAttribs().get(attrName);
	    	if (attr != null) {
		    	if (attr.getValues().size() == 1) {
		    		claims.setClaim(attrName,attr.getValues().get(0));
		    	} else {
		    		claims.setStringListClaim(attrName, attr.getValues());
		    	}
	    	}
	    }
	    
	    
	   

	    // A JWT is a JWS and/or a JWE with JSON claims as the payload.
	    // In this example it is a JWS so we create a JsonWebSignature object.
	    JsonWebSignature jws = new JsonWebSignature();

	    // The payload of the JWS is JSON content of the JWT Claims
	    jws.setPayload(claims.toJson());

	    // The JWT is signed using the private key
	    jws.setKey(cfg.getPrivateKey(this.jwtSigningKeyName));

	    // Set the Key ID (kid) header because it's just the polite thing to do.
	    // We only have one key in this example but a using a Key ID helps
	    // facilitate a smooth key rollover process
	    //jws.setKeyIdHeaderValue(javax.xml.bind.DatatypeConverter.printHexBinary(cfg.getCertificate(jwtSigningKeyName).getExtensionValue("2.5.29.14")));

	    // Set the signature algorithm on the JWT/JWS that will integrity protect the claims
	    jws.setAlgorithmHeaderValue(AlgorithmIdentifiers.RSA_USING_SHA256);
	    

	    // Sign the JWS and produce the compact serialization or the complete JWT/JWS
	    // representation, which is a string consisting of three dot ('.') separated
	    // base64url-encoded parts in the form Header.Payload.Signature
	    // If you wanted to encrypt it, you can simply set this jwt as the payload
	    // of a JsonWebEncryption object and set the cty (Content Type) header to "jwt".
	    String jwt = jws.getCompactSerialization();
	    
	    logger.info("JWT : '" + jwt + "'");
	    
	    return jwt;
	}
}
