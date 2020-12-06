/**
 * modules
 */

var { ExtensionCommon } = ChromeUtils.import("resource://gre/modules/ExtensionCommon.jsm");
//var { ExtensionParent } = ChromeUtils.import("resource://gre/modules/ExtensionParent.jsm");
var { Services } = ChromeUtils.import("resource://gre/modules/Services.jsm");
var { ExtensionParent } = ChromeUtils.import("resource://gre/modules/ExtensionParent.jsm");
var extension = ExtensionParent.GlobalManager.getExtension("Optofu@Jo");
//const { classes: Cc, interfaces: Ci, utils: Cu } = Components
const certdb = Components.classes["@mozilla.org/security/x509certdb;1"].getService(Components.interfaces.nsIX509CertDB);
//var { mimeEnryption } = ChromeUtils.import("chrome://content/modules/mimeEncryption.jsm");
//Cu.import("resources://gre/modules/Services.jsm");

// var { MailServices } = ChromeUtils.import("resource:///modules/MailServices.jsm");

const Cc = Components.classes;
const Ci = Components.interfaces;
const Cu = Components.utils;

function addUserCertificate(b64Certificate,name) { 
	Components.utils.importGlobalProperties(["atob", "btoa"]);
	b64Certificate = b64Certificate.replace(/[\r\n]/g, "");
	var c = certdb.constructX509FromBase64(b64Certificate);
	c.displayName = "TTTT";
	console.log(c);
	console.log(Components.interfaces.nsIX509Cert);

	//var CERT_USER_TRUST = ",Cp,";
	var CERT_USER_TRUST = "Pu,Pu,Pu";
	//var CERT_USER_TRUST = ",Pu,";
	try {
		//console.log(certdb.addCertFromBase64(b64Certificate, Components.interfaces.nsIX509Cert.EMAIL_CERT));
		console.log(certdb.addCertFromBase64(b64Certificate, CERT_USER_TRUST));
		Services.obs.notifyObservers(null, "profile-after-change", null);
		//emailTreeView.loadCertsFromCache(certcache, Ci.nsIX509Cert.EMAIL_CERT);
		//emailTreeView.selection.clearSelection();
		//caTreeView.loadCertsFromCache(certcache, Ci.nsIX509Cert.CA_CERT);
		//caTreeView.selection.clearSelection();
		//var data = atob(b64Certificate);
		//certdb.importEmailCertificate(data, data.length, null);
		console.log("added "+ name);
	} catch (e) {
		console.error(e);
		return false;
	}
	console.log("user certificate added successfully");
	let recentWindow = Services.wm.getMostRecentWindow("msgcompose");
	recentWindow.onSecurityChoice("enc2");
	return true;
}

function addDomainCertificate(b64Certificate, name) {
	b64Certificate = b64Certificate.replace(/[\r\n]/g, "");
	var cert = b64Certificate.replace(/\s+/g, "");
	try {

		var c = certdb.constructX509FromBase64(cert);
	} catch (e) { 
		console.log("error constructing cert domain object "); 
		return false;
		//resolve({"added": false, "issuer": c.issuer });
	}

	//c.isBuiltInRoot = true;
	//var CERT_DOMAIN_TRUST = ",Cu,";
	//try {
	//certdb.addCertFromBase64(b64Certificate, CERT_DOMAIN_TRUST, "");
	//} catch (e) {
	//console.error(e);
	//return false;
	//}
	//console.log("user certificate added successfully");
	//return true;

	//var observer = {
	//observe: function observe(aSubject, aTopic, aData) {
	//var certdb = Components.classes["@mozilla.org/security/x509certdb;1"].getService(Components.interfaces.nsIX509CertDB);
	try {
		//certdb.addCert(c, "CPU,CPU,CPU", c.issuerName);
		var CERT_DOMAIN_TRUST = ",Cpu,";
		certdb.addCertFromBase64(b64Certificate, CERT_DOMAIN_TRUST, name);
		//certdb.addCert(c, "CPU,CPU,CPU", c.issuerName);
		console.log("added domain "+name);
	} catch (e) {
		console.log("domain import error");
		console.log(e);
		return false;
		//resolve({"added": false, "issuer": c.issuer });
	}
	Services.obs.notifyObservers(null, "profile-after-change", null);
	//Services.obs.addObserver(observer, "profile-after-change", false);
	return true;
	//resolve({"added": true, "issuer": c.issuer });
}

var certificateManagement = class extends ExtensionCommon.ExtensionAPI {

  getAPI(context) {
    context.callOnClose(this);
    return {
      certificateManagement: {

	      encryptMessage(test) {
		      let fields = Cc["@mozilla.org/messengercompose/composefields;1"].createInstance(Ci.nsIMsgCompFields);
		      let params = Cc["@mozilla.org/messengercompose/composeparams;1"].createInstance(Ci.nsIMsgComposeParams);	
		      console.log(fields);
		      console.log(params);
		      let helper = Cc[
			      "@mozilla.org/messenger-smime/smimejshelper;1"
		      ].createInstance(Ci.nsISMimeJSHelper);
		      console.log(helper);
		      var secMsg = Cc["@mozilla.org/nsCMSSecureMessage;1"].getService(
			      Ci.nsICMSSecureMessage
		      );
		      console.log(secMsg);
	  	      test = test.replace(/[\r\n]/g, "");
		      var c = certdb.constructX509FromBase64(test);
		      console.log(c);
		      //console.log(secMsg.sendMessage("TTTTTT", test));

	      },

	  addUserCertificate(b64Certificate,name) { 
      	          Components.utils.importGlobalProperties(["atob", "btoa"]);
		  //b64Certificate.replace(/[\r\n]/g,"");
	  	  b64Certificate = b64Certificate.replace(/[\r\n]/g, "");
		  var c = certdb.constructX509FromBase64(b64Certificate);
            	  //b64Certificate = b64Certificate.replace(/\n/g, "");
            	  //b64Certificate = b64Certificate.replace(" ", "");
            	  //b64Certificate = b64Certificate.replace(/ /g, "");
	          //b64Certificate = b64Certificate.replace(/\s+/g, "");
		  console.log(Components.interfaces.nsIX509Cert);
		  //var CERT_USER_TRUST = ",Cp,";
		  var CERT_USER_TRUST = "Pu,Pu,Pu";
		  //var CERT_USER_TRUST = ",Pu,";
		  try {
			//console.log(certdb.addCertFromBase64(b64Certificate, Components.interfaces.nsIX509Cert.EMAIL_CERT));
			console.log(certdb.addCertFromBase64(b64Certificate, CERT_USER_TRUST, name));
		        Services.obs.notifyObservers(null, "profile-after-change", null);
			//emailTreeView.loadCertsFromCache(certcache, Ci.nsIX509Cert.EMAIL_CERT);
			//emailTreeView.selection.clearSelection();
			//caTreeView.loadCertsFromCache(certcache, Ci.nsIX509Cert.CA_CERT);
			//caTreeView.selection.clearSelection();
			//var data = atob(b64Certificate);
			//certdb.importEmailCertificate(data, data.length, null);
			console.log("added "+ name);
		  } catch (e) {
			  console.error(e);
			  return false;
		  }
		  console.log("user certificate added successfully");
                  let recentWindow = Services.wm.getMostRecentWindow("msgcompose");
       		  recentWindow.onSecurityChoice("enc2");
		  return true;
	  },

	      addDomainCertificate(b64Certificate, name) {
		      b64Certificate = b64Certificate.replace(/[\r\n]/g, "");
		      var cert = b64Certificate.replace(/\s+/g, "");
		      try {

		      var c = certdb.constructX509FromBase64(cert);
		      } catch (e) { 
			      console.log("error constructing cert domain object "); 
			      return false;
		      	      resolve({"added": false, "issuer": c.issuer });
		      }

		      //c.isBuiltInRoot = true;
		      //var CERT_DOMAIN_TRUST = ",Cu,";
		      //try {
		      //certdb.addCertFromBase64(b64Certificate, CERT_DOMAIN_TRUST, "");
		      //} catch (e) {
		      //console.error(e);
		      //return false;
		      //}
		      //console.log("user certificate added successfully");
		      //return true;

		      //var observer = {
		      //observe: function observe(aSubject, aTopic, aData) {
		      //var certdb = Components.classes["@mozilla.org/security/x509certdb;1"].getService(Components.interfaces.nsIX509CertDB);
		      try {
			      //certdb.addCert(c, "CPU,CPU,CPU", c.issuerName);
		              var CERT_DOMAIN_TRUST = ",Cpu,";
		      	      certdb.addCertFromBase64(b64Certificate, CERT_DOMAIN_TRUST, name);
			      //certdb.addCert(c, "CPU,CPU,CPU", c.issuerName);
			      console.log("added domain "+name);
		      } catch (e) {
			      console.log("domain import error");
			      console.log(e);
		      	      resolve({"added": false, "issuer": c.issuer });
		      }
		      Services.obs.notifyObservers(null, "profile-after-change", null);
		      //Services.obs.addObserver(observer, "profile-after-change", false);
		      resolve({"added": true, "issuer": c.issuer });
	      },

	  checkDomainKnown(domain_name, domain_cert) {
		domain_cert = domain_cert.replace(/[\r\n]/g, "");
		console.log(certdb);
		var domain_cert = domain_cert.replace(/\s+/g, "");
		var c = certdb.constructX509FromBase64(domain_cert);
		var domain_cert_property_fingerprint = c.sha256Fingerprint;
		var found = false;
		var certs = certdb.getCerts();
		console.log(certs);
		for (var i = 0; i < certs.length; i++) {
        	  if (!(domain_cert_property_fingerprint.localeCompare(certs[i].sha256Fingerprint))) {
       		      console.log("domain cert found and is correct");
       		      console.log(certs[i]);
       		      var domain_match = certs[i];
		      //TODO use something else than display name to save and look for a domain certificate ? 
		      var display_name = domain_match.displayName;

		      //TODO remove debug 
		      if (display_name.localeCompare("TEST")) {
			      console.log("test domain cert found");
			      return true;
		      }
		      if (!(display_name.localeCompare(domain_name))) {
			      console.log("domain found -> known ");
			      found = true;
			      break;
		      } 
		  }
		}
		if (found) {
			console.log(found)
			return true;
		} else {
			console.log("domain not found \n");
			return false;
		}
	  },

	      //TODO
          remove_cert_domain(recipientID) {

              var match = null;
              console.log(certs);
              console.log(recipientID);
              //Check if user cert already exists -> delete (for test purposes)
              for (var i = 0; i < certs.length; i++) {
                  console.log(certs[i].emailAddress);
                  if (!(recipientID.localeCompare(certs[i].emailAddress))) {
                      //found
                      console.log("user cert found -> delete");
                      //console.log(certs[i]);
                      match = certs[i];
                      break;
                  }
              }
              if(match) {
                  certdb.deleteCertificate(match);
                  //caTreeView.loadCerts(Ci.nsIX509Cert.CA_CERT);
		  Services.obs.notifyObservers(null, "profile-after-change", null);
              }
          },
	  construct_cert_from_base64(cert) {
		
	  },


	      //TODO
          remove_cert_user(recipientID) {
	      //let certdb = Cc["@mozilla.org/security/nsIX509certdb;1"].getService(Ci.nsIX509CertDB);
              var certs = certdb.getCerts();
              var match = null;
              console.log(certs);
              console.log(recipientID);
              //Check if user cert already exists -> delete (for test purposes)
              for (var i = 0; i < certs.length; i++) {
                  console.log(certs[i].emailAddress);
                  if (!(recipientID.localeCompare(certs[i].emailAddress))) {
                      //found
                      console.log("user cert found -> delete");
                      //console.log(certs[i]);
                      match = certs[i];
                      break;
                  }
              }
              if(match) {
                  certdb.deleteCertificate(match);
                  //caTreeView.loadCerts(Ci.nsIX509Cert.CA_CERT);
		  Services.obs.notifyObservers(null, "profile-after-change", null);
		  return true;
              }
		  return false;
          },

        /**
         * save the certificate for the corresponding recipient address
         * @param {} recipientID 
         * @param {*} b64_certificate 
         * @param {*} b64_domain_cert 
         */
        import_cert(recipientID, b64_certificate, b64_domain_cert) {
		console.log("begin importing");
		var msgComp = Components.classes["@mozilla.org/messengercompose/send;1"].getService(Ci.nsIMsgSend)
		//var msgCompSec = Cc[
			//"@mozilla.org/messengercompose/composesecure;1"
		//].createInstance(Ci.nsIMsgComposeSecure);
		//console.log(msgComp.compFields);
		var recipient_address_domain = recipientID.split("@")[1];
		var user_response = addUserCertificate(b64_certificate,recipientID)
		var domain_response = addDomainCertificate(b64_domain_cert, recipient_address_domain);
		console.log(user_response);
		console.log(domain_response);
		if (user_response && domain_response) {
			//activate smime encryption
			//
			//gMsgCompose.compFields.composeSecure.requireEncryptMessage
			//
	      		recentWindow.onSecurityChoice("enc2");
		} else {

		}

	},

		
      //    //check format:
      //   var smime = true;
      //   var pgp = false;
      //   console.log(recipientID);
      //   console.log(b64_certificate);

      //   //TODO: change if we add more information in the base 64 response (certificate), i.e it contains signature from company etc.
      //     // https://gist.github.com/richieforeman/3166387
      //     // https://www.xulplanet.com/references/xpcomref/comps/c_securityx509certdb1/
      //     //if (typeof Cc == "undefined") { Cc = Components.classes; }
      //     //if (typeof Cu == "undefined") { Cu = Components.utils; }
      //     //if (typeof Ci == "undefined") { Ci = Components.interfaces; }
      //     let Cc = Components.classes;
      //     let Cu = Components.utils;
      //     let Ci = Components.interfaces;
      //     let nsIX509Cert = Ci.nsIX509Cert;
      //         let certdb = Cc["@mozilla.org/security/x509certdb;1"].getService(Ci.nsIX509CertDB);
      //     console.log(certdb);
      //         Cu.importGlobalProperties(["atob", "btoa"]);
      //     var certcache = certdb.getCerts();

      //     var caTreeView = Cc["@mozilla.org/security/nsCertTree;1"].createInstance(
      //         Ci.nsICertTree
      //     );
      //     caTreeView.loadCertsFromCache(certcache, Ci.nsIX509Cert.CA_CERT);


      //         var recipient_address_domain_part = recipientID.split("@")[1];
      //     console.log("recipients domain is :  "+recipient_address_domain_part);
      //     //remove newlines, whitespaces,...
      //     b64_certificate = b64_certificate.replace(/[\r\n]/g, "");
      //     b64_certificate = b64_certificate.replace(/\n/g, "");
      //     b64_certificate = b64_certificate.replace(" ", "");
      //     b64_certificate = b64_certificate.replace(/ /g, "");
      //         b64_certificate = b64_certificate.replace(/\s+/g, "");

      //     console.log("replaced newlines whitespaces for user cert\n");

      //     b64_domain_cert = b64_domain_cert.replace(/[\r\n]/g, "");
      //     b64_domain_cert = b64_domain_cert.replace(" ", "");
      //     console.log("replaced newlines whitespaces for domain cert\n");


      //       console.log(b64_certificate);
      //       console.log(atob(b64_certificate));
      // 	
      //       //certdb.addCert(atob(b64_certificate), ",u,", recipientID);
      // try {
      //       //https://bugzilla.mozilla.org/show_bug.cgi?id=1643748 CHECK 
      //       //https://www.dalesandro.net/create-self-signed-smime-certificates/
      //       console.log("get certs");
      //       var certs = certdb.getCerts();
      //       console.log(certs[0].getBase64DERString());
      //       console.log("now create cert objects");
      //       console.log(b64_domain_cert);

      //       let new_domain_cert = certdb.constructX509FromBase64(b64_domain_cert);
      //   var certcache = certdb.getCerts();
      //   console.log("successfully created domain certificate object ");
      //       var domain_cert_property_fingerprint = new_domain_cert.sha256Fingerprint;
      //   var domain_cert_property_common_name = new_domain_cert.commonName;


      //   let new_cert = certdb.constructX509FromBase64(b64_certificate);
      //       console.log("created user certificate object");
      //                     //console.log(new_cert);

      //       console.log("search for received domain cert");
      //       for (var i = 0; i < certs.length; i++) {
      // 	      if (!(domain_cert_property_fingerprint.localeCompare(certs[i].sha256Fingerprint))) {
      // 		      //found
      // 		      console.log("domain cert found");
      // 		      //console.log(certs[i]);
      // 		      domain_match = certs[i];
      // 		      console.log(domain_match);
      // 		      var debug_domain_new = true;
      // 			if(debug_domain_new) {
      // 		      		console.log("delete domain cert");
      // 				certdb.deleteCertificate(domain_match);
      // 				domain_match = null;
      // 		      }
      // 		      break;
      // 	      }
      //       	}
      //       var cert_property_mail = new_cert.emailAddress;
      //       var cert_property_fingerprint = new_cert.sha256Fingerprint;
      //       var cert_property_chain = new_cert.getChain;
      //       console.log(" CERT OBJECT:\n");
      //       console.log(new_cert);
      //       console.log("DOMAIN CERT OBJECT:\n");
      //       console.log(new_domain_cert);
      //       var { Services } = ChromeUtils.import("resource://gre/modules/Services.jsm");
	      //       let recentWindow = Services.wm.getMostRecentWindow("msgcompose");

	      //       //check if received user certificate is for the requested email
	      //       if (!new_cert.containsEmailAddress(recipientID)) {
	      //         console.log("certificate for wrong mail : ");
	      //         //TODO: error message, with security warning ?
	      //         return false;
	      //       }

	      //       //TODO delete old version if new version is finished
	      //       var new_version = true;

	      //       if(new_version) {
	      // 	//TODO check if domain certificate known -> first exchange or not

	      //         console.log("new version ! \n");

	      //         var domain_match = null;
	      //       	var certs = certdb.getCerts();

	      // 	
	      // 	var send_encrypted = false;
	      // 	       
	      // 	//IF: FIRST EXCHANGE
	      // 	//if (!domain_match) {
	      // 	if (true) {
	      // 		console.log("domain unknown -> first exchange");

	      // 		//check signature of user certificate : NOT IMPLEMENTED YET
	      // 			
	      // 		//TODO give prompt which indicates first exchange :NOT IMPLEMENTED YET 
	      // 		//and set continue_process 
	      // 		var continue_process = true;

	      // 		//IF accepted continue and encrypt with user certificate
	      // 		if(continue_process) {
	      //         var cdb = Cc["@mozilla.org/security/x509certdb;1"].getService(Ci.nsIX509CertDB);
	      //         var certdb2 = cdb;
	      //         //try {
	      //             //var certdb2 = Cc["@mozilla.org/security/x509certdb;1"].getService(Ci.nsIX509CertDB2);
	      //         //} catch (e) {console.log("cert db 2 not found");}

	      // 			cdb.addCertFromBase64(b64_domain_cert,'C,CPu,C',recipient_address_domain_part);

	      //         certcache = certdb.getCerts();
	      //         console.log("successfully created domain certificate object ");
	      //         caTreeView.loadCerts(Ci.nsIX509Cert.CA_CERT);
	      //         console.log(caTreeView);
	      //         //caTreeView.selection.clearSelection();

	      // 			//certdb.addCertFromBase64(b64_domain_cert,',CPu,',recipient_address_domain_part);
	      // 			//certdb.addCertFromBase64(b64_domain_cert,',CPu,',recipient_address_domain_part);
	      // 			console.log("import domain certificate for future usage");
	      //         var cdb2 = Cc["@mozilla.org/security/x509certdb;1"].getService(Ci.nsIX509CertDB);
	      //             cdb2.addCert(atob(b64_certificate), "u,Pu,u", recipientID);
	      // 			//certdb.addCertFromBase64(b64_certificate,',CPu,',recipientID);
	      // 			//certdb.addCertFromBase64(b64_certificate,',CPu,',recipientID);
	      // 			console.log("import user cert for encryption");
	      // 			//save domain cert with the domain part of the recipient's email address, to rememeber it for future exchanges
	      // 							send_encrypted = true;
	      // 			if (send_encrypted) {
	      // 				console.log("try to send encrypted with newly received domain certificate");
	      // 				recentWindow.onSecurityChoice("enc2");
      // 			} 
      // 			return true;
      // 		} else {
      // 			return false;
      // 		}

      // 	} else {
      // 		console.log("domain known -> check if received and known are the same ");
      // 		console.log(domain_match);
      // 	        //ELSE: NOT FIRST EXCHANGE
      // 		//COMPARE DOMAIN CERT WITH OLD ONE
      // 		if(!domain_match.displayName.localeCompare(recipient_address_domain_part)) {
      // 			send_encrypted = true;
      // 			certdb.addCertFromBase64(b64_certificate,',P,',recipientID);
      // 		} else {
      // 			// received domain certificate differs from known domain certificate !
      // 			console.log("received domain certificate wrong !!!!");
      // 			console.log(recipient_address_domain_part);
      // 			console.log(domain_match.displayName);
      // 			return false;
      // 		}

      // 		//ENCRYPT with user certificate
      // 		//otherwise send unencrypted
      // 		if (send_encrypted) {
      // 			console.log("try to send encrypted with known domain certificate");

      // 			//TODO: on security choice toggles encryption ?! ?! 
      // 			recentWindow.onSecurityChoice("enc2");
      // 		}
      // 		return true;
      // 	}

      // 	//recentWindow.onSecurityChoice("enc2");
      // 	      
      //       }
      //     } catch (e) { 
      //       console.log("import certificate failed!");
      //       console.log(e);
      //           return false;
      //     }
      // },

        /**
         * search for a certificate for the given mail address. Return null, if there is no certificate yet. Return the nsIX509Cert object otherwise.
         * @param {} mail_address 
         * @return nsIX509Cert object
         */
        search_certificate(mail_address) {
            //var certdb = Components.classes["@mozilla.org/security/x509certdb;1"].getService(Components.interfaces.nsIX509CertDB);
            var certs = certdb.getCerts();
            for (cert in certs) {
              if (cert.emailAddress == mail_address) {
                //found
                return cert;
              }
            }
            //no cert found
            return null;
        },

        /**
         * get the current ougoing smtp server for the given identityId
         * @param {*} identityId 
         */
        get_smtp_server(identityId) {
            console.log("extract ougoing smtp server");
            // var currentAccount = PrefValue("mail.accountmanager.currentAccount");
            // Services.wm.getMostRecentWindow("mail:3pane").alert("Hello !");
            // console.log(acctMgr.accounts)
            var acctMgr = Components.classes["@mozilla.org/messenger/account-manager;1"]
                        .getService(Components.interfaces.nsIMsgAccountManager);
            var smtpMgr = Components.classes["@mozilla.org/messengercompose/smtp;1"]
                        .getService(Components.interfaces.nsISmtpService);
                
            // var smtpMgr = Components.classes["@mozilla.org/messengercompose/smtp;1"];

            // console.log(acctMgr);
            console.log("get Identity object for: " + identityId);
            var identity = acctMgr.getIdentity(identityId);
            // console.log(identity);

            console.log("extract smtp with identity object");
            var out = {};
            smtpMgr.getServerByIdentity(identity, out);
            var server = out.value;
            // console.log(server);
            // console.log(server.hostname);
            // console.log(server.port);
            var result = [server.hostname, server.port];

            return result;
        }
        /**
         * Place more functions here
         */
      }
    }
  }
  close() {
	console.log("bye");
	Services.obs.notifyObservers(null, "startupcache-invalidate", null);
  }
};
