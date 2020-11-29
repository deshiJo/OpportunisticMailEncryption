/**
 * modules
 */

var { ExtensionParent } = ChromeUtils.import("resource://gre/modules/ExtensionParent.jsm");
var extension = ExtensionParent.GlobalManager.getExtension("experiment@sample.extensions.thunderbird.net");
var { ExtensionCommon } = ChromeUtils.import("resource://gre/modules/ExtensionCommon.jsm");
var { Services } = ChromeUtils.import("resource://gre/modules/Services.jsm");

// var { MailServices } = ChromeUtils.import("resource:///modules/MailServices.jsm");

var certificateManagement = class extends ExtensionCommon.ExtensionAPI {
  getAPI(context) {
    return {
      certificateManagement: {

	remove_cert(recipientID) {
		if (typeof Cc == "undefined") { Cc = Components.classes; }
            	if (typeof Cu == "undefined") { Cu = Components.utils; }
            	if (typeof Ci == "undefined") { Ci = Components.interfaces; }
            	const nsX509CertDB = "@mozilla.org/security/x509certdb;1";
            	const nsIX509Cert = Ci.nsIX509Cert;
            	const nsIX509CertDB = Ci.nsIX509CertDB;
            	const certdb = Cc[nsX509CertDB].getService(nsIX509CertDB);
		 
                var certs = certdb.getCerts();
		var match = null;
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
		}
	 },

        /**
         * save the certificate for the corresponding recipient address
         * @param {} recipientID 
         * @param {*} b64_certificate 
         * @param {*} b64_domain_cert 
         */
        import_cert(recipientID, b64_certificate, b64_domain_cert) {
		
          //check format:
          var smime = true;
          var pgp = false;
          console.log(recipientID);
          console.log(b64_certificate);

          //TODO: change if we add more information in the base 64 response (certificate), i.e it contains signature from company etc.
          if (smime) {
            // https://gist.github.com/richieforeman/3166387
            // https://www.xulplanet.com/references/xpcomref/comps/c_securityx509certdb1/
            if (typeof Cc == "undefined") { Cc = Components.classes; }
            if (typeof Cu == "undefined") { Cu = Components.utils; }
            if (typeof Ci == "undefined") { Ci = Components.interfaces; }
            const nsX509CertDB = "@mozilla.org/security/x509certdb;1";
            const nsIX509Cert = Ci.nsIX509Cert;
            const nsIX509CertDB = Ci.nsIX509CertDB;
            const certdb = Cc[nsX509CertDB].getService(nsIX509CertDB);
            console.log(certdb);
	    var recipient_address_domain_part = recipientID.split("@")[1];
            console.log("recipients domain is :  "+recipient_address_domain_part);
	    Cu.importGlobalProperties(["atob", "btoa"]);

            //remove newlines, whitespaces,...
            b64_certificate = b64_certificate.replace(/[\r\n]/g, "");
            b64_certificate = b64_certificate.replace(/\n/g, "");
            b64_certificate = b64_certificate.replace(" ", "");
            b64_certificate = b64_certificate.replace(/ /g, "");
	    b64_certificate = b64_certificate.replace(/\s+/g, "");

            console.log("replaced newlines whitespaces for user cert\n");

            b64_domain_cert = b64_domain_cert.replace(/[\r\n]/g, "");
            b64_domain_cert = b64_domain_cert.replace(" ", "");
            console.log("replaced newlines whitespaces for domain cert\n");
            //TODO remove !
            // console.log(test);
            // b64_certificate = test.getBase64DERString()
            // console.log(b64_certificate);
            // var CERT_TRUST = ",CPu,";
            // certdb.addCert(atob(b64_certificate), CERT_TRUST, "")
            // certdb.addCert(b64_certificate, CERT_TRUST, "");
            // b64_certificate = b64_certificate.replace(/-----BEGIN CERTIFICATE-----/, "")
            // b64_certificate = b64_certificate.replace(/-----END CERTIFICATE-----/, "")
            // b64_certificate = b64_certificate.replace(/(.*)-----BEGIN CERTIFICATE-----/, "")
            // b64_certificate = b64_certificate.replace(/-----END CERTIFICATE-----(.*)/, "")

            // if (b64_certificate.includes("BEGIN TRUSTED CERTIFICATE")) {
            //   // cut the first line:
            //   b64_certificate = b64_certificate.substring(b64_certificate.indexOf("\n") + 1);
            // }
            // while (b64_certificate.includes("END TRUSTED CERTIFICATE")) {
            //   //remove all lines after the end of encoded string
            //   b64_certificate = b64_certificate.substring(0, b64_certificate.lastIndexOf("\n"));
            // }

            // //remove new lines
            //TODO: extract mail from certificate and compare with the mail we requested the certificate for.
            // var new_cert = certdb.constructX509FromBase64(b64_certificate.trim());
            //var certdb = Components.classes["@mozilla.org/security/x509certdb;1"].getService(Components.interfaces.nsIX509CertDB);
            // certdb.importCertsFromFile(fp.file, Ci.nsIX509Cert.EMAIL_CERT);

            // let lines = b64_certificate.split("\n");
            // for (let i in lines) {
            //   if (lines[i].startsWith("---")) {
            //     lines.splice(i, 1)
            //   }
            // }
            // b64_certificate = lines.join(""); // removes newlines
            // b64_certificate = b64_certificate.replace(" ", "");
            try {
              //https://bugzilla.mozilla.org/show_bug.cgi?id=1643748 CHECK 
              //https://www.dalesandro.net/create-self-signed-smime-certificates/
	      console.log("get certs");
              var certs = certdb.getCerts();
	      console.log(certs[0].getBase64DERString());
	      console.log("now create cert objects");
	      console.log(b64_domain_cert);
	      let new_domain_cert = certdb.constructX509FromBase64(b64_domain_cert);
              console.log("successfully created domain certificate object ");
	      var domain_cert_property_fingerprint = new_domain_cert.sha256Fingerprint;
              var domain_cert_property_common_name = new_domain_cert.commonName;


	      console.log("search for received domain cert");
	      for (var i = 0; i < certs.length; i++) {
		      if (!(domain_cert_property_fingerprint.localeCompare(certs[i].sha256Fingerprint))) {
			      //found
			      console.log("domain cert found");
			      //console.log(certs[i]);
			      domain_match = certs[i];
			      console.log(domain_match);
			      var debug_domain_new = true;
				if(debug_domain_new) {
			      		console.log("delete domain cert");
					certdb.deleteCertificate(domain_match);
					domain_match = null;
			      }
			      break;
		      }
	      	}


		var match = null;

		//Check if user cert already exists -> delete (for test purposes)
		for (var i = 0; i < certs.length; i++) {
		      if (!(recipientID.localeCompare(certs[i].emailAddress))) {
			      //found
			      console.log("user cert found -> delete");
			      //console.log(certs[i]);
			      match = certs[i];
			      console.log(match);
			      break;
		      }
	      	}
		if (match) {
			certdb.deleteCertificate(match);
			console.log("user cert deleted !");
		}


	      console.log(b64_certificate);
	      console.log(atob(b64_certificate));
		
		    //TODO !!!!! use atob ? 


              let new_cert = certdb.constructX509FromBase64(b64_certificate);
	      console.log("created user certificate object");
                            //console.log(new_cert);

              var cert_property_mail = new_cert.emailAddress;
              var cert_property_fingerprint = new_cert.sha256Fingerprint;
              var cert_property_chain = new_cert.getChain;
	      console.log(" CERT OBJECT:\n");
	      console.log(new_cert);
	      console.log("DOMAIN CERT OBJECT:\n");
	      console.log(new_domain_cert);
              var { Services } = ChromeUtils.import("resource://gre/modules/Services.jsm");
	      let recentWindow = Services.wm.getMostRecentWindow("msgcompose");



	      //check if received user certificate is for the requested email
              if (!new_cert.containsEmailAddress(recipientID)) {
                console.log("certificate for wrong mail : ");
                //TODO: error message, with security warning ?
                return false;
              }

	      //TODO delete old version if new version is finished
	      var new_version = true;

	      if(new_version) {
		//TODO check if domain certificate known -> first exchange or not

	        console.log("new version ! \n");

	        var domain_match = null;
	      	var certs = certdb.getCerts();

		
		var send_encrypted = false;
		       
		//IF: FIRST EXCHANGE
		//if (!domain_match) {
		if (true) {
			console.log("domain unknown -> first exchange");

			//check signature of user certificate : NOT IMPLEMENTED YET
				
			//TODO give prompt which indicates first exchange :NOT IMPLEMENTED YET 
			//and set continue_process 
			var continue_process = true;

			//IF accepted continue and encrypt with user certificate
			if(continue_process) {
				certdb.addCertFromBase64(b64_domain_cert,',Cu,',recipient_address_domain_part);
				//certdb.addCertFromBase64(b64_domain_cert,',CPu,',recipient_address_domain_part);
				//certdb.addCertFromBase64(b64_domain_cert,',CPu,',recipient_address_domain_part);
				console.log("import domain certificate for future usage");
				certdb.addCertFromBase64(b64_certificate,',Cu,',recipientID);
				//certdb.addCertFromBase64(b64_certificate,',CPu,',recipientID);
				//certdb.addCertFromBase64(b64_certificate,',CPu,',recipientID);
				console.log("import user cert for encryption");
				//save domain cert with the domain part of the recipient's email address, to rememeber it for future exchanges
								send_encrypted = true;
				if (send_encrypted) {
					console.log("try to send encrypted with newly received domain certificate");
					recentWindow.onSecurityChoice("enc2");
				} 
				return true;
			} else {
				return false;
			}

		} else {
			console.log("domain known -> check if received and known are the same ");
			console.log(domain_match);
		        //ELSE: NOT FIRST EXCHANGE
			//COMPARE DOMAIN CERT WITH OLD ONE
			if(!domain_match.displayName.localeCompare(recipient_address_domain_part)) {
				send_encrypted = true;
				certdb.addCertFromBase64(b64_certificate,',P,',recipientID);
			} else {
				// received domain certificate differs from known domain certificate !
				console.log("received domain certificate wrong !!!!");
				console.log(recipient_address_domain_part);
				console.log(domain_match.displayName);
				return false;
			}

			//ENCRYPT with user certificate
			//otherwise send unencrypted
			if (send_encrypted) {
				console.log("try to send encrypted with known domain certificate");

				//TODO: on security choice toggles encryption ?! ?! 
				recentWindow.onSecurityChoice("enc2");
			}
			return true;
		}

		//recentWindow.onSecurityChoice("enc2");
		      

	      //TODO REMOVE IF NOT NEEDED ANYMORE
	      } else {



		      /**
		       * certificate already present for requested mail ? 
		       * Compare certificate and check signature. 
		       * If signature is verified, use new certificate.
		       * 
		       * OR does this implicitly happen with the authority we added with the first exchange ? 
		       */
		      // var certdb = Components.classes["@mozilla.org/security/x509certdb;1"].getService(Components.interfaces.nsIX509CertDB);
		      var match = null;
		      var certs = certdb.getCerts();
		      //console.log(certs);
		      for (var i = 0; i < certs.length; i++) {
			if (!(cert_property_mail.localeCompare(certs[i].emailAddress))) {
			  //found
			  console.log("cert found");
			  //console.log(certs[i]);
			  match = certs[i];
			  break;
			}
		      }

		      var { Services } = ChromeUtils.import("resource://gre/modules/Services.jsm");
		      let recentWindow = Services.wm.getMostRecentWindow("msgcompose");

		      //certificate for this mail already present
		      if (match) {
			console.log("certificate already present for this requested mail");

			//is trusted just checks if we trust the signing CA. But we have to check if the Domain CA is the correct one!
			var isTrusted = certdb.isCertTrusted(new_cert, nsIX509Cert.EMAIL_CERT, nsIX509CertDB.TRUSTED_EMAIL);

			//TODO: check if domain is the same ca als the last one
			console.log("trusted : " + isTrusted);
			/**
			 * for debugging
			 */
			isTrusted = true;

			 //console.log(document.getElementById("menu_securityEncryptRequire_Toolbar"));

			      //let msgComposeParams = Components.classes["@mozilla.org/messengercompose;1"].getService(Components.interfaces.nsIMsgComposeService);
			      //console.log(msgComposeParams);
			      //console.log(windows.getCurrent(null));
			      //console.log(recentWindow);
			      //recentWindow.onSecurityChoice("enc2");
			      //recentWindow.onSendSMIME("enc2");

			      //var all = recentWindow.document.getElementsByTagName("*");

			      //console.log(recentWindow.document.getElementById('menu_securityEncryptRequire_Toolbar'));
			      //console.log(recentWindow.document.getElementById('menu_securityEncryptRequire_Menubar'));
			      //var notFound = false;
			      //var security_toolbar = recentWindow.document.getElementById('menu_securityEncryptRequire_Toolbar');
			      //var security_options = recentWindow.document.getElementById('button-security');
			      //console.log(security_options);
				//console.log(security_options.getAttribute("oncommand"));
				//var security_option_function = security_options.getAttribute("oncommand");
			      //console.log(typeof security_option_function);
			      //security_option_function.apply("enc2");

			      //if (typeof security_option_function == "function") {
				      
			      //}

			      //console.log(security_toolbar.attributes);
			      //security_toolbar.setAttribute(checked, true);
			      //console.log(security_toolbar.getAttribute(checked));
			      //console.log(security_toolbar.checked);
			      //var security_menu = recentWindow.document.getElementById('menu_securityEncryptRequire_Menubar');
			      //while(notFound) {
				      //var next = security_toolbar.nextElementSibling;	
				      

			      //}
			      //console.log(recentWindow.document.getElementById('menu_securityEncryptRequire'));

			/**
			 * the old certificate could be revoced or is expired. 
			 * If the received certificate is new, check if it is signed with the same private key.  
			 * Otherwise security warning.
			*/



			if (!(match.sha256Fingerprint.localeCompare(cert_property_fingerprint))) {
			  /**
			   * saved certificate is identical -> nothing changed
			   */
			  if (isTrusted) {
			    console.log("use saved certificate");
			    recentWindow.onSecurityChoice("enc2");
			    return true;
			  } else {
			    console.log("cannot trust certificate");
			    return false;
			  }

			} else {
			  /**
			   * the certificate is different to the saved one 
			   * -> check if the signature is created with the same private key.
			   * (issuer certificate/sk should not change often)
			   */
			  console.log("the certificate is new !");
			  if (isTrusted) {

			  }

			  same_sk = true; //debug
			  if (same_sk) {
			    /**
			     * save new certificate and delete old
			     */
			    var name = "xcertreq" + recipientID;
			    console.log("save certificate as new and deleted old");
			    var debug = true;
			    if (debug) {
			      console.log("debug delete old and save new: " + match.emailAddress);
			    } else {
			      certdb.deleteCertificate(match);
			      //certdb.addCertFromBase64(b64_certificate, 'Cu,,', name);
			      certdb.addCertFromBase64(b64_certificate,',P,',name);
			    }
			    recentWindow.onSecurityChoice("enc2");
			    return true;
			  } else {
			    //security warning
			  }
			}

			//check certificate with known pk for this domain
			var cert_property_chain = new_cert.getChain();
			console.log(cert_property_chain);

			// var dom_cert = search_domain_certificate();
			recentWindow.onSecurityChoice("enc2");
			return true;

		      } else {
			//cert = 
			console.log("no certificate for this mail address present.");
			//TODO: can we trust this cert ? check signature of this cert, if we already have a certificate for this requested mail

			/**
			 * "Query whether a certificate is trusted for a particular use. "
			 * if we have 
			*/
			//if (certdb.isCertTrusted(new_cert, , nsIX509CertDB.TRUSTED_EMAIL))

			//also check if we seen certificates for this domain
			var domain_known = false; //debug
			if (domain_known) {
				//Domain known -> check if we can trust this cert
				//

			} else {
				//Domain not known -> trust on first use
				//save the domain cert and remeber this cert for this domain

			}

			var name = "xcertreq"+recipientID;
			console.log("save received cert");
			
			//certdb.addCertFromBase64(certifcate, "C,C,C", name) //TODO check second param
			// let der = atob(b64);
			//certdb.addCertFromBase64(b64_certificate,'Cu,,',name);
			//certdb.addCertFromBase64(b64_certificate,',CPu,',name);

			//TODO: the trust string (second parameter) could be wrong. But its hard to find a documentation...
			//find a correct way to add the received certificate 
			//certdb.addCertFromBase64(b64_certificate,',P,',name);
			certdb.addCertFromBase64(b64_certificate,nsIX509CertDB.TRUSTED_EMAIL,name);
			recentWindow.onSecurityChoice("enc2");
			return true;
		      }
              }
            } catch (e) { 
              console.log("import certificate failed!");
              console.log(e);
	      return false;
            }

          }
          else if (pgp) {

          } else {
            console.log("Error, certificate format not known")
            return false;
          }
        },

        /**
         * search for a certificate for the given mail address. Return null, if there is no certificate yet. Return the nsIX509Cert object otherwise.
         * @param {} mail_address 
         * @return nsIX509Cert object
         */
        search_certificate(mail_address) {
            var certdb = Components.classes["@mozilla.org/security/x509certdb;1"].getService(Components.interfaces.nsIX509CertDB);
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
};
