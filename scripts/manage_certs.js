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

        /**
         * save the certificate for the corresponding recipient address
         * @param {} recipientID 
         * @param {*} certificate 
         */
        import_cert(recipientID, b64_certificate) {

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

            //remove newlines, whitespaces,...
            b64_certificate = b64_certificate.replace(/[\r\n]/g, "");
            b64_certificate = b64_certificate.replace(" ", "");

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
              var certs = certdb.getCerts();
              let new_cert = certdb.constructX509FromBase64(b64_certificate);
              console.log("sucessfully created certificate object ");
              //console.log(new_cert);

              var cert_property_mail = new_cert.emailAddress;
              var cert_property_fingerprint = new_cert.sha256Fingerprint;

              if (!new_cert.containsEmailAddress(recipientID)) {
                console.log("certificate for wrong mail : ");
                //TODO: error message, with security warning ?
                return false;
              }


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

                var isTrusted = certdb.isCertTrusted(new_cert, nsIX509Cert.CA_CERT, nsIX509CertDB.TRUSTED_EMAIL);
                console.log("trusted : " + isTrusted);
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
                      certdb.addCertFromBase64(b64_certificate, 'Cu,,', name);
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

                } else {

                }

                var name = "xcertreq"+recipientID;
                console.log("save received cert");
                
                //certdb.addCertFromBase64(certifcate, "C,C,C", name) //TODO check second param
                // let der = atob(b64);
                certdb.addCertFromBase64(b64_certificate,'Cu,,',name);
		recentWindow.onSecurityChoice("enc2");
                return true;
              }
            } catch (e) { 
              console.log("import certificate failed!");
              console.log(e);
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
