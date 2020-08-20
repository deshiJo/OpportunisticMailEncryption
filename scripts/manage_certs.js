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


          if(smime) {
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
              console.log(new_cert);

              var cert_property_mail = new_cert.emailAddress;
              console.log(cert_property_mail);
              if (!new_cert.containsEmailAddress(recipientID)) {
                console.log("certificate for wrong mail : " );
                //TODO: error message, with security warning ?
                return;
              }
              var cert_property_issuerCert = new_cert.issuer;
              console.log(cert_property_issuerCert);



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
              for (const cert in certs) {
                if (recipientID.localeCompare(cert.emailAddress)) {
                  console.log("cert found");
                  //found
                  match = cert;
                }
              }

              // var match = search_certificate(recipientID);
              // match = certdb.findCertByEmailAddress(null, recipientID);

              //certificate for this mail already present
              if (match) {
                console.log("certificate already present for this requested mail");
                //check certificate with known pk for this domain
                // var dom_cert = search_domain_certificate();
                return true;

              } else {
                //cert = 
                console.log("no certificate for this mail address present.");
                //TODO: can we trust this cert ? check signature of this cert, if we already have a certificate for this requested mail

                var name = "xcertreq"+recipientID;
                console.log("save received cert");
                
                //certdb.addCertFromBase64(certifcate, "C,C,C", name) //TODO check second param
                // let der = atob(b64);
                certdb.addCertFromBase64(b64_certificate,'Cu,,',name);
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
